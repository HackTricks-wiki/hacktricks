# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il time namespace virtualizza clock selezionati di tipo monotonic invece dell'orologio di sistema dell'host. In pratica, ciò significa offset privati per **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**, oltre alle viste strettamente correlate **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** e **`CLOCK_BOOTTIME_ALARM`**. Non virtualizza **`CLOCK_REALTIME`**, quindi `date` e la logica di scadenza dei certificati continuano a osservare l'orologio di sistema dell'host, a meno che non intervenga qualche altro meccanismo.

Lo scopo principale è consentire a un processo di osservare offset controllati del tempo trascorso senza modificare la vista temporale globale dell'host. Ciò è utile per i workflow di checkpoint/restore, i test deterministici e i comportamenti runtime avanzati. Di solito non è un controllo di isolamento di primo piano come i mount namespace o gli user namespace, ma contribuisce comunque a rendere l'ambiente del processo più autonomo.

Dal punto di vista offensivo, questo namespace è solitamente più rilevante per **reconnaissance, timer skew e comprensione del runtime** che per un breakout diretto. Tuttavia, è importante perché un numero crescente di container runtime e workflow di checkpoint/restore è ora in grado di richiederlo esplicitamente.

## Lab

Se il kernel dell'host e lo userspace lo supportano, puoi ispezionare il namespace con:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Il supporto varia in base alle versioni del kernel e degli strumenti, quindi questa pagina riguarda più la comprensione del meccanismo che l'aspettativa di vederlo in ogni ambiente di laboratorio. L'osservazione importante è che `date` dovrebbe continuare a riflettere l'orologio di sistema dell'host, mentre i valori basati su monotonic/boottime sono quelli che cambiano quando vengono configurati offset diversi da zero.

### Sottigliezza della creazione

I time namespaces sono leggermente insoliti rispetto ai mount, PID o network namespaces:

- `unshare(CLONE_NEWTIME)` crea un nuovo time namespace per i **futuri processi figli**.
- Il task chiamante rimane nel proprio time namespace corrente.
- Di conseguenza, `/proc/<pid>/ns/time_for_children` è spesso più interessante di `/proc/<pid>/ns/time` durante il debugging della configurazione del runtime.

Anche la finestra di scrittura è speciale. Gli offset in `/proc/<pid>/timens_offsets` devono essere scritti prima che il nuovo time namespace venga completamente popolato con task in esecuzione; in pratica, i runtime eseguono questa operazione durante la stretta finestra di configurazione tra la creazione del namespace e l'avvio del payload finale. Una volta che un task è già in esecuzione al suo interno, le scritture successive falliscono con `EACCES`. Per questo i runtime di basso livello gestiscono la configurazione del time namespace come un passaggio iniziale di bootstrap, invece di provare a modificare gli offset dall'interno di un processo container già avviato.

### Offset temporali

I time namespaces Linux espongono gli offset specifici del namespace tramite `/proc/<pid>/timens_offsets`. Il formato consiste in un insieme di nomi o ID di clock, oltre a delta in secondi/nanosecondi relativi al time namespace iniziale.

In pratica, il workflow user-facing più affidabile consiste nel lasciare che sia `unshare` a scrivere gli offset al posto dell'utente:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Il punto importante non è la sintassi esatta del comando, ma il comportamento: un container può osservare una visualizzazione simile all'uptime diversa senza modificare l'orologio civile dell'host.

### Flag helper di `unshare`

Le versioni recenti di `util-linux` forniscono flag di convenienza che scrivono automaticamente gli offset durante la creazione del namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Questi flag rappresentano principalmente un miglioramento dell'usabilità, ma facilitano anche il riconoscimento della funzionalità nella documentazione, nei test harness e nei wrapper di runtime.

## Utilizzo a runtime

I time namespaces sono più recenti e vengono utilizzati meno universalmente rispetto ai mount o ai PID namespaces. La OCI Runtime Specification v1.1 ha aggiunto il supporto esplicito per il namespace `time` e il campo `linux.timeOffsets`, e i runtime moderni possono mappare questi dati nel flusso di bootstrap del kernel. Un frammento OCI minimale è il seguente:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Questo è importante perché trasforma il time namespacing da primitiva del kernel di nicchia in qualcosa che i runtime possono richiedere in modo portabile. Spiega inoltre perché gli elementi interni del runtime necessitano di un passaggio di sincronizzazione esplicito: l'offset deve essere scritto in `/proc/<pid>/timens_offsets` prima che il payload del container entri completamente nel nuovo namespace.

Gli stack di checkpoint/restore come CRIU sono una delle principali ragioni pratiche per cui questa funzionalità esiste. Senza i time namespaces, il ripristino di un workload in pausa farebbe avanzare bruscamente i clock monotonic e boot-time dell'intervallo di tempo trascorso dal workload in stato sospeso.

## Impatto sulla sicurezza

Esistono meno casi classici di breakout incentrati sul time namespace rispetto ad altri tipi di namespace. In questo caso, il rischio generalmente non consiste nel fatto che il time namespace abiliti direttamente l'escape, ma nel fatto che gli analisti lo ignorino completamente e non comprendano quindi come i runtime avanzati possano modificare il comportamento dei processi.

In ambienti specializzati, le visualizzazioni alterate dei clock monotonic o boottime possono influenzare:

- il comportamento di timeout e retry
- watchdog e logica delle lease
- il comportamento di `timerfd`, `nanosleep` e `clock_nanosleep`
- la forensics di checkpoint/restore
- la telemetria del tempo trascorso e le euristiche basate sull'uptime

Quindi, anche se raramente è il primo namespace che si abusa, può spiegare perfettamente un comportamento temporale "impossibile" durante un assessment.

## Abuse

Di solito non esiste qui una primitiva di breakout diretta, ma il comportamento alterato dei clock può comunque essere utile per comprendere l'ambiente di esecuzione, identificare funzionalità avanzate del runtime e individuare la logica basata sui timer che viene misurata rispetto ai clock monotonic invece che al tempo reale:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Se stai confrontando due processi, le differenze qui possono aiutare a spiegare comportamenti anomali relativi ai tempi, artifact di checkpoint/restore o discrepanze nei log specifiche dell’ambiente.

Aspetti pratici rilevanti per un attacker:

- confondere la logica di backoff, sleep o watchdog implementata con clock monotonic
- spiegare perché `/proc/uptime` e il comportamento basato sui timer non coincidono con le aspettative del wall-clock dell’host
- riconoscere workflow di CRIU/checkpoint-restore e altre funzionalità runtime avanzate
- individuare ambienti in cui il joining del target time namespace con `nsenter -T -t <pid> -- ...` può riprodurre il comportamento dei timer locali al container per attività di debugging o post-exploitation

Impatto:

- quasi sempre ricognizione o comprensione dell’ambiente
- utile per spiegare anomalie nei log, nell’uptime o nel checkpoint/restore
- utile per analizzare sleep, retry e timer basati sul tempo monotonic
- normalmente non è di per sé un meccanismo diretto di container-escape

La precisazione importante sull’abuso è che i time namespaces non virtualizzano `CLOCK_REALTIME`; quindi, da soli, non permettono a un attacker di falsificare il wall-clock dell’host o di compromettere direttamente i controlli di scadenza dei certificati a livello di sistema. Il loro valore consiste soprattutto nel confondere la logica basata sul tempo monotonic, riprodurre bug specifici dell’ambiente o comprendere comportamenti runtime avanzati.

## Verifiche

Queste verifiche servono principalmente a confermare se il runtime stia utilizzando un time namespace privato e se abbia effettivamente impostato offset diversi da zero.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
Cosa è interessante qui:

- In molti ambienti questi valori non porteranno a una security finding immediata, ma indicano se è in uso una funzionalità specializzata del runtime.
- Se `time_for_children` differisce da `time`, il chiamante potrebbe aver preparato un time namespace riservato ai child in cui non è entrato personalmente.
- Se `date` corrisponde a quello dell'host, ma i valori basati su monotonic/boottime differiscono, probabilmente si tratta di time namespacing e non di manomissione del wall-clock.
- Se stai confrontando due processi, le differenze qui potrebbero spiegare comportamenti confusi relativi al timing o al checkpoint/restore.

Per la maggior parte dei container breakout, il time namespace non è il primo controllo da esaminare. Tuttavia, una sezione completa sulla container security dovrebbe menzionarlo, perché fa parte del moderno modello del kernel e occasionalmente è rilevante in scenari runtime avanzati.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
