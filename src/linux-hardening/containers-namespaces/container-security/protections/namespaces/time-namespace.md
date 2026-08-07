# Namespace del tempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il time namespace virtualizza orologi selezionati in stile monotonic invece dell'orologio di sistema dell'host. In pratica, ciò significa offset privati per **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**, oltre alle viste strettamente correlate **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** e **`CLOCK_BOOTTIME_ALARM`**. Non virtualizza **`CLOCK_REALTIME`**, quindi `date` e la logica di scadenza dei certificati continuano a osservare l'orologio di sistema dell'host, a meno che qualche altro meccanismo non interferisca.<sup>[[1]](#references)</sup>

Lo scopo principale è consentire a un processo di osservare offset controllati del tempo trascorso senza modificare la visualizzazione globale dell'ora sull'host. Ciò è utile per i workflow di checkpoint/restore, i test deterministici e i comportamenti avanzati del runtime. Di solito non è un controllo di isolamento principale come i mount namespace o gli user namespace, ma contribuisce comunque a rendere l'ambiente del processo più autonomo.

Dal punto di vista offensivo, questo namespace è generalmente più rilevante per la **ricognizione, lo skew dei timer e la comprensione del runtime** che per un breakout diretto. Tuttavia, è importante perché sempre più container runtime e workflow di checkpoint/restore sono ora in grado di richiederlo esplicitamente.

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
Il supporto varia in base alle versioni del kernel e degli strumenti, quindi questa pagina riguarda più la comprensione del meccanismo che l'aspettativa di vederlo in ogni ambiente di laboratorio. L'osservazione importante è che `date` dovrebbe continuare a riflettere il wall clock dell'host, mentre i valori basati su monotonic/boottime sono quelli che cambiano quando vengono configurati offset diversi da zero.

### Particolarità della creazione

I time namespace sono leggermente insoliti rispetto ai mount, PID o network namespace:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` crea un nuovo time namespace per i **figli futuri**.
- Il task chiamante rimane nel proprio time namespace corrente.
- `/proc/<pid>/ns/time_for_children` è quindi spesso più interessante di `/proc/<pid>/ns/time` durante il debugging della configurazione del runtime.

Anche la finestra di scrittura è speciale. Gli offset in `/proc/<pid>/timens_offsets` devono essere scritti prima che il nuovo time namespace venga completamente popolato con task in esecuzione; in pratica, i runtime lo fanno durante la stretta finestra di configurazione tra la creazione del namespace e l'avvio del payload finale. Quando un task è già in esecuzione al suo interno, le scritture successive falliscono con `EACCES`. Per questo i runtime di basso livello gestiscono la configurazione del time namespace come un passaggio iniziale di bootstrap, invece di tentare di modificare gli offset dall'interno di un processo container già avviato.<sup>[[1]](#references)</sup>

### Offset temporali

I time namespace Linux espongono gli offset per-namespace tramite `/proc/<pid>/timens_offsets`. Il formato consiste in un insieme di nomi o ID dei clock, più delta espressi in secondi/nanosecondi rispetto al time namespace iniziale.<sup>[[1]](#references)</sup>

In pratica, il workflow più affidabile per l'utente consiste nel lasciare che sia `unshare` a scrivere gli offset al posto suo:
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
Il punto importante non è la sintassi esatta del comando, ma il comportamento: un container può osservare una visualizzazione simile all’uptime diversa senza modificare il wall clock dell’host.

### Flag di supporto di `unshare`

Le versioni recenti di `util-linux` forniscono flag di praticità che scrivono automaticamente gli offset durante la creazione del namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Questi flag rappresentano principalmente un miglioramento dell'usabilità, ma facilitano anche il riconoscimento della funzionalità nella documentazione, nei test harness e nei runtime wrapper.

## Utilizzo a Runtime

I time namespaces sono più recenti e vengono utilizzati meno universalmente rispetto ai mount o PID namespaces. OCI Runtime Specification v1.1 ha aggiunto il supporto esplicito per il namespace `time` e il campo `linux.timeOffsets`, e i runtime moderni possono trasferire questi dati nel flusso di bootstrap del kernel. Un frammento OCI minimale è simile al seguente:
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
Questo è importante perché trasforma il time namespacing da una primitiva del kernel di nicchia in qualcosa che i runtime possono richiedere in modo portabile. Spiega inoltre perché gli internals dei runtime necessitano di un passaggio di sincronizzazione esplicito: l'offset deve essere scritto in `/proc/<pid>/timens_offsets` prima che il payload del container entri completamente nel nuovo namespace.

Gli stack di checkpoint/restore come CRIU sono uno dei principali motivi reali per cui questa funzionalità esiste. Senza i time namespaces, il ripristino di un workload sospeso farebbe avanzare bruscamente gli orologi monotonic e boot-time dell'intervallo di tempo in cui il workload è rimasto sospeso.<sup>[[2]](#references)</sup>

## Impatto sulla sicurezza

Esistono meno casi classici di breakout incentrati sul time namespace rispetto ad altri tipi di namespace. Il rischio, in questo caso, solitamente non consiste nel fatto che il time namespace abiliti direttamente l'escape, ma nel fatto che gli analisti lo ignorino completamente e non comprendano quindi come i runtime avanzati possano modificare il comportamento dei processi.

In ambienti specializzati, le visualizzazioni alterate dei tempi monotonic o boottime possono influire su:

- comportamento di timeout e retry
- watchdog e logica delle lease
- comportamento di `timerfd`, `nanosleep` e `clock_nanosleep`
- attività forensics di checkpoint/restore
- telemetria del tempo trascorso ed euristiche basate sull'uptime

Pertanto, anche se raramente è il primo namespace di cui si esegue l'abuse, può spiegare perfettamente comportamenti temporali "impossibili" durante un assessment.

## Abuse

Di solito qui non esiste una primitiva diretta di breakout, ma il comportamento alterato degli orologi può comunque essere utile per comprendere l'ambiente di esecuzione, identificare funzionalità avanzate dei runtime e individuare la logica basata sui timer che viene misurata rispetto agli orologi monotonic invece che rispetto al wall clock time:
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
Se stai confrontando due processi, le differenze qui possono aiutare a spiegare comportamenti anomali relativi ai tempi, artefatti di checkpoint/restore o discrepanze nei log specifiche dell’ambiente.

Aspetti pratici rilevanti per un attacker:

- confondere la logica di backoff, sleep o watchdog implementata con clock monotonic
- spiegare perché `/proc/uptime` e il comportamento basato sui timer non corrispondono alle aspettative del wall-clock dell’host
- riconoscere workflow CRIU/checkpoint-restore e altre funzionalità runtime avanzate
- individuare gli ambienti in cui unirsi al time namespace di un target con `nsenter -T -t <pid> -- ...` può riprodurre il comportamento dei timer locale al container per il debugging o il post-exploitation

Impatto:

- quasi sempre ricognizione o comprensione dell’ambiente
- utile per spiegare anomalie nei log, nell’uptime o nel checkpoint/restore
- utile per analizzare sleep, retry e timer basati sul monotonic time
- normalmente non è di per sé un meccanismo diretto di container escape

La considerazione importante relativa all’abuso è che i time namespace non virtualizzano `CLOCK_REALTIME`; pertanto, da soli, non permettono a un attacker di falsificare il wall-clock dell’host o di compromettere direttamente i controlli di scadenza dei certificati a livello di sistema. Il loro valore consiste soprattutto nel confondere la logica basata sul monotonic time, riprodurre bug specifici dell’ambiente o comprendere il comportamento avanzato del runtime.

## Checks

Questi checks servono principalmente a confermare se il runtime stia utilizzando un time namespace privato e se abbia effettivamente impostato offset diversi da zero.
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

- In molti ambienti questi valori non porteranno a un'immediata security finding, ma indicano se è attiva una funzionalità specializzata del runtime.
- Se `time_for_children` differisce da `time`, il processo chiamante potrebbe aver preparato un time namespace destinato esclusivamente ai processi figli, senza essere entrato al suo interno.
- Se `date` corrisponde a quello dell'host, ma i valori basati su monotonic/boottime differiscono, probabilmente si tratta di time namespacing e non di manomissione dell'orologio di sistema.
- Se si confrontano due processi, le differenze qui presenti potrebbero spiegare comportamenti temporali o di checkpoint/restore poco chiari.

Per la maggior parte dei container breakout, il time namespace non è il primo controllo da analizzare. Tuttavia, una sezione completa sulla container-security dovrebbe menzionarlo, poiché fa parte del moderno modello del kernel e occasionalmente è rilevante in scenari avanzati del runtime.

## Riferimenti

- [1] [Pagina del manuale Linux `time_namespaces(7)`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
