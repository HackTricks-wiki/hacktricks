# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Il time namespace virtualizza clock monotonic-style selezionati invece del wall clock dell'host. In pratica, questo significa offset privati per **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**, più le viste strettamente correlate **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** e **`CLOCK_BOOTTIME_ALARM`**. Non virtualizza **`CLOCK_REALTIME`**, quindi `date` e la logica di scadenza dei certificati continuano a osservare il wall clock dell'host, a meno che qualche altro meccanismo non interferisca.

Lo scopo principale è consentire a un processo di osservare offset controllati del tempo trascorso senza modificare la vista globale del tempo dell'host. Questo è utile per workflow di checkpoint/restore, test deterministici e comportamento runtime avanzato. Di solito non è un controllo di isolamento in primo piano come mount o user namespaces, ma contribuisce comunque a rendere l'ambiente del processo più self-contained.

Dal punto di vista offensivo, questo namespace è di solito più rilevante per **reconnaissance, timer skew e runtime understanding** che per un breakout diretto. Tuttavia, è importante perché sempre più container runtime e workflow di checkpoint/restore possono richiederlo esplicitamente.

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
Il supporto varia in base al kernel e alle versioni degli tool, quindi questa pagina serve più a capire il meccanismo che ad aspettarsi di vederlo in ogni lab environment. L’osservazione importante è che `date` dovrebbe ancora riflettere l’orologio wall clock dell’host, mentre i valori basati su monotonic/boottime sono quelli che cambiano quando vengono configurati offset non zero.

### Creation Nuance

I time namespaces sono leggermente insoliti rispetto ai mount, PID o network namespaces:

- `unshare(CLONE_NEWTIME)` crea un nuovo time namespace per i **future children**.
- Il task che effettua la chiamata rimane nel proprio current time namespace.
- `/proc/<pid>/ns/time_for_children` è quindi spesso più interessante di `/proc/<pid>/ns/time` quando si esegue il debug della runtime setup.

Anche la write window è speciale. Gli offset in `/proc/<pid>/timens_offsets` devono essere scritti prima che il nuovo time namespace sia completamente popolato con task in esecuzione; in pratica le runtime lo fanno durante la stretta setup window tra la creazione del namespace e l’avvio del payload finale. Una volta che un task è già in esecuzione lì dentro, i write successivi falliscono con `EACCES`. Ecco perché le runtime low-level gestiscono la time-namespace setup come un early bootstrap step invece di provare a patchare gli offset dall’interno di un container process già avviato.

### Time Offsets

I Linux time namespaces espongono gli offset per namespace tramite `/proc/<pid>/timens_offsets`. Il formato è un insieme di clock names o ID più delta in secondi/nanosecondi rispetto all’initial time namespace.

In pratica, il workflow più affidabile lato user è lasciare che `unshare` scriva quegli offset per te:
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
Il punto importante non è la sintassi esatta del comando, ma il comportamento: un container può osservare una vista simile all'uptime diversa senza modificare l'orologio di sistema dell'host.

### `unshare` Helper Flags

Le versioni recenti di `util-linux` forniscono flag di convenienza che scrivono automaticamente gli offset durante la creazione del namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Questi flag sono principalmente un miglioramento dell'usabilità, ma rendono anche più facile riconoscere la feature nella documentazione, nei test harness e nei runtime wrapper.

## Runtime Usage

I time namespaces sono più recenti e meno usati in modo universale rispetto ai mount o PID namespaces. OCI Runtime Specification v1.1 ha aggiunto supporto esplicito per il namespace `time` e per il campo `linux.timeOffsets`, e i runtime moderni possono mappare quei dati nel flusso di bootstrap del kernel. Un frammento OCI minimale è simile a questo:
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
Questo è importante perché trasforma il time namespacing da una primitive di kernel di nicchia in qualcosa che i runtimes possono richiedere in modo portabile. Spiega anche perché gli internals del runtime hanno bisogno di un passo esplicito di sincronizzazione: l'offset deve essere scritto in `/proc/<pid>/timens_offsets` prima che il payload del container entri completamente nel nuovo namespace.

Stack di checkpoint/restore come CRIU sono una delle principali ragioni pratiche per cui questo esiste. Senza i time namespaces, ripristinare un workload in pausa farebbe saltare gli orologi monotonic e boot-time della quantità di tempo in cui il workload è rimasto sospeso.

## Security Impact

Ci sono meno storie classiche di breakout incentrate sul time namespace rispetto ad altri tipi di namespace. Il rischio qui di solito non è che il time namespace consenta direttamente l'escape, ma che i lettori lo ignorino completamente e quindi non notino come runtimes avanzati possano modellare il comportamento dei processi.

In ambienti specializzati, visioni alterate di monotonic o boottime possono influenzare:

- timeout e retry behavior
- watchdogs e logica di lease
- comportamento di `timerfd`, `nanosleep`, e `clock_nanosleep`
- forensics di checkpoint/restore
- telemetria del tempo trascorso ed euristiche basate sull'uptime

Quindi, anche se raramente è il primo namespace che sfrutti, può assolutamente spiegare comportamenti temporali "impossibili" durante un assessment.

## Abuse

Di solito non c'è una primitive diretta di breakout qui, ma un comportamento alterato degli orologi può comunque essere utile per comprendere l'execution environment, identificare funzionalità avanzate del runtime, e individuare logiche basate su timer misurate rispetto agli orologi monotonic invece che al wall clock time:
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
Se stai confrontando due processi, le differenze qui possono aiutare a spiegare comportamenti di timing strani, artefatti di checkpoint/restore o mismatch di logging specifici dell'ambiente.

Angoli pratici rilevanti per un attacker:

- confondere logica di backoff, sleep o watchdog implementata con clock monotonic
- spiegare perché `/proc/uptime` e il comportamento guidato dai timer non coincidono con le aspettative del wall clock lato host
- riconoscere workflow CRIU/checkpoint-restore e altre funzionalità avanzate del runtime
- individuare ambienti in cui unire il time namespace di un target con `nsenter -T -t <pid> -- ...` può riprodurre il comportamento dei timer locale al container per debugging o post-exploitation

Impatto:

- quasi sempre reconnaissance o comprensione dell'ambiente
- utile per spiegare anomalie di logging, uptime o checkpoint/restore
- utile per analizzare sleep, retry e timer basati su monotonic-time
- di norma non è di per sé un meccanismo diretto di container-escape

La nuance importante dell'abuso è che i time namespaces non virtualizzano `CLOCK_REALTIME`, quindi da soli non permettono a un attacker di falsificare l'orologio del host o di rompere direttamente i controlli di scadenza dei certificati a livello di sistema. Il loro valore è soprattutto nel confondere logiche basate su monotonic-time, riprodurre bug specifici dell'ambiente o comprendere il comportamento avanzato del runtime.

## Checks

Questi controlli servono soprattutto a confermare se il runtime stia usando affatto un private time namespace e se abbia effettivamente impostato offset non zero.
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
Cosa c’è di interessante qui:

- In molti ambienti questi valori non porteranno a un finding di sicurezza immediato, ma ti dicono se è in uso una feature runtime specializzata.
- Se `time_for_children` differisce da `time`, il chiamante potrebbe aver preparato un time namespace solo per i figli che non ha ancora entrato lui stesso.
- Se `date` corrisponde all’host ma i valori basati su monotonic/boottime non lo fanno, probabilmente stai osservando time namespacing invece di una manipolazione del wall-clock.
- Se stai confrontando due processi, le differenze qui possono spiegare comportamenti confusi di timing o checkpoint/restore.

Per la maggior parte dei container breakout, il time namespace non è il primo controllo che investigherai. Tuttavia, una sezione completa sulla container-security dovrebbe menzionarlo perché fa parte del moderno kernel model e occasionalmente conta in scenari runtime avanzati.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
