# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il time namespace virtualizza orologi selezionati, in particolare **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**. È un namespace più recente e più specializzato rispetto a mount, PID, network, o user namespaces, e raramente è la prima cosa a cui un operatore pensa quando si parla di hardening dei container. Tuttavia, fa parte della famiglia moderna di namespace ed è utile capirne i concetti a livello teorico.

Lo scopo principale è permettere a un processo di osservare offset controllati per certi orologi senza modificare la vista globale del tempo dell'host. Questo è utile per checkpoint/restore workflows, test deterministici e alcuni comportamenti runtime avanzati. Non è solitamente un controllo di isolamento di primo piano allo stesso modo di mount o user namespaces, ma contribuisce comunque a rendere l'ambiente del processo più autonomo.

## Lab

Se il kernel dell'host e la userspace lo supportano, puoi ispezionare il namespace con:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Il supporto varia in base alle versioni del kernel e degli strumenti, quindi questa pagina serve più a comprendere il meccanismo che a prevederne la presenza in ogni ambiente di laboratorio.

### Offset temporali

I time namespaces di Linux virtualizzano gli offset per `CLOCK_MONOTONIC` e `CLOCK_BOOTTIME`. Gli offset correnti per namespace sono esposti tramite `/proc/<pid>/timens_offsets`, che sui kernel che lo supportano possono anche essere modificati da un processo che detiene `CAP_SYS_TIME` all'interno del namespace pertinente:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Il file contiene delta in nanosecondi. Modificare `monotonic` di due giorni cambia le osservazioni relative all'uptime all'interno di quel namespace senza modificare l'orologio di sistema dell'host.

### `unshare` Helper Flags

Versioni recenti di `util-linux` forniscono flag comodi che scrivono automaticamente gli offset:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Questi flag sono per lo più un miglioramento dell'usabilità, ma rendono anche più facile riconoscere la feature nella documentazione e nei test.

## Utilizzo a runtime

I namespace `time` sono più recenti e meno utilizzati in modo universale rispetto ai namespace mount o PID. OCI Runtime Specification v1.1 ha aggiunto il supporto esplicito per il namespace `time` e per il campo `linux.timeOffsets`, e le release più recenti di `runc` implementano quella parte del modello. Un frammento OCI minimale è il seguente:
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
Questo è importante perché trasforma il namespace temporale da una primitiva del kernel di nicchia in qualcosa che i runtime possono richiedere in modo portabile.

## Impatto sulla sicurezza

Ci sono meno storie classiche di breakout incentrate sul namespace temporale rispetto ad altri tipi di namespace. Il rischio qui di solito non è che il namespace temporale permetta direttamente una fuga, ma che i lettori lo ignorino completamente e quindi non notino come i runtime avanzati possano modellare il comportamento dei processi. In ambienti specializzati, viste dell'orologio alterate possono influenzare checkpoint/restore, osservabilità o le ipotesi forensi.

## Abuso

Di solito non esiste una primitiva di evasione diretta qui, ma il comportamento dell'orologio alterato può comunque essere utile per comprendere l'ambiente di esecuzione e identificare funzionalità avanzate del runtime:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Se stai confrontando due processi, le differenze qui possono aiutare a spiegare comportamenti temporali strani, artefatti di checkpoint/restore o discrepanze nei log specifiche dell'ambiente.

Impatto:

- quasi sempre reconnaissance o comprensione dell'ambiente
- utile per spiegare anomalie nei log, nell'uptime o nel checkpoint/restore
- normalmente non è di per sé un meccanismo diretto di container-escape

La sfumatura importante nell'abuso è che i time namespaces non virtualizzano `CLOCK_REALTIME`, quindi da soli non consentono a un attacker di falsificare l'orologio di sistema dell'host o di violare direttamente i controlli di scadenza dei certificati a livello di sistema. Il loro valore sta soprattutto nel confondere logiche basate su tempo monotono, riprodurre bug specifici dell'ambiente o comprendere comportamento runtime avanzato.

## Verifiche

Queste verifiche riguardano principalmente confermare se il runtime sta utilizzando un time namespace privato.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Cosa c'è di interessante qui:

- In molti ambienti questi valori non porteranno a una segnalazione di sicurezza immediata, ma indicano se una specifica funzionalità di runtime è in uso.
- Se confronti due processi, le differenze qui possono spiegare comportamenti di timing confusi o di checkpoint/restore.

Per la maggior parte dei container breakouts, il time namespace non è il primo controllo che esaminerai. Tuttavia, una sezione completa su container-security dovrebbe menzionarlo perché fa parte del moderno kernel model e occasionalmente è rilevante in scenari avanzati di runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
