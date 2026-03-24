# Namespace del tempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace del tempo virtualizza alcuni clock selezionati, in particolare **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**. È un namespace più recente e più specializzato rispetto a mount, PID, network o user namespaces, e raramente è la prima cosa a cui un operatore pensa quando si discute di hardening dei container. Anche così, fa parte della famiglia moderna di namespace ed è utile comprenderlo a livello concettuale.

Lo scopo principale è permettere a un processo di osservare offset controllati per certi clock senza modificare la vista temporale globale dell'host. Questo è utile per workflow di checkpoint/restore, test deterministici e alcuni comportamenti runtime avanzati. Di solito non è un controllo di isolamento di primo piano come mount o user namespaces, ma contribuisce comunque a rendere l'ambiente del processo più autonomo.

## Laboratorio

Se kernel e userspace dell'host lo supportano, puoi ispezionare il namespace con:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Il supporto varia in base alle versioni del kernel e degli strumenti, quindi questa pagina serve più a comprendere il meccanismo che ad aspettarsi che sia visibile in ogni ambiente di laboratorio.

### Offset temporali

I namespace temporali di Linux virtualizzano gli offset per `CLOCK_MONOTONIC` e `CLOCK_BOOTTIME`. Gli offset correnti per namespace sono esposti tramite `/proc/<pid>/timens_offsets`, che sui kernel che lo supportano può anche essere modificato da un processo che possiede `CAP_SYS_TIME` all'interno del namespace rilevante:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Il file contiene delta in nanosecondi. Modificare `monotonic` di due giorni altera le osservazioni simili all'uptime all'interno di quel namespace senza cambiare l'orologio di sistema dell'host.

### `unshare` Flag di utilità

Le versioni recenti di `util-linux` forniscono flag di utilità che scrivono automaticamente gli offset:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Questi flags sono per lo più un miglioramento dell'usabilità, ma rendono anche più semplice riconoscere la funzionalità nella documentazione e nei test.

## Utilizzo a runtime

I time namespaces sono più recenti e meno universalmente utilizzati rispetto ai mount o PID namespaces. OCI Runtime Specification v1.1 ha aggiunto il supporto esplicito per il namespace `time` e il campo `linux.timeOffsets`, e le release più recenti di `runc` implementano quella parte del modello. Un frammento OCI minimale è il seguente:
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
Questo è importante perché trasforma il time namespacing da una primitiva di kernel di nicchia in qualcosa che i runtime possono richiedere in modo portabile.

## Impatto sulla sicurezza

Ci sono meno storie classiche di breakout incentrate sul time namespace rispetto ad altri tipi di namespace. Il rischio qui di solito non è che il time namespace abiliti direttamente una fuga, ma che i lettori lo ignorino completamente e quindi non colgano come i runtime avanzati possano modellare il comportamento dei processi. In ambienti specializzati, una vista dell'orologio alterata può influenzare checkpoint/restore, observability o le assunzioni forensi.

## Abuso

Di solito qui non esiste una primitiva di breakout diretta, ma il comportamento dell'orologio alterato può comunque essere utile per comprendere l'ambiente di esecuzione e identificare funzionalità avanzate dei runtime:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Se stai confrontando due processi, le differenze qui possono aiutare a spiegare comportamenti di timing anomali, artefatti di checkpoint/restore, o incongruenze nei logging specifiche dell'ambiente.

Impatto:

- quasi sempre reconnaissance o comprensione dell'ambiente
- utile per spiegare logging, uptime, o anomalie di checkpoint/restore
- non normalmente un container-escape diretto di per sé

La sottigliezza importante nell'abuso è che i time namespaces non virtualizzano `CLOCK_REALTIME`, quindi di per sé non permettono a un attacker di falsificare l'orologio dell'host o di rompere direttamente i controlli di certificate-expiry a livello di sistema. Il loro valore è soprattutto nel confondere la logica basata su monotonic-time, riprodurre bug specifici dell'ambiente o comprendere comportamenti avanzati del runtime.

## Checks

Questi controlli riguardano principalmente la conferma se il runtime sta usando un time namespace privato.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
- In molti ambienti questi valori non porteranno a una segnalazione di sicurezza immediata, ma indicano se è in uso una funzionalità runtime specializzata.
- Se confronti due processi, le differenze qui possono spiegare comportamenti di timing confusi o di checkpoint/restore.

Per la maggior parte dei container breakouts, il time namespace non è il primo controllo che indagherai. Tuttavia, una sezione completa di container-security dovrebbe menzionarlo perché fa parte del modello del kernel moderno e occasionalmente è rilevante in scenari runtime avanzati.
{{#include ../../../../../banners/hacktricks-training.md}}
