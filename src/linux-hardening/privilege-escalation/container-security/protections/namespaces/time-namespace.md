# Namespace del tempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace del tempo virtualizza orologi selezionati, in particolare **`CLOCK_MONOTONIC`** e **`CLOCK_BOOTTIME`**. È un namespace più recente e più specializzato rispetto ai namespace mount, PID, network o user, e raramente è la prima cosa a cui un operatore pensa quando si parla di hardening dei container. Anche così, fa parte della famiglia moderna di namespace ed è utile comprenderlo a livello concettuale.

Lo scopo principale è permettere a un processo di osservare offset controllati per certi orologi senza cambiare la vista temporale globale dell'host. Questo è utile per workflow di checkpoint/restore, test deterministici e alcuni comportamenti runtime avanzati. Di solito non è un controllo di isolamento di primo piano allo stesso modo dei namespace mount o user, ma contribuisce comunque a rendere l'ambiente del processo più autosufficiente.

## Laboratorio

Se il kernel e l'userspace dell'host lo supportano, puoi ispezionare il namespace con:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Il supporto varia in base alle versioni del kernel e degli strumenti, quindi questa pagina serve più a comprendere il meccanismo che a aspettarsi di trovarlo visibile in ogni ambiente di laboratorio.

### Offset temporali

Linux time namespaces virtualizzano gli offset per `CLOCK_MONOTONIC` e `CLOCK_BOOTTIME`. Gli offset correnti per namespace sono esposti tramite `/proc/<pid>/timens_offsets`; sui kernel che lo supportano, questi possono anche essere modificati da un processo che possiede `CAP_SYS_TIME` all'interno del namespace pertinente:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Il file contiene delta in nanosecondi. Regolando `monotonic` di due giorni si modificano le osservazioni di tipo uptime all'interno di quel namespace senza cambiare l'orologio di sistema dell'host.

### Flag di comodità per `unshare`

Le versioni recenti di `util-linux` forniscono flag di comodità che scrivono automaticamente gli offset:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Questi flag sono per lo più un miglioramento dell'usabilità, ma rendono anche più facile riconoscere la funzionalità nella documentazione e nei test.

## Utilizzo a runtime

I time namespaces sono più recenti e meno ampiamente utilizzati rispetto ai mount o PID namespaces. OCI Runtime Specification v1.1 ha aggiunto il supporto esplicito per il namespace `time` e il campo `linux.timeOffsets`, e le release più recenti di `runc` implementano quella parte del modello. Un frammento OCI minimale appare così:
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
Questo è importante perché trasforma time namespacing da una primitiva del kernel di nicchia in qualcosa che i runtimes possono richiedere in modo portabile.

## Impatto sulla sicurezza

Ci sono meno storie classiche di breakout incentrate sul time namespace rispetto ad altri tipi di namespace. Il rischio qui di solito non è che il time namespace abiliti direttamente l'escape, ma che i lettori lo ignorino completamente e quindi non notino come i runtimes avanzati possano plasmare il comportamento dei processi. In ambienti specializzati, viste dell'orologio alterate possono influenzare checkpoint/restore, osservabilità o le assunzioni forensi.

## Abuso

Di solito non esiste una primitiva di breakout diretta qui, ma il comportamento dell'orologio alterato può comunque essere utile per comprendere l'ambiente di esecuzione e identificare funzionalità avanzate del runtime:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Se stai confrontando due processi, le differenze qui possono aiutare a spiegare comportamenti di temporizzazione anomali, artefatti di checkpoint/restore o discrepanze nei logging specifiche dell'ambiente.

Impatto:

- quasi sempre reconnaissance o comprensione dell'ambiente
- utile per spiegare anomalie nei logging, nell'uptime o nei checkpoint/restore
- di norma non è un meccanismo diretto di container-escape di per sé

La sfumatura importante nell'abuso è che i time namespaces non virtualizzano `CLOCK_REALTIME`, quindi di per sé non permettono a un attacker di falsificare l'orologio di sistema dell'host né di compromettere direttamente i certificate-expiry checks a livello di sistema. Il loro valore risiede soprattutto nel confondere logiche basate su monotonic-time, nel riprodurre bug specifici dell'ambiente o nel comprendere comportamenti avanzati del runtime.

## Controlli

Questi controlli riguardano principalmente la conferma se il runtime sta usando un private time namespace o meno.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Cosa c'è di interessante qui:

- In molti ambienti questi valori non porteranno a una segnalazione di sicurezza immediata, ma indicano se è in uso una runtime feature specializzata.
- Se stai confrontando due processi, differenze qui possono spiegare comportamenti di timing confusi o di checkpoint/restore.

Per la maggior parte dei container breakouts, il time namespace non è il primo controllo che indagherai. Tuttavia, una sezione completa su container-security dovrebbe menzionarlo perché fa parte del modern kernel model e occasionalmente è rilevante in scenari runtime avanzati.
