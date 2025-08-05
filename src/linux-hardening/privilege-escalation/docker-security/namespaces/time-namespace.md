# Time Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Il time namespace in Linux consente offset per namespace sugli orologi monotoni e di avvio del sistema. È comunemente usato nei contenitori Linux per modificare la data/ora all'interno di un contenitore e regolare gli orologi dopo il ripristino da un checkpoint o snapshot.

## Laboratorio:

### Crea diversi Namespaces

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` se utilizzi il parametro `--mount-proc`, garantisci che il nuovo namespace di mount abbia una **visione accurata e isolata delle informazioni sui processi specifiche per quel namespace**.

<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). I dettagli chiave e la soluzione sono delineati di seguito:

1. **Spiegazione del problema**:

- Il kernel Linux consente a un processo di creare nuovi namespace utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo namespace PID (chiamato "processo unshare") non entra nel nuovo namespace; solo i suoi processi figli lo fanno.
- Eseguire `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figli si trovano nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, attiva la pulizia del namespace se non ci sono altri processi, poiché PID 1 ha il ruolo speciale di adottare processi orfani. Il kernel Linux disabiliterà quindi l'allocazione PID in quel namespace.

2. **Conseguenza**:

- L'uscita di PID 1 in un nuovo namespace porta alla pulizia del flag `PIDNS_HASH_ADDING`. Questo provoca il fallimento della funzione `alloc_pid` nell'allocare un nuovo PID durante la creazione di un nuovo processo, producendo l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto utilizzando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` fork un nuovo processo dopo aver creato il nuovo namespace PID.
- Eseguire `%unshare -fp /bin/bash%` garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figli sono quindi contenuti in modo sicuro all'interno di questo nuovo namespace, prevenendo l'uscita prematura di PID 1 e consentendo l'allocazione normale dei PID.

Assicurandoti che `unshare` venga eseguito con il flag `-f`, il nuovo namespace PID viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi subprocessi di operare senza incontrare l'errore di allocazione della memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Controlla in quale namespace si trova il tuo processo
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Trova tutti i namespace di tempo
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entra all'interno di un Time namespace
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## Manipulating Time Offsets

A partire da Linux 5.6, due orologi possono essere virtualizzati per ogni namespace temporale:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

I loro delta per namespace sono esposti (e possono essere modificati) attraverso il file `/proc/<PID>/timens_offsets`:
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
Il file contiene due righe - una per orologio - con l'offset in **nanosecondi**. I processi che detengono **CAP_SYS_TIME** _nella time namespace_ possono cambiare il valore:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
Se hai bisogno che l'orologio a muro (`CLOCK_REALTIME`) cambi, devi comunque fare affidamento su meccanismi classici (`date`, `hwclock`, `chronyd`, …); **non** è namespaced.


### `unshare(1)` helper flags (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
Le opzioni lunghe scrivono automaticamente i delta scelti in `timens_offsets` subito dopo la creazione dello spazio dei nomi, risparmiando un `echo` manuale.

---

## Supporto OCI e Runtime

* La **OCI Runtime Specification v1.1** (Nov 2023) ha aggiunto un tipo di spazio dei nomi `time` dedicato e il campo `linux.timeOffsets` in modo che i motori dei container possano richiedere la virtualizzazione del tempo in modo portabile.
* **runc >= 1.2.0** implementa quella parte della specifica. Un frammento minimo di `config.json` appare così:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Poi esegui il container con `runc run <id>`.

>  NOTA: runc **1.2.6** (Feb 2025) ha corretto un bug "exec into container with private timens" che poteva portare a un blocco e potenziale DoS. Assicurati di essere su ≥ 1.2.6 in produzione.

---

## Considerazioni sulla sicurezza

1. **Capacità richiesta** – Un processo ha bisogno di **CAP_SYS_TIME** all'interno del suo spazio dei nomi utente/tempo per cambiare gli offset. Rimuovere quella capacità nel container (predefinito in Docker e Kubernetes) previene manomissioni.
2. **Nessuna modifica dell'orologio** – Poiché `CLOCK_REALTIME` è condiviso con l'host, gli attaccanti non possono falsificare le scadenze dei certificati, la scadenza dei JWT, ecc. tramite timens da solo.
3. **Evasione di log / rilevamento** – Il software che si basa su `CLOCK_MONOTONIC` (ad es. limitatori di velocità basati sul tempo di attività) può essere confuso se l'utente dello spazio dei nomi regola l'offset. Preferisci `CLOCK_REALTIME` per i timestamp rilevanti per la sicurezza.
4. **Superficie di attacco del kernel** – Anche con `CAP_SYS_TIME` rimosso, il codice del kernel rimane accessibile; mantieni l'host aggiornato. Linux 5.6 → 5.12 ha ricevuto molteplici correzioni di bug timens (NULL-deref, problemi di segno).

### Checklist di indurimento

* Rimuovi `CAP_SYS_TIME` nel profilo predefinito del runtime del tuo container.
* Tieni aggiornati i runtime (runc ≥ 1.2.6, crun ≥ 1.12).
* Fissa util-linux ≥ 2.38 se fai affidamento sugli helper `--monotonic/--boottime`.
* Audita il software nel container che legge **uptime** o **CLOCK_MONOTONIC** per la logica critica per la sicurezza.

## Riferimenti

* man7.org – Pagina del manuale degli spazi dei nomi temporali: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* Blog OCI – "OCI v1.1: nuovi spazi dei nomi time e RDT" (15 Nov 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
