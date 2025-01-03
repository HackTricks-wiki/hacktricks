# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Un namespace IPC (Inter-Process Communication) è una funzionalità del kernel Linux che fornisce **isolamento** degli oggetti IPC di System V, come code di messaggi, segmenti di memoria condivisa e semafori. Questo isolamento garantisce che i processi in **diversi namespace IPC non possano accedere o modificare direttamente gli oggetti IPC degli altri**, fornendo un ulteriore livello di sicurezza e privacy tra i gruppi di processi.

### Come funziona:

1. Quando viene creato un nuovo namespace IPC, inizia con un **set completamente isolato di oggetti IPC di System V**. Ciò significa che i processi in esecuzione nel nuovo namespace IPC non possono accedere o interferire con gli oggetti IPC in altri namespace o nel sistema host per impostazione predefinita.
2. Gli oggetti IPC creati all'interno di un namespace sono visibili e **accessibili solo ai processi all'interno di quel namespace**. Ogni oggetto IPC è identificato da una chiave unica all'interno del suo namespace. Anche se la chiave può essere identica in diversi namespace, gli oggetti stessi sono isolati e non possono essere accessibili tra i namespace.
3. I processi possono spostarsi tra i namespace utilizzando la chiamata di sistema `setns()` o creare nuovi namespace utilizzando le chiamate di sistema `unshare()` o `clone()` con il flag `CLONE_NEWIPC`. Quando un processo si sposta in un nuovo namespace o ne crea uno, inizierà a utilizzare gli oggetti IPC associati a quel namespace.

## Laboratorio:

### Crea diversi Namespace

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` se utilizzi il parametro `--mount-proc`, garantisci che il nuovo namespace di mount abbia una **visione accurata e isolata delle informazioni sui processi specifiche per quel namespace**.

<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si incontra un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). I dettagli chiave e la soluzione sono delineati di seguito:

1. **Spiegazione del problema**:

- Il kernel Linux consente a un processo di creare nuovi namespace utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo namespace PID (denominato processo "unshare") non entra nel nuovo namespace; solo i suoi processi figli lo fanno.
- Eseguire `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figli si trovano nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, attiva la pulizia del namespace se non ci sono altri processi, poiché PID 1 ha il ruolo speciale di adottare processi orfani. Il kernel Linux disabiliterà quindi l'allocazione PID in quel namespace.

2. **Conseguenza**:

- L'uscita di PID 1 in un nuovo namespace porta alla pulizia del flag `PIDNS_HASH_ADDING`. Questo porta al fallimento della funzione `alloc_pid` nell'allocare un nuovo PID durante la creazione di un nuovo processo, producendo l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto utilizzando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` fork un nuovo processo dopo aver creato il nuovo namespace PID.
- Eseguire `%unshare -fp /bin/bash%` garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figli sono quindi contenuti in modo sicuro all'interno di questo nuovo namespace, prevenendo l'uscita prematura di PID 1 e consentendo l'allocazione normale dei PID.

Assicurandoti che `unshare` venga eseguito con il flag `-f`, il nuovo namespace PID viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi subprocessi di operare senza incontrare l'errore di allocazione della memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Controlla in quale namespace si trova il tuo processo
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Trova tutti gli IPC namespace
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entra in un namespace IPC
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/net`).

### Crea oggetto IPC
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Riferimenti

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
