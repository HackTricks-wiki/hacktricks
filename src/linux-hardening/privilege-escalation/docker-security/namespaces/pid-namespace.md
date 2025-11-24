# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Il PID (Process IDentifier) namespace è una funzionalità del kernel Linux che fornisce isolamento dei processi permettendo a un gruppo di processi di avere il proprio insieme di PIDs unici, separati dai PIDs in altri namespace. Questo è particolarmente utile nella containerizzazione, dove l'isolamento dei processi è essenziale per la sicurezza e la gestione delle risorse.

Quando viene creato un nuovo PID namespace, al primo processo in quel namespace viene assegnato il PID 1. Questo processo diventa il processo "init" del nuovo namespace ed è responsabile della gestione degli altri processi all'interno del namespace. Ogni processo successivo creato nel namespace avrà un PID unico all'interno dello stesso, e questi PIDs saranno indipendenti dai PIDs in altri namespace.

Dal punto di vista di un processo all'interno di un PID namespace, può vedere solo gli altri processi nello stesso namespace. Non è a conoscenza dei processi in altri namespace e non può interagire con essi usando i tradizionali strumenti di gestione dei processi (es. `kill`, `wait`, ecc.). Questo fornisce un livello di isolamento che aiuta a prevenire che i processi interferiscano tra loro.

### Come funziona:

1. Quando viene creato un nuovo processo (es. usando la system call `clone()`), il processo può essere assegnato a un PID namespace nuovo o esistente. **Se viene creato un nuovo namespace, il processo diventa il processo "init" di quel namespace**.
2. Il **kernel** mantiene una **mappatura tra i PIDs nel nuovo namespace e i corrispondenti PIDs** nel namespace parent (cioè il namespace dal quale è stato creato il nuovo namespace). Questa mappatura **permette al kernel di tradurre i PIDs quando necessario**, ad esempio quando vengono inviati segnali tra processi in namespace diversi.
3. **I processi all'interno di un PID namespace possono vedere ed interagire solo con altri processi nello stesso namespace**. Non sono a conoscenza dei processi in altri namespace e i loro PIDs sono unici all'interno del loro namespace.
4. Quando un **PID namespace viene distrutto** (es. quando il processo "init" del namespace termina), **tutti i processi all'interno di quel namespace vengono terminati**. Questo garantisce che tutte le risorse associate al namespace vengano correttamente liberate.

## Laboratorio:

### Creare diversi namespace

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore dovuto al modo in cui Linux gestisce i nuovi PID (Process ID) namespaces. I dettagli principali e la soluzione sono riportati di seguito:

1. **Spiegazione del problema**:

- Il kernel Linux permette a un processo di creare nuovi namespace usando la system call `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo PID namespace (denominato processo "unshare") non entra nel nuovo namespace; solo i suoi processi figli vi entrano.
- Lanciare %unshare -p /bin/bash% avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figli rimangono nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, innesca la pulizia del namespace se non ci sono altri processi, poiché PID 1 ha il ruolo speciale di adottare i processi orfani. Il kernel Linux disabiliterà quindi l'allocazione di PID in quel namespace.

2. **Conseguenza**:

- L'uscita di PID 1 in un nuovo namespace porta alla rimozione del flag `PIDNS_HASH_ADDING`. Questo fa sì che la funzione `alloc_pid` non riesca ad allocare un nuovo PID quando viene creato un nuovo processo, producendo l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto usando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` esegua un fork di un nuovo processo dopo aver creato il nuovo PID namespace.
- Eseguire %unshare -fp /bin/bash% garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figli saranno così contenuti in modo sicuro all'interno di questo nuovo namespace, evitando l'uscita prematura di PID 1 e permettendo la normale allocazione dei PID.

Assicurandosi che `unshare` venga eseguito con il flag `-f`, il nuovo PID namespace viene mantenuto correttamente, permettendo a `/bin/bash` e ai suoi sotto-processi di operare senza incontrare l'errore di allocazione della memoria.

</details>

Montando una nuova istanza del filesystem `/proc` usando il parametro `--mount-proc`, si garantisce che il nuovo mount namespace abbia una **visione accurata e isolata delle informazioni di processo specifiche di quel namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Controlla in quale namespace si trova il tuo processo
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Individuare tutti i PID namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Nota che l'utente root del PID namespace iniziale (predefinito) può vedere tutti i processi, anche quelli nei nuovi PID namespaces; per questo possiamo vedere tutti i PID namespaces.

### Entrare in un PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Quando entri all'interno di un PID namespace dal namespace predefinito, sarai comunque in grado di vedere tutti i processi. E il processo di quel PID ns sarà in grado di vedere la nuova bash nel PID ns.

Inoltre, puoi solo **entrare in un altro PID namespace di processo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/pid`)

## Note recenti di sfruttamento

### CVE-2025-31133: abuso di `maskedPaths` per raggiungere i PID dell'host

runc ≤1.2.7 consentiva ad attaccanti che controllano immagini container o workload `runc exec` di sostituire `/dev/null` lato container appena prima che il runtime mascherasse voci sensibili di procfs. Quando la race ha successo, `/dev/null` può diventare un symlink che punta a qualsiasi percorso dell'host (per esempio `/proc/sys/kernel/core_pattern`), quindi il nuovo PID namespace del container eredita improvvisamente accesso in lettura/scrittura alle impostazioni globali di procfs dell'host anche se non ha mai lasciato il proprio namespace. Una volta che `core_pattern` o `/proc/sysrq-trigger` sono scrivibili, generare un coredump o triggerare SysRq permette l'esecuzione di codice o denial of service nel PID namespace dell'host.

Flusso di lavoro pratico:

1. Costruisci un OCI bundle il cui rootfs sostituisce `/dev/null` con un link al percorso dell'host che vuoi (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Avvia il container prima della patch in modo che runc effettui un bind-mount del target procfs dell'host sopra il link.
3. All'interno del namespace del container, scrivi nel file procfs ora esposto (es., punta `core_pattern` a un reverse shell helper) e fai crashare qualsiasi processo per costringere il kernel dell'host a eseguire il tuo helper nel contesto PID 1.

Puoi rapidamente verificare se un bundle sta mascherando i file corretti prima di avviarlo:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Se il runtime manca di una voce di mascheramento che ti aspetti (o la salta perché `/dev/null` è scomparso), considera il container come potenzialmente in grado di vedere i PID dell'host.

### Iniezione di namespace con `insject`

NCC Group’s `insject` viene caricato come payload LD_PRELOAD che aggancia una fase tardiva del programma target (predefinito `main`) ed esegue una sequenza di chiamate `setns()` dopo `execve()`. Questo permette di attaccarsi dall'host (o da un altro container) al PID namespace della vittima *dopo* l'inizializzazione del suo runtime, preservandone la vista di `/proc/<pid>` senza dover copiare binari nel filesystem del container. Poiché `insject` può differire l'entrata nel PID namespace fino al fork, puoi mantenere un thread nel namespace host (con CAP_SYS_PTRACE) mentre un altro thread esegue nel PID namespace target, creando potenti primitive di debugging o offensive.

Esempio di utilizzo:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Punti chiave quando si sfrutta o si difende contro namespace injection:

- Usa `-S/--strict` per forzare `insject` ad abortire se threads esistono già o se namespace joins falliscono; altrimenti potresti lasciare threads parzialmente migrati che si estendono attraverso gli spazi PID dell'host e del container.
- Non collegare mai strumenti che mantengono ancora writable host file descriptors a meno che non ti unisca anche al mount namespace — altrimenti qualsiasi processo all'interno del PID namespace può ptrace il tuo helper e riutilizzare quei file descriptor per manomettere le risorse dell'host.

## Riferimenti

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
