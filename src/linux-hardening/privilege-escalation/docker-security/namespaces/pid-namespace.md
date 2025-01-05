# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Il namespace PID (Process IDentifier) è una funzionalità nel kernel Linux che fornisce isolamento dei processi consentendo a un gruppo di processi di avere il proprio insieme di PID unici, separati dai PID in altri namespace. Questo è particolarmente utile nella containerizzazione, dove l'isolamento dei processi è essenziale per la sicurezza e la gestione delle risorse.

Quando viene creato un nuovo namespace PID, il primo processo in quel namespace viene assegnato il PID 1. Questo processo diventa il processo "init" del nuovo namespace ed è responsabile della gestione degli altri processi all'interno del namespace. Ogni processo successivo creato all'interno del namespace avrà un PID unico all'interno di quel namespace, e questi PID saranno indipendenti dai PID in altri namespace.

Dal punto di vista di un processo all'interno di un namespace PID, può vedere solo altri processi nello stesso namespace. Non è a conoscenza dei processi in altri namespace e non può interagire con essi utilizzando strumenti di gestione dei processi tradizionali (ad es., `kill`, `wait`, ecc.). Questo fornisce un livello di isolamento che aiuta a prevenire che i processi interferiscano l'uno con l'altro.

### Come funziona:

1. Quando viene creato un nuovo processo (ad es., utilizzando la chiamata di sistema `clone()`), il processo può essere assegnato a un nuovo namespace PID o a uno esistente. **Se viene creato un nuovo namespace, il processo diventa il processo "init" di quel namespace**.
2. Il **kernel** mantiene una **mappatura tra i PID nel nuovo namespace e i corrispondenti PID** nel namespace padre (cioè, il namespace da cui è stato creato il nuovo namespace). Questa mappatura **consente al kernel di tradurre i PID quando necessario**, ad esempio quando si inviano segnali tra processi in diversi namespace.
3. **I processi all'interno di un namespace PID possono vedere e interagire solo con altri processi nello stesso namespace**. Non sono a conoscenza dei processi in altri namespace e i loro PID sono unici all'interno del loro namespace.
4. Quando un **namespace PID viene distrutto** (ad es., quando il processo "init" del namespace termina), **tutti i processi all'interno di quel namespace vengono terminati**. Questo garantisce che tutte le risorse associate al namespace vengano pulite correttamente.

## Lab:

### Crea diversi Namespace

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). I dettagli chiave e la soluzione sono delineati di seguito:

1. **Spiegazione del Problema**:

- Il kernel Linux consente a un processo di creare nuovi namespace utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo namespace PID (chiamato "processo unshare") non entra nel nuovo namespace; solo i suoi processi figli lo fanno.
- Eseguire `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figli si trovano nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, attiva la pulizia del namespace se non ci sono altri processi, poiché PID 1 ha il ruolo speciale di adottare processi orfani. Il kernel Linux disabiliterà quindi l'allocazione PID in quel namespace.

2. **Conseguenza**:

- L'uscita di PID 1 in un nuovo namespace porta alla pulizia del flag `PIDNS_HASH_ADDING`. Questo provoca il fallimento della funzione `alloc_pid` nell'allocare un nuovo PID durante la creazione di un nuovo processo, producendo l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto utilizzando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` fork un nuovo processo dopo aver creato il nuovo namespace PID.
- Eseguire `%unshare -fp /bin/bash%` garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figli sono quindi contenuti in modo sicuro all'interno di questo nuovo namespace, prevenendo l'uscita prematura di PID 1 e consentendo l'allocazione normale dei PID.

Assicurandosi che `unshare` venga eseguito con il flag `-f`, il nuovo namespace PID viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi subprocessi di operare senza incontrare l'errore di allocazione della memoria.

</details>

Montando una nuova istanza del filesystem `/proc` se utilizzi il parametro `--mount-proc`, garantisci che il nuovo namespace di mount abbia una **visione accurata e isolata delle informazioni sui processi specifiche per quel namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Controlla in quale namespace si trova il tuo processo
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Trova tutti i namespace PID
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Nota che l'utente root del namespace PID iniziale (predefinito) può vedere tutti i processi, anche quelli nei nuovi spazi dei nomi PID, ecco perché possiamo vedere tutti i namespace PID.

### Entra all'interno di un namespace PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Quando entri in un namespace PID dal namespace predefinito, sarai comunque in grado di vedere tutti i processi. E il processo di quel namespace PID sarà in grado di vedere il nuovo bash nel namespace PID.

Inoltre, puoi **entrare in un altro namespace PID di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/pid`)

## Riferimenti

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
