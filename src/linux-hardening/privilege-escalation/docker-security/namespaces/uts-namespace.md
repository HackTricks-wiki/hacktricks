# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Un namespace UTS (UNIX Time-Sharing System) è una funzionalità del kernel Linux che fornisce **isolamento di due identificatori di sistema**: il **nome host** e il **nome di dominio NIS** (Network Information Service). Questo isolamento consente a ciascun namespace UTS di avere il **proprio nome host e nome di dominio NIS indipendenti**, il che è particolarmente utile negli scenari di containerizzazione in cui ogni container dovrebbe apparire come un sistema separato con il proprio nome host.

### Come funziona:

1. Quando viene creato un nuovo namespace UTS, inizia con una **copia del nome host e del nome di dominio NIS dal suo namespace genitore**. Ciò significa che, al momento della creazione, il nuovo namespace **condivide gli stessi identificatori del suo genitore**. Tuttavia, eventuali modifiche successive al nome host o al nome di dominio NIS all'interno del namespace non influenzeranno altri namespace.
2. I processi all'interno di un namespace UTS **possono cambiare il nome host e il nome di dominio NIS** utilizzando le chiamate di sistema `sethostname()` e `setdomainname()`, rispettivamente. Queste modifiche sono locali al namespace e non influenzano altri namespace o il sistema host.
3. I processi possono spostarsi tra i namespace utilizzando la chiamata di sistema `setns()` o creare nuovi namespace utilizzando le chiamate di sistema `unshare()` o `clone()` con il flag `CLONE_NEWUTS`. Quando un processo si sposta in un nuovo namespace o ne crea uno, inizierà a utilizzare il nome host e il nome di dominio NIS associati a quel namespace.

## Laboratorio:

### Crea diversi Namespace

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` se utilizzi il parametro `--mount-proc`, garantisci che il nuovo namespace di mount abbia una **visione accurata e isolata delle informazioni sui processi specifiche per quel namespace**.

<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). I dettagli chiave e la soluzione sono delineati di seguito:

1. **Spiegazione del Problema**:

- Il kernel Linux consente a un processo di creare nuovi namespace utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo namespace PID (denominato processo "unshare") non entra nel nuovo namespace; solo i suoi processi figli lo fanno.
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
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Trova tutti i namespace UTS
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entra all'interno di un namespace UTS
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
