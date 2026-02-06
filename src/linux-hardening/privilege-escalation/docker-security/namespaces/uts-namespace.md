# Namespace UTS

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Un UTS (UNIX Time-Sharing System) namespace è una funzionalità del kernel Linux che fornisce i**solamento di due identificatori di sistema**: il **hostname** e il **NIS** (Network Information Service) nome di dominio. Questo isolamento permette a ogni UTS namespace di avere il **proprio hostname e nome di dominio NIS indipendenti**, cosa particolarmente utile negli scenari di containerization dove ogni container dovrebbe apparire come un sistema separato con il proprio hostname.

### Come funziona:

1. Quando viene creato un nuovo UTS namespace, esso inizia con una **copia dell'hostname e del nome di dominio NIS dal suo namespace padre**. Questo significa che, alla creazione, il nuovo namespace s**condivide gli stessi identificatori del suo namespace padre**. Tuttavia, qualsiasi modifica successiva all'hostname o al nome di dominio NIS all'interno del namespace non influenzerà gli altri namespace.
2. I processi all'interno di un UTS namespace **possono cambiare l'hostname e il nome di dominio NIS** usando le system call `sethostname()` e `setdomainname()`, rispettivamente. Queste modifiche sono locali al namespace e non influenzano altri namespace o il sistema host.
3. I processi possono spostarsi tra namespace usando la system call `setns()` o creare nuovi namespace usando le system call `unshare()` o `clone()` con il flag `CLONE_NEWUTS`. Quando un processo si sposta in un nuovo namespace o ne crea uno, inizierà a usare l'hostname e il nome di dominio NIS associati a quel namespace.

## Laboratorio:

### Creare diversi Namespace

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` usando il parametro `--mount-proc`, si assicura che il nuovo mount namespace abbia una **vista accurata e isolata delle informazioni sui processi specifiche di quel namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Spiegazione del problema**:

- Il kernel Linux permette a un processo di creare nuovi namespace usando la system call `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo PID namespace (indicato come il processo "unshare") non entra nel nuovo namespace; soltanto i suoi processi figli lo fanno.
- Eseguire `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figli rimangono nel PID namespace originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, innesca la pulizia del namespace se non ci sono altri processi, poiché PID 1 ha il ruolo speciale di adottare i processi orfani. Il kernel Linux disabiliterà quindi l'assegnazione di PID in quel namespace.

2. **Conseguenza**:

- L'uscita di PID 1 in un nuovo namespace porta alla rimozione del flag `PIDNS_HASH_ADDING`. Questo fa sì che la funzione `alloc_pid` non riesca ad allocare un nuovo PID quando viene creato un nuovo processo, producendo l'errore "Cannot allocate memory".

3. **Soluzione**:
- Il problema può essere risolto usando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` esegua un fork di un nuovo processo dopo aver creato il nuovo PID namespace.
- Eseguire `%unshare -fp /bin/bash%` assicura che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figli sono così contenuti in modo sicuro all'interno di questo nuovo namespace, evitando l'uscita prematura di PID 1 e permettendo la normale allocazione dei PID.

Assicurandosi che `unshare` venga eseguito con il flag `-f`, il nuovo PID namespace viene mantenuto correttamente, permettendo a `/bin/bash` e ai suoi sotto-processi di operare senza incontrare l'errore di allocazione memoria.

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
### Entrare in un namespace UTS
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Abuso della condivisione UTS dell'host

Se un container viene avviato con `--uts=host`, si unisce al namespace UTS dell'host invece di ottenere uno isolato. Con capability (ad es. `--cap-add SYS_ADMIN`), il codice nel container può modificare l'hostname/NIS name dell'host tramite `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Modificare il nome host può manomettere i log/gli avvisi, confondere la discovery del cluster o rompere le configurazioni TLS/SSH che vincolano il nome host.

### Rilevare container che condividono UTS con l'host
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
