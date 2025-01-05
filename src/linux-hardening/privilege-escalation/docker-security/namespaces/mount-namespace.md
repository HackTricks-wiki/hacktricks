# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Un mount namespace è una funzionalità del kernel Linux che fornisce isolamento dei punti di montaggio del file system visti da un gruppo di processi. Ogni mount namespace ha il proprio insieme di punti di montaggio del file system e **le modifiche ai punti di montaggio in un namespace non influenzano altri namespace**. Ciò significa che i processi in esecuzione in diversi mount namespace possono avere visioni diverse della gerarchia del file system.

I mount namespace sono particolarmente utili nella containerizzazione, dove ogni container dovrebbe avere il proprio file system e configurazione, isolati da altri container e dal sistema host.

### Come funziona:

1. Quando viene creato un nuovo mount namespace, viene inizializzato con una **copia dei punti di montaggio dal suo namespace genitore**. Ciò significa che, al momento della creazione, il nuovo namespace condivide la stessa visione del file system del suo genitore. Tuttavia, eventuali modifiche successive ai punti di montaggio all'interno del namespace non influenzeranno il genitore o altri namespace.
2. Quando un processo modifica un punto di montaggio all'interno del proprio namespace, come montare o smontare un file system, la **modifica è locale a quel namespace** e non influisce su altri namespace. Questo consente a ciascun namespace di avere la propria gerarchia del file system indipendente.
3. I processi possono spostarsi tra i namespace utilizzando la chiamata di sistema `setns()`, o creare nuovi namespace utilizzando le chiamate di sistema `unshare()` o `clone()` con il flag `CLONE_NEWNS`. Quando un processo si sposta in un nuovo namespace o ne crea uno, inizierà a utilizzare i punti di montaggio associati a quel namespace.
4. **I descrittori di file e gli inode sono condivisi tra i namespace**, il che significa che se un processo in un namespace ha un descrittore di file aperto che punta a un file, può **passare quel descrittore di file** a un processo in un altro namespace, e **entrambi i processi accederanno allo stesso file**. Tuttavia, il percorso del file potrebbe non essere lo stesso in entrambi i namespace a causa delle differenze nei punti di montaggio.

## Laboratorio:

### Crea diversi Namespace

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` se utilizzi il parametro `--mount-proc`, garantisci che il nuovo mount namespace abbia una **visione accurata e isolata delle informazioni sui processi specifiche per quel namespace**.

<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si incontra un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). I dettagli chiave e la soluzione sono delineati di seguito:

1. **Spiegazione del problema**:

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
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Trova tutti i Mount namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Entra all'interno di un Mount namespace
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Inoltre, puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/mnt`).

Poiché i nuovi mount sono accessibili solo all'interno del namespace, è possibile che un namespace contenga informazioni sensibili che possono essere accessibili solo da esso.

### Monta qualcosa
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Riferimenti

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
