# Namespace utente

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Riferimenti

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Informazioni di base

Un namespace utente è una funzionalità del kernel Linux che **fornisce l'isolamento delle mappature degli UID e GID**, permettendo a ogni namespace utente di avere il **proprio insieme di UID e GID**. Questo isolamento consente ai processi in esecuzione in diversi namespace utente di **avere privilegi e proprietà differenti**, anche se condividono gli stessi UID e GID a livello numerico.

I namespace utente sono particolarmente utili nella containerizzazione, dove ogni container dovrebbe avere il proprio set indipendente di UID e GID, consentendo una migliore sicurezza e isolamento tra i container e il sistema host.

### Come funziona:

1. Quando viene creato un nuovo namespace utente, questo **inizia con un insieme vuoto di mappature di UID e GID**. Ciò significa che qualsiasi processo in esecuzione nel nuovo namespace utente **inizialmente non avrà privilegi al di fuori del namespace**.
2. Si possono stabilire mappature degli ID tra gli UID e GID nel nuovo namespace e quelli nel namespace genitore (o host). Questo **permette ai processi nel nuovo namespace di avere privilegi e proprietà corrispondenti agli UID e GID nel namespace genitore**. Tuttavia, le mappature degli ID possono essere limitate a specifici intervalli e sottoinsiemi di ID, permettendo un controllo granulare sui privilegi concessi ai processi nel nuovo namespace.
3. All'interno di un namespace utente, **i processi possono avere pieni privilegi di root (UID 0) per le operazioni all'interno del namespace**, pur mantenendo privilegi limitati al di fuori del namespace. Questo consente **ai container di funzionare con capacità simili a root all'interno del proprio namespace senza avere pieni privilegi di root sul sistema host**.
4. I processi possono spostarsi tra namespace usando la system call `setns()` o creare nuovi namespace usando le system call `unshare()` o `clone()` con la flag `CLONE_NEWUSER`. Quando un processo si sposta in un nuovo namespace o ne crea uno, inizierà a usare le mappature di UID e GID associate a quel namespace.

## Laboratorio:

### Creare namespace diversi

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` se usi il parametro `--mount-proc`, ti assicuri che il nuovo mount namespace abbia una **vista accurata e isolata delle informazioni di processo specifiche per quel namespace**.

<details>

<summary>Errore: bash: fork: Cannot allocate memory</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si incontra un errore dovuto al modo in cui Linux gestisce i nuovi PID (Process ID) namespace. I dettagli principali e la soluzione sono illustrati di seguito:

1. **Spiegazione del problema**:

- Il kernel Linux permette a un processo di creare nuovi namespace usando la system call `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo PID namespace (indicato come il processo "unshare") non entra nel nuovo namespace; solo i suoi processi figli lo fanno.
- Eseguire %unshare -p /bin/bash% avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figli sono nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, avvia la pulizia del namespace se non ci sono altri processi, poiché PID 1 ha il ruolo speciale di adottare i processi orfani. Il kernel Linux disabiliterà quindi l'allocazione dei PID in quel namespace.

2. **Conseguenza**:

- L'uscita di PID 1 in un nuovo namespace porta alla rimozione del flag `PIDNS_HASH_ADDING`. Questo causa il fallimento della funzione `alloc_pid` nell'allocare un nuovo PID durante la creazione di un nuovo processo, producendo l'errore "Cannot allocate memory".

3. **Soluzione**:
- Il problema può essere risolto usando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` faccia fork di un nuovo processo dopo aver creato il nuovo PID namespace.
- Eseguire %unshare -fp /bin/bash% garantisce che il comando `unshare` diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figli saranno così contenuti in modo sicuro in questo nuovo namespace, evitando l'uscita prematura di PID 1 e permettendo una normale allocazione dei PID.

Assicurandosi che `unshare` venga eseguito con il flag `-f`, il nuovo PID namespace viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi sotto-processi di operare senza incorrere nell'errore di allocazione della memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Per usare user namespace, il daemon Docker deve essere avviato con **`--userns-remap=default`**(In ubuntu 14.04, questo può essere fatto modificando `/etc/default/docker` e poi eseguendo `sudo service docker restart`)

### Verificare in quale namespace si trova il processo
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
È possibile verificare la mappatura degli utenti dal container docker con:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Oppure dal host con:
```bash
cat /proc/<pid>/uid_map
```
### Trova tutti i namespace utente
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrare in un User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Inoltre, puoi solo **entrare in un altro namespace di processo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/user`).

### Crea un nuovo User namespace (con mappature)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Regole di mappatura UID/GID non privilegiate

Quando il processo che scrive in `uid_map`/`gid_map` **non possiede CAP_SETUID/CAP_SETGID nel parent user namespace**, il kernel impone regole più severe: è permessa solo una **singola mappatura** per l'UID/GID effettivo del chiamante, e per `gid_map` **devi prima disabilitare `setgroups(2)`** scrivendo `deny` in `/proc/<pid>/setgroups`.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

I mount ID-mapped **associano una mappatura del namespace utente a un mount**, così la proprietà dei file viene rimappata quando vi si accede tramite quel mount. Questo è comunemente usato dai container runtimes (soprattutto rootless) per **condividere percorsi host senza un `chown` ricorsivo**, pur imponendo la traduzione UID/GID del namespace utente.

Da una prospettiva offensiva, **se puoi creare un mount namespace e possedere `CAP_SYS_ADMIN` all'interno del tuo namespace utente**, e il filesystem supporta gli ID-mapped mounts, puoi rimappare le *visualizzazioni* di ownership dei bind mounts. Questo **non cambia la proprietà su disco**, ma può far apparire file altrimenti non scrivibili come appartenenti al tuo UID/GID mappato all'interno del namespace.

### Recupero delle capability

Nel caso dei namespace utente, **quando viene creato un nuovo namespace utente, il processo che entra nel namespace gli viene assegnato un set completo di capability all'interno di quel namespace**. Queste capability permettono al processo di eseguire operazioni privilegiate come **montare** **filesystem**, creare dispositivi o cambiare la proprietà dei file, ma **solo nel contesto del proprio namespace utente**.

Ad esempio, quando hai la capability `CAP_SYS_ADMIN` all'interno di un namespace utente, puoi eseguire operazioni che tipicamente richiedono questa capability, come montare filesystem, ma solo nel contesto del tuo namespace utente. Qualsiasi operazione eseguita con questa capability non influenzerà il sistema host o altri namespace.

> [!WARNING]
> Quindi, anche se ottenere un nuovo processo dentro un nuovo namespace utente **ti restituirà tutte le capability** (CapEff: 000001ffffffffff), in realtà puoi **usare solo quelle relative al namespace** (ad esempio mount) ma non tutte. Pertanto, questo di per sé non è sufficiente per evadere da un Docker container.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Riferimenti

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
