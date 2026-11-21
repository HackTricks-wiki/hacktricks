# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinationen von POSIX-Berechtigungen

Bei einem **Verzeichnis** bedeuten die drei Berechtigungsbits etwas anderes als bei einer regulären Datei. `chmod(1)` bezeichnet das Execute-Bit bei Anwendung auf ein Verzeichnis als „**search**“:<sup>[[2]](#references)</sup>

> `0100` Für Dateien wird die Ausführung durch den Besitzer erlaubt. Für Verzeichnisse wird dem Besitzer die **Suche** im Verzeichnis erlaubt.

- **read** – Sie können die Verzeichniseinträge **auflisten** (die Namen anzeigen).
- **write** – Sie können Einträge im Verzeichnis **erstellen, umbenennen und löschen**. Beachten Sie, dass dies eine Eigenschaft des *übergeordneten* Verzeichnisses ist, nicht der Datei: Sie können eine Datei löschen, die Sie weder lesen noch beschreiben können, solange Sie in ihr übergeordnetes Verzeichnis schreiben können.
  - Zum Löschen eines **Unterverzeichnisses** muss dieses leer sein. Dazu müssen wiederum ausreichende Rechte vorhanden sein, um alles darin zu entfernen.
  - Hat das Verzeichnis das **Sticky Bit** (`S_ISVTX`, wie `/tmp`), ist dies eingeschränkt – POSIX legt fest, dass ein Prozess darin Dateien nur dann entfernen oder umbenennen darf, wenn er die Datei oder das Verzeichnis besitzt oder über die entsprechenden Privilegien verfügt.<sup>[[1]](#references)</sup>
- **execute / search** – Sie dürfen das Verzeichnis **durchlaufen**. Bei der Pfadnamensauflösung wird jede Komponente „im durch ihren Vorgänger angegebenen Verzeichnis“ gesucht. Daher macht der **Verlust der Suchrechte auf nur einer Komponente des Pfadpräfixes alles darunter über den Pfad unerreichbar**, selbst wenn die Datei am Ende des Pfads für alle lesbar ist.<sup>[[1]](#references)</sup>

### Gefährliche Kombinationen

**Eine Datei/einen Ordner im Besitz von root überschreiben**, wenn:

- Der **Besitzer** eines übergeordneten **Verzeichnisses** im Pfad der Benutzer ist
- Der **Besitzer** eines übergeordneten **Verzeichnisses** im Pfad eine **Benutzergruppe** mit **Schreibzugriff** ist
- Eine **Benutzergruppe** **Schreibzugriff** auf die **Datei** hat

Bei jeder der vorherigen Kombinationen könnte ein Angreifer einen **sym-/hard link** in den erwarteten Pfad **injecten**, um beliebige Schreibzugriffe mit erhöhten Privilegien zu erhalten.

### Sonderfall: Ordner mit R+X nur für root

Das ergibt sich unmittelbar aus der obigen Regel zur Pfadnamensauflösung. Wenn ein **Verzeichnis nur root R+X gewährt**, sind die darin enthaltenen Dateien für alle anderen *über den Pfad* unerreichbar – aber die **eigenen Berechtigungsbits der Dateien können weiterhin großzügig gesetzt sein**. Nur das Verzeichnis steht im Weg.

Jeder Primitive, der es ermöglicht, die Datei **aus diesem Verzeichnis herauszubekommen** – etwa ein privilegierter Prozess, der einen vom Angreifer gewählten Pfad an einen Ort **verschiebt/umbenennt/kopiert**, den Sie durchlaufen *können* –, ermöglicht beliebige Lesezugriffe, ohne jemals die eigenen Berechtigungen der Datei überwinden zu müssen:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Suche nach privilegierten Datei-Verschiebeprozessen (Installern, Log-Rotatoren, Crash-/Diagnose-Sammlern, Backup- und „Export“-Funktionen), die einen Quellpfad von einem Benutzer mit geringeren Rechten akzeptieren.

## Symbolischer Link / Hardlink

### Freigebene Datei/Ordner

Wenn ein privilegierter Prozess Daten in eine **Datei** schreibt, die von einem **Benutzer mit geringeren Rechten kontrolliert** werden kann oder die zuvor von einem Benutzer mit geringeren Rechten **erstellt wurde**, kann der Benutzer sie einfach über einen symbolischen Link oder Hardlink auf eine andere Datei **verweisen lassen**. Der privilegierte Prozess schreibt dann in diese Datei.

Sieh dir die anderen Abschnitte an, in denen ein Angreifer einen **beliebigen Schreibzugriff missbrauchen könnte, um seine Rechte auszuweiten**.

### `O_NOFOLLOW` beim Öffnen

Laut [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *„Wird `O_NOFOLLOW` in der Maske verwendet und ist die an `open()` übergebene Zieldatei ein symbolischer Link, schlägt `open()` fehl.“* Es wird nur die **letzte** Komponente geprüft — alle **Zwischenkomponenten** werden weiterhin aufgelöst und verfolgt. Ein Entwickler, der einen Schreibvorgang mit `O_NOFOLLOW` „geschützt“ hat, kann also weiterhin angegriffen werden, indem ein Angreifer einen Symlink in einem beliebigen **übergeordneten Verzeichnis** des Zielpfads platziert.<sup>[[3]](#references)</sup>

Dieselbe Manpage dokumentiert die Flags, die diese Lücke tatsächlich schließen:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *„Ist ... eine beliebige Komponente des an `open()` übergebenen Pfads ein symbolischer Link, schlägt `open()` fehl.“*
- **`O_RESOLVE_BENEATH`** — *„Führt ... die angegebene Pfadauflösung aus dem Verzeichnis heraus, das dem FD zugeordnet ist, schlägt `openat()` fehl.“*

Alternativ sind `openat()` relativ zu einem Verzeichnis-FD, das du bereits validiert hast, oder `realpath()` mit anschließender erneuter Validierung die verbleibenden Möglichkeiten, Symlink-Austausch während der Pfadauflösung zu verhindern.

## .fileloc

Dateien mit der Erweiterung **`.fileloc`** können auf andere Anwendungen oder Binärdateien verweisen. Wenn sie geöffnet werden, wird daher die betreffende Anwendung/Binärdatei ausgeführt.\
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

Wenn bei einem Aufruf von `open` das Flag `O_CLOEXEC` fehlt, wird der Dateideskriptor an den Kindprozess vererbt. Öffnet ein privilegierter Prozess also eine privilegierte Datei und führt einen vom Angreifer kontrollierten Prozess aus, **erbt der Angreifer den FD für die privilegierte Datei**.

Das kanonische Beispiel ist die **`DYLD_PRINT_TO_FILE`-LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` berücksichtigte `DYLD_PRINT_TO_FILE=/path` sogar in **restricted (suid root) binaries**, weil diese spezielle Variable außerhalb von `processDyldEnvironmentVariable()` geparst wurde.
- Es führte `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` aus und **erstellte dadurch eine root-owned Datei an einem beliebigen Pfad**.
- Der FD wurde **nie geschlossen und hatte kein close-on-exec-Flag**, sodass jeder Kindprozess des suid-Binaries einen **schreibbaren FD für eine root-owned Datei** erbte.
- Wenn man beispielsweise `DYLD_PRINT_TO_FILE=/etc/target suid_binary` ausführte und anschließend im Kindprozess die Nummer des geerbten FD auslas, waren beliebige Schreibvorgänge in root-owned Dateien möglich; `fcntl(fd, F_SETFL, 0)` entfernte sogar `O_APPEND`, sodass Überschreiben statt Anhängen möglich war.

Dasselbe Muster tritt immer dann auf, wenn ein privilegierter Prozess **vor** dem `exec` einer von dir kontrollierten Anwendung eine Datei öffnet (Hilfsprogramme, über `$EDITOR` aufgerufene Editoren im Stil von `crontab`, Log-/Debug-Dateien, die über einen Umgebungsvariablenpfad geöffnet werden usw.). Ermittle die geerbten FDs mit:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Alles über `2`, das auf eine Datei verweist, die du selbst nicht öffnen kannst, ist ein Arbitrary-Write- (oder Arbitrary-Read-) Primitive.

## Tricks mit Quarantine-xattrs vermeiden

### Entfernen it

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable-Flag

Wenn eine Datei/ein Ordner dieses unveränderliche Attribut hat, kann kein xattr darauf gesetzt werden.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Dateisysteme ohne xattr-Unterstützung

Nicht jedes Dateisystem, das macOS einbinden kann, speichert **erweiterte Attribute** nativ. HFS+ und APFS können das; **FAT32, exFAT und (die meisten) NFS-Einhängungen nicht** – macOS emuliert sie, indem es eine **AppleDouble**-Begleitdatei namens `._<filename>` schreibt ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Das ist für Quarantäne wichtig, denn das xattr bleibt nur erhalten, wenn es tatsächlich auf dasselbe Volume **geschrieben und wieder ausgelesen** werden kann:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Wenn das Volume später über einen Pfad gelesen wird, der die `._`-Begleitdatei ignoriert (oder die Begleitdatei entfernt/gelöscht wird), kommt die Datei **ohne Quarantäne-Flag** an – und eine nicht unter Quarantäne stehende `.app` reicht aus, um der App Sandbox zu entkommen, wie unter [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) beschrieben.

### writeextattr-ACL und AppleDouble-Quarantäneverhalten

Informationen zum `writeextattr`-ACL-Beispiel, zum AppleDouble-Mechanismus `com.apple.acl.text` sowie zu den Schritten für die Erstellung und Validierung der Sidecar-Datei finden Sie unter [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## Signaturprüfungen umgehen

### Prüfungen auf Plattform-Binärdateien umgehen

Manche Sicherheitsprüfungen überprüfen, ob es sich bei der Binärdatei um eine **Plattform-Binärdatei** handelt, beispielsweise um eine Verbindung zu einem XPC-Dienst zu erlauben. Wie in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ bei einem Bypass gezeigt, lässt sich diese Prüfung jedoch umgehen, indem man eine Plattform-Binärdatei (wie `/bin/ls`) nimmt und den Exploit über dyld mithilfe der Umgebungsvariablen `DYLD_INSERT_LIBRARIES` einschleust.<sup>[[7]](#references)</sup>

### Flags `CS_REQUIRE_LV` und `CS_FORCED_LV` umgehen

Eine ausgeführte Binärdatei kann ihre eigenen Flags ändern, um Prüfungen zu umgehen, beispielsweise mit folgendem Code:<sup>[[7]](#references)</sup>

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

Bundles enthalten die Datei **`_CodeSignature/CodeResources`**, die den **Hash** jeder einzelnen **Datei** im **Bundle** enthält. Beachte, dass der Hash von CodeResources auch in die ausführbare Datei **eingebettet** ist, daher können wir auch daran nichts ändern.

Es gibt jedoch einige Dateien, deren Signatur nicht überprüft wird. Diese haben den Schlüssel omit in der plist, zum Beispiel:

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

Es ist möglich, die Signatur einer Ressource über die CLI zu berechnen:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## DMGs mounten

Ein Benutzer kann ein benutzerdefiniertes DMG einhängen, das sogar über einigen vorhandenen Ordnern erstellt wurde. So kannst du ein benutzerdefiniertes DMG-Paket mit eigenen Inhalten erstellen:

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

Normalerweise bindet macOS Datenträger ein, indem es mit dem Mach-Dienst `com.apple.DiskArbitrarion.diskarbitrariond` kommuniziert (bereitgestellt von `/usr/libexec/diskarbitrationd`). Wenn du den Parameter `-d` zur LaunchDaemons-plist-Datei hinzufügst und den Dienst neu startest, werden Logs in `/var/log/diskarbitrationd.log` gespeichert.\
Es ist jedoch möglich, Tools wie `hdik` und `hdiutil` zu verwenden, um direkt mit dem `com.apple.driver.DiskImages`-kext zu kommunizieren.

## Beliebige Schreibvorgänge

### Periodische Shell-Skripte

Wenn dein Skript als **Shell-Skript** interpretiert werden kann, könntest du das Shell-Skript **`/etc/periodic/daily/999.local`** überschreiben, das täglich ausgeführt wird.

Du kannst die Ausführung dieses Skripts mit folgendem Befehl **simulieren**: **`sudo periodic daily`**

### Daemons

Schreibe einen beliebigen **LaunchDaemon** wie **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** mit einer plist, die ein beliebiges Skript ausführt, zum Beispiel:

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

### Sudoers-Datei

Wenn du **arbitrary write** hast, könntest du eine Datei im Ordner **`/etc/sudoers.d/`** erstellen, die dir **sudo**-Berechtigungen gewährt.

### PATH-Dateien

Die Datei **`/etc/paths`** ist eine der wichtigsten Quellen für die PATH-Umgebungsvariable. Du musst root sein, um sie zu überschreiben. Wenn ein Skript eines **privilegierten Prozesses** jedoch einen **Befehl ohne vollständigen Pfad** ausführt, kannst du ihn möglicherweise **hijacken**, indem du diese Datei änderst.

Du kannst auch Dateien in **`/etc/paths.d`** schreiben, um der PATH-Umgebungsvariable neue Ordner hinzuzufügen.

### cups-files.conf

Diese Technik wurde in [diesem Write-up](https://www.kandji.io/blog/macos-audit-story-part1) verwendet.<sup>[[8]](#references)</sup>

Erstelle die Datei `/etc/cups/cups-files.conf` mit folgendem Inhalt:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

Dadurch wird die Datei `/etc/sudoers.d/lpe` mit den Berechtigungen 777 erstellt. Der zusätzliche Müll am Ende dient dazu, die Erstellung des Fehlerprotokolls auszulösen.

Schreibe anschließend die benötigte Konfiguration zur Rechteausweitung in `/etc/sudoers.d/lpe`, zum Beispiel `%staff ALL=(ALL) NOPASSWD:ALL`.

Ändere dann erneut die Datei `/etc/cups/cups-files.conf` und setze `LogFilePerm 700`, damit die neue sudoers-Datei gültig wird, wenn du `cupsctl` aufrufst.

### Sandbox Escape

Es ist möglich, mit einem beliebigen FS-Schreibzugriff aus der macOS-Sandbox auszubrechen. Beispiele findest du auf der Seite [macOS Auto Start](../../../../macos-auto-start-locations.md). Eine gängige Methode ist, eine Terminal-Einstellungsdatei unter `~/Library/Preferences/com.apple.Terminal.plist` zu schreiben, die beim Start einen Befehl ausführt, und sie mit `open` aufzurufen.

## Schreibbare Dateien als andere Benutzer erzeugen

Ein sehr häufiges Privesc-Grundelement besteht darin, **einen privilegierten Prozess eine Datei für dich** in einem Verzeichnis erstellen zu lassen, das du kontrollierst, und anschließend **Schreibzugriff** auf diese Datei zu behalten. Dafür sind zwei Voraussetzungen erforderlich:

1. Ein Verzeichnis, das dir gehört (oder für das du eine **vererbbare ACL** festlegen kannst), sodass alles, was darin erstellt wird, deine Berechtigungen erbt.
2. Ein privilegierter/`suid`-Prozess, dem mitgeteilt werden kann, **wo** er eine Datei erstellen soll – typischerweise über eine Debug-/Logging-Umgebungsvariable, eine Konfigurationsdatei oder die XPC-API eines Helferprogramms.

Der Teil mit der **vererbbaren ACL** sorgt dafür, dass die erstellte Datei für dich beschreibbar ist, obwohl sie einem anderen Benutzer gehört. Die Vererbungsflags `file_inherit` / `directory_inherit` sind in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) dokumentiert:<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Jetzt ist jede Datei, die ein privilegierter Prozess innerhalb von `$DIRNAME` erstellt, **für dich beschreibbar**. Wenn dieses Verzeichnis außerdem ein Ort ist, dessen Inhalt später **als root ausgeführt** wird (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, ein LaunchDaemon-Verzeichnis ...), führt das direkt zu einer Root-Eskalation. In den obigen Abschnitten [Sudoers File](#sudoers-file) und [cups-files.conf](#cups-filesconf) findest du, was du in die Datei schreiben musst, sobald du sie hast.

Ein vollständiges Beispiel für die Kette „Eine Umgebungsvariable veranlasst einen Root-Prozess, eine Datei zu erstellen, und der FD wird an dich geleakt“ findest du oben unter [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec).

## POSIX Shared Memory

**POSIX shared memory** ermöglicht es Prozessen in POSIX-konformen Betriebssystemen, auf einen gemeinsamen Speicherbereich zuzugreifen, wodurch eine schnellere Kommunikation als mit anderen Interprozesskommunikationsmethoden möglich ist. Dazu wird mit `shm_open()` ein Shared-Memory-Objekt erstellt oder geöffnet, seine Größe mit `ftruncate()` festgelegt und es mithilfe von `mmap()` in den Adressraum des Prozesses eingeblendet. Anschließend können Prozesse direkt aus diesem Speicherbereich lesen und in ihn schreiben. Um den gleichzeitigen Zugriff zu verwalten und Datenkorruption zu verhindern, werden häufig Synchronisierungsmechanismen wie Mutexes oder Semaphoren verwendet. Schließlich heben Prozesse die Speicherzuordnung mit `munmap()` auf und schließen den Shared Memory mit `close()`. Optional können sie das Speicherobjekt mit `shm_unlink()` entfernen. Dieses System eignet sich besonders gut für eine effiziente, schnelle IPC in Umgebungen, in denen mehrere Prozesse schnell auf gemeinsam genutzte Daten zugreifen müssen.

<details>

<summary>Producer Code Example</summary>

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

<summary>Verbraucher-Codebeispiel</summary>

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

**macOS Guarded Descriptors** sind eine in macOS eingeführte Sicherheitsfunktion, die die Sicherheit und Zuverlässigkeit von **Datei-Deskriptor-Operationen** in Benutzeranwendungen verbessern soll. Diese Guarded Descriptors ermöglichen es, bestimmte Einschränkungen oder „Guards“ mit Datei-Deskriptoren zu verknüpfen, die vom Kernel durchgesetzt werden.

Diese Funktion ist besonders nützlich, um bestimmte Arten von Sicherheitslücken wie **unbefugten Dateizugriff** oder **Race Conditions** zu verhindern. Diese Sicherheitslücken treten beispielsweise auf, wenn ein Thread auf eine Datei zugreift und dadurch **einem anderen, anfälligen Thread Zugriff darauf gewährt**, oder wenn ein Datei-Deskriptor von einem anfälligen Kindprozess **geerbt** wird. Einige Funktionen im Zusammenhang mit dieser Funktionalität sind:

- `guarded_open_np`: Öffnet einen Datei-Deskriptor mit einem Guard
- `guarded_close_np`: Schließt ihn
- `change_fdguard_np`: Ändert die Guard-Flags eines Deskriptors (und kann den Guard-Schutz sogar entfernen)

## References

- [1] [POSIX.1-2024 — Grundlegende Definitionen, Kap. 4 (Dateizugriffsrechte, Verzeichnisschutz, Auflösung von Pfadnamen)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)`-Manpage](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)`-Manpage](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - Lokale Rechteausweitung über DYLD_PRINT_TO_FILE in OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Welche Dateisysteme und Cloud-Dienste Extended Attributes erhalten](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - Eine neue Ära von macOS-Sandbox-Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Apple-Sicherheitslücken aufgedeckt: Die Audit-Geschichte von diskarbitrationd und storagekitd, Teil 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
