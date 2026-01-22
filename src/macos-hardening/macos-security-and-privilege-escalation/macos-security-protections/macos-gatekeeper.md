# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ist eine Sicherheitsfunktion für macOS, die dafür entwickelt wurde sicherzustellen, dass Benutzer **nur vertrauenswürdige Software ausführen**. Sie funktioniert, indem sie die Software **validiert**, die ein Benutzer aus **Quellen außerhalb des App Store** herunterlädt und zu öffnen versucht, wie z. B. eine App, ein Plug-in oder ein Installer-Paket.

Der Kernmechanismus von Gatekeeper liegt in seinem **Verifizierungsprozess**. Er prüft, ob die heruntergeladene Software **von einem anerkannten Entwickler signiert** ist, um die Echtheit der Software sicherzustellen. Außerdem stellt er fest, ob die Software von Apple **notarisiert** wurde, womit bestätigt wird, dass sie keine bekannten schädlichen Inhalte enthält und nach der Notarisierung nicht manipuliert wurde.

Zusätzlich stärkt Gatekeeper die Benutzerkontrolle und Sicherheit, indem er Benutzer beim ersten Öffnen heruntergeladener Software dazu **auffordert, das Öffnen zu genehmigen**. Diese Schutzmaßnahme hilft zu verhindern, dass Benutzer versehentlich potenziell schädlichen ausführbaren Code ausführen, den sie für eine harmlose Datendatei gehalten haben könnten.

### Anwendungssignaturen

Anwendungssignaturen, auch bekannt als Code-Signaturen, sind ein kritischer Bestandteil von Apples Sicherheitsinfrastruktur. Sie werden verwendet, um die **Identität des Softwareautors** (des Entwicklers) zu **verifizieren** und sicherzustellen, dass der Code seit der letzten Signierung nicht manipuliert wurde.

So funktioniert es:

1. **Signieren der Anwendung:** Wenn ein Entwickler bereit ist, seine Anwendung zu verteilen, **signiert er die Anwendung mit einem privaten Schlüssel**. Dieser private Schlüssel ist mit einem **Zertifikat verbunden, das Apple dem Entwickler ausstellt**, wenn er sich im Apple Developer Program anmeldet. Der Signiervorgang erstellt einen kryptografischen Hash aller Teile der App und verschlüsselt diesen Hash mit dem privaten Schlüssel des Entwicklers.
2. **Verteilen der Anwendung:** Die signierte Anwendung wird dann zusammen mit dem Zertifikat des Entwicklers an Benutzer verteilt, welches den entsprechenden öffentlichen Schlüssel enthält.
3. **Überprüfen der Anwendung:** Wenn ein Benutzer die Anwendung herunterlädt und auszuführen versucht, verwendet sein macOS den öffentlichen Schlüssel aus dem Zertifikat des Entwicklers, um den Hash zu entschlüsseln. Es berechnet dann den Hash basierend auf dem aktuellen Zustand der Anwendung neu und vergleicht diesen mit dem entschlüsselten Hash. Stimmen beide überein, bedeutet dies, dass **die Anwendung seit der Signierung nicht verändert wurde**, und das System erlaubt das Ausführen der Anwendung.

Anwendungssignaturen sind ein wesentlicher Bestandteil der Gatekeeper-Technologie von Apple. Wenn ein Benutzer versucht, **eine aus dem Internet heruntergeladene Anwendung zu öffnen**, prüft Gatekeeper die Anwendungssignatur. Ist sie mit einem von Apple an einen bekannten Entwickler ausgestellten Zertifikat signiert und der Code wurde nicht manipuliert, erlaubt Gatekeeper das Ausführen der Anwendung. Andernfalls blockiert er die Anwendung und warnt den Benutzer.

Seit macOS Catalina prüft **Gatekeeper außerdem, ob die Anwendung von Apple notarisiert wurde**, und fügt damit eine zusätzliche Sicherheitsebene hinzu. Der Notarisierungsprozess untersucht die Anwendung auf bekannte Sicherheitsprobleme und bösartigen Code; wenn diese Prüfungen bestanden werden, fügt Apple der Anwendung ein Ticket hinzu, das Gatekeeper verifizieren kann.

#### Signaturen prüfen

Beim Überprüfen einer **malware sample** sollte man immer die **Signatur** der Binärdatei prüfen, da der **Entwickler**, der sie signiert hat, möglicherweise bereits mit **malware** in Verbindung steht.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarisierung

Der Notarisierungsprozess von Apple dient als zusätzliche Schutzmaßnahme, um Benutzer vor potenziell schädlicher Software zu schützen. Er umfasst, dass der **Entwickler seine Anwendung zur Prüfung einreicht** bei **Apples Notary Service**, was nicht mit App Review zu verwechseln ist. Dieser Dienst ist ein **automatisiertes System**, das die eingereichte Software auf **bösartige Inhalte** und mögliche Probleme mit dem Code-Signing prüft.

Wenn die Software diese Prüfung **bestanden** hat, ohne Bedenken zu erzeugen, erstellt der Notary Service ein Notarisierungs-Ticket. Der Entwickler muss dieses Ticket dann an seiner Software **anheften** (sogenanntes 'stapling'). Außerdem wird das Notarisierungs-Ticket online veröffentlicht, wo Gatekeeper, Apples Sicherheitstechnik, darauf zugreifen kann.

Bei der ersten Installation oder Ausführung der Software teilt das Vorhandensein des Notarisierungs-Tickets — ob am ausführbaren Programm 'gestapelt' oder online verfügbar — **Gatekeeper mit, dass die Software von Apple notariell geprüft wurde**. Infolgedessen zeigt Gatekeeper im ersten Startdialog eine erläuternde Meldung an, die darauf hinweist, dass Apple die Software auf bösartige Inhalte überprüft hat. Dieser Prozess erhöht somit das Vertrauen der Benutzer in die Sicherheit der Software, die sie auf ihren Systemen installieren oder ausführen.

### spctl & syspolicyd

> [!CAUTION]
> Beachte, dass ab der Sequoia-Version **`spctl`** nicht mehr erlaubt ist, die Gatekeeper-Konfiguration zu ändern.

**`spctl`** ist das CLI-Tool, um Gatekeeper aufzulisten und damit zu interagieren (mit dem `syspolicyd`-Daemon über XPC-Nachrichten). Zum Beispiel kann man den **Status** von GateKeeper mit folgendem Befehl sehen:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Beachte, dass GateKeeper-Signaturprüfungen nur für **Dateien mit dem Quarantine attribute** durchgeführt werden, nicht für jede Datei.

GateKeeper überprüft, ob gemäß den **Einstellungen & der Signatur** ein binary ausgeführt werden kann:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ist der Hauptdaemon, der für die Durchsetzung von GateKeeper verantwortlich ist. Er verwaltet eine Datenbank unter `/var/db/SystemPolicy` und den Code zur Unterstützung der Datenbank findet man [hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) und die [SQL-Vorlage hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Beachte, dass die Datenbank nicht durch SIP eingeschränkt ist und von root beschreibbar ist; die Datenbank `/var/db/.SystemPolicy-default` wird als Original-Backup verwendet, falls die andere beschädigt wird.

Außerdem enthalten die Bundles **`/var/db/gke.bundle`** und **`/var/db/gkopaque.bundle`** Dateien mit Regeln, die in die Datenbank eingefügt werden. Du kannst diese Datenbank als root mit folgendem Befehl prüfen:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** stellt außerdem einen XPC-Server mit verschiedenen Operationen wie `assess`, `update`, `record` und `cancel` bereit, die auch über die **`Security.framework`'s `SecAssessment*`** APIs erreichbar sind, und **`spctl`** kommuniziert tatsächlich über XPC mit **`syspolicyd`**.

Beachte, wie die erste Regel mit "**App Store**" endete und die zweite mit "**Developer ID**" und dass im vorherigen Bild **zum Ausführen von Apps aus dem App Store und von identifizierten Entwicklern aktiviert war**.\
Wenn du diese Einstellung auf App Store **änderst**, werden die "**Notarized Developer ID" Regeln verschwinden**.

Es gibt auch Tausende von Regeln vom **Typ GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Die folgenden hashes stammen aus:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Oder du könntest die vorherigen Informationen mit:
```bash
sudo spctl --list
```
Die Optionen **`--master-disable`** und **`--global-disable`** von **`spctl`** setzen diese Signaturprüfungen vollständig auf **disable**:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wenn vollständig aktiviert ist, erscheint eine neue Option:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Es ist möglich, **zu prüfen, ob eine App von GateKeeper erlaubt wird**, mit:
```bash
spctl --assess -v /Applications/App.app
```
Es ist möglich, in GateKeeper neue Regeln hinzuzufügen, um die Ausführung bestimmter Apps zu erlauben:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
Bezüglich **kernel extensions** enthält der Ordner `/var/db/SystemPolicyConfiguration` Dateien mit Listen von kexts, die geladen werden dürfen. Außerdem besitzt `spctl` das Entitlement `com.apple.private.iokit.nvram-csr`, da es neue vorab genehmigte kernel extensions hinzufügen kann, die außerdem im NVRAM unter dem Schlüssel `kext-allowed-teams` gespeichert werden müssen.

#### Verwaltung von Gatekeeper unter macOS 15 (Sequoia) und später

- Der langjährige Finder‑Bypass **Ctrl+Open / Right‑click → Open** wurde entfernt; Nutzer müssen eine blockierte App nach dem ersten Blockdialog explizit über **Systemeinstellungen → Datenschutz & Sicherheit → Trotzdem öffnen** zulassen.
- `spctl --master-disable/--global-disable` werden nicht mehr akzeptiert; `spctl` ist effektiv schreibgeschützt für Überprüfungs- und Label‑Verwaltung, während die Durchsetzung der Richtlinien über die Benutzeroberfläche oder MDM konfiguriert wird.

Ab macOS 15 Sequoia können Endbenutzer die Gatekeeper‑Richtlinie nicht mehr über `spctl` umschalten. Die Verwaltung erfolgt über die Systemeinstellungen oder durch Bereitstellung eines MDM-Konfigurationsprofils mit dem Payload `com.apple.systempolicy.control`. Beispiel eines Profilausschnitts, um den App Store und identifizierte Entwickler zu erlauben (aber nicht "Anywhere"):

<details>
<summary>MDM-Profil, um App Store und identifizierte Entwickler zu erlauben</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Dateien in Quarantäne

Beim **Herunterladen** einer Anwendung oder Datei hängen bestimmte macOS **Anwendungen**, wie Webbrowser oder E-Mail-Clients, ein erweitertes Datei-Attribut an die heruntergeladene Datei an, das allgemein als "**Quarantäne-Flag**" bekannt ist. Dieses Attribut dient als Sicherheitsmaßnahme, um die Datei als aus einer nicht vertrauenswürdigen Quelle (dem Internet) stammend zu **kennzeichnen** und möglicherweise Risiken zu bergen. Allerdings fügen nicht alle Anwendungen dieses Attribut hinzu; zum Beispiel umgehen gängige BitTorrent-Clients diesen Prozess in der Regel.

**Das Vorhandensein eines Quarantäne-Flags weist die Sicherheitsfunktion Gatekeeper von macOS darauf hin, wenn ein Benutzer versucht, die Datei auszuführen.**

Wenn das **Quarantäne-Flag nicht vorhanden ist** (wie bei Dateien, die über manche BitTorrent-Clients heruntergeladen wurden), werden die **Prüfungen von Gatekeeper möglicherweise nicht durchgeführt**. Daher sollten Benutzer beim Öffnen von Dateien, die aus weniger sicheren oder unbekannten Quellen stammen, Vorsicht walten lassen.

> [!NOTE] > **Das Überprüfen** der **Gültigkeit** von Code-Signaturen ist ein **ressourcenintensiver** Prozess, der das Erzeugen kryptografischer **Hashes** des Codes und aller gebündelten Ressourcen umfasst. Darüber hinaus beinhaltet die Überprüfung der Zertifikatsgültigkeit eine **Online-Überprüfung** bei Apples Servern, um zu prüfen, ob es nach der Ausstellung widerrufen wurde. Aus diesen Gründen ist eine vollständige Prüfung der Code-Signatur und Notarisierung **unpraktisch, um sie bei jedem Start einer App durchzuführen**.
>
> Daher werden diese Prüfungen **nur ausgeführt, wenn Apps mit dem Quarantäne-Attribut ausgeführt werden.**

> [!WARNING]
> Dieses Attribut muss von der Anwendung, die die Datei erstellt/herunterlädt, **gesetzt werden**.
>
> Dateien, die sandboxed sind, erhalten dieses Attribut jedoch für jede von ihnen erstellte Datei. Nicht-sandboxed Apps können es selbst setzen oder den [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) Schlüssel in der **Info.plist** angeben, wodurch das System das `com.apple.quarantine` erweiterte Attribut auf den erstellten Dateien setzt,

Außerdem werden alle Dateien, die von einem Prozess erstellt werden, der **`qtn_proc_apply_to_self`** aufruft, in Quarantäne gesetzt. Oder die API **`qtn_file_apply_to_path`** fügt das Quarantäne-Attribut zu einem angegebenen Dateipfad hinzu.

Es ist möglich, seinen Status zu **prüfen** und (Root-Rechte erforderlich) zu **aktivieren/deaktivieren** mit:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Sie können außerdem **prüfen, ob eine Datei das erweiterte Attribut quarantine besitzt** mit:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Überprüfe den **Wert** der **erweiterten** **Attribute** und finde heraus, welche App das quarantine-Attribut geschrieben hat mit:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Tatsächlich könnte ein Prozess "Quarantäne-Flags für die von ihm erstellten Dateien setzen" (ich habe bereits versucht, das USER_APPROVED-Flag in einer erstellten Datei anzuwenden, aber es wird nicht gesetzt):

<details>

<summary>Quellcode zum Setzen von Quarantäne-Flags</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

Und **entferne** dieses Attribut mit:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Und finde alle unter Quarantäne gestellten Dateien mit:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** which allows the GUI to obtain data about the file origins. Moreover this can be overwritten by applications which might be interested in hiding its origins. Moreover, this can be done from LaunchServices APIS.

#### **libquarantine.dylib**

This library exports several functions that allow to manipulate the extended attribute fields.

The `qtn_file_*` APIs deal with file quarantine policies, the `qtn_proc_*` APIs are applied to processes (files created by the process). The unexported `__qtn_syscall_quarantine*` functions are the ones that applies the policies which calls `mac_syscall` with "Quarantine" as first argument which sends the requests to `Quarantine.kext`.

#### **Quarantine.kext**

The kernel extension is only available through the **kernel cache on the system**; however, you _can_ download the **Kernel Debug Kit from** [**https://developer.apple.com/**](https://developer.apple.com/), which will contain a symbolicated version of the extension.

This Kext will hook via MACF several calls in order to traps all file lifecycle events: Creation, opening, renaming, hard-linkning... even `setxattr` to prevent it from setting the `com.apple.quarantine` extended attribute.

It also uses a couple of MIBs:

- `security.mac.qtn.sandbox_enforce`: Enforce quarantine along Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs can only execute approved files

#### Provenance xattr (Ventura and later)

macOS 13 Ventura introduced a separate provenance mechanism which is populated the first time a quarantined app is allowed to run. Two artefacts are created:

- The `com.apple.provenance` xattr on the `.app` bundle directory (fixed-size binary value containing a primary key and flags).
- A row in the `provenance_tracking` table inside the ExecPolicy database at `/var/db/SystemPolicyConfiguration/ExecPolicy/` storing the app’s cdhash and metadata.

Practical usage:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect ist eine integrierte **Anti-Malware**-Funktion in macOS. XProtect **prüft jede Anwendung beim ersten Start oder nach Änderungen anhand seiner Datenbank** bekannter Malware und unsicherer Dateitypen. Wenn du eine Datei über bestimmte Apps wie Safari, Mail oder Messages herunterlädst, scannt XProtect die Datei automatisch. Wenn sie mit einer bekannten Malware in der Datenbank übereinstimmt, wird XProtect **die Ausführung der Datei verhindern** und dich vor der Bedrohung warnen.

Die XProtect-Datenbank wird von Apple regelmäßig mit neuen Malware-Definitionen **aktualisiert**, und diese Updates werden automatisch auf deinem Mac heruntergeladen und installiert. Das stellt sicher, dass XProtect stets auf dem neuesten Stand der bekannten Bedrohungen ist.

Es ist jedoch wichtig zu beachten, dass **XProtect keine vollwertige Antivirus-Lösung** ist. Es prüft nur eine bestimmte Liste bekannter Bedrohungen und führt kein On-Access-Scanning wie die meisten Antivirusprogramme durch.

Informationen zum neuesten XProtect-Update erhältst du, indem du Folgendes ausführst:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect befindet sich an einem durch SIP geschützten Ort unter **/Library/Apple/System/Library/CoreServices/XProtect.bundle** und innerhalb des Bundles finden Sie Informationen, die XProtect verwendet:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Ermöglicht Code mit diesen cdhashes, legacy entitlements zu verwenden.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Liste von Plugins und Erweiterungen, die über BundleID und TeamID daran gehindert werden zu laden oder die eine Mindestversion angeben.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-Regeln zur Erkennung von Malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-Datenbank mit Hashes blockierter Anwendungen und TeamIDs.

Beachte, dass es eine weitere App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** gibt, die mit XProtect zusammenhängt, aber nicht am Gatekeeper-Prozess beteiligt ist.

> XProtect Remediator: Auf modernen macOS-Systemen liefert Apple On-Demand-Scanner (XProtect Remediator) aus, die periodisch via launchd laufen, um Malware-Familien zu erkennen und zu beseitigen. Du kannst diese Scans in den unified logs beobachten:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nicht Gatekeeper

> [!CAUTION]
> Beachte, dass Gatekeeper **nicht jedes Mal ausgeführt wird**, wenn du eine Anwendung startest; nur _**AppleMobileFileIntegrity**_ (AMFI) wird **die Signaturen ausführbaren Codes verifizieren**, wenn du eine App ausführst, die bereits von Gatekeeper ausgeführt und verifiziert wurde.

Früher war es daher möglich, eine App auszuführen, um sie von Gatekeeper cachen zu lassen, und dann **nicht-ausführbare Dateien der Anwendung zu verändern** (wie Electron asar oder NIB-Dateien). Wenn keine weiteren Schutzmaßnahmen vorhanden waren, wurde die Anwendung mit den **bösartigen** Ergänzungen **ausgeführt**.

Heute ist das jedoch nicht mehr möglich, weil macOS das **Ändern von Dateien** innerhalb von Application-Bundles verhindert. Wenn du also den [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) Angriff ausprobierst, wirst du feststellen, dass er nicht mehr ausnutzbar ist, denn nachdem die App zum Cache mit Gatekeeper ausgeführt wurde, kannst du das Bundle nicht mehr ändern. Und wenn du zum Beispiel den Namen des Contents-Verzeichnisses in NotCon änderst (wie im Exploit angegeben) und dann die Haupt-Binärdatei der App ausführst, um sie mit Gatekeeper zu cachen, wird ein Fehler ausgelöst und die Ausführung schlägt fehl.

## Gatekeeper-Umgehungen

Jeder Weg, Gatekeeper zu umgehen (d. h. den Nutzer dazu zu bringen, etwas herunterzuladen und auszuführen, obwohl Gatekeeper dies verweigern sollte), gilt als Sicherheitslücke in macOS. Hier sind einige CVEs, die Techniken betreffen, mit denen Gatekeeper in der Vergangenheit umgangen werden konnte:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Es wurde beobachtet, dass bei Verwendung des **Archive Utility** zum Entpacken Dateien mit **Pfaden, die 886 Zeichen überschreiten**, kein com.apple.quarantine Extended Attribute erhalten. Dies ermöglicht es diesen Dateien unbeabsichtigt, die Sicherheitsprüfungen von Gatekeeper zu **umgehen**.

Siehe den [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) für weitere Informationen.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wenn eine Anwendung mit **Automator** erstellt wird, liegen die Informationen darüber, was zur Ausführung benötigt wird, in `application.app/Contents/document.wflow` und nicht im ausführbaren Programm. Die ausführbare Datei ist nur ein generisches Automator-Binary namens **Automator Application Stub**.

Deshalb konnte man `application.app/Contents/MacOS/Automator\ Application\ Stub` **mithilfe eines symbolischen Links auf einen anderen Automator Application Stub im System verweisen**, und es wurde ausgeführt, was in `document.wflow` enthalten ist (dein Script), **ohne Gatekeeper auszulösen**, weil das tatsächliche Executable kein quarantine xattr hatte.

Erwarteter Speicherort des Beispiels: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Siehe den [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) für weitere Informationen.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bei diesem Bypass wurde ein Zip-Archiv erstellt, bei dem die Kompression mit `application.app/Contents` begann statt mit `application.app`. Daher wurde das **quarantine-Attribut** auf alle **Dateien aus `application.app/Contents`** angewendet, jedoch **nicht auf `application.app`**, das Gatekeeper prüft. Gatekeeper wurde deshalb umgangen, weil `application.app` beim Auslösen **nicht das quarantine-Attribut** hatte.
```bash
zip -r test.app/Contents test.zip
```
Siehe den [**Originalbericht**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) für weitere Informationen.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Auch wenn die Komponenten unterschiedlich sind, ist die Ausnutzung dieser Schwachstelle der vorherigen sehr ähnlich. In diesem Fall wird ein Apple-Archiv aus **`application.app/Contents`** erzeugt, sodass **`application.app` won't get the quarantine attr** beim Dekomprimieren durch **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Siehe den [**Originalbericht**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) für weitere Informationen.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kann verwendet werden, um zu verhindern, dass jemand ein Attribut in eine Datei schreibt:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Außerdem kopiert das **AppleDouble**-Dateiformat eine Datei inklusive ihrer ACEs.

Im [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die als xattr namens **`com.apple.acl.text`** gespeicherte ACL-Textrepräsentation als ACL in der dekomprimierten Datei gesetzt wird. Also, wenn du eine Anwendung in eine Zip-Datei im **AppleDouble**-Format mit einer ACL komprimiert hast, die verhindert, dass andere xattrs darauf geschrieben werden... wurde das quarantine xattr nicht in die Anwendung gesetzt:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Siehe den [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) für weitere Informationen.

Beachte, dass dies auch mit AppleArchives ausgenutzt werden könnte:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Es wurde entdeckt, dass **Google Chrome das Quarantäne-Attribut nicht für heruntergeladene Dateien gesetzt hat**, aufgrund einiger interner macOS-Probleme.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble-Dateiformate speichern die Attribute einer Datei in einer separaten Datei, die mit `._` beginnt; das hilft, Dateiattribute **zwischen macOS-Rechnern** zu kopieren. Es wurde jedoch festgestellt, dass nach dem Dekomprimieren einer AppleDouble-Datei die mit `._` beginnende Datei **nicht mit dem Quarantäne-Attribut versehen wurde**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Wenn man eine Datei erstellen konnte, bei der das quarantine attribute nicht gesetzt war, war es **möglich, Gatekeeper zu umgehen.** Der Trick bestand darin, eine **DMG file application** unter Verwendung der AppleDouble name convention (beginne sie mit `._`) zu erstellen und eine **sichtbare Datei als sym link zu dieser versteckten** Datei ohne quarantine attribute zu erstellen.\
Wenn die **dmg file ausgeführt wird**, da sie kein quarantine attribute hat, wird sie **Gatekeeper umgehen**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

Eine Gatekeeper-Umgehung, die in macOS Sonoma 14.0 behoben wurde, erlaubte manipulierten Apps, ohne Aufforderung ausgeführt zu werden. Details wurden nach der Veröffentlichung des Patches öffentlich bekanntgegeben und das Problem wurde vor der Behebung aktiv in freier Wildbahn ausgenutzt. Stelle sicher, dass Sonoma 14.0 oder neuer installiert ist.

### [CVE-2024-27853]

Eine Gatekeeper-Umgehung in macOS 14.4 (veröffentlicht März 2024), die auf die `libarchive`-Verarbeitung bösartiger ZIPs zurückgeht, erlaubte es Apps, der Überprüfung zu entgehen. Aktualisiere auf 14.4 oder neuer, wo Apple das Problem behoben hat.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Ein **Automator Quick Action workflow**, der in einer heruntergeladenen App eingebettet war, konnte ohne Gatekeeper-Prüfung ausgelöst werden, weil Workflows als Daten behandelt und vom Automator-Helfer außerhalb des normalen Notarisierungs-Aufforderungswegs ausgeführt wurden. Eine manipulierte `.app`, die eine Quick Action enthält, die ein Shell-Skript ausführt (z. B. innerhalb von `Contents/PlugIns/*.workflow/Contents/document.wflow`), konnte beim Start sofort ausgeführt werden. Apple fügte einen zusätzlichen Zustimmungsdialog hinzu und behob den Bewertungsweg in Ventura **13.7**, Sonoma **14.7** und Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Mehrere Schwachstellen in populären Entpack-Tools (z. B. The Unarchiver) führten dazu, dass aus Archiven extrahierte Dateien das xattr `com.apple.quarantine` nicht erhielten, was Gatekeeper-Umgehungsmöglichkeiten eröffnete. Verlasse dich beim Testen immer auf das macOS Archive Utility oder gepatchte Tools und überprüfe die xattr nach dem Entpacken.

### uchg (aus diesem [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Erstelle ein Verzeichnis, das eine App enthält.
- Füge uchg zur App hinzu.
- Komprimiere die App zu einer tar.gz-Datei.
- Sende die tar.gz-Datei an ein Opfer.
- Das Opfer öffnet die tar.gz-Datei und führt die App aus.
- Gatekeeper prüft die App nicht.

### Prevent Quarantine xattr

In einem ".app"-Bundle: wenn das Quarantine-xattr nicht hinzugefügt wird, wird beim Ausführen **Gatekeeper nicht ausgelöst**.


## References

- Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: How macOS now tracks the provenance of apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
