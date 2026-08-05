# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ist eine für Mac-Betriebssysteme entwickelte Sicherheitsfunktion, die sicherstellen soll, dass Benutzer auf ihren Systemen **nur vertrauenswürdige Software ausführen**. Sie validiert **Software**, die ein Benutzer herunterlädt und aus **Quellen außerhalb des App Store** zu öffnen versucht, beispielsweise eine App, ein Plug-in oder ein Installationspaket.

Der zentrale Mechanismus von Gatekeeper ist der **Überprüfungsprozess**. Dabei wird geprüft, ob die heruntergeladene Software **von einem anerkannten Entwickler signiert** wurde, um ihre Authentizität sicherzustellen. Außerdem wird festgestellt, ob die Software **von Apple notarisiert** wurde. Dadurch wird bestätigt, dass sie keine bekannte schädliche Inhalte enthält und nach der Notarisierung nicht manipuliert wurde.

Zusätzlich stärkt Gatekeeper die Kontrolle und Sicherheit der Benutzer, indem es sie **zum Bestätigen des erstmaligen Öffnens** heruntergeladener Software auffordert. Dieser Schutz hilft zu verhindern, dass Benutzer versehentlich potenziell schädlichen ausführbaren Code ausführen, den sie möglicherweise für eine harmlose Datendatei gehalten haben.

### Anwendungssignaturen

Anwendungssignaturen, auch als Codesignaturen bezeichnet, sind ein wesentlicher Bestandteil der Sicherheitsinfrastruktur von Apple. Sie werden verwendet, um **die Identität des Softwareautors** (des Entwicklers) zu **überprüfen** und sicherzustellen, dass der Code seit seiner letzten Signierung nicht manipuliert wurde.

So funktioniert es:

1. **Signieren der Anwendung:** Wenn ein Entwickler bereit ist, seine Anwendung zu verteilen, **signiert er die Anwendung mithilfe eines privaten Schlüssels**. Dieser private Schlüssel ist mit einem **Zertifikat verknüpft, das Apple dem Entwickler ausstellt**, wenn dieser sich im Apple Developer Program registriert. Beim Signieren wird ein kryptografischer Hash aller Bestandteile der App erstellt und dieser Hash mit dem privaten Schlüssel des Entwicklers verschlüsselt.
2. **Verteilen der Anwendung:** Die signierte Anwendung wird anschließend zusammen mit dem Entwicklerzertifikat an die Benutzer verteilt. Dieses enthält den zugehörigen öffentlichen Schlüssel.
3. **Überprüfen der Anwendung:** Wenn ein Benutzer die Anwendung herunterlädt und auszuführen versucht, verwendet das Mac-Betriebssystem den öffentlichen Schlüssel aus dem Entwicklerzertifikat, um den Hash zu entschlüsseln. Anschließend wird der Hash anhand des aktuellen Zustands der Anwendung erneut berechnet und mit dem entschlüsselten Hash verglichen. Stimmen sie überein, bedeutet dies, dass **die Anwendung seit ihrer Signierung durch den Entwickler nicht verändert wurde**, und das System erlaubt die Ausführung der Anwendung.

Anwendungssignaturen sind ein wesentlicher Bestandteil der Gatekeeper-Technologie von Apple. Wenn ein Benutzer versucht, **eine aus dem Internet heruntergeladene Anwendung zu öffnen**, überprüft Gatekeeper die Anwendungssignatur. Wenn sie mit einem von Apple für einen bekannten Entwickler ausgestellten Zertifikat signiert wurde und der Code nicht manipuliert wurde, erlaubt Gatekeeper die Ausführung der Anwendung. Andernfalls blockiert es die Anwendung und warnt den Benutzer.

Ab macOS Catalina überprüft **Gatekeeper außerdem, ob die Anwendung von Apple notarisiert wurde**, wodurch eine zusätzliche Sicherheitsebene geschaffen wird. Beim Notarisierungsprozess wird die Anwendung auf bekannte Sicherheitsprobleme und schädlichen Code geprüft. Wenn diese Prüfungen erfolgreich sind, fügt Apple der Anwendung ein Ticket hinzu, das Gatekeeper überprüfen kann.

#### Signaturen überprüfen

Beim Überprüfen eines **Malware-Samples** solltest du immer **die Signatur überprüfen**, da der Entwickler, der es signiert hat, möglicherweise bereits **mit Malware in Verbindung steht.**
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

Der Notarisierungsprozess von Apple dient als zusätzliche Schutzmaßnahme, um Benutzer vor potenziell schädlicher Software zu schützen. Dabei **reicht der Entwickler seine Anwendung zur Prüfung** durch den **Apple Notary Service** ein, der nicht mit dem App Review verwechselt werden sollte. Dieser Service ist ein **automatisiertes System**, das die eingereichte Software auf **schädliche Inhalte** und mögliche Probleme bei der Code-Signierung untersucht.

Wenn die Software diese Prüfung **besteht**, ohne Bedenken zu verursachen, erstellt der Notary Service ein Notarisierungs-Ticket. Der Entwickler muss dieses Ticket anschließend **an seine Software anhängen**. Dieser Vorgang wird als „Stapling“ bezeichnet. Außerdem wird das Notarisierungs-Ticket online veröffentlicht, wo Gatekeeper, Apples Sicherheitstechnologie, darauf zugreifen kann.

Bei der ersten Installation oder Ausführung der Software durch den Benutzer **informiert das Vorhandensein des Notarisierungs-Tickets - unabhängig davon, ob es an die ausführbare Datei angeheftet oder online gefunden wurde - Gatekeeper darüber, dass die Software von Apple notariell beglaubigt wurde**. Daraufhin zeigt Gatekeeper im Dialogfeld beim ersten Start eine beschreibende Meldung an, die darauf hinweist, dass die Software von Apple auf schädliche Inhalte überprüft wurde. Dieser Prozess stärkt somit das Vertrauen der Benutzer in die Sicherheit der Software, die sie auf ihren Systemen installieren oder ausführen.

### spctl & syspolicyd

> [!CAUTION]
> Beachte, dass **`spctl`** ab der Sequoia-Version keine Änderungen an der Gatekeeper-Konfiguration mehr zulässt.

**`spctl`** ist das CLI-Tool zum Auflisten und Interagieren mit Gatekeeper (über den `syspolicyd`-Daemon mittels XPC-Nachrichten). Beispielsweise kann der **Status** von GateKeeper mit folgendem Befehl angezeigt werden:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Beachte, dass GateKeeper-Signaturprüfungen nur für **Dateien mit dem Quarantine-Attribut** durchgeführt werden, nicht für jede Datei.

GateKeeper prüft anhand der **Einstellungen und der Signatur**, ob ein Binary ausgeführt werden kann:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ist der wichtigste Daemon, der für die Durchsetzung von Gatekeeper verantwortlich ist. Er verwaltet eine Datenbank unter `/var/db/SystemPolicy`. Den Code zur Unterstützung der [Datenbank findest du hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) und das [SQL-Template hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Beachte, dass die Datenbank nicht durch SIP beschränkt und für root beschreibbar ist. Die Datenbank `/var/db/.SystemPolicy-default` wird als ursprüngliches Backup verwendet, falls die andere beschädigt wird.

Außerdem enthalten die Bundles **`/var/db/gke.bundle`** und **`/var/db/gkopaque.bundle`** Dateien mit Regeln, die in die Datenbank eingefügt werden. Du kannst diese Datenbank als root überprüfen mit:
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
**`syspolicyd`** stellt außerdem einen XPC-Server mit verschiedenen Operationen wie `assess`, `update`, `record` und `cancel` bereit, die ebenfalls über die **`Security.framework`-APIs `SecAssessment*`** erreichbar sind, und **`spctl`** kommuniziert tatsächlich über XPC mit **`syspolicyd`**.

Beachte, dass die erste Regel mit "**App Store**" und die zweite mit "**Developer ID**" endete und dass im vorherigen Bild die Ausführung von Apps aus dem **App Store** und von identifizierten Entwicklern **aktiviert war**.\
Wenn du diese Einstellung auf den App Store **änderst**, verschwinden die Regeln für "**Notarized Developer ID**".

Es gibt außerdem Tausende von Regeln vom **Typ GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Dies sind Hashes aus:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Oder du könntest die vorherigen Informationen mit folgendem Befehl auflisten:
```bash
sudo spctl --list
```
Die Optionen **`--master-disable`** und **`--global-disable`** von **`spctl`** werden diese Signaturprüfungen vollständig **deaktivieren**:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wenn die Option vollständig aktiviert ist, wird eine neue Option angezeigt:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Mit Folgendem lässt sich **überprüfen, ob eine App von GateKeeper zugelassen wird**:
```bash
spctl --assess -v /Applications/App.app
```
Es ist möglich, neue Regeln in GateKeeper hinzuzufügen, um die Ausführung bestimmter Apps zu erlauben:
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
Im Hinblick auf **Kernel-Erweiterungen** enthält der Ordner `/var/db/SystemPolicyConfiguration` Dateien mit Listen der Kexts, deren Laden erlaubt ist. Außerdem verfügt `spctl` über das Entitlement `com.apple.private.iokit.nvram-csr`, da es neue vorab genehmigte Kernel-Erweiterungen hinzufügen kann, die auch im NVRAM in einem Schlüssel `kext-allowed-teams` gespeichert werden müssen.

#### Verwalten von Gatekeeper unter macOS 15 (Sequoia) und höher

- Der seit Langem bestehende Umgehungsmechanismus im Finder **Ctrl+Öffnen / Rechtsklick → Öffnen** wurde entfernt. Benutzer müssen eine blockierte App nach dem ersten Blockierungsdialog ausdrücklich über **Systemeinstellungen → Datenschutz & Sicherheit → Trotzdem öffnen** erlauben.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` werden nicht mehr akzeptiert. `spctl` ist für Assessment und die Verwaltung von Labels praktisch schreibgeschützt, während die Richtliniendurchsetzung über die Benutzeroberfläche oder MDM konfiguriert wird.

Ab macOS 15 Sequoia können Endbenutzer die Gatekeeper-Richtlinie nicht mehr über `spctl` umschalten. Die Verwaltung erfolgt über die Systemeinstellungen oder durch das Deployment eines MDM-Konfigurationsprofils mit der Payload `com.apple.systempolicy.control`. Beispiel für einen Profilausschnitt, der den App Store und identifizierte Entwickler erlaubt, jedoch nicht „Überall“:

<details>
<summary>MDM-Profil zum Erlauben des App Store und identifizierter Entwickler</summary>
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

### Quarantine Files

Beim **Herunterladen** einer Anwendung oder Datei fügen bestimmte macOS-**Anwendungen** wie Webbrowser oder E-Mail-Clients der heruntergeladenen Datei ein **erweitertes Dateiattribut** hinzu, das allgemein als "**quarantine flag**" bezeichnet wird. Dieses Attribut dient als Sicherheitsmaßnahme, um **die Datei zu markieren**, die aus einer nicht vertrauenswürdigen Quelle (dem Internet) stammt und möglicherweise Risiken birgt. Allerdings fügen nicht alle Anwendungen dieses Attribut hinzu; gängige BitTorrent-Client-Software umgeht diesen Prozess beispielsweise in der Regel.

**Das Vorhandensein eines quarantine flag signalisiert macOS' Gatekeeper-Sicherheitsfunktion, wenn ein Benutzer versucht, die Datei auszuführen**.

Wenn das **quarantine flag nicht vorhanden ist** (wie bei Dateien, die über einige BitTorrent-Clients heruntergeladen wurden), werden die **Prüfungen von Gatekeeper möglicherweise nicht durchgeführt**. Daher sollten Benutzer beim Öffnen von Dateien, die aus weniger sicheren oder unbekannten Quellen heruntergeladen wurden, Vorsicht walten lassen.

> [!NOTE] > Die **Überprüfung** der **Gültigkeit** von Codesignaturen ist ein **ressourcenintensiver** Prozess, der das Erzeugen kryptografischer **Hashes** des Codes und aller gebündelten Ressourcen umfasst. Außerdem beinhaltet die Überprüfung der Gültigkeit des Zertifikats eine **Online-Prüfung** der Apple-Server, um festzustellen, ob es nach seiner Ausstellung widerrufen wurde. Aus diesen Gründen ist eine vollständige Prüfung der Codesignatur und Notarisierung **bei jedem Start einer App unpraktisch**.
>
> Daher werden diese Prüfungen **nur beim Ausführen von Apps mit dem quarantined Attribut durchgeführt.**

> [!WARNING]
> Dieses Attribut muss von der **Anwendung gesetzt werden, die** die Datei erstellt/herunterlädt.
>
> Dateien, die sandboxed sind, erhalten dieses Attribut jedoch für jede von ihnen erstellte Datei. Nicht sandboxed Apps können es selbst setzen oder den Schlüssel [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) in der **Info.plist** angeben, wodurch das System das erweiterte Attribut `com.apple.quarantine` auf den erstellten Dateien setzt.

Außerdem werden alle von einem Prozess erstellten Dateien, der **`qtn_proc_apply_to_self`** aufruft, unter Quarantäne gestellt. Alternativ fügt die API **`qtn_file_apply_to_path`** das Quarantäneattribut zu einem angegebenen Dateipfad hinzu.

Der **Status kann überprüft und die Funktion aktiviert/deaktiviert** werden (root erforderlich) mit:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Du kannst auch **herausfinden, ob eine Datei das Quarantäne-Erweiterungsattribut** besitzt, mit:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Prüfe den **Wert** der **erweiterten** **Attribute** und finde mit Folgendem die App heraus, die das Quarantäne-Attribut geschrieben hat:
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
Tatsächlich könnte ein Prozess „Quarantine-Flags auf die von ihm erstellten Dateien setzen“ (ich habe bereits versucht, das USER_APPROVED-Flag auf eine erstellte Datei anzuwenden, aber es lässt sich nicht setzen):

<details>

<summary>Source Code zum Anwenden von Quarantine-Flags</summary>
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

Und **entfernen** Sie dieses Attribut mit:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Und finde alle unter Quarantäne gestellten Dateien mit:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine-Informationen werden außerdem in einer zentralen, von LaunchServices verwalteten Datenbank unter **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** gespeichert, wodurch die GUI Daten über die Herkunft der Datei abrufen kann. Dies kann zudem von Anwendungen überschrieben werden, die daran interessiert sein könnten, ihre Herkunft zu verbergen. Außerdem kann dies über LaunchServices-APIS erfolgen.

#### **libquarantine.dylib**

Diese Library exportiert mehrere Funktionen, mit denen sich die Felder der Extended Attributes manipulieren lassen.

Die `qtn_file_*`-APIs behandeln Quarantine-Richtlinien für Dateien, während die `qtn_proc_*`-APIs auf Prozesse angewendet werden (Dateien, die vom Prozess erstellt wurden). Die nicht exportierten `__qtn_syscall_quarantine*`-Funktionen wenden die Richtlinien an. Sie rufen `mac_syscall` mit "Quarantine" als erstem Argument auf, wodurch die Anfragen an `Quarantine.kext` gesendet werden.

#### **Quarantine.kext**

Die Kernel Extension ist nur über den **Kernel Cache auf dem System** verfügbar. Du kannst jedoch das **Kernel Debug Kit von** [**https://developer.apple.com/**](https://developer.apple.com/) herunterladen, das eine symbolicated Version der Extension enthält.

Diese Kext verwendet MACF-Hooks für mehrere Aufrufe, um alle Dateilebenszyklus-Ereignisse abzufangen: Erstellung, Öffnen, Umbenennen, Hard-Linking ... sogar `setxattr`, um das Setzen des Extended Attributes `com.apple.quarantine` zu verhindern.

Sie verwendet außerdem einige MIBs:

- `security.mac.qtn.sandbox_enforce`: Erzwingt Quarantine zusammen mit der Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined Procs können nur genehmigte Dateien ausführen

#### Provenance xattr (Ventura und später)

macOS 13 Ventura führte einen separaten Provenance-Mechanismus ein, der beim ersten erlaubten Start einer quarantined App gefüllt wird.<sup>[[2]](#references)</sup> Es werden zwei Artefakte erstellt:

- Das `com.apple.provenance`-xattr im `.app`-Bundle-Verzeichnis (binärer Wert fester Größe, der einen Primary Key und Flags enthält).
- Eine Zeile in der Tabelle `provenance_tracking` innerhalb der ExecPolicy-Datenbank unter `/var/db/SystemPolicyConfiguration/ExecPolicy/`, in der der cdhash und die Metadaten der App gespeichert werden.

Praktische Anwendung:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect ist eine integrierte **Anti-Malware**-Funktion in macOS. XProtect **überprüft jede Anwendung beim ersten Start oder nach einer Änderung anhand seiner Datenbank** bekannter Malware und unsicherer Dateitypen. Wenn du eine Datei über bestimmte Apps wie Safari, Mail oder Messages herunterlädst, scannt XProtect die Datei automatisch. Wenn sie mit bekannter Malware aus seiner Datenbank übereinstimmt, **verhindert XProtect, dass die Datei ausgeführt wird**, und informiert dich über die Bedrohung.

Die XProtect-Datenbank wird von Apple **regelmäßig** mit neuen Malware-Definitionen **aktualisiert**. Diese Updates werden automatisch auf deinen Mac heruntergeladen und dort installiert. Dadurch ist XProtect stets auf dem aktuellen Stand der neuesten bekannten Bedrohungen.

Beachte jedoch, dass **XProtect keine vollwertige Antivirus-Lösung ist**. Es überprüft nur eine bestimmte Liste bekannter Bedrohungen und führt kein On-Access-Scanning wie die meisten Antivirus-Programme durch.

Du kannst Informationen über das neueste XProtect-Update mit folgendem Befehl abrufen:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect befindet sich am durch SIP geschützten Speicherort **/Library/Apple/System/Library/CoreServices/XProtect.bundle**. Innerhalb des Bundles findest du Informationen, die XProtect verwendet:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Erlaubt Code mit diesen cdhashes, legacy entitlements zu verwenden.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Liste von Plugins und Extensions, deren Laden anhand von BundleID und TeamID untersagt ist, oder die eine Mindestversion angibt.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-Regeln zur Erkennung von Malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-Datenbank mit Hashes blockierter Anwendungen und TeamIDs.

Beachte, dass es unter **`/Library/Apple/System/Library/CoreServices/XProtect.app`** eine weitere App gibt, die mit XProtect zusammenhängt, aber nicht am Gatekeeper-Prozess beteiligt ist.

> XProtect Remediator: Unter modernen macOS-Versionen liefert Apple On-Demand-Scanner (XProtect Remediator) aus, die regelmäßig über launchd ausgeführt werden, um Malware-Familien zu erkennen und zu beseitigen. Diese Scans kannst du in den Unified Logs beobachten:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nicht Gatekeeper

> [!CAUTION]
> Beachte, dass Gatekeeper **nicht jedes Mal ausgeführt wird**, wenn du eine Anwendung ausführst. Stattdessen wird nur von _**AppleMobileFileIntegrity**_ die **Signatur des ausführbaren Codes überprüft**, wenn du eine App ausführst, die bereits von Gatekeeper ausgeführt und verifiziert wurde.

Daher war es früher möglich, eine App auszuführen, um sie bei Gatekeeper zu cachen, anschließend **nicht ausführbare Dateien der Anwendung** (wie Electron-asar- oder NIB-Dateien) zu **ändern** und die Anwendung, sofern keine anderen Schutzmechanismen vorhanden waren, mit den **bösartigen** Ergänzungen **auszuführen**.

Dies ist nun jedoch nicht mehr möglich, da macOS das **Ändern von Dateien** innerhalb von Application-Bundles verhindert. Wenn du also den [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md)-Angriff ausprobierst, wirst du feststellen, dass er nicht mehr ausgenutzt werden kann, da du nach dem Ausführen der App zum Cachen bei Gatekeeper das Bundle nicht mehr ändern kannst. Wenn du beispielsweise den Namen des Contents-Verzeichnisses in NotCon änderst (wie im Exploit angegeben) und anschließend die Haupt-Binary der App ausführst, um sie bei Gatekeeper zu cachen, wird ein Fehler ausgelöst und die App nicht ausgeführt.

## Gatekeeper Bypasses

Jede Möglichkeit, Gatekeeper zu umgehen (den Benutzer dazu zu bringen, etwas herunterzuladen und auszuführen, obwohl Gatekeeper dies verhindern sollte), gilt als Schwachstelle in macOS. Dies sind einige CVEs, die Techniken zugewiesen wurden, mit denen Gatekeeper in der Vergangenheit umgangen werden konnte:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Es wurde beobachtet, dass Dateien, deren **Pfade mehr als 886 Zeichen umfassen**, bei Verwendung des **Archive Utility** zur Extraktion nicht das erweiterte Attribut com.apple.quarantine erhalten. Dadurch können diese Dateien unbeabsichtigt die Sicherheitsprüfungen von **Gatekeeper umgehen**.<sup>[[5]](#references)</sup>

Weitere Informationen findest du im [**Originalbericht**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wenn eine Anwendung mit **Automator** erstellt wird, befinden sich die Informationen darüber, was sie ausführen muss, in `application.app/Contents/document.wflow` und nicht in der ausführbaren Datei. Die ausführbare Datei ist lediglich eine generische Automator-Binary namens **Automator Application Stub**.

Daher könntest du `application.app/Contents/MacOS/Automator\ Application\ Stub` **mit einem symbolischen Link auf einen anderen Automator Application Stub innerhalb des Systems verweisen lassen**. Dadurch wird der Inhalt von `document.wflow` (dein Script) **ausgeführt, ohne Gatekeeper auszulösen**, da die eigentliche ausführbare Datei nicht über das Quarantäne-xattr verfügt.<sup>[[6]](#references)</sup>

Beispiel für den erwarteten Speicherort: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Weitere Informationen findest du im [**Originalbericht**](https://ronmasas.com/posts/bypass-macos-gatekeeper).

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bei diesem Bypass wurde eine Zip-Datei erstellt, deren Komprimierung bei `application.app/Contents` statt bei `application.app` begann. Daher wurde das **Quarantäne-Attribut** auf alle **Dateien innerhalb von `application.app/Contents`** angewendet, jedoch **nicht auf `application.app`**, das von Gatekeeper überprüft wurde. Dadurch wurde Gatekeeper umgangen, weil `application.app` beim Auslösen **nicht über das Quarantäne-Attribut verfügte.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Weitere Informationen finden Sie im [**Originalbericht**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/).

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Auch wenn die Komponenten unterschiedlich sind, ist die Ausnutzung dieser Schwachstelle der vorherigen sehr ähnlich. In diesem Fall erstellen wir ein Apple Archive aus **`application.app/Contents`**, sodass **`application.app`** beim Dekomprimieren durch das **Archive Utility** nicht mit dem Quarantäne-Attribut versehen wird.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Weitere Informationen finden Sie im [**Originalbericht**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/).

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kann verwendet werden, um zu verhindern, dass jemand ein Attribut in eine Datei schreibt:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Darüber hinaus kopiert das Dateiformat **AppleDouble** eine Datei einschließlich ihrer ACEs.<sup>[[9]](#references)</sup>

Im [**Quellcode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die im xattr namens **`com.apple.acl.text`** gespeicherte ACL-Textdarstellung als ACL für die dekomprimierte Datei gesetzt wird. Wenn du also eine Anwendung mit dem Dateiformat **AppleDouble** in eine ZIP-Datei komprimiert hast und eine ACL verwendet wurde, die verhindert, dass andere xattrs in die Datei geschrieben werden ... wurde das Quarantäne-xattr nicht für die Anwendung gesetzt:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Weitere Informationen findest du im [**Originalbericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/).

Beachte, dass dies auch mit AppleArchives ausgenutzt werden konnte:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Es wurde festgestellt, dass **Google Chrome heruntergeladenen Dateien das Quarantäne-Attribut nicht zuwies**, weil einige interne macOS-Probleme auftraten.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble-Dateiformate speichern die Attribute einer Datei in einer separaten Datei, die mit `._` beginnt. Dies hilft dabei, Dateiattribute **über mehrere macOS-Geräte hinweg** zu kopieren. Es wurde jedoch festgestellt, dass die Datei, die mit `._` beginnt, **nach dem Dekomprimieren einer AppleDouble-Datei nicht mit dem Quarantäne-Attribut versehen wurde**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Da eine Datei erstellt werden konnte, für die das Attribut `quarantine` nicht gesetzt wurde, war es **möglich, Gatekeeper zu umgehen**. Der Trick bestand darin, eine **DMG-Dateianwendung** mithilfe der AppleDouble-Namenskonvention zu erstellen (mit `._` zu beginnen) und eine **sichtbare Datei als symbolischen Link** auf diese versteckte Datei ohne das Attribut `quarantine` zu erstellen.\
Wenn die **DMG-Datei ausgeführt wird**, umgeht sie **Gatekeeper**, da sie kein Attribut `quarantine` besitzt.
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

Ein Gatekeeper bypass, der in macOS Sonoma 14.0 behoben wurde, ermöglichte die Ausführung speziell erstellter Apps ohne Rückfrage. Details wurden nach dem Patching öffentlich bekannt gegeben, und das Problem wurde vor der Behebung aktiv in freier Wildbahn ausgenutzt. Stelle sicher, dass Sonoma 14.0 oder höher installiert ist.

### [CVE-2024-27853]

Ein Gatekeeper bypass in macOS 14.4 (veröffentlicht im März 2024), der auf die Verarbeitung bösartiger ZIP-Dateien durch `libarchive` zurückzuführen war, ermöglichte es Apps, der Überprüfung zu entgehen. Aktualisiere auf 14.4 oder höher, wo Apple das Problem behoben hat.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Ein **Automator Quick Action workflow**, der in eine heruntergeladene App eingebettet war, konnte ohne Gatekeeper assessment ausgelöst werden, da Workflows als Daten behandelt und vom Automator helper außerhalb des normalen Pfads für den Notarisierungsdialog ausgeführt wurden. Eine speziell erstellte `.app`, die eine Quick Action zum Ausführen eines Shell-Skripts enthielt (z. B. in `Contents/PlugIns/*.workflow/Contents/document.wflow`), konnte daher unmittelbar beim Start ausgeführt werden. Apple fügte einen zusätzlichen Zustimmungsdialog hinzu und behob den assessment-Pfad in Ventura **13.7**, Sonoma **14.7** und Sequoia **15**.<sup>[[3]](#references)</sup>

### Quarantine-Weitergabe durch third-party unarchivers (2023–2024)

Mehrere Schwachstellen in beliebten Extraction-Tools (z. B. The Unarchiver) führten dazu, dass aus Archiven extrahierte Dateien das `com.apple.quarantine` xattr nicht erhielten, wodurch Möglichkeiten für Gatekeeper bypasses entstanden. Verwende beim Testen immer macOS Archive Utility oder gepatchte Tools und überprüfe die xattrs nach der Extraktion.

### uchg (aus diesem [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Erstelle ein Verzeichnis, das eine App enthält.
- Füge der App uchg hinzu.
- Komprimiere die App in eine tar.gz-Datei.
- Sende die tar.gz-Datei an ein Opfer.
- Das Opfer öffnet die tar.gz-Datei und führt die App aus.
- Gatekeeper überprüft die App nicht.<sup>[[12]](#references)</sup>

### Quarantine xattr verhindern

Wenn in einem ".app"-Bundle das Quarantine xattr nicht hinzugefügt wird, wird **Gatekeeper beim Ausführen nicht ausgelöst**.


## Referenzen

- [1] [Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: How macOS now tracks the provenance of apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: The Discovery of CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypassing The macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifies Safari vulnerability allowing for Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifies macOS Archive Utility vulnerability allowing for Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper's Achilles heel: Unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Discovery of a Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Finding and reporting a Gatekeeper bypass exploit with help from Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypassing macOS Security and Privacy Mechanisms — From Gatekeeper to System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
