# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** ist eine Sicherheitsfunktion für Mac-Betriebssysteme, die sicherstellen soll, dass Benutzer auf ihren Systemen **nur vertrauenswürdige Software ausführen**. Sie funktioniert, indem sie Software überprüft, die ein Benutzer herunterlädt und aus **Quellen außerhalb des App Store** zu öffnen versucht, beispielsweise eine App, ein Plug-in oder ein Installationspaket.

Der zentrale Mechanismus von Gatekeeper ist der **Überprüfungsprozess**. Dabei wird geprüft, ob die heruntergeladene Software **von einem anerkannten Entwickler signiert** wurde, um ihre Authentizität sicherzustellen. Außerdem wird festgestellt, ob die Software von Apple **notarisiert** wurde. Damit wird bestätigt, dass sie keine bekannte schädliche Inhalte enthält und nach der Notarisierung nicht manipuliert wurde.

Zusätzlich stärkt Gatekeeper die Benutzerkontrolle und Sicherheit, indem es Benutzer beim ersten Öffnen heruntergeladener Software **um ihre Zustimmung bittet**. Diese Schutzmaßnahme hilft zu verhindern, dass Benutzer versehentlich potenziell schädlichen ausführbaren Code ausführen, den sie möglicherweise für eine harmlose Datendatei gehalten haben.

### Anwendungssignaturen

Anwendungssignaturen, auch Codesignaturen genannt, sind ein zentraler Bestandteil der Sicherheitsinfrastruktur von Apple. Sie dienen dazu, **die Identität des Softwareautors** (des Entwicklers) zu überprüfen und sicherzustellen, dass der Code seit seiner letzten Signierung nicht manipuliert wurde.

So funktioniert es:

1. **Signieren der Anwendung:** Wenn ein Entwickler bereit ist, seine Anwendung zu verteilen, **signiert er die Anwendung mit einem privaten Schlüssel**. Dieser private Schlüssel ist einem **Zertifikat zugeordnet, das Apple dem Entwickler ausstellt**, wenn dieser sich beim Apple Developer Program anmeldet. Beim Signiervorgang wird ein kryptografischer Hash aller Teile der App erstellt und mit dem privaten Schlüssel des Entwicklers verschlüsselt.
2. **Verteilen der Anwendung:** Anschließend wird die signierte Anwendung zusammen mit dem Zertifikat des Entwicklers verteilt, das den zugehörigen öffentlichen Schlüssel enthält.
3. **Überprüfen der Anwendung:** Wenn ein Benutzer die Anwendung herunterlädt und auszuführen versucht, verwendet sein Mac-Betriebssystem den öffentlichen Schlüssel aus dem Zertifikat des Entwicklers, um den Hash zu entschlüsseln. Anschließend berechnet es den Hash anhand des aktuellen Zustands der Anwendung neu und vergleicht ihn mit dem entschlüsselten Hash. Stimmen sie überein, bedeutet dies, dass **die Anwendung seit der Signierung durch den Entwickler nicht verändert wurde**; das System lässt die Anwendung dann ausführen.

Anwendungssignaturen sind ein wesentlicher Bestandteil der Gatekeeper-Technologie von Apple. Wenn ein Benutzer versucht, **eine aus dem Internet heruntergeladene Anwendung zu öffnen**, überprüft Gatekeeper die Anwendungssignatur. Wurde sie mit einem von Apple ausgestellten Zertifikat eines bekannten Entwicklers signiert und der Code nicht manipuliert, lässt Gatekeeper die Anwendung ausführen. Andernfalls blockiert es die Anwendung und warnt den Benutzer.

Ab macOS Catalina überprüft **Gatekeeper auch, ob die Anwendung von Apple notarisiert wurde**, wodurch eine zusätzliche Sicherheitsebene hinzugefügt wird. Bei der Notarisierung wird die Anwendung auf bekannte Sicherheitsprobleme und schädlichen Code überprüft. Wenn sie diese Prüfungen besteht, fügt Apple der Anwendung ein Ticket hinzu, das Gatekeeper überprüfen kann.

#### Signaturen überprüfen

Wenn du ein **Malware-Sample** untersuchst, solltest du immer die **Signatur** der Binärdatei überprüfen, da der **Entwickler**, der sie signiert hat, möglicherweise bereits mit **Malware in Verbindung gebracht wird**.

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

Der Notarisierungsprozess von Apple dient als zusätzliche Schutzmaßnahme, um Nutzer vor potenziell schädlicher Software zu schützen. Dabei **reicht der Entwickler seine Anwendung zur Prüfung** durch **Apples Notary Service** ein, der nicht mit App Review verwechselt werden sollte. Bei diesem Service handelt es sich um ein **automatisiertes System**, das die eingereichte Software auf **schädliche Inhalte** und mögliche Probleme mit der Codesignierung überprüft.

Wenn die Software diese Prüfung **besteht**, ohne Bedenken hervorzurufen, erstellt der Notary Service ein Notarisierungsticket. Der Entwickler muss dieses Ticket dann **an seine Software anhängen**; dieser Vorgang wird als „stapling“ bezeichnet. Außerdem wird das Notarisierungsticket online veröffentlicht, wo Gatekeeper, Apples Sicherheitstechnologie, darauf zugreifen kann.

Bei der ersten Installation oder Ausführung der Software durch den Nutzer **informiert das Notarisierungsticket Gatekeeper darüber, dass die Software von Apple notariell beglaubigt wurde** – unabhängig davon, ob das Ticket an die ausführbare Datei angeheftet oder online gefunden wird. Daraufhin zeigt Gatekeeper im Dialogfeld beim ersten Start eine beschreibende Meldung an, die darauf hinweist, dass Apple die Software auf schädliche Inhalte überprüft hat. Dieser Prozess stärkt das Vertrauen der Nutzer in die Sicherheit der Software, die sie auf ihren Systemen installieren oder ausführen.

### spctl & syspolicyd

> [!CAUTION]
> Beachte, dass **`spctl`** ab der Version Sequoia Änderungen an der Gatekeeper-Konfiguration nicht mehr zulässt.

**`spctl`** ist das CLI-Tool zum Auflisten und Interagieren mit Gatekeeper (über den `syspolicyd`-Daemon mittels XPC-Nachrichten). Beispielsweise lässt sich der **Status** von GateKeeper wie folgt anzeigen:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Beachte, dass GateKeeper-Signaturprüfungen nur für **Dateien mit dem Quarantine-Attribut** durchgeführt werden, nicht für jede Datei.

GateKeeper prüft anhand der **Einstellungen und der Signatur**, ob eine Binärdatei ausgeführt werden kann:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** ist der Haupt-Daemon, der für die Durchsetzung von Gatekeeper verantwortlich ist. Er verwaltet eine Datenbank unter `/var/db/SystemPolicy`. Der Code zur Unterstützung der [Datenbank ist hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) und die [SQL-Vorlage hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) zu finden. Beachte, dass die Datenbank nicht durch SIP eingeschränkt ist und für root beschreibbar ist. Die Datenbank `/var/db/.SystemPolicy-default` dient als Original-Backup für den Fall, dass die andere beschädigt wird.

Außerdem enthalten die Bundles **`/var/db/gke.bundle`** und **`/var/db/gkopaque.bundle`** Dateien mit Regeln, die in die Datenbank eingefügt werden. Du kannst diese Datenbank als root wie folgt überprüfen:

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

**`syspolicyd`** stellt außerdem einen XPC-Server mit verschiedenen Operationen wie `assess`, `update`, `record` und `cancel` bereit. Diese sind auch über die **`SecAssessment*`-APIs von `Security.framework`** erreichbar, und **`spctl`** kommuniziert tatsächlich über XPC mit **`syspolicyd`**.

Beachte, dass die erste Regel mit „**App Store**“ und die zweite mit „**Developer ID**“ endete und dass im vorherigen Bild **die Ausführung von Apps aus dem App Store und von identifizierten Entwicklern erlaubt** war.\
Wenn du diese Einstellung auf App Store **änderst**, verschwinden die Regeln für „**Notarized Developer ID**“.

Es gibt außerdem Tausende Regeln vom **Typ GKE** :

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

Oder du kannst die vorherigen Informationen mit folgendem Befehl auflisten:

```bash
sudo spctl --list
```

Die Optionen **`--master-disable`** und **`--global-disable`** von **`spctl`** **deaktivieren** diese Signaturprüfungen vollständig:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Wenn die Funktion vollständig aktiviert ist, wird eine neue Option angezeigt:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Mit folgendem Befehl lässt sich **prüfen, ob eine App von GateKeeper zugelassen wird**:

```bash
spctl --assess -v /Applications/App.app
```

Unter macOS 14 und neuer ist **`syspolicy_check`** eine nützliche Prüfung auf höherer Ebene vor der Verteilung eines App-Bundles. Sie liefert aussagekräftigere Diagnosen zur vertrauenswürdigen Ausführung als ein bloßes `spctl`-Ergebnis. Apple empfiehlt jedoch weiterhin, den tatsächlichen Ablauf aus Download, Entpacken und erstem Start zu testen, da dabei auch die Weitergabe der Quarantäne geprüft wird.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

Es ist möglich, GateKeeper neue Regeln hinzuzufügen, um die Ausführung bestimmter Apps zu erlauben mit:

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

Bezüglich **Kernel-Erweiterungen** enthält der Ordner `/var/db/SystemPolicyConfiguration` Dateien mit Listen der kexts, deren Laden erlaubt ist. Außerdem verfügt `spctl` über das Entitlement `com.apple.private.iokit.nvram-csr`, da es neue vorab genehmigte Kernel-Erweiterungen hinzufügen kann, die auch in NVRAM unter dem Schlüssel `kext-allowed-teams` gespeichert werden müssen.

#### Gatekeeper unter macOS 15 (Sequoia) und neuer verwalten

- Die seit Langem bekannte Finder-Umgehung **Ctrl+Open / Rechtsklick → Öffnen** wurde entfernt. Nutzer müssen eine blockierte App nach dem ersten Blockierungsdialog ausdrücklich über **Systemeinstellungen → Datenschutz & Sicherheit → Dennoch öffnen** erlauben.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` werden nicht mehr als unbeaufsichtigte Richtlinienänderungen akzeptiert. Vorgänge, die die Regel-Datenbank oder den globalen Bewertungsstatus ändern, sind veraltet. Verwende `spctl` daher zur Bewertung und konfiguriere die Durchsetzung über die Benutzeroberfläche oder MDM.

Ab macOS 15 Sequoia können Endnutzer die Gatekeeper-Richtlinie nicht mehr über `spctl` umschalten. Die Verwaltung erfolgt über die Systemeinstellungen oder durch Bereitstellung eines MDM-Konfigurationsprofils mit dem Payload `com.apple.systempolicy.control`. Beispiel für einen Profil-Snippet, der App Store und identifizierte Entwickler zulässt (aber nicht „Überall“):

<details>
<summary>MDM-Profil zum Zulassen des App Store und identifizierter Entwickler</summary>

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

### Quarantäne-Dateien

Beim **Herunterladen** einer Anwendung oder Datei fügen bestimmte macOS-**Anwendungen** wie Webbrowser oder E-Mail-Clients der heruntergeladenen Datei ein **erweitertes Dateiattribut** hinzu, das allgemein als „**Quarantäne-Flag**“ bezeichnet wird. Dieses Attribut dient als Sicherheitsmaßnahme, um **die Datei als** aus einer nicht vertrauenswürdigen Quelle (dem Internet) stammend und potenziell riskant zu **kennzeichnen**. Allerdings fügen nicht alle Anwendungen dieses Attribut hinzu. Gängige BitTorrent-Client-Software umgeht diesen Vorgang beispielsweise normalerweise.

**Das Vorhandensein eines Quarantäne-Flags signalisiert macOS’ Gatekeeper-Sicherheitsfunktion, wenn ein Benutzer versucht, die Datei auszuführen**.

Wenn das **Quarantäne-Flag nicht vorhanden ist** (wie bei Dateien, die über einige BitTorrent-Clients heruntergeladen wurden), werden die **Prüfungen von** Gatekeeper möglicherweise **nicht durchgeführt**. Daher sollten Benutzer beim Öffnen von Dateien aus weniger sicheren oder unbekannten Quellen vorsichtig sein.

> [!NOTE] > Die **Überprüfung** der **Gültigkeit** von Codesignaturen ist ein **ressourcenintensiver** Vorgang, bei dem kryptografische **Hashes** des Codes und aller darin enthaltenen Ressourcen erstellt werden. Außerdem erfordert die Überprüfung der Gültigkeit von Zertifikaten eine **Online-Prüfung** bei den Apple-Servern, um festzustellen, ob das Zertifikat seit seiner Ausstellung widerrufen wurde. Aus diesen Gründen ist es **unpraktisch, bei jedem Start einer App die vollständige Codesignatur- und Notarisierungsprüfung durchzuführen**.
>
> Daher werden diese Prüfungen **nur beim Ausführen von Apps mit dem Quarantäne-Attribut durchgeführt**.

> [!WARNING]
> Dieses Attribut muss von der **Anwendung gesetzt werden, die die Datei erstellt/herunterlädt**.
>
> Dateien, die in einer Sandbox erstellt werden, erhalten dieses Attribut jedoch für jede von ihnen erstellte Datei. Nicht in einer Sandbox ausgeführte Apps können es selbst setzen oder den Schlüssel [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) in der **Info.plist** angeben. Dadurch setzt das System das erweiterte Attribut `com.apple.quarantine` für die erstellten Dateien.

Darüber hinaus werden alle Dateien, die von einem Prozess erstellt werden, der **`qtn_proc_apply_to_self`** aufruft, unter Quarantäne gestellt. Die API **`qtn_file_apply_to_path`** fügt das Quarantäne-Attribut einem angegebenen Dateipfad hinzu.

Der **Status lässt sich prüfen und die Funktion aktivieren/deaktivieren** (Root erforderlich) mit:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Du kannst auch **prüfen, ob eine Datei das Quarantäne-Erweiterungsattribut besitzt**:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Prüfe den **Wert** der **erweiterten** **Attribute** und finde mit folgendem Befehl heraus, welche App das Quarantäne-Attribut geschrieben hat:

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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```

Tatsächlich kann ein Prozess „Quarantäne-Flags für die von ihm erstellten Dateien setzen“ (ich habe bereits versucht, das Flag USER_APPROVED auf eine erstellte Datei anzuwenden, aber es lässt sich nicht setzen):

<details>

<summary>Quarantäne-Flags im Quellcode setzen</summary>

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

Und finde alle unter Quarantäne stehenden Dateien mit:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Quarantäneinformationen werden auch in einer zentralen Datenbank gespeichert, die von LaunchServices unter **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** verwaltet wird. Dadurch kann die GUI Daten über den Ursprung der Datei abrufen. Außerdem können Anwendungen, die daran interessiert sind, ihren Ursprung zu verbergen, diese Informationen überschreiben. Dies ist auch über LaunchServices-APIs möglich.

#### **libquarantine.dylib**

Diese Bibliothek exportiert mehrere Funktionen, mit denen die Felder der erweiterten Attribute bearbeitet werden können.

Die `qtn_file_*`-APIs behandeln Quarantänerichtlinien für Dateien, die `qtn_proc_*`-APIs werden auf Prozesse angewendet (Dateien, die vom Prozess erstellt werden). Die nicht exportierten `__qtn_syscall_quarantine*`-Funktionen wenden die Richtlinien an. Sie rufen `mac_syscall` mit `"Quarantine"` als erstem Argument auf, wodurch die Anfragen an `Quarantine.kext` gesendet werden.

#### **Quarantine.kext**

Die Kernel-Erweiterung ist nur über den **Kernel-Cache auf dem System** verfügbar. Du kannst jedoch das **Kernel Debug Kit von** [**https://developer.apple.com/**](https://developer.apple.com/) herunterladen, das eine symbolisierte Version der Erweiterung enthält.

Diese Kext hängt sich über MACF in mehrere Aufrufe ein, um alle Datei-Lebenszyklusereignisse abzufangen: Erstellen, Öffnen, Umbenennen, Hard-Linking usw. – sogar `setxattr`, um das Setzen des erweiterten Attributs `com.apple.quarantine` zu verhindern.

Außerdem verwendet sie einige MIBs:

- `security.mac.qtn.sandbox_enforce`: Quarantäne zusammen mit der Sandbox erzwingen
- `security.mac.qtn.user_approved_exec`: Prozesse in Quarantäne können nur genehmigte Dateien ausführen

#### Provenance-xattr (Ventura und neuer)

macOS 13 Ventura führte einen separaten Provenance-Mechanismus ein, der beim ersten Ausführen einer App in Quarantäne befüllt wird.<sup>[[2]](#references)</sup> Dabei werden zwei Artefakte erstellt:

- Das `com.apple.provenance`-xattr im `.app`-Bundle-Verzeichnis (binärer Wert fester Größe, der einen Primärschlüssel und Flags enthält).
- Eine Zeile in der Tabelle `provenance_tracking` innerhalb der ExecPolicy-Datenbank unter `/var/db/SystemPolicyConfiguration/ExecPolicy/`, in der der cdhash und Metadaten der App gespeichert werden.

Praktische Verwendung:

```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```

### XProtect

XProtect ist eine integrierte **Anti-Malware-Funktion** in macOS. XProtect **prüft jede Anwendung bei ihrem ersten Start oder nach einer Änderung anhand seiner Datenbank** mit bekannter Malware und unsicheren Dateitypen. Wenn du eine Datei über bestimmte Apps wie Safari, Mail oder Messages herunterlädst, scannt XProtect die Datei automatisch. Wenn sie mit bekannter Malware in der Datenbank übereinstimmt, **verhindert XProtect, dass die Datei ausgeführt wird**, und warnt dich vor der Bedrohung.

Apple **aktualisiert die XProtect-Datenbank regelmäßig** mit neuen Malware-Definitionen. Diese Updates werden automatisch heruntergeladen und auf deinem Mac installiert. So ist XProtect immer auf dem neuesten Stand und kennt die aktuellsten Bedrohungen.

Beachte jedoch, dass **XProtect keine vollwertige Antivirenlösung ist**. Es prüft nur eine bestimmte Liste bekannter Bedrohungen und führt kein On-Access-Scanning wie die meisten Antivirenprogramme durch.

Du kannst Informationen zum letzten XProtect-Update abrufen, indem du Folgendes ausführst:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect befindet sich an einem durch SIP geschützten Speicherort unter **/Library/Apple/System/Library/CoreServices/XProtect.bundle**. Im Bundle finden Sie Informationen, die XProtect verwendet:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Ermöglicht Code mit diesen cdhashes die Verwendung von Legacy-Entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Liste der Plugins und Erweiterungen, deren Laden anhand von BundleID und TeamID untersagt ist oder für die eine Mindestversion angegeben wird.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-Regeln zur Erkennung von Malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-Datenbank mit Hashes blockierter Anwendungen und TeamIDs.

Beachten Sie, dass es unter **`/Library/Apple/System/Library/CoreServices/XProtect.app`** eine weitere XProtect-bezogene App gibt, die nicht am Gatekeeper-Prozess beteiligt ist.

> XProtect Remediator: In modernen macOS-Versionen liefert Apple bedarfsgesteuerte Scanner (XProtect Remediator) aus, die regelmäßig über launchd ausgeführt werden, um Malware-Familien zu erkennen und zu beseitigen. Sie können diese Scans in den Unified Logs beobachten:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Kein Gatekeeper

> [!CAUTION]
> Beachte, dass Gatekeeper **nicht jedes Mal ausgeführt wird**, wenn du eine Anwendung startest. Nur _**AppleMobileFileIntegrity**_ (AMFI) **überprüft ausführbare Codesignaturen**, wenn du eine App startest, die bereits von Gatekeeper gestartet und überprüft wurde.

Daher war es zuvor möglich, eine App zu starten, damit Gatekeeper sie cached, anschließend **nicht ausführbare Dateien der Anwendung zu ändern** (wie Electron-asar- oder NIB-Dateien) und die Anwendung ohne weitere Schutzmaßnahmen mit den **schädlichen** Ergänzungen **auszuführen**.

Das ist nun jedoch nicht mehr möglich, weil macOS **Änderungen an Dateien innerhalb von Anwendungspaketen verhindert**. Wenn du also den [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md)-Angriff ausprobierst, wirst du feststellen, dass er nicht mehr ausgenutzt werden kann: Nachdem du die App gestartet hast, damit Gatekeeper sie cached, kannst du das Paket nicht mehr ändern. Wenn du beispielsweise den Namen des Verzeichnisses `Contents` in `NotCon` änderst (wie im Exploit beschrieben) und dann die Haupt-Binärdatei der App startest, damit Gatekeeper sie cached, wird ein Fehler ausgelöst und die App nicht ausgeführt.

## Gatekeeper-Umgehungen

Jede Methode, Gatekeeper zu umgehen (den Benutzer dazu zu bringen, etwas herunterzuladen und auszuführen, obwohl Gatekeeper dies verhindern sollte), gilt als Schwachstelle in macOS. Dies sind einige CVEs, die Techniken zugewiesen wurden, mit denen Gatekeeper in der Vergangenheit umgangen werden konnte:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Es wurde festgestellt, dass Dateien mit **Pfaden, die 886 Zeichen überschreiten**, kein erweitertes Attribut `com.apple.quarantine` erhalten, wenn das **Archivierungsprogramm** zum Entpacken verwendet wird. Dadurch können diese Dateien unbeabsichtigt die Sicherheitsprüfungen von **Gatekeeper umgehen**.<sup>[[5]](#references)</sup>

Weitere Informationen findest du im [**Originalbericht**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wenn eine Anwendung mit **Automator** erstellt wird, befinden sich die Informationen darüber, was ausgeführt werden soll, in `application.app/Contents/document.wflow` und nicht in der ausführbaren Datei. Die ausführbare Datei ist lediglich eine generische Automator-Binärdatei namens **Automator Application Stub**.

Daher konntest du `application.app/Contents/MacOS/Automator\ Application\ Stub` **mit einem symbolischen Link auf einen anderen Automator Application Stub im System verweisen lassen**. Dadurch wird der Inhalt von `document.wflow` (dein Skript) **ohne Auslösung von Gatekeeper** ausgeführt, da die tatsächliche ausführbare Datei nicht das Quarantäne-xattr besitzt.<sup>[[6]](#references)</sup>

Beispiel für den erwarteten Speicherort: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Weitere Informationen findest du im [**Originalbericht**](https://ronmasas.com/posts/bypass-macos-gatekeeper).<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bei dieser Umgehung wurde eine ZIP-Datei erstellt, wobei das Komprimieren der Anwendung bei `application.app/Contents` statt bei `application.app` begann. Daher wurde das **Quarantäne-Attribut** auf alle **Dateien in `application.app/Contents`** angewendet, aber **nicht auf `application.app`**, das Gatekeeper überprüfte. So wurde Gatekeeper umgangen, denn beim Aufruf von `application.app` **war das Quarantäne-Attribut nicht vorhanden.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Weitere Informationen finden Sie im [**Originalbericht**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/).<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Auch wenn die Komponenten unterschiedlich sind, ist die Ausnutzung dieser Schwachstelle der vorherigen sehr ähnlich. In diesem Fall erstellen wir ein Apple Archive aus **`application.app/Contents`**, sodass **`application.app`** beim Dekomprimieren durch das **Archive Utility** kein Quarantäneattribut erhält.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Weitere Informationen finden Sie im [**Originalbericht**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/).<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kann verwendet werden, um zu verhindern, dass jemand ein Attribut in eine Datei schreibt:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Für den `com.apple.acl.text`-/AppleDouble-Mechanismus und die vollständige Reproduktion der Sidecar-Datei siehe [Reproduktion des AppleDouble-ACL-Quarantine-Bypass](macos-fs-tricks/macos-appledouble-acl-quarantine-bypass.md). Die Gatekeeper-Variante mit Anwendungs-ZIP verwendet die folgende Abfolge:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Weitere Informationen finden Sie im [**Originalbericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/).<sup>[[9]](#references)</sup>

Beachten Sie, dass dies auch mit AppleArchives ausgenutzt werden könnte:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Es wurde entdeckt, dass **Google Chrome heruntergeladenen Dateien aufgrund interner macOS-Probleme nicht das Quarantäneattribut zuwies**.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble speichert die Attribute einer Datei in einer separaten Datei, deren Name mit `._` beginnt; dadurch lassen sich Dateiattribute **zwischen macOS-Rechnern** kopieren. Nach dem Dekomprimieren einer AppleDouble-Datei **wurde der Datei mit dem Namen `._` jedoch nicht das Quarantäneattribut zugewiesen**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Wenn eine Datei erstellt werden konnte, bei der das Quarantäne-Attribut nicht gesetzt wurde, war es **möglich, Gatekeeper zu umgehen.** Der Trick bestand darin, eine **DMG-Datei-Anwendung** nach der AppleDouble-Namenskonvention zu erstellen (mit `._` beginnend) und eine **sichtbare Datei als Symlink zu dieser versteckten** Datei ohne Quarantäne-Attribut anzulegen.\
Wird die **DMG-Datei ausgeführt**, **umgeht sie Gatekeeper**, da sie kein Quarantäne-Attribut hat.

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

Apple behob einen Logikfehler in LaunchServices in macOS Sonoma 14.0 durch verbesserte Prüfungen. Im öffentlichen Advisory steht lediglich, dass eine App Gatekeeper umgehen konnte. Leite daher allein aus dem CVE-Eintrag kein bestimmtes Trägerformat oder eine Exploit-Kette ab.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Eine Gatekeeper-Umgehung in macOS 14.4 (veröffentlicht im März 2024), die auf den Umgang von `libarchive` mit bösartigen ZIP-Dateien zurückging, ermöglichte es Apps, der Prüfung zu entgehen. Aktualisiere auf Version 14.4 oder höher, in der Apple das Problem behoben hat.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Ein **Automator-Quick-Action-Workflow**, der in einer heruntergeladenen App eingebettet war, konnte ohne Gatekeeper-Prüfung ausgeführt werden, da Workflows als Daten behandelt und vom Automator-Hilfsprozess außerhalb des üblichen Ablaufs für Notarisierungsabfragen ausgeführt wurden. Eine manipulierte `.app`, die eine Quick Action mit einem Shell-Skript enthielt (z. B. unter `Contents/PlugIns/*.workflow/Contents/document.wflow`), konnte daher direkt beim Start ausgeführt werden. Apple fügte einen zusätzlichen Zustimmungsdialog hinzu und behob den Prüfungsablauf in Ventura **13.7**, Sonoma **14.7** und Sequoia **15**.<sup>[[3]](#references)</sup>

### Fehler bei der Quarantäne-Übertragung beim Entpacken und Kopieren

Eine Studie aus dem Jahr 2024 stellte in den getesteten Versionen von iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) und 7z Utility (DMG/ZIP/7Z) Lücken bei der Übertragung fest. Außerdem wurde beobachtet, dass das Attribut beim Kopieren vom Host auf den Gast mit VMware Tools verloren ging. Mehrere Anbieter kündigten anschließend Korrekturen an. Betrachte diese Namen daher als Ansatzpunkte für **versionsspezifische erneute Tests**, nicht als dauerhafte Liste anfälliger Software. Dasselbe Problem an Vertrauensgrenzen betrifft native Unix-Workflows: `curl`/`scp` setzen keine Quarantäne, und `tar`/`unzip` auf der Kommandozeile übernehmen sie nicht automatisch aus einem Trägerarchiv.<sup>[[15]](#references)</sup>

Vergleiche bei offensiven Tests den Träger und die endgültige App nach **jedem** Übergang durch Browser, E-Mail-Client, Archivprogramm, Disk-Image, Cloud-Sync, freigegebenen Ordner und VM-Kopie. Eine ausdrückliche Ablehnung durch `spctl` behebt kein fehlendes xattr: Ohne Quarantäne wird die übliche Gatekeeper-Prüfung beim ersten Öffnen möglicherweise gar nicht angefordert.<sup>[[15]](#references)</sup>

```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
  'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```

### uchg (aus diesem [Vortrag](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Erstellen Sie ein Verzeichnis, das eine App enthält.
- Fügen Sie der App uchg hinzu.
- Komprimieren Sie die App in eine tar.gz-Datei.
- Senden Sie die tar.gz-Datei an ein Opfer.
- Das Opfer öffnet die tar.gz-Datei und führt die App aus.
- Gatekeeper überprüft die App nicht.<sup>[[12]](#references)</sup>

### Quarantine-xattr verhindern

Wenn einem „.app“-Bundle das Quarantine-xattr nicht hinzugefügt wird, wird **Gatekeeper beim Ausführen nicht ausgelöst**.

Unter [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) finden Sie dateisystem-, flag-, ACL- und AppleDouble-basierte Primitive, mit denen erweiterte Attribute verhindert oder verworfen werden können.





## References

- [1] [Apple Platform Security: Informationen zu den Sicherheitsinhalten von macOS Sonoma 14.4 (einschließlich CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Wie macOS jetzt die Herkunft von Apps nachverfolgt](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Informationen zu den Sicherheitsinhalten von macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia entfernt die Gatekeeper-Umgehung per Ctrl-Klick auf „Öffnen“](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Die Entdeckung von CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990: macOS Gatekeeper umgehen](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs entdeckt eine Safari-Sicherheitslücke, die eine Gatekeeper-Umgehung ermöglicht](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs entdeckt eine Sicherheitslücke im macOS Archive Utility, die eine Gatekeeper-Umgehung ermöglicht (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeepers Achillesferse: Eine macOS-Sicherheitslücke aufdecken](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Entdeckung einer Gatekeeper-Umgehung (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Eine Gatekeeper-Umgehung mit Hilfe von Mac Monitor finden und melden](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Umgehung von macOS-Sicherheits- und Datenschutzmechanismen — von Gatekeeper bis System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Informationen zu den Sicherheitsinhalten von macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Ein notarisiertes Produkt testen](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper-Umgehung — Schwachstellen in einem macOS-Sicherheitsmechanismus aufdecken](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
