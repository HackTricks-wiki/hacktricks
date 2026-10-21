# macOS-Dateien, Ordner, Binärdateien & Speicher

{{#include ../../../banners/hacktricks-training.md}}

## Dateisystemhierarchie

Apple dokumentiert das macOS-Dateisystem als Hierarchie aus System-, lokalen, Netzwerk- und Benutzer-Domänen. Der genaue Inhalt variiert je nach OS-Version, und Systembereiche werden zunehmend geschützt oder synthetisiert. <sup>[[1]](#references)</sup>

- **/Applications**: Hier sollten die installierten Apps liegen. Alle Benutzer können darauf zugreifen.
- **/bin**: Befehlszeilen-Binärdateien
- **/cores**: Falls vorhanden, wird dieses Verzeichnis zum Speichern von Core Dumps verwendet.
- **/dev**: Alles wird als Datei behandelt, daher können hier Hardwaregeräte gespeichert sein.
- **/etc**: Konfigurationsdateien
- **/Library**: Hier finden sich zahlreiche Unterverzeichnisse und Dateien zu Einstellungen, Caches und Logs. Ein Library-Ordner befindet sich im Stammverzeichnis und im Verzeichnis jedes Benutzers.
- **/private**: Nicht dokumentiert, aber viele der genannten Ordner sind symbolische Links auf das private Verzeichnis.
- **/sbin**: Essenzielle System-Binärdateien (für die Administration)
- **/System**: Von macOS benötigte Dateien; dieser Verzeichnisbaum enthält hauptsächlich von Apple bereitgestellte Komponenten.
- **/tmp**: Temporäre Dateien (ein symbolischer Link auf `/private/tmp`). Bei älteren Installationen wurden alte temporäre Dateien häufig regelmäßig gelöscht, teils im Abstand von drei Tagen. Der aktuelle Löschzeitpunkt hängt jedoch vom System und den Richtlinien ab. Verlasse dich nicht darauf, dass Daten dort erhalten bleiben.
- **/Users**: Benutzer-Home-Verzeichnisse.
- **/usr**: Konfiguration und System-Binärdateien
- **/var**: Logdateien
- **/Volumes**: Hier erscheinen eingehängte Volumes.
- **/.vol**: Bei der Ausführung von `stat a.txt` erhältst du etwa `16777223 7545753 -rw-r--r-- 1 username wheel ...`. Die erste Zahl ist die ID des Volumes, auf dem die Datei liegt, die zweite die Inode-Nummer. Mit diesen Angaben kannst du über /.vol/ auf den Inhalt der Datei zugreifen, indem du `cat /.vol/16777223/7545753` ausführst.

### Anwendungsordner

- **Systemanwendungen** befinden sich unter `/System/Applications`
- **Installierte** Anwendungen werden üblicherweise in `/Applications` oder `~/Applications` installiert.
- **Anwendungsdaten** befinden sich für als root ausgeführte Anwendungen unter `/Library/Application Support` und für als Benutzer ausgeführte Anwendungen unter `~/Library/Application Support`.
- **Daemons** von Drittanbieteranwendungen, die **als root ausgeführt werden müssen**, befinden sich üblicherweise in `/Library/PrivilegedHelperTools/`.
- **Sandboxed** Apps werden dem Ordner `~/Library/Containers` zugeordnet. Jede App hat einen Ordner, der nach der Bundle-ID der Anwendung benannt ist (`com.apple.Safari`).
- Der **kernel** befindet sich unter `/System/Library/Kernels/kernel`
- **Apple-Kernel-Erweiterungen** befinden sich unter `/System/Library/Extensions`
- **Kernel-Erweiterungen von Drittanbietern** werden unter `/Library/Extensions` gespeichert.

### Dateien mit sensiblen Informationen

macOS speichert sensible Informationen, einschließlich Zugangsdaten, an verschiedenen Orten:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Verwundbare pkg-Installer


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Eine Erklärung des Unterschieds zwischen dem beschreibbaren Data-Volume und dem versiegelten System-Volume, die in dieser Hierarchie sichtbar sind, findest du unter [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## OS-X-spezifische Erweiterungen

- **`.dmg`**: Apple-Disk-Image-Dateien werden häufig für Installer verwendet.
- **`.kext`**: Muss einer bestimmten Struktur folgen und ist die OS-X-Version eines Treibers (ein Bundle).
- **`.plist`**: Eine Property List speichert strukturierte Informationen im XML- oder Binärformat.
  - Kann XML oder Binärdaten enthalten. Binärdateien lassen sich mit folgenden Befehlen lesen:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Ein Anwendungs-Bundle, das der standardmäßigen macOS-Verzeichnisstruktur folgt.
- **`.dylib`**: Dynamische Bibliotheken (wie Windows-DLL-Dateien)
- **`.pkg`**: Moderne flache Installer-Pakete sind XAR-Archive, aber `.pkg` ist ein Installer-Format und kein Synonym für XAR. Ältere Installer-Pakete im Bundle-Stil sind Verzeichnisse. Siehe [macOS installers](macos-installers-abuse.md) für Informationen zur Paketstruktur und -prüfung. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Diese Datei befindet sich in jedem Verzeichnis und speichert dessen Attribute und Anpassungen.
- **`.Spotlight-V100`**: Dieser Ordner befindet sich im Stammverzeichnis jedes Volumes auf dem System.
- **`.metadata_never_index`**: Befindet sich diese Datei im Stammverzeichnis eines Volumes, indexiert Spotlight dieses Volume nicht.
- **`.noindex`**: Dateien und Ordner mit dieser Erweiterung werden nicht von Spotlight indexiert.
- **`.sdef`**: Eine Scripting-Definitionsdatei, die beschreibt, wie AppleScript mit einer Anwendung interagieren kann.

### macOS-Bundles

Ein Bundle ist ein Verzeichnis mit einer standardisierten Hierarchie, das Finder als einzelnes Objekt darstellen kann; Anwendungs-Bundles verwenden die Erweiterung `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Unter macOS und iOS werden häufig verwendete Systembibliotheken und Frameworks im **dyld shared cache** vorab verknüpft, wodurch der Start von Anwendungen beschleunigt wird. Obwohl er als ein logischer Cache behandelt wird, kann er in aktuellen Versionen aus einem Haupt-Cache und mehreren Subcache-Dateien bestehen, statt tatsächlich nur eine Datei zu sein. Format und Speicherort sind Implementierungsdetails, die sich zwischen OS-Versionen ändern. <sup>[[3]](#references)</sup>

Unter macOS befindet sich dieser Cache in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`; in älteren Versionen findest du den **shared cache** möglicherweise unter **`/System/Library/dyld/`**.\
Unter iOS findest du ihn unter **`/System/Library/Caches/com.apple.dyld/`**.

Ähnlich wie der dyld shared cache werden auch der kernel und die Kernel-Erweiterungen in einem Kernel-Cache kompiliert, der beim Booten geladen wird.

Ältere Versionen konnten mit [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) extrahiert werden. Dieser Build unterstützt möglicherweise keine aktuellen Cache-Formate; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) ist eine weitere Möglichkeit:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Beachte, dass du, selbst wenn das Tool `dyld_shared_cache_util` nicht funktioniert, das **gemeinsam genutzte dyld-Binary an Hopper übergeben** kannst. Hopper kann dann alle Bibliotheken identifizieren und dich **auswählen lassen, welche** du untersuchen möchtest:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Einige Extractors funktionieren möglicherweise nicht, da dylibs mit fest codierten Adressen vorverknüpft sind und daher zu unbekannten Adressen springen können.

> [!TIP]
> Es ist auch möglich, den Shared Library Cache anderer \*OS-Geräte in macOS mithilfe eines Emulators in Xcode herunterzuladen. Sie werden hier gespeichert: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, zum Beispiel:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Zuordnung des SLC

**`dyld`** verwendet den Syscall **`shared_region_check_np`**, um festzustellen, ob der SLC bereits zugeordnet wurde (und die Adresse zurückzugeben), und **`shared_region_map_and_slide_np`**, um den SLC zuzuordnen.

Beachte, dass der SLC zwar bei der ersten Verwendung verschoben wird, aber alle **Prozesse** dieselbe **Kopie** verwenden. Dadurch wird der **ASLR**-Schutz aufgehoben, wenn der Angreifer Prozesse auf dem System ausführen konnte. Dies wurde in der Vergangenheit tatsächlich ausgenutzt und mit dem Shared Region Pager behoben.

Branch pools sind kleine Mach-O-dylibs, die kleine Abstände zwischen den Image-Zuordnungen erzeugen und so das Interponieren von Funktionen unmöglich machen.

### Einschränkungen der Shared-Cache-Umgebung

`DYLD_SHARED_CACHE_DIR` gibt ein Cache-Verzeichnis an, während `DYLD_SHARED_REGION` einen Shared-Region-Modus auswählt. Die frühere Schreibweise `DYLD_DHARED_REGION` war ungültig, und `avoid` ist kein gültiger Wert für `DYLD_SHARED_CACHE_DIR`. Das aktuelle dyld lässt den `private`-Modus nur zu, wenn AMFI die Verwendung benutzerdefinierter Shared Caches erlaubt. Das Setzen von Umgebungsvariablen allein bedeutet also nicht, dass ein Prozess einen Ersatz-Cache laden kann. <sup>[[10]](#references)</sup>

## Spezielle Dateiberechtigungen

### Ordnerberechtigungen

Bei einem Verzeichnis erlaubt **read** das Auflisten von Einträgen, **write** das Erstellen oder Entfernen von Einträgen und **execute** das Durchlaufen des Verzeichnisses. Daher kann ein Benutzer, der eine Datei lesen, aber ein übergeordnetes Verzeichnis nicht durchlaufen kann, nicht über den Pfad auf diese Datei zugreifen. <sup>[[4]](#references)</sup>

### Flag-Modifikatoren

Dateien können Flags tragen, die ihr Verhalten ändern. Untersuche die Flags in einem Verzeichnis mit `ls -lO /path/directory`.

- **`uchg`**: Das **uchange**-Flag verhindert **jede Aktion**, die die **Datei** ändert oder löscht. Setze es mit: `chflags uchg file.txt`
  - Der Dateieigentümer oder root kann dieses **Benutzer**-Flag mit `chflags nouchg file.txt` entfernen; es schützt nicht vor ihnen. Das separate unveränderliche **System**-Flag (`schg`) ist root vorbehalten. <sup>[[11]](#references)</sup>
- **`restricted`**: Dieses Flag bewirkt, dass die Datei **durch SIP geschützt** ist (du kannst dieses Flag nicht zu einer Datei hinzufügen).
- **`Sticky bit`**: In einem Verzeichnis mit gesetztem Sticky bit können nur der Dateieigentümer, der Verzeichniseigentümer oder root einen Eintrag umbenennen oder löschen. Es ist typischerweise für `/tmp` aktiviert, um zu verhindern, dass Benutzer die Dateien anderer Benutzer löschen oder verschieben.

Alle Flags sind in der Datei `sys/stat.h` zu finden (suche sie mit `mdfind stat.h | grep stat.h`):

- `UF_SETTABLE` 0x0000ffff: Maske der vom Eigentümer änderbaren Flags.
- `UF_NODUMP` 0x00000001: Datei nicht sichern.
- `UF_IMMUTABLE` 0x00000002: Datei darf nicht geändert werden.
- `UF_APPEND` 0x00000004: An die Datei darf nur angehängt werden.
- `UF_OPAQUE` 0x00000008: Verzeichnis ist bezüglich Union undurchsichtig.
- `UF_COMPRESSED` 0x00000020: Datei ist komprimiert (auf einigen Dateisystemen).
- `UF_TRACKED` 0x00000040: Für Dateien mit diesem Flag werden keine Benachrichtigungen über Löschungen/Umbenennungen gesendet.
- `UF_DATAVAULT` 0x00000080: Zum Lesen und Schreiben ist ein Entitlement erforderlich.
- `UF_HIDDEN` 0x00008000: Hinweis, dass dieses Objekt nicht in einer GUI angezeigt werden soll.
- `SF_SUPPORTED` 0x009f0000: Maske der vom Superuser unterstützten Flags.
- `SF_SETTABLE` 0x3fff0000: Maske der vom Superuser änderbaren Flags.
- `SF_SYNTHETIC` 0xc0000000: Maske der schreibgeschützten synthetischen System-Flags.
- `SF_ARCHIVED` 0x00010000: Datei ist archiviert.
- `SF_IMMUTABLE` 0x00020000: Datei darf nicht geändert werden.
- `SF_APPEND` 0x00040000: An die Datei darf nur angehängt werden.
- `SF_RESTRICTED` 0x00080000: Zum Schreiben ist ein Entitlement erforderlich.
- `SF_NOUNLINK` 0x00100000: Objekt darf nicht entfernt, umbenannt oder eingehängt werden.
- `SF_FIRMLINK` 0x00800000: Datei ist ein Firmlink.
- `SF_DATALESS` 0x40000000: Datei ist ein dataless object.

### **Datei-ACLs**

Datei-**ACLs** enthalten **ACE** (Access Control Entries), über die verschiedenen Benutzern **detailliertere Berechtigungen** zugewiesen werden können.

Einem **Verzeichnis** lassen sich folgende Berechtigungen zuweisen: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Für eine **Datei**: `read`, `write`, `append` und `execute`.

Wenn die Datei ACLs enthält, **siehst du beim Auflisten der Berechtigungen ein „+“, wie hier**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

Du kannst die **ACLs** der Datei mit folgendem Befehl **auslesen**:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

Du kannst **alle Dateien mit ACLs** mit folgendem Befehl finden (dies ist sehr langsam):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Erweiterte Attribute

Erweiterte Attribute sind benannte Metadatenwerte, die getrennt von den gewöhnlichen Attributen einer Datei gespeichert werden. Mit `ls -l@` lassen sie sich auflisten und mit `xattr` untersuchen oder ändern. <sup>[[5]](#references)</sup> Einige häufige erweiterte Attribute sind:

- `com.apple.resourceFork`: Kompatibilität mit Resource Forks. Auch sichtbar als `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Quarantäne-Metadaten von macOS Gatekeeper
- `metadata:*`: macOS-Metadaten, etwa `_backup_excludeItem` oder `kMD*`
- `com.apple.lastuseddate` (#PS): Datum der letzten Dateiverwendung
- `com.apple.FinderInfo`: Informationen des macOS Finders, etwa Farbetiketten
- `com.apple.TextEncoding`: Gibt die Textkodierung von ASCII-Textdateien an
- `com.apple.logd.metadata`: Wird von logd für Dateien in `/var/db/diagnostics` verwendet
- `com.apple.genstore.*`: Generational Storage (`/.DocumentRevisions-V100` im Stammverzeichnis des Dateisystems)
- `com.apple.rootless`: Mit System Integrity Protection verknüpfte macOS-Metadaten
- `com.apple.uuidb.boot-uuid`: Markierungen von logd für Boot-Epochen mit eindeutiger UUID
- `com.apple.decmpfs`: Metadaten für transparente Dateikomprimierung von macOS
- `com.apple.cprotect`: \*OS: Verschlüsselungsdaten pro Datei (III/11)
- `com.apple.installd.*`: \*OS: Von installd verwendete Metadaten, z. B. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource Forks stellen unter macOS einen alternativen Datenstrom bereit. Inhalte können im erweiterten Attribut `com.apple.ResourceFork` gespeichert und über `file/..namedfork/rsrc` abgerufen werden.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

Mit folgendem Befehl kannst du alle Dateien finden, die dieses erweiterte Attribut enthalten:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

Das erweiterte Attribut `com.apple.decmpfs` speichert Metadaten für transparente Komprimierung; es weist nicht auf eine Verschlüsselung hin. Je nach Komprimierungsformat können die komprimierten Daten im Attribut oder in einem Resource Fork gespeichert sein und werden beim Lesen transparent dekomprimiert.

Das Flag `UF_COMPRESSED` wird in `ls -lO` als `compressed` angezeigt. Lösche es nicht manuell: Dadurch kann das System die komprimierte Darstellung falsch interpretieren.

Der Befehl zum Löschen des Flags wird hier gezeigt, weil er bei forensischen Untersuchungen nützlich ist. Wird er jedoch auf eine komprimierte Datei angewendet, kann die Datei leer oder unzugänglich erscheinen, bis ihre Metadaten repariert wurden:

```bash
chflags nocompressed /path/to/file
```

Das integrierte Dienstprogramm `/usr/bin/afscexpand` kann die Expansion transparent komprimierter Dateien erzwingen. Das separate Drittanbieter-Dienstprogramm `afsctool` kann Apple-Dateisystemkomprimierung ebenfalls untersuchen oder dekomprimieren, sollte aber nicht mit dem integrierten Befehl verwechselt werden. <sup>[[8]](#references)</sup>


### Interessante Konfigurationsorte (macOS)

| Pfad / Ort | Zweck / Konfiguration | Sicherheit / Angriffspotenzial |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Enthält Apples Feature-Flag-PLIST-Dateien zur Steuerung optionaler oder experimenteller Verhaltensweisen in System-Daemons und Frameworks | Wenn ein Angreifer SIP umgehen oder privilegierten Zugriff erlangen kann, könnte eine Manipulation versteckte Codepfade aktivieren oder Schutzmaßnahmen deaktivieren |
| `/System/Library/CoreServices/systemVersion.plist` | Enthält macOS-Versionsmetadaten (ProductVersion, BuildVersion), die Apps und Installer zur Verhaltenssteuerung verwenden | Änderungen können Apps oder Installer dazu verleiten, nicht unterstützte OS-Versionen zu akzeptieren oder Funktionen freizuschalten |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Anwendungsweite und systemweite Einstellungen | Sind diese Dateien beschreibbar, können Angreifer Einstellungen einschleusen, um das App-Verhalten zu beeinflussen, Schutzmaßnahmen zu deaktivieren oder Fehlkonfigurationen zu verursachen |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | PLIST-Definitionen für Hintergrund-Daemons und Agents | Das Einschleusen oder Manipulieren schädlicher PLIST-Dateien (sofern die Berechtigungen es zulassen) ermöglicht Persistenz oder Privilegieneskalationen |
| `/etc/hosts` | Hostname-↔-IP-Zuordnungen, die der systemeigene DNS-Resolver verwendet | Umleiten von Domainnamen, Abfangen von Datenverkehr und Spoofing lokal kontrollierter Dienste |
| `/etc/sudoers` | Legt fest, wer unter welchen Bedingungen Befehle mit `sudo` ausführen darf | Eine manipulierte sudoers-Datei kann Angreiferkonten Root- oder unzulässige Berechtigungen gewähren |
| `/private/var/db/dslocal/nodes/Default/users/` | PLIST-Dateien mit Definitionen lokaler Benutzerkonten | Manipulationen ermöglichen das Erstellen oder Ändern von Benutzerkonten, Passwort-Hashes oder Benutzermetadaten |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel-Erweiterungen / Treiber | Das Installieren oder Ändern von kexts kann Kontrolle auf Kernel-Ebene ermöglichen; SIP und Signaturrichtlinien schützen diese besonders stark |
| `/private/var/db/SystemPolicyConfiguration/` | Enthält Konfigurationen zur Durchsetzung von Systemrichtlinien (z. B. Gatekeeper, Notarisierung) | Manipulationen können die Umgehung von Richtlinienprüfungen oder Vertrauensregeln ermöglichen |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH-Hilfsprogramme und Konfigurationsdateien | Fehlkonfiguration kann zu schwacher SSH-Sicherheit, unbefugtem Zugriff oder unsicheren Algorithmen führen |
| `/System/Library/Sandbox/Profiles` | System-Sandbox-Profile (SBPL), die Prozessaktionen einschränken | Das Ersetzen oder Ändern von Profilen kann Sandbox-Escape-Angriffsvektoren eröffnen oder die Isolation schwächen |

> **Hinweis**: Viele dieser Pfade liegen in SIP-geschützten Verzeichnissen (z. B. `/System`) und sind gegen Schreibzugriffe geschützt, sofern SIP nicht deaktiviert oder umgangen wird.  


## Universal Binaries und das Mach-O-Format

Mach-O ist das native ausführbare Format unter macOS. Ein Universal- oder Fat-Binary bündelt mehrere architekturspezifische Mach-O-Slices in einer Datei; die entsprechende Seite erläutert beide Formate:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Speicherabbilder unter macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Dateirisiken und Handler-Metadaten

LaunchServices, Dateiquarantäne und Gatekeeper beeinflussen gemeinsam, wie macOS heruntergeladene Dateien verarbeitet und Anwendungen für Erweiterungen und URL-Schemata auswählt. Ihre Datenbanken und internen Ressourcendateien ändern sich zwischen Releases; verwende daher die entsprechenden Seiten, statt einen privaten CoreTypes-Pfad als stabile Richtlinienschnittstelle zu behandeln:

In Releases, in denen die Metadaten zu den älteren CoreTypes-Risikokategorien unter `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` verfügbar sind, kommen häufig folgende Kategorien vor:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: Inhalte, die gemäß den geltenden Anwendungsrichtlinien als sicher genug für das automatische Öffnen gelten.
- **`LSRiskCategoryNeutral`**: Inhalte, die normalerweise keine Warnung auslösen und nicht automatisch geöffnet werden.
- **`LSRiskCategoryUnsafeExecutable`**: Ausführbare Inhalte, für die der Benutzer eine Anwendungswarnung erhalten sollte.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Container wie Archive, die ausführbare Inhalte enthalten können und daher genauer untersucht werden müssen.

Dies sind Implementierungsdetails und keine stabile öffentliche Richtlinien-API. Überprüfe die tatsächlichen Metadaten und das Verhalten von Safari und Gatekeeper in der zu testenden macOS-Version.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Protokolldateien

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Enthält Informationen zu heruntergeladenen Dateien, etwa die URL, von der sie heruntergeladen wurden.
- **Einheitliches Protokoll**: Verwende in aktuellen macOS-Versionen `log show` und `log stream`, um System- und Anwendungsereignisse abzufragen. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** und **`/private/var/log/asl/*.asl`**: Ältere Protokollartefakte, die auf älteren Systemen noch relevant sein können. In diesen Releases konfiguriert `/System/Library/LaunchDaemons/com.apple.syslogd.plist` `syslogd`; `launchctl list | grep com.apple.syslogd` kann dabei helfen festzustellen, ob der Dienst geladen ist.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Speichert über „Finder“ zuletzt aufgerufene Dateien und Anwendungen.
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Älterer Einstellungs-Pfad für Anmeldeobjekte; aktuelle macOS-Versionen verwenden zusätzliche Mechanismen.
- **`$HOME/Library/Logs/DiskUtility.log`**: Älteres Festplattendienstprogramm-Protokoll, das Informationen zu Laufwerken, einschließlich USB-Geräten, enthalten kann.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Daten zu WLAN-Zugangspunkten.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Ältere launchd-Override-Daten.



## References

- [1] [Apple – Leitfaden zur Dateisystemprogrammierung](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple – Leitfaden zur Bundle-Programmierung](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums – Überblick über den dyld Shared Cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple – Leitfaden zur Dateisystemprogrammierung: Sicherheit des macOS-Dateisystems](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` – macOS-Handbuchseite](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` – macOS-Handbuchseite](https://manp.gs/mac/1/log)
- [7] [Apple Developer – Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` – macOS-Handbuchseite](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums – Apple-Archive entpacken](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld – DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple – Sicherheit von Shell-Skripten: spezielle Dateiberechtigungs-Flags](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple – Aufgaben zur Codesignierung: Installer-Pakete](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
