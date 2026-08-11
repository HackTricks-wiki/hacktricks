# macOS-Dateien, Ordner, Binaries & Speicher

{{#include ../../../banners/hacktricks-training.md}}

## Hierarchie des Dateisystems

Apple dokumentiert das macOS-Dateisystem als Hierarchie aus System-, lokalen, Netzwerk- und Benutzer-Domänen. Die genauen Inhalte variieren je nach OS-Version, und Systempfade werden zunehmend geschützt oder synthetisiert. <sup>[[1]](#references)</sup>

- **/Applications**: Die installierten Apps sollten sich hier befinden. Alle Benutzer können auf sie zugreifen.
- **/bin**: Binaries für die Kommandozeile
- **/cores**: Falls vorhanden, wird dieser Ordner zum Speichern von Core Dumps verwendet.
- **/dev**: Alles wird als Datei behandelt, daher können hier gespeicherte Hardwaregeräte zu finden sein.
- **/etc**: Konfigurationsdateien
- **/Library**: Hier befinden sich viele Unterverzeichnisse und Dateien im Zusammenhang mit Einstellungen, Caches und Logs. Ein Library-Ordner existiert im Root-Verzeichnis und im Verzeichnis jedes Benutzers.
- **/private**: Nicht dokumentiert, aber viele der genannten Ordner sind symbolische Links auf das private Verzeichnis.
- **/sbin**: Essenzielle System-Binaries (im Zusammenhang mit der Administration)
- **/System**: Von macOS benötigte Dateien; dieser Verzeichnisbaum enthält hauptsächlich von Apple bereitgestellte Komponenten.
- **/tmp**: Temporäre Dateien (ein symbolischer Link auf `/private/tmp`). Bei historischen Installationen wurden alte temporäre Dateien üblicherweise regelmäßig bereinigt, teilweise mit einem Zeitraum von drei Tagen beschrieben. Die aktuelle Bereinigungsdauer hängt jedoch vom System und den Richtlinien ab. Verlasse dich daher nicht darauf, dass Daten dort erhalten bleiben.
- **/Users**: Home-Verzeichnis der Benutzer
- **/usr**: Konfigurations- und System-Binaries
- **/var**: Log-Dateien
- **/Volumes**: Eingehängte Volumes werden hier angezeigt.
- **/.vol**: Wenn du `stat a.txt` ausführst, erhältst du etwas wie `16777223 7545753 -rw-r--r-- 1 username wheel ...`, wobei die erste Zahl die ID-Nummer des Volumes ist, auf dem sich die Datei befindet, und die zweite die Inode-Nummer. Du kannst über `/.vol/` auf den Inhalt dieser Datei zugreifen, indem du diese Informationen mit `cat /.vol/16777223/7545753` verwendest.

### Anwendungsordner

- **Systemanwendungen** befinden sich unter `/System/Applications`.
- **Installierte** Anwendungen werden üblicherweise in `/Applications` oder in `~/Applications` installiert.
- **Anwendungsdaten** befinden sich für Anwendungen, die als Root ausgeführt werden, in `/Library/Application Support` und für Anwendungen, die als Benutzer ausgeführt werden, in `~/Library/Application Support`.
- **Daemons** von Drittanbieter-Anwendungen, die **als Root ausgeführt werden müssen**, befinden sich üblicherweise in `/Library/PrivilegedHelperTools/`.
- **Sandboxed** Apps werden in den Ordner `~/Library/Containers` abgebildet. Jede App besitzt einen Ordner, der nach der Bundle-ID der Anwendung benannt ist (`com.apple.Safari`).
- Der **Kernel** befindet sich in `/System/Library/Kernels/kernel`.
- **Kernel-Erweiterungen von Apple** befinden sich in `/System/Library/Extensions`.
- **Kernel-Erweiterungen von Drittanbietern** werden in `/Library/Extensions` gespeichert.

### Dateien mit sensiblen Informationen

macOS speichert an mehreren Stellen sensible Informationen, einschließlich Zugangsdaten:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Verwundbare pkg-Installer


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Spezifische OS-X-Erweiterungen

- **`.dmg`**: Apple-Disk-Image-Dateien werden sehr häufig für Installer verwendet.
- **`.kext`**: Muss einer bestimmten Struktur folgen und ist die OS-X-Version eines Treibers. (Es handelt sich um ein Bundle.)
- **`.plist`**: Eine Property List speichert strukturierte Informationen im XML- oder Binärformat.
- Kann XML oder binär sein. Binärdateien können gelesen werden mit:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Ein Application Bundle, das der standardmäßigen macOS-Verzeichnisstruktur folgt.
- **`.dylib`**: Dynamische Libraries (wie Windows-DLL-Dateien)
- **`.pkg`**: Entsprechen xar (eXtensible Archive Format). Der Installer-Befehl kann verwendet werden, um den Inhalt dieser Dateien zu installieren.
- **`.DS_Store`**: Diese Datei befindet sich in jedem Verzeichnis und speichert die Attribute und Anpassungen des Verzeichnisses.
- **`.Spotlight-V100`**: Dieser Ordner erscheint im Root-Verzeichnis jedes Volumes im System.
- **`.metadata_never_index`**: Wenn sich diese Datei im Root-Verzeichnis eines Volumes befindet, wird dieses Volume nicht von Spotlight indexiert.
- **`.noindex`**: Dateien und Ordner mit dieser Erweiterung werden von Spotlight nicht indexiert.
- **`.sdef`**: Eine Scripting-Definitionsdatei, die beschreibt, wie AppleScript mit einer Anwendung interagieren kann.

### macOS-Bundles

Ein Bundle ist ein Verzeichnis mit einer standardisierten Hierarchie, das Finder als einzelnes Objekt darstellen kann; Application Bundles verwenden die Erweiterung `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Unter macOS und iOS werden häufig verwendete System-Libraries und Frameworks in den **dyld shared cache** vorverknüpft, wodurch die Startleistung von Anwendungen verbessert wird. Obwohl er als ein logischer Cache behandelt wird, kann er in aktuellen Versionen aus einem Haupt-Cache und mehreren Subcache-Dateien bestehen, anstatt buchstäblich nur eine Datei zu sein. Sein Format und sein Speicherort sind Implementierungsdetails, die sich zwischen OS-Versionen ändern. <sup>[[3]](#references)</sup>

Unter macOS befindet er sich in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`; in älteren Versionen konnte der **shared cache** möglicherweise in **`/System/Library/dyld/`** gefunden werden.\
Unter iOS befinden sie sich in **`/System/Library/Caches/com.apple.dyld/`**.

Ähnlich wie der dyld shared cache werden auch der Kernel und die Kernel-Erweiterungen in einen Kernel-Cache kompiliert, der beim Booten geladen wird.

Ältere Versionen konnten mit [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) extrahiert werden. Dieser Build unterstützt möglicherweise keine aktuellen Cache-Formate; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) ist eine weitere Option:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Beachte, dass du selbst dann, wenn das Tool `dyld_shared_cache_util` nicht funktioniert, die **shared dyld binary an Hopper** übergeben kannst. Hopper ist dann in der Lage, alle Libraries zu identifizieren, und lässt dich **auswählen, welche du untersuchen** möchtest:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Einige Extractors funktionieren nicht, da dylibs mit fest codierten Adressen vorverknüpft sind und daher möglicherweise zu unbekannten Adressen springen.

> [!TIP]
> Es ist auch möglich, den Shared Library Cache anderer \*OS-Geräte in macOS herunterzuladen, indem ein Emulator in Xcode verwendet wird. Sie werden hier heruntergeladen: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, zum Beispiel:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### SLC-Mapping

**`dyld`** verwendet den syscall **`shared_region_check_np`**, um festzustellen, ob der SLC gemappt wurde (wodurch die Adresse zurückgegeben wird), sowie **`shared_region_map_and_slide_np`**, um den SLC zu mappen.

Beachte, dass selbst wenn der SLC bei der ersten Verwendung geslidet wird, alle **Prozesse** dieselbe **Kopie** verwenden, wodurch der **ASLR**-Schutz aufgehoben wird, wenn der Angreifer Prozesse im System ausführen konnte. Dies wurde in der Vergangenheit tatsächlich ausgenutzt und mit dem shared region pager behoben.

Branch pools sind kleine Mach-O-dylibs, die kleine Abstände zwischen Image-Mappings erzeugen und dadurch das Interposen der Funktionen unmöglich machen.

### SLCs überschreiben

Unter Verwendung der Umgebungsvariablen:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Dadurch kann ein neuer Shared Library Cache geladen werden.
- **`DYLD_SHARED_CACHE_DIR=avoid`** und die Libraries manuell durch Symlinks zum Shared Cache mit den echten Libraries ersetzen (du musst sie extrahieren).

## Spezielle Dateiberechtigungen

### Verzeichnisberechtigungen

Für ein Verzeichnis erlaubt **read** das Auflisten von Einträgen, **write** das Erstellen oder Entfernen von Einträgen und **execute** das Durchqueren. Folglich kann ein Benutzer, der eine Datei lesen, aber ein übergeordnetes Verzeichnis nicht durchqueren kann, nicht über den Pfad auf diese Datei zugreifen. <sup>[[4]](#references)</sup>

### Flag-Modifikatoren

Dateien können Flags enthalten, die ihr Verhalten ändern. Untersuche die Flags in einem Verzeichnis mit `ls -lO /path/directory`.

- **`uchg`**: Das als **uchange**-Flag bekannte Flag **verhindert jede Aktion**, durch die die **Datei** geändert oder gelöscht wird. Setze es mit: `chflags uchg file.txt`
- Der Root-Benutzer könnte das **Flag entfernen** und die Datei ändern.
- **`restricted`**: Dieses Flag sorgt dafür, dass die Datei **durch SIP geschützt** ist (du kannst dieses Flag nicht zu einer Datei hinzufügen).
- **`Sticky bit`**: In einem Verzeichnis mit gesetztem Sticky bit kann nur der Dateibesitzer, der Verzeichnisbesitzer oder root einen Eintrag umbenennen oder löschen. Dies ist typischerweise auf `/tmp` aktiviert, um zu verhindern, dass Benutzer die Dateien anderer Benutzer löschen oder verschieben.

Alle Flags sind in der Datei `sys/stat.h` zu finden (ermittle sie mit `mdfind stat.h | grep stat.h`) und lauten:

- `UF_SETTABLE` 0x0000ffff: Maske der durch den Besitzer änderbaren Flags.
- `UF_NODUMP` 0x00000001: Datei nicht dumpen.
- `UF_IMMUTABLE` 0x00000002: Datei darf nicht geändert werden.
- `UF_APPEND` 0x00000004: An die Datei darf nur angehängt werden.
- `UF_OPAQUE` 0x00000008: Verzeichnis ist bezüglich Union opaque.
- `UF_COMPRESSED` 0x00000020: Datei ist komprimiert (einige Dateisysteme).
- `UF_TRACKED` 0x00000040: Keine Benachrichtigungen über Löschungen/Umbenennungen für Dateien, bei denen dieses Flag gesetzt ist.
- `UF_DATAVAULT` 0x00000080: Für das Lesen und Schreiben ist ein Entitlement erforderlich.
- `UF_HIDDEN` 0x00008000: Hinweis, dass dieses Element nicht in einer GUI angezeigt werden soll.
- `SF_SUPPORTED` 0x009f0000: Maske der vom Superuser unterstützten Flags.
- `SF_SETTABLE` 0x3fff0000: Maske der durch den Superuser änderbaren Flags.
- `SF_SYNTHETIC` 0xc0000000: Maske der synthetischen, schreibgeschützten System-Flags.
- `SF_ARCHIVED` 0x00010000: Datei ist archiviert.
- `SF_IMMUTABLE` 0x00020000: Datei darf nicht geändert werden.
- `SF_APPEND` 0x00040000: An die Datei darf nur angehängt werden.
- `SF_RESTRICTED` 0x00080000: Für das Schreiben ist ein Entitlement erforderlich.
- `SF_NOUNLINK` 0x00100000: Element darf nicht entfernt, umbenannt oder gemountet werden.
- `SF_FIRMLINK` 0x00800000: Datei ist ein Firmlink.
- `SF_DATALESS` 0x40000000: Datei ist ein dataless object.

### **Datei-ACLs**

Datei-**ACLs** enthalten **ACEs** (Access Control Entries), über die verschiedenen Benutzern **granularere Berechtigungen** zugewiesen werden können.

Einem **Verzeichnis** können diese Berechtigungen gewährt werden: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Für eine **Datei**: `read`, `write`, `append` und `execute`.

Wenn die Datei ACLs enthält, wirst du beim Auflisten der Berechtigungen ein **„+“ finden, wie in**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Du kannst die **ACLs** der Datei mit Folgendem **lesen**:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Mit folgendem Befehl können Sie **alle Dateien mit ACLs** finden (dies ist sehr langsam):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Erweiterte Attribute

Erweiterte Attribute sind benannte Metadatenwerte, die getrennt von den gewöhnlichen Attributen einer Datei gespeichert werden. Sie können mit `ls -l@` aufgelistet und mit `xattr` untersucht oder geändert werden. <sup>[[5]](#references)</sup> Einige häufige erweiterte Attribute sind:

- `com.apple.resourceFork`: Kompatibilität mit Resource Forks. Auch sichtbar als `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Quarantäne-Metadaten für macOS Gatekeeper
- `metadata:*`: macOS-Metadaten, z. B. `_backup_excludeItem` oder `kMD*`
- `com.apple.lastuseddate` (#PS): Datum der letzten Dateinutzung
- `com.apple.FinderInfo`: macOS-Finder-Informationen, z. B. Farb-Tags
- `com.apple.TextEncoding`: Gibt die Textkodierung von ASCII-Textdateien an
- `com.apple.logd.metadata`: Wird von logd für Dateien in `/var/db/diagnostics` verwendet
- `com.apple.genstore.*`: Generational Storage (`/.DocumentRevisions-V100` im Stammverzeichnis des Dateisystems)
- `com.apple.rootless`: Mit System Integrity Protection verbundene macOS-Metadaten
- `com.apple.uuidb.boot-uuid`: Markierungen von logd für Boot-Epochen mit einer eindeutigen UUID
- `com.apple.decmpfs`: Metadaten für die transparente Dateikomprimierung von macOS
- `com.apple.cprotect`: \*OS: Verschlüsselungsdaten pro Datei (III/11)
- `com.apple.installd.*`: \*OS: Von installd verwendete Metadaten, z. B. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource Forks stellen einen alternativen Datenstrom unter macOS bereit. Inhalte können im erweiterten Attribut `com.apple.ResourceFork` gespeichert und über `file/..namedfork/rsrc` abgerufen werden.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Du kannst **alle Dateien finden, die dieses erweiterte Attribut enthalten**, mit:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Das erweiterte Attribut `com.apple.decmpfs` speichert Metadaten für transparente Komprimierung; es weist nicht auf eine Verschlüsselung hin. Abhängig vom Komprimierungsformat können komprimierte Daten im Attribut oder in einem resource fork gespeichert und beim Lesen transparent dekomprimiert werden.

Das Flag `UF_COMPRESSED` erscheint in `ls -lO` als `compressed`. Entfernen Sie es nicht manuell: Dadurch kann das System die komprimierte Darstellung falsch interpretieren.

Der Befehl zum Entfernen des Flags wird hier gezeigt, da er während einer forensischen Untersuchung nützlich ist. Wird er jedoch auf eine komprimierte Datei angewendet, kann diese Datei leer oder unzugänglich erscheinen, bis ihre Metadaten repariert wurden:
```bash
chflags nocompressed /path/to/file
```
Das integrierte Dienstprogramm `/usr/bin/afscexpand` kann die Expansion transparent komprimierter Dateien erzwingen. Das separate Third-Party-Dienstprogramm `afsctool` kann die Apple-Dateisystemkomprimierung ebenfalls untersuchen oder dekomprimieren, sollte jedoch nicht mit dem integrierten Befehl verwechselt werden. <sup>[[8]](#references)</sup>


### Interessante Konfigurationsorte (macOS)

| Pfad / Ort | Zweck / Was konfiguriert wird | Sicherheits- / Angriffspotenzial |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Speichert Apples Feature-Flag-plist-Dateien, die optionale oder experimentelle Verhaltensweisen in System-Daemons / Frameworks steuern | Wenn ein Angreifer SIP umgehen oder Privilegien erlangen kann, könnte eine Manipulation versteckte Codepfade aktivieren oder Schutzmaßnahmen deaktivieren |
| `/System/Library/CoreServices/systemVersion.plist` | Enthält macOS-Versionsmetadaten (ProductVersion, BuildVersion), die von Apps / Installationsprogrammen zur Steuerung des Verhaltens verwendet werden | Eine Änderung kann Apps oder Installationsprogramme dazu bringen, nicht unterstützte OS-Versionen zu akzeptieren oder Funktionen freizuschalten |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Anwendungs- / systemweite Einstellungen | Falls beschreibbar, können Angreifer Einstellungen einschleusen, um das Verhalten von Apps zu steuern, Schutzmaßnahmen zu deaktivieren oder Fehlkonfigurationen zu verursachen |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist-Definitionen für Hintergrund-Daemons und Agents | Das Einschleusen oder Manipulieren bösartiger Plists (falls die Berechtigungen dies erlauben) ermöglicht Persistenz oder Privilege Escalation |
| `/etc/hosts` | Hostname- ↔ IP-Zuordnungen, die vom systemweiten DNS-Resolver verwendet werden | Umleiten von Domainnamen, Abfangen von Traffic, Spoofing von Diensten unter lokaler Kontrolle |
| `/etc/sudoers` | Definiert, wer Befehle mit `sudo` und unter welchen Bedingungen ausführen kann | Eine beschädigte sudoers-Datei kann Root- oder unangemessene Privilegien für Angreiferkonten gewähren |
| `/private/var/db/dslocal/nodes/Default/users/` | Plists mit Definitionen lokaler Benutzerkonten | Eine Manipulation ermöglicht das Erstellen oder Ändern von Benutzerkonten, Passwort-Hashes oder Benutzermetadaten |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel-Erweiterungen / Treiber | Das Installieren oder Ändern von kexts kann zu Kontrolle auf Kernel-Ebene führen; durch SIP- / Signaturrichtlinien stark geschützt |
| `/private/var/db/SystemPolicyConfiguration/` | Speichert die Konfiguration für die Durchsetzung von Systemrichtlinien (z. B. Gatekeeper, Notarisierung) | Eine Manipulation kann die Umgehung von Richtlinienprüfungen oder Vertrauensregeln ermöglichen |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH-Hilfsprogramme und Konfigurationsdateien | Fehlkonfigurationen führen zu schwacher SSH-Sicherheit, unbefugtem Zugriff oder unsicheren Algorithmen |
| `/System/Library/Sandbox/Profiles` | System-Sandbox-Profile (SBPL), die zur Einschränkung von Prozessaktionen verwendet werden | Das Ersetzen oder Ändern von Profilen kann Vektoren für Sandbox Escape eröffnen oder die Isolation schwächen |

> **Hinweis**: Viele dieser Pfade liegen in SIP-geschützten Verzeichnissen (z. B. `/System`) und sind vor Schreibzugriffen geschützt, sofern SIP nicht deaktiviert oder umgangen wird.


## Universal Binaries und Mach-O-Format

Mach-O ist das native Format für ausführbare Dateien unter macOS. Ein Universal- oder Fat-Binary kapselt mehrere architekturspezifische Mach-O-Slices in einer Datei; die entsprechende Seite erklärt beide Formate:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Metadaten zu Dateirisiken und Handlern

LaunchServices, Dateiquarantäne und Gatekeeper beeinflussen gemeinsam, wie macOS heruntergeladene Dateien behandelt und Anwendungen für Erweiterungen und URL-Schemata auswählt. Ihre Datenbanken und internen Ressourcendateien ändern sich zwischen Releases; verwende die entsprechenden Seiten, anstatt einen privaten CoreTypes-Pfad als stabile Richtlinienschnittstelle zu behandeln:

Auf Releases, die die Legacy-CoreTypes-Risikometadaten unter `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` bereitstellen, sind die häufig anzutreffenden Kategorien:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: Inhalte, die gemäß der jeweils geltenden Anwendungsrichtlinie als sicher genug für das automatische Öffnen gelten.
- **`LSRiskCategoryNeutral`**: Inhalte, die normalerweise keine Warnung auslösen und nicht automatisch geöffnet werden.
- **`LSRiskCategoryUnsafeExecutable`**: Ausführbare Inhalte, für die der Benutzer eine Anwendungswarnung erhalten sollte.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Container wie Archive, die ausführbare Inhalte enthalten können und eine weitere Prüfung erfordern.

Dies sind Implementierungsdetails und keine stabile öffentliche Richtlinien-API; bestätige die tatsächlichen Metadaten sowie das Safari-/Gatekeeper-Verhalten für die getestete macOS-Version.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Logdateien

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Enthält Informationen über heruntergeladene Dateien, z. B. die URL, von der sie heruntergeladen wurden.
- **Unified log**: Auf aktuellen macOS-Versionen können System- und Anwendungsereignisse mit `log show` und `log stream` abgefragt werden. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** und **`/private/var/log/asl/*.asl`**: Legacy-Logging-Artefakte, die auf älteren Systemen weiterhin relevant sein können. Auf diesen Releases konfiguriert `/System/Library/LaunchDaemons/com.apple.syslogd.plist` den `syslogd`; `launchctl list | grep com.apple.syslogd` kann dabei helfen festzustellen, ob der Dienst geladen ist.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Speichert über den „Finder“ zuletzt aufgerufene Dateien und Anwendungen.
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Legacy-Einstellungspfad im Zusammenhang mit Login-Items; moderne macOS-Versionen verwenden zusätzliche Mechanismen.
- **`$HOME/Library/Logs/DiskUtility.log`**: Legacy-Protokoll des Festplattendienstprogramms, das Informationen über Laufwerke, einschließlich USB-Geräten, enthalten kann.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Daten über drahtlose Access Points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy-Override-Daten von launchd.

## References

- [1] [Apple - Programmierleitfaden für Dateisysteme](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Programmierleitfaden für Bundles](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - Übersicht über den dyld Shared Cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Programmierleitfaden für Dateisysteme: Sicherheit des macOS-Dateisystems](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS-Handbuchseite](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS-Handbuchseite](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS-Handbuchseite](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
