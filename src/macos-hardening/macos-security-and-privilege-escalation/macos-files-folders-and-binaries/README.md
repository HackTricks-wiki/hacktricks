# macOS-Dateien, Ordner, Binaries & Memory

{{#include ../../../banners/hacktricks-training.md}}

## Dateihierarchie

- **/Applications**: Die installierten Apps sollten sich hier befinden. Alle Benutzer können auf sie zugreifen.
- **/bin**: Binaries für die Kommandozeile
- **/cores**: Falls vorhanden, wird dieser Ordner zum Speichern von core dumps verwendet.
- **/dev**: Alles wird als Datei behandelt, daher können hier gespeicherte Hardwaregeräte zu finden sein.
- **/etc**: Konfigurationsdateien
- **/Library**: Hier befinden sich viele Unterverzeichnisse und Dateien im Zusammenhang mit Einstellungen, Caches und Logs. Ein Library-Ordner existiert im Root-Verzeichnis und im Verzeichnis jedes Benutzers.
- **/private**: Nicht dokumentiert, aber viele der genannten Ordner sind symbolische Links auf das private-Verzeichnis.
- **/sbin**: Essenzielle System-Binaries (im Zusammenhang mit der Administration)
- **/System**: Dateien, die für die Ausführung von OS X erforderlich sind. Hier sollten sich hauptsächlich Apple-spezifische Dateien befinden (keine Dateien von Drittanbietern).
- **/tmp**: Dateien werden nach 3 Tagen gelöscht (dies ist ein Softlink auf /private/tmp).
- **/Users**: Home-Verzeichnis der Benutzer.
- **/usr**: Konfigurations- und System-Binaries
- **/var**: Log-Dateien
- **/Volumes**: Die gemounteten Laufwerke werden hier angezeigt.
- **/.vol**: Wenn du `stat a.txt` ausführst, erhältst du etwas wie `16777223 7545753 -rw-r--r-- 1 username wheel ...`, wobei die erste Zahl die ID-Nummer des Volumes ist, auf dem sich die Datei befindet, und die zweite die Inode-Nummer. Du kannst über `/.vol/` auf den Inhalt dieser Datei zugreifen, indem du diese Informationen mit `cat /.vol/16777223/7545753` verwendest.

### Applications-Ordner

- **Systemanwendungen** befinden sich unter `/System/Applications`.
- **Installierte** Anwendungen werden normalerweise in `/Applications` oder in `~/Applications` installiert.
- **Anwendungsdaten** befinden sich für als root ausgeführte Anwendungen in `/Library/Application Support` und für als Benutzer ausgeführte Anwendungen in `~/Library/Application Support`.
- **Daemons** von Drittanbieteranwendungen, die **als root ausgeführt werden müssen**, befinden sich normalerweise in `/Library/PrivilegedHelperTools/`.
- **Sandboxed** Apps werden in den Ordner `~/Library/Containers` eingebunden. Jede App verfügt über einen Ordner, der nach der Bundle-ID der Anwendung benannt ist (`com.apple.Safari`).
- Der **Kernel** befindet sich in `/System/Library/Kernels/kernel`.
- **Kernel extensions von Apple** befinden sich in `/System/Library/Extensions`.
- **Kernel extensions von Drittanbietern** werden in `/Library/Extensions` gespeichert.

### Dateien mit vertraulichen Informationen

MacOS speichert Informationen wie Passwörter an mehreren Stellen:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Verwundbare pkg-Installer


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Spezifische Erweiterungen von OS X

- **`.dmg`**: Apple Disk Image-Dateien werden häufig für Installer verwendet.
- **`.kext`**: Diese Dateien müssen einer bestimmten Struktur folgen und sind die OS-X-Version eines Treibers (es handelt sich um ein Bundle).
- **`.plist`**: Auch als Property List bekannt; speichert Informationen im XML- oder Binärformat.
- Kann XML oder binär sein. Binärdateien können gelesen werden mit:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple-Anwendungen, die einer Verzeichnisstruktur folgen (es handelt sich um ein Bundle).
- **`.dylib`**: Dynamische Libraries (wie Windows-DLL-Dateien)
- **`.pkg`**: Entsprechen xar (eXtensible Archive format). Der Installer-Befehl kann verwendet werden, um den Inhalt dieser Dateien zu installieren.
- **`.DS_Store`**: Diese Datei befindet sich in jedem Verzeichnis und speichert die Attribute und Anpassungen des Verzeichnisses.
- **`.Spotlight-V100`**: Dieser Ordner erscheint im Root-Verzeichnis jedes Volumes auf dem System.
- **`.metadata_never_index`**: Wenn sich diese Datei im Root-Verzeichnis eines Volumes befindet, wird dieses Volume von Spotlight nicht indiziert.
- **`.noindex`**: Dateien und Ordner mit dieser Erweiterung werden von Spotlight nicht indiziert.
- **`.sdef`**: Dateien innerhalb von Bundles, die festlegen, wie mit der Anwendung über ein AppleScript interagiert werden kann.

### macOS-Bundles

Ein Bundle ist ein **Verzeichnis**, das im **Finder wie ein Objekt aussieht** (ein Beispiel für ein Bundle sind `*.app`-Dateien).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Unter macOS (und iOS) werden alle Shared Libraries des Systems, wie Frameworks und dylibs, **zu einer einzigen Datei zusammengefasst**, die als **dyld shared cache** bezeichnet wird. Dies verbessert die Performance, da Code schneller geladen werden kann.

Unter macOS befindet sich diese Datei in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`. In älteren Versionen findet sich der **shared cache** möglicherweise in **`/System/Library/dyld/`**.\
Unter iOS befinden sie sich in **`/System/Library/Caches/com.apple.dyld/`**.

Ähnlich wie der dyld shared cache werden auch der Kernel und die Kernel extensions in einen Kernel-Cache kompiliert, der beim Booten geladen wird.

Um die Libraries aus der einzelnen dylib shared cache-Datei zu extrahieren, konnte das Binary [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) verwendet werden, das heutzutage möglicherweise nicht mehr funktioniert. Du kannst jedoch auch [**dyldextractor**](https://github.com/arandomdev/dyldextractor) verwenden:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Beachten Sie, dass Sie selbst dann, wenn das Tool `dyld_shared_cache_util` nicht funktioniert, die **gemeinsam genutzte dyld-Binärdatei an Hopper übergeben** können. Hopper kann dann alle Bibliotheken identifizieren und Ihnen erlauben, **auszuwählen, welche Sie untersuchen** möchten:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Einige Extractors funktionieren nicht, da dylibs mit fest codierten Adressen vorverknüpft sind und daher möglicherweise zu unbekannten Adressen springen.

> [!TIP]
> Es ist auch möglich, den Shared Library Cache anderer \*OS-Geräte in macos herunterzuladen, indem ein Emulator in Xcode verwendet wird. Sie werden hier heruntergeladen: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, wie zum Beispiel:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** verwendet den Syscall **`shared_region_check_np`**, um festzustellen, ob der SLC gemappt wurde (wodurch die Adresse zurückgegeben wird), und **`shared_region_map_and_slide_np`**, um den SLC zu mappen.

Beachten Sie, dass der SLC selbst dann, wenn er bei der ersten Verwendung geslidet wird, von allen **Prozessen** dieselbe **Kopie** verwendet wird, wodurch der **ASLR**-Schutz entfällt, wenn der Angreifer in der Lage war, Prozesse auf dem System auszuführen. Dies wurde in der Vergangenheit tatsächlich ausgenutzt und mit dem shared region pager behoben.

Branch pools sind kleine Mach-O-dylibs, die kleine Abstände zwischen Image-Mappings erzeugen und dadurch das Interposen der Funktionen unmöglich machen.

### SLCs überschreiben

Unter Verwendung der Umgebungsvariablen:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Dies ermöglicht das Laden eines neuen Shared Library Cache.
- **`DYLD_SHARED_CACHE_DIR=avoid`** und manuelles Ersetzen der Bibliotheken durch Symlinks auf den Shared Cache mit den echten Bibliotheken (Sie müssen diese extrahieren).

## Spezielle Dateiberechtigungen

### Ordnerberechtigungen

In einem **Ordner** ermöglicht **Lesen**, ihn **aufzulisten**, **Schreiben**, Dateien darin zu **löschen** und zu **schreiben**, und **Ausführen**, das Verzeichnis zu **durchlaufen**. Ein Benutzer mit **Leseberechtigung für eine Datei** in einem Verzeichnis, für das er **keine Ausführungsberechtigung** besitzt, kann die Datei beispielsweise **nicht lesen**.

### Flag modifiers

Es gibt einige Flags, die für Dateien gesetzt werden können und dafür sorgen, dass sich die Datei anders verhält. Sie können die **Flags** der Dateien in einem Verzeichnis mit `ls -lO /path/directory` **überprüfen**.

- **`uchg`**: Das als **uchange** bekannte Flag **verhindert jede Aktion**, durch die die **Datei** geändert oder gelöscht wird. Zum Setzen verwenden Sie: `chflags uchg file.txt`
- Der Root-Benutzer kann das **Flag entfernen** und die Datei ändern.
- **`restricted`**: Dieses Flag sorgt dafür, dass die Datei **durch SIP geschützt** ist (Sie können dieses Flag nicht zu einer Datei hinzufügen).
- **`Sticky bit`**: Wenn ein Verzeichnis über das Sticky Bit verfügt, können **nur der Besitzer des Verzeichnisses oder Root Dateien umbenennen oder löschen**. Typischerweise wird dies für das Verzeichnis /tmp gesetzt, um zu verhindern, dass gewöhnliche Benutzer die Dateien anderer Benutzer löschen oder verschieben.

Alle Flags sind in der Datei `sys/stat.h` zu finden (verwenden Sie `mdfind stat.h | grep stat.h` zur Suche). Sie lauten:

- `UF_SETTABLE` 0x0000ffff: Maske der vom Besitzer änderbaren Flags.
- `UF_NODUMP` 0x00000001: Datei nicht dumpen.
- `UF_IMMUTABLE` 0x00000002: Datei darf nicht geändert werden.
- `UF_APPEND` 0x00000004: An die Datei darf nur angehängt werden.
- `UF_OPAQUE` 0x00000008: Verzeichnis ist bezüglich union undurchsichtig.
- `UF_COMPRESSED` 0x00000020: Datei ist komprimiert (einige Dateisysteme).
- `UF_TRACKED` 0x00000040: Keine Benachrichtigungen für Löschungen/Umbenennungen von Dateien, für die dieses Flag gesetzt ist.
- `UF_DATAVAULT` 0x00000080: Zum Lesen und Schreiben ist ein Entitlement erforderlich.
- `UF_HIDDEN` 0x00008000: Hinweis, dass dieses Element nicht in einer GUI angezeigt werden soll.
- `SF_SUPPORTED` 0x009f0000: Maske der vom Superuser unterstützten Flags.
- `SF_SETTABLE` 0x3fff0000: Maske der vom Superuser änderbaren Flags.
- `SF_SYNTHETIC` 0xc0000000: Maske der synthetischen, schreibgeschützten System-Flags.
- `SF_ARCHIVED` 0x00010000: Datei ist archiviert.
- `SF_IMMUTABLE` 0x00020000: Datei darf nicht geändert werden.
- `SF_APPEND` 0x00040000: An die Datei darf nur angehängt werden.
- `SF_RESTRICTED` 0x00080000: Zum Schreiben ist ein Entitlement erforderlich.
- `SF_NOUNLINK` 0x00100000: Element darf nicht entfernt, umbenannt oder gemountet werden.
- `SF_FIRMLINK` 0x00800000: Datei ist ein Firmlink.
- `SF_DATALESS` 0x40000000: Datei ist ein dataless object.

### **File ACLs**

Datei-**ACLs** enthalten **ACE** (Access Control Entries), über die **granularere Berechtigungen** für verschiedene Benutzer festgelegt werden können.

Einem **Verzeichnis** können die folgenden Berechtigungen gewährt werden: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Und einer **Datei**: `read`, `write`, `append`, `execute`.

Wenn die Datei ACLs enthält, wird beim Auflisten der Berechtigungen ein **„+“ angezeigt, wie in**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Du kannst die **ACLs** der Datei mit folgendem Befehl **lesen**:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Du kannst **alle Dateien mit ACLs** finden mit (das ist seeehr langsam):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Erweiterte Attribute

Erweiterte Attribute haben einen Namen und einen beliebigen Wert und können mit `ls -@` angezeigt sowie mit dem Befehl `xattr` bearbeitet werden. Einige häufige erweiterte Attribute sind:

- `com.apple.resourceFork`: Kompatibilität mit Resource Forks. Auch sichtbar als `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS: Gatekeeper-Quarantänemechanismus (III/6)
- `metadata:*`: macOS: verschiedene Metadaten, etwa `_backup_excludeItem` oder `kMD*`
- `com.apple.lastuseddate` (#PS): Datum der letzten Dateiverwendung
- `com.apple.FinderInfo`: macOS: Finder-Informationen (z. B. farbige Tags)
- `com.apple.TextEncoding`: Gibt die Textkodierung von ASCII-Textdateien an
- `com.apple.logd.metadata`: Wird von logd für Dateien in `/var/db/diagnostics` verwendet
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` im Root des Dateisystems)
- `com.apple.rootless`: macOS: Wird von System Integrity Protection verwendet, um Dateien zu kennzeichnen (III/10)
- `com.apple.uuidb.boot-uuid`: Markierungen von logd für Boot-Epochen mit eindeutiger UUID
- `com.apple.decmpfs`: macOS: Transparente Dateikomprimierung (II/7)
- `com.apple.cprotect`: \*OS: Verschlüsselungsdaten pro Datei (III/11)
- `com.apple.installd.*`: \*OS: Von installd verwendete Metadaten, z. B. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Dies ist eine Möglichkeit, **Alternate Data Streams auf macOS-Systemen** zu erhalten. Inhalte können in einem erweiterten Attribut namens **com.apple.ResourceFork** innerhalb einer Datei gespeichert werden, indem sie unter **file/..namedfork/rsrc** gespeichert werden.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Du kannst **alle Dateien finden, die dieses erweiterte Attribut enthalten**, mit:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Das erweiterte Attribut `com.apple.decmpfs` weist darauf hin, dass die Datei verschlüsselt gespeichert ist. `ls -l` meldet eine **Größe von 0**, und die komprimierten Daten befinden sich in diesem Attribut. Beim Zugriff auf die Datei wird sie im Speicher entschlüsselt.

Dieses Attribut kann mit `ls -lO` angezeigt werden und wird als komprimiert gekennzeichnet, da komprimierte Dateien ebenfalls mit dem Flag `UF_COMPRESSED` markiert sind. Wenn bei einer komprimierten Datei dieses Flag mit `chflags nocompressed </path/to/file>` entfernt wird, erkennt das System nicht mehr, dass die Datei komprimiert war, und kann die Daten daher nicht dekomprimieren und darauf zugreifen (es geht davon aus, dass sie tatsächlich leer ist).

Das Tool afscexpand kann verwendet werden, um die Komprimierung einer Datei zu erzwingen.


### Interessante Konfigurationsorte (macOS)

| Pfad / Ort | Zweck / Was konfiguriert wird | Sicherheits- / Angriffspotenzial |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Speichert Apples Feature-Flag-plist-Dateien, die optionale oder experimentelle Verhaltensweisen in System-Daemons / Frameworks steuern | Wenn ein Angreifer SIP umgehen oder Privilegien erlangen kann, könnte eine Manipulation versteckte Codepfade aktivieren oder Schutzmechanismen deaktivieren |
| `/System/Library/CoreServices/systemVersion.plist` | Enthält macOS-Versionsmetadaten (ProductVersion, BuildVersion), die von Apps / Installern verwendet werden, um Verhalten zu steuern | Eine Änderung kann Apps oder Installer dazu bringen, nicht unterstützte OS-Versionen zu akzeptieren oder Features freizuschalten |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Anwendungs- / systemweite Einstellungen | Falls beschreibbar, können Angreifer Einstellungen einschleusen, um das Verhalten von Apps zu beeinflussen, Schutzmechanismen zu deaktivieren oder Fehlkonfigurationen zu verursachen |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist-Definitionen für Hintergrund-Daemons und Agents | Das Einfügen oder Manipulieren bösartiger Plists (falls die Berechtigungen dies erlauben) ermöglicht Persistenz oder Privilege Escalations |
| `/etc/hosts` | Hostname- ↔ IP-Zuordnungen, die vom System-DNS-Resolver verwendet werden | Umleitung von Domainnamen, Abfangen von Datenverkehr und Spoofing von Diensten unter lokaler Kontrolle |
| `/etc/sudoers` | Definiert, wer Befehle mit `sudo` und unter welchen Bedingungen ausführen darf | Eine manipulierte sudoers-Datei kann Root- oder unzulässige Privilegien für Angreiferkonten gewähren |
| `/private/var/db/dslocal/nodes/Default/users/` | Plists mit Definitionen lokaler Benutzerkonten | Eine Manipulation ermöglicht die Erstellung oder Änderung von Benutzerkonten, Passwort-Hashes oder Benutzermetadaten |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel-Erweiterungen / Treiber | Das Installieren oder Ändern von kexts kann zu Kontrolle auf Kernel-Ebene führen; diese werden stark durch SIP- / Signaturrichtlinien geschützt |
| `/private/var/db/SystemPolicyConfiguration/` | Speichert die Konfiguration für die Durchsetzung von Systemrichtlinien (z. B. Gatekeeper, Notarisierung) | Eine Manipulation kann die Umgehung von Richtlinienprüfungen oder Vertrauensregeln ermöglichen |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH-Hilfsprogramme und Konfigurationsdateien | Fehlkonfigurationen führen zu schwacher SSH-Sicherheit, unbefugtem Zugriff oder unsicheren Algorithmen |
| `/System/Library/Sandbox/Profiles` | System-Sandbox-Profile (SBPL), die zur Einschränkung von Prozessaktionen verwendet werden | Das Ersetzen oder Ändern von Profilen kann Sandbox-Escape-Vektoren eröffnen oder die Isolation schwächen |

> **Hinweis**: Viele dieser Pfade befinden sich in SIP-geschützten Verzeichnissen (z. B. `/System`) und sind gegen Schreibzugriffe geschützt, sofern SIP nicht deaktiviert oder umgangen wird.


## **Universal binaries &** Mach-o Format

Mac-OS-Binaries werden normalerweise als **Universal binaries** kompiliert. Ein **Universal binary** kann **mehrere Architekturen in derselben Datei unterstützen**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risikokategorie-Dateien Mac OS

Das Verzeichnis `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` enthält Informationen über das **Risiko im Zusammenhang mit verschiedenen Dateierweiterungen**. Dieses Verzeichnis kategorisiert Dateien in verschiedene Risikostufen und beeinflusst, wie Safari diese Dateien nach dem Download behandelt. Die Kategorien sind wie folgt:

- **LSRiskCategorySafe**: Dateien in dieser Kategorie gelten als **vollständig sicher**. Safari öffnet diese Dateien automatisch, nachdem sie heruntergeladen wurden.
- **LSRiskCategoryNeutral**: Für diese Dateien werden keine Warnungen angezeigt, und sie werden von Safari **nicht automatisch geöffnet**.
- **LSRiskCategoryUnsafeExecutable**: Dateien in dieser Kategorie **lösen eine Warnung aus**, die darauf hinweist, dass es sich bei der Datei um eine Anwendung handelt. Dies dient als Sicherheitsmaßnahme, um den Benutzer zu warnen.
- **LSRiskCategoryMayContainUnsafeExecutable**: Diese Kategorie gilt für Dateien wie Archive, die eine ausführbare Datei enthalten könnten. Safari **löst eine Warnung aus**, sofern es nicht überprüfen kann, dass alle Inhalte sicher oder neutral sind.

## Logdateien

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Enthält Informationen über heruntergeladene Dateien, beispielsweise die URL, von der sie heruntergeladen wurden.
- **`/var/log/system.log`**: Haupt-Log von OSX-Systemen. com.apple.syslogd.plist ist für die Ausführung des Sysloggings verantwortlich (ob es deaktiviert ist, kann durch die Suche nach "com.apple.syslogd" in `launchctl list` überprüft werden).
- **`/private/var/log/asl/*.asl`**: Dies sind die Apple System Logs, die interessante Informationen enthalten können.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Speichert zuletzt über „Finder“ aufgerufene Dateien und Anwendungen.
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Speichert Elemente, die beim Systemstart gestartet werden sollen
- **`$HOME/Library/Logs/DiskUtility.log`**: Logdatei der DiskUtility-App (Informationen über Laufwerke, einschließlich USB-Laufwerken)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Daten über drahtlose Access Points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Liste deaktivierter Daemons.

{{#include ../../../banners/hacktricks-training.md}}
