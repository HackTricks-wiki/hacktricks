# macOS Dateien, Ordner, Binaries & Speicher

{{#include ../../../banners/hacktricks-training.md}}

## Dateihierarchie

- **/Applications**: Die installierten Apps sollten hier sein. Alle Benutzer können darauf zugreifen.
- **/bin**: Befehlszeilen-Binaries
- **/cores**: Wenn vorhanden, wird es verwendet, um Core-Dumps zu speichern
- **/dev**: Alles wird als Datei behandelt, sodass Sie hier Hardwaregeräte sehen können.
- **/etc**: Konfigurationsdateien
- **/Library**: Viele Unterverzeichnisse und Dateien, die mit Einstellungen, Caches und Protokollen zu tun haben, finden sich hier. Ein Library-Ordner existiert im Root-Verzeichnis und im Verzeichnis jedes Benutzers.
- **/private**: Nicht dokumentiert, aber viele der genannten Ordner sind symbolische Links zum privaten Verzeichnis.
- **/sbin**: Essentielle System-Binaries (bezogen auf die Verwaltung)
- **/System**: Dateien, um OS X auszuführen. Hier sollten hauptsächlich nur Apple-spezifische Dateien zu finden sein (keine Drittanbieter).
- **/tmp**: Dateien werden nach 3 Tagen gelöscht (es ist ein symbolischer Link zu /private/tmp)
- **/Users**: Heimatverzeichnis für Benutzer.
- **/usr**: Konfigurations- und System-Binaries
- **/var**: Protokolldateien
- **/Volumes**: Die gemounteten Laufwerke erscheinen hier.
- **/.vol**: Wenn Sie `stat a.txt` ausführen, erhalten Sie etwas wie `16777223 7545753 -rw-r--r-- 1 username wheel ...`, wobei die erste Zahl die ID-Nummer des Volumes ist, auf dem die Datei existiert, und die zweite die Inode-Nummer ist. Sie können den Inhalt dieser Datei über /.vol/ mit dieser Information abrufen, indem Sie `cat /.vol/16777223/7545753` ausführen.

### Anwendungsordner

- **Systemanwendungen** befinden sich unter `/System/Applications`
- **Installierte** Anwendungen sind normalerweise in `/Applications` oder in `~/Applications` installiert.
- **Anwendungsdaten** finden sich in `/Library/Application Support` für Anwendungen, die als Root ausgeführt werden, und in `~/Library/Application Support` für Anwendungen, die als Benutzer ausgeführt werden.
- Drittanbieteranwendungen **Dämonen**, die **als Root ausgeführt werden müssen**, befinden sich normalerweise in `/Library/PrivilegedHelperTools/`
- **Sandboxed** Apps sind im Ordner `~/Library/Containers` abgebildet. Jede App hat einen Ordner, der nach der Bundle-ID der Anwendung benannt ist (`com.apple.Safari`).
- Der **Kernel** befindet sich in `/System/Library/Kernels/kernel`
- **Apples Kernel-Erweiterungen** befinden sich in `/System/Library/Extensions`
- **Drittanbieter-Kernel-Erweiterungen** werden in `/Library/Extensions` gespeichert.

### Dateien mit sensiblen Informationen

MacOS speichert Informationen wie Passwörter an mehreren Orten:

{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Verwundbare pkg-Installer

{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X spezifische Erweiterungen

- **`.dmg`**: Apple Disk Image-Dateien sind sehr häufig für Installer.
- **`.kext`**: Es muss einer bestimmten Struktur folgen und ist die OS X-Version eines Treibers. (es ist ein Bundle)
- **`.plist`**: Auch bekannt als Property List, speichert Informationen im XML- oder Binärformat.
- Kann XML oder binär sein. Binäre können gelesen werden mit:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple-Anwendungen, die der Verzeichnisstruktur folgen (es ist ein Bundle).
- **`.dylib`**: Dynamische Bibliotheken (wie Windows DLL-Dateien)
- **`.pkg`**: Sind dasselbe wie xar (eXtensible Archive Format). Der Installer-Befehl kann verwendet werden, um den Inhalt dieser Dateien zu installieren.
- **`.DS_Store`**: Diese Datei befindet sich in jedem Verzeichnis und speichert die Attribute und Anpassungen des Verzeichnisses.
- **`.Spotlight-V100`**: Dieser Ordner erscheint im Root-Verzeichnis jedes Volumes im System.
- **`.metadata_never_index`**: Wenn sich diese Datei im Root eines Volumes befindet, wird Spotlight dieses Volume nicht indizieren.
- **`.noindex`**: Dateien und Ordner mit dieser Erweiterung werden von Spotlight nicht indiziert.
- **`.sdef`**: Dateien innerhalb von Bundles, die angeben, wie mit der Anwendung über ein AppleScript interagiert werden kann.

### macOS Bundles

Ein Bundle ist ein **Verzeichnis**, das **wie ein Objekt im Finder aussieht** (ein Beispiel für ein Bundle sind `*.app`-Dateien).

{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Auf macOS (und iOS) sind alle systemweiten Shared Libraries, wie Frameworks und dylibs, **in einer einzigen Datei kombiniert**, die als **dyld shared cache** bezeichnet wird. Dies verbessert die Leistung, da der Code schneller geladen werden kann.

Dies befindet sich in macOS unter `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` und in älteren Versionen finden Sie den **shared cache** möglicherweise in **`/System/Library/dyld/`**.\
In iOS finden Sie sie in **`/System/Library/Caches/com.apple.dyld/`**.

Ähnlich wie der dyld shared cache sind der Kernel und die Kernel-Erweiterungen ebenfalls in einem Kernel-Cache kompiliert, der beim Booten geladen wird.

Um die Bibliotheken aus der einzelnen Datei des dylib shared cache zu extrahieren, war es möglich, das Binary [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) zu verwenden, das möglicherweise heutzutage nicht mehr funktioniert, aber Sie können auch [**dyldextractor**](https://github.com/arandomdev/dyldextractor) verwenden:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Beachten Sie, dass selbst wenn das Tool `dyld_shared_cache_util` nicht funktioniert, Sie das **gemeinsame dyld-Binärformat an Hopper übergeben** können und Hopper in der Lage sein wird, alle Bibliotheken zu identifizieren und Ihnen zu **ermöglichen, auszuwählen, welche Sie** untersuchen möchten:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Einige Extraktoren funktionieren nicht, da dylibs mit fest codierten Adressen vorverlinkt sind, wodurch sie möglicherweise zu unbekannten Adressen springen.

> [!TIP]
> Es ist auch möglich, den Shared Library Cache anderer \*OS-Geräte in macos herunterzuladen, indem Sie einen Emulator in Xcode verwenden. Sie werden heruntergeladen in: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, wie: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** verwendet den Syscall **`shared_region_check_np`**, um zu wissen, ob das SLC gemappt wurde (was die Adresse zurückgibt) und **`shared_region_map_and_slide_np`**, um das SLC zu mappen.

Beachten Sie, dass selbst wenn das SLC beim ersten Gebrauch verschoben wird, alle **Prozesse** die **gleiche Kopie** verwenden, was den ASLR-Schutz **eliminierte**, wenn der Angreifer in der Lage war, Prozesse im System auszuführen. Dies wurde in der Vergangenheit tatsächlich ausgenutzt und mit einem Shared Region Pager behoben.

Branch-Pools sind kleine Mach-O dylibs, die kleine Räume zwischen Bildzuordnungen schaffen, wodurch es unmöglich wird, die Funktionen zu interponieren.

### Override SLCs

Verwendung der Umgebungsvariablen:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Dies ermöglicht das Laden eines neuen Shared Library Cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** und manuelles Ersetzen der Bibliotheken durch Symlinks zum Shared Cache mit den echten (Sie müssen sie extrahieren)

## Besondere Dateiberechtigungen

### Ordners Berechtigungen

In einem **Ordner** erlaubt **lesen**, ihn **aufzulisten**, **schreiben** erlaubt das **Löschen** und **Schreiben** von Dateien darin, und **ausführen** erlaubt das **Durchqueren** des Verzeichnisses. Ein Benutzer mit **Leseerlaubnis über eine Datei** in einem Verzeichnis, in dem er **keine Ausführungsberechtigung** hat, **wird die Datei nicht lesen können**.

### Flag-Modifikatoren

Es gibt einige Flags, die in den Dateien gesetzt werden können, die das Verhalten der Datei ändern. Sie können die **Flags** der Dateien in einem Verzeichnis mit `ls -lO /path/directory` überprüfen.

- **`uchg`**: Bekannt als **uchange**-Flag, wird **jede Aktion** verhindern, die die **Datei** ändert oder löscht. Um es zu setzen, tun Sie: `chflags uchg file.txt`
- Der Root-Benutzer könnte **das Flag entfernen** und die Datei ändern.
- **`restricted`**: Dieses Flag schützt die Datei **durch SIP** (Sie können dieses Flag nicht zu einer Datei hinzufügen).
- **`Sticky bit`**: Wenn ein Verzeichnis mit Sticky-Bit, **kann nur** der **Verzeichnisbesitzer oder Root Dateien umbenennen oder löschen**. Typischerweise wird dies im /tmp-Verzeichnis gesetzt, um zu verhindern, dass normale Benutzer die Dateien anderer Benutzer löschen oder verschieben.

Alle Flags finden Sie in der Datei `sys/stat.h` (finden Sie sie mit `mdfind stat.h | grep stat.h`) und sind:

- `UF_SETTABLE` 0x0000ffff: Maske der vom Eigentümer änderbaren Flags.
- `UF_NODUMP` 0x00000001: Datei nicht dumpen.
- `UF_IMMUTABLE` 0x00000002: Datei darf nicht geändert werden.
- `UF_APPEND` 0x00000004: Schreibvorgänge in die Datei dürfen nur anhängen.
- `UF_OPAQUE` 0x00000008: Verzeichnis ist undurchsichtig in Bezug auf Union.
- `UF_COMPRESSED` 0x00000020: Datei ist komprimiert (einige Dateisysteme).
- `UF_TRACKED` 0x00000040: Keine Benachrichtigungen für Löschungen/Umbenennungen für Dateien mit diesem Set.
- `UF_DATAVAULT` 0x00000080: Berechtigung erforderlich zum Lesen und Schreiben.
- `UF_HIDDEN` 0x00008000: Hinweis, dass dieses Element nicht in einer GUI angezeigt werden sollte.
- `SF_SUPPORTED` 0x009f0000: Maske der vom Superuser unterstützten Flags.
- `SF_SETTABLE` 0x3fff0000: Maske der vom Superuser änderbaren Flags.
- `SF_SYNTHETIC` 0xc0000000: Maske der systemeigenen schreibgeschützten synthetischen Flags.
- `SF_ARCHIVED` 0x00010000: Datei ist archiviert.
- `SF_IMMUTABLE` 0x00020000: Datei darf nicht geändert werden.
- `SF_APPEND` 0x00040000: Schreibvorgänge in die Datei dürfen nur anhängen.
- `SF_RESTRICTED` 0x00080000: Berechtigung erforderlich zum Schreiben.
- `SF_NOUNLINK` 0x00100000: Element darf nicht entfernt, umbenannt oder gemountet werden.
- `SF_FIRMLINK` 0x00800000: Datei ist ein Firmlink.
- `SF_DATALESS` 0x40000000: Datei ist ein dataloses Objekt.

### **Datei-ACLs**

Datei-**ACLs** enthalten **ACE** (Access Control Entries), bei denen granularere Berechtigungen verschiedenen Benutzern zugewiesen werden können.

Es ist möglich, einem **Verzeichnis** diese Berechtigungen zu gewähren: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Und für eine **Datei**: `read`, `write`, `append`, `execute`.

Wenn die Datei ACLs enthält, werden Sie **ein "+" finden, wenn Sie die Berechtigungen auflisten, wie in**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Sie können **die ACLs** der Datei mit folgendem Befehl lesen:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Sie können **alle Dateien mit ACLs** mit (das ist sehr langsam) finden:
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Erweiterte Attribute

Erweiterte Attribute haben einen Namen und einen beliebigen gewünschten Wert und können mit `ls -@` angezeigt und mit dem Befehl `xattr` bearbeitet werden. Einige gängige erweiterte Attribute sind:

- `com.apple.resourceFork`: Kompatibilität mit Resource Fork. Auch sichtbar als `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Gatekeeper-Quarantänemechanismus (III/6)
- `metadata:*`: MacOS: verschiedene Metadaten, wie `_backup_excludeItem` oder `kMD*`
- `com.apple.lastuseddate` (#PS): Letztes Dateinutzungsdatum
- `com.apple.FinderInfo`: MacOS: Finder-Informationen (z.B. Farb-Tags)
- `com.apple.TextEncoding`: Gibt die Textkodierung von ASCII-Textdateien an
- `com.apple.logd.metadata`: Wird von logd für Dateien in `/var/db/diagnostics` verwendet
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` im Wurzelverzeichnis des Dateisystems)
- `com.apple.rootless`: MacOS: Wird von System Integrity Protection verwendet, um Dateien zu kennzeichnen (III/10)
- `com.apple.uuidb.boot-uuid`: logd-Markierungen von Boot-Epochen mit eindeutiger UUID
- `com.apple.decmpfs`: MacOS: Transparente Dateikompression (II/7)
- `com.apple.cprotect`: \*OS: Verschlüsselungsdaten pro Datei (III/11)
- `com.apple.installd.*`: \*OS: Metadaten, die von installd verwendet werden, z.B. `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Dies ist eine Möglichkeit, **Alternate Data Streams in MacOS**-Maschinen zu erhalten. Sie können Inhalte in einem erweiterten Attribut namens **com.apple.ResourceFork** innerhalb einer Datei speichern, indem Sie es in **file/..namedfork/rsrc** speichern.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Sie können **alle Dateien, die dieses erweiterte Attribut enthalten**, mit folgendem Befehl finden:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

Das erweiterte Attribut `com.apple.decmpfs` zeigt an, dass die Datei verschlüsselt gespeichert ist, `ls -l` wird eine **Größe von 0** melden und die komprimierten Daten befinden sich in diesem Attribut. Jedes Mal, wenn auf die Datei zugegriffen wird, wird sie im Speicher entschlüsselt.

Dieses Attribut kann mit `ls -lO` gesehen werden, das als komprimiert angezeigt wird, da komprimierte Dateien auch mit dem Flag `UF_COMPRESSED` gekennzeichnet sind. Wenn eine komprimierte Datei mit `chflags nocompressed </path/to/file>` entfernt wird, weiß das System nicht, dass die Datei komprimiert war, und kann daher die Daten nicht dekomprimieren und darauf zugreifen (es wird denken, dass sie tatsächlich leer ist).

Das Tool afscexpand kann verwendet werden, um eine Datei zwangsweise zu dekomprimieren.

## **Universelle Binaries &** Mach-o Format

Mac OS-Binaries werden normalerweise als **universelle Binaries** kompiliert. Eine **universelle Binary** kann **mehrere Architekturen in derselben Datei unterstützen**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}

## macOS Prozessspeicher

## macOS Speicher-Dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risikokategorie Dateien Mac OS

Das Verzeichnis `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` ist der Ort, an dem Informationen über das **Risiko, das mit verschiedenen Dateierweiterungen verbunden ist**, gespeichert sind. Dieses Verzeichnis kategorisiert Dateien in verschiedene Risikostufen, die beeinflussen, wie Safari mit diesen Dateien beim Herunterladen umgeht. Die Kategorien sind wie folgt:

- **LSRiskCategorySafe**: Dateien in dieser Kategorie gelten als **vollständig sicher**. Safari öffnet diese Dateien automatisch, nachdem sie heruntergeladen wurden.
- **LSRiskCategoryNeutral**: Diese Dateien kommen ohne Warnungen und werden **nicht automatisch von Safari geöffnet**.
- **LSRiskCategoryUnsafeExecutable**: Dateien in dieser Kategorie **lösen eine Warnung aus**, die darauf hinweist, dass die Datei eine Anwendung ist. Dies dient als Sicherheitsmaßnahme, um den Benutzer zu alarmieren.
- **LSRiskCategoryMayContainUnsafeExecutable**: Diese Kategorie ist für Dateien, wie Archive, die möglicherweise eine ausführbare Datei enthalten. Safari wird **eine Warnung auslösen**, es sei denn, es kann bestätigen, dass alle Inhalte sicher oder neutral sind.

## Protokolldateien

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Enthält Informationen über heruntergeladene Dateien, wie die URL, von der sie heruntergeladen wurden.
- **`/var/log/system.log`**: Hauptprotokoll der OSX-Systeme. com.apple.syslogd.plist ist verantwortlich für die Ausführung des Sysloggings (Sie können überprüfen, ob es deaktiviert ist, indem Sie nach "com.apple.syslogd" in `launchctl list` suchen).
- **`/private/var/log/asl/*.asl`**: Dies sind die Apple-Systemprotokolle, die interessante Informationen enthalten können.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Speichert kürzlich aufgerufene Dateien und Anwendungen über "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Speichert Elemente, die beim Systemstart gestartet werden sollen.
- **`$HOME/Library/Logs/DiskUtility.log`**: Protokolldatei für die DiskUtility-App (Informationen über Laufwerke, einschließlich USBs).
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Daten über drahtlose Zugangspunkte.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Liste der deaktivierten Daemons.

{{#include ../../../banners/hacktricks-training.md}}
