# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Quick Look ist macOS' **Framework für Dateivorschauen**. Wenn ein Benutzer eine Datei im Finder auswählt, die Leertaste drückt, den Mauszeiger darüber bewegt oder ein Verzeichnis mit aktivierten Vorschaubildern anzeigt, lädt Quick Look **automatisch ein Generator-Plugin**, um die Datei zu analysieren und eine visuelle Vorschau darzustellen.<sup>[[1]](#references)</sup>

Quick Look generators sind **Bundles** (`.qlgenerator`), die sich für bestimmte **Uniform Type Identifiers (UTIs)** registrieren. Wenn macOS eine Vorschau für eine Datei benötigt, die dieser UTI entspricht, lädt es den Generator in einen sandboxed Helper-Prozess (`QuickLookSatellite` oder `qlmanage`) und ruft dessen Generator-Funktion auf.

### Warum das für die Sicherheit relevant ist

> [!WARNING]
> Quick Look generators werden bereits durch das **einfache Auswählen oder Anzeigen einer Datei** ausgelöst — es ist keine „Open“-Aktion erforderlich. Dadurch sind sie ein leistungsfähiger **passiver Exploitation-Vektor**: Der Benutzer muss lediglich zu einem Verzeichnis navigieren, das eine schädliche Datei enthält.

**Angriffsfläche:**
- Generators **analysieren beliebige Dateiinhalte** von der Festplatte, aus Downloads, E-Mail-Anhängen oder Network Shares
- Eine speziell erstellte Datei kann **Parsing-Schwachstellen** (Buffer Overflows, Format Strings, Type Confusion) im Generator-Code ausnutzen
- Die Darstellung der Vorschau erfolgt **automatisch** — das Anzeigen eines Downloads-Ordners, in dem eine schädliche Datei abgelegt wurde, reicht aus
- Quick Look läuft in einem **sandboxed Helper**, doch Sandbox Escapes aus diesem Kontext wurden demonstriert

## Architektur
```
User selects file in Finder
↓
Finder → QuickLookSatellite (sandboxed helper)
↓
Generator plugin loaded (.qlgenerator bundle)
↓
Plugin parses file content → Returns preview image/HTML
↓
Preview displayed to user
```
## Enumeration

### Installierte Generatoren auflisten
```bash
# List all Quick Look generators with their UTI registrations
qlmanage -m plugins 2>&1

# Find generator bundles on the system
find / -name "*.qlgenerator" -type d 2>/dev/null

# Common locations
ls /Library/QuickLook/
ls ~/Library/QuickLook/
ls /System/Library/QuickLook/

# Check a generator's Info.plist for UTI registrations
defaults read /path/to/Generator.qlgenerator/Contents/Info.plist 2>/dev/null
```
### Verwendung des Scanners
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Angriffsszenarien

### Dateibasierte Ausnutzung

Ein von einem Drittanbieter stammender Quick Look generator, der komplexe Dateiformate (3D-Modelle, wissenschaftliche Daten, Archivformate) analysiert, ist ein ideales Ziel:
```bash
# 1. Identify a third-party generator and its UTI
qlmanage -m plugins 2>&1 | grep -v "com.apple" | head -20

# 2. Find what file types it handles
defaults read /Library/QuickLook/SomeGenerator.qlgenerator/Contents/Info.plist \
CFBundleDocumentTypes 2>/dev/null

# 3. Craft a malicious file matching that UTI
# (fuzzer output or hand-crafted malformed file)

# 4. Place the file where the user will preview it
cp malicious.xyz ~/Downloads/

# 5. When user opens Downloads in Finder → preview triggers → exploit fires
```
### Drive-By über Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Ersetzen von Drittanbieter-Generatoren

Wenn ein Quick Look generator bundle an einem **vom Benutzer beschreibbaren Speicherort** (`~/Library/QuickLook/`) installiert ist, kann es ersetzt werden:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Quick Look remote auslösen
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Sandbox-Überlegungen

Quick Look generators werden innerhalb eines sandboxed helper process ausgeführt. Das sandbox profile beschränkt:
- Dateisystemzugriff (größtenteils nur lesender Zugriff auf die Datei, deren Vorschau angezeigt wird)
- Network access (eingeschränkt)
- IPC (begrenztes mach-lookup)

Die Sandbox verfügt jedoch über bekannte escape vectors:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## Reale CVEs

| CVE | Beschreibung |
|---|---|
| CVE-2019-8741 | Speicherbeschädigung in der Quick Look-Vorschau durch eine präparierte Datei |
| CVE-2018-4293 | Quick Look Generator Sandbox Escape |
| CVE-2020-9963 | Offenlegung von Informationen bei der Verarbeitung der Quick Look-Vorschau |
| CVE-2021-30876 | Speicherbeschädigung bei der Thumbnail-Generierung |

## Fuzzing von Quick Look Generators
```bash
# Basic fuzzing approach for a Quick Look generator:

# 1. Identify the target generator and its file format
qlmanage -m plugins 2>&1 | grep "target-uti"

# 2. Collect seed corpus of valid files
find / -name "*.targetext" -size -1M 2>/dev/null | head -100

# 3. Mutate files and trigger preview
for f in /tmp/fuzz_corpus/*; do
# Mutate the file (using radamsa, honggfuzz, etc.)
radamsa "$f" > /tmp/fuzz_input.targetext

# Trigger Quick Look (with timeout to catch hangs)
timeout 5 qlmanage -t /tmp/fuzz_input.targetext 2>&1

# Check if QuickLookSatellite crashed
log show --last 5s --predicate 'process == "QuickLookSatellite" AND eventMessage CONTAINS "crash"' 2>/dev/null
done
```
## Referenzen

- [1] [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
