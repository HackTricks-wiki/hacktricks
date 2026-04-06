# macOS Quick Look-Generatoren

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Quick Look ist macOS' **Dateivorschau-Framework**. Wenn ein Benutzer eine Datei im Finder auswählt, die Leertaste drückt, mit der Maus darüber schwebt oder ein Verzeichnis mit aktivierten Miniaturansichten öffnet, lädt Quick Look **automatisch ein Generator-Plugin**, um die Datei zu parsen und eine visuelle Vorschau zu rendern.

Quick Look-Generatoren sind **bundles** (`.qlgenerator`), die sich für bestimmte **Uniform Type Identifiers (UTIs)** registrieren. Wenn macOS eine Vorschau für eine Datei benötigt, die zu diesem UTI passt, lädt es den Generator in einen sandboxed helper process (`QuickLookSatellite` oder `qlmanage`) und ruft dessen generator function auf.

### Warum das für die Sicherheit relevant ist

> [!WARNING]
> Quick Look-Generatoren werden ausgelöst, indem eine Datei **einfach ausgewählt oder angezeigt** wird — keine "Open"-Aktion ist erforderlich. Das macht sie zu einem mächtigen **passiven Exploit-Vektor**: der Benutzer muss nur in ein Verzeichnis navigieren, das eine bösartige Datei enthält.

Angriffsfläche:
- Generatoren **parsen beliebige Dateiinhalte** von der Festplatte, Downloads, E-Mail-Anhängen oder Netzwerkfreigaben
- Eine manipulierte Datei kann **parsing vulnerabilities** (buffer overflows, format strings, type confusion) im Generator-Code ausnutzen
- Die Vorschau-Erstellung geschieht **automatisch** — das Ansehen des Downloads-Ordners, in dem eine bösartige Datei gelandet ist, reicht aus
- Quick Look läuft in einem **sandboxed helper**, aber sandbox escapes aus diesem Kontext wurden demonstriert

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

Ein Drittanbieter-Quick Look-Generator, der komplexe Dateiformate (3D-Modelle, wissenschaftliche Daten, Archivformate) parst, ist ein primäres Ziel:
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

Wenn ein Quick Look generator bundle in einem **benutzerschreibbaren Speicherort** (`~/Library/QuickLook/`) installiert ist, kann es ersetzt werden:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Quick Look aus der Ferne auslösen
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Sandbox-Überlegungen

Quick Look generators laufen in einem sandboxed Hilfsprozess. Das Sandbox-Profil begrenzt:
- Dateisystemzugriff (meist nur Lesezugriff auf die Datei, die angezeigt wird)
- Netzwerkzugriff (eingeschränkt)
- IPC (eingeschränktes mach-lookup)

Jedoch hat die Sandbox bekannte Escape-Vektoren:
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
| CVE-2019-8741 | Quick Look-Vorschau memory corruption durch manipulierte Datei |
| CVE-2018-4293 | Quick Look-Generator sandbox escape |
| CVE-2020-9963 | Information disclosure bei der Verarbeitung von Quick Look-Vorschauen |
| CVE-2021-30876 | Thumbnail-Erstellung memory corruption |

## Fuzzing von Quick Look-Generatoren
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

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
