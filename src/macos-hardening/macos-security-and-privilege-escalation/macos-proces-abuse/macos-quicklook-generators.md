# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Quick Look ist macOS' **Framework für Dateivorschauen**. Wenn ein Benutzer eine Datei im Finder auswählt, die Leertaste drückt, den Mauszeiger darüber bewegt oder ein Verzeichnis mit aktivierten Miniaturansichten anzeigt, **lädt Quick Look automatisch ein Generator-Plugin**, um die Datei zu analysieren und eine visuelle Vorschau zu erstellen.<sup>[[1]](#references)</sup>

Quick Look generators sind **Bundles** (`.qlgenerator`), die sich für bestimmte **Uniform Type Identifiers (UTIs)** registrieren. Wenn macOS eine Vorschau für eine Datei benötigt, die dieser UTI entspricht, lädt es den Generator in einen sandboxed Hilfsprozess (`QuickLookSatellite` oder `qlmanage`) und ruft dessen Generatorfunktion auf.

### Warum dies für die Sicherheit wichtig ist

> [!WARNING]
> Quick Look generators werden bereits durch das **einfache Auswählen oder Anzeigen einer Datei** ausgelöst — keine „Öffnen“-Aktion ist erforderlich. Dadurch entsteht ein leistungsfähiger **passiver Exploitation-Vektor**: Der Benutzer muss lediglich in ein Verzeichnis navigieren, das eine schädliche Datei enthält.

**Angriffsfläche:**
- Generators **analysieren beliebige Dateiinhalte** von der Festplatte, aus Downloads, E-Mail-Anhängen oder Netzwerkfreigaben
- Eine speziell erstellte Datei kann **Parsing-Schwachstellen** (Buffer Overflows, Format Strings, Type Confusion) im Generator-Code ausnutzen
- Das Rendern der Vorschau erfolgt **automatisch** — es reicht aus, einen Downloads-Ordner anzuzeigen, in dem eine schädliche Datei abgelegt wurde
- Quick Look läuft in einem **sandboxed Hilfsprozess**, aber Sandbox Escapes aus diesem Kontext wurden demonstriert

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
## Aufzählung

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

### Datei-basierte Ausnutzung

Ein Drittanbieter-Quick-Look-Generator, der komplexe Dateiformate (3D-Modelle, wissenschaftliche Daten, Archivformate) analysiert, ist ein bevorzugtes Ziel:
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
### Ersatz eines Drittanbieter-Generators

Wenn ein Quick Look-Generator-Bundle an einem **vom Benutzer beschreibbaren Speicherort** (`~/Library/QuickLook/`) installiert ist, kann es ersetzt werden:
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

Quick Look generators werden innerhalb eines sandboxed Hilfsprozesses ausgeführt. Das Sandbox-Profil beschränkt:
- Dateisystemzugriff (größtenteils schreibgeschützt auf die Datei, die in der Vorschau angezeigt wird)
- Netzwerkzugriff (eingeschränkt)
- IPC (begrenztes mach-lookup)

Die Sandbox verfügt jedoch über bekannte Escape-Vektoren:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## Praxisnahe CVEs<sup>[[2]](#references)</sup>

| CVE | Beschreibung |
|---|---|
| CVE-2019-8741 | Speicherbeschädigung in der Quick Look-Vorschau durch eine manipulierte Datei |
| CVE-2018-4293 | Quick Look generator sandbox escape |
| CVE-2020-9963 | Informationspreisgabe bei der Verarbeitung der Quick Look-Vorschau |
| CVE-2021-30876 | Speicherbeschädigung bei der Thumbnail-Erstellung |

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
## References

- [1] [Apple Developer — Quick Look-Programmierhandbuch](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple-Sicherheitsupdates — Quick Look-CVEs](https://support.apple.com/en-us/HT201222)
{{#include ../../../banners/hacktricks-training.md}}
