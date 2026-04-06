# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Quick Look is macOS se **lêer-voorskou raamwerk**. Wanneer 'n gebruiker 'n lêer in Finder kies, die Space toets druk, daaroor hover, of 'n gids met miniatuurvoorstellings geaktiveer kyk, laai Quick Look **outomaties 'n generator-plugin** om die lêer te ontleed en 'n visuele voorskou te genereer.

Quick Look generators is **bundels** (`.qlgenerator`) wat registreer vir spesifieke **Uniform Type Identifiers (UTIs)**. Wanneer macOS 'n voorskou benodig vir 'n lêer wat by daardie UTI pas, laai dit die generator in 'n sandboxed helper-proses (`QuickLookSatellite` of `qlmanage`) en roep sy generatorfunksie aan.

### Waarom dit vir sekuriteit saak maak

> [!WARNING]
> Quick Look generators word geaktiveer deur **net 'n lêer te kies of te kyk** — geen "Open"-aksie is vereis nie. Dit maak hulle 'n kragtige **passiewe eksploitasievektor**: die gebruiker hoef net na 'n gids te navigeer wat 'n kwaadwillige lêer bevat.

**Aanvalsoppervlak:**
- Generators **ontleed arbitrêre lêerinhoud** vanaf skyf, downloads, e-pos-aanhegsels, of netwerk shares
- 'n Gemanipuleerde lêer kan **parsing-kwetsbaarhede** uitbuit (buffer overflows, format strings, type confusion) in die generator-kode
- Die voorskou-rendering gebeur **outomaties** — die kyk na 'n Downloads-gids waar 'n kwaadwillige lêer geland het is genoeg
- Quick Look loop in 'n **sandboxed helper**, maar sandbox escapes uit hierdie konteks is gedemonstreer

## Argitektuur
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
## Enumerasie

### Lys geïnstalleerde generatoren
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
### Gebruik van die skandeerder
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Aanvalscenario's

### Lêer-gebaseerde uitbuiting

'n Quick Look generator van derdepartye wat komplekse lêerformate (3D-modelle, wetenskaplike data, argiefformate) ontleed, is 'n primêre teiken:
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
### Drive-By via aflaaie
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Third-Party Generator Replacement

Indien 'n Quick Look generator-bundel in 'n **gebruikers-skryfbare ligging** (`~/Library/QuickLook/`) geïnstalleer is, kan dit vervang word:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Aktiveer Quick Look op afstand
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Sandbox Oorwegings

Quick Look generators word binne 'n sandboxed helper-proses uitgevoer. Die sandbox-profiel beperk:
- Toegang tot die lêerstelsel (meestal slegs lees-toegang tot die lêer wat voorbeskou word)
- Netwerktoegang (beperk)
- IPC (beperkte mach-lookup)

Daar is egter bekende escape vectors:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## Werklike CVEs

| CVE | Beskrywing |
|---|---|
| CVE-2019-8741 | Quick Look preview geheuekorrupsie via 'n vervaardigde lêer |
| CVE-2018-4293 | Quick Look generator sandbox escape |
| CVE-2020-9963 | Inligtingsvrystelling tydens verwerking van Quick Look preview |
| CVE-2021-30876 | Geheuekorrupsie tydens miniatuurgenerering |

## Fuzzing van Quick Look Generators
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
## Verwysings

* [Apple Developer — Quick Look Programmeringsgids](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Sekuriteitsopdaterings — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look-aanvalsoppervlak](https://objectivesee.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
