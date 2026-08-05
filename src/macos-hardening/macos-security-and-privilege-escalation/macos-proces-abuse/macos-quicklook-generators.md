# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Quick Look is macOS se **lêervoorskouraamwerk**. Wanneer 'n gebruiker 'n lêer in Finder kies, Space druk, daaroor beweeg, of 'n gids met geaktiveerde duimnaels bekyk, **laai Quick Look outomaties 'n generator-plugin** om die lêer te ontleed en 'n visuele voorskou te vertoon.<sup>[[1]](#references)</sup>

Quick Look generators is **bundles** (`.qlgenerator`) wat vir spesifieke **Uniform Type Identifiers (UTIs)** registreer. Wanneer macOS 'n voorskou benodig vir 'n lêer wat met daardie UTI ooreenstem, laai dit die generator in 'n sandboxed helper process (`QuickLookSatellite` of `qlmanage`) en roep sy generator-funksie aan.

### Waarom Dit Belangrik is vir Sekuriteit

> [!WARNING]
> Quick Look generators word geaktiveer deur **bloot 'n lêer te kies of te bekyk** — geen "Open"-aksie word vereis nie. Dit maak hulle 'n kragtige **passive exploitation vector**: die gebruiker hoef slegs na 'n gids te navigeer wat 'n malicious file bevat.

**Attack surface:**
- Generators **ontleed arbitrêre lêerinhoud** vanaf skyf, downloads, email attachments of network shares
- 'n Crafted file kan **parsing vulnerabilities** (buffer overflows, format strings, type confusion) in die generator-kode uitbuit
- Die voorskouweergawe gebeur **outomaties** — dit is genoeg om 'n Downloads-gids te bekyk waarin 'n malicious file beland het
- Quick Look loop in 'n **sandboxed helper**, maar sandbox escapes vanuit hierdie konteks is gedemonstreer

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

### Lys geïnstalleerde Generators
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
### Gebruik van die Scanner
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

### Lêer-gebaseerde Exploitation

'n Third-party Quick Look generator wat komplekse lêerformate (3D-modelle, wetenskaplike data, argiefformate) ontleed, is 'n uitstekende teiken:
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
### Drive-By deur Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Third-Party Generator Replacement

As 'n Quick Look generator bundle in 'n **user-writable location** (`~/Library/QuickLook/`) geïnstalleer is, kan dit vervang word:
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
## Sandbox-oorwegings

Quick Look generators loop binne 'n sandboxed helper process. Die sandbox-profiel beperk:
- Lêerstelseltoegang (meestal slegs lees-toegang tot die lêer wat voorbeskou word)
- Network access (beperk)
- IPC (beperkte mach-lookup)

Die sandbox het egter bekende escape vectors:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE's in die werklike wêreld

| CVE | Beskrywing |
|---|---|
| CVE-2019-8741 | Quick Look preview memory corruption via crafted file |
| CVE-2018-4293 | Quick Look generator sandbox escape |
| CVE-2020-9963 | Quick Look preview processing information disclosure |
| CVE-2021-30876 | Thumbnail generation memory corruption |

## Fuzzing Quick Look Generators
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

- [1] [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
