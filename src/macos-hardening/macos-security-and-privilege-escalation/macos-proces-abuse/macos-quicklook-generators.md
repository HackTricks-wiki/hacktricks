# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Quick Look je macOS-ov **okvir za pregled fajlova**. Kada korisnik izabere fajl u Finder, pritisne Space, pređe mišem preko njega, ili pregleda direktorijum sa uključenim thumbnails, Quick Look **automatski učitava generator plugin** da parsira fajl i prikaže vizuelni pregled.

Quick Look generators su **bundles** (`.qlgenerator`) koji se registruju za specifične **Uniform Type Identifiers (UTIs)**. Kada macOS treba da prikaže preview fajla koji odgovara tom UTI, učitava generator u sandboxovan pomoćni proces (`QuickLookSatellite` or `qlmanage`) i poziva njegovu funkciju generatora.

### Zašto je ovo važno za bezbednost

> [!WARNING]
> Quick Look generatori se aktiviraju **jednostavnim odabirom ili pregledom fajla** — nije potrebna radnja "Open". Ovo ih čini moćnim **pasivnim vektorom eksploatacije**: korisnik samo treba da navigira do direktorijuma koji sadrži zlonamerni fajl.

**Površina napada:**
- Generatori **parsiraju proizvoljan sadržaj fajlova** sa diska, downloads, email priloga, ili mrežnih deljenja
- Umetnuti fajl može iskoristiti **ranjivosti u parsiranju** (buffer overflows, format strings, type confusion) u kodu generatora
- Renderovanje preview-a se dešava **automatski** — dovoljno je pregledati Downloads direktorijum u koji je zlonamerni fajl dospeo
- Quick Look radi u **sandboxovanom pomoćnom procesu**, ali su demonstrirani sandbox escapes iz ovog konteksta

## Arhitektura
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
## Enumeracija

### Lista instaliranih generatora
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
### Korišćenje skenera
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Scenariji napada

### Eksploatacija zasnovana na datotekama

Quick Look generator treće strane koji parsira složene formate datoteka (3D modeli, naučni podaci, formati arhiva) predstavlja primarnu metu:
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
### Drive-By via Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Zamena generatora treće strane

Ako je Quick Look generator bundle instaliran u **lokaciji koju korisnik može menjati** (`~/Library/QuickLook/`), može se zameniti:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Pokrenite Quick Look na daljinu
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Razmatranja o sandboxu

Quick Look generators se pokreću unutar sandboxovanog helper procesa. Sandbox profil ograničava:
- Pristup datotečnom sistemu (uglavnom samo za čitanje prema fajlu koji se pregledava)
- Pristup mreži (ograničen)
- IPC (ograničen mach-lookup)

Međutim, sandbox ima poznate vektore za bekstvo:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE iz stvarnog sveta

| CVE | Opis |
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
## Izvori

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
