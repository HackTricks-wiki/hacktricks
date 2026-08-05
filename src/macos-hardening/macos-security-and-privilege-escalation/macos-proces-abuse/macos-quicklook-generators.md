# Quick Look Generatori za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Quick Look je macOS-ov **framework za pregled datoteka**. Kada korisnik izabere datoteku u Finder-u, pritisne Space, pređe kursorom preko nje ili pregleda direktorijum sa omogućenim sličicama, Quick Look **automatski učitava generator plugin** za parsiranje datoteke i renderovanje vizuelnog pregleda.<sup>[1]</sup>

Quick Look generatori su **bundle-ovi** (`.qlgenerator`) koji se registruju za određene **Uniform Type Identifiers (UTI-jeve)**. Kada macOS-u treba pregled datoteke koja odgovara tom UTI-ju, učitava generator u sandboxovani pomoćni proces (`QuickLookSatellite` ili `qlmanage`) i poziva njegovu generatorsku funkciju.

### Zašto je ovo važno za bezbednost

> [!WARNING]
> Quick Look generatori se aktiviraju **samim izborom ili pregledom datoteke** — akcija „Open“ nije potrebna. To ih čini moćnim **vektorom pasivne eksploatacije**: korisnik samo treba da ode u direktorijum koji sadrži malicioznu datoteku.

**Napadna površina:**
- Generatori **parsiraju proizvoljan sadržaj datoteka** sa diska, iz downloads-a, email priloga ili network share-ova
- Posebno kreirana datoteka može da iskoristi **ranjivosti u parsiranju** (buffer overflow, format strings, type confusion) u kodu generatora
- Renderovanje pregleda se odvija **automatski** — dovoljno je otvoriti Downloads folder u koji je dospela maliciozna datoteka
- Quick Look se izvršava u **sandboxovanom pomoćnom procesu**, ali su sandbox escapes iz ovog konteksta već demonstrirani

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

### Izlistavanje instaliranih Generatora
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

Quick Look generator treće strane koji parsira složene formate datoteka (3D modele, naučne podatke, arhivske formate) predstavlja idealnu metu:
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
### Drive-By putem preuzimanja
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Zamena generatora treće strane

Ako je bundle Quick Look generatora instaliran na **lokaciji u koju korisnik može da upisuje** (`~/Library/QuickLook/`), može biti zamenjen:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Daljinsko pokretanje Quick Look-a
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Razmatranja u vezi sa sandboxom

Quick Look generators se izvršavaju unutar sandboxovanog pomoćnog procesa. Profil sandboxa ograničava:
- Pristup sistemu datoteka (uglavnom samo za čitanje datoteke čiji se pregled prikazuje)
- Mrežni pristup (ograničen)
- IPC (ograničen `mach-lookup`)

Međutim, sandbox ima poznate vektore za bekstvo:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE-ovi iz stvarnog sveta

| CVE | Opis |
|---|---|
| CVE-2019-8741 | Oštećenje memorije Quick Look preview-a putem posebno napravljene datoteke |
| CVE-2018-4293 | Izlazak Quick Look generatora iz sandbox-a |
| CVE-2020-9963 | Otkrivanje informacija tokom obrade Quick Look preview-a |
| CVE-2021-30876 | Oštećenje memorije tokom generisanja thumbnail-a |

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
## Reference

- [1] [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
