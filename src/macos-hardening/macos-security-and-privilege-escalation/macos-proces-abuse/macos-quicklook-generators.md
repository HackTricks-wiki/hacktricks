# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Quick Look ni **mfumo wa macOS wa kuonyesha hakikisho la faili**. Mtumiaji anapochagua faili katika Finder, kubonyeza Space, kuweka pointer juu yake, au kuangalia directory yenye thumbnails zilizowashwa, Quick Look **hupakia kiotomatiki generator plugin** ili kuchanganua faili na kuonyesha hakikisho la kionekano.<sup>[[1]](#references)</sup>

Quick Look generators ni **bundles** (`.qlgenerator`) zinazojiandikisha kwa **Uniform Type Identifiers (UTIs)** maalum. macOS inapohitaji hakikisho la faili inayolingana na UTI hiyo, hupakia generator ndani ya sandboxed helper process (`QuickLookSatellite` au `qlmanage`) na kuita generator function yake.

### Kwa Nini Hili Ni Muhimu kwa Usalama

> [!WARNING]
> Quick Look generators huanzishwa kwa **kuchagua au kuangalia faili tu** — hakuna kitendo cha "Open" kinachohitajika. Hii huzifanya kuwa **passive exploitation vector** yenye nguvu: mtumiaji anahitaji tu kwenda kwenye directory iliyo na faili hasidi.

**Attack surface:**
- Generators **huchanganua maudhui ya faili kiholela** kutoka kwenye disk, downloads, email attachments, au network shares
- Faili iliyotengenezwa kwa makusudi inaweza kutumia **parsing vulnerabilities** (buffer overflows, format strings, type confusion) katika generator code
- Utoaji wa hakikisho hutokea **kiotomatiki** — kuangalia Downloads folder ambako faili hasidi imehifadhiwa kunatosha
- Quick Look huendeshwa katika **sandboxed helper**, lakini sandbox escapes kutoka kwenye mazingira haya zimeonyeshwa

## Muundo wa Mfumo
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
## Uorodheshaji

### Orodhesha Generators Zilizosakinishwa
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
### Kutumia Scanner
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Matukio ya Mashambulizi

### Unyonyaji Unaotegemea Faili

Quick Look generator ya mtu wa tatu inayochanganua miundo changamano ya faili (miundo ya 3D, data za kisayansi, miundo ya kumbukumbu) ni shabaha kuu:
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
### Drive-By kupitia Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Kubadilisha Third-Party Generator

Ikiwa bundle ya Quick Look generator imesakinishwa katika **eneo linaloweza kuandikwa na mtumiaji** (`~/Library/QuickLook/`), inaweza kubadilishwa:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Trigger Quick Look kwa Mbali
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Mazingatio ya Sandbox

Quick Look generators huendeshwa ndani ya mchakato msaidizi ulio kwenye sandbox. Wasifu wa sandbox unaweka mipaka kwa:
- Ufikiaji wa mfumo wa faili (hasa kusoma tu faili inayotazamwa)
- Ufikiaji wa mtandao (wenye vikwazo)
- IPC (mach-lookup yenye mipaka)

Hata hivyo, sandbox ina njia zinazojulikana za kutoroka:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVEs za Ulimwengu Halisi

| CVE | Maelezo |
|---|---|
| CVE-2019-8741 | Uharibifu wa memory kwenye preview ya Quick Look kupitia faili iliyoundwa mahsusi |
| CVE-2018-4293 | Kutoka kwenye sandbox ya Quick Look generator |
| CVE-2020-9963 | Ufichuaji wa taarifa wakati wa kuchakata preview ya Quick Look |
| CVE-2021-30876 | Uharibifu wa memory wakati wa kutengeneza thumbnail |

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
## Marejeo

- [1] [Apple Developer — Mwongozo wa Programming wa Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
