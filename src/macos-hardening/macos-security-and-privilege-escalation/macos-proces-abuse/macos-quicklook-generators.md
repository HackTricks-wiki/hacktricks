# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Quick Look ni **framework ya preview ya faili** ya macOS. Mtumiaji anapochagua faili katika Finder, kubonyeza Space, kuweka kielekezi juu yake, au kuangalia directory yenye thumbnails zilizowashwa, Quick Look **hupakia kiotomatiki plugin ya generator** ili kuchanganua faili na kuonyesha preview ya kuona.<sup>[[1]](#references)</sup>

Quick Look generators ni **bundles** (`.qlgenerator`) zinazojiandikisha kwa **Uniform Type Identifiers (UTIs)** maalum. macOS inapohitaji preview ya faili inayolingana na UTI hiyo, hupakia generator ndani ya helper process yenye sandbox (`QuickLookSatellite` au `qlmanage`) na kuita function ya generator.

### Kwa Nini Hili Ni Muhimu kwa Usalama

> [!WARNING]
> Quick Look generators huanzishwa kwa **kuchagua au kuangalia faili tu** — hakuna hatua ya "Open" inayohitajika. Hii inazifanya kuwa **passive exploitation vector** yenye nguvu: mtumiaji anahitaji tu kwenda kwenye directory iliyo na faili hasidi.

**Attack surface:**
- Generators **huchanganua maudhui ya faili kiholela** kutoka kwenye disk, downloads, email attachments, au network shares
- Faili iliyoundwa mahsusi inaweza kutumia **parsing vulnerabilities** (buffer overflows, format strings, type confusion) ndani ya code ya generator
- Uonyeshaji wa preview hufanyika **kiotomatiki** — kuangalia Downloads folder ambako faili hasidi imehifadhiwa kunatosha
- Quick Look huendeshwa ndani ya **sandboxed helper**, lakini sandbox escapes kutoka kwenye mazingira haya zimedhihirishwa

## Muundo
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

Quick Look generator ya third-party inayochanganua fomati changamano za faili (miundo ya 3D, data za kisayansi, fomati za archive) ni lengo kuu:
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
### Ubadilishaji wa Generator ya Third-Party

Ikiwa bundle ya generator ya Quick Look imesakinishwa katika **user-writable location** (`~/Library/QuickLook/`), inaweza kubadilishwa:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Kuwasha Quick Look kwa Mbali
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Mazingatio ya Sandbox

Quick Look generators huendeshwa ndani ya helper process iliyo kwenye sandbox. Sandbox profile hupunguza:
- Ufikiaji wa mfumo wa faili (hasa kusoma tu faili inayotazamwa)
- Ufikiaji wa mtandao (uliowekewa vizuizi)
- IPC (mach-lookup iliyowekewa mipaka)

Hata hivyo, sandbox ina njia zinazojulikana za kutoroka:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE za Ulimwengu Halisi<sup>[[2]](#references)</sup>

| CVE | Maelezo |
|---|---|
| CVE-2019-8741 | Uharibifu wa memory katika Quick Look preview kupitia faili iliyoundwa mahususi |
| CVE-2018-4293 | Kutoroka sandbox ya Quick Look generator |
| CVE-2020-9963 | Kufichua taarifa wakati wa kuchakata Quick Look preview |
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
## References

- [1] [Apple Developer — Mwongozo wa Programming wa Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Sasisho za Usalama za Apple — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
{{#include ../../../banners/hacktricks-training.md}}
