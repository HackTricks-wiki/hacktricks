# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

Quick Look ni macOS's **file preview framework**. Wakati mtumiaji anachagua faili katika Finder, anabonyeza Space, au kuzungusha mshale juu yake, au akiangalia saraka yenye thumbnails imewezeshwa, Quick Look **inaingiza moja kwa moja generator plugin** ili kuchambua faili na kuonyesha onyesho la awali.

Quick Look generators ni **bundles** (`.qlgenerator`) ambazo zinasajiliwa kwa ajili ya maalum **Uniform Type Identifiers (UTIs)**. Wakati macOS inahitaji preview kwa faili inayolingana na UTI hiyo, inaingiza generator ndani ya mchakato wa msaada unaosandbox (`QuickLookSatellite` au `qlmanage`) na kuitisha generator function yake.

### Kwa Nini Hii Inahusu Usalama

> [!WARNING]
> Quick Look generators zinachochewa kwa **kwa urahisi kwa kuchagua au kuangalia faili** — hakuna kitendo cha "Open" kinachohitajika. Hii zinafanya kuwa nguvu ya **passive exploitation vector**: mtumiaji anabidi tu apite hadi saraka yenye faili hatari.

Eneo la mashambulizi:
- Generators **huchambua yaliyomo yoyote ya faili** kutoka kwenye diski, folda za Downloads, viambatisho vya barua pepe, au shared za mtandao
- Faili iliyotengenezwa kwa ustadi inaweza kutumia **parsing vulnerabilities** (buffer overflows, format strings, type confusion) kwenye code ya generator
- Uonyeshaji wa preview hufanyika **kiotomatiki** — kuangalia folda ya Downloads ambapo faili hatari imewekwa inatosha
- Quick Look inafanya kazi ndani ya **sandboxed helper**, lakini sandbox escapes kutoka kwa muktadha huu zimetokea pokazazi
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

### Orodhesha Generators Zilizowekwa
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
## Senario za Shambulio

### File-Based Exploitation

Quick Look generator ya mtu wa tatu inayochambua miundo ya faili ngumu (modeli za 3D, data za kisayansi, miundo za archive) ni lengo kuu:
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
### Drive-By kupitia Upakuaji
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Kubadilisha Generator wa Mtu wa Tatu

Kama bundle ya Quick Look generator imewekwa katika **eneo linaloweza kuandikwa na mtumiaji** (`~/Library/QuickLook/`), inaweza kubadilishwa:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Sababisha Quick Look kwa mbali
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Masuala ya Sandbox

Quick Look generators zinaendesha ndani ya mchakato wa msaidizi uliopo kwenye sandbox. Profaili ya sandbox ina mipaka:
- Ufikiaji wa mfumo wa faili (kawaida kwa kusoma pekee kwa faili inayotazamwa)
- Ufikiaji wa mtandao (umeruhusiwa kwa kiasi)
- IPC (mach-lookup iliyopunguzwa)

Hata hivyo, sandbox ina njia za kutoroka zinazojulikana:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE za Dunia Halisi

| CVE | Maelezo |
|---|---|
| CVE-2019-8741 | Korapsheni ya kumbukumbu ya Quick Look preview kupitia faili iliyotengenezwa |
| CVE-2018-4293 | Quick Look generator kutoroka kutoka sandbox |
| CVE-2020-9963 | Funuo la taarifa wakati wa usindikaji wa Quick Look preview |
| CVE-2021-30876 | Korapsheni ya kumbukumbu katika utengenezaji wa thumbnail |

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

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
