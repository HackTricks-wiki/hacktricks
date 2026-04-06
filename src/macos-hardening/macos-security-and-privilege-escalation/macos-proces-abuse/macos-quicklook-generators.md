# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Quick Look macOS का एक **file preview framework** है। जब कोई उपयोगकर्ता Finder में कोई फ़ाइल select करता है, Space दबाता है, उस पर hover करता है, या thumbnails enabled डायरेक्टरी देखता है, तो Quick Look फ़ाइल को parse करने और visual preview render करने के लिए **automatically loads a generator plugin**।

Quick Look generators **bundles** (`.qlgenerator`) होते हैं जो specific **Uniform Type Identifiers (UTIs)** के लिए register करते हैं। जब macOS को किसी उस UTI से मिलती फ़ाइल का preview चाहिए होता है, तो वह generator को एक sandboxed helper process (`QuickLookSatellite` या `qlmanage`) में load करता है और उसके generator function को call करता है।

### Why This Matters for Security

> [!WARNING]
> Quick Look generators are triggered by **simply selecting or viewing a file** — no "Open" action is required. This makes them a powerful **passive exploitation vector**: the user just needs to navigate to a directory containing a malicious file.

**Attack surface:**
- Generators **disk, downloads, email attachments, or network shares** से arbitrary file content को parse करते हैं
- एक crafted फ़ाइल generator code में मौजूद **parsing vulnerabilities** (buffer overflows, format strings, type confusion) का exploit कर सकती है
- preview rendering **automatically** होता है — उस Downloads फ़ोल्डर को देखना जहाँ एक malicious फ़ाइल आ गिरी है ही काफी है
- Quick Look एक **sandboxed helper** में चलता है, पर इस context से sandbox escapes की घटनाएँ दिखाई गई हैं

## Architecture
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
## सूचीकरण

### इंस्टॉल किए गए जनरेटरों की सूची
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
### स्कैनर का उपयोग
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## हमले के परिदृश्य

### फ़ाइल-आधारित शोषण

तीसरे पक्ष का Quick Look generator जो जटिल फ़ाइल स्वरूपों (3D मॉडल, वैज्ञानिक डेटा, आर्काइव फॉर्मैट्स) को पार्स करता है, एक प्रमुख लक्ष्य है:
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
### Drive-By के माध्यम से डाउनलोड्स
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### तृतीय-पक्ष जेनरेटर प्रतिस्थापन

यदि Quick Look generator bundle किसी **उपयोगकर्ता-लिखने योग्य स्थान** (`~/Library/QuickLook/`) में इंस्टॉल है, तो इसे बदला जा सकता है:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### रिमोट से Quick Look ट्रिगर करें
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Sandbox पर विचार

Quick Look generators एक sandboxed helper process के अंदर चलते हैं। Sandbox profile निम्न को सीमित करता है:
- File system access (मुख्यतः पूर्वावलोकन की जा रही फ़ाइल के लिए केवल read-only)
- Network access (सीमित)
- IPC (limited mach-lookup)

हालाँकि, sandbox के ज्ञात escape vectors मौजूद हैं:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## वास्तविक दुनिया के CVEs

| CVE | विवरण |
|---|---|
| CVE-2019-8741 | Quick Look preview memory corruption (निर्मित फ़ाइल के माध्यम से) |
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
## संदर्भ

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
