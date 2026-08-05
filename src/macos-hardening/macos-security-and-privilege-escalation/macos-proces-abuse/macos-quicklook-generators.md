# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Quick Look, macOS का **file preview framework** है। जब कोई user Finder में किसी file को select करता है, Space दबाता है, उस पर hover करता है, या thumbnails enabled वाली directory देखता है, तो Quick Look file को parse करने और visual preview render करने के लिए **generator plugin को automatically load** करता है।<sup>[[1]](#references)</sup>

Quick Look generators **bundles** (`.qlgenerator`) होते हैं, जो specific **Uniform Type Identifiers (UTIs)** के लिए register होते हैं। जब macOS को उस UTI से match करने वाली file का preview चाहिए होता है, तो यह generator को sandboxed helper process (`QuickLookSatellite` या `qlmanage`) में load करता है और उसके generator function को call करता है।

### Security के लिए यह क्यों महत्वपूर्ण है

> [!WARNING]
> Quick Look generators **किसी file को केवल select या view करने पर** trigger हो जाते हैं — किसी "Open" action की आवश्यकता नहीं होती। यह उन्हें एक शक्तिशाली **passive exploitation vector** बनाता है: user को केवल ऐसी directory में जाना होता है जिसमें malicious file मौजूद हो।

**Attack surface:**
- Generators disk, downloads, email attachments या network shares से प्राप्त **arbitrary file content को parse** करते हैं
- Crafted file generator code में **parsing vulnerabilities** (buffer overflows, format strings, type confusion) का exploit कर सकती है
- Preview rendering **automatically** होता है — ऐसी Downloads folder को view करना, जिसमें malicious file आ गई हो, पर्याप्त है
- Quick Look एक **sandboxed helper** में चलता है, लेकिन इस context से sandbox escapes प्रदर्शित किए जा चुके हैं

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
## Enumeration

### Installed Generators की सूची
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
### Scanner का उपयोग
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Attack Scenarios

### File-Based Exploitation

एक third-party Quick Look generator जो complex file formats (3D models, scientific data, archive formats) को parse करता है, एक prime target है:
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
### Downloads के माध्यम से Drive-By
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Third-Party Generator Replacement

यदि कोई Quick Look generator bundle **user-writable location** (`~/Library/QuickLook/`) में installed है, तो उसे replace किया जा सकता है:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Quick Look को Remotely Trigger करना
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Sandbox Considerations

Quick Look generators एक sandboxed helper process के अंदर run होते हैं। Sandbox profile निम्न को सीमित करता है:
- File system access (preview की जा रही file के लिए mostly read-only)
- Network access (restricted)
- IPC (limited mach-lookup)

हालांकि, sandbox में ज्ञात escape vectors हैं:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2019-8741 | crafted file के माध्यम से Quick Look preview memory corruption |
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

- [1] [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
