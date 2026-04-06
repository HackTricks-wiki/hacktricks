# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Quick Look is macOS's **file preview framework**. When a user selects a file in Finder, presses Space, hovers over it, or views a directory with thumbnails enabled, Quick Look **automatically loads a generator plugin** to parse the file and render a visual preview.

Quick Look generators are **bundles** (`.qlgenerator`) that register for specific **Uniform Type Identifiers (UTIs)**. When macOS needs a preview for a file matching that UTI, it loads the generator into a sandboxed helper process (`QuickLookSatellite` or `qlmanage`) and calls its generator function.

### Why This Matters for Security

> [!WARNING]
> Quick Look generators are triggered by **simply selecting or viewing a file** — no "Open" action is required. This makes them a powerful **passive exploitation vector**: the user just needs to navigate to a directory containing a malicious file.

**Attack surface:**
- Generators **parse arbitrary file content** from disk, downloads, email attachments, or network shares
- A crafted file can exploit **parsing vulnerabilities** (buffer overflows, format strings, type confusion) in the generator code
- The preview rendering happens **automatically** — viewing a Downloads folder where a malicious file landed is enough
- Quick Look runs in a **sandboxed helper**, but sandbox escapes from this context have been demonstrated

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

### List Installed Generators

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

### Using the Scanner

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

A third-party Quick Look generator that parses complex file formats (3D models, scientific data, archive formats) is a prime target:

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

### Third-Party Generator Replacement

If a Quick Look generator bundle is installed in a **user-writable location** (`~/Library/QuickLook/`), it can be replaced:

```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```

### Trigger Quick Look Remotely

```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```

## Sandbox Considerations

Quick Look generators run inside a sandboxed helper process. The sandbox profile limits:
- File system access (mostly read-only to the file being previewed)
- Network access (restricted)
- IPC (limited mach-lookup)

However, the sandbox has known escape vectors:

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

## References

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
