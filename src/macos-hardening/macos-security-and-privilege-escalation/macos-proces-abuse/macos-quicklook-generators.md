# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Quick Look, macOS'un **dosya önizleme framework'üdür**. Bir kullanıcı Finder'da bir dosya seçtiğinde, Space tuşuna bastığında, dosyanın üzerine geldiğinde veya thumbnails etkin bir directory görüntülediğinde, Quick Look dosyayı ayrıştırmak ve görsel bir önizleme oluşturmak için **otomatik olarak bir generator plugin'i yükler**.<sup>[1]</sup>

Quick Look generators, belirli **Uniform Type Identifiers (UTIs)** için kayıt olan **bundle**'lardır (`.qlgenerator`). macOS, bu UTI ile eşleşen bir dosya için önizlemeye ihtiyaç duyduğunda generator'ı sandboxed bir yardımcı process'e (`QuickLookSatellite` veya `qlmanage`) yükler ve generator function'ını çağırır.

### Bu Neden Security Açısından Önemlidir?

> [!WARNING]
> Quick Look generators, **yalnızca bir dosya seçilerek veya görüntülenerek** tetiklenir — "Open" action'ı gerekmez. Bu durum onları güçlü bir **pasif exploitation vector'ı** hâline getirir: Kullanıcının yalnızca malicious bir dosya içeren directory'ye gitmesi yeterlidir.

**Attack surface:**
- Generators, diskten, download'lardan, email attachment'larından veya network share'lerden gelen **keyfi dosya içeriğini parse eder**
- Özel olarak hazırlanmış bir dosya, generator kodundaki **parsing vulnerability'lerini** (buffer overflow'ları, format string'leri, type confusion) exploit edebilir
- Preview rendering işlemi **otomatik olarak** gerçekleşir — malicious bir dosyanın bulunduğu Downloads folder'ını görüntülemek yeterlidir
- Quick Look, **sandboxed bir helper** içinde çalışır; ancak bu context'ten sandbox escape örnekleri gösterilmiştir

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
## Enumerasyon

### Yüklü Generator'ları Listeleme
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
### Scanner'ı Kullanma
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

Complex file formats (3D models, scientific data, archive formats) ayrıştıran üçüncü taraf bir Quick Look generator, birincil hedeftir:
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
### Downloads Üzerinden Drive-By
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Third-Party Generator Replacement

Bir Quick Look generator bundle'ı **kullanıcı tarafından yazılabilir bir konuma** (`~/Library/QuickLook/`) kurulmuşsa, değiştirilebilir:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Quick Look'u Uzaktan Tetikleme
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Sandbox Hususları

Quick Look generator'ları sandbox'lanmış bir yardımcı işlem içinde çalışır. Sandbox profili şunları sınırlar:
- Dosya sistemi erişimi (çoğunlukla önizlemesi yapılan dosyaya salt okunur erişim)
- Network erişimi (kısıtlı)
- IPC (sınırlı mach-lookup)

Ancak sandbox'ın bilinen kaçış vektörleri vardır:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## Gerçek Dünya CVE'leri

| CVE | Açıklama |
|---|---|
| CVE-2019-8741 | Özel olarak hazırlanmış dosya aracılığıyla Quick Look önizlemesinde bellek bozulması |
| CVE-2018-4293 | Quick Look generator sandbox kaçışı |
| CVE-2020-9963 | Quick Look önizleme işleme bilgi disclosure |
| CVE-2021-30876 | Thumbnail oluşturma sırasında bellek bozulması |

## Quick Look Generators için Fuzzing
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
## Referanslar

- [1] [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
