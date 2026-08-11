# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Quick Look, macOS'un **dosya önizleme framework'üdür**. Bir kullanıcı Finder'da bir dosya seçtiğinde, Space tuşuna bastığında, dosyanın üzerine geldiğinde veya küçük resimler etkinleştirilmiş bir dizini görüntülediğinde Quick Look, dosyayı ayrıştırmak ve görsel bir önizleme oluşturmak için **otomatik olarak bir generator plugin'i yükler**.<sup>[[1]](#references)</sup>

Quick Look generators, belirli **Uniform Type Identifiers (UTI'ler)** için kayıt olan **bundle'lardır** (`.qlgenerator`). macOS, UTI ile eşleşen bir dosya için önizlemeye ihtiyaç duyduğunda generator'ı sandbox'lanmış bir yardımcı process'e (`QuickLookSatellite` veya `qlmanage`) yükler ve generator function'ını çağırır.

### Bunun Security Açısından Önemi

> [!WARNING]
> Quick Look generators, **bir dosyayı yalnızca seçerek veya görüntüleyerek** tetiklenir — "Open" action'ı gerekli değildir. Bu durum onları güçlü bir **pasif exploitation vector'ü** haline getirir: kullanıcının tek yapması gereken, malicious bir dosya içeren bir dizine gitmektir.

**Attack surface:**
- Generators; diskten, download'lardan, email attachment'larından veya network share'lerden gelen **rastgele dosya içeriğini ayrıştırır**
- Hazırlanmış bir dosya, generator code'undaki **parsing vulnerability'lerini** (buffer overflow'lar, format string'ler, type confusion) exploit edebilir
- Preview rendering **otomatik olarak gerçekleşir** — malicious bir dosyanın bulunduğu Downloads klasörünü görüntülemek yeterlidir
- Quick Look **sandbox'lanmış bir helper** içinde çalışır, ancak bu context'ten sandbox escape'leri gösterilmiştir

## Mimari
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

### Kurulu Generator'leri Listeleme
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
## Saldırı Senaryoları

### Dosya Tabanlı Exploitation

Karmaşık dosya formatlarını (3D modeller, bilimsel veriler, arşiv formatları) ayrıştıran üçüncü taraf bir Quick Look generator, başlıca hedeftir:
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
### İndirmeler Üzerinden Drive-By
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Third-Party Generator Replacement

Bir Quick Look generator bundle'ı **user-writable location** (`~/Library/QuickLook/`) içine yüklenmişse değiştirilebilir:
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
## Sandbox Considerations

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
## Gerçek Dünyadaki CVE'ler<sup>[[2]](#references)</sup>

| CVE | Açıklama |
|---|---|
| CVE-2019-8741 | Özel olarak hazırlanmış dosya aracılığıyla Quick Look önizlemesinde bellek bozulması |
| CVE-2018-4293 | Quick Look generator sandbox kaçışı |
| CVE-2020-9963 | Quick Look önizleme işlemesi aracılığıyla bilgi ifşası |
| CVE-2021-30876 | Küçük resim oluşturma sırasında bellek bozulması |

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

- [1] [Apple Developer — Quick Look Programlama Kılavuzu](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — Quick Look CVE'leri](https://support.apple.com/en-us/HT201222)
{{#include ../../../banners/hacktricks-training.md}}
