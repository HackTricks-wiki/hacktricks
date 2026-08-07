# Έλεγχος συνδεόμενης διεργασίας macOS XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Έλεγχος συνδεόμενης διεργασίας XPC

Όταν δημιουργείται μια σύνδεση με μια υπηρεσία XPC, ο server ελέγχει αν επιτρέπεται η σύνδεση. Συνήθως εκτελεί τους εξής ελέγχους:

1. Έλεγχος αν η **διεργασία είναι υπογεγραμμένη με πιστοποιητικό υπογεγραμμένο από την Apple** (το οποίο παρέχεται αποκλειστικά από την Apple).
- Αν αυτό **δεν επαληθεύεται**, ένας attacker θα μπορούσε να δημιουργήσει ένα **fake certificate** ώστε να περάσει οποιονδήποτε άλλο έλεγχο.
2. Έλεγχος αν η συνδεόμενη διεργασία είναι υπογεγραμμένη με το **πιστοποιητικό του οργανισμού**, (επαλήθευση team ID).
- Αν αυτό **δεν επαληθεύεται**, οποιοδήποτε **developer certificate** από την Apple μπορεί να χρησιμοποιηθεί για την υπογραφή και τη σύνδεση στην υπηρεσία.
3. Έλεγχος αν η συνδεόμενη διεργασία **περιέχει το σωστό bundle ID**.
- Αν αυτό **δεν επαληθεύεται**, οποιοδήποτε εργαλείο **υπογεγραμμένο από τον ίδιο οργανισμό** θα μπορούσε να χρησιμοποιηθεί για αλληλεπίδραση με την υπηρεσία XPC.
4. (4 ή 5) Έλεγχος αν η συνδεόμενη διεργασία διαθέτει **σωστό αριθμό έκδοσης λογισμικού**.
- Αν αυτό **δεν επαληθεύεται**, θα μπορούσαν να χρησιμοποιηθούν παλιοί, μη ασφαλείς clients, ευάλωτοι σε process injection, για σύνδεση στην υπηρεσία XPC, ακόμη και όταν οι υπόλοιποι έλεγχοι είναι σε ισχύ.
5. (4 ή 5) Έλεγχος αν η συνδεόμενη διεργασία διαθέτει hardened runtime χωρίς επικίνδυνα entitlements (όπως αυτά που επιτρέπουν τη φόρτωση αυθαίρετων libraries ή τη χρήση μεταβλητών περιβάλλοντος DYLD)
1. Αν αυτό **δεν επαληθεύεται**, ο client ενδέχεται να είναι **ευάλωτος σε code injection**
6. Έλεγχος αν η συνδεόμενη διεργασία διαθέτει **entitlement** που της επιτρέπει να συνδεθεί στην υπηρεσία. Αυτό ισχύει για τα Apple binaries.
7. Η **επαλήθευση** πρέπει να **βασίζεται** στο **audit token** του συνδεόμενου **client** και **όχι** στο process ID (**PID**), καθώς το πρώτο αποτρέπει τις **PID reuse attacks**.
- Οι developers **σπάνια χρησιμοποιούν το audit token** API call, επειδή είναι **private**, οπότε η Apple θα μπορούσε να το **αλλάξει** ανά πάσα στιγμή. Επιπλέον, η χρήση private API δεν επιτρέπεται σε εφαρμογές του Mac App Store.
- Αν χρησιμοποιείται η μέθοδος **`processIdentifier`**, ενδέχεται να είναι ευάλωτη
- Θα πρέπει να χρησιμοποιείται το **`xpc_dictionary_get_audit_token`** αντί για το **`xpc_connection_get_audit_token`**, καθώς το τελευταίο θα μπορούσε επίσης να είναι [ευάλωτο σε συγκεκριμένες περιπτώσεις](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Επιθέσεις επικοινωνίας

Για περισσότερες πληροφορίες σχετικά με την επίθεση PID reuse:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Για περισσότερες πληροφορίες σχετικά με την επίθεση **`xpc_connection_get_audit_token`**:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Πρόληψη επιθέσεων downgrade

Το Trustcache είναι μια αμυντική μέθοδος που εισήχθη σε μηχανήματα Apple Silicon και αποθηκεύει μια βάση δεδομένων με CDHSAH των Apple binaries, ώστε να μπορούν να εκτελούνται μόνο επιτρεπόμενα, μη τροποποιημένα binaries. Αυτό αποτρέπει την εκτέλεση υποβαθμισμένων εκδόσεων.

### Παραδείγματα κώδικα

Ο server υλοποιεί αυτή την **επαλήθευση** σε μια συνάρτηση που ονομάζεται **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Το αντικείμενο NSXPCConnection διαθέτει την **private** ιδιότητα **`auditToken`** (αυτή που θα πρέπει να χρησιμοποιείται, αλλά ενδέχεται να αλλάξει) και την **public** ιδιότητα **`processIdentifier`** (αυτή που δεν θα πρέπει να χρησιμοποιείται).

Η connecting process θα μπορούσε να επαληθευτεί κάπως έτσι:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
Αν ένας developer δεν θέλει να ελέγξει την έκδοση του client, θα μπορούσε τουλάχιστον να ελέγξει ότι ο client δεν είναι ευάλωτος σε process injection:
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
Τα παραπάνω σταθερά `cs_*` είναι οι code-signing flags που ορίζονται στο `osfmk/kern/cs_blobs.h` του XNU, επομένως μπορούν να ελεγχθούν απευθείας στον source code αντί να γίνονται υποθέσεις:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Αναφορές

- [1] [Apple Developer — Γλώσσα απαιτήσεων Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (σημαίες Code Signing `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
