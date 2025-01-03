# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Όταν μια σύνδεση δημιουργείται σε μια υπηρεσία XPC, ο διακομιστής θα ελέγξει αν η σύνδεση επιτρέπεται. Αυτοί είναι οι έλεγχοι που θα εκτελέσει συνήθως:

1. Έλεγχος αν η **διαδικασία που συνδέεται είναι υπογεγραμμένη με πιστοποιητικό υπογεγραμμένο από την Apple** (δίδεται μόνο από την Apple).
- Αν αυτό **δεν επαληθευτεί**, ένας επιτιθέμενος θα μπορούσε να δημιουργήσει ένα **ψεύτικο πιστοποιητικό** για να ταιριάζει με οποιονδήποτε άλλο έλεγχο.
2. Έλεγχος αν η διαδικασία που συνδέεται είναι υπογεγραμμένη με το **πιστοποιητικό της οργάνωσης** (επικύρωση ID ομάδας).
- Αν αυτό **δεν επαληθευτεί**, **οποιοδήποτε πιστοποιητικό προγραμματιστή** από την Apple μπορεί να χρησιμοποιηθεί για υπογραφή και σύνδεση με την υπηρεσία.
3. Έλεγχος αν η διαδικασία που συνδέεται **περιέχει ένα κατάλληλο bundle ID**.
- Αν αυτό **δεν επαληθευτεί**, οποιοδήποτε εργαλείο **υπογεγραμμένο από την ίδια οργάνωση** θα μπορούσε να χρησιμοποιηθεί για αλληλεπίδραση με την υπηρεσία XPC.
4. (4 ή 5) Έλεγχος αν η διαδικασία που συνδέεται έχει έναν **κατάλληλο αριθμό έκδοσης λογισμικού**.
- Αν αυτό **δεν επαληθευτεί**, παλιοί, ανασφαλείς πελάτες, ευάλωτοι σε διαδικαστική ένεση, θα μπορούσαν να χρησιμοποιηθούν για σύνδεση με την υπηρεσία XPC ακόμη και με τους άλλους ελέγχους σε εφαρμογή.
5. (4 ή 5) Έλεγχος αν η διαδικασία που συνδέεται έχει σκληρυμένο χρόνο εκτέλεσης χωρίς επικίνδυνες εξουσιοδοτήσεις (όπως αυτές που επιτρέπουν τη φόρτωση αυθαίρετων βιβλιοθηκών ή τη χρήση μεταβλητών περιβάλλοντος DYLD).
1. Αν αυτό **δεν επαληθευτεί**, ο πελάτης μπορεί να είναι **ευάλωτος σε ένεση κώδικα**.
6. Έλεγχος αν η διαδικασία που συνδέεται έχει μια **εξουσιοδότηση** που της επιτρέπει να συνδεθεί με την υπηρεσία. Αυτό ισχύει για τα δυαδικά αρχεία της Apple.
7. Η **επικύρωση** πρέπει να είναι **βασισμένη** στο **token ελέγχου του πελάτη** **αντί** για το ID διαδικασίας του (**PID**) καθώς το πρώτο αποτρέπει τις **επιθέσεις επαναχρησιμοποίησης PID**.
- Οι προγραμματιστές **σπάνια χρησιμοποιούν το API token ελέγχου** καθώς είναι **ιδιωτικό**, οπότε η Apple θα μπορούσε να **αλλάξει** ανά πάσα στιγμή. Επιπλέον, η χρήση ιδιωτικών API δεν επιτρέπεται σε εφαρμογές του Mac App Store.
- Αν η μέθοδος **`processIdentifier`** χρησιμοποιηθεί, μπορεί να είναι ευάλωτη.
- **`xpc_dictionary_get_audit_token`** θα πρέπει να χρησιμοποιείται αντί για **`xpc_connection_get_audit_token`**, καθώς η τελευταία θα μπορούσε επίσης να είναι [ευάλωτη σε ορισμένες καταστάσεις](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Για περισσότερες πληροφορίες σχετικά με την επίθεση επαναχρησιμοποίησης PID ελέγξτε:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Για περισσότερες πληροφορίες σχετικά με την επίθεση **`xpc_connection_get_audit_token`** ελέγξτε:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Το Trustcache είναι μια αμυντική μέθοδος που εισήχθη σε μηχανές Apple Silicon που αποθηκεύει μια βάση δεδομένων CDHSAH των δυαδικών αρχείων της Apple, ώστε μόνο επιτρεπόμενα μη τροποποιημένα δυαδικά αρχεία να μπορούν να εκτελούνται. Αυτό αποτρέπει την εκτέλεση υποβαθμισμένων εκδόσεων.

### Code Examples

Ο διακομιστής θα υλοποιήσει αυτή την **επικύρωση** σε μια συνάρτηση που ονομάζεται **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Το αντικείμενο NSXPCConnection έχει μια **ιδιωτική** ιδιότητα **`auditToken`** (αυτή που θα έπρεπε να χρησιμοποιείται αλλά μπορεί να αλλάξει) και μια **δημόσια** ιδιότητα **`processIdentifier`** (αυτή που δεν θα έπρεπε να χρησιμοποιείται).

Η διαδικασία σύνδεσης θα μπορούσε να επαληθευτεί με κάτι όπως:
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
Αν ένας προγραμματιστής δεν θέλει να ελέγξει την έκδοση του πελάτη, θα μπορούσε τουλάχιστον να ελέγξει ότι ο πελάτης δεν είναι ευάλωτος σε διαδικαστική έγχυση:
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
{{#include ../../../../../../banners/hacktricks-training.md}}
