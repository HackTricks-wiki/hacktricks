# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Εστιάζει στην επιβολή της ακεραιότητας του code που εκτελείται στο σύστημα, παρέχοντας τη λογική πίσω από την επαλήθευση code signature του XNU. Μπορεί επίσης να ελέγχει entitlements και να χειρίζεται άλλες ευαίσθητες εργασίες, όπως το να επιτρέπει debugging ή να αποκτά task ports.

Επιπλέον, για ορισμένες λειτουργίες, το kext προτιμά να επικοινωνεί με το user space running daemon `/usr/libexec/amfid`. Αυτή η σχέση εμπιστοσύνης έχει καταχραστεί σε αρκετά jailbreaks.

Σε πρόσφατες εκδόσεις macOS, το AMFI δεν είναι πλέον διαθέσιμο εύκολα ως standalone on-disk kext, οπότε το reversing συνήθως σημαίνει εργασία από το **kernelcache** ή ένα **KDK** αντί για περιήγηση στο `/System/Library/Extensions`.

Το AMFI χρησιμοποιεί πολιτικές **MACF** και καταχωρεί τα hooks του τη στιγμή που ξεκινά. Επίσης, η αποτροπή του loading ή το unloading του μπορεί να προκαλέσει kernel panic. Ωστόσο, υπάρχουν κάποια boot arguments που επιτρέπουν να αποδυναμωθεί το AMFI:

- `amfi_unrestricted_task_for_pid`: Επιτρέπει το task_for_pid χωρίς τα απαιτούμενα entitlements
- `amfi_allow_any_signature`: Επιτρέπει οποιοδήποτε code signature
- `cs_enforcement_disable`: Argument σε επίπεδο συστήματος που απενεργοποιεί το code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Ακυρώνει platform binaries με entitlements
- `amfi_get_out_of_my_way`: Απενεργοποιεί πλήρως το amfi

Αυτές είναι μερικές από τις πολιτικές MACF που καταχωρεί:

- **`cred_check_label_update_execve:`** Θα γίνει label update και θα επιστρέψει 1
- **`cred_label_associate`**: Ενημερώνει το mac label slot του AMFI με label
- **`cred_label_destroy`**: Αφαιρεί το mac label slot του AMFI
- **`cred_label_init`**: Μετακινεί το 0 στο mac label slot του AMFI
- **`cred_label_update_execve`:** Ελέγχει τα entitlements του process για να δει αν πρέπει να επιτρέπεται η τροποποίηση των labels.
- **`file_check_mmap`:** Ελέγχει αν το mmap αποκτά memory και τη ρυθμίζει ως executable. Σε αυτή την περίπτωση ελέγχει αν απαιτείται library validation και, αν ναι, καλεί τη function της library validation.
- **`file_check_library_validation`**: Καλεί τη function της library validation, η οποία ελέγχει μεταξύ άλλων αν ένα platform binary φορτώνει άλλο platform binary ή αν το process και το νέο loaded file έχουν το ίδιο TeamID. Ορισμένα entitlements θα επιτρέψουν επίσης να φορτωθεί οποιαδήποτε library.
- **`policy_initbsd`**: Ρυθμίζει trusted NVRAM Keys
- **`policy_syscall`**: Ελέγχει DYLD policies όπως αν το binary έχει unrestricted segments, αν πρέπει να επιτρέπονται env vars... αυτό καλείται επίσης όταν ένα process ξεκινά μέσω `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Ελέγχει αν όταν ένα process εκτελεί ένα νέο binary άλλα processes με SEND rights πάνω στο task port του process πρέπει να τα διατηρήσουν ή όχι. Τα platform binaries επιτρέπονται, το entitlement `get-task-allow` το επιτρέπει, τα entitlements `task_for_pid-allow` επιτρέπονται και επίσης binaries με το ίδιο TeamID.
- **`proc_check_expose_task`**: επιβάλλει entitlements
- **`amfi_exc_action_check_exception_send`**: Στέλνεται exception message σε debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Κύκλος ζωής του label κατά τον χειρισμό exception (debugging)
- **`proc_check_get_task`**: Ελέγχει entitlements όπως `get-task-allow` που επιτρέπει σε άλλα processes να αποκτούν το tasks port και `task_for_pid-allow`, που επιτρέπουν στο process να αποκτά τα tasks ports άλλων processes. Αν κανένα από αυτά δεν ισχύει, καλεί το `amfid permitunrestricteddebugging` για να ελέγξει αν επιτρέπεται.
- **`proc_check_mprotect`**: Αρνείται αν το `mprotect` κληθεί με το flag `VM_PROT_TRUSTED`, το οποίο δείχνει ότι η περιοχή πρέπει να αντιμετωπίζεται σαν να έχει έγκυρο code signature.
- **`vnode_check_exec`**: Καλείται όταν executable files φορτώνονται στη memory και ορίζει `cs_hard | cs_kill`, που θα σκοτώσει το process αν οποιαδήποτε από τις pages καταστεί invalid
- **`vnode_check_getextattr`**: MacOS: Ελέγχει `com.apple.root.installed` και `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Όπως το get + `com.apple.private.allow-bless` και internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code που καλεί το XNU για να ελέγξει το code signature χρησιμοποιώντας entitlements, trust cache και `amfid`
- **`proc_check_run_cs_invalid`**: Παρεμβάλλεται σε κλήσεις `ptrace()` (`PT_ATTACH` και `PT_TRACE_ME`). Ελέγχει για οποιοδήποτε από τα entitlements `get-task-allow`, `run-invalid-allow` και `run-unsigned-code` και αν δεν υπάρχει κανένα, ελέγχει αν επιτρέπεται το debugging.
- **`proc_check_map_anon`**: Αν το mmap κληθεί με το flag **`MAP_JIT`**, το AMFI θα ελέγξει το entitlement `dynamic-codesigning`.

`AMFI.kext` επίσης εκθέτει ένα API για άλλα kernel extensions, και είναι δυνατό να βρεθούν τα dependencies του με:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

Αυτός είναι ο daemon σε user mode που το `AMFI.kext` θα χρησιμοποιεί για να ελέγχει code signatures σε user mode.\
Για να επικοινωνήσει το `AMFI.kext` με τον daemon χρησιμοποιεί mach messages μέσω του port `HOST_AMFID_PORT`, που είναι το special port `18`.

Σημειώστε ότι στο macOS δεν είναι πλέον δυνατό για root processes να hijack ειδικά ports, καθώς προστατεύονται από το `SIP` και μόνο το launchd μπορεί να τα πάρει. Στο iOS ελέγχεται ότι το process που στέλνει πίσω το response έχει το CDHash hardcoded του `amfid`.

Είναι δυνατό να δει κανείς πότε το `amfid` ζητείται να ελέγξει ένα binary και το response του, κάνοντας debugging σε αυτό και βάζοντας ένα breakpoint στο `mach_msg`.

Μόλις ληφθεί ένα message μέσω του special port, το **MIG** χρησιμοποιείται για να στείλει κάθε function στη function που καλεί. Οι κύριες functions έχουν αναστραφεί και εξηγηθεί μέσα στο βιβλίο.

### DYLD policy and library validation

Οι νεότερες εκδόσεις του `dyld` καλούν το `amfi_check_dyld_policy_self()` πολύ νωρίς από το `configureProcessRestrictions()` για να ρωτήσουν το AMFI αν το process μπορεί να χρησιμοποιήσει `DYLD_*` path variables, interposing, fallback paths, embedded variables ή να ανεχθεί αποτυχημένη library insertion. Επομένως, κατά το triaging ενός injection surface, δεν αρκεί να εξετάζετε μόνο Mach-O load commands: πρέπει επίσης να εξετάζετε τα entitlements και τα runtime flags που το AMFI θα μεταφράσει σε `dyld` policy.

Ένας πρακτικός triage loop είναι:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Σε σύγχρονο macOS, πολλά Apple binaries δεν φέρουν πλέον άμεσα το `com.apple.security.cs.disable-library-validation` και αντί αυτού συνοδεύονται από το `com.apple.private.security.clear-library-validation`. Σε αυτή την περίπτωση, η library validation δεν απενεργοποιείται τη στιγμή του `execve`: η διεργασία πρέπει να καλέσει `csops(..., CS_OPS_CLEAR_LV, ...)` πάνω στον εαυτό της, και το XNU επιτρέπει αυτή την ενέργεια μόνο για την calling process όταν υπάρχει το entitlement. Από επιθετική σκοπιά, αυτό έχει σημασία επειδή ένας στόχος μπορεί να γίνει injectable μόνο **αφού** φτάσει στο code path που καθαρίζει ρητά το LV (για παράδειγμα, λίγο πριν φορτώσει προαιρετικά plugins).

## Provisioning Profiles

Ένα provisioning profile μπορεί να χρησιμοποιηθεί για να sign code. Υπάρχουν **Developer** profiles που μπορούν να χρησιμοποιηθούν για να sign code και να το δοκιμάσουν, και **Enterprise** profiles που μπορούν να χρησιμοποιηθούν σε όλες τις συσκευές.

Αφού ένα App υποβληθεί στο Apple Store, αν εγκριθεί, signάρεται από την Apple και το provisioning profile δεν χρειάζεται πλέον.

Ένα profile συνήθως χρησιμοποιεί την επέκταση `.mobileprovision` ή `.provisionprofile` και μπορεί να γίνει dump με:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Παρόλο που μερικές φορές αναφέρονται ως certificated, αυτά τα provisioning profiles έχουν περισσότερα από ένα certificate:

- **AppIDName:** Το Application Identifier
- **AppleInternalProfile**: Δηλώνει ότι αυτό είναι ένα Apple Internal profile
- **ApplicationIdentifierPrefix**: Προστίθεται πριν από το AppIDName (ίδιο με το TeamIdentifier)
- **CreationDate**: Ημερομηνία σε μορφή `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Ένας πίνακας από (συνήθως ένα) certificate(s), κωδικοποιημένα ως Base64 data
- **Entitlements**: Τα entitlements που επιτρέπονται με entitlements για αυτό το profile
- **ExpirationDate**: Ημερομηνία λήξης σε μορφή `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Το Application Name, ίδιο με το AppIDName
- **ProvisionedDevices**: Ένας πίνακας (για developer certificates) από UDIDs για τα οποία αυτό το profile είναι έγκυρο
- **ProvisionsAllDevices**: Ένα boolean (true για enterprise certificates)
- **TeamIdentifier**: Ένας πίνακας από (συνήθως ένα) αλφαριθμητικό string(s) που χρησιμοποιείται για την αναγνώριση του developer για σκοπούς inter-app interaction
- **TeamName**: Ένα αναγνώσιμο από άνθρωπο όνομα που χρησιμοποιείται για την αναγνώριση του developer
- **TimeToLive**: Η ισχύς (σε ημέρες) του certificate
- **UUID**: Ένα Universally Unique Identifier για αυτό το profile
- **Version**: Αυτή τη στιγμή ορίζεται σε 1

Σημείωσε ότι η καταχώρηση entitlements θα περιέχει ένα περιορισμένο σύνολο entitlements και το provisioning profile θα μπορεί να δίνει μόνο αυτά τα συγκεκριμένα entitlements, ώστε να αποτρέπεται η παροχή των private entitlements της Apple.

Σημείωσε ότι τα profiles συνήθως βρίσκονται στο `/var/MobileDeviceProvisioningProfiles` και είναι δυνατό να τα ελέγξεις με **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Αυτή είναι η εξωτερική βιβλιοθήκη που καλεί το `amfid` για να ρωτήσει αν πρέπει να επιτρέψει κάτι ή όχι. Αυτό έχει καταχραστεί ιστορικά στο jailbreaking, εκτελώντας μια backdoored έκδοση της που θα επέτρεπε τα πάντα.

Στο macOS αυτό βρίσκεται μέσα στο `MobileDevice.framework`.

## AMFI Trust Caches

Τα trust caches δεν είναι μόνο έννοια του iOS. Στο σύγχρονο macOS, ειδικά σε **Apple silicon**, το static trust cache και τα loadable trust caches αποτελούν μέρος της Secure Boot αλυσίδας. Όταν το **CodeDirectory hash** ενός Mach-O υπάρχει εκεί, το AMFI μπορεί να του δώσει **platform privilege** χωρίς περαιτέρω authenticity checks κατά το launch time. Αυτό σημαίνει επίσης ότι η Apple μπορεί να κλειδώσει platform binaries σε μια συγκεκριμένη έκδοση OS και να αποτρέψει την επαναχρησιμοποίηση παλιότερων Apple-signed binaries σε νεότερα συστήματα.

Σε πρόσφατες εκδόσεις macOS, τα trust-cache metadata συνδέονται επίσης με τα **launch constraints**, έτσι ώστε αντιγραμμένες system apps και binaries που ξεκινούν από λάθος parent/location να μπορούν να απορριφθούν από το AMFI ακόμα και αν είναι ακόμη Apple-signed. Η λεπτομερής διαδικασία extraction και reversing καλύπτεται στο:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Στο iOS και στο jailbreak research θα βρεις ακόμα το παραδοσιακό μοντέλο των **loadable trust caches** να χρησιμοποιείται για whitelisting ad-hoc signed binaries.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
