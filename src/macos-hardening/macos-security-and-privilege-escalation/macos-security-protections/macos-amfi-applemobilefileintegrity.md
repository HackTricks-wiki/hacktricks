# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Εστιάζει στην επιβολή της ακεραιότητας του code που εκτελείται στο σύστημα, παρέχοντας τη λογική πίσω από το XNU's code signature verification. Μπορεί επίσης να ελέγχει entitlements και να χειρίζεται άλλες ευαίσθητες εργασίες, όπως το να επιτρέπει debugging ή την απόκτηση task ports.

Επιπλέον, για ορισμένες operations, το kext προτιμά να επικοινωνεί με το user space running daemon `/usr/libexec/amfid`. Αυτή η σχέση εμπιστοσύνης έχει καταχραστεί σε αρκετά jailbreaks.

Σε πρόσφατες εκδόσεις macOS, το AMFI δεν εκτίθεται πλέον εύκολα ως standalone on-disk kext, οπότε το reversing συνήθως σημαίνει εργασία από το **kernelcache** ή ένα **KDK** αντί για περιήγηση στο `/System/Library/Extensions`.

Το AMFI χρησιμοποιεί **MACF** policies και καταχωρεί τα hooks του τη στιγμή που ξεκινά. Επίσης, η αποτροπή του loading του ή το unloading του μπορεί να προκαλέσει kernel panic. Ωστόσο, υπάρχουν ορισμένα boot arguments που επιτρέπουν την αποδυνάμωση του AMFI:

- `amfi_unrestricted_task_for_pid`: Επιτρέπει το task_for_pid να επιτρέπεται χωρίς τα απαιτούμενα entitlements
- `amfi_allow_any_signature`: Επιτρέπει οποιοδήποτε code signature
- `cs_enforcement_disable`: System-wide argument που χρησιμοποιείται για να απενεργοποιήσει το code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Void platform binaries με entitlements
- `amfi_get_out_of_my_way`: Απενεργοποιεί πλήρως το amfi

Αυτές είναι μερικές από τις MACF policies που καταχωρεί:

- **`cred_check_label_update_execve:`** Θα πραγματοποιηθεί label update και θα επιστρέψει 1
- **`cred_label_associate`**: Ενημερώνει το mac label slot του AMFI με το label
- **`cred_label_destroy`**: Αφαιρεί το mac label slot του AMFI
- **`cred_label_init`**: Μετακινεί το 0 στο mac label slot του AMFI
- **`cred_label_update_execve`:** Ελέγχει τα entitlements του process για να δει αν πρέπει να επιτραπεί η τροποποίηση των labels.
- **`file_check_mmap`:** Ελέγχει αν το mmap αποκτά memory και το ορίζει ως executable. Σε αυτή την περίπτωση ελέγχει αν χρειάζεται library validation και, αν ναι, καλεί τη συνάρτηση library validation.
- **`file_check_library_validation`**: Καλεί τη συνάρτηση library validation, η οποία ελέγχει μεταξύ άλλων αν ένα platform binary φορτώνει άλλο platform binary ή αν το process και το νέο loaded file έχουν το ίδιο TeamID. Ορισμένα entitlements θα επιτρέψουν επίσης τη φόρτωση οποιασδήποτε library.
- **`policy_initbsd`**: Ρυθμίζει trusted NVRAM Keys
- **`policy_syscall`**: Ελέγχει DYLD policies όπως αν το binary έχει unrestricted segments, αν πρέπει να επιτρέψει env vars... αυτό καλείται επίσης όταν ένα process ξεκινά μέσω `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Ελέγχει αν, όταν ένα process εκτελεί ένα νέο binary, άλλα processes με SEND rights πάνω στο task port του process πρέπει να τα διατηρήσουν ή όχι. Platform binaries επιτρέπονται, το `get-task-allow` entitlement το επιτρέπει, τα `task_for_pid-allow` entitles επιτρέπονται και binaries με το ίδιο TeamID.
- **`proc_check_expose_task`**: επιβάλλει entitlements
- **`amfi_exc_action_check_exception_send`**: Στέλνεται exception message σε debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Lifecycle του label κατά τον χειρισμό exception (debugging)
- **`proc_check_get_task`**: Ελέγχει entitlements όπως `get-task-allow`, το οποίο επιτρέπει σε άλλα processes να πάρουν το tasks port, και `task_for_pid-allow`, τα οποία επιτρέπουν στο process να πάρει τα tasks ports άλλων processes. Αν κανένα από αυτά δεν ισχύει, καλεί το `amfid permitunrestricteddebugging` για να ελέγξει αν επιτρέπεται.
- **`proc_check_mprotect`**: Απορρίπτει αν το `mprotect` καλείται με το flag `VM_PROT_TRUSTED`, που υποδεικνύει ότι το region πρέπει να αντιμετωπίζεται σαν να έχει έγκυρο code signature.
- **`vnode_check_exec`**: Καλείται όταν executable files φορτώνονται στη memory και ορίζει `cs_hard | cs_kill`, κάτι που θα σκοτώσει το process αν οποιοδήποτε από τα pages γίνει invalid
- **`vnode_check_getextattr`**: MacOS: Ελέγχει `com.apple.root.installed` και `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Όπως get + `com.apple.private.allow-bless` και internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code που καλεί το XNU για να ελέγξει το code signature χρησιμοποιώντας entitlements, trust cache και `amfid`
- **`proc_check_run_cs_invalid`**: Παρεμβάλλει `ptrace()` calls (`PT_ATTACH` and `PT_TRACE_ME`). Ελέγχει για οποιοδήποτε από τα entitlements `get-task-allow`, `run-invalid-allow` και `run-unsigned-code` και αν δεν υπάρχει κανένα, ελέγχει αν επιτρέπεται debugging.
- **`proc_check_map_anon`**: Αν το `mmap` καλείται με το flag **`MAP_JIT`**, το AMFI θα ελέγξει το `dynamic-codesigning` entitlement.

`AMFI.kext` εκθέτει επίσης ένα API για άλλα kernel extensions, και είναι δυνατό να βρεθούν οι εξαρτήσεις του με:
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

Αυτός είναι ο daemon σε user mode που το `AMFI.kext` θα χρησιμοποιήσει για να ελέγχει code signatures σε user mode.\
Για να επικοινωνεί το `AMFI.kext` με τον daemon, χρησιμοποιεί mach messages μέσω του port `HOST_AMFID_PORT`, που είναι το ειδικό port `18`.

Σημείωσε ότι στο macOS πλέον δεν είναι δυνατό για root processes να hijack special ports, καθώς προστατεύονται από το `SIP` και μόνο το launchd μπορεί να τα αποκτήσει. Στο iOS ελέγχεται ότι το process που στέλνει πίσω την απόκριση έχει το CDHash hardcoded του `amfid`.

Είναι δυνατό να δεις πότε το `amfid` ζητείται να ελέγξει ένα binary και ποια είναι η απόκρισή του, κάνοντας debugging σε αυτό και βάζοντας breakpoint στο `mach_msg`.

Μόλις ληφθεί ένα μήνυμα μέσω του special port, το **MIG** χρησιμοποιείται για να στείλει κάθε function στη function που καλεί. Οι κύριες functions αναλύθηκαν reverse-engineered και εξηγήθηκαν μέσα στο βιβλίο.

### DYLD policy and library validation

Οι νεότερες εκδόσεις του `dyld` καλούν πολύ νωρίς το `amfi_check_dyld_policy_self()` από το `configureProcessRestrictions()` για να ρωτήσουν το AMFI αν το process επιτρέπεται να χρησιμοποιεί `DYLD_*` path variables, interposing, fallback paths, embedded variables ή να ανέχεται failed library insertion. Επομένως, όταν κάνεις triage σε ένα injection surface, δεν αρκεί να εξετάσεις μόνο Mach-O load commands: χρειάζεται επίσης να εξετάσεις τα entitlements και τα runtime flags που το AMFI θα μετατρέψει σε `dyld` policy.

Ένας πρακτικός triage loop είναι:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Σε σύγχρονο macOS, πολλά Apple binaries δεν φέρουν πλέον απευθείας το `com.apple.security.cs.disable-library-validation` και αντί αυτού διανέμονται με `com.apple.private.security.clear-library-validation`. Σε αυτή την περίπτωση, το library validation δεν απενεργοποιείται τη στιγμή του `execve`: το process πρέπει να καλέσει `csops(..., CS_OPS_CLEAR_LV, ...)` στον εαυτό του, και το XNU επιτρέπει αυτή την operation μόνο στο calling process όταν υπάρχει το entitlement. Από offensive πλευρά, αυτό έχει σημασία επειδή ένας target μπορεί να γίνει injectable μόνο **αφού** φτάσει στο code path που καθαρίζει ρητά το LV (για παράδειγμα, λίγο πριν φορτώσει optional plugins).

## Provisioning Profiles

Ένα provisioning profile μπορεί να χρησιμοποιηθεί για να sign code. Υπάρχουν **Developer** profiles που μπορούν να χρησιμοποιηθούν για να sign code και να το test, και **Enterprise** profiles που μπορούν να χρησιμοποιηθούν σε όλες τις devices.

Αφού ένα App υποβληθεί στο Apple Store, αν εγκριθεί, signάρεται από την Apple και το provisioning profile δεν χρειάζεται πλέον.

Ένα profile συνήθως χρησιμοποιεί την επέκταση `.mobileprovision` ή `.provisionprofile` και μπορεί να dumped με:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Αν και μερικές φορές αναφέρονται ως certificated, αυτά τα provisioning profiles έχουν περισσότερα από ένα certificate:

- **AppIDName:** Το Application Identifier
- **AppleInternalProfile**: Υποδηλώνει ότι αυτό είναι ένα Apple Internal profile
- **ApplicationIdentifierPrefix**: Προστίθεται πριν από το AppIDName (ίδιο με το TeamIdentifier)
- **CreationDate**: Ημερομηνία σε μορφή `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Ένας πίνακας από (συνήθως ένα) certificate(s), κωδικοποιημένα ως Base64 data
- **Entitlements**: Τα entitlements που επιτρέπονται με entitlements για αυτό το profile
- **ExpirationDate**: Ημερομηνία λήξης σε μορφή `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Το Application Name, ίδιο με το AppIDName
- **ProvisionedDevices**: Ένας πίνακας (για developer certificates) από UDIDs για τα οποία ισχύει αυτό το profile
- **ProvisionsAllDevices**: Ένα boolean (true για enterprise certificates)
- **TeamIdentifier**: Ένας πίνακας από (συνήθως ένα) αλφαριθμητικό string(s) που χρησιμοποιούνται για να αναγνωρίζουν τον developer για purposes inter-app interaction
- **TeamName**: Ένα human-readable όνομα που χρησιμοποιείται για να αναγνωρίζει τον developer
- **TimeToLive**: Validity (σε ημέρες) του certificate
- **UUID**: Ένα Universally Unique Identifier για αυτό το profile
- **Version**: Αυτή τη στιγμή έχει οριστεί σε 1

Σημειώστε ότι η εγγραφή entitlements θα περιέχει ένα περιορισμένο σύνολο entitlements και το provisioning profile θα μπορεί να δώσει μόνο αυτά τα συγκεκριμένα entitlements, ώστε να αποτραπεί η παροχή private entitlements της Apple.

Σημειώστε ότι τα profiles συνήθως βρίσκονται στο `/var/MobileDeviceProvisioningProfiles` και είναι δυνατό να τα ελέγξετε με **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Αυτή είναι η εξωτερική library που καλεί το `amfid` προκειμένου να ρωτήσει αν θα πρέπει να επιτρέψει κάτι ή όχι. Αυτό ιστορικά έχει γίνει abuse στο jailbreaking με την εκτέλεση μιας backdoored έκδοσης του, η οποία θα επέτρεπε τα πάντα.

Στο macOS αυτό βρίσκεται μέσα στο `MobileDevice.framework`.

## AMFI Trust Caches

Τα trust caches δεν είναι μόνο ένα iOS concept. Στο σύγχρονο macOS, ειδικά στο **Apple silicon**, το static trust cache και τα loadable trust caches αποτελούν μέρος της Secure Boot chain. Όταν το **CodeDirectory hash** ενός Mach-O υπάρχει εκεί, το AMFI μπορεί να του αποδώσει **platform privilege** χωρίς να κάνει περαιτέρω authenticity checks κατά το launch time. Αυτό σημαίνει επίσης ότι η Apple μπορεί να κλειδώσει platform binaries σε μια συγκεκριμένη έκδοση OS και να αποτρέψει παλαιότερα Apple-signed binaries από το να επαναχρησιμοποιηθούν σε νεότερα συστήματα.

Σε πρόσφατες εκδόσεις macOS, τα trust-cache metadata συνδέονται επίσης με τα **launch constraints**, οπότε copied system apps και binaries που ξεκινούν από τον λάθος parent/location μπορούν να απορριφθούν από το AMFI ακόμη κι αν είναι ακόμα Apple-signed. Το αναλυτικό extraction και reversing workflow καλύπτεται στο:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Στην έρευνα iOS και jailbreak θα βρείτε ακόμη το παραδοσιακό model των **loadable trust caches** να χρησιμοποιείται για whitelisting ad-hoc signed binaries.

## Αναφορές

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
