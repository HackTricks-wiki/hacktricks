# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext και amfid

Εστιάζει στην επιβολή της ακεραιότητας του κώδικα που εκτελείται στο σύστημα, παρέχοντας τη λογική πίσω από την επαλήθευση υπογραφών κώδικα του XNU. Μπορεί επίσης να ελέγχει entitlements και να χειρίζεται άλλες ευαίσθητες εργασίες, όπως την允许 debugging ή την απόκτηση task ports.

Επιπλέον, για ορισμένες λειτουργίες, το kext προτιμά να επικοινωνεί με το daemon του user space `/usr/libexec/amfid`. Αυτή η σχέση εμπιστοσύνης έχει γίνει αντικείμενο abuse σε αρκετά jailbreaks.

Σε πρόσφατες εκδόσεις του macOS, το AMFI δεν εκτίθεται πλέον με πρακτικό τρόπο ως αυτόνομο on-disk kext, επομένως το reversing συνήθως σημαίνει εργασία από το **kernelcache** ή ένα **KDK**, αντί για περιήγηση στο `/System/Library/Extensions`.

Το AMFI χρησιμοποιεί **MACF** policies και καταχωρίζει τα hooks του τη στιγμή που ξεκινά. Επίσης, η αποτροπή της φόρτωσής του ή η εκφόρτωσή του μπορεί να προκαλέσει kernel panic. Ωστόσο, υπάρχουν ορισμένα boot arguments που επιτρέπουν την απενεργοποίηση του AMFI:

- `amfi_unrestricted_task_for_pid`: Επιτρέπει στο task_for_pid να εκτελείται χωρίς τα απαιτούμενα entitlements
- `amfi_allow_any_signature`: Επιτρέπει οποιαδήποτε code signature
- `cs_enforcement_disable`: Argument σε επίπεδο συστήματος που χρησιμοποιείται για την απενεργοποίηση του code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Ακυρώνει τα platform binaries με entitlements
- `amfi_get_out_of_my_way`: Απενεργοποιεί πλήρως το amfi

Αυτές είναι ορισμένες από τις MACF policies που καταχωρίζει:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Θα πραγματοποιηθεί ενημέρωση του label και θα επιστραφεί 1
- **`cred_label_associate`**: Ενημερώνει το mac label slot του AMFI με το label
- **`cred_label_destroy`**: Αφαιρεί το mac label slot του AMFI
- **`cred_label_init`**: Μετακινεί το 0 στο mac label slot του AMFI
- **`cred_label_update_execve:`** Ελέγχει τα entitlements της διεργασίας για να δει αν πρέπει να της επιτραπεί να τροποποιήσει τα labels.
- **`file_check_mmap:`** Ελέγχει αν το mmap αποκτά μνήμη και τη ρυθμίζει ως executable. Σε αυτή την περίπτωση ελέγχει αν απαιτείται library validation και, αν απαιτείται, καλεί τη library validation function.
- **`file_check_library_validation`**: Καλεί τη library validation function, η οποία ελέγχει, μεταξύ άλλων, αν ένα platform binary φορτώνει άλλο platform binary ή αν η διεργασία και το νέο φορτωμένο αρχείο έχουν το ίδιο TeamID. Ορισμένα entitlements επιτρέπουν επίσης τη φόρτωση οποιασδήποτε library.
- **`policy_initbsd`**: Ρυθμίζει τα trusted NVRAM Keys
- **`policy_syscall`**: Ελέγχει policies του DYLD, όπως αν το binary έχει unrestricted segments και αν πρέπει να επιτρέπονται env vars. Καλείται επίσης όταν μια διεργασία ξεκινά μέσω της `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Ελέγχει αν, όταν μια διεργασία εκτελεί ένα νέο binary, άλλες διεργασίες με SEND rights πάνω στο task port της διεργασίας θα πρέπει να τα διατηρήσουν ή όχι. Τα platform binaries επιτρέπονται, το entitlement `get-task-allow` το επιτρέπει, επιτρέπονται τα entitlements `task_for_pid-allow` και binaries με το ίδιο TeamID.
- **`proc_check_expose_task`**: Επιβάλλει τα entitlements
- **`amfi_exc_action_check_exception_send`**: Ένα exception message αποστέλλεται στον debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Κύκλος ζωής του label κατά τον χειρισμό exception (debugging)
- **`proc_check_get_task`**: Ελέγχει entitlements όπως το `get-task-allow`, το οποίο επιτρέπει σε άλλες διεργασίες να αποκτούν το task port της διεργασίας, και το `task_for_pid-allow`, το οποίο επιτρέπει στη διεργασία να αποκτά τα task ports άλλων διεργασιών. Αν δεν υπάρχει κανένα από τα δύο, καλεί το `amfid permitunrestricteddebugging` για να ελέγξει αν επιτρέπεται.
- **`proc_check_mprotect`**: Απορρίπτει την κλήση αν το `mprotect` χρησιμοποιείται με το flag `VM_PROT_TRUSTED`, το οποίο υποδεικνύει ότι η περιοχή πρέπει να αντιμετωπίζεται σαν να διαθέτει έγκυρη code signature.
- **`vnode_check_exec`**: Καλείται όταν executable files φορτώνονται στη μνήμη και ορίζει τα `cs_hard | cs_kill`, τα οποία θα τερματίσουν τη διεργασία αν οποιαδήποτε από τις σελίδες καταστεί invalid<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: macOS: Ελέγχει το `com.apple.root.installed` και το `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Όπως το get + τα entitlements `com.apple.private.allow-bless` και `internal-installer-equivalent`
- **`vnode_check_signature`**: Κώδικας που καλεί το XNU για να ελέγξει την code signature χρησιμοποιώντας entitlements, trust cache και `amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Intercepts κλήσεις `ptrace()` (`PT_ATTACH` και `PT_TRACE_ME`). Ελέγχει για οποιοδήποτε από τα entitlements `get-task-allow`, `run-invalid-allow` και `run-unsigned-code` και, αν δεν υπάρχει κανένα, ελέγχει αν επιτρέπεται το debugging.
- **`proc_check_map_anon`**: Αν κληθεί το mmap με το flag **`MAP_JIT`**, το AMFI θα ελέγξει το entitlement `dynamic-codesigning`.

Το `AMFI.kext` εκθέτει επίσης ένα API για άλλα kernel extensions και είναι δυνατό να βρεθούν οι dependencies του με:
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

Αυτός είναι ο daemon σε user mode που χρησιμοποιεί το `AMFI.kext` για να ελέγχει τις code signatures σε user mode.\
Για να επικοινωνεί το `AMFI.kext` με τον daemon, χρησιμοποιεί Mach messages μέσω της θύρας `HOST_AMFID_PORT`, η οποία είναι η ειδική θύρα `18`.

Σημειώστε ότι στο macOS δεν είναι πλέον δυνατό για root processes να κάνουν hijack στις special ports, καθώς προστατεύονται από το `SIP` και μόνο το launchd μπορεί να τις αποκτήσει. Στο iOS ελέγχεται ότι το process που στέλνει την απάντηση έχει το CDHash του `amfid` hardcoded.

Μπορείτε να δείτε πότε ζητείται από το `amfid` να ελέγξει ένα binary, καθώς και την απάντησή του, κάνοντας debugging σε αυτό και ορίζοντας breakpoint στο `mach_msg`.

Μόλις ληφθεί ένα message μέσω της special port, χρησιμοποιείται το **MIG** για να στείλει κάθε function στη function που καλεί. Οι κύριες functions έγιναν reverse και εξηγήθηκαν μέσα στο βιβλίο.

### Πολιτική DYLD και library validation

Οι πρόσφατες εκδόσεις του `dyld` καλούν πολύ νωρίς τη `amfi_check_dyld_policy_self()` από τη `configureProcessRestrictions()`, για να ρωτήσουν το AMFI αν το process επιτρέπεται να χρησιμοποιεί `DYLD_*` path variables, interposing, fallback paths, embedded variables ή να ανέχεται αποτυχημένο library insertion. Επομένως, κατά την αξιολόγηση ενός injection surface, δεν αρκεί να εξετάζετε μόνο τα Mach-O load commands: πρέπει επίσης να εξετάζετε τα entitlements και τα runtime flags που το AMFI θα μεταφράσει σε `dyld` policy.

Ένας πρακτικός κύκλος triage είναι:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Σε σύγχρονα macOS πολλά Apple binaries δεν περιλαμβάνουν πλέον απευθείας το `com.apple.security.cs.disable-library-validation` και, αντίθετα, αποστέλλονται με το `com.apple.private.security.clear-library-validation`. Σε αυτή την περίπτωση το library validation δεν απενεργοποιείται κατά το `execve`: η διεργασία πρέπει να καλέσει το `csops(..., CS_OPS_CLEAR_LV, ...)` στον εαυτό της και το XNU επιτρέπει αυτή την ενέργεια μόνο στη διεργασία που την καλεί, όταν υπάρχει το entitlement. Από offensive perspective αυτό έχει σημασία, επειδή ένας στόχος μπορεί να γίνει injectable μόνο **αφού** φτάσει στο code path που εκκαθαρίζει ρητά το LV (για παράδειγμα, λίγο πριν φορτώσει optional plugins).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Ένα provisioning profile μπορεί να χρησιμοποιηθεί για την υπογραφή code. Υπάρχουν **Developer** profiles που μπορούν να χρησιμοποιηθούν για την υπογραφή και τη δοκιμή code, καθώς και **Enterprise** profiles που μπορούν να χρησιμοποιηθούν σε όλες τις συσκευές.

Μετά την υποβολή ενός App στο Apple Store, εάν εγκριθεί, υπογράφεται από την Apple και το provisioning profile δεν είναι πλέον απαραίτητο.

Ένα profile χρησιμοποιεί συνήθως την επέκταση `.mobileprovision` ή `.provisionprofile` και μπορεί να γίνει dump με:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Παρότι μερικές φορές αναφέρονται ως certificates, αυτά τα provisioning profiles περιέχουν περισσότερα από ένα certificate:

- **AppIDName:** Το Application Identifier
- **AppleInternalProfile**: Υποδεικνύει ότι πρόκειται για Apple Internal profile
- **ApplicationIdentifierPrefix**: Προστίθεται πριν από το AppIDName (ίδιο με το TeamIdentifier)
- **CreationDate**: Η ημερομηνία στη μορφή `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Ένας πίνακας από (συνήθως ένα) certificate(s), encoded ως Base64 data
- **Entitlements**: Τα entitlements που επιτρέπονται, μαζί με τα entitlements για αυτό το profile
- **ExpirationDate**: Η ημερομηνία λήξης στη μορφή `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Το Application Name, ίδιο με το AppIDName
- **ProvisionedDevices**: Ένας πίνακας (για developer certificates) από UDIDs για τα οποία ισχύει αυτό το profile
- **ProvisionsAllDevices**: Μια boolean τιμή (true για enterprise certificates)
- **TeamIdentifier**: Ένας πίνακας από (συνήθως ένα) alphanumeric string(s) που χρησιμοποιούνται για την αναγνώριση του developer για σκοπούς inter-app interaction
- **TeamName**: Ένα human-readable όνομα που χρησιμοποιείται για την αναγνώριση του developer
- **TimeToLive**: Η ισχύς (σε ημέρες) του certificate
- **UUID**: Ένα Universally Unique Identifier για αυτό το profile
- **Version**: Αυτήν τη στιγμή έχει την τιμή 1

Σημειώστε ότι το entitlements entry θα περιέχει ένα περιορισμένο σύνολο από entitlements και το provisioning profile θα μπορεί να παρέχει μόνο τα συγκεκριμένα entitlements, ώστε να αποτρέπεται η παροχή private entitlements της Apple.

Σημειώστε ότι τα profiles συνήθως βρίσκονται στο `/var/MobileDeviceProvisioningProfiles` και μπορείτε να τα ελέγξετε με το **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Αυτή είναι η external library που καλεί το `amfid` για να ρωτήσει αν πρέπει να επιτρέψει κάτι ή όχι. Ιστορικά έχει γίνει abuse στο jailbreaking με την εκτέλεση μιας backdoored έκδοσής της, η οποία επέτρεπε τα πάντα.

Στο macOS βρίσκεται μέσα στο `MobileDevice.framework`.

## AMFI Trust Caches

Τα Trust Caches δεν είναι αποκλειστικά concept του iOS. Στα σύγχρονα macOS, ειδικά σε **Apple silicon**, το static trust cache και τα loadable trust caches αποτελούν μέρος της Secure Boot chain. Όταν το **CodeDirectory hash** ενός Mach-O υπάρχει εκεί, το AMFI μπορεί να του εκχωρήσει **platform privilege** χωρίς να πραγματοποιήσει περαιτέρω authenticity checks κατά το launch time. Αυτό σημαίνει επίσης ότι η Apple μπορεί να κλειδώνει τα platform binaries σε συγκεκριμένη έκδοση του OS και να αποτρέπει την επαναχρησιμοποίηση παλαιότερων Apple-signed binaries σε νεότερα συστήματα.<sup>[[6]](#references)</sup>

Σε πρόσφατες εκδόσεις του macOS, τα trust-cache metadata συνδέονται επίσης με **launch constraints**, επομένως τα copied system apps και binaries που ξεκινούν από λάθος parent/location μπορούν να απορριφθούν από το AMFI, ακόμη και αν εξακολουθούν να είναι Apple-signed. Η λεπτομερής διαδικασία extraction και reversing καλύπτεται στο:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Στο iOS και στο jailbreak research θα συνεχίσετε να συναντάτε το παραδοσιακό μοντέλο των **loadable trust caches**, το οποίο χρησιμοποιείται για whitelist ad-hoc signed binaries.

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
