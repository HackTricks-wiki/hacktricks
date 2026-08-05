# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext και amfid

Εστιάζει στην επιβολή της ακεραιότητας του κώδικα που εκτελείται στο σύστημα, παρέχοντας τη λογική πίσω από την επαλήθευση code signature του XNU. Μπορεί επίσης να ελέγχει entitlements και να χειρίζεται άλλες ευαίσθητες εργασίες, όπως την άδεια για debugging ή την απόκτηση task ports.

Επιπλέον, για ορισμένες λειτουργίες, το kext προτιμά να επικοινωνεί με το daemon του user space `/usr/libexec/amfid`. Αυτή η σχέση εμπιστοσύνης έχει γίνει αντικείμενο abuse σε αρκετά jailbreaks.

Σε πρόσφατες εκδόσεις του macOS, το AMFI δεν εκτίθεται πλέον εύκολα ως αυτόνομο on-disk kext, επομένως το reversing συνήθως σημαίνει εργασία από το **kernelcache** ή ένα **KDK**, αντί για περιήγηση στο `/System/Library/Extensions`.

Το AMFI χρησιμοποιεί policies του **MACF** και καταχωρίζει τα hooks του τη στιγμή που εκκινείται. Επίσης, η αποτροπή της φόρτωσης ή η εκφόρτωσή του θα μπορούσε να προκαλέσει kernel panic. Ωστόσο, υπάρχουν ορισμένα boot arguments που επιτρέπουν την απενεργοποίηση του AMFI:

- `amfi_unrestricted_task_for_pid`: Επιτρέπει στο task_for_pid να επιτρέπεται χωρίς τα απαιτούμενα entitlements
- `amfi_allow_any_signature`: Επιτρέπει οποιοδήποτε code signature
- `cs_enforcement_disable`: System-wide argument που χρησιμοποιείται για την απενεργοποίηση της επιβολής code signing
- `amfi_prevent_old_entitled_platform_binaries`: Ακυρώνει platform binaries με entitlements
- `amfi_get_out_of_my_way`: Απενεργοποιεί πλήρως το amfi

Αυτές είναι ορισμένες από τις policies του MACF που καταχωρίζει:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Θα πραγματοποιηθεί ενημέρωση του label και θα επιστραφεί 1
- **`cred_label_associate`**: Ενημερώνει το mac label slot του AMFI με το label
- **`cred_label_destroy`**: Αφαιρεί το mac label slot του AMFI
- **`cred_label_init`**: Μετακινεί το 0 στο mac label slot του AMFI
- **`cred_label_update_execve:`** Ελέγχει τα entitlements της process για να δει αν θα πρέπει να της επιτραπεί να τροποποιήσει τα labels.
- **`file_check_mmap:`** Ελέγχει αν το mmap αποκτά memory και τη θέτει ως executable. Σε αυτή την περίπτωση ελέγχει αν απαιτείται library validation και, αν απαιτείται, καλεί τη library validation function.
- **`file_check_library_validation`**: Καλεί τη library validation function, η οποία ελέγχει, μεταξύ άλλων, αν ένα platform binary φορτώνει άλλο platform binary ή αν η process και το νέο loaded file έχουν το ίδιο TeamID. Ορισμένα entitlements επιτρέπουν επίσης τη φόρτωση οποιασδήποτε library.
- **`policy_initbsd`**: Ρυθμίζει trusted NVRAM Keys
- **`policy_syscall`**: Ελέγχει DYLD policies, όπως αν το binary έχει unrestricted segments και αν θα πρέπει να επιτρέπονται env vars... Καλείται επίσης όταν ξεκινά μια process μέσω της `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Ελέγχει αν, όταν μια process εκτελεί ένα νέο binary, άλλες processes με SEND rights πάνω στο task port της process θα πρέπει να τα διατηρήσουν ή όχι. Τα platform binaries επιτρέπονται, το `get-task-allow` entitlement το επιτρέπει, τα `task_for_pid-allow` entitlements επιτρέπονται και επιτρέπονται binaries με το ίδιο TeamID.
- **`proc_check_expose_task`**: Επιβάλλει τα entitlements
- **`amfi_exc_action_check_exception_send`**: Ένα exception message αποστέλλεται στον debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Κύκλος ζωής του label κατά τον χειρισμό exceptions (debugging)
- **`proc_check_get_task`**: Ελέγχει entitlements όπως το `get-task-allow`, το οποίο επιτρέπει σε άλλες processes να αποκτήσουν το task port, και το `task_for_pid-allow`, το οποίο επιτρέπει στην process να αποκτήσει τα task ports άλλων processes. Αν δεν υπάρχει κανένα από τα δύο, καλεί το `amfid permitunrestricteddebugging` για να ελέγξει αν επιτρέπεται.
- **`proc_check_mprotect`**: Απορρίπτει την κλήση αν το `mprotect` καλείται με το flag `VM_PROT_TRUSTED`, το οποίο υποδεικνύει ότι η περιοχή πρέπει να αντιμετωπίζεται σαν να διαθέτει έγκυρο code signature.
- **`vnode_check_exec`**: Καλείται όταν executable files φορτώνονται στη memory και θέτει τα `cs_hard | cs_kill`, τα οποία θα τερματίσουν την process αν οποιαδήποτε από τις pages καταστεί invalid<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Ελέγχει τα `com.apple.root.installed` και `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Όπως το get + `com.apple.private.allow-bless` και internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Κώδικας που καλεί το XNU για να ελέγξει το code signature χρησιμοποιώντας entitlements, trust cache και το `amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Intercepts κλήσεις `ptrace()` (`PT_ATTACH` και `PT_TRACE_ME`). Ελέγχει για οποιοδήποτε από τα entitlements `get-task-allow`, `run-invalid-allow` και `run-unsigned-code` και, αν δεν υπάρχει κανένα, ελέγχει αν επιτρέπεται το debugging.
- **`proc_check_map_anon`**: Αν κληθεί το mmap με το flag **`MAP_JIT`**, το AMFI θα ελέγξει το `dynamic-codesigning` entitlement.

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

Αυτός είναι ο daemon που εκτελείται σε user mode και τον οποίο το `AMFI.kext` χρησιμοποιεί για να ελέγχει code signatures σε user mode.\
Για να επικοινωνήσει το `AMFI.kext` με τον daemon, χρησιμοποιεί mach messages μέσω του port `HOST_AMFID_PORT`, το οποίο είναι το special port `18`.

Σημειώστε ότι στο macOS δεν είναι πλέον δυνατή η κατάληψη special ports από root processes, καθώς προστατεύονται από το `SIP` και μόνο το launchd μπορεί να τα λάβει. Στο iOS ελέγχεται ότι το process που στέλνει πίσω την απάντηση έχει το CDHash του `amfid` hardcoded.

Μπορείτε να δείτε πότε ζητείται από το `amfid` να ελέγξει ένα binary και την απάντησή του, κάνοντας debugging και ορίζοντας breakpoint στο `mach_msg`.

Μόλις ληφθεί ένα message μέσω του special port, χρησιμοποιείται το **MIG** για την αποστολή κάθε function στη function που καλεί. Οι κύριες functions έγιναν reverse και εξηγήθηκαν μέσα στο βιβλίο.

### Πολιτική DYLD και library validation

Οι πρόσφατες εκδόσεις του `dyld` καλούν το `amfi_check_dyld_policy_self()` πολύ νωρίς από το `configureProcessRestrictions()`, για να ρωτήσουν το AMFI αν το process μπορεί να χρησιμοποιήσει `DYLD_*` path variables, interposing, fallback paths, embedded variables ή να ανεχθεί αποτυχημένο library insertion. Επομένως, κατά την αξιολόγηση ενός injection surface, δεν αρκεί να ελέγχετε μόνο τα Mach-O load commands: πρέπει επίσης να ελέγχετε τα entitlements και τα runtime flags που το AMFI θα μεταφράσει σε πολιτική `dyld`.

Ένας πρακτικός κύκλος triage είναι:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Σε σύγχρονα macOS, πολλά Apple binaries δεν περιέχουν πλέον απευθείας το `com.apple.security.cs.disable-library-validation` και αντ' αυτού αποστέλλονται με το `com.apple.private.security.clear-library-validation`. Σε αυτή την περίπτωση, το library validation δεν απενεργοποιείται κατά το `execve`: η διεργασία πρέπει να καλέσει το `csops(..., CS_OPS_CLEAR_LV, ...)` στον εαυτό της, και το XNU επιτρέπει αυτή τη λειτουργία μόνο στη διεργασία που την καλεί, όταν υπάρχει το entitlement. Από offensive perspective, αυτό έχει σημασία επειδή ένας στόχος μπορεί να γίνει injectable μόνο **αφού** φτάσει στο code path που εκκαθαρίζει ρητά το LV (για παράδειγμα, λίγο πριν φορτώσει optional plugins).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Ένα provisioning profile μπορεί να χρησιμοποιηθεί για την υπογραφή κώδικα. Υπάρχουν **Developer** profiles, τα οποία μπορούν να χρησιμοποιηθούν για την υπογραφή και τη δοκιμή κώδικα, και **Enterprise** profiles, τα οποία μπορούν να χρησιμοποιηθούν σε όλες τις συσκευές.

Αφού μια εφαρμογή υποβληθεί στο Apple Store και εγκριθεί, υπογράφεται από την Apple και το provisioning profile δεν είναι πλέον απαραίτητο.

Ένα profile χρησιμοποιεί συνήθως την επέκταση `.mobileprovision` ή `.provisionprofile` και μπορεί να γίνει dump με:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Παρότι μερικές φορές αναφέρονται ως certificated, αυτά τα provisioning profiles περιέχουν περισσότερα από ένα certificate:

- **AppIDName:** Το Application Identifier
- **AppleInternalProfile**: Καθορίζει ότι πρόκειται για Apple Internal profile
- **ApplicationIdentifierPrefix**: Προστίθεται πριν από το AppIDName (ίδιο με το TeamIdentifier)
- **CreationDate**: Ημερομηνία στη μορφή `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Array από (συνήθως ένα) certificate(s), encoded ως Base64 data
- **Entitlements**: Τα entitlements που επιτρέπονται για αυτό το profile
- **ExpirationDate**: Ημερομηνία λήξης στη μορφή `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Το Application Name, ίδιο με το AppIDName
- **ProvisionedDevices**: Array (για developer certificates) από UDIDs για τα οποία ισχύει αυτό το profile
- **ProvisionsAllDevices**: Boolean (true για enterprise certificates)
- **TeamIdentifier**: Array από (συνήθως ένα) αλφαριθμητικό string που χρησιμοποιείται για την αναγνώριση του developer για σκοπούς inter-app interaction
- **TeamName**: Human-readable όνομα που χρησιμοποιείται για την αναγνώριση του developer
- **TimeToLive**: Ισχύς του certificate (σε ημέρες)
- **UUID**: Ένα Universally Unique Identifier για αυτό το profile
- **Version**: Αυτήν τη στιγμή ορίζεται σε 1

Σημειώστε ότι το entitlements entry περιέχει ένα περιορισμένο σύνολο entitlements και το provisioning profile μπορεί να παρέχει μόνο τα συγκεκριμένα entitlements, ώστε να αποτρέπεται η παροχή Apple private entitlements.

Σημειώστε ότι τα profiles βρίσκονται συνήθως στο `/var/MobileDeviceProvisioningProfiles` και μπορείτε να τα ελέγξετε με **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Αυτή είναι η external library που καλεί το `amfid`, προκειμένου να ζητήσει αν πρέπει να επιτρέψει κάτι ή όχι. Ιστορικά έχει γίνει abuse στο jailbreaking με την εκτέλεση μιας backdoored έκδοσής της, η οποία επέτρεπε τα πάντα.

Στο macOS βρίσκεται μέσα στο `MobileDevice.framework`.

## AMFI Trust Caches

Τα trust caches δεν είναι αποκλειστικά έννοια του iOS. Στα σύγχρονα macOS, ιδιαίτερα στο **Apple silicon**, το static trust cache και τα loadable trust caches αποτελούν μέρος της Secure Boot chain. Όταν το **CodeDirectory hash** ενός Mach-O υπάρχει εκεί, το AMFI μπορεί να του παραχωρήσει **platform privilege** χωρίς να εκτελέσει περαιτέρω authenticity checks κατά το launch. Αυτό σημαίνει επίσης ότι η Apple μπορεί να κλειδώνει τα platform binaries σε συγκεκριμένη έκδοση του OS και να αποτρέπει την επαναχρησιμοποίηση παλαιότερων Apple-signed binaries σε νεότερα συστήματα.<sup>[[6]](#references)</sup>

Σε πρόσφατες εκδόσεις του macOS, τα trust-cache metadata συνδέονται επίσης με **launch constraints**, επομένως τα αντιγραμμένα system apps και binaries που εκκινούνται από λάθος parent/location μπορούν να απορριφθούν από το AMFI, ακόμη και αν παραμένουν Apple-signed. Η αναλυτική διαδικασία extraction και reversing καλύπτεται στο:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Στην έρευνα για iOS και jailbreak θα συνεχίσετε να συναντάτε το παραδοσιακό μοντέλο των **loadable trust caches**, το οποίο χρησιμοποιείται για το whitelisting ad-hoc signed binaries.

## Αναφορές

- [1] [XNU — `security/mac_policy.h` (MACF policy ops που καταχωρίζει το AMFI, συμπεριλαμβανομένου του `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (code-signing flags `CS_*` που ορίζει το AMFI)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (parsing και validation του code-signature blob)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (operations `CS_OPS_*` και `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler των `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
