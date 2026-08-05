# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το **MACF** σημαίνει **Mandatory Access Control Framework**, ένα σύστημα ασφαλείας ενσωματωμένο στο λειτουργικό σύστημα, το οποίο συμβάλλει στην προστασία του υπολογιστή σας. Λειτουργεί ορίζοντας **αυστηρούς κανόνες σχετικά με το ποιος ή τι μπορεί να έχει πρόσβαση σε συγκεκριμένα τμήματα του συστήματος**, όπως αρχεία, εφαρμογές και πόρους συστήματος. Επιβάλλοντας αυτόματα αυτούς τους κανόνες, το MACF διασφαλίζει ότι μόνο εξουσιοδοτημένοι χρήστες και διεργασίες μπορούν να εκτελούν συγκεκριμένες ενέργειες, μειώνοντας τον κίνδυνο μη εξουσιοδοτημένης πρόσβασης ή κακόβουλων δραστηριοτήτων.

Σημειώστε ότι το MACF στην πραγματικότητα δεν λαμβάνει αποφάσεις, καθώς απλώς **παρεμβάλλεται** στις ενέργειες. Αφήνει τις αποφάσεις στα **policy modules** (επεκτάσεις kernel) που καλεί, όπως τα `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` και `mcxalr.kext`.

- Μια policy μπορεί να επιβάλλει περιορισμούς (να επιστρέφει 0 ή non-zero σε κάποια λειτουργία)
- Μια policy μπορεί να πραγματοποιεί monitoring (να επιστρέφει 0, ώστε να μην προβάλλει αντίρρηση, αλλά να χρησιμοποιεί το hook για να κάνει κάτι)
- Μια στατική policy του MACF εγκαθίσταται κατά την εκκίνηση και δεν θα αφαιρεθεί ΠΟΤΕ
- Μια δυναμική policy του MACF εγκαθίσταται από ένα KEXT (kextload) και θεωρητικά μπορεί να γίνει kextunload
- Στο iOS επιτρέπονται μόνο στατικές policies, ενώ στο macOS επιτρέπονται στατικές + δυναμικές policies.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Ροή

1. Η διεργασία εκτελεί ένα syscall/mach trap
2. Η σχετική συνάρτηση καλείται μέσα στον kernel
3. Η συνάρτηση καλεί το MACF
4. Το MACF ελέγχει τα policy modules που ζήτησαν να κάνουν hook σε αυτήν τη συνάρτηση μέσω της policy τους
5. Το MACF καλεί τις σχετικές policies
6. Οι policies υποδεικνύουν αν επιτρέπουν ή απορρίπτουν την ενέργεια

> [!CAUTION]
> Μόνο η Apple μπορεί να χρησιμοποιήσει το MAC Framework KPI.

Συνήθως, οι συναρτήσεις που ελέγχουν δικαιώματα με το MACF καλούν το macro `MAC_CHECK`. Για παράδειγμα, στην περίπτωση του syscall για τη δημιουργία ενός socket, καλείται η συνάρτηση `mac_socket_check_create`, η οποία καλεί το `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Επιπλέον, το macro `MAC_CHECK` ορίζεται στο security/mac_internal.h ως εξής:<sup>[3]</sup>
```c
Resolver tambien MAC_POLICY_ITERATE, MAC_CHECK_CALL, MAC_CHECK_RSLT


#define MAC_CHECK(check, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_ ## check != NULL) {                   \
MAC_CHECK_CALL(check, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
MAC_CHECK_RSLT(check, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
Σημειώστε ότι μετατρέποντας το `check` σε `socket_check_create` και το `args...` σε `(cred, domain, type, protocol)` λαμβάνετε:
```c
// Note the "##" just get the param name and append it to the prefix
#define MAC_CHECK(socket_check_create, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {                   \
MAC_CHECK_CALL(socket_check_create, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_socket_check_create (args); \
MAC_CHECK_RSLT(socket_check_create, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
Η ανάπτυξη των helper macros αποκαλύπτει τη συγκεκριμένη ροή ελέγχου:
```c
do {                                                // MAC_CHECK
error = 0;
do {                                            // MAC_POLICY_ITERATE
struct mac_policy_conf *mpc;
u_int i;
for (i = 0; i < mac_policy_list.staticmax; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK); // MAC_CHECK_CALL
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);                    // MAC_CHECK_RSLT
error = mac_error_select(__step_err, error);
}
}
if (mac_policy_list_conditional_busy() != 0) {
for (; i <= mac_policy_list.maxindex; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK);
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);
error = mac_error_select(__step_err, error);
}
}
mac_policy_list_unbusy();
}
} while (0);
} while (0);
```
Με άλλα λόγια, το `MAC_CHECK(socket_check_create, ...)` διατρέχει πρώτα τις static policies, κλειδώνει και επαναλαμβάνει υπό συνθήκες τις dynamic policies, εκπέμπει τα DTrace probes γύρω από κάθε hook και συγχωνεύει τον κωδικό επιστροφής κάθε hook στο μοναδικό αποτέλεσμα `error` μέσω της `mac_error_select()`.


### Ετικέτες

Το MACF χρησιμοποιεί **labels**, τις οποίες στη συνέχεια χρησιμοποιούν οι policies για να ελέγξουν αν πρέπει να παραχωρήσουν ή όχι κάποια πρόσβαση. Ο κώδικας της δήλωσης του struct των labels βρίσκεται [εδώ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), και στη συνέχεια χρησιμοποιείται μέσα στο **`struct ucred`** [εδώ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), στο τμήμα **`cr_label`**. Το label περιέχει flags και έναν αριθμό από **slots**, τα οποία μπορούν να χρησιμοποιηθούν από τις **MACF policies για την εκχώρηση pointers**. Για παράδειγμα, το Sandbox θα δείχνει στο container profile.

## MACF Policies

Μια MACF Policy ορίζει **κανόνες και συνθήκες που εφαρμόζονται σε συγκεκριμένες kernel operations**.

Ένα kernel extension μπορεί να διαμορφώσει ένα `mac_policy_conf` struct και στη συνέχεια να το καταχωρίσει καλώντας τη `mac_policy_register`. Από [εδώ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[1]</sup>
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered enty point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better aligment on 64bit platforms */
struct mac_policy_conf {
const char		*mpc_name;		/** policy name */
const char		*mpc_fullname;		/** full name */
const char		**mpc_labelnames;	/** managed label namespaces */
unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
struct mac_policy_ops	*mpc_ops;		/** operation vector */
int			 mpc_loadtime_flags;	/** load time flags */
int			*mpc_field_off;		/** label slot */
int			 mpc_runtime_flags;	/** run time flags */
mpc_t			 mpc_list;		/** List reference */
void			*mpc_data;		/** module data */
};
```
Είναι εύκολο να εντοπιστούν τα kernel extensions που ρυθμίζουν αυτές τις πολιτικές, ελέγχοντας τις κλήσεις στη `mac_policy_register`. Επιπλέον, εξετάζοντας το disassemble του extension, είναι επίσης δυνατό να βρεθεί το χρησιμοποιούμενο struct `mac_policy_conf`.

Σημειώστε ότι οι πολιτικές MACF μπορούν να καταχωρίζονται και να καταργούνται επίσης **δυναμικά**.

Ένα από τα κύρια πεδία του `mac_policy_conf` είναι το **`mpc_ops`**. Αυτό το πεδίο καθορίζει για ποιες λειτουργίες ενδιαφέρεται η πολιτική. Σημειώστε ότι υπάρχουν εκατοντάδες από αυτές, επομένως είναι δυνατό να μηδενιστούν όλες και στη συνέχεια να επιλεγούν μόνο εκείνες για τις οποίες ενδιαφέρεται η πολιτική. Από [εδώ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[1]</sup>
```c
struct mac_policy_ops {
mpo_audit_check_postselect_t		*mpo_audit_check_postselect;
mpo_audit_check_preselect_t		*mpo_audit_check_preselect;
mpo_bpfdesc_label_associate_t		*mpo_bpfdesc_label_associate;
mpo_bpfdesc_label_destroy_t		*mpo_bpfdesc_label_destroy;
mpo_bpfdesc_label_init_t		*mpo_bpfdesc_label_init;
mpo_bpfdesc_check_receive_t		*mpo_bpfdesc_check_receive;
mpo_cred_check_label_update_execve_t	*mpo_cred_check_label_update_execve;
mpo_cred_check_label_update_t		*mpo_cred_check_label_update;
[...]
```
Σχεδόν όλα τα hooks θα καλούνται από το MACF όταν μία από αυτές τις λειτουργίες αναχαιτίζεται. Ωστόσο, τα **`mpo_policy_*`** hooks αποτελούν εξαίρεση, επειδή το `mpo_hook_policy_init()` είναι callback που καλείται κατά την εγγραφή (δηλαδή μετά το `mac_policy_register()`), ενώ το `mpo_hook_policy_initbsd()` καλείται κατά την καθυστερημένη εγγραφή, αφού το υποσύστημα BSD έχει αρχικοποιηθεί σωστά.

Επιπλέον, το **`mpo_policy_syscall`** hook μπορεί να εγγραφεί από οποιοδήποτε kext, ώστε να εκθέσει ένα ιδιωτικό **ioctl** style call **interface**. Στη συνέχεια, ένας user client θα μπορεί να καλέσει το `mac_syscall` (#381), καθορίζοντας ως παραμέτρους το **όνομα της policy**, έναν ακέραιο **κωδικό** και προαιρετικά **ορίσματα**.\
Για παράδειγμα, το **`Sandbox.kext`** το χρησιμοποιεί συχνά.

Εξετάζοντας το **`__DATA.__const*`** του kext, είναι δυνατό να εντοπιστεί η δομή `mac_policy_ops` που χρησιμοποιείται κατά την εγγραφή της policy. Είναι δυνατό να βρεθεί επειδή ο δείκτης της βρίσκεται σε ένα offset μέσα στο `mpo_policy_conf`, καθώς και λόγω του πλήθους των NULL pointers που θα υπάρχουν σε εκείνη την περιοχή.

Επιπλέον, είναι επίσης δυνατό να ληφθεί η λίστα των kexts που έχουν ρυθμίσει μια policy, κάνοντας dump από τη μνήμη της struct **`_mac_policy_list`**, η οποία ενημερώνεται με κάθε policy που εγγράφεται.

Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο `xnoop` για να κάνετε dump όλων των policies που έχουν εγγραφεί στο σύστημα:
```bash
xnoop offline .

Xn👀p> macp
mac_policy_list(@0xfffffff0447159b8): 3 Mac Policies@0xfffffff0447153f0
0: 0xfffffff044886f18:
mpc_name: AppleImage4
mpc_fullName: AppleImage4 hooks
mpc_ops: mac_policy_ops@0xfffffff044886f68
1: 0xfffffff0448d7d40:
mpc_name: AMFI
mpc_fullName: Apple Mobile File Integrity
mpc_ops: mac_policy_ops@0xfffffff0448d72c8
2: 0xfffffff044b0b950:
mpc_name: Sandbox
mpc_fullName: Seatbelt sandbox policy
mpc_ops: mac_policy_ops@0xfffffff044b0b9b0
Xn👀p> dump mac_policy_opns@0xfffffff0448d72c8
Type 'struct mac_policy_opns' is unrecognized - dumping as raw 64 bytes
Dumping 64 bytes from 0xfffffff0448d72c8
```
Και, στη συνέχεια, κάντε dump όλων των checks του check policy με:
```bash
Xn👀p> dump mac_policy_ops@0xfffffff044b0b9b0
Dumping 2696 bytes from 0xfffffff044b0b9b0 (as struct mac_policy_ops)

mpo_cred_check_label_update_execve(@0x30): 0xfffffff046d7fb54(PACed)
mpo_cred_check_label_update(@0x38): 0xfffffff046d7348c(PACed)
mpo_cred_label_associate(@0x58): 0xfffffff046d733f0(PACed)
mpo_cred_label_destroy(@0x68): 0xfffffff046d733e4(PACed)
mpo_cred_label_update_execve(@0x90): 0xfffffff046d7fb60(PACed)
mpo_cred_label_update(@0x98): 0xfffffff046d73370(PACed)
mpo_file_check_fcntl(@0xe8): 0xfffffff046d73164(PACed)
mpo_file_check_lock(@0x110): 0xfffffff046d7309c(PACed)
mpo_file_check_mmap(@0x120): 0xfffffff046d72fc4(PACed)
mpo_file_check_set(@0x130): 0xfffffff046d72f2c(PACed)
mpo_reserved08(@0x168): 0xfffffff046d72e3c(PACed)
mpo_reserved09(@0x170): 0xfffffff046d72e34(PACed)
mpo_necp_check_open(@0x1f0): 0xfffffff046d72d9c(PACed)
mpo_necp_check_client_action(@0x1f8): 0xfffffff046d72cf8(PACed)
mpo_vnode_notify_setextattr(@0x218): 0xfffffff046d72ca4(PACed)
mpo_vnode_notify_setflags(@0x220): 0xfffffff046d72c84(PACed)
mpo_proc_check_get_task_special_port(@0x250): 0xfffffff046d72b98(PACed)
mpo_proc_check_set_task_special_port(@0x258): 0xfffffff046d72ab4(PACed)
mpo_vnode_notify_unlink(@0x268): 0xfffffff046d72958(PACed)
mpo_vnode_check_copyfile(@0x290): 0xfffffff046d726c0(PACed)
mpo_mount_check_quotactl(@0x298): 0xfffffff046d725c4(PACed)
...
```
## Αρχικοποίηση του MACF στο XNU

### Πρώιμη εκκίνηση και mac_policy_init()

- Το MACF αρχικοποιείται πολύ νωρίς. Στο `bootstrap_thread` (στον κώδικα εκκίνησης του XNU), μετά το `ipc_bootstrap`, το XNU καλεί τη `mac_policy_init()` (στο `mac_base.c`).
- Η `mac_policy_init()` αρχικοποιεί την καθολική `mac_policy_list` (έναν πίνακα ή μια λίστα από policy slots) και ρυθμίζει την υποδομή για το MAC (Mandatory Access Control) μέσα στο XNU.
- Αργότερα καλείται η `mac_policy_initmach()`, η οποία διαχειρίζεται την πλευρά του kernel για την καταχώριση policies ενσωματωμένων ή bundled policies.

### `mac_policy_initmach()` και φόρτωση “security extensions”

- Η `mac_policy_initmach()` εξετάζει τα kernel extensions (kexts) που έχουν προφορτωθεί (ή βρίσκονται σε μια λίστα “policy injection”) και ελέγχει το Info.plist τους για το key `AppleSecurityExtension`.
- Τα kexts που δηλώνουν `<key>AppleSecurityExtension</key>` (ή `true`) στο Info.plist τους θεωρούνται “security extensions” — δηλαδή extensions που υλοποιούν ένα MAC policy ή συνδέονται με την υποδομή MACF.
- Παραδείγματα Apple kexts με αυτό το key είναι τα **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, μεταξύ άλλων (όπως ήδη ανέφερες).
- Ο kernel διασφαλίζει ότι αυτά τα kexts φορτώνονται νωρίς και, στη συνέχεια, καλεί τις routines καταχώρισής τους (μέσω της `mac_policy_register`) κατά την εκκίνηση, εισάγοντάς τα στη `mac_policy_list`.

- Κάθε policy module (kext) παρέχει μια δομή `mac_policy_conf`, με hooks (`mpc_ops`) για διάφορες MAC operations (vnode checks, exec checks, ενημερώσεις labels κ.λπ.).
- Τα load time flags μπορεί να περιλαμβάνουν το `MPC_LOADTIME_FLAG_NOTLATE`, που σημαίνει “πρέπει να φορτωθεί νωρίς” (οπότε οι απόπειρες late registration απορρίπτονται).
- Μετά την καταχώρισή του, κάθε module λαμβάνει ένα handle και καταλαμβάνει ένα slot στη `mac_policy_list`.
- Όταν καλείται αργότερα ένα MAC hook (για παράδειγμα, για vnode access, exec κ.λπ.), το MACF επαναλαμβάνει τη διαδικασία για όλα τα καταχωρισμένα policies, ώστε να λάβει συλλογικές αποφάσεις.

- Ειδικότερα, το **AMFI** (Apple Mobile File Integrity) είναι ένα τέτοιο security extension. Το Info.plist του περιλαμβάνει το `AppleSecurityExtension`, χαρακτηρίζοντάς το ως security policy.
- Κατά την εκκίνηση του kernel, η λογική φόρτωσης του kernel διασφαλίζει ότι το “security policy” (AMFI κ.λπ.) είναι ήδη ενεργό πριν εξαρτηθούν από αυτό πολλά subsystems. Για παράδειγμα, ο kernel “προετοιμάζεται για τις επόμενες εργασίες φορτώνοντας … security policy, συμπεριλαμβανομένων των AppleMobileFileIntegrity (AMFI), Sandbox και Quarantine policy.”
```bash
cd /System/Library/Extensions
find . -name Info.plist | xargs grep AppleSecurityExtension 2>/dev/null

./AppleImage4.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./ALF.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./CoreTrust.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleMobileFileIntegrity.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Quarantine.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Sandbox.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleSystemPolicy.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
```
## Εξάρτηση από KPI και com.apple.kpi.dsep σε MAC policy kexts

Όταν γράφετε ένα kext που χρησιμοποιεί το MAC framework (δηλαδή καλεί `mac_policy_register()` κ.λπ.), πρέπει να δηλώσετε εξαρτήσεις από τα KPIs (Kernel Programming Interfaces), ώστε ο linker του kext (kxld) να μπορεί να επιλύσει αυτά τα symbols. Επομένως, για να δηλώσετε ότι ένα `kext` εξαρτάται από το MACF, πρέπει να το υποδείξετε στο `Info.plist` με το `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`). Στη συνέχεια, το kext θα αναφέρεται σε symbols όπως τα `mac_policy_register`, `mac_policy_unregister` και τους MAC hook function pointers. Για να επιλυθούν αυτά, πρέπει να καταχωρίσετε το `com.apple.kpi.dsep` ως dependency.

Παράδειγμα αποσπάσματος `Info.plist` (μέσα στο `.kext` σας):
```xml
<key>OSBundleLibraries</key>
<dict>
<key>com.apple.kpi.dsep</key>
<string>18.0</string>
<key>com.apple.kpi.libkern</key>
<string>18.0</string>
<key>com.apple.kpi.bsd</key>
<string>18.0</string>
<key>com.apple.kpi.mach</key>
<string>18.0</string>
… (other kpi dependencies as needed)
</dict>
```
## MACF σε σύγχρονες εκδόσεις του macOS

Στο σύγχρονο macOS, οι πολιτικές ασφάλειας της Apple συνήθως δεν προσεγγίζονται καλύτερα ως χαλαρά, αυτόνομα bundles `.kext`. Από το **macOS 11**, τα kernel extensions συνδέονται σε **kernel collections**· στο **Apple Silicon** δεν υπάρχει ξεχωριστό **SystemKC**, και τα kexts τρίτων κατασκευαστών μπορούν να φορτωθούν μόνο αφού ενσωματωθούν στο **Auxiliary Kernel Collection (AuxKC)** και γίνει reboot. Για την έρευνα του MACF, αυτό σημαίνει ότι οι ενσωματωμένες πολιτικές, όπως οι **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ή **Quarantine**, συνήθως απαριθμούνται ευκολότερα με το `kmutil` παρά με deprecated εργαλεία όπως το `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Σε Apple Silicon, αν ένα security kext δεν βρίσκεται στο BootKC, ελέγξτε στη συνέχεια το AuxKC. Αυτό είναι συνήθως πιο χρήσιμο από το να αναζητάτε ένα standalone bundle στο `/System/Library/Extensions`.

## MACF Callouts

Είναι σύνηθες να βρίσκετε callouts προς το MACF ορισμένα σε κώδικα, όπως σε conditional blocks τύπου **`#if CONFIG_MAC`**. Επιπλέον, μέσα σε αυτά τα blocks είναι πιθανό να βρείτε κλήσεις προς `mac_proc_check*`, οι οποίες καλούν το MACF για να **ελέγξουν τα permissions** εκτέλεσης συγκεκριμένων ενεργειών. Επιπλέον, η μορφή των MACF callouts είναι: **`mac_<object>_<opType>_opName`**.

Το object είναι ένα από τα εξής: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Το `opType` είναι συνήθως `check`, το οποίο χρησιμοποιείται για να επιτρέψει ή να απορρίψει την ενέργεια. Ωστόσο, είναι επίσης πιθανό να βρείτε `notify`, το οποίο επιτρέπει στο kext να αντιδράσει στη δεδομένη ενέργεια.

Μπορείτε να βρείτε ένα παράδειγμα στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&maxprot);
if (error) {
(void)vnode_put(vp);
goto bad;
}
#endif /* MAC */
[...]
</code></pre>

Στη συνέχεια, είναι δυνατό να βρείτε τον κώδικα του `mac_file_check_mmap` στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
```c
mac_file_check_mmap(struct ucred *cred, struct fileglob *fg, int prot,
int flags, uint64_t offset, int *maxprot)
{
int error;
int maxp;

maxp = *maxprot;
MAC_CHECK(file_check_mmap, cred, fg, NULL, prot, flags, offset, &maxp);
if ((maxp | *maxprot) != *maxprot) {
panic("file_check_mmap increased max protections");
}
*maxprot = maxp;
return error;
}
```
Το οποίο καλεί το macro `MAC_CHECK`, του οποίου ο κώδικας βρίσκεται στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[3]</sup>.
```c
/*
* MAC_CHECK performs the designated check by walking the policy
* module list and checking with each as to how it feels about the
* request.  Note that it returns its value via 'error' in the scope
* of the caller.
*/
#define MAC_CHECK(check, args...) do {                              \
error = 0;                                                      \
MAC_POLICY_ITERATE({                                            \
if (mpc->mpc_ops->mpo_ ## check != NULL) {              \
DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_CHECK); \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_err); \
error = mac_error_select(__step_err, error);         \
}                                                           \
});                                                             \
} while (0)
```
Το οποίο θα περάσει από όλες τις καταχωρισμένες mac policies, καλώντας τις functions τους και αποθηκεύοντας το output μέσα στη μεταβλητή `error`, η οποία μπορεί να αντικατασταθεί από το `mac_error_select` μόνο μέσω success codes. Επομένως, αν οποιοσδήποτε έλεγχος αποτύχει, ο συνολικός έλεγχος θα αποτύχει και η ενέργεια δεν θα επιτραπεί.

> [!TIP]
> Ωστόσο, θυμηθείτε ότι δεν χρησιμοποιούνται όλα τα MACF callouts μόνο για την απόρριψη ενεργειών. Για παράδειγμα, το `mac_priv_grant` καλεί το macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), το οποίο παραχωρεί το ζητούμενο privilege αν οποιαδήποτε policy απαντήσει με 0:
>
> ```c
> /*
> * MAC_GRANT performs the designated check by walking the policy
> * module list and checking with each as to how it feels about the
> * request.  Unlike MAC_CHECK, it grants if any policies return '0',
> * and otherwise returns EPERM.  Note that it returns its value via
> * 'error' in the scope of the caller.
> */
> #define MAC_GRANT(check, args...) do {                              \
>    error = EPERM;                                                  \
>    MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>    });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

Αυτά τα callouts προορίζονται για τον έλεγχο και την παροχή δεκάδων **privileges**, τα οποία ορίζονται στο [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Κάποιος kernel code μπορεί να καλέσει το `priv_check_cred()` από το [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c), χρησιμοποιώντας τα KAuth credentials της process και ένα από τα privilege codes, το οποίο θα καλέσει το `mac_priv_check` για να ελέγξει αν κάποια policy **αρνείται** την παροχή του privilege και στη συνέχεια θα καλέσει το `mac_priv_grant` για να ελέγξει αν κάποια policy παραχωρεί το `privilege`.<sup>[4]</sup>

### proc_check_syscall_unix

Αυτό το hook επιτρέπει την interception όλων των system calls. Στο `bsd/dev/[i386|arm]/systemcalls.c` μπορείτε να δείτε τη δηλωμένη function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), η οποία περιέχει τον εξής κώδικα:
```c
#if CONFIG_MACF
if (__improbable(proc_syscall_filter_mask(proc) != NULL && !bitstr_test(proc_syscall_filter_mask(proc), syscode))) {
error = mac_proc_check_syscall_unix(proc, syscode);
if (error) {
goto skip_syscall;
}
}
#endif /* CONFIG_MACF */
```
Το οποίο θα ελέγξει το **bitmask** στη calling process, για να διαπιστώσει αν το τρέχον syscall πρέπει να καλέσει το `mac_proc_check_syscall_unix`. Αυτό συμβαίνει επειδή τα syscalls καλούνται τόσο συχνά, ώστε είναι χρήσιμο να αποφεύγεται η κλήση του `mac_proc_check_syscall_unix` κάθε φορά.

Σημειώστε ότι η συνάρτηση `proc_set_syscall_filter_mask()`, η οποία ορίζει το bitmask των syscalls σε ένα process, καλείται από το Sandbox για να ορίσει masks σε sandboxed processes.

## Εκτεθειμένα MACF syscalls

Υπάρχει δυνατότητα αλληλεπίδρασης με το MACF μέσω ορισμένων syscalls που ορίζονται στο [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
```c
/*
* Extended non-POSIX.1e interfaces that offer additional services
* available from the userland and kernel MAC frameworks.
*/
#ifdef __APPLE_API_PRIVATE
__BEGIN_DECLS
int      __mac_execve(char *fname, char **argv, char **envv, mac_t _label);
int      __mac_get_fd(int _fd, mac_t _label);
int      __mac_get_file(const char *_path, mac_t _label);
int      __mac_get_link(const char *_path, mac_t _label);
int      __mac_get_pid(pid_t _pid, mac_t _label);
int      __mac_get_proc(mac_t _label);
int      __mac_set_fd(int _fildes, const mac_t _label);
int      __mac_set_file(const char *_path, mac_t _label);
int      __mac_set_link(const char *_path, mac_t _label);
int      __mac_mount(const char *type, const char *path, int flags, void *data,
struct mac *label);
int      __mac_get_mount(const char *path, struct mac *label);
int      __mac_set_proc(const mac_t _label);
int      __mac_syscall(const char *_policyname, int _call, void *_arg);
__END_DECLS
#endif /*__APPLE_API_PRIVATE*/
```
Για το offensive reversing, το **`__mac_syscall`** παραμένει ένα από τα καλύτερα userland chokepoints. Μεταφέρει ένα **policy name** (για παράδειγμα `"Sandbox"` ή `"AMFI"`), έναν **policy-specific selector/code** και έναν pointer στο **opaque argument blob**, το οποίο θα χειριστεί το `mpo_policy_syscall`. Αυτό είναι ιδιαίτερα χρήσιμο κατά το reversing undocumented operations αρχικά από το userland και μόνο αργότερα με pivot στο kernel implementation. Το Sandbox συνήθως το προσεγγίζει μέσω του `__sandbox_ms`, ενώ το AMFI χρησιμοποιεί τον ίδιο μηχανισμό για αποφάσεις policy του dyld.<sup>[2][5]</sup>

## Πρακτικές σημειώσεις offensive research

Τα πρόσφατα macOS bugs σπάνια κάνουν άμεσο "break MACF". Αντίθετα, συνήθως εκμεταλλεύονται έναν **αποσυγχρονισμό μεταξύ μιας απόφασης MACF / Sandbox / TCC και της privileged action που εκτελείται αργότερα**.

### Έλεγχοι paths στο broker έναντι της πραγματικής privileged action

Ένα επαναλαμβανόμενο pattern είναι ένας privileged daemon να εκτελεί ένα **userland pre-check** (για παράδειγμα `sandbox_check_by_audit_token()`) σε μία εκδοχή ενός path και αργότερα να εκτελεί το πραγματικό privileged sink με ένα **διαφορετικό ή μη canonical path που ελέγχεται από τον attacker**. Η πρόσφατη έρευνα για τα `diskarbitrationd` / `storagekitd` αποτελεί καλό παράδειγμα: το **directory traversal** μαζί με **symlink swaps** επιτρέπει στον attacker να περάσει το sandbox validation του daemon και στη συνέχεια να κάνει mount πάνω από ευαίσθητες τοποθεσίες, όπως το `~/Library/Application Support/com.apple.TCC`, μετατρέποντας το bug σε **sandbox escape**, **local privilege escalation** ή **TCC bypass**, ανάλογα με το επιλεγμένο mount point.<sup>[6]</sup>

Κατά τον έλεγχο root brokers που είναι reachable από το sandbox, κάντε πρώτα grep για:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers για path canonicalisation
- privileged sinks όπως `mount`, `rename`, `copyfile`, helper-tool XPC methods ή οτιδήποτε αργότερα αγγίζει attacker-controlled paths ως root

### Trusted deputies με private entitlements

Ένα ακόμη πρακτικό pattern είναι να αποφεύγετε την άμεση επίθεση στα MACF hooks και, αντί γι' αυτό, να εκμεταλλεύεστε μια **trusted process** που διαθέτει ήδη τα δικαιώματα για να περάσει το boundary. Η πρόσφατη έρευνα για Safari/TCC αποτελεί καλό παράδειγμα: το ενδιαφέρον primitive δεν ήταν το "disable TCC in the kernel", αλλά η τροποποίηση της local policy/configuration, ώστε μια Apple-signed process με **`com.apple.private.tcc.allow`** να εκτελεί την ευαίσθητη action για λογαριασμό σας. Στην πράξη, στόχοι υψηλής αξίας για auditing είναι Apple daemons/apps που συνδυάζουν:

- **private entitlements** ή reach παρόμοιο με FDA
- ένα writable config / database / mount point / policy file
- μια μεταγενέστερη ευαίσθητη operation που διαμεσολαβείται από **Sandbox**, **AMFI**, **TCC** ή άλλο MACF policy

Για βαθύτερο product-specific reversing, δείτε τις dedicated σελίδες για [macOS Sandbox](macos-sandbox/README.md) και [macOS TCC](macos-tcc/README.md).

## References

- [1] [XNU — `security/mac_policy.h` (το πλήρες MACF policy operations vector)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (τα macros `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (οι privilege codes που χρησιμοποιούνται από τα `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Αποκάλυψη Apple Vulnerabilities: Audit των diskarbitrationd και storagekitd, Μέρος 2](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
