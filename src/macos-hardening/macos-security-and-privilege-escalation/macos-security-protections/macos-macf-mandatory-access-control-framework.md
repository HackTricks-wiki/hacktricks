# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

**MACF** σημαίνει **Πλαίσιο Υποχρεωτικού Ελέγχου Πρόσβασης (Mandatory Access Control Framework)**, το οποίο είναι ένα σύστημα ασφάλειας ενσωματωμένο στο λειτουργικό σύστημα για να βοηθά στην προστασία του υπολογιστή σας. Λειτουργεί ορίζοντας **αυστηρούς κανόνες για το ποιος ή τι μπορεί να έχει πρόσβαση σε συγκεκριμένα μέρη του συστήματος**, όπως αρχεία, εφαρμογές και πόροι συστήματος. Με την αυτόματη επιβολή αυτών των κανόνων, το MACF εξασφαλίζει ότι μόνο εξουσιοδοτημένοι χρήστες και διαδικασίες μπορούν να εκτελούν συγκεκριμένες ενέργειες, μειώνοντας τον κίνδυνο μη εξουσιοδοτημένης πρόσβασης ή κακόβουλων δραστηριοτήτων.

Σημειώστε ότι το MACF δεν παίρνει πραγματικά αποφάσεις· απλώς **παρεμβάλλεται** στις ενέργειες και αφήνει τις αποφάσεις στις **πολιτικές modules** (kernel extensions) που καλεί, όπως `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` και `mcxalr.kext`.

- Μια πολιτική μπορεί να είναι εφαρμοστική (enforcing) (επιστρέφει μη-μηδενική τιμή σε κάποια λειτουργία)
- Μια πολιτική μπορεί να είναι παρακολουθητική (monitoring) (επιστρέφει 0, ώστε να μην αντιτίθεται αλλά να εκμεταλλεύεται το hook για να κάνει κάτι)
- Μια στατική πολιτική MACF εγκαθίσταται κατά την εκκίνηση και ΔΕΝ θα αφαιρεθεί ΠΟΤΕ
- Μια δυναμική πολιτική MACF εγκαθίσταται από ένα KEXT (kextload) και ενδεχομένως μπορεί να γίνει kextunloaded
- Σε iOS επιτρέπονται μόνο στατικές πολιτικές και σε macOS επιτρέπονται στατικές + δυναμικές.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Ροή

1. Η διαδικασία εκτελεί ένα syscall/mach trap
2. Η σχετική συνάρτηση καλείται μέσα στον kernel
3. Η συνάρτηση καλεί το MACF
4. Το MACF ελέγχει τις πολιτικές modules που ζήτησαν να «hookάρουν» αυτή τη συνάρτηση στην πολιτική τους
5. Το MACF καλεί τις σχετικές πολιτικές
6. Οι πολιτικές υποδεικνύουν αν επιτρέπουν ή απορρίπτουν την ενέργεια

> [!CAUTION]
> Η Apple είναι η μόνη που μπορεί να χρησιμοποιήσει το MAC Framework KPI.

Συνήθως οι συναρτήσεις που ελέγχουν δικαιώματα μέσω του MACF καλούν το macro `MAC_CHECK`. Όπως στην περίπτωση ενός syscall για τη δημιουργία socket το οποίο θα καλέσει τη συνάρτηση `mac_socket_check_create` που καλεί `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Επιπλέον, το macro `MAC_CHECK` ορίζεται στο security/mac_internal.h ως:
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
Σημειώστε ότι μετατρέποντας `check` σε `socket_check_create` και `args...` σε `(cred, domain, type, protocol)` παίρνετε:
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
Η επέκταση των βοηθητικών macros δείχνει τη concrete control flow:
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
Με άλλα λόγια, `MAC_CHECK(socket_check_create, ...)` ελέγχει πρώτα τις στατικές πολιτικές, κλειδώνει υπό όρους και επαναλαμβάνει τις δυναμικές πολιτικές, εκδίδει τα DTrace probes γύρω από κάθε hook, και συγχωνεύει τον κωδικό επιστροφής κάθε hook στο ενιαίο αποτέλεσμα `error` μέσω της `mac_error_select()`.


### Ετικέτες

MACF use **labels** που στη συνέχεια οι πολιτικές ελέγχουν για να αποφασίσουν αν θα χορηγήσουν πρόσβαση ή όχι. The code of the labels struct declaration can be [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), which is then used inside the **`struct ucred`** in [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) in the **`cr_label`** part. Η ετικέτα περιέχει flags και έναν αριθμό από **slots** που μπορούν να χρησιμοποιηθούν από **MACF policies to allocate pointers**. For example Sanbox will point to the container profile

## Πολιτικές MACF

Μια MACF Policy ορίζει **κανόνες και συνθήκες που θα εφαρμοστούν σε ορισμένες λειτουργίες του kernel**.

A kernel extension could configure a `mac_policy_conf` struct and then register it calling `mac_policy_register`. Από [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Είναι εύκολο να εντοπίσετε τις kernel extensions που διαμορφώνουν αυτές τις πολιτικές ελέγχοντας τις κλήσεις στο `mac_policy_register`. Επιπλέον, ελέγχοντας την αποσυναρμολόγηση της επέκτασης, είναι επίσης δυνατό να βρείτε τη χρησιμοποιούμενη δομή `mac_policy_conf`.

Σημειώστε ότι οι πολιτικές MACF μπορούν να εγγραφούν και να αποεγγραφούν επίσης **δυναμικά**.

Ένα από τα κύρια πεδία της `mac_policy_conf` είναι το **`mpc_ops`**. Αυτό το πεδίο καθορίζει ποιες λειτουργίες ενδιαφέρουν την πολιτική. Σημειώστε ότι υπάρχουν εκατοντάδες από αυτές, οπότε είναι δυνατόν να μηδενίσετε όλες και στη συνέχεια να επιλέξετε μόνο αυτές που ενδιαφέρουν την πολιτική. Από [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Σχεδόν όλα τα hooks θα κληθούν από το MACF όταν κάποια από αυτές τις λειτουργίες αναχαιτιστεί. Ωστόσο, τα **`mpo_policy_*`** hooks αποτελούν εξαίρεση επειδή η `mpo_hook_policy_init()` είναι ένα callback που καλείται κατά την εγγραφή (δηλαδή μετά το `mac_policy_register()`) και η `mpo_hook_policy_initbsd()` καλείται κατά την καθυστερημένη εγγραφή όταν το υποσύστημα BSD έχει αρχικοποιηθεί σωστά.

Επιπλέον, το **`mpo_policy_syscall`** hook μπορεί να εγγραφεί από οποιοδήποτε kext για να εκθέσει μια ιδιωτική **ioctl** τύπου κλήσης **διεπαφή**. Στη συνέχεια, ένας user client θα μπορεί να καλέσει το `mac_syscall` (#381) καθορίζοντας ως παραμέτρους το **policy name** με έναν ακέραιο **code** και προαιρετικά **arguments**.\\
Για παράδειγμα, το **`Sandbox.kext`** το χρησιμοποιεί πολύ.

Ελέγχοντας το kext's **`__DATA.__const*`** είναι δυνατό να εντοπιστεί η δομή `mac_policy_ops` που χρησιμοποιείται κατά την εγγραφή της policy. Μπορεί να βρεθεί επειδή ο δείκτης της είναι σε ένα offset μέσα στο `mpo_policy_conf` και επίσης λόγω του πλήθους των NULL pointers που θα υπάρχουν σε αυτή την περιοχή.

Επιπλέον, είναι επίσης δυνατό να ληφθεί η λίστα των kexts που έχουν ρυθμίσει μια policy κάνοντας dump από τη μνήμη της δομής **`_mac_policy_list`** η οποία ενημερώνεται με κάθε policy που εγγράφεται.

Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο `xnoop` για να κάνετε dump όλες τις policies που είναι εγγεγραμμένες στο σύστημα:
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
Και στη συνέχεια dump όλους τους checks της check policy με:
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

### Πρώιμο bootstrap και mac_policy_init()

- Το MACF αρχικοποιείται πολύ νωρίς. Στο `bootstrap_thread` (στον κώδικα εκκίνησης του XNU), μετά το `ipc_bootstrap`, το XNU καλεί το `mac_policy_init()` (στο `mac_base.c`).
- Το `mac_policy_init()` αρχικοποιεί την παγκόσμια `mac_policy_list` (ένας πίνακας ή λίστα θέσεων πολιτικής) και στήνει την υποδομή για το MAC (Mandatory Access Control) μέσα στο XNU.
- Αργότερα, καλείται το `mac_policy_initmach()`, που χειρίζεται το kernel μέρος της εγγραφής πολιτικών για ενσωματωμένες ή παρεχόμενες πολιτικές.

### `mac_policy_initmach()` και φόρτωση “security extensions”

- Το `mac_policy_initmach()` εξετάζει kernel extensions (kexts) που είναι προφορτωμένα (ή σε μια λίστα “policy injection”) και ελέγχει τα Info.plist τους για το κλειδί `AppleSecurityExtension`.
- Τα kexts που δηλώνουν `<key>AppleSecurityExtension</key>` (ή `true`) στο Info.plist τους θεωρούνται “security extensions” — δηλαδή αυτά που υλοποιούν μια MAC policy ή συνδέονται με την υποδομή του MACF.
- Παραδείγματα Apple kexts με αυτό το κλειδί περιλαμβάνουν **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, μεταξύ άλλων (όπως ήδη αναφέρατε).
- Ο kernel διασφαλίζει ότι αυτά τα kexts φορτώνονται νωρίς και στη συνέχεια καλεί τις ρουτίνες εγγραφής τους (μέσω `mac_policy_register`) κατά την εκκίνηση, εισάγοντας τα στην `mac_policy_list`.

- Κάθε module πολιτικής (kext) παρέχει μια δομή `mac_policy_conf`, με hooks (`mpc_ops`) για διάφορες λειτουργίες MAC (έλεγχοι vnode, έλεγχοι exec, ενημερώσεις label, κ.λπ.).
- Τα flags φόρτωσης μπορεί να περιλαμβάνουν το `MPC_LOADTIME_FLAG_NOTLATE` που σημαίνει “πρέπει να φορτωθεί νωρίς” (οπότε οι προσπάθειες καθυστερημένης εγγραφής απορρίπτονται).
- Μόλις εγγραφεί, κάθε module παίρνει ένα handle και καταλαμβάνει μια θέση στην `mac_policy_list`.
- Όταν αργότερα καλείται ένα MAC hook (για παράδειγμα, πρόσβαση vnode, exec, κ.λπ.), το MACF διέρχεται όλες τις εγγεγραμμένες πολιτικές για να λάβει συλλογικές αποφάσεις.

- Ειδικότερα, η **AMFI** (Apple Mobile File Integrity) είναι μια τέτοια security extension. Το Info.plist της περιέχει το `AppleSecurityExtension` που την χαρακτηρίζει ως security policy.
- Στο πλαίσιο της εκκίνησης του kernel, η λογική φόρτωσης του kernel διασφαλίζει ότι η “security policy” (AMFI, κ.λπ.) είναι ήδη ενεργή πριν πολλά υποσυστήματα εξαρτηθούν από αυτήν. Για παράδειγμα, ο kernel “προετοιμάζεται για τις επόμενες εργασίες φορτώνοντας … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## Εξάρτηση KPI & com.apple.kpi.dsep στα MAC policy kexts

Όταν γράφετε ένα kext που χρησιμοποιεί το MAC framework (π.χ. καλώντας `mac_policy_register()` κ.λπ.), πρέπει να δηλώνετε εξαρτήσεις από KPIs (Διεπαφές Προγραμματισμού Πυρήνα) ώστε ο kext linker (kxld) να μπορεί να επιλύσει αυτά τα σύμβολα. Έτσι, για να δηλώσετε ότι ένα `kext` εξαρτάται από MACF, πρέπει να το υποδείξετε στο `Info.plist` με `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`). Το kext θα αναφέρεται σε σύμβολα όπως `mac_policy_register`, `mac_policy_unregister` και δείκτες συναρτήσεων hook του MAC. Για να επιλυθούν αυτά, πρέπει να αναφέρετε `com.apple.kpi.dsep` ως εξάρτηση.

Παράδειγμα αποσπάσματος Info.plist (μέσα στο .kext σας):
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
## Κλήσεις MACF

Συχνά θα βρείτε αναφορές στο MACF ορισμένες στον κώδικα, όπως τα **`#if CONFIG_MAC`** μπλοκ υπό όρους. Επιπλέον, μέσα σε αυτά τα μπλοκ μπορεί να βρείτε κλήσεις σε `mac_proc_check*` που καλούν το MACF για να **ελέγξουν δικαιώματα** προκειμένου να εκτελέσουν ορισμένες ενέργειες. Το φορμά των κλήσεων MACF είναι: **`mac_<object>_<opType>_opName`**.

Το αντικείμενο είναι ένα από τα εξής: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Το `opType` είναι συνήθως check, το οποίο θα χρησιμοποιηθεί για να επιτρέψει ή να αρνηθεί την ενέργεια. Ωστόσο, είναι επίσης πιθανό να βρείτε `notify`, που θα επιτρέψει στο kext να αντιδράσει στην συγκεκριμένη ενέργεια.

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

Κατόπιν, μπορείτε να βρείτε τον κώδικα του `mac_file_check_mmap` στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Το οποίο καλεί το macro `MAC_CHECK`, του οποίου ο κώδικας μπορεί να βρεθεί στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261).
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
Το οποίο θα επεξεργαστεί όλες τις εγγεγραμμένες πολιτικές mac καλώντας τις συναρτήσεις τους και αποθηκεύοντας την έξοδο στη μεταβλητή error, η οποία μπορεί να αντικατασταθεί μόνο από την `mac_error_select` με κωδικούς επιτυχίας — οπότε αν οποιοσδήποτε έλεγχος αποτύχει, ο συνολικός έλεγχος θα αποτύχει και η ενέργεια δεν θα επιτραπεί.

> [!TIP]
> Ωστόσο, θυμηθείτε ότι δεν χρησιμοποιούνται όλα τα MACF callouts αποκλειστικά για να απορρίψουν ενέργειες. Για παράδειγμα, η `mac_priv_grant` καλεί το macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), το οποίο θα χορηγήσει το ζητούμενο privilege αν οποιαδήποτε πολιτική απαντήσει με 0:
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

Αυτές οι κλήσεις προορίζονται να ελέγξουν και να παρέχουν (δεκάδες) **privileges** ορισμένα στο [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Μέρος του kernel κώδικα θα καλούσε την `priv_check_cred()` από [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) με τα KAuth credentials της διεργασίας και έναν από τους κωδικούς privileges, η οποία θα καλούσε την `mac_priv_check` για να δει αν κάποια πολιτική **απορρίπτει** την παροχή του privilege και στη συνέχεια καλεί την `mac_priv_grant` για να δει αν κάποια πολιτική χορηγεί το `privilege`.

### proc_check_syscall_unix

Αυτό το hook επιτρέπει την υποκλοπή όλων των κλήσεων συστήματος. Στο `bsd/dev/[i386|arm]/systemcalls.c` είναι δυνατό να δει κανείς τη δηλωμένη συνάρτηση [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), η οποία περιέχει αυτόν τον κώδικα:
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
Το οποίο θα ελέγξει στο **bitmask** της καλούσας διεργασίας αν το τρέχον syscall πρέπει να καλέσει `mac_proc_check_syscall_unix`. Αυτό συμβαίνει επειδή τα syscalls καλούνται τόσο συχνά που είναι σκόπιμο να αποφεύγεται η κλήση της `mac_proc_check_syscall_unix` κάθε φορά.

Σημειώστε ότι η συνάρτηση `proc_set_syscall_filter_mask()`, που ορίζει το bitmask των syscalls σε μια διεργασία, καλείται από το Sandbox για να θέσει μάσκες σε sandboxed processes.

## Εκτεθειμένα MACF syscalls

Είναι δυνατό να αλληλεπιδράσει κανείς με το MACF μέσω ορισμένων syscalls που ορίζονται στο [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
## Αναφορές

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
