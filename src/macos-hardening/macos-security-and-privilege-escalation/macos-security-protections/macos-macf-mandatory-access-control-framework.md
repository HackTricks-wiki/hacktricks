# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

**MACF** σημαίνει **Mandatory Access Control Framework**, που είναι ένα σύστημα ασφάλειας ενσωματωμένο στο λειτουργικό σύστημα για να βοηθά στην προστασία του υπολογιστή σας. Λειτουργεί θέτοντας **αυστηρούς κανόνες σχετικά με το ποιος ή τι μπορεί να έχει πρόσβαση σε ορισμένα μέρη του συστήματος**, όπως αρχεία, εφαρμογές και πόροι συστήματος. Εφαρμόζοντας αυτούς τους κανόνες αυτόματα, το MACF διασφαλίζει ότι μόνο εξουσιοδοτημένοι χρήστες και διεργασίες μπορούν να εκτελέσουν συγκεκριμένες ενέργειες, μειώνοντας τον κίνδυνο μη εξουσιοδοτημένης πρόσβασης ή κακόβουλων δραστηριοτήτων.

Σημειώστε ότι το MACF δεν παίρνει πραγματικές αποφάσεις· απλώς **παρεμβάλλεται** στις ενέργειες και αφήνει τις αποφάσεις στις **policy modules** (kernel extensions) που καλεί, όπως `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` και `mcxalr.kext`.

- Μια πολιτική μπορεί να είναι enforcing (επιστρέφει 0 ή μη μηδενική τιμή σε κάποια λειτουργία)
- Μια πολιτική μπορεί να είναι monitoring (επιστρέφει 0, ώστε να μη διαφωνεί αλλά να εκμεταλλεύεται το hook για να κάνει κάτι)
- Μια στατική πολιτική MACF εγκαθίσταται κατά την εκκίνηση και ΔΕΝ θα αφαιρεθεί ΠΟΤΕ
- Μια δυναμική πολιτική MACF εγκαθίσταται από ένα KEXT (kextload) και υποθετικά μπορεί να γίνει kextunloaded
- Στο iOS επιτρέπονται μόνο στατικές πολιτικές και στο macOS στατικές + δυναμικές.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Ροή

1. Η διεργασία εκτελεί ένα syscall/mach trap
2. Η σχετική συνάρτηση καλείται μέσα στον kernel
3. Η συνάρτηση καλεί το MACF
4. Το MACF ελέγχει τα policy modules που ζήτησαν να συσχετίσουν (hook) αυτή τη συνάρτηση στην πολιτική τους
5. Το MACF καλεί τις σχετικές πολιτικές
6. Οι πολιτικές υποδεικνύουν αν επιτρέπουν ή αρνούνται τη δράση

> [!CAUTION]
> Apple είναι η μόνη που μπορεί να χρησιμοποιήσει το MAC Framework KPI.

Συνήθως οι συναρτήσεις που ελέγχουν δικαιώματα με MACF καλούν το macro `MAC_CHECK`. Όπως στην περίπτωση ενός syscall για τη δημιουργία ενός socket που θα καλέσει τη συνάρτηση `mac_socket_check_create` η οποία καλεί `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Επιπλέον, το macro `MAC_CHECK` ορίζεται στο security/mac_internal.h ως:
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
Σημειώστε ότι, μετατρέποντας το `check` σε `socket_check_create` και το `args...` σε `(cred, domain, type, protocol)`, παίρνετε:
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
Η επέκταση των helper macros δείχνει τη συγκεκριμένη ροή ελέγχου:
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
Με άλλα λόγια, `MAC_CHECK(socket_check_create, ...)` διασχίζει πρώτα τις στατικές πολιτικές, κλειδώνει υπό όρους και επαναλαμβάνει τις δυναμικές πολιτικές, εκπέμπει τα DTrace probes γύρω από κάθε hook, και συγχωνεύει τον κωδικό επιστροφής κάθε hook στο ενιαίο αποτέλεσμα `error` μέσω `mac_error_select()`.


### Labels

MACF use **labels** που στη συνέχεια θα χρησιμοποιηθούν από τις πολιτικές όταν ελέγχουν αν πρέπει να χορηγήσουν κάποια πρόσβαση ή όχι. The code of the labels struct declaration can be [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), which is then used inside the **`struct ucred`** in [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) in the **`cr_label`** part. Η label περιέχει flags και έναν αριθμό **slots** που μπορούν να χρησιμοποιηθούν από **MACF policies to allocate pointers**. Για παράδειγμα Sanbox θα δείχνει στο container profile

## MACF Policies

Μια MACF Policy ορίζει κανόνες και προϋποθέσεις που εφαρμόζονται σε συγκεκριμένες λειτουργίες του kernel.

Μια επέκταση του kernel θα μπορούσε να διαμορφώσει μια δομή `mac_policy_conf` και στη συνέχεια να την καταχωρίσει καλώντας `mac_policy_register`. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Είναι εύκολο να εντοπίσεις τις επεκτάσεις του kernel που διαμορφώνουν αυτές τις πολιτικές ελέγχοντας τις κλήσεις προς `mac_policy_register`. Επιπλέον, ελέγχοντας την αποσυναρμολόγηση της επέκτασης, είναι επίσης δυνατό να βρεις την χρησιμοποιούμενη δομή `mac_policy_conf`.

Σημείωση ότι οι πολιτικές MACF μπορούν επίσης να καταχωρούνται και να καταργούνται **δυναμικά**.

Ένα από τα κύρια πεδία της `mac_policy_conf` είναι το **`mpc_ops`**. Αυτό το πεδίο προσδιορίζει ποιες λειτουργίες ενδιαφέρουν την πολιτική. Σημείωσε ότι υπάρχουν εκατοντάδες από αυτές, οπότε είναι δυνατόν να μηδενίσεις όλες και μετά να επιλέξεις μόνο αυτές που ενδιαφέρουν την πολιτική. Από [εδώ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Σχεδόν όλα τα hooks θα κληθούν πίσω από το MACF όταν κάποια από αυτές τις λειτουργίες παρεμποδίζεται. Ωστόσο, τα **`mpo_policy_*`** hooks αποτελούν εξαίρεση επειδή η `mpo_hook_policy_init()` είναι callback που καλείται κατά την εγγραφή (δηλαδή μετά το `mac_policy_register()`) και η `mpo_hook_policy_initbsd()` καλείται κατά την μεταγενέστερη εγγραφή μόλις το BSD subsystem έχει αρχικοποιηθεί σωστά.

Επιπλέον, το **`mpo_policy_syscall`** hook μπορεί να εγγραφεί από οποιοδήποτε kext για να εκθέσει μια ιδιωτική **ioctl** style call **interface**. Τότε, ένας user client θα είναι σε θέση να καλέσει την `mac_syscall` (#381) καθορίζοντας ως παραμέτρους το **policy name** με έναν ακέραιο **code** και προαιρετικά **arguments**.\
Για παράδειγμα, το **`Sandbox.kext`** χρησιμοποιεί αυτό πολύ.

Ελέγχοντας το kext's **`__DATA.__const*`** είναι δυνατόν να εντοπιστεί η δομή `mac_policy_ops` που χρησιμοποιείται κατά την εγγραφή της policy. Μπορεί να βρεθεί επειδή ο δείκτης της βρίσκεται σε ένα offset μέσα στο `mpo_policy_conf` και επίσης λόγω του αριθμού των NULL pointers που θα υπάρχουν σε αυτή την περιοχή.

Επιπλέον, είναι επίσης δυνατόν να ληφθεί η λίστα των kexts που έχουν διαμορφώσει μια policy εξάγοντας από τη μνήμη τη δομή **`_mac_policy_list`**, η οποία ενημερώνεται με κάθε policy που εγγράφεται.

Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο `xnoop` για να εξάγετε όλες τις policies που έχουν εγγραφεί στο σύστημα:
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
Και στη συνέχεια εξάγετε όλους τους ελέγχους του check policy με:
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

### Πρώιμη εκκίνηση (bootstrap) και mac_policy_init()

- Το MACF αρχικοποιείται πολύ νωρίς. Στο `bootstrap_thread` (στον κώδικα εκκίνησης του XNU), μετά το `ipc_bootstrap`, το XNU καλεί το `mac_policy_init()` (στο `mac_base.c`).
- Το `mac_policy_init()` αρχικοποιεί την παγκόσμια `mac_policy_list` (ένας πίνακας ή λίστα με θέσεις πολιτικών) και στήνει την υποδομή για το MAC (Υποχρεωτικός Έλεγχος Πρόσβασης) μέσα στο XNU.
- Αργότερα καλείται το `mac_policy_initmach()`, που χειρίζεται το kernel-μέρος της καταχώρησης πολιτικών για ενσωματωμένες ή παρεχόμενες (bundled) πολιτικές.

### `mac_policy_initmach()` και φόρτωση “επεκτάσεων ασφαλείας”

- Το `mac_policy_initmach()` εξετάζει kernel extensions (kexts) που είναι προφορτωμένα (ή σε μια λίστα “policy injection”) και ελέγχει το Info.plist τους για το κλειδί `AppleSecurityExtension`.
- Τα kexts που δηλώνουν `<key>AppleSecurityExtension</key>` (ή `true`) στο Info.plist τους θεωρούνται “security extensions” — δηλαδή αυτά που υλοποιούν μια πολιτική MAC ή συνδέονται στην υποδομή MACF.
- Παραδείγματα Apple kexts με αυτό το κλειδί περιλαμβάνουν **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, μεταξύ άλλων (όπως ήδη αναφέρατε).
- Ο kernel διασφαλίζει ότι αυτά τα kexts φορτώνονται νωρίς, και στη συνέχεια καλεί τις ρουτίνες καταχώρησής τους (μέσω `mac_policy_register`) κατά την εκκίνηση, εισάγοντάς τα στην `mac_policy_list`.

- Κάθε module πολιτικής (kext) παρέχει μια δομή `mac_policy_conf`, με hooks (`mpc_ops`) για διάφορες λειτουργίες MAC (έλεγχοι vnode, έλεγχοι exec, ενημερώσεις ετικετών, κ.λπ.).
- Τα flags χρόνου φόρτωσης μπορεί να περιλαμβάνουν το `MPC_LOADTIME_FLAG_NOTLATE`, που σημαίνει «πρέπει να φορτωθεί νωρίς» (οπότε οι προσπάθειες καθυστερημένης καταχώρησης απορρίπτονται).
- Μόλις καταχωρηθεί, κάθε module λαμβάνει ένα handle και καταλαμβάνει μια θέση στην `mac_policy_list`.
- Όταν ένα MAC hook καλείται αργότερα (για παράδειγμα, πρόσβαση vnode, exec, κ.λπ.), το MACF επαναλαμβάνει όλες τις καταχωρημένες πολιτικές για να λάβει συλλογικές αποφάσεις.

- Συγκεκριμένα, το **AMFI** (Apple Mobile File Integrity) είναι τέτοια μια επέκταση ασφαλείας. Το Info.plist του περιλαμβάνει το `AppleSecurityExtension` που το χαρακτηρίζει ως security policy.
- Ως μέρος της εκκίνησης του kernel, η λογική φόρτωσης διασφαλίζει ότι η «πολιτική ασφαλείας» (AMFI, κ.λπ.) είναι ήδη ενεργή πριν πολλά υποσυστήματα εξαρτηθούν από αυτήν. Για παράδειγμα, ο kernel «προετοιμάζεται για τις εργασίες φορτώνοντας … πολιτικές ασφαλείας, συμπεριλαμβανομένων των AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine.»
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
## Εξάρτηση KPI & com.apple.kpi.dsep σε MAC policy kexts

Όταν γράφετε ένα kext που χρησιμοποιεί το MAC framework (π.χ. καλώντας `mac_policy_register()` κ.λπ.), πρέπει να δηλώσετε εξαρτήσεις από KPIs (Kernel Programming Interfaces) ώστε ο linker του kext (kxld) να μπορεί να επιλύσει αυτά τα σύμβολα. Έτσι, για να δηλώσετε ότι ένα `kext` εξαρτάται από το MACF πρέπει να το υποδείξετε στο `Info.plist` με `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), τότε το kext θα αναφέρεται σε σύμβολα όπως `mac_policy_register`, `mac_policy_unregister`, και δείκτες συναρτήσεων hook του MAC. Για να επιλυθούν αυτά, πρέπει να καταχωρήσετε το `com.apple.kpi.dsep` ως εξάρτηση.
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

Είναι συνηθισμένο να βρίσκει κανείς αναφορές στο MACF ορισμένες στον κώδικα μέσα σε μπλοκ υπό συνθήκη όπως: **`#if CONFIG_MAC`**. Επιπλέον, μέσα σε αυτά τα μπλοκ μπορεί να βρει κανείς κλήσεις σε `mac_proc_check*` που καλούν το MACF για να **ελέγξουν τα δικαιώματα** για την εκτέλεση ορισμένων ενεργειών. Επιπλέον, η μορφή των κλήσεων MACF είναι: **`mac_<object>_<opType>_opName`**.

Το αντικείμενο είναι ένα από τα εξής: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Το `opType` είναι συνήθως check που θα χρησιμοποιηθεί για να επιτρέψει ή να αρνηθεί τη δράση. Ωστόσο, είναι επίσης πιθανό να βρεθεί `notify`, το οποίο θα επιτρέψει στο kext να αντιδράσει στην εν λόγω ενέργεια.

You can find an example in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Στη συνέχεια, είναι δυνατόν να βρείτε τον κώδικα της `mac_file_check_mmap` στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Το οποίο καλεί το `MAC_CHECK` macro, του οποίου ο κώδικας μπορεί να βρεθεί στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Αυτό θα διατρέξει όλες τις καταγεγραμμένες πολιτικές mac καλώντας τις συναρτήσεις τους και αποθηκεύοντας την έξοδο μέσα στη μεταβλητή error, η οποία θα μπορεί να υπερισχύσει μόνο από το `mac_error_select` με κωδικούς επιτυχίας — οπότε αν οποιοςδήποτε έλεγχος αποτύχει, ο συνολικός έλεγχος θα αποτύχει και η ενέργεια δεν θα επιτραπεί.

> [!TIP]
> Ωστόσο, να θυμάστε ότι όχι όλα τα MACF callouts χρησιμοποιούνται μόνο για να απορρίψουν ενέργειες. Για παράδειγμα, `mac_priv_grant` καλεί τη macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), η οποία θα χορηγήσει το ζητούμενο privilege αν κάποια πολιτική απαντήσει με 0:
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

Αυτές οι κλήσεις προορίζονται να ελέγξουν και να παρέχουν (δεκάδες) **privileges** που ορίζονται στο [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Κάποιος κώδικας του kernel θα καλούσε το `priv_check_cred()` από [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) με τα KAuth credentials της διεργασίας και έναν από τους κωδικούς privileges, ο οποίος θα καλεί το `mac_priv_check` για να δει αν κάποια πολιτική **απαγορεύει** τη χορήγηση του `privilege` και μετά θα καλεί το `mac_priv_grant` για να δει αν κάποια πολιτική χορηγεί το `privilege`.

### proc_check_syscall_unix

Αυτό το hook επιτρέπει την παρεμβολή σε όλες τις system calls. Στο `bsd/dev/[i386|arm]/systemcalls.c` είναι δυνατό να δει κανείς τη δηλωμένη συνάρτηση [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), η οποία περιέχει αυτόν τον κώδικα:
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
Το οποίο θα ελέγξει στο **bitmask** της διαδικασίας που καλεί αν το τρέχον syscall θα πρέπει να καλέσει `mac_proc_check_syscall_unix`. Αυτό συμβαίνει επειδή τα syscalls καλούνται τόσο συχνά που είναι ενδιαφέρον να αποφευχθεί η κλήση του `mac_proc_check_syscall_unix` κάθε φορά.

Σημειώστε ότι η συνάρτηση `proc_set_syscall_filter_mask()`, που θέτει το bitmask των syscalls σε μια διαδικασία, καλείται από το Sandbox για να θέσει μάσκες σε διαδικασίες που βρίσκονται σε sandbox.

## Εκτεθειμένα MACF syscalls

Είναι δυνατό να αλληλεπιδράσετε με το MACF μέσω ορισμένων syscalls που ορίζονται στο [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
