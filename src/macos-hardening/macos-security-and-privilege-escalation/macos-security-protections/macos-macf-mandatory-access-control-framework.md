# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Το **MACF** σημαίνει **Mandatory Access Control Framework**, το οποίο είναι ένα σύστημα ασφάλειας ενσωματωμένο στο λειτουργικό σύστημα για να βοηθά στην προστασία του υπολογιστή σου. Λειτουργεί ορίζοντας **αυστηρούς κανόνες για το ποιος ή τι μπορεί να έχει πρόσβαση σε ορισμένα μέρη του συστήματος**, όπως αρχεία, εφαρμογές και πόρους του συστήματος. Επιβάλλοντας αυτούς τους κανόνες αυτόματα, το MACF διασφαλίζει ότι μόνο εξουσιοδοτημένοι χρήστες και διεργασίες μπορούν να εκτελούν συγκεκριμένες ενέργειες, μειώνοντας τον κίνδυνο μη εξουσιοδοτημένης πρόσβασης ή κακόβουλων ενεργειών.

Σημείωσε ότι το MACF στην πραγματικότητα δεν παίρνει αποφάσεις, καθώς απλώς **παρεμβάλλει** ενέργειες, αφήνοντας τις αποφάσεις στα **policy modules** (kernel extensions) που καλεί, όπως τα `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` και `mcxalr.kext`.

- Ένα policy μπορεί να είναι enforcing (return 0 non-zero on some operation)
- Ένα policy μπορεί να είναι monitoring (return 0, so as not to object but piggyback on hook to do something)
- Ένα MACF static policy εγκαθίσταται στο boot και ΔΕΝ θα αφαιρεθεί ΠΟΤΕ
- Ένα MACF dynamic policy εγκαθίσταται από ένα KEXT (kextload) και υποθετικά μπορεί να γίνει kextunloaded
- Στο iOS επιτρέπονται μόνο static policies και στο macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Ροή

1. Process performs a syscall/mach trap
2. Η σχετική function καλείται μέσα στο kernel
3. Η function καλεί MACF
4. Το MACF ελέγχει τα policy modules που ζήτησαν να hookάρουν αυτή τη function στο policy τους
5. Το MACF καλεί τα σχετικά policies
6. Τα policies δείχνουν αν επιτρέπουν ή απορρίπτουν την ενέργεια

> [!CAUTION]
> Μόνο η Apple μπορεί να χρησιμοποιήσει το MAC Framework KPI.

Συνήθως οι functions που ελέγχουν permissions με MACF θα καλούν το macro `MAC_CHECK`. Όπως στην περίπτωση ενός syscall για τη δημιουργία ενός socket, το οποίο θα καλέσει τη function `mac_socket_check_create` που καλεί `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Επιπλέον, το macro `MAC_CHECK` ορίζεται στο security/mac_internal.h ως:
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
Σημειώστε ότι μετατρέποντας το `check` σε `socket_check_create` και τα `args...` σε `(cred, domain, type, protocol)` παίρνετε:
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
Η επέκταση των helper macros αποκαλύπτει τη συγκεκριμένη ροή ελέγχου:
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
Με άλλα λόγια, το `MAC_CHECK(socket_check_create, ...)` διατρέχει πρώτα τις static policies, κάνει conditionally lock και iterates over τις dynamic policies, εκπέμπει τα DTrace probes γύρω από κάθε hook, και συμπτύσσει τον return code κάθε hook στο ενιαίο `error` αποτέλεσμα μέσω του `mac_error_select()`.


### Labels

Το MACF χρησιμοποιεί **labels** τα οποία στη συνέχεια θα χρησιμοποιηθούν από τα policies που ελέγχουν αν πρέπει να παραχωρήσουν κάποια πρόσβαση ή όχι. Ο κώδικας του struct declaration των labels μπορεί να [βρεθεί εδώ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), ο οποίος στη συνέχεια χρησιμοποιείται μέσα στο **`struct ucred`** [**εδώ**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) στο **`cr_label`** μέρος. Το label περιέχει flags και έναν αριθμό από **slots** που μπορούν να χρησιμοποιηθούν από **MACF policies to allocate pointers**. Για παράδειγμα, το Sanbox θα δείχνει στο container profile

## MACF Policies

Ένα MACF Policy ορίζει **κανόνες και συνθήκες που εφαρμόζονται σε συγκεκριμένες kernel operations**.

Ένα kernel extension θα μπορούσε να διαμορφώσει ένα `mac_policy_conf` struct και στη συνέχεια να το register κάνοντας `mac_policy_register`. Από [εδώ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Είναι εύκολο να εντοπίσει κανείς τα kernel extensions που διαμορφώνουν αυτές τις πολιτικές ελέγχοντας κλήσεις στο `mac_policy_register`. Επιπλέον, ελέγχοντας το disassemble του extension είναι επίσης δυνατό να βρεθεί η χρησιμοποιούμενη δομή `mac_policy_conf`.

Σημείωσε ότι οι MACF policies μπορούν να εγγραφούν και να καταργηθούν επίσης **δυναμικά**.

Ένα από τα κύρια πεδία του `mac_policy_conf` είναι το **`mpc_ops`**. Αυτό το πεδίο καθορίζει ποιες operations ενδιαφέρουν την policy. Σημείωσε ότι υπάρχουν εκατοντάδες από αυτές, οπότε είναι δυνατό να μηδενιστούν όλες και μετά να επιλεγούν μόνο εκείνες που ενδιαφέρουν την policy. Από [εδώ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Σχεδόν όλα τα hooks θα καλούνται πίσω από το MACF όταν μία από αυτές τις λειτουργίες παρεμποδίζεται. Ωστόσο, τα **`mpo_policy_*`** hooks αποτελούν εξαίρεση, επειδή το **`mpo_hook_policy_init()`** είναι ένα callback που καλείται κατά το registration (άρα μετά το **`mac_policy_register()`**) και το **`mpo_hook_policy_initbsd()`** καλείται κατά το late registration, αφού το BSD subsystem έχει αρχικοποιηθεί σωστά.

Επιπλέον, το **`mpo_policy_syscall`** hook μπορεί να γίνει register από οποιοδήποτε kext ώστε να εκθέσει ένα ιδιωτικό **ioctl** style call **interface**. Στη συνέχεια, ένα user client θα μπορεί να καλέσει το **`mac_syscall`** (#381) καθορίζοντας ως παραμέτρους το **policy name** με έναν ακέραιο **code** και προαιρετικά **arguments**.\
Για παράδειγμα, το **`Sandbox.kext`** το χρησιμοποιεί πολύ.

Ο έλεγχος του **`__DATA.__const*`** του kext είναι δυνατόν να βοηθήσει στην αναγνώριση της δομής `mac_policy_ops` που χρησιμοποιείται κατά το registration της policy. Είναι δυνατό να βρεθεί επειδή ο pointer της βρίσκεται σε ένα offset μέσα στο `mpo_policy_conf` και επίσης λόγω του αριθμού των NULL pointers που θα υπάρχουν σε εκείνη την περιοχή.

Επιπλέον, είναι επίσης δυνατό να ληφθεί η λίστα των kexts που έχουν ρυθμίσει μια policy κάνοντας dump από τη μνήμη τη δομή **`_mac_policy_list`**, η οποία ενημερώνεται με κάθε policy που γίνεται register.

Θα μπορούσες επίσης να χρησιμοποιήσεις το εργαλείο `xnoop` για να κάνεις dump όλες τις policies που είναι registered στο σύστημα:
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
Και στη συνέχεια κάνε dump όλους τους ελέγχους του check policy με:
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
## MACF initialization in XNU

### Early bootstrap and mac_policy_init()

- Το MACF αρχικοποιείται πολύ νωρίς. Στο `bootstrap_thread` (στο XNU startup code), μετά το `ipc_bootstrap`, το XNU καλεί το `mac_policy_init()` (στο `mac_base.c`).
- Το `mac_policy_init()` αρχικοποιεί το global `mac_policy_list` (έναν πίνακα ή λίστα από policy slots) και στήνει την infrastructure για MAC (Mandatory Access Control) μέσα στο XNU.
- Αργότερα, καλείται το `mac_policy_initmach()`, το οποίο χειρίζεται το kernel side του policy registration για built-in ή bundled policies.

### `mac_policy_initmach()` and loading “security extensions”

- Το `mac_policy_initmach()` εξετάζει kernel extensions (kexts) που είναι preloaded (ή σε μια “policy injection” list) και επιθεωρεί το Info.plist τους για το key `AppleSecurityExtension`.
- Kexts που δηλώνουν `<key>AppleSecurityExtension</key>` (ή `true`) στο Info.plist τους θεωρούνται “security extensions” — δηλαδή αυτά που υλοποιούν μια MAC policy ή κάνουν hook στο MACF infrastructure.
- Παραδείγματα Apple kexts με αυτό το key περιλαμβάνουν **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, μεταξύ άλλων (όπως ήδη ανέφερες).
- Το kernel διασφαλίζει ότι αυτά τα kexts φορτώνονται νωρίς, και μετά καλεί τα registration routines τους (μέσω `mac_policy_register`) κατά το boot, εισάγοντάς τα στο `mac_policy_list`.

- Κάθε policy module (kext) παρέχει μια `mac_policy_conf` δομή, με hooks (`mpc_ops`) για διάφορες MAC operations (vnode checks, exec checks, label updates, κ.λπ.).
- Τα load time flags μπορεί να περιλαμβάνουν το `MPC_LOADTIME_FLAG_NOTLATE`, που σημαίνει “must be loaded early” (άρα απορρίπτονται late registration attempts).
- Μόλις γίνει registration, κάθε module παίρνει ένα handle και καταλαμβάνει ένα slot στο `mac_policy_list`.
- Όταν αργότερα καλείται ένα MAC hook (για παράδειγμα, vnode access, exec, κ.λπ.), το MACF κάνει iterate σε όλες τις registered policies για να λάβει συλλογικές αποφάσεις.

- Συγκεκριμένα, το **AMFI** (Apple Mobile File Integrity) είναι ένα τέτοιο security extension. Το Info.plist του περιλαμβάνει το `AppleSecurityExtension`, που το επισημαίνει ως security policy.
- Ως μέρος του kernel boot, το kernel load logic διασφαλίζει ότι το “security policy” (AMFI, κ.λπ.) είναι ήδη ενεργό πριν εξαρτηθούν από αυτό πολλά subsystems. Για παράδειγμα, ο kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## KPI dependency & com.apple.kpi.dsep in MAC policy kexts

Όταν γράφετε ένα kext που χρησιμοποιεί το MAC framework (δηλαδή καλεί `mac_policy_register()` κ.λπ.), πρέπει να δηλώσετε εξαρτήσεις από KPIs (Kernel Programming Interfaces) ώστε ο kext linker (kxld) να μπορεί να επιλύσει αυτά τα symbols. Επομένως, για να δηλώσετε ότι ένα `kext` εξαρτάται από το MACF, πρέπει να το υποδείξετε στο `Info.plist` με `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), και τότε το kext θα αναφέρεται σε symbols όπως `mac_policy_register`, `mac_policy_unregister`, και MAC hook function pointers. Για να επιλύσετε αυτά, πρέπει να καταγράψετε το `com.apple.kpi.dsep` ως εξάρτηση.

Παράδειγμα snippet του Info.plist (μέσα στο .kext σας):
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
## MACF σε σύγχρονες εκδόσεις macOS

Στο σύγχρονο macOS, οι πολιτικές ασφαλείας της Apple συνήθως δεν προσεγγίζονται καλύτερα ως χαλαρά, αυτόνομα `.kext` bundles. Από το **macOS 11**, τα kernel extensions συνδέονται σε **kernel collections**· στο **Apple Silicon** δεν υπάρχει ξεχωριστό **SystemKC**, και τα third-party kexts γίνονται φορτώσιμα μόνο αφού ενσωματωθούν στο **Auxiliary Kernel Collection (AuxKC)** και γίνει επανεκκίνηση. Για έρευνα MACF αυτό σημαίνει ότι ενσωματωμένες πολιτικές όπως **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ή **Quarantine** συνήθως απαριθμούνται πιο εύκολα με `kmutil` παρά με deprecated εργαλεία όπως το `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Στο Apple Silicon, αν ένα security kext δεν βρίσκεται στο BootKC, έλεγξε το AuxKC στη συνέχεια. Αυτό συνήθως είναι πιο χρήσιμο από το να ψάχνεις για ένα standalone bundle κάτω από `/System/Library/Extensions`.

## MACF Callouts

Είναι συνηθισμένο να βρίσκεις callouts προς MACF ορισμένα σε code όπως: **`#if CONFIG_MAC`** conditional blocks. Επιπλέον, μέσα σε αυτά τα blocks είναι δυνατό να βρεθούν calls προς `mac_proc_check*`, τα οποία καλούν το MACF για να **ελέγξουν permissions** για την εκτέλεση συγκεκριμένων ενεργειών. Επίσης, η μορφή των MACF callouts είναι: **`mac_<object>_<opType>_opName`**.

Το object είναι ένα από τα ακόλουθα: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Το `opType` είναι συνήθως `check`, το οποίο θα χρησιμοποιηθεί για να επιτρέψει ή να απορρίψει την ενέργεια. Ωστόσο, είναι επίσης δυνατό να βρεθεί το `notify`, το οποίο θα επιτρέψει στο kext να αντιδράσει στη δεδομένη ενέργεια.

Μπορείς να βρεις ένα example στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Έπειτα, είναι δυνατό να βρεθεί ο code του `mac_file_check_mmap` στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Το οποίο καλεί το μακρο `MAC_CHECK`, του οποίου ο κώδικας μπορεί να βρεθεί στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Το οποίο θα περάσει από όλες τις εγγεγραμμένες MAC policies καλώντας τις συναρτήσεις τους και αποθηκεύοντας το output μέσα στη μεταβλητή `error`, η οποία θα μπορεί να αντικατασταθεί μόνο από το `mac_error_select` με success codes, οπότε αν οποιοσδήποτε έλεγχος αποτύχει, ο συνολικός έλεγχος θα αποτύχει και η ενέργεια δεν θα επιτραπεί.

> [!TIP]
> Ωστόσο, να θυμάστε ότι δεν χρησιμοποιούνται όλα τα MACF callouts μόνο για να αρνούνται actions. Για παράδειγμα, το `mac_priv_grant` καλεί το macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), το οποίο θα δώσει το ζητούμενο privilege αν οποιοδήποτε policy απαντήσει με 0:
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
>    }); \
> } while (0)
> ```

### priv_check & priv_grant

These callas are meant to check and provide (tens of) **privileges** defined in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Some kernel code would call `priv_check_cred()` from [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) with the KAuth credentials of the process and one of the privileges code which will call `mac_priv_check` to see if any policy **denies** giving the privilege and then it calls `mac_priv_grant` to see if any policy grants the `privilege`.

### proc_check_syscall_unix

This hook allows to intercept all system calls. In `bsd/dev/[i386|arm]/systemcalls.c` it's possible to see the declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), which contains this code:
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
Το οποίο θα ελέγξει στο calling process **bitmask** αν το τρέχον syscall θα πρέπει να καλέσει το `mac_proc_check_syscall_unix`. Αυτό συμβαίνει επειδή τα syscalls καλούνται τόσο συχνά, ώστε είναι ενδιαφέρον να αποφεύγεται η κλήση του `mac_proc_check_syscall_unix` κάθε φορά.

Σημειώστε ότι η συνάρτηση `proc_set_syscall_filter_mask()`, η οποία ορίζει το bitmask των syscalls σε ένα process, καλείται από το Sandbox για να ορίσει masks σε sandboxed processes.

## Exposed MACF syscalls

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
Για offensive reversing, το **`__mac_syscall`** είναι ακόμα ένα από τα καλύτερα userland chokepoints. Μεταφέρει ένα **policy name** (για παράδειγμα `"Sandbox"` ή `"AMFI"`), έναν **policy-specific selector/code**, και έναν δείκτη στο **opaque argument blob** που θα χειριστεί το `mpo_policy_syscall`. Αυτό είναι πολύ χρήσιμο όταν κάνεις reversing undocumented operations από το userland πρώτα και μόνο αργότερα pivoting into the kernel implementation. Το Sandbox συνήθως το προσεγγίζει μέσω του `__sandbox_ms`, και το AMFI χρησιμοποιεί το ίδιο mechanism για dyld policy decisions.

## Πρακτικές σημειώσεις offensive research

Τα πρόσφατα macOS bugs σπάνια "σπάνε το MACF" άμεσα. Αντίθετα, συνήθως abuse μια **desynchronisation μεταξύ ενός MACF / Sandbox / TCC decision και της privileged action που συμβαίνει αργότερα**.

### Broker path checks vs real privileged action

Ένα επαναλαμβανόμενο pattern είναι ένα privileged daemon να κάνει ένα **userland pre-check** (για παράδειγμα `sandbox_check_by_audit_token()`) σε μία έκδοση ενός path, και αργότερα να εκτελεί το πραγματικό privileged sink με ένα **διαφορετικό ή non-canonical attacker-controlled path**. Η πρόσφατη έρευνα σε `diskarbitrationd` / `storagekitd` είναι καλό παράδειγμα: το **directory traversal** plus **symlink swaps** επιτρέπει στον attacker να περάσει το sandbox validation του daemon και μετά να κάνει mount πάνω από sensitive locations όπως `~/Library/Application Support/com.apple.TCC`, μετατρέποντας το bug σε **sandbox escape**, **local privilege escalation** ή **TCC bypass** ανάλογα με το επιλεγμένο mount point.

Όταν κάνεις auditing root brokers που είναι reachable από το sandbox, κάνε πρώτα grep για:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks όπως `mount`, `rename`, `copyfile`, helper-tool XPC methods, ή οτιδήποτε αργότερα αγγίζει attacker-controlled paths ως root

### Trusted deputies with private entitlements

Ένα άλλο πρακτικό pattern είναι να αποφεύγεις να επιτίθεσαι άμεσα στα MACF hooks και αντί να abuse έναν **trusted process** που ήδη έχει τα rights που χρειάζονται για να περάσει το boundary. Η πρόσφατη έρευνα σε Safari/TCC είναι καλό παράδειγμα: το ενδιαφέρον primitive δεν ήταν το "disable TCC in the kernel", αλλά η τροποποίηση της local policy/configuration ώστε ένα Apple-signed process με **`com.apple.private.tcc.allow`** να εκτελεί τη sensitive action για λογαριασμό σου. Στην πράξη, υψηλής αξίας auditing targets είναι Apple daemons/apps που συνδυάζουν:

- **private entitlements** ή FDA-like reach
- ένα writable config / database / mount point / policy file
- μια μεταγενέστερη sensitive operation mediated by **Sandbox**, **AMFI**, **TCC** ή άλλο MACF policy

Για πιο βαθύ product-specific reversing, δες τις dedicated pages στο [macOS Sandbox](macos-sandbox/README.md) και [macOS TCC](macos-tcc/README.md).

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
