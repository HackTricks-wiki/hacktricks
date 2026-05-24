# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Το **MACF** σημαίνει **Mandatory Access Control Framework**, και είναι ένα σύστημα ασφάλειας ενσωματωμένο στο λειτουργικό σύστημα για να βοηθά στην προστασία του υπολογιστή σου. Λειτουργεί ορίζοντας **αυστηρούς κανόνες για το ποιος ή τι μπορεί να έχει πρόσβαση σε ορισμένα μέρη του συστήματος**, όπως αρχεία, εφαρμογές και πόρους του συστήματος. Επιβάλλοντας αυτούς τους κανόνες αυτόματα, το MACF διασφαλίζει ότι μόνο εξουσιοδοτημένοι χρήστες και διεργασίες μπορούν να εκτελέσουν συγκεκριμένες ενέργειες, μειώνοντας τον κίνδυνο μη εξουσιοδοτημένης πρόσβασης ή κακόβουλων ενεργειών.

Σημείωσε ότι το MACF στην πραγματικότητα δεν παίρνει αποφάσεις, καθώς απλώς **παρεμποδίζει** ενέργειες· αφήνει τις αποφάσεις στα **policy modules** (kernel extensions) που καλεί, όπως `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` και `mcxalr.kext`.

- Ένα policy μπορεί να είναι enforcing (να επιστρέφει 0 μη μηδενικό σε κάποια λειτουργία)
- Ένα policy μπορεί να είναι monitoring (να επιστρέφει 0, ώστε να μην αντιτίθεται αλλά να χρησιμοποιεί το hook για να κάνει κάτι)
- Ένα MACF static policy εγκαθίσταται στο boot και ΔΕΝ θα αφαιρεθεί ΠΟΤΕ
- Ένα MACF dynamic policy εγκαθίσταται από ένα KEXT (kextload) και θεωρητικά μπορεί να γίνει kextunloaded
- Στο iOS επιτρέπονται μόνο static policies και στο macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Ροή

1. Η διεργασία εκτελεί ένα syscall/mach trap
2. Η σχετική function καλείται μέσα στον kernel
3. Η function καλεί MACF
4. Το MACF ελέγχει policy modules που ζήτησαν να κάνουν hook σε αυτή τη function στο policy τους
5. Το MACF καλεί τα σχετικά policies
6. Τα policies δείχνουν αν επιτρέπουν ή αρνούνται την ενέργεια

> [!CAUTION]
> Η Apple είναι η μόνη που μπορεί να χρησιμοποιήσει το MAC Framework KPI.

Συνήθως οι functions που ελέγχουν permissions με MACF θα καλούν το macro `MAC_CHECK`. Όπως στην περίπτωση syscall για τη δημιουργία ενός socket, που θα καλέσει τη function η οποία `mac_socket_check_create` η οποία καλεί `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Επιπλέον, το macro `MAC_CHECK` ορίζεται στο security/mac_internal.h ως:
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
Σημείωσε ότι μετατρέποντας το `check` σε `socket_check_create` και το `args...` σε `(cred, domain, type, protocol)` παίρνεις:
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
Η επέκταση των βοηθητικών macros δείχνει τη συγκεκριμένη ροή ελέγχου:
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
In other words, `MAC_CHECK(socket_check_create, ...)` περνά πρώτα από τις στατικές policies, κάνει conditionally lock και iterates over τις dynamic policies, emits τα DTrace probes γύρω από κάθε hook, και collapse-άρει τον return code κάθε hook στο ενιαίο αποτέλεσμα `error` μέσω του `mac_error_select()`.


### Labels

Το MACF χρησιμοποιεί **labels** τα οποία στη συνέχεια οι policies που ελέγχουν αν πρέπει να παραχωρήσουν κάποιο access ή όχι θα χρησιμοποιούν. Ο κώδικας της δήλωσης του labels struct μπορεί να [βρεθεί εδώ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), και στη συνέχεια χρησιμοποιείται μέσα στο **`struct ucred`** [**εδώ**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) στο πεδίο **`cr_label`**. Το label περιέχει flags και έναν αριθμό από **slots** που μπορούν να χρησιμοποιηθούν από **MACF policies to allocate pointers**. Για παράδειγμα, το Sanbox θα δείχνει στο container profile

## MACF Policies

Μια MACF Policy ορίζει **rule and conditions to be applied in certain kernel operations**.

Ένα kernel extension θα μπορούσε να ρυθμίσει ένα `mac_policy_conf` struct και στη συνέχεια να το καταχωρίσει καλώντας `mac_policy_register`. Από [εδώ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Είναι εύκολο να εντοπίσετε τα kernel extensions που διαμορφώνουν αυτές τις πολιτικές ελέγχοντας τις κλήσεις προς `mac_policy_register`. Επιπλέον, ελέγχοντας το disassemble του extension είναι επίσης δυνατό να βρείτε το χρησιμοποιούμενο `mac_policy_conf` struct.

Σημειώστε ότι οι MACF policies μπορούν να εγγραφούν και να απεγγραφούν επίσης **δυναμικά**.

Ένα από τα κύρια πεδία του `mac_policy_conf` είναι το **`mpc_ops`**. Αυτό το πεδίο καθορίζει ποιες operations ενδιαφέρουν την policy. Σημειώστε ότι υπάρχουν εκατοντάδες από αυτές, οπότε είναι δυνατό να μηδενίσετε όλες και μετά να επιλέξετε μόνο εκείνες που ενδιαφέρουν την policy. Από [εδώ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Σχεδόν όλα τα hooks θα καλούνται πίσω από το MACF όταν μία από αυτές τις λειτουργίες υποκλαπεί. Ωστόσο, τα **`mpo_policy_*`** hooks αποτελούν εξαίρεση, επειδή το **`mpo_hook_policy_init()`** είναι ένα callback που καλείται κατά την εγγραφή (άρα μετά το `mac_policy_register()`) και το **`mpo_hook_policy_initbsd()`** καλείται κατά την καθυστερημένη εγγραφή, αφού το BSD subsystem έχει αρχικοποιηθεί σωστά.

Επιπλέον, το **`mpo_policy_syscall`** hook μπορεί να εγγραφεί από οποιοδήποτε kext για να εκθέσει ένα ιδιωτικό **ioctl** style call **interface**. Τότε, ένα user client θα μπορεί να καλέσει το `mac_syscall` (#381) καθορίζοντας ως παραμέτρους το **policy name** με έναν ακέραιο **code** και προαιρετικά **arguments**.\
Για παράδειγμα, το **`Sandbox.kext`** το χρησιμοποιεί πολύ συχνά.

Ελέγχοντας το **`__DATA.__const*`** του kext είναι δυνατό να εντοπιστεί το `mac_policy_ops` structure που χρησιμοποιείται κατά την εγγραφή του policy. Είναι δυνατό να βρεθεί επειδή ο pointer του βρίσκεται σε ένα offset μέσα στο `mpo_policy_conf` και επίσης λόγω του αριθμού των NULL pointers που θα υπάρχουν σε εκείνη την περιοχή.

Επιπλέον, είναι επίσης δυνατό να ληφθεί η λίστα των kexts που έχουν διαμορφώσει ένα policy κάνοντας dump από τη μνήμη το struct **`_mac_policy_list`**, το οποίο ενημερώνεται με κάθε policy που εγγράφεται.

Θα μπορούσες επίσης να χρησιμοποιήσεις το εργαλείο `xnoop` για να κάνεις dump όλα τα policies που είναι εγγεγραμμένα στο σύστημα:
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
## Αρχικοποίηση του MACF στο XNU

### Early bootstrap and mac_policy_init()

- Το MACF αρχικοποιείται πολύ νωρίς. Στο `bootstrap_thread` (στο startup code του XNU), μετά το `ipc_bootstrap`, το XNU καλεί το `mac_policy_init()` (στο `mac_base.c`).
- Το `mac_policy_init()` αρχικοποιεί το global `mac_policy_list` (έναν array ή list από policy slots) και ρυθμίζει την infrastructure για το MAC (Mandatory Access Control) μέσα στο XNU.
- Αργότερα, καλείται το `mac_policy_initmach()`, το οποίο χειρίζεται το kernel side του policy registration για built-in ή bundled policies.

### `mac_policy_initmach()` and loading “security extensions”

- Το `mac_policy_initmach()` εξετάζει kernel extensions (kexts) που είναι preloaded (ή σε μια “policy injection” list) και επιθεωρεί το Info.plist τους για το key `AppleSecurityExtension`.
- Τα kexts που δηλώνουν `<key>AppleSecurityExtension</key>` (ή `true`) στο Info.plist τους θεωρούνται “security extensions” — δηλαδή αυτά που υλοποιούν μια MAC policy ή hook into το MACF infrastructure.
- Παραδείγματα Apple kexts με αυτό το key περιλαμβάνουν **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, μεταξύ άλλων (όπως ήδη ανέφερες).
- Το kernel διασφαλίζει ότι αυτά τα kexts φορτώνονται νωρίς, και μετά καλεί τις registration routines τους (μέσω `mac_policy_register`) κατά το boot, εισάγοντάς τα στο `mac_policy_list`.

- Κάθε policy module (kext) παρέχει μια `mac_policy_conf` structure, με hooks (`mpc_ops`) για διάφορες MAC operations (vnode checks, exec checks, label updates, etc.).
- Τα load time flags μπορεί να περιλαμβάνουν `MPC_LOADTIME_FLAG_NOTLATE`, που σημαίνει “must be loaded early” (οπότε οι late registration attempts απορρίπτονται).
- Μόλις γίνει registration, κάθε module παίρνει ένα handle και καταλαμβάνει ένα slot στο `mac_policy_list`.
- Όταν αργότερα κληθεί ένα MAC hook (για παράδειγμα, vnode access, exec, etc.), το MACF κάνει iterate όλα τα registered policies για να λάβει συλλογικές αποφάσεις.

- Συγκεκριμένα, το **AMFI** (Apple Mobile File Integrity) είναι ένα τέτοιο security extension. Το Info.plist του περιλαμβάνει το `AppleSecurityExtension`, σηματοδοτώντας το ως security policy.
- Ως μέρος του kernel boot, το kernel load logic διασφαλίζει ότι η “security policy” (AMFI, etc.) είναι ήδη ενεργή πριν πολλά subsystems βασιστούν σε αυτήν. Για παράδειγμα, το kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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

Όταν γράφεις ένα kext που χρησιμοποιεί το MAC framework (δηλαδή καλεί `mac_policy_register()` κ.λπ.), πρέπει να δηλώσεις εξαρτήσεις από KPIs (Kernel Programming Interfaces) ώστε ο kext linker (kxld) να μπορεί να επιλύσει αυτά τα symbols. Άρα, για να δηλώσεις ότι ένα `kext` εξαρτάται από το MACF, πρέπει να το αναφέρεις στο `Info.plist` με `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), τότε το kext θα αναφέρεται σε symbols όπως `mac_policy_register`, `mac_policy_unregister`, και MAC hook function pointers. Για να τα επιλύσεις αυτά, πρέπει να δηλώσεις το `com.apple.kpi.dsep` ως dependency.

Example Info.plist snippet (inside your .kext):
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

Στο σύγχρονο macOS, οι πολιτικές ασφαλείας της Apple συνήθως δεν είναι καλύτερο να αντιμετωπίζονται ως χαλαρά ανεξάρτητα `.kext` bundles. Από το **macOS 11**, τα kernel extensions συνδέονται σε **kernel collections**· στο **Apple Silicon** δεν υπάρχει ξεχωριστό **SystemKC**, και τα third-party kexts γίνονται loadable μόνο αφού χτιστούν στο **Auxiliary Kernel Collection (AuxKC)** και γίνει επανεκκίνηση. Για έρευνα MACF αυτό σημαίνει ότι οι built-in πολιτικές όπως **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ή **Quarantine** είναι συνήθως ευκολότερο να enumerated με `kmutil` παρά με deprecated tooling όπως το `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Στο Apple Silicon, αν ένα security kext δεν βρίσκεται στο BootKC, έλεγξε στη συνέχεια το AuxKC. Αυτό είναι συνήθως πιο χρήσιμο από το να ψάχνεις για ένα standalone bundle κάτω από `/System/Library/Extensions`.

## MACF Callouts

Είναι συνηθισμένο να βρίσκονται callouts προς το MACF ορισμένα σε code όπως: **`#if CONFIG_MAC`** conditional blocks. Επιπλέον, μέσα σε αυτά τα blocks είναι δυνατό να βρεθούν κλήσεις προς `mac_proc_check*`, οι οποίες καλούν το MACF για να **ελέγξουν δικαιώματα** ώστε να εκτελεστούν συγκεκριμένες actions. Επίσης, η μορφή των MACF callouts είναι: **`mac_<object>_<opType>_opName`**.

Το object είναι ένα από τα εξής: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Το `opType` είναι συνήθως `check`, το οποίο θα χρησιμοποιηθεί για να επιτρέψει ή να απορρίψει την action. Ωστόσο, είναι επίσης δυνατό να βρεθεί το `notify`, το οποίο θα επιτρέψει στο kext να αντιδράσει στη δεδομένη action.

Μπορείς να βρεις ένα παράδειγμα στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Στη συνέχεια, είναι δυνατό να βρεθεί ο code του `mac_file_check_mmap` στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
το οποίο καλεί τη μακροεντολή `MAC_CHECK`, ο κώδικας της οποίας μπορεί να βρεθεί στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Το οποίο θα περάσει από όλες τις καταγεγραμμένες πολιτικές MAC, καλώντας τις συναρτήσεις τους και αποθηκεύοντας το αποτέλεσμα μέσα στη μεταβλητή error, η οποία θα μπορεί να αντικατασταθεί μόνο από το `mac_error_select` με success codes, οπότε αν οποιοσδήποτε έλεγχος αποτύχει, ο πλήρης έλεγχος θα αποτύχει και η ενέργεια δεν θα επιτραπεί.

> [!TIP]
> Ωστόσο, να θυμάστε ότι δεν χρησιμοποιούνται όλα τα MACF callouts μόνο για να αρνούνται ενέργειες. Για παράδειγμα, το `mac_priv_grant` καλεί το macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), το οποίο θα παραχωρήσει το ζητούμενο privilege αν οποιαδήποτε policy απαντήσει με 0:
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

Αυτά τα callas προορίζονται να ελέγχουν και να παρέχουν (δεκάδες) **privileges** που ορίζονται στο [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Κάποιος κώδικας του kernel θα καλούσε το `priv_check_cred()` από το [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) με τα KAuth credentials της διεργασίας και ένα από τα privilege codes, το οποίο θα καλέσει το `mac_priv_check` για να δει αν κάποια policy **αρνείται** την παροχή του privilege και στη συνέχεια καλεί το `mac_priv_grant` για να δει αν κάποια policy παραχωρεί το `privilege`.

### proc_check_syscall_unix

Αυτό το hook επιτρέπει να παρεμβάλλονται όλα τα system calls. Στο `bsd/dev/[i386|arm]/systemcalls.c` είναι δυνατό να δει κανείς τη δηλωμένη συνάρτηση [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), η οποία περιέχει αυτόν τον κώδικα:
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
Το οποίο θα ελέγξει στο **bitmask** της διεργασίας κλήσης αν το τρέχον syscall θα πρέπει να καλέσει `mac_proc_check_syscall_unix`. Αυτό συμβαίνει επειδή τα syscalls καλούνται τόσο συχνά, ώστε είναι ενδιαφέρον να αποφεύγεται η κλήση του `mac_proc_check_syscall_unix` κάθε φορά.

Σημείωσε ότι η συνάρτηση `proc_set_syscall_filter_mask()`, η οποία ορίζει τα syscalls bitmask σε μια διεργασία, καλείται από το Sandbox για να ορίσει masks σε sandboxed διεργασίες.

## Exposed MACF syscalls

Είναι δυνατόν να αλληλεπιδράσεις με το MACF μέσω κάποιων syscalls που ορίζονται στο [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Για offensive reversing, το **`__mac_syscall`** εξακολουθεί να είναι ένα από τα καλύτερα userland chokepoints. Μεταφέρει ένα **policy name** (για παράδειγμα `"Sandbox"` ή `"AMFI"`), έναν **policy-specific selector/code**, και έναν δείκτη στο **opaque argument blob** που θα χειριστεί το `mpo_policy_syscall`. Αυτό είναι πολύ χρήσιμο όταν κάνεις reverse undocumented operations από το userland πρώτα και μόνο αργότερα pivotάρεις στην kernel implementation. Το Sandbox συνήθως φτάνει εκεί μέσω του `__sandbox_ms`, και το AMFI χρησιμοποιεί τον ίδιο μηχανισμό για dyld policy decisions.

## Practical offensive research notes

Recent macOS bugs σπάνια "break MACF" directly. Αντίθετα, συνήθως εκμεταλλεύονται μια **desynchronisation between a MACF / Sandbox / TCC decision and the privileged action that happens later**.

### Broker path checks vs real privileged action

Ένα επαναλαμβανόμενο pattern είναι ένα privileged daemon να εκτελεί έναν **userland pre-check** (για παράδειγμα `sandbox_check_by_audit_token()`) σε μία έκδοση ενός path, και αργότερα να εκτελεί το πραγματικό privileged sink με ένα **διαφορετικό ή non-canonical attacker-controlled path**. Recent `diskarbitrationd` / `storagekitd` research είναι καλό παράδειγμα: **directory traversal** plus **symlink swaps** επιτρέπουν στον attacker να περάσει το sandbox validation του daemon και μετά να κάνει mount πάνω από sensitive locations όπως `~/Library/Application Support/com.apple.TCC`, μετατρέποντας το bug σε **sandbox escape**, **local privilege escalation** ή **TCC bypass** ανάλογα με το επιλεγμένο mount point.

Όταν κάνεις audit root brokers reachable από το sandbox, κάνε πρώτα grep για:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks όπως `mount`, `rename`, `copyfile`, helper-tool XPC methods, ή οτιδήποτε αργότερα αγγίζει attacker-controlled paths ως root

### Trusted deputies with private entitlements

Ένα άλλο πρακτικό pattern είναι να αποφεύγεις το direct attacking των MACF hooks και αντ' αυτού να κάνεις abuse σε ένα **trusted process** που ήδη έχει τα rights που χρειάζονται για να περάσει το boundary. Recent Safari/TCC research είναι καλό παράδειγμα: το ενδιαφέρον primitive δεν ήταν το "disable TCC in the kernel", αλλά η τροποποίηση local policy/configuration ώστε ένα Apple-signed process με **`com.apple.private.tcc.allow`** να εκτελεί το sensitive action εκ μέρους σου. Στην πράξη, υψηλής αξίας auditing targets είναι Apple daemons/apps που συνδυάζουν:

- **private entitlements** ή FDA-like reach
- ένα writable config / database / mount point / policy file
- μια μετέπειτα sensitive operation mediated by **Sandbox**, **AMFI**, **TCC** ή άλλη MACF policy

Για πιο βαθύ product-specific reversing, δες τις dedicated pages στο [macOS Sandbox](macos-sandbox/README.md) και [macOS TCC](macos-tcc/README.md).

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
