# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το **MACF** σημαίνει **Mandatory Access Control Framework** και είναι ένα σύστημα ασφάλειας ενσωματωμένο στο λειτουργικό σύστημα, το οποίο συμβάλλει στην προστασία του υπολογιστή σας. Λειτουργεί θέτοντας **αυστηρούς κανόνες σχετικά με το ποιος ή τι μπορεί να έχει πρόσβαση σε συγκεκριμένα τμήματα του συστήματος**, όπως αρχεία, εφαρμογές και πόρους συστήματος. Επιβάλλοντας αυτόματα αυτούς τους κανόνες, το MACF διασφαλίζει ότι μόνο εξουσιοδοτημένοι χρήστες και διεργασίες μπορούν να εκτελούν συγκεκριμένες ενέργειες, μειώνοντας τον κίνδυνο μη εξουσιοδοτημένης πρόσβασης ή κακόβουλης δραστηριότητας.

Σημειώστε ότι το MACF δεν λαμβάνει στην πραγματικότητα αποφάσεις, καθώς απλώς **παρεμβάλλεται** στις ενέργειες. Αφήνει τις αποφάσεις στις **μονάδες πολιτικής** (επεκτάσεις πυρήνα) που καλεί, όπως οι `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` και `mcxalr.kext`.

- Μια πολιτική μπορεί να επιβάλλεται (να επιστρέφει 0 ή μη μηδενική τιμή σε κάποια λειτουργία)
- Μια πολιτική μπορεί να παρακολουθεί (να επιστρέφει 0, ώστε να μην προβάλλει αντίρρηση, αλλά να αξιοποιεί το hook για να κάνει κάτι)
- Μια στατική πολιτική MACF εγκαθίσταται κατά την εκκίνηση και δεν αφαιρείται ΠΟΤΕ
- Μια δυναμική πολιτική MACF εγκαθίσταται από ένα KEXT (`kextload`) και θεωρητικά μπορεί να αποφορτωθεί με `kextunload`
- Στο iOS επιτρέπονται μόνο στατικές πολιτικές, ενώ στο macOS επιτρέπονται στατικές και δυναμικές.<sup>[[7]](#references)</sup>

### Ροή

1. Η διεργασία εκτελεί ένα syscall/mach trap
2. Καλείται η σχετική συνάρτηση μέσα στον πυρήνα
3. Η συνάρτηση καλεί το MACF
4. Το MACF ελέγχει τις μονάδες πολιτικής που ζήτησαν να προσθέσουν hook σε αυτήν τη συνάρτηση μέσω της πολιτικής τους
5. Το MACF καλεί τις σχετικές πολιτικές
6. Οι πολιτικές υποδεικνύουν αν επιτρέπουν ή αρνούνται την ενέργεια

> [!CAUTION]
> Μόνο η Apple μπορεί να χρησιμοποιήσει το MAC Framework KPI.

Συνήθως, οι συναρτήσεις που ελέγχουν τα δικαιώματα μέσω του MACF καλούν τη μακροεντολή `MAC_CHECK`. Όπως στην περίπτωση του syscall για τη δημιουργία ενός socket, όπου καλείται η συνάρτηση `mac_socket_check_create`, η οποία με τη σειρά της καλεί το `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Επιπλέον, η μακροεντολή `MAC_CHECK` ορίζεται στο `security/mac_internal.h` ως εξής:<sup>[[3]](#references)</sup>
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

Σημειώστε ότι, μετατρέποντας το `check` σε `socket_check_create` και το `args...` σε `(cred, domain, type, protocol)`, προκύπτει:

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

Η ανάπτυξη των βοηθητικών macros αποκαλύπτει τη συγκεκριμένη ροή ελέγχου:

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

Με άλλα λόγια, το `MAC_CHECK(socket_check_create, ...)` διατρέχει πρώτα τις στατικές πολιτικές, κλειδώνει και επαναλαμβάνει υπό προϋποθέσεις τις δυναμικές πολιτικές, εκπέμπει τα DTrace probes γύρω από κάθε hook και συμπτύσσει τον κωδικό επιστροφής κάθε hook σε ένα μόνο αποτέλεσμα `error` μέσω της `mac_error_select()`.


### Ετικέτες

Το MACF χρησιμοποιεί **ετικέτες**, τις οποίες στη συνέχεια αξιοποιούν οι πολιτικές για να ελέγξουν αν θα επιτρέψουν ή όχι κάποια πρόσβαση. Ο κώδικας της δήλωσης της δομής των ετικετών [βρίσκεται εδώ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) και χρησιμοποιείται μέσα στη **`struct ucred`** [εδώ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), στο τμήμα **`cr_label`**. Η ετικέτα περιέχει flags και έναν αριθμό από **slots** που μπορούν να χρησιμοποιηθούν από τις **πολιτικές MACF για την εκχώρηση δεικτών**. Για παράδειγμα, το Sanbox δείχνει στο προφίλ του container.

## Πολιτικές MACF

Μια πολιτική MACF ορίζει **κανόνες και συνθήκες που εφαρμόζονται σε συγκεκριμένες λειτουργίες του kernel**.

Ένα kernel extension μπορεί να διαμορφώσει μια δομή `mac_policy_conf` και στη συνέχεια να την καταχωρίσει καλώντας τη `mac_policy_register`. Από [εδώ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

```c
 #define mpc_t	struct mac_policy_conf *

/**
  @brief Mac policy configuration

  This structure specifies the configuration information for a
  MAC policy module.  A policy module developer must supply
  a short unique policy name, a more descriptive full name, a list of label
  namespaces and count, a pointer to the registered entry-point operations,
  any load time flags, and optionally, a pointer to a label slot identifier.

  The Framework will update the runtime flags (mpc_runtime_flags) to
  indicate that the module has been registered.

  If the label slot identifier (mpc_field_off) is NULL, the Framework
  will not provide label storage for the policy.  Otherwise, the
  Framework will store the label location (slot) in this field.

  The mpc_list field is used by the Framework and should not be
  modified by policies.
*/
/* XXX - reorder these for better alignment on 64bit platforms */
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

Είναι εύκολο να εντοπίσετε τις επεκτάσεις πυρήνα που ρυθμίζουν αυτές τις πολιτικές, ελέγχοντας τις κλήσεις στη `mac_policy_register`. Επιπλέον, εξετάζοντας το disassembly της επέκτασης, είναι επίσης δυνατό να βρείτε τη χρησιμοποιούμενη δομή `mac_policy_conf`.

Σημειώστε ότι οι πολιτικές MACF μπορούν επίσης να καταχωρίζονται και να καταργούνται **δυναμικά**.

Ένα από τα κύρια πεδία της `mac_policy_conf` είναι το **`mpc_ops`**. Αυτό το πεδίο καθορίζει ποιες λειτουργίες ενδιαφέρουν την πολιτική. Υπάρχουν εκατοντάδες λειτουργίες, επομένως είναι δυνατό να μηδενιστούν όλες οι καταχωρίσεις και στη συνέχεια να επιλεγούν μόνο όσες χρειάζεται η πολιτική. Από [εδώ](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Σχεδόν όλα τα hooks θα κληθούν από το MACF όταν κάποια από αυτές τις λειτουργίες αναχαιτίζεται. Ωστόσο, τα hooks **`mpo_policy_*`** αποτελούν εξαίρεση, επειδή το `mpo_hook_policy_init()` είναι callback που καλείται κατά την εγγραφή (δηλαδή μετά το `mac_policy_register()`), ενώ το `mpo_hook_policy_initbsd()` καλείται κατά την καθυστερημένη εγγραφή, μόλις αρχικοποιηθεί σωστά το υποσύστημα BSD.

Επιπλέον, οποιοδήποτε kext μπορεί να εγγράψει το hook **`mpo_policy_syscall`** για να εκθέσει ένα ιδιωτικό **ioctl**-style **interface** κλήσεων. Στη συνέχεια, ένας user client θα μπορεί να καλέσει το `mac_syscall` (#381), καθορίζοντας ως παραμέτρους το **όνομα της policy**, έναν ακέραιο **κωδικό** και προαιρετικά **ορίσματα**.\
Για παράδειγμα, το **`Sandbox.kext`** το χρησιμοποιεί συχνά.

Είναι δυνατό να εντοπιστεί η δομή `mac_policy_ops` που χρησιμοποιείται κατά την εγγραφή της policy, εξετάζοντας το **`__DATA.__const*`** του kext. Μπορεί να βρεθεί επειδή ο δείκτης της βρίσκεται σε μια μετατόπιση μέσα στο `mpo_policy_conf`, αλλά και λόγω του πλήθους των δεικτών NULL σε εκείνη την περιοχή.

Επιπλέον, είναι επίσης δυνατό να ληφθεί η λίστα των kexts που έχουν διαμορφώσει μια policy, κάνοντας dump από τη μνήμη τη δομή **`_mac_policy_list`**, η οποία ενημερώνεται κάθε φορά που εγγράφεται μια policy.

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

Και στη συνέχεια κάντε dump όλων των ελέγχων της πολιτικής check με:

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
- Η `mac_policy_init()` αρχικοποιεί την καθολική `mac_policy_list` (έναν πίνακα ή μια λίστα θέσεων πολιτικών) και δημιουργεί την υποδομή για το MAC (Mandatory Access Control) μέσα στο XNU.  
- Αργότερα, καλείται η `mac_policy_initmach()`, η οποία χειρίζεται την εγγραφή πολιτικών σε επίπεδο kernel για ενσωματωμένες πολιτικές ή πολιτικές που συνοδεύουν το σύστημα.

### `mac_policy_initmach()` και φόρτωση «security extensions»

- Η `mac_policy_initmach()` εξετάζει kernel extensions (kexts) που έχουν προφορτωθεί (ή βρίσκονται σε μια λίστα «policy injection») και ελέγχει το Info.plist τους για το κλειδί `AppleSecurityExtension`.  
- Τα kexts που δηλώνουν `<key>AppleSecurityExtension</key>` (ή `true`) στο Info.plist τους θεωρούνται «security extensions» — δηλαδή, υλοποιούν μια πολιτική MAC ή συνδέονται με την υποδομή MACF.  
- Παραδείγματα Apple kexts με αυτό το κλειδί είναι τα **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, μεταξύ άλλων (όπως αναφέρθηκε ήδη).  
- Ο kernel διασφαλίζει ότι αυτά τα kexts φορτώνονται νωρίς και, στη συνέχεια, καλεί τις ρουτίνες εγγραφής τους (μέσω της `mac_policy_register`) κατά την εκκίνηση, προσθέτοντάς τα στη `mac_policy_list`.

  - Κάθε μονάδα πολιτικής (kext) παρέχει μια δομή `mac_policy_conf`, με hooks (`mpc_ops`) για διάφορες λειτουργίες MAC (έλεγχοι vnode, έλεγχοι exec, ενημερώσεις label κ.λπ.).  
  - Οι σημαίες χρόνου φόρτωσης μπορεί να περιλαμβάνουν την `MPC_LOADTIME_FLAG_NOTLATE`, που σημαίνει «πρέπει να φορτωθεί νωρίς» (ώστε να απορρίπτονται απόπειρες καθυστερημένης εγγραφής).  
  - Μετά την εγγραφή, κάθε μονάδα λαμβάνει ένα handle και καταλαμβάνει μια θέση στη `mac_policy_list`.  
  - Όταν καλείται αργότερα ένα MAC hook (για παράδειγμα, για πρόσβαση σε vnode, exec κ.λπ.), το MACF επαναλαμβάνει όλες τις καταχωρισμένες πολιτικές για να λάβει συλλογικές αποφάσεις.

- Συγκεκριμένα, το **AMFI** (Apple Mobile File Integrity) είναι ένα τέτοιο security extension. Το Info.plist του περιλαμβάνει το `AppleSecurityExtension`, το οποίο το χαρακτηρίζει ως πολιτική ασφάλειας.  
- Κατά την εκκίνηση του kernel, η λογική φόρτωσης του kernel διασφαλίζει ότι η «security policy» (AMFI κ.λπ.) είναι ήδη ενεργή πριν εξαρτηθούν από αυτήν πολλά υποσυστήματα. Για παράδειγμα, ο kernel «προετοιμάζεται για τις επόμενες εργασίες φορτώνοντας … security policy, συμπεριλαμβανομένων των AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.» 

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

Όταν γράφετε ένα kext που χρησιμοποιεί το MAC framework (δηλ. καλεί `mac_policy_register()` κ.λπ.), πρέπει να δηλώσετε τις εξαρτήσεις του από KPI (Kernel Programming Interfaces), ώστε ο linker του kext (kxld) να μπορεί να επιλύσει αυτά τα σύμβολα. Επομένως, για να δηλώσετε ότι ένα `kext` εξαρτάται από το MACF, πρέπει να το ορίσετε στο `Info.plist` με το `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`). Στη συνέχεια, το kext θα αναφέρεται σε σύμβολα όπως τα `mac_policy_register`, `mac_policy_unregister` και τους δείκτες συναρτήσεων των MAC hook. Για να επιλυθούν αυτά, πρέπει να καταχωρίσετε το `com.apple.kpi.dsep` ως εξάρτηση.

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



## Το MACF σε σύγχρονες εκδόσεις του macOS

Στο σύγχρονο macOS, συνήθως δεν είναι καλύτερο να προσεγγίζουμε τις πολιτικές ασφαλείας της Apple ως μεμονωμένα, ανεξάρτητα πακέτα `.kext`. Από το **macOS 11**, τα kernel extensions συνδέονται σε **kernel collections**· στο **Apple Silicon** δεν υπάρχει ξεχωριστό **SystemKC**, και τα kext τρίτων κατασκευαστών μπορούν να φορτωθούν μόνο αφού ενσωματωθούν στο **Auxiliary Kernel Collection (AuxKC)** και γίνει επανεκκίνηση. Για την έρευνα του MACF, αυτό σημαίνει ότι οι ενσωματωμένες πολιτικές, όπως οι **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** ή **Quarantine**, συνήθως απαριθμούνται ευκολότερα με το `kmutil` παρά με παρωχημένα εργαλεία όπως το `kextstat`.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Σε Apple Silicon, αν ένα security kext δεν βρίσκεται στο BootKC, ελέγξτε στη συνέχεια το AuxKC. Αυτό είναι συνήθως πιο χρήσιμο από το να αναζητάτε ένα αυτόνομο bundle στον κατάλογο `/System/Library/Extensions`.

## MACF Callouts

Είναι συνηθισμένο να βρίσκουμε callouts προς το MACF ορισμένα σε κώδικα, σε conditional blocks όπως το **`#if CONFIG_MAC`**. Επιπλέον, μέσα σε αυτά τα blocks είναι δυνατό να βρεθούν κλήσεις προς `mac_proc_check*`, οι οποίες καλούν το MACF για να **ελέγξουν τα δικαιώματα** εκτέλεσης ορισμένων ενεργειών. Η μορφή των MACF callouts είναι: **`mac_<object>_<opType>_opName`**.

Το object είναι ένα από τα εξής: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Το `opType` είναι συνήθως `check`, το οποίο χρησιμοποιείται για να επιτρέψει ή να αρνηθεί την ενέργεια. Ωστόσο, είναι δυνατό να βρεθεί και το `notify`, το οποίο επιτρέπει στο kext να αντιδράσει στη συγκεκριμένη ενέργεια.

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

Στη συνέχεια, μπορείτε να βρείτε τον κώδικα της `mac_file_check_mmap` στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)

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

Το οποίο καλεί τη macro `MAC_CHECK`, της οποίας ο κώδικας βρίσκεται στο [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>

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

Αυτό διατρέχει τις καταχωρισμένες πολιτικές και συνδυάζει τα αποτελέσματά τους με το `mac_error_select()`. Μια επιστροφή μηδενός από μεταγενέστερο έλεγχο δεν μπορεί να αναιρέσει μια προηγούμενη άρνηση· αν αρνηθούν πολλές πολιτικές, η συνάρτηση επιλέγει το σφάλμα βάσει προτεραιότητας (για παράδειγμα, το `EACCES` προηγείται του `EPERM`).<sup>[[2]](#references)</sup>

> [!TIP]
> Ωστόσο, να θυμάστε ότι τα MACF callouts δεν χρησιμοποιούνται όλα αποκλειστικά για την άρνηση ενεργειών. Για παράδειγμα, το `mac_priv_grant` καλεί τη μακροεντολή [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), η οποία θα παραχωρήσει το ζητούμενο προνόμιο αν οποιαδήποτε πολιτική απαντήσει με 0:
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

Αυτές οι κλήσεις προορίζονται για τον έλεγχο και την παροχή (δεκάδων) **δικαιωμάτων** που ορίζονται στο [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Κάποιος κώδικας του kernel καλεί τη `priv_check_cred()` από το [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c), περνώντας τα διαπιστευτήρια KAuth της διεργασίας και έναν από τους κωδικούς δικαιωμάτων. Αυτή καλεί τη `mac_priv_check` για να ελέγξει αν κάποια πολιτική **αρνείται** την παροχή του δικαιώματος και, στη συνέχεια, καλεί τη `mac_priv_grant` για να ελέγξει αν κάποια πολιτική παρέχει το `privilege`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Αυτό το hook επιτρέπει την παρεμβολή σε όλες τις κλήσεις συστήματος. Στο `bsd/dev/[i386|arm]/systemcalls.c` μπορείτε να δείτε τη δηλωμένη συνάρτηση [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), η οποία περιέχει τον εξής κώδικα:

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

Το οποίο θα ελέγξει το **bitmask** στη διεργασία που το καλεί, για να διαπιστώσει αν η τρέχουσα syscall πρέπει να καλέσει τη `mac_proc_check_syscall_unix`. Αυτό συμβαίνει επειδή οι syscalls καλούνται πολύ συχνά, επομένως είναι προτιμότερο να αποφεύγεται η κλήση της `mac_proc_check_syscall_unix` κάθε φορά.

Σημειώστε ότι η συνάρτηση `proc_set_syscall_filter_mask()`, η οποία ορίζει το bitmask των syscalls σε μια διεργασία, καλείται από το Sandbox για να ορίσει μάσκες στις διεργασίες που βρίσκονται σε sandbox.

## Εκτεθειμένες MACF syscalls

Είναι δυνατή η αλληλεπίδραση με το MACF μέσω ορισμένων syscalls που ορίζονται στο [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):

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

Για offensive reversing, το **`__mac_syscall`** παραμένει ένα από τα καλύτερα userland chokepoints. Μεταφέρει ένα **policy name** (για παράδειγμα `"Sandbox"` ή `"AMFI"`), ένα **policy-specific selector/code** και έναν δείκτη προς το **opaque argument blob** που θα χειριστεί το `mpo_policy_syscall`. Αυτό είναι πολύ χρήσιμο όταν κάνετε reverse engineering σε μη τεκμηριωμένες λειτουργίες, ξεκινώντας από το userland και περνώντας αργότερα στην υλοποίηση του kernel. Το Sandbox συνήθως το καλεί μέσω του `__sandbox_ms`, ενώ το AMFI χρησιμοποιεί τον ίδιο μηχανισμό για αποφάσεις πολιτικής του dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Πρακτικές σημειώσεις για offensive έρευνα

Τα πρόσφατα bugs στο macOS σπάνια «παρακάμπτουν άμεσα το MACF». Συνήθως εκμεταλλεύονται έναν **αποσυγχρονισμό ανάμεσα σε μια απόφαση του MACF / Sandbox / TCC και στην privileged ενέργεια που εκτελείται αργότερα**.

### Policy-specific spawn attributes ως είσοδος του MACF

Η `posix_spawnattr_setmacpolicyinfo_np()` επισυνάπτει ένα policy name και opaque bytes σε ένα αίτημα `posix_spawn()`. Το XNU αναζητά αυτά τα bytes βάσει του `mpc_name` κάθε καταχωρισμένης πολιτικής και τα περνά στο exec-label hook της συγκεκριμένης πολιτικής· το launch-constraints hook διαβάζει επίσης τα αντίστοιχα bytes. Αυτή είναι μια ξεχωριστή διαδρομή εισόδου στο MACF, ελεγχόμενη από τον attacker, ανεξάρτητη από το `__mac_syscall`. Ελέγξτε αν η πολιτική αντιμετωπίζει αυτά τα bytes ως *πρόσθετο περιορισμό* ή αν τα αφήνει να αντικαταστήσουν την υπάρχουσα πολιτική του γονέα ή του εκτελέσιμου αρχείου.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Για μια ελεγχόμενη δοκιμή, ξεκινήστε με έναν περιορισμένο γονέα και κάντε spawn το ίδιο child **χωρίς** και **με** ένα policy-specific attribute. Συγκρίνετε την αποτελεσματική πρόσβαση του child σε έναν πόρο που ο γονέας δεν μπορεί να χρησιμοποιήσει· το επιτυχές spawn από μόνο του δεν αποδεικνύει ότι παραβιάστηκε κάποιο όριο.<sup>[[12]](#references)[[13]](#references)</sup>

Κατά το reversing της πολιτικής, ακολουθήστε τα `mpo_cred_label_update_execve` και `mpo_proc_check_launch_constraints` και, στη συνέχεια, ελέγξτε αν ο caller μπορεί να παρέχει το attribute.<sup>[[10]](#references)[[11]](#references)</sup> Ιστορικά, το AMFI δεχόταν launch constraints που παρέχονταν από τον caller αντί για τα ενσωματωμένα· το Sandbox μπορούσε να εφαρμόσει ένα ονομασμένο ενσωματωμένο profile σε ένα child αντί να διατηρήσει τους περιορισμούς του γονέα.<sup>[[13]](#references)[[12]](#references)</sup> Και οι δύο συμπεριφορές διορθώθηκαν, επομένως μην θεωρείτε δεδομένο ότι ισχύει κάποια από αυτές στα τρέχοντα συστήματα.<sup>[[13]](#references)[[12]](#references)</sup>

Για την περίπτωση του AMFI, δείτε την [ανάλυση launch constraints](macos-launch-environment-constraints.md) και για δοκιμές της αποτελεσματικής πολιτικής του child, το [debugging του Sandbox](macos-sandbox/macos-sandbox-debug-and-bypass/).

### Έλεγχοι διαδρομών από broker έναντι πραγματικής privileged ενέργειας

Ένα επαναλαμβανόμενο μοτίβο είναι ένας privileged daemon να εκτελεί έναν **userland προέλεγχο** (για παράδειγμα, `sandbox_check_by_audit_token()`) σε μία εκδοχή μιας διαδρομής και αργότερα να εκτελεί την πραγματική privileged ενέργεια με μια **διαφορετική ή μη κανονικοποιημένη διαδρομή που ελέγχει ο attacker**. Πρόσφατη έρευνα για τα `diskarbitrationd` / `storagekitd` αποτελεί καλό παράδειγμα: **directory traversal** σε συνδυασμό με **symlink swaps** επιτρέπουν στον attacker να περάσει την επικύρωση του daemon για το sandbox και, στη συνέχεια, να κάνει mount πάνω σε ευαίσθητες τοποθεσίες όπως το `~/Library/Application Support/com.apple.TCC`, μετατρέποντας το bug σε **sandbox escape**, **local privilege escalation** ή **TCC bypass**, ανάλογα με το επιλεγμένο mount point.<sup>[[6]](#references)</sup>

Κατά τον έλεγχο root brokers στους οποίους υπάρχει πρόσβαση από το sandbox, αναζητήστε πρώτα:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers κανονικοποίησης διαδρομών
- privileged sinks όπως `mount`, `rename`, `copyfile`, μέθοδοι XPC helper-tool ή οτιδήποτε άλλο που αργότερα αγγίζει διαδρομές ελεγχόμενες από τον attacker ως root

### Trusted deputies με private entitlements

Ένα άλλο πρακτικό μοτίβο είναι να αποφύγετε την άμεση επίθεση στα MACF hooks και, αντί γι’ αυτό, να εκμεταλλευτείτε μια **trusted process** που διαθέτει ήδη τα δικαιώματα τα οποία απαιτούνται για να περάσει το όριο. Πρόσφατη έρευνα για το Safari/TCC αποτελεί καλό παράδειγμα: το ενδιαφέρον primitive δεν ήταν «να απενεργοποιηθεί το TCC στον kernel», αλλά να τροποποιηθεί η τοπική πολιτική/διαμόρφωση, ώστε μια διεργασία υπογεγραμμένη από την Apple και με **`com.apple.private.tcc.allow`** να εκτελέσει την ευαίσθητη ενέργεια για λογαριασμό σας.<sup>[[8]](#references)</sup> Στην πράξη, σημαντικοί στόχοι για auditing είναι Apple daemons/apps που συνδυάζουν:

- **private entitlements** ή πρόσβαση παρόμοια με FDA
- μια εγγράψιμη διαμόρφωση / βάση δεδομένων / mount point / αρχείο πολιτικής
- μια μεταγενέστερη ευαίσθητη ενέργεια που ελέγχεται από το **Sandbox**, το **AMFI**, το **TCC** ή κάποια άλλη πολιτική MACF

Για πιο εξειδικευμένο reversing ανά προϊόν, δείτε τις ειδικές σελίδες για το [macOS Sandbox](macos-sandbox/README.md) και το [macOS TCC](macos-tcc/README.md).



## References

- [1] [XNU — `security/mac_policy.h` (το πλήρες διάνυσμα λειτουργιών πολιτικής MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (macros `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (κωδικοί προνομίων που χρησιμοποιούνται από τα `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Αποκάλυψη ευπαθειών της Apple: έλεγχος των diskarbitrationd και storagekitd, μέρος 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — εργαλείο Cross Reference του XNU](https://newosxbook.com/xxr/index.php)
- [8] [Νέα ευπάθεια στο macOS, «HM Surf», θα μπορούσε να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση σε δεδομένα (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — setter policy attribute του posix_spawn](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — dispatch exec-label attribute για συγκεκριμένες πολιτικές](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — dispatch πολιτικής launch constraints](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Διαφυγή από το Apple Sandbox μέσω spawn ενός εκτελέσιμου αρχείου](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [Παράκαμψη των Launch Constraints στο macOS](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
