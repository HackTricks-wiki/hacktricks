# Κατάχρηση Kernel Modules και modprobe

## Λανθασμένες ρυθμίσεις των kernel modules και της φόρτωσης modules

Η υποστήριξη kernel modules είναι ένας τομέας υψηλού αντίκτυπου κατά τον έλεγχο για Linux privilege escalation. Μην αντιμετωπίζετε κάθε μήνυμα για unsigned module ως exploitable από μόνο του, αλλά χρησιμοποιήστε το για να απαντήσετε σε πρακτικές ερωτήσεις.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Μπορεί ο τρέχων χρήστης να φορτώσει modules μέσω του `sudo`, capabilities ή ενός writable helper path;
- Είναι ακόμη ενεργοποιημένη η φόρτωση modules;
- Είναι απενεργοποιημένο το module signature enforcement;
- Είναι writable οι κατάλογοι των modules ή τα αρχεία των modules;
- Μπορούν να διαβαστούν τα kernel logs για επιβεβαίωση του τι συνέβη;

Το γρήγορο triage ξεκινά με τους παρακάτω ελέγχους για την κατάσταση των modules, τις υπογραφές, το logging και το module tree.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Ερμηνεία:

- `modules_disabled=1` σημαίνει ότι τα modules δεν μπορούν ούτε να φορτωθούν ούτε να αφαιρεθούν, και η τιμή δεν μπορεί να επανέλθει σε `0` μέχρι την επανεκκίνηση.<sup>[[1]](#references)</sup>
- Το `module.sig_enforce=1` στη γραμμή εντολών του kernel ή το `CONFIG_MODULE_SIG_FORCE=y` απαιτεί έγκυρα υπογεγραμμένα modules· διαφορετικά, μη υπογεγραμμένα modules ενδέχεται να φορτωθούν και να επισημάνουν τον kernel ως tainted.<sup>[[2]](#references)</sup>
- Το `dmesg_restrict=0` δεν επιβάλλει κανέναν περιορισμό στο `dmesg`· όταν είναι `1`, η πρόσβαση απαιτεί `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Τα paths με δυνατότητα εγγραφής κάτω από το `/lib/modules/$(uname -r)/` είναι επικίνδυνα, επειδή το `modprobe` αναζητά σε αυτό το tree και στα δεδομένα dependencies του κατά τη φόρτωση modules.<sup>[[8]](#references)</sup>

### Φόρτωση ενός module και ανάγνωση kernel output

Αν έχετε νόμιμη άδεια να φορτώσετε ένα local module, το `insmod` εισάγει το ακριβές αρχείο `.ko` που παρέχετε. Η init function του module εκτελείται ως μέρος της φόρτωσης και τα μηνύματα που γράφονται με `printk()` καταλήγουν στο kernel log buffer, το οποίο συνήθως διαβάζεται με `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Μια ελάχιστη ροή εργασίας ελέγχου χρησιμοποιεί το `modinfo` για την εξέταση metadata, τα `insmod` και `rmmod` για τη φόρτωση και την αφαίρεση ενός module, το `lsmod` για την επιβεβαίωση της κατάστασης φόρτωσης και το `dmesg` για την εξέταση των kernel logs.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Αν το `sudo -l` επιτρέπει τα `insmod`, `modprobe` ή ένα wrapper γύρω από αυτά, θεωρήστε το κρίσιμο: το `sudo -l` εμφανίζει τα προνόμια του χρήστη που το καλεί, και η φόρτωση ενός kernel module απαιτεί `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` που επιτρέπεται μέσω `sudo`

Ένας κανόνας `sudo` που επιτρέπει σε έναν χρήστη να εκτελεί το `insmod` δεν είναι συγκρίσιμος με την άδεια εκτέλεσης ενός συνηθισμένου βοηθητικού εργαλείου διαχείρισης. Ο κώδικας αρχικοποίησης του module εκτελείται κατά την εισαγωγή του, επομένως το πρακτικό ερώτημα κατά την αξιολόγηση είναι αν αυτός ο χρήστης μπορεί να επιλέξει ή να τροποποιήσει το module που φορτώνεται.<sup>[[3]](#references)</sup>

Η ακόλουθη γενική ροή αξιολόγησης επαναλαμβάνει αυτούς τους ελέγχους επιθεώρησης, φόρτωσης, κατάστασης, καταγραφής και αφαίρεσης για ένα υποψήφιο module.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Εάν ο χρήστης μπορεί να παρέχει ένα αυθαίρετο `.ko`, ο κανόνας θα πρέπει να αντιμετωπίζεται ως πλήρης παραβίαση του συστήματος σε μια εξουσιοδοτημένη αξιολόγηση. Ένα ασφαλέστερο operational pattern είναι να αποφεύγεται η ανάθεση φόρτωσης module μέσω sudo· εάν αυτό είναι αναπόφευκτο, περιορίστε την ακριβή διαδρομή, την ιδιοκτησία, τα δικαιώματα, την signing policy και τη διαδικασία αφαίρεσης.<sup>[[3]](#references)[[10]](#references)</sup>

Για ένα ακίνδυνο pattern δημιουργίας module σε ελεγχόμενο lab, παρακάτω παρουσιάζονται ένας ελάχιστος πηγαίος κώδικας και ένα Makefile· η μορφή `make -C /lib/modules/$(uname -r)/build M=$PWD` ακολουθεί το τεκμηριωμένο workflow kbuild του kernel για external modules.<sup>[[5]](#references)[[7]](#references)</sup>
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
Κάντε build και load μόνο σε εξουσιοδοτημένο lab· το kbuild κάνει build το external module και οι εντολές load/remove καλούν τα interfaces των kernel modules.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Έλεγχοι κατάχρησης των `kernel.modprobe` / `modprobe_path`

Το `kernel.modprobe` καθορίζει το userspace helper που εκτελεί ο kernel για αιτήματα αυτόματης φόρτωσης modules· αυτό το sysctl επηρεάζει την αυτόματη φόρτωση και όχι την explicit εισαγωγή modules. Αν ένας attacker μπορεί να το αλλάξει σε διαδρομή writable executable και να προκαλέσει ένα module request, το συγκεκριμένο helper γίνεται privileged code-execution path.<sup>[[1]](#references)</sup>

Ελέγξτε την τρέχουσα διαδρομή του helper μέσω του kernel sysctl interface και εξετάστε το ownership και το mode του στόχου.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Ελέγξτε αν μπορούν να επηρεαστούν οι ρυθμίσεις sysctl, οι delegated κανόνες sudo ή τα file capabilities.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Το ακόλουθο μοτίβο, αποκλειστικά για εργαστηριακή χρήση, αλλάζει τη διαδρομή του helper και ενεργοποιεί ένα τεκμηριωμένο αίτημα module-autoload· χρησιμοποιήστε το μόνο σε απομονωμένο, εξουσιοδοτημένο σύστημα.<sup>[[1]](#references)</sup>

Σε τρέχοντες Linux kernels, μην χρησιμοποιείτε ένα άγνωστο executable ως γενικό trigger: το legacy module autoloading για custom binary formats καταργήθηκε στο Linux 6.14, ενώ η τεκμηρίωση του kernel αναγνωρίζει έναν άγνωστο τύπο filesystem ως διαδρομή αιτήματος module-autoload.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Σε hardened systems, αυτό θα πρέπει να αποτυγχάνει όταν τα permissions εμποδίζουν εγγραφές από unprivileged χρήστες στο `kernel.modprobe`, το helper path δεν είναι writable ή το module autoloading είναι απενεργοποιημένο.<sup>[[1]](#references)</sup>

### Έλεγχος writable `/lib/modules`

Οι writable module directories μπορούν να επιτρέψουν αντικατάσταση modules, τοποθέτηση malicious modules ή κατάχρηση του auto-load, ανάλογα με τον τρόπο με τον οποίο θα κληθεί αργότερα το `modprobe`· το `modprobe` αναζητά στο `/lib/modules/$(uname -r)` και χρησιμοποιεί τα dependency data του κατά την επίλυση modules.<sup>[[8]](#references)</sup>

Ελέγξτε τα writable module files και τα dependency/alias metadata κάτω από το module tree της ενεργής έκδοσης του kernel.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Αν εντοπίσετε εγγράψιμο περιεχόμενο module, εξετάστε τον τρόπο με τον οποίο το `modprobe` επιλύει τις εξαρτήσεις και τον τρόπο με τον οποίο το `modinfo` αναφέρει τα metadata του module.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Αμυντικές σημειώσεις:

- Διατηρείτε το `/lib/modules` με ιδιοκτήτη `root:root` και χωρίς δυνατότητα εγγραφής από τους χρήστες.<sup>[[8]](#references)</sup>
- Ορίστε το `kernel.modules_disabled=1` μετά την εκκίνηση, όπου αυτό είναι λειτουργικά εφικτό.<sup>[[1]](#references)</sup>
- Επιβάλετε την υπογραφή kernel module σε συστήματα που απαιτούν loadable modules.<sup>[[2]](#references)</sup>
- Παρακολουθείτε τις εγγραφές στο `/proc/sys/kernel/modprobe`, στο `/lib/modules` και την απρόσμενη εκτέλεση των `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Τεκμηρίωση για το /proc/sys/kernel/ — Η τεκμηρίωση του Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Υποδομή υπογραφής kernel module — Η τεκμηρίωση του Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Βασικά στοιχεία Driver — Η τεκμηρίωση του Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Καταγραφή μηνυμάτων με printk — Η τεκμηρίωση του Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Κατασκευή External Modules — Η τεκμηρίωση του Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Συγχώνευση του tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
