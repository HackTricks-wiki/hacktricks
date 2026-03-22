# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces είναι το χαρακτηριστικό του πυρήνα που κάνει ένα container να φαίνεται σαν "η δική του μηχανή" παρόλο που στην πραγματικότητα είναι απλώς ένα δέντρο διεργασιών του host. Δεν δημιουργούν νέο πυρήνα και δεν εικονικοποιούν τα πάντα, αλλά επιτρέπουν στον πυρήνα να παρουσιάζει διαφορετικές όψεις επιλεγμένων πόρων σε διαφορετικές ομάδες διεργασιών. Αυτό είναι ο πυρήνας της ψευδαίσθησης του container: το workload βλέπει ένα filesystem, πίνακα διεργασιών, network stack, hostname, πόρους IPC και μοντέλο ταυτότητας user/group που φαίνεται τοπικό, παρόλο που το υποκείμενο σύστημα είναι κοινό.

Γι' αυτό τα namespaces είναι η πρώτη έννοια που συναντάει κάποιος όταν μαθαίνει πώς λειτουργούν τα containers. Ταυτόχρονα, είναι από τις πιο παρεξηγημένες έννοιες, γιατί πολλοί υποθέτουν ότι "έχει namespaces" σημαίνει "είναι ασφαλώς απομονωμένο". Στην πραγματικότητα, ένα namespace απομονώνει μόνο την συγκεκριμένη κατηγορία πόρων για την οποία σχεδιάστηκε. Μια διεργασία μπορεί να έχει ιδιωτικό PID namespace και παρ' όλα αυτά να είναι επικίνδυνη επειδή έχει ένα εγγράψιμο host bind mount. Μπορεί να έχει ιδιωτικό network namespace και παρ' όλα αυτά να είναι επικίνδυνη επειδή διατηρεί `CAP_SYS_ADMIN` και τρέχει χωρίς seccomp. Τα namespaces είναι θεμελιώδη, αλλά αποτελούν μόνο ένα στρώμα στα τελικά όρια.

## Τύποι Namespaces

Τα Linux containers συνήθως βασίζονται σε αρκετούς τύπους namespaces ταυτόχρονα. Το **mount namespace** δίνει στη διεργασία ξεχωριστό mount table και επομένως μια ελεγχόμενη όψη του filesystem. Το **PID namespace** αλλάζει την ορατότητα και την αρίθμηση των διεργασιών, έτσι το workload βλέπει το δικό του δέντρο διεργασιών. Το **network namespace** απομονώνει interfaces, routes, sockets και κατάσταση firewall. Το **IPC namespace** απομονώνει SysV IPC και POSIX message queues. Το **UTS namespace** απομονώνει το hostname και το NIS domain name. Το **user namespace** αναχάρτης (remaps) τα user και group IDs ώστε το root μέσα στο container να μην σημαίνει απαραίτητα root στο host. Το **cgroup namespace** εικονικοποιεί την ορατή ιεραρχία cgroup, και το **time namespace** εικονικοποιεί επιλεγμένα ρολόγια σε νεότερους πυρήνες.

Κάθε ένα από αυτά τα namespaces λύνει ένα διαφορετικό πρόβλημα. Γι' αυτό η πρακτική ανάλυση ασφάλειας container συχνά καταλήγει στο να ελέγξει ποια namespaces είναι απομονωμένα και ποια έχουν σκοπίμως κοινοποιηθεί με τον host.

## Host Namespace Sharing

Πολλές διαφυγές από container δεν ξεκινούν από ευπάθεια του πυρήνα. Ξεκινούν από έναν χειριστή που εξασθενεί εσκεμμένα το μοντέλο απομόνωσης. Τα παραδείγματα `--pid=host`, `--network=host`, και `--userns=host` είναι Docker/Podman-style CLI flags που χρησιμοποιούνται εδώ ως χειροπιαστά παραδείγματα κοινοποίησης namespace με τον host. Άλλα runtimes εκφράζουν την ίδια ιδέα διαφορετικά. Στο Kubernetes τα αντίστοιχα εμφανίζονται συνήθως ως ρυθμίσεις Pod όπως `hostPID: true`, `hostNetwork: true`, ή `hostIPC: true`. Σε χαμηλότερου επιπέδου runtime stacks όπως containerd ή CRI-O, η ίδια συμπεριφορά συχνά επιτυγχάνεται μέσω της παραγόμενης OCI runtime configuration αντί μέσω ενός user-facing flag με το ίδιο όνομα. Σε όλες αυτές τις περιπτώσεις, το αποτέλεσμα είναι παρόμοιο: το workload δεν λαμβάνει πλέον την προεπιλεγμένη απομονωμένη όψη των namespaces.

Γι' αυτό οι ανασκοπήσεις namespaces δεν πρέπει ποτέ να σταματούν στο "η διεργασία βρίσκεται σε κάποιο namespace". Το σημαντικό ερώτημα είναι αν το namespace είναι ιδιωτικό για το container, κοινοποιημένο με sibling containers, ή ενωμένο άμεσα με τον host. Στο Kubernetes η ίδια ιδέα εμφανίζεται με flags όπως `hostPID`, `hostNetwork` και `hostIPC`. Τα ονόματα αλλάζουν μεταξύ πλατφορμών, αλλά το πρότυπο κινδύνου είναι το ίδιο: ένα κοινόχρηστο host namespace κάνει τα υπόλοιπα προνόμια του container και την προσβάσιμη κατάσταση του host πολύ πιο σημαντικά.

## Επιθεώρηση

Η απλούστερη επισκόπηση είναι:
```bash
ls -l /proc/self/ns
```
Κάθε καταχώρηση είναι ένας συμβολικός σύνδεσμος με αναγνωριστικό τύπου inode. Αν δύο διεργασίες δείχνουν στο ίδιο αναγνωριστικό namespace, βρίσκονται στο ίδιο namespace αυτού του τύπου. Αυτό κάνει το `/proc` πολύ χρήσιμο για να συγκρίνετε τη τρέχουσα διεργασία με άλλες ενδιαφέρουσες διεργασίες στο μηχάνημα.

Αυτές οι γρήγορες εντολές συχνά αρκούν για να ξεκινήσετε:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Από εκεί, το επόμενο βήμα είναι να συγκρίνετε τη διεργασία του container με τη διεργασία του host ή με γειτονικές διεργασίες και να προσδιορίσετε αν ένα namespace είναι πραγματικά ιδιωτικό ή όχι.

### Απαρίθμηση περιπτώσεων namespace από το host

Όταν έχετε ήδη πρόσβαση στο host και θέλετε να καταλάβετε πόσα διακριτά namespaces ενός δεδομένου τύπου υπάρχουν, το `/proc` δίνει μια γρήγορη επισκόπηση:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Εάν θέλεις να βρεις ποιες διεργασίες ανήκουν σε ένα συγκεκριμένο αναγνωριστικό namespace, άλλαξε από `readlink` σε `ls -l` και χρησιμοποίησε `grep` για τον στοχευόμενο αριθμό του namespace:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Αυτές οι εντολές είναι χρήσιμες επειδή σας επιτρέπουν να διαπιστώσετε εάν ένας host εκτελεί ένα απομονωμένο workload, πολλά απομονωμένα workloads, ή ένα μείγμα shared και private namespace instances.

### Είσοδος σε στόχο namespace

Όταν η διεργασία που καλεί έχει επαρκή προνόμια, το `nsenter` είναι ο τυπικός τρόπος για να μπείτε στο namespace μιας άλλης διεργασίας:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
Ο σκοπός της παράθεσης αυτών των μορφών μαζί δεν είναι ότι κάθε αξιολόγηση χρειάζεται όλες, αλλά ότι η namespace-specific post-exploitation συχνά γίνεται πολύ πιο εύκολη μόλις ο χειριστής γνωρίζει την ακριβή σύνταξη εισόδου αντί να θυμάται μόνο τη μορφή all-namespaces.

## Σελίδες

The following pages explain each namespace in more detail:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Καθώς τα διαβάζετε, κρατήστε δύο ιδέες στο μυαλό. Πρώτον, κάθε namespace απομονώνει μόνο ένα είδος προβολής. Δεύτερον, ένα ιδιωτικό namespace είναι χρήσιμο μόνο αν το υπόλοιπο μοντέλο προνομίων εξακολουθεί να κάνει αυτή την απομόνωση ουσιαστική.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση namespace | Συχνή χειροκίνητη αποδυνάμωση |
| --- | --- | --- |
| Docker Engine | Νέα mount, PID, network, IPC, και UTS namespaces ως προεπιλογή· user namespaces είναι διαθέσιμα αλλά δεν ενεργοποιούνται εξ ορισμού σε τυπικές rootful εγκαταστάσεις | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Νέα namespaces ως προεπιλογή· rootless Podman χρησιμοποιεί αυτόματα user namespace· οι προεπιλογές cgroup namespace εξαρτώνται από την έκδοση cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Συνήθως ακολουθούν τις προεπιλογές Pod του Kubernetes | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Ο βασικός κανόνας φορητότητας είναι απλός: η **έννοια** του host namespace sharing είναι κοινή μεταξύ των runtimes, αλλά η **σύνταξη** είναι ειδική για το runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
