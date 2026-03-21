# Χώροι ονομάτων

{{#include ../../../../../banners/hacktricks-training.md}}

Οι namespaces είναι μια λειτουργία του πυρήνα που κάνει ένα container να μοιάζει σαν «το δικό του μηχάνημα», παρόλο που στην πραγματικότητα είναι απλώς ένα δέντρο διεργασιών του host. Δεν δημιουργούν νέο πυρήνα και δεν εικονικοποιούν τα πάντα, αλλά επιτρέπουν στον πυρήνα να παρουσιάζει διαφορετικές όψεις επιλεγμένων πόρων σε διαφορετικές ομάδες διεργασιών. Αυτή είναι η ουσία της ψευδαίσθησης του container: το workload βλέπει ένα filesystem, process table, network stack, hostname, IPC πόρους και ένα μοντέλο ταυτότητας χρήστη/ομάδας που φαίνεται τοπικό, παρόλο που το υποκείμενο σύστημα είναι κοινόχρηστο.

Γι' αυτό τα namespaces είναι η πρώτη έννοια που συναντάνε οι περισσότεροι όταν μαθαίνουν πώς λειτουργούν τα containers. Ταυτόχρονα είναι από τις πιο παρερμηνευμένες έννοιες, γιατί οι αναγνώστες συχνά υποθέτουν ότι «έχει namespaces» σημαίνει «είναι απομονωμένο με ασφάλεια». Στην πραγματικότητα, ένα namespace απομονώνει μόνο την συγκεκριμένη κατηγορία πόρων για την οποία σχεδιάστηκε. Μια διεργασία μπορεί να έχει ιδιωτικό PID namespace και παρ' όλα αυτά να είναι επικίνδυνη επειδή έχει ένα εγγράψιμο host bind mount. Μπορεί να έχει ιδιωτικό network namespace και παρ' όλα αυτά να είναι επικίνδυνη επειδή διατηρεί `CAP_SYS_ADMIN` και τρέχει χωρίς seccomp. Τα namespaces είναι θεμελιώδη, αλλά αποτελούν μόνο ένα στρώμα στα τελικά όρια.

## Τύποι χώρων ονομάτων

Τα Linux containers συνήθως βασίζονται σε αρκετούς τύπους namespaces ταυτόχρονα. Το **mount namespace** δίνει στη διεργασία ξεχωριστό πίνακα mount και επομένως ελεγχόμενη όψη του filesystem. Το **PID namespace** αλλάζει την ορατότητα και την αρίθμηση διεργασιών ώστε το workload να βλέπει το δικό του δέντρο διεργασιών. Το **network namespace** απομονώνει interfaces, routes, sockets και κατάσταση firewall. Το **IPC namespace** απομονώνει SysV IPC και POSIX message queues. Το **UTS namespace** απομονώνει το hostname και το NIS domain name. Το **user namespace** ανακατευθύνει τα user και group IDs ώστε το root μέσα στο container να μην σημαίνει απαραίτητα root στο host. Το **cgroup namespace** εικονικοποιεί την ορατή ιεραρχία cgroup, και το **time namespace** εικονικοποιεί επιλεγμένα clocks σε νεότερους πυρήνες.

Καθένα από αυτά τα namespaces λύνει ένα διαφορετικό πρόβλημα. Γι' αυτό η πρακτική ανάλυση ασφάλειας container συχνά συνοψίζεται σε έλεγχο του ποιες namespaces είναι απομονωμένες και ποιες έχουν σκόπιμα μοιραστεί με το host.

## Host Namespace Sharing

Πολλές διαρροές από container δεν ξεκινούν με ευπάθεια του πυρήνα. Ξεκινούν με έναν χειριστή που αποδυναμώνει επίτηδες το μοντέλο απομόνωσης. Τα παραδείγματα `--pid=host`, `--network=host`, και `--userns=host` είναι **Docker/Podman-style CLI flags** που χρησιμοποιούνται εδώ ως συγκεκριμένα παραδείγματα κοινοποίησης host namespaces. Άλλα runtimes εκφράζουν την ίδια ιδέα διαφορετικά. Στο Kubernetes τα αντίστοιχα εμφανίζονται συνήθως ως ρυθμίσεις Pod όπως `hostPID: true`, `hostNetwork: true`, ή `hostIPC: true`. Σε χαμηλότερου επιπέδου runtime stacks όπως containerd ή CRI-O, η ίδια συμπεριφορά συχνά επιτυγχάνεται μέσω της παραγόμενης OCI runtime διαμόρφωσης αντί μέσω ενός user-facing flag με το ίδιο όνομα. Σε όλες αυτές τις περιπτώσεις, το αποτέλεσμα είναι παρόμοιο: το workload δεν λαμβάνει πλέον την προεπιλεγμένη απομονωμένη όψη του namespace.

Γι' αυτό οι ανασκοπήσεις namespaces δεν πρέπει ποτέ να σταματούν στο «η διεργασία είναι σε κάποιο namespace». Το σημαντικό ερώτημα είναι αν το namespace είναι ιδιωτικό για το container, μοιρασμένο με sibling containers, ή ενωμένο απευθείας με το host. Στο Kubernetes η ίδια ιδέα εμφανίζεται με flags όπως `hostPID`, `hostNetwork`, και `hostIPC`. Τα ονόματα αλλάζουν ανάμεσα στις πλατφόρμες, αλλά το μοτίβο κινδύνου είναι το ίδιο: ένα κοινόχρηστο host namespace κάνει τα εναπομένουσα προνόμια του container και την προσβάσιμη κατάσταση του host πολύ πιο σημαντικά.

## Επιθεώρηση

Η απλούστερη επισκόπηση είναι:
```bash
ls -l /proc/self/ns
```
Κάθε καταχώρηση είναι ένας συμβολικός σύνδεσμος με ένα αναγνωριστικό παρόμοιο με inode. Εάν δύο διεργασίες δείχνουν στο ίδιο αναγνωριστικό namespace, βρίσκονται στο ίδιο namespace αυτού του τύπου. Αυτό κάνει το `/proc` ένα πολύ χρήσιμο μέρος για να συγκρίνετε την τρέχουσα διεργασία με άλλες ενδιαφέρουσες διεργασίες στη μηχανή.

Αυτές οι γρήγορες εντολές είναι συχνά αρκετές για να ξεκινήσετε:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Από εκεί, το επόμενο βήμα είναι να συγκρίνετε τη διεργασία του container με διεργασίες του host ή γειτονικές διεργασίες και να προσδιορίσετε εάν ένα namespace είναι πραγματικά ιδιωτικό ή όχι.

### Απαρίθμηση παραδειγμάτων namespace από το host

Όταν έχετε ήδη πρόσβαση στο host και θέλετε να καταλάβετε πόσα διακριτά namespace ενός δεδομένου τύπου υπάρχουν, `/proc` δίνει μια γρήγορη καταγραφή:
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
Εάν θέλετε να βρείτε ποιες διεργασίες ανήκουν σε έναν συγκεκριμένο namespace identifier, αντικαταστήστε το `readlink` με `ls -l` και κάντε `grep` για τον αριθμό του namespace-στόχου:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Αυτές οι εντολές είναι χρήσιμες επειδή σας επιτρέπουν να προσδιορίσετε εάν ένας host εκτελεί ένα απομονωμένο workload, πολλά απομονωμένα workloads, ή ένα μείγμα κοινόχρηστων και ιδιωτικών namespace instances.

### Είσοδος σε στοχευμένο Namespace

Όταν ο καλών έχει επαρκή δικαιώματα, το `nsenter` είναι ο τυπικός τρόπος για να εισέλθετε στο namespace μιας άλλης διεργασίας:
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
Ο λόγος που απαριθμούνται αυτές οι μορφές μαζί δεν είναι ότι κάθε αξιολόγηση χρειάζεται όλες, αλλά ότι το namespace-specific post-exploitation συχνά γίνεται πολύ πιο εύκολο μόλις ο χειριστής γνωρίζει την ακριβή σύνταξη εισόδου αντί να θυμάται μόνο τη μορφή all-namespaces.

## Σελίδες

Οι παρακάτω σελίδες εξηγούν κάθε namespace με περισσότερες λεπτομέρειες:

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

Καθώς τις διαβάζετε, κρατήστε δύο ιδέες στο μυαλό. Πρώτον, κάθε namespace απομονώνει μόνο έναν τύπο όψης. Δεύτερον, ένα private namespace είναι χρήσιμο μόνο αν το υπόλοιπο μοντέλο προνομίων εξακολουθεί να κάνει αυτή την απομόνωση ουσιαστική.

## Προεπιλογές χρόνου εκτέλεσης

| Runtime / platform | Προεπιλεγμένη συμπεριφορά namespace | Συνήθεις χειροκίνητες αποδυναμώσεις |
| --- | --- | --- |
| Docker Engine | Νέοι mount, PID, network, IPC και UTS namespaces από προεπιλογή· user namespaces είναι διαθέσιμα αλλά δεν είναι ενεργοποιημένα από προεπιλογή σε standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Νέοι namespaces από προεπιλογή· το rootless Podman χρησιμοποιεί αυτόματα user namespace· οι προεπιλογές του cgroup namespace εξαρτώνται από την έκδοση του cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Τα Pods **δεν** μοιράζονται τον host PID, network ή IPC από προεπιλογή· το δικτύωμα Pod είναι ιδιωτικό για το Pod, όχι για κάθε μεμονωμένο container· user namespaces είναι opt-in μέσω `spec.hostUsers: false` σε clusters που το υποστηρίζουν | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / παράλειψη opt-in του user-namespace, ρυθμίσεις privileged workload |
| containerd / CRI-O under Kubernetes | Συνήθως ακολουθούν τις προεπιλογές των Kubernetes Pod | ίδιο με τη γραμμή Kubernetes; απευθείας CRI/OCI specs μπορούν επίσης να ζητήσουν συμμετοχές σε host namespaces |

Ο βασικός κανόνας φορητότητας είναι απλός: η **έννοια** του host namespace sharing είναι κοινή μεταξύ runtimes, αλλά η **σύνταξη** είναι ειδική για το runtime.
