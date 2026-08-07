# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Τα Namespaces είναι μια δυνατότητα του kernel που κάνει ένα container να μοιάζει με «δικό του μηχάνημα», παρόλο που στην πραγματικότητα είναι απλώς ένα δέντρο διεργασιών του host. Δεν δημιουργούν νέο kernel και δεν κάνουν virtualize τα πάντα, αλλά επιτρέπουν στον kernel να παρουσιάζει διαφορετικές όψεις επιλεγμένων resources σε διαφορετικές ομάδες διεργασιών. Αυτός είναι ο πυρήνας της ψευδαίσθησης του container: το workload βλέπει ένα filesystem, έναν πίνακα διεργασιών, ένα network stack, ένα hostname, resources IPC και ένα μοντέλο ταυτότητας user/group που φαίνονται τοπικά, παρόλο που το υποκείμενο σύστημα είναι κοινόχρηστο.

Αυτός είναι ο λόγος για τον οποίο τα namespaces είναι η πρώτη έννοια που συναντούν οι περισσότεροι όταν μαθαίνουν πώς λειτουργούν τα containers. Ταυτόχρονα, είναι μία από τις πιο συχνά παρεξηγημένες έννοιες, επειδή οι αναγνώστες συχνά υποθέτουν ότι το «έχει namespaces» σημαίνει «είναι με ασφάλεια απομονωμένο». Στην πραγματικότητα, ένα namespace απομονώνει μόνο τη συγκεκριμένη κατηγορία resources για την οποία σχεδιάστηκε. Μια διεργασία μπορεί να έχει private PID namespace και παρ' όλα αυτά να είναι επικίνδυνη, επειδή διαθέτει writable host bind mount. Μπορεί να έχει private network namespace και παρ' όλα αυτά να είναι επικίνδυνη, επειδή διατηρεί `CAP_SYS_ADMIN` και εκτελείται χωρίς seccomp. Τα namespaces είναι θεμελιώδη, αλλά αποτελούν μόνο ένα layer του τελικού boundary.

## Τύποι Namespace

Τα Linux containers βασίζονται συνήθως ταυτόχρονα σε διάφορους τύπους namespace. Το **mount namespace** παρέχει στη διεργασία ξεχωριστό mount table και επομένως ελεγχόμενη όψη του filesystem. Το **PID namespace** αλλάζει την ορατότητα και την αρίθμηση των διεργασιών, ώστε το workload να βλέπει το δικό του process tree. Το **network namespace** απομονώνει interfaces, routes, sockets και firewall state. Το **IPC namespace** απομονώνει τα SysV IPC και POSIX message queues. Το **UTS namespace** απομονώνει το hostname και το NIS domain name. Το **user namespace** κάνει remap τα user και group IDs, ώστε το root μέσα στο container να μη σημαίνει απαραίτητα root στον host. Το **cgroup namespace** κάνει virtualize την ορατή cgroup hierarchy, ενώ το **time namespace** κάνει virtualize επιλεγμένα clocks σε νεότερους kernels.

Κάθε ένα από αυτά τα namespaces επιλύει διαφορετικό πρόβλημα. Γι' αυτό η πρακτική ανάλυση container security συχνά καταλήγει στον έλεγχο του **ποια namespaces είναι απομονωμένα** και **ποια έχουν σκόπιμα γίνει shared με τον host**.

## Κοινή χρήση Host Namespace

Πολλά container breakouts δεν ξεκινούν από μια ευπάθεια του kernel. Ξεκινούν όταν ένας operator αποδυναμώνει σκόπιμα το μοντέλο isolation. Τα παραδείγματα `--pid=host`, `--network=host` και `--userns=host` είναι **Docker/Podman-style CLI flags** που χρησιμοποιούνται εδώ ως συγκεκριμένα παραδείγματα κοινής χρήσης host namespace. Άλλα runtimes εκφράζουν την ίδια ιδέα διαφορετικά. Στο Kubernetes, τα αντίστοιχα εμφανίζονται συνήθως ως Pod settings, όπως `hostPID: true`, `hostNetwork: true` ή `hostIPC: true`. Σε lower-level runtime stacks, όπως τα containerd ή CRI-O, η ίδια συμπεριφορά επιτυγχάνεται συχνά μέσω του generated OCI runtime configuration και όχι μέσω ενός user-facing flag με το ίδιο όνομα. Σε όλες αυτές τις περιπτώσεις, το αποτέλεσμα είναι παρόμοιο: το workload δεν λαμβάνει πλέον την προεπιλεγμένη isolated view των namespaces.

Γι' αυτό τα namespace reviews δεν πρέπει ποτέ να σταματούν στο «η διεργασία βρίσκεται σε κάποιο namespace». Το σημαντικό ερώτημα είναι αν το namespace είναι private για το container, shared με sibling containers ή joined απευθείας στον host. Στο Kubernetes η ίδια ιδέα εμφανίζεται με flags όπως `hostPID`, `hostNetwork` και `hostIPC`. Τα ονόματα αλλάζουν μεταξύ των platforms, αλλά το risk pattern είναι το ίδιο: ένα shared host namespace κάνει τα εναπομείναντα privileges του container και το host state στο οποίο μπορεί να έχει πρόσβαση πολύ πιο σημαντικά.

## Inspection

Η απλούστερη overview είναι:
```bash
ls -l /proc/self/ns
```
Κάθε καταχώριση είναι ένας symbolic link με αναγνωριστικό παρόμοιο με inode. Αν δύο διεργασίες δείχνουν στο ίδιο αναγνωριστικό namespace, βρίσκονται στο ίδιο namespace αυτού του τύπου. Αυτό καθιστά το `/proc` ένα πολύ χρήσιμο σημείο για τη σύγκριση της τρέχουσας διεργασίας με άλλες ενδιαφέρουσες διεργασίες στο μηχάνημα.

Αυτές οι σύντομες εντολές είναι συχνά αρκετές για να ξεκινήσετε:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Από εκεί, το επόμενο βήμα είναι να συγκρίνετε τη διεργασία του container με διεργασίες του host ή γειτονικές διεργασίες και να καθορίσετε αν ένα namespace είναι πράγματι ιδιωτικό ή όχι.

### Καταμέτρηση Namespace Instances Από Το Host

Όταν έχετε ήδη πρόσβαση στο host και θέλετε να κατανοήσετε πόσα distinct namespaces ενός συγκεκριμένου τύπου υπάρχουν, το `/proc` παρέχει μια γρήγορη καταγραφή:
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
Αν θέλετε να βρείτε ποιες διεργασίες ανήκουν σε ένα συγκεκριμένο namespace identifier, μεταβείτε από το `readlink` στο `ls -l` και χρησιμοποιήστε το grep για τον αριθμό του namespace-στόχου:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Αυτές οι εντολές είναι χρήσιμες επειδή σας επιτρέπουν να απαντήσετε αν ένας host εκτελεί ένα isolated workload, πολλά isolated workloads ή έναν συνδυασμό από shared και private namespace instances.

### Είσοδος σε Ένα Target Namespace

Όταν ο caller διαθέτει επαρκή privileges, το `nsenter` είναι ο τυπικός τρόπος για να συνδεθείτε στο namespace μιας άλλης διεργασίας:
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
Το σημείο της παράθεσης αυτών των μορφών μαζί δεν είναι ότι κάθε assessment χρειάζεται όλες, αλλά ότι το namespace-specific post-exploitation συχνά γίνεται πολύ ευκολότερο όταν ο operator γνωρίζει την ακριβή entry syntax, αντί να θυμάται μόνο τη μορφή all-namespaces.

## Σελίδες

Οι ακόλουθες σελίδες εξηγούν κάθε namespace με περισσότερες λεπτομέρειες:

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

Καθώς τα διαβάζετε, κρατήστε υπόψη δύο ιδέες. Πρώτον, κάθε namespace απομονώνει μόνο ένα είδος view. Δεύτερον, ένα private namespace είναι χρήσιμο μόνο αν το υπόλοιπο privilege model εξακολουθεί να καθιστά αυτή την απομόνωση ουσιαστική.

## Προεπιλογές Runtime

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Ο βασικός κανόνας φορητότητας είναι απλός: η **έννοια** του host namespace sharing είναι κοινή μεταξύ των runtimes, αλλά η **σύνταξη** είναι συγκεκριμένη για κάθε runtime.

{{#include ../../../../../banners/hacktricks-training.md}}
