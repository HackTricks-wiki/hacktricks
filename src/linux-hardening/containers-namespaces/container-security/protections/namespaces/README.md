# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Τα Namespaces είναι η δυνατότητα του kernel που κάνει ένα container να μοιάζει με «δικό του μηχάνημα», παρόλο που στην πραγματικότητα είναι απλώς ένα δέντρο διεργασιών του host. Δεν δημιουργούν νέο kernel και δεν virtualize-άρουν τα πάντα, αλλά επιτρέπουν στον kernel να παρουσιάζει διαφορετικές όψεις επιλεγμένων πόρων σε διαφορετικές ομάδες διεργασιών. Αυτός είναι ο πυρήνας της ψευδαίσθησης του container: το workload βλέπει ένα filesystem, έναν πίνακα διεργασιών, ένα network stack, ένα hostname, πόρους IPC και ένα μοντέλο ταυτότητας χρηστών/ομάδων που φαίνονται τοπικά, παρόλο που το υποκείμενο σύστημα είναι κοινόχρηστο.

Αυτός είναι ο λόγος για τον οποίο τα namespaces είναι η πρώτη έννοια που συναντούν οι περισσότεροι όταν μαθαίνουν πώς λειτουργούν τα containers. Ταυτόχρονα, είναι μία από τις πιο συχνά παρεξηγημένες έννοιες, επειδή οι αναγνώστες συχνά υποθέτουν ότι το «έχει namespaces» σημαίνει «είναι με ασφάλεια isolated». Στην πραγματικότητα, ένα namespace απομονώνει μόνο τη συγκεκριμένη κατηγορία πόρων για την οποία σχεδιάστηκε. Μια διεργασία μπορεί να έχει private PID namespace και παρ' όλα αυτά να είναι επικίνδυνη επειδή διαθέτει writable host bind mount. Μπορεί να έχει private network namespace και παρ' όλα αυτά να είναι επικίνδυνη επειδή διατηρεί το `CAP_SYS_ADMIN` και εκτελείται χωρίς seccomp. Τα namespaces είναι θεμελιώδη, αλλά αποτελούν μόνο ένα layer του τελικού boundary.

## Τύποι Namespace

Τα Linux containers βασίζονται συνήθως σε πολλούς τύπους namespace ταυτόχρονα. Το **mount namespace** παρέχει στη διεργασία ξεχωριστό mount table και επομένως ελεγχόμενη όψη του filesystem. Το **PID namespace** αλλάζει την ορατότητα και την αρίθμηση των διεργασιών, ώστε το workload να βλέπει το δικό του process tree. Το **network namespace** απομονώνει interfaces, routes, sockets και firewall state. Το **IPC namespace** απομονώνει τα SysV IPC και τα POSIX message queues. Το **UTS namespace** απομονώνει το hostname και το NIS domain name. Το **user namespace** κάνει remap τα user και group IDs, ώστε το root μέσα στο container να μη σημαίνει απαραίτητα root στον host. Το **cgroup namespace** virtualize-άρει την ορατή cgroup hierarchy και το **time namespace** virtualize-άρει επιλεγμένα clocks σε νεότερους kernels.

Κάθε ένα από αυτά τα namespaces επιλύει διαφορετικό πρόβλημα. Γι' αυτό η πρακτική ανάλυση container security συχνά καταλήγει στον έλεγχο του **ποια namespaces είναι isolated** και **ποια έχουν σκόπιμα γίνει shared με τον host**.

## Κοινή χρήση Host Namespace

Πολλά container breakouts δεν ξεκινούν από vulnerability του kernel. Ξεκινούν όταν ένας operator αποδυναμώνει σκόπιμα το μοντέλο isolation. Τα παραδείγματα `--pid=host`, `--network=host` και `--userns=host` είναι **Docker/Podman-style CLI flags** που χρησιμοποιούνται εδώ ως συγκεκριμένα παραδείγματα κοινής χρήσης host namespace. Άλλα runtimes εκφράζουν την ίδια ιδέα διαφορετικά. Στο Kubernetes, τα αντίστοιχα συνήθως εμφανίζονται ως ρυθμίσεις Pod, όπως `hostPID: true`, `hostNetwork: true` ή `hostIPC: true`. Σε lower-level runtime stacks, όπως τα containerd ή CRI-O, η ίδια συμπεριφορά επιτυγχάνεται συχνά μέσω του generated OCI runtime configuration και όχι μέσω ενός user-facing flag με το ίδιο όνομα. Σε όλες αυτές τις περιπτώσεις, το αποτέλεσμα είναι παρόμοιο: το workload δεν λαμβάνει πλέον την προεπιλεγμένη isolated namespace view.

Γι' αυτό οι έλεγχοι namespaces δεν πρέπει ποτέ να σταματούν στο «η διεργασία βρίσκεται σε κάποιο namespace». Το σημαντικό ερώτημα είναι αν το namespace είναι private για το container, shared με sibling containers ή joined απευθείας στον host. Στο Kubernetes, η ίδια ιδέα εμφανίζεται με flags όπως `hostPID`, `hostNetwork` και `hostIPC`. Τα ονόματα αλλάζουν μεταξύ των platforms, αλλά το risk pattern παραμένει ίδιο: ένα shared host namespace κάνει τα υπόλοιπα privileges του container και το host state στο οποίο μπορεί να έχει πρόσβαση πολύ πιο σημαντικά.

## Έλεγχος

Η απλούστερη επισκόπηση είναι:
```bash
ls -l /proc/self/ns
```
Κάθε καταχώριση είναι ένας συμβολικός σύνδεσμος με ένα αναγνωριστικό τύπου inode. Αν δύο διεργασίες δείχνουν στο ίδιο αναγνωριστικό namespace, βρίσκονται στο ίδιο namespace αυτού του τύπου. Αυτό καθιστά το `/proc` ένα πολύ χρήσιμο μέρος για τη σύγκριση της τρέχουσας διεργασίας με άλλες ενδιαφέρουσες διεργασίες στο μηχάνημα.

Αυτές οι γρήγορες εντολές είναι συχνά αρκετές για να ξεκινήσετε:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Από εκεί, το επόμενο βήμα είναι να συγκρίνετε το container process με διεργασίες του host ή γειτονικές διεργασίες και να προσδιορίσετε αν ένα namespace είναι πράγματι private ή όχι.

### Enumerating Namespace Instances From The Host

Όταν έχετε ήδη πρόσβαση στον host και θέλετε να κατανοήσετε πόσα distinct namespaces ενός συγκεκριμένου τύπου υπάρχουν, το `/proc` παρέχει μια γρήγορη inventory:
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
Αν θέλετε να βρείτε ποιες διεργασίες ανήκουν σε ένα συγκεκριμένο αναγνωριστικό namespace, χρησιμοποιήστε το `ls -l` αντί για το `readlink` και κάντε grep για τον αριθμό του namespace-στόχου:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Αυτές οι εντολές είναι χρήσιμες επειδή σας επιτρέπουν να απαντήσετε αν ένας host εκτελεί ένα isolated workload, πολλά isolated workloads ή έναν συνδυασμό από shared και private namespace instances.

### Είσοδος σε Target Namespace

Όταν ο caller έχει επαρκή δικαιώματα, το `nsenter` είναι ο τυπικός τρόπος συμμετοχής στο namespace μιας άλλης διεργασίας:
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
Το σημείο της παράθεσης αυτών των μορφών μαζί δεν είναι ότι κάθε assessment χρειάζεται όλες, αλλά ότι το namespace-specific post-exploitation συχνά γίνεται πολύ ευκολότερο όταν ο operator γνωρίζει την ακριβή σύνταξη εισόδου, αντί να θυμάται μόνο τη μορφή all-namespaces.

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

Καθώς τις διαβάζετε, κρατήστε δύο ιδέες στο μυαλό σας. Πρώτον, κάθε namespace απομονώνει μόνο ένα είδος view. Δεύτερον, ένα private namespace είναι χρήσιμο μόνο αν το υπόλοιπο privilege model εξακολουθεί να κάνει αυτή την απομόνωση ουσιαστική.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη στάση namespace | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- |
| Docker Engine | Νέα mount, PID, network, IPC και UTS namespaces από προεπιλογή· τα user namespaces είναι διαθέσιμα, αλλά δεν είναι ενεργοποιημένα από προεπιλογή σε standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Νέα namespaces από προεπιλογή· το rootless Podman χρησιμοποιεί αυτόματα ένα user namespace· οι προεπιλογές του cgroup namespace εξαρτώνται από την έκδοση του cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Τα Pods **δεν** μοιράζονται από προεπιλογή το host PID, network ή IPC· το Pod networking είναι private στο Pod και όχι σε κάθε μεμονωμένο container· τα user namespaces ενεργοποιούνται προαιρετικά μέσω του `spec.hostUsers: false` σε υποστηριζόμενα clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / παράλειψη του user-namespace opt-in, ρυθμίσεις privileged workload |
| containerd / CRI-O under Kubernetes | Συνήθως ακολουθούν τις προεπιλογές των Kubernetes Pods | ίδια με τη γραμμή του Kubernetes· τα direct CRI/OCI specs μπορούν επίσης να ζητήσουν joins σε host namespaces |

Ο βασικός κανόνας portability είναι απλός: η **έννοια** του host namespace sharing είναι κοινή μεταξύ των runtimes, αλλά η **σύνταξη** είναι runtime-specific.
{{#include ../../../../../banners/hacktricks-training.md}}
