# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το IPC namespace απομονώνει τα **System V IPC objects** και τα **POSIX message queues**. Σε αυτά περιλαμβάνονται segments κοινόχρηστης μνήμης, semaphores και message queues, τα οποία διαφορετικά θα ήταν ορατά μεταξύ άσχετων processes στο host. Πρακτικά, αυτό εμποδίζει ένα container να συνδέεται αυθαίρετα σε IPC objects που ανήκουν σε άλλα workloads ή στο host.

Σε σύγκριση με τα mount, PID ή user namespaces, το IPC namespace συζητείται συχνά λιγότερο, αλλά αυτό δεν σημαίνει ότι είναι άνευ σημασίας. Η shared memory και οι σχετικοί IPC mechanisms μπορεί να περιέχουν ιδιαίτερα χρήσιμο state. Αν το IPC namespace του host είναι εκτεθειμένο, το workload μπορεί να αποκτήσει ορατότητα σε objects συντονισμού μεταξύ processes ή σε data που δεν προορίζονταν ποτέ να περάσουν τα όρια του container.

## Λειτουργία

Όταν το runtime δημιουργεί ένα νέο IPC namespace, το process αποκτά το δικό του απομονωμένο σύνολο από IPC identifiers. Αυτό σημαίνει ότι commands όπως το `ipcs` εμφανίζουν μόνο τα objects που είναι διαθέσιμα σε αυτό το namespace. Αν αντίθετα το container συνδεθεί στο IPC namespace του host, αυτά τα objects γίνονται μέρος μιας κοινόχρηστης global view.

Αυτό είναι ιδιαίτερα σημαντικό σε περιβάλλοντα όπου applications ή services χρησιμοποιούν εντατικά shared memory. Ακόμη και όταν το container δεν μπορεί να πραγματοποιήσει άμεσα breakout μόνο μέσω IPC, το namespace μπορεί να προκαλέσει leak πληροφοριών ή να επιτρέψει cross-process interference, κάτι που μπορεί να βοηθήσει ουσιαστικά μια μεταγενέστερη επίθεση.

## Εργαστήριο

Μπορείτε να δημιουργήσετε ένα private IPC namespace με:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Και συγκρίνετε τη συμπεριφορά κατά την εκτέλεση με:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Χρήση κατά το Runtime

Τα Docker και Podman απομονώνουν το IPC από προεπιλογή. Το Kubernetes συνήθως παρέχει στο Pod το δικό του IPC namespace, το οποίο είναι κοινόχρηστο μεταξύ των containers του ίδιου Pod, αλλά όχι από προεπιλογή με το host. Η κοινή χρήση του host IPC είναι δυνατή, αλλά θα πρέπει να αντιμετωπίζεται ως ουσιαστική μείωση της απομόνωσης και όχι ως μια ασήμαντη επιλογή του runtime.

## Λανθασμένες ρυθμίσεις

Το προφανές λάθος είναι το `--ipc=host` ή το `hostIPC: true`. Αυτό μπορεί να γίνει για συμβατότητα με legacy software ή για ευκολία, αλλά αλλάζει σημαντικά το trust model. Ένα ακόμη συχνό ζήτημα είναι η απλή παράβλεψη του IPC, επειδή φαίνεται λιγότερο δραματικό από το host PID ή το host networking. Στην πραγματικότητα, αν το workload διαχειρίζεται browsers, databases, scientific workloads ή άλλο software που χρησιμοποιεί εκτενώς shared memory, η επιφάνεια IPC μπορεί να είναι ιδιαίτερα σημαντική.

## Abuse

Όταν το host IPC είναι κοινόχρηστο, ένας attacker μπορεί να επιθεωρήσει ή να παρέμβει σε αντικείμενα shared memory, να αποκτήσει νέα εικόνα για τη συμπεριφορά του host ή γειτονικών workloads ή να συνδυάσει τις πληροφορίες που έμαθε εκεί με visibility διεργασιών και δυνατότητες τύπου ptrace. Η κοινή χρήση του IPC αποτελεί συχνά supporting weakness και όχι το πλήρες breakout path, αλλά οι supporting weaknesses είναι σημαντικές επειδή συντομεύουν και σταθεροποιούν τα πραγματικά attack chains.

Το πρώτο χρήσιμο βήμα είναι να γίνει enumeration των IPC objects που είναι ορατά:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Εάν το IPC namespace του host είναι shared, μεγάλα shared-memory segments ή ενδιαφέροντες owners αντικειμένων μπορούν να αποκαλύψουν άμεσα τη συμπεριφορά της εφαρμογής:
```bash
ipcs -m -p
ipcs -q -p
```
Σε ορισμένα περιβάλλοντα, τα ίδια τα περιεχόμενα του `/dev/shm` κάνουν leak filenames, artifacts ή tokens που αξίζει να ελεγχθούν:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Η κοινή χρήση IPC σπάνια παρέχει από μόνη της άμεσο host root, αλλά μπορεί να εκθέσει κανάλια δεδομένων και συντονισμού που κάνουν τις μεταγενέστερες επιθέσεις σε processes πολύ ευκολότερες.

### Πλήρες Παράδειγμα: Ανάκτηση Μυστικών από το `/dev/shm`

Το πιο ρεαλιστικό σενάριο πλήρους abuse αφορά την κλοπή δεδομένων και όχι το άμεσο escape. Αν εκτεθεί το host IPC ή μια ευρεία διάταξη shared memory, ορισμένα ευαίσθητα artifacts μπορεί μερικές φορές να ανακτηθούν απευθείας:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Επίπτωση:

- εξαγωγή secrets ή session material που έχουν παραμείνει σε shared memory
- εικόνα των εφαρμογών που είναι ενεργές αυτήν τη στιγμή στο host
- καλύτερη στόχευση για μεταγενέστερες επιθέσεις μέσω PID-namespace ή ptrace

Το IPC sharing επομένως είναι προτιμότερο να θεωρείται **amplifier επιθέσεων** παρά standalone primitive για host-escape.

## Έλεγχοι

Οι παρακάτω εντολές αποσκοπούν στο να δείξουν αν το workload έχει private IPC view, αν είναι ορατά meaningful αντικείμενα shared-memory ή message και αν το ίδιο το `/dev/shm` εκθέτει χρήσιμα artifacts.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Τι είναι ενδιαφέρον εδώ:

- Αν το `ipcs -a` αποκαλύπτει objects που ανήκουν σε μη αναμενόμενους χρήστες ή services, το namespace ενδέχεται να μην είναι τόσο isolated όσο αναμενόταν.
- Μεγάλα ή ασυνήθιστα segments κοινόχρηστης μνήμης συχνά αξίζει να διερευνηθούν περαιτέρω.
- Ένα ευρύ `/dev/shm` mount δεν αποτελεί αυτόματα bug, αλλά σε ορισμένα περιβάλλοντα κάνει leak filenames, artifacts και προσωρινά secrets.

Το IPC σπάνια λαμβάνει τόση προσοχή όσο οι μεγαλύτεροι τύποι namespace, όμως σε περιβάλλοντα που το χρησιμοποιούν εκτενώς, η κοινή χρήση του με το host αποτελεί ξεκάθαρα απόφαση ασφάλειας.
{{#include ../../../../../banners/hacktricks-training.md}}
