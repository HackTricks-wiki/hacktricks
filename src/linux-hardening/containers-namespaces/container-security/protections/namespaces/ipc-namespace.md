# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το IPC namespace απομονώνει τα **System V IPC objects** και τα **POSIX message queues**. Αυτό περιλαμβάνει shared memory segments, semaphores και message queues που διαφορετικά θα ήταν ορατά μεταξύ άσχετων processes στο host. Πρακτικά, αυτό αποτρέπει ένα container από το να συνδέεται ανεμπόδιστα σε IPC objects που ανήκουν σε άλλα workloads ή στο host.

Σε σύγκριση με τα mount, PID ή user namespaces, το IPC namespace συζητείται συχνά λιγότερο, όμως αυτό δεν πρέπει να συγχέεται με την έλλειψη σημασίας του. Η shared memory και οι σχετικοί μηχανισμοί IPC μπορεί να περιέχουν ιδιαίτερα χρήσιμο state. Αν το host IPC namespace είναι εκτεθειμένο, το workload μπορεί να αποκτήσει ορατότητα σε inter-process coordination objects ή δεδομένα που δεν προορίζονταν ποτέ να περάσουν τα όρια του container.

## Λειτουργία

Όταν το runtime δημιουργεί ένα νέο IPC namespace, το process αποκτά το δικό του απομονωμένο σύνολο από IPC identifiers. Αυτό σημαίνει ότι εντολές όπως η `ipcs` εμφανίζουν μόνο τα objects που είναι διαθέσιμα σε αυτό το namespace. Αν, αντίθετα, το container συνδεθεί στο host IPC namespace, αυτά τα objects γίνονται μέρος μιας κοινόχρηστης global view.

Αυτό έχει ιδιαίτερη σημασία σε environments όπου οι εφαρμογές ή τα services χρησιμοποιούν εκτενώς shared memory. Ακόμη και όταν το container δεν μπορεί να πραγματοποιήσει άμεσο breakout μόνο μέσω IPC, το namespace μπορεί να διαρρεύσει πληροφορίες ή να επιτρέψει cross-process interference που βοηθά ουσιαστικά μια μεταγενέστερη επίθεση.

## Lab

Μπορείτε να δημιουργήσετε ένα private IPC namespace με:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Και συγκρίνετε τη συμπεριφορά κατά το runtime με:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Χρήση στο Runtime

Τα Docker και Podman απομονώνουν το IPC από προεπιλογή. Το Kubernetes συνήθως δίνει στο Pod το δικό του IPC namespace, το οποίο είναι shared από τα containers του ίδιου Pod, αλλά όχι από προεπιλογή με το host. Η κοινή χρήση του host IPC είναι δυνατή, αλλά θα πρέπει να αντιμετωπίζεται ως ουσιαστική μείωση της απομόνωσης και όχι ως μια ασήμαντη επιλογή του runtime.

## Misconfigurations

Το προφανές λάθος είναι το `--ipc=host` ή το `hostIPC: true`. Αυτό μπορεί να γίνεται για συμβατότητα με legacy software ή για ευκολία, αλλά αλλάζει σημαντικά το trust model. Ένα ακόμη συχνό ζήτημα είναι η απλή παράβλεψη του IPC, επειδή φαίνεται λιγότερο δραματικό από το host PID ή το host networking. Στην πραγματικότητα, αν το workload χειρίζεται browsers, databases, scientific workloads ή άλλο software που χρησιμοποιεί σε μεγάλο βαθμό shared memory, το IPC surface μπορεί να είναι ιδιαίτερα σημαντικό.

## Abuse

Όταν γίνεται shared το host IPC, ένας attacker μπορεί να επιθεωρήσει ή να παρέμβει σε shared memory objects, να αποκτήσει νέες πληροφορίες σχετικά με τη συμπεριφορά του host ή γειτονικών workloads ή να συνδυάσει τις πληροφορίες που αποκτήθηκαν εκεί με process visibility και ptrace-style capabilities. Το IPC sharing αποτελεί συχνά supporting weakness και όχι το πλήρες breakout path, όμως οι supporting weaknesses είναι σημαντικές επειδή συντομεύουν και σταθεροποιούν τα πραγματικά attack chains.

Το πρώτο χρήσιμο βήμα είναι να γίνει enumeration των IPC objects που είναι ορατά συνολικά:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Εάν το IPC namespace του host είναι κοινόχρηστο, μεγάλα shared-memory segments ή ενδιαφέροντες ιδιοκτήτες αντικειμένων μπορούν να αποκαλύψουν άμεσα τη συμπεριφορά της εφαρμογής:
```bash
ipcs -m -p
ipcs -q -p
```
Σε ορισμένα περιβάλλοντα, τα ίδια τα περιεχόμενα του `/dev/shm` leak filenames, artifacts ή tokens που αξίζει να ελεγχθούν:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Η κοινή χρήση IPC σπάνια παρέχει από μόνη της άμεσο host root, αλλά μπορεί να εκθέσει κανάλια δεδομένων και συντονισμού που κάνουν τις μεταγενέστερες επιθέσεις σε processes πολύ ευκολότερες.

### Πλήρες παράδειγμα: Ανάκτηση μυστικών από το `/dev/shm`

Η πιο ρεαλιστική πλήρης περίπτωση abuse αφορά την κλοπή δεδομένων και όχι το άμεσο escape. Αν εκτεθεί το host IPC ή μια ευρεία διάταξη shared memory, ενδέχεται να ανακτηθούν απευθείας ευαίσθητα artifacts:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Επιπτώσεις:

- εξαγωγή secrets ή session material που έχουν παραμείνει σε shared memory
- insight στις εφαρμογές που είναι ενεργές αυτήν τη στιγμή στο host
- καλύτερη στόχευση για μεταγενέστερες επιθέσεις βασισμένες σε PID-namespace ή ptrace

Το IPC sharing πρέπει επομένως να θεωρείται περισσότερο **ενισχυτής επιθέσεων** παρά αυτοτελής primitive για host-escape.

## Έλεγχοι

Αυτές οι εντολές έχουν ως στόχο να διαπιστώσουν αν το workload διαθέτει ιδιωτική προβολή IPC, αν είναι ορατά σημαντικά αντικείμενα shared memory ή message, και αν το ίδιο το `/dev/shm` εκθέτει χρήσιμα artifacts.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Τι είναι ενδιαφέρον εδώ:

- Αν το `ipcs -a` αποκαλύπτει αντικείμενα που ανήκουν σε μη αναμενόμενους χρήστες ή services, το namespace μπορεί να μην είναι τόσο απομονωμένο όσο αναμενόταν.
- Τα μεγάλα ή ασυνήθιστα segments shared memory συχνά αξίζει να διερευνηθούν περαιτέρω.
- Ένα ευρύ `/dev/shm` mount δεν αποτελεί αυτόματα bug, αλλά σε ορισμένα περιβάλλοντα κάνει leak filenames, artifacts και προσωρινά secrets.

Το IPC σπάνια λαμβάνει τόση προσοχή όσο οι μεγαλύτεροι τύποι namespace, αλλά σε περιβάλλοντα που το χρησιμοποιούν εκτενώς, η κοινή χρήση του με το host αποτελεί ξεκάθαρα απόφαση ασφάλειας.

{{#include ../../../../../banners/hacktricks-training.md}}
