# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Ένα IPC (Inter-Process Communication) namespace είναι μια δυνατότητα του πυρήνα Linux που παρέχει **απομόνωση** των αντικειμένων IPC System V, όπως οι ουρές μηνυμάτων, τα τμήματα κοινής μνήμης και οι σηματοδότες. Αυτή η απομόνωση διασφαλίζει ότι οι διαδικασίες σε **διαφορετικά IPC namespaces δεν μπορούν να έχουν άμεση πρόσβαση ή να τροποποιήσουν τα αντικείμενα IPC των άλλων**, παρέχοντας ένα επιπλέον επίπεδο ασφάλειας και ιδιωτικότητας μεταξύ των ομάδων διαδικασιών.

### How it works:

1. Όταν δημιουργείται ένα νέο IPC namespace, ξεκινά με ένα **εντελώς απομονωμένο σύνολο αντικειμένων IPC System V**. Αυτό σημαίνει ότι οι διαδικασίες που εκτελούνται στο νέο IPC namespace δεν μπορούν να έχουν πρόσβαση ή να παρεμβαίνουν στα αντικείμενα IPC σε άλλα namespaces ή στο σύστημα υποδοχής από προεπιλογή.
2. Τα αντικείμενα IPC που δημιουργούνται εντός ενός namespace είναι ορατά και **προσβάσιμα μόνο από διαδικασίες εντός αυτού του namespace**. Κάθε αντικείμενο IPC αναγνωρίζεται από ένα μοναδικό κλειδί εντός του namespace του. Αν και το κλειδί μπορεί να είναι ταυτόσημο σε διαφορετικά namespaces, τα ίδια τα αντικείμενα είναι απομονωμένα και δεν μπορούν να προσπελαστούν μεταξύ των namespaces.
3. Οι διαδικασίες μπορούν να μετακινούνται μεταξύ namespaces χρησιμοποιώντας την κλήση συστήματος `setns()` ή να δημιουργούν νέα namespaces χρησιμοποιώντας τις κλήσεις συστήματος `unshare()` ή `clone()` με την σημαία `CLONE_NEWIPC`. Όταν μια διαδικασία μετακινείται σε ένα νέο namespace ή δημιουργεί ένα, θα αρχίσει να χρησιμοποιεί τα αντικείμενα IPC που σχετίζονται με αυτό το namespace.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Με την τοποθέτηση μιας νέας παρουσίας του συστήματος αρχείων `/proc` αν χρησιμοποιήσετε την παράμετρο `--mount-proc`, διασφαλίζετε ότι η νέα mount namespace έχει μια **ακριβή και απομονωμένη άποψη των πληροφοριών διαδικασίας που είναι συγκεκριμένες για αυτή τη namespace**.

<details>

<summary>Σφάλμα: bash: fork: Cannot allocate memory</summary>

Όταν εκτελείται το `unshare` χωρίς την επιλογή `-f`, προκύπτει ένα σφάλμα λόγω του τρόπου που το Linux διαχειρίζεται τις νέες PID (Process ID) namespaces. Οι βασικές λεπτομέρειες και η λύση περιγράφονται παρακάτω:

1. **Εξήγηση Προβλήματος**:

- Ο πυρήνας του Linux επιτρέπει σε μια διαδικασία να δημιουργεί νέες namespaces χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διαδικασία που ξεκινά τη δημιουργία μιας νέας PID namespace (αναφερόμενη ως η διαδικασία "unshare") δεν εισέρχεται στη νέα namespace; μόνο οι παιδικές της διαδικασίες το κάνουν.
- Η εκτέλεση `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διαδικασία με το `unshare`. Ως εκ τούτου, το `/bin/bash` και οι παιδικές του διαδικασίες βρίσκονται στην αρχική PID namespace.
- Η πρώτη παιδική διαδικασία του `/bin/bash` στη νέα namespace γίνεται PID 1. Όταν αυτή η διαδικασία τερματίσει, ενεργοποιεί την καθαριότητα της namespace αν δεν υπάρχουν άλλες διαδικασίες, καθώς το PID 1 έχει τον ειδικό ρόλο της υιοθέτησης ορφανών διαδικασιών. Ο πυρήνας του Linux θα απενεργοποιήσει στη συνέχεια την κατανομή PID σε αυτή τη namespace.

2. **Συνέπεια**:

- Η έξοδος του PID 1 σε μια νέα namespace οδηγεί στον καθαρισμό της σημαίας `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα η συνάρτηση `alloc_pid` να αποτύχει να κατανοήσει ένα νέο PID κατά τη δημιουργία μιας νέας διαδικασίας, παράγοντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα μπορεί να επιλυθεί χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να δημιουργήσει μια νέα διαδικασία μετά τη δημιουργία της νέας PID namespace.
- Η εκτέλεση `%unshare -fp /bin/bash%` διασφαλίζει ότι η εντολή `unshare` γίνεται PID 1 στη νέα namespace. Το `/bin/bash` και οι παιδικές του διαδικασίες είναι στη συνέχεια ασφαλώς περιορισμένες μέσα σε αυτή τη νέα namespace, αποτρέποντας την πρόωρη έξοδο του PID 1 και επιτρέποντας την κανονική κατανομή PID.

Διασφαλίζοντας ότι το `unshare` εκτελείται με την επιλογή `-f`, η νέα PID namespace διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και τις υπο-διαδικασίες του να λειτουργούν χωρίς να συναντούν το σφάλμα κατανομής μνήμης.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Ελέγξτε σε ποιο namespace βρίσκεται η διαδικασία σας
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Βρείτε όλα τα IPC namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Είσοδος σε ένα IPC namespace
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Επίσης, μπορείτε να **μπείτε σε άλλη διαδικασία namespace μόνο αν είστε root**. Και **δεν μπορείτε** να **μπείτε** σε άλλη namespace **χωρίς έναν περιγραφέα** που να δείχνει σε αυτήν (όπως το `/proc/self/ns/net`).

### Δημιουργία αντικειμένου IPC
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Αναφορές

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
