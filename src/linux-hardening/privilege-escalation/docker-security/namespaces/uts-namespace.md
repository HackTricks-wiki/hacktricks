# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Ένα UTS (UNIX Time-Sharing System) namespace είναι μια δυνατότητα του πυρήνα Linux που παρέχει **απομόνωση δύο αναγνωριστικών συστήματος**: το **hostname** και το **NIS** (Network Information Service) domain name. Αυτή η απομόνωση επιτρέπει σε κάθε UTS namespace να έχει το **δικό του ανεξάρτητο hostname και NIS domain name**, το οποίο είναι ιδιαίτερα χρήσιμο σε σενάρια κοντεϊνεροποίησης όπου κάθε κοντέινερ θα πρέπει να εμφανίζεται ως ξεχωριστό σύστημα με το δικό του hostname.

### How it works:

1. Όταν δημιουργείται ένα νέο UTS namespace, ξεκινά με μια **αντίγραφο του hostname και του NIS domain name από το γονικό namespace**. Αυτό σημαίνει ότι, κατά τη δημιουργία, το νέο namespace **μοιράζεται τα ίδια αναγνωριστικά με το γονικό του**. Ωστόσο, οποιεσδήποτε επακόλουθες αλλαγές στο hostname ή το NIS domain name εντός του namespace δεν θα επηρεάσουν άλλα namespaces.
2. Οι διεργασίες εντός ενός UTS namespace **μπορούν να αλλάξουν το hostname και το NIS domain name** χρησιμοποιώντας τις κλήσεις συστήματος `sethostname()` και `setdomainname()`, αντίστοιχα. Αυτές οι αλλαγές είναι τοπικές στο namespace και δεν επηρεάζουν άλλα namespaces ή το σύστημα φιλοξενίας.
3. Οι διεργασίες μπορούν να μετακινηθούν μεταξύ namespaces χρησιμοποιώντας την κλήση συστήματος `setns()` ή να δημιουργήσουν νέα namespaces χρησιμοποιώντας τις κλήσεις συστήματος `unshare()` ή `clone()` με την σημαία `CLONE_NEWUTS`. Όταν μια διεργασία μετακινείται σε ένα νέο namespace ή δημιουργεί ένα, θα αρχίσει να χρησιμοποιεί το hostname και το NIS domain name που σχετίζονται με αυτό το namespace.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Με την τοποθέτηση μιας νέας παρουσίας του συστήματος αρχείων `/proc` αν χρησιμοποιήσετε την παράμετρο `--mount-proc`, διασφαλίζετε ότι το νέο mount namespace έχει μια **ακριβή και απομονωμένη άποψη των πληροφοριών διαδικασίας που είναι συγκεκριμένες για αυτό το namespace**.

<details>

<summary>Σφάλμα: bash: fork: Cannot allocate memory</summary>

Όταν εκτελείται το `unshare` χωρίς την επιλογή `-f`, προκύπτει ένα σφάλμα λόγω του τρόπου που το Linux χειρίζεται τα νέα PID (Process ID) namespaces. Οι βασικές λεπτομέρειες και η λύση περιγράφονται παρακάτω:

1. **Εξήγηση Προβλήματος**:

- Ο πυρήνας του Linux επιτρέπει σε μια διαδικασία να δημιουργήσει νέα namespaces χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διαδικασία που ξεκινά τη δημιουργία ενός νέου PID namespace (αναφερόμενη ως η διαδικασία "unshare") δεν εισέρχεται στο νέο namespace; μόνο οι παιδικές της διαδικασίες το κάνουν.
- Η εκτέλεση `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διαδικασία με το `unshare`. Κατά συνέπεια, το `/bin/bash` και οι παιδικές του διαδικασίες βρίσκονται στο αρχικό PID namespace.
- Η πρώτη παιδική διαδικασία του `/bin/bash` στο νέο namespace γίνεται PID 1. Όταν αυτή η διαδικασία τερματίσει, ενεργοποιεί την καθαριότητα του namespace αν δεν υπάρχουν άλλες διαδικασίες, καθώς το PID 1 έχει τον ειδικό ρόλο της υιοθέτησης ορφανών διαδικασιών. Ο πυρήνας του Linux θα απενεργοποιήσει στη συνέχεια την κατανομή PID σε αυτό το namespace.

2. **Συνέπεια**:

- Η έξοδος του PID 1 σε ένα νέο namespace οδηγεί στον καθαρισμό της σημαίας `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα η συνάρτηση `alloc_pid` να αποτύχει να κατανοήσει ένα νέο PID κατά τη δημιουργία μιας νέας διαδικασίας, παράγοντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα μπορεί να επιλυθεί χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να δημιουργήσει μια νέα διαδικασία μετά τη δημιουργία του νέου PID namespace.
- Η εκτέλεση `%unshare -fp /bin/bash%` διασφαλίζει ότι η εντολή `unshare` γίνεται PID 1 στο νέο namespace. Το `/bin/bash` και οι παιδικές του διαδικασίες είναι στη συνέχεια ασφαλώς περιορισμένες μέσα σε αυτό το νέο namespace, αποτρέποντας την πρόωρη έξοδο του PID 1 και επιτρέποντας την κανονική κατανομή PID.

Διασφαλίζοντας ότι το `unshare` εκτελείται με την επιλογή `-f`, το νέο PID namespace διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και τις υπο-διαδικασίες του να λειτουργούν χωρίς να αντιμετωπίζουν το σφάλμα κατανομής μνήμης.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Ελέγξτε σε ποιο namespace βρίσκεται η διαδικασία σας
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Βρείτε όλα τα UTS namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Είσοδος σε ένα UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
