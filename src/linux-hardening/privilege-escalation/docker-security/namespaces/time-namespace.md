# Χρονικό Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Το χρονικό namespace στο Linux επιτρέπει για ανά namespace offsets στους συστήματος μονοτονικούς και χρόνους εκκίνησης ρολόγια. Χρησιμοποιείται συνήθως σε κοντέινερ Linux για να αλλάξει την ημερομηνία/ώρα εντός ενός κοντέινερ και να ρυθμίσει τα ρολόγια μετά την αποκατάσταση από ένα checkpoint ή snapshot.

## Εργαστήριο:

### Δημιουργία διαφορετικών Namespaces

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Με την τοποθέτηση μιας νέας παρουσίας του συστήματος αρχείων `/proc` αν χρησιμοποιήσετε την παράμετρο `--mount-proc`, διασφαλίζετε ότι η νέα mount namespace έχει μια **ακριβή και απομονωμένη άποψη των πληροφοριών διαδικασίας που είναι συγκεκριμένες για αυτή τη namespace**.

<details>

<summary>Σφάλμα: bash: fork: Cannot allocate memory</summary>

Όταν εκτελείται το `unshare` χωρίς την επιλογή `-f`, προκύπτει ένα σφάλμα λόγω του τρόπου που το Linux χειρίζεται τις νέες PID (Process ID) namespaces. Οι βασικές λεπτομέρειες και η λύση περιγράφονται παρακάτω:

1. **Εξήγηση Προβλήματος**:

- Ο πυρήνας του Linux επιτρέπει σε μια διαδικασία να δημιουργήσει νέες namespaces χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διαδικασία που ξεκινά τη δημιουργία μιας νέας PID namespace (αναφερόμενη ως η διαδικασία "unshare") δεν εισέρχεται στη νέα namespace; μόνο οι παιδικές της διαδικασίες το κάνουν.
- Η εκτέλεση `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διαδικασία με το `unshare`. Ως εκ τούτου, το `/bin/bash` και οι παιδικές του διαδικασίες βρίσκονται στην αρχική PID namespace.
- Η πρώτη παιδική διαδικασία του `/bin/bash` στη νέα namespace γίνεται PID 1. Όταν αυτή η διαδικασία τερματίσει, ενεργοποιεί την καθαριότητα της namespace αν δεν υπάρχουν άλλες διαδικασίες, καθώς το PID 1 έχει τον ειδικό ρόλο της υιοθέτησης ορφανών διαδικασιών. Ο πυρήνας του Linux θα απενεργοποιήσει στη συνέχεια την κατανομή PID σε αυτή τη namespace.

2. **Συνέπεια**:

- Η έξοδος του PID 1 σε μια νέα namespace οδηγεί στον καθαρισμό της σημαίας `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα τη αποτυχία της συνάρτησης `alloc_pid` να κατανεμηθεί ένα νέο PID κατά τη δημιουργία μιας νέας διαδικασίας, παράγοντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα μπορεί να επιλυθεί χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να δημιουργήσει μια νέα διαδικασία μετά τη δημιουργία της νέας PID namespace.
- Η εκτέλεση `%unshare -fp /bin/bash%` διασφαλίζει ότι η εντολή `unshare` γίνεται PID 1 στη νέα namespace. Το `/bin/bash` και οι παιδικές του διαδικασίες είναι τότε ασφαλώς περιορισμένες μέσα σε αυτή τη νέα namespace, αποτρέποντας την πρόωρη έξοδο του PID 1 και επιτρέποντας την κανονική κατανομή PID.

Διασφαλίζοντας ότι το `unshare` εκτελείται με την επιλογή `-f`, η νέα PID namespace διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και τις υπο-διαδικασίες του να λειτουργούν χωρίς να αντιμετωπίζουν το σφάλμα κατανομής μνήμης.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Έλεγχος σε ποιο namespace βρίσκεται η διαδικασία σας
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Βρείτε όλα τα Time namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Είσοδος σε ένα Time namespace
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
