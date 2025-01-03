# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Ένα mount namespace είναι μια δυνατότητα του πυρήνα Linux που παρέχει απομόνωση των σημείων προσάρτησης του συστήματος αρχείων που βλέπει μια ομάδα διεργασιών. Κάθε mount namespace έχει το δικό του σύνολο σημείων προσάρτησης του συστήματος αρχείων, και **οι αλλαγές στα σημεία προσάρτησης σε ένα namespace δεν επηρεάζουν άλλα namespaces**. Αυτό σημαίνει ότι οι διεργασίες που εκτελούνται σε διαφορετικά mount namespaces μπορούν να έχουν διαφορετικές απόψεις της ιεραρχίας του συστήματος αρχείων.

Τα mount namespaces είναι ιδιαίτερα χρήσιμα στην κοντεντοποίηση, όπου κάθε κοντέινερ θα πρέπει να έχει το δικό του σύστημα αρχείων και ρύθμιση, απομονωμένο από άλλα κοντέινερ και το σύστημα φιλοξενίας.

### How it works:

1. Όταν δημιουργείται ένα νέο mount namespace, αρχικοποιείται με μια **αντίγραφο των σημείων προσάρτησης από το γονικό namespace**. Αυτό σημαίνει ότι, κατά τη δημιουργία, το νέο namespace μοιράζεται την ίδια άποψη του συστήματος αρχείων με το γονικό του. Ωστόσο, οποιεσδήποτε επακόλουθες αλλαγές στα σημεία προσάρτησης εντός του namespace δεν θα επηρεάσουν το γονικό ή άλλα namespaces.
2. Όταν μια διεργασία τροποποιεί ένα σημείο προσάρτησης εντός του namespace της, όπως η προσάρτηση ή η αποσύνδεση ενός συστήματος αρχείων, η **αλλαγή είναι τοπική σε εκείνο το namespace** και δεν επηρεάζει άλλα namespaces. Αυτό επιτρέπει σε κάθε namespace να έχει τη δική του ανεξάρτητη ιεραρχία συστήματος αρχείων.
3. Οι διεργασίες μπορούν να μετακινηθούν μεταξύ namespaces χρησιμοποιώντας την κλήση συστήματος `setns()`, ή να δημιουργήσουν νέα namespaces χρησιμοποιώντας τις κλήσεις συστήματος `unshare()` ή `clone()` με την σημαία `CLONE_NEWNS`. Όταν μια διεργασία μετακινείται σε ένα νέο namespace ή δημιουργεί ένα, θα αρχίσει να χρησιμοποιεί τα σημεία προσάρτησης που σχετίζονται με εκείνο το namespace.
4. **Οι περιγραφείς αρχείων και οι inodes μοιράζονται μεταξύ namespaces**, πράγμα που σημαίνει ότι αν μια διεργασία σε ένα namespace έχει έναν ανοιχτό περιγραφέα αρχείου που δείχνει σε ένα αρχείο, μπορεί να **περάσει αυτόν τον περιγραφέα αρχείου** σε μια διεργασία σε άλλο namespace, και **και οι δύο διεργασίες θα έχουν πρόσβαση στο ίδιο αρχείο**. Ωστόσο, η διαδρομή του αρχείου μπορεί να μην είναι η ίδια και στα δύο namespaces λόγω διαφορών στα σημεία προσάρτησης.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Με την τοποθέτηση μιας νέας παρουσίας του συστήματος αρχείων `/proc` αν χρησιμοποιήσετε την παράμετρο `--mount-proc`, διασφαλίζετε ότι το νέο mount namespace έχει μια **ακριβή και απομονωμένη άποψη των πληροφοριών διαδικασίας που είναι συγκεκριμένες για αυτό το namespace**.

<details>

<summary>Σφάλμα: bash: fork: Cannot allocate memory</summary>

Όταν εκτελείται το `unshare` χωρίς την επιλογή `-f`, προκύπτει ένα σφάλμα λόγω του τρόπου που το Linux χειρίζεται τα νέα PID (Process ID) namespaces. Οι βασικές λεπτομέρειες και η λύση περιγράφονται παρακάτω:

1. **Εξήγηση Προβλήματος**:

- Ο πυρήνας του Linux επιτρέπει σε μια διαδικασία να δημιουργεί νέα namespaces χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διαδικασία που ξεκινά τη δημιουργία ενός νέου PID namespace (αναφερόμενη ως η διαδικασία "unshare") δεν εισέρχεται στο νέο namespace; μόνο οι παιδικές της διαδικασίες το κάνουν.
- Η εκτέλεση `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διαδικασία με το `unshare`. Κατά συνέπεια, το `/bin/bash` και οι παιδικές του διαδικασίες βρίσκονται στο αρχικό PID namespace.
- Η πρώτη παιδική διαδικασία του `/bin/bash` στο νέο namespace γίνεται PID 1. Όταν αυτή η διαδικασία τερματίσει, ενεργοποιεί την καθαριότητα του namespace αν δεν υπάρχουν άλλες διαδικασίες, καθώς το PID 1 έχει τον ειδικό ρόλο της υιοθέτησης ορφανών διαδικασιών. Ο πυρήνας του Linux θα απενεργοποιήσει στη συνέχεια την κατανομή PID σε αυτό το namespace.

2. **Συνέπεια**:

- Η έξοδος του PID 1 σε ένα νέο namespace οδηγεί στον καθαρισμό της σημαίας `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα τη αποτυχία της συνάρτησης `alloc_pid` να κατανεμηθεί ένα νέο PID κατά τη δημιουργία μιας νέας διαδικασίας, παράγοντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα μπορεί να επιλυθεί χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να δημιουργήσει μια νέα διαδικασία μετά τη δημιουργία του νέου PID namespace.
- Η εκτέλεση `%unshare -fp /bin/bash%` διασφαλίζει ότι η εντολή `unshare` γίνεται PID 1 στο νέο namespace. Το `/bin/bash` και οι παιδικές του διαδικασίες είναι στη συνέχεια ασφαλώς περιορισμένες μέσα σε αυτό το νέο namespace, αποτρέποντας την πρόωρη έξοδο του PID 1 και επιτρέποντας την κανονική κατανομή PID.

Διασφαλίζοντας ότι το `unshare` εκτελείται με την επιλογή `-f`, το νέο PID namespace διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και τις υπο-διαδικασίες του να λειτουργούν χωρίς να αντιμετωπίζουν το σφάλμα κατανομής μνήμης.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Ελέγξτε ποιο namespace είναι η διαδικασία σας
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Βρείτε όλα τα Mount namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Είσοδος σε ένα Mount namespace
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Επίσης, μπορείτε να **μπείτε σε άλλη διαδικασία namespace μόνο αν είστε root**. Και **δεν μπορείτε** να **μπείτε** σε άλλη namespace **χωρίς έναν περιγραφέα** που να δείχνει σε αυτήν (όπως το `/proc/self/ns/mnt`).

Επειδή οι νέες προσβάσεις είναι προσβάσιμες μόνο εντός της namespace, είναι πιθανό μια namespace να περιέχει ευαίσθητες πληροφορίες που μπορούν να είναι προσβάσιμες μόνο από αυτήν.

### Mount something
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Αναφορές

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
