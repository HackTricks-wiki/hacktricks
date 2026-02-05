# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Ένας UTS (UNIX Time-Sharing System) namespace είναι μια δυνατότητα του Linux kernel που παρέχει α**πομόνωση δύο συστημικών ταυτοτήτων**: την **hostname** και το **NIS** (Network Information Service) domain name. Αυτή η απομόνωση επιτρέπει σε κάθε UTS namespace να έχει το **δικό του ανεξάρτητο hostname και NIS domain name**, κάτι που είναι ιδιαίτερα χρήσιμο σε σενάρια containerization όπου κάθε container πρέπει να εμφανίζεται ως ξεχωριστό σύστημα με το δικό του hostname.

### Πώς λειτουργεί:

1. Όταν δημιουργείται ένα νέο UTS namespace, ξεκινά με ένα **αντίγραφο του hostname και του NIS domain name από το γονικό namespace**. Αυτό σημαίνει ότι, κατά τη δημιουργία, το νέο namespace μ**οιράζεται τα ίδια αναγνωριστικά με το γονικό του**. Ωστόσο, οποιεσδήποτε μεταγενέστερες αλλαγές στο hostname ή στο NIS domain name εντός του namespace δεν θα επηρεάσουν άλλα namespaces.
2. Διεργασίες εντός ενός UTS namespace μπορούν να αλλάξουν το hostname και το NIS domain name χρησιμοποιώντας τις κλήσεις συστήματος `sethostname()` και `setdomainname()`, αντίστοιχα. Αυτές οι αλλαγές είναι τοπικές στο namespace και δεν επηρεάζουν άλλα namespaces ή το host system.
3. Διεργασίες μπορούν να μετακινηθούν μεταξύ namespaces χρησιμοποιώντας την κλήση `setns()` ή να δημιουργήσουν νέα namespaces χρησιμοποιώντας τις `unshare()` ή `clone()` system calls με τη σημαία `CLONE_NEWUTS`. Όταν μια διεργασία μεταφερθεί σε ένα νέο namespace ή δημιουργήσει ένα, θα αρχίσει να χρησιμοποιεί το hostname και το NIS domain name που σχετίζονται με εκείνο το namespace.

## Εργαστήριο:

### Δημιουργία διαφορετικών Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **ακριβή και απομονωμένη εικόνα των πληροφοριών διεργασιών συγκεκριμένων για αυτό το namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Επεξήγηση του προβλήματος**:

- Ο πυρήνας του Linux επιτρέπει σε μια διεργασία να δημιουργεί νέα namespaces χρησιμοποιώντας το system call `unshare`. Ωστόσο, η διεργασία που ξεκινά τη δημιουργία ενός νέου PID namespace (αναφερόμενη ως η διεργασία "unshare") δεν εισέρχεται στο νέο namespace· μόνο οι θυγατρικές της διεργασίες το κάνουν.
- Το τρέξιμο %unshare -p /bin/bash% ξεκινάει το `/bin/bash` στην ίδια διεργασία με το `unshare`. Κατά συνέπεια, το `/bin/bash` και οι θυγατρικές διεργασίες του βρίσκονται στο αρχικό PID namespace.
- Η πρώτη θυγατρική διεργασία του `/bin/bash` στο νέο namespace καταλαμβάνει το PID 1. Όταν αυτή η διεργασία τερματίζει, ενεργοποιεί τον καθαρισμό του namespace αν δεν υπάρχουν άλλες διεργασίες, καθώς το PID 1 έχει τον ειδικό ρόλο της υιοθεσίας ορφανών διεργασιών. Ο πυρήνας του Linux τότε θα απενεργοποιήσει την κατανομή PID σε αυτό το namespace.

2. **Συνέπεια**:

- Ο τερματισμός του PID 1 σε ένα νέο namespace οδηγεί στον καθαρισμό της σημαίας `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα η συνάρτηση `alloc_pid` να αποτύχει στην εκχώρηση νέου PID κατά τη δημιουργία μιας νέας διεργασίας, δημιουργώντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα επιλύεται χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να κάνει fork μια νέα διεργασία μετά τη δημιουργία του νέου PID namespace.
- Η εκτέλεση %unshare -fp /bin/bash% διασφαλίζει ότι η εντολή `unshare` η ίδια γίνεται PID 1 στο νέο namespace. Το `/bin/bash` και οι θυγατρικές διεργασίες του στη συνέχεια περιέχονται με ασφάλεια μέσα σε αυτό το νέο namespace, αποτρέποντας τον πρόωρο τερματισμό του PID 1 και επιτρέποντας την κανονική κατανομή PID.

Εξασφαλίζοντας ότι το `unshare` τρέχει με τη σημαία `-f`, το νέο PID namespace διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και στις υπο-διεργασίες του να λειτουργούν χωρίς να συναντήσουν το σφάλμα κατανομής μνήμης.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Ελέγξτε σε ποιο namespace βρίσκεται η διεργασία σας
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
### Εισέλθετε σε UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Κατάχρηση κοινής χρήσης host UTS

Αν ένα container ξεκινήσει με `--uts=host`, εντάσσεται στο host UTS namespace αντί να αποκτήσει ένα απομονωμένο. Με capabilities όπως `--cap-add SYS_ADMIN`, code στο container μπορεί να αλλάξει το host hostname/NIS name μέσω `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Η αλλαγή του host name μπορεί να παραποιήσει logs/alerts, να μπερδέψει cluster discovery ή να σπάσει TLS/SSH configs που κάνουν pin το hostname.

### Εντοπισμός containers που μοιράζονται το UTS με τον host
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
