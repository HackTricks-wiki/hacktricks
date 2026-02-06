# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

A UTS (UNIX Time-Sharing System) namespace είναι μια δυνατότητα του Linux kernel που παρέχει i**απομόνωση δύο συστημικών αναγνωριστικών**: τα **hostname** και το **NIS** (Network Information Service) όνομα τομέα. Αυτή η απομόνωση επιτρέπει σε κάθε UTS namespace να έχει το **own independent hostname and NIS domain name**, κάτι ιδιαίτερα χρήσιμο σε σενάρια containerization όπου κάθε container πρέπει να εμφανίζεται ως ξεχωριστό σύστημα με το δικό του hostname.

### Πώς λειτουργεί:

1. Όταν δημιουργείται ένα νέο UTS namespace, ξεκινά με ένα **αντίγραφο του hostname και του NIS domain name από το parent namespace**. Αυτό σημαίνει ότι, κατά τη δημιουργία, το νέο namespace s**μοιράζεται τα ίδια αναγνωριστικά με το parent namespace**. Ωστόσο, οποιεσδήποτε επακόλουθες αλλαγές στο hostname ή στο NIS domain name εντός του namespace δεν θα επηρεάσουν άλλα namespaces.
2. Διαδικασίες εντός ενός UTS namespace **μπορούν να αλλάξουν το hostname και το NIS domain name** χρησιμοποιώντας τις `sethostname()` και `setdomainname()` system calls, αντίστοιχα. Αυτές οι αλλαγές είναι τοπικές στο namespace και δεν επηρεάζουν άλλα namespaces ή το host system.
3. Διαδικασίες μπορούν να μετακινηθούν μεταξύ namespaces χρησιμοποιώντας την `setns()` system call ή να δημιουργήσουν νέα namespaces χρησιμοποιώντας τις `unshare()` ή `clone()` system calls με το flag `CLONE_NEWUTS`. Όταν μια διεργασία μετακινηθεί σε ένα νέο namespace ή δημιουργήσει ένα, θα αρχίσει να χρησιμοποιεί το hostname και το NIS domain name που σχετίζονται με αυτό το namespace.

## Εργαστήριο:

### Δημιουργία διαφορετικών Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Consequence**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Solution**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Ελέγξτε σε ποιο namespace βρίσκεται η διαδικασία σας
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Βρες όλα τα UTS namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Εισέλθετε σε ένα UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Κατάχρηση κοινής χρήσης host UTS

Αν ένα container ξεκινήσει με `--uts=host`, εντάσσεται στο host UTS namespace αντί να αποκτά ένα απομονωμένο. Με capabilities όπως `--cap-add SYS_ADMIN`, κώδικας μέσα στο container μπορεί να αλλάξει το host hostname/NIS name μέσω `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Η αλλαγή του hostname μπορεί να παραποιήσει logs/alerts, να μπερδέψει το cluster discovery ή να σπάσει TLS/SSH configs που κάνουν pin στο hostname.

### Εντοπίστε containers που μοιράζονται το UTS με τον host
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
