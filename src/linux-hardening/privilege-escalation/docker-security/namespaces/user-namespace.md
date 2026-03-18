# Χώρος ονομάτων χρήστη

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Αναφορές

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Βασικές Πληροφορίες

Ένας χώρος ονομάτων χρήστη είναι ένα χαρακτηριστικό του Linux kernel που **παρέχει απομόνωση των αντιστοιχίσεων ταυτοτήτων χρήστη και ομάδας**, επιτρέποντας σε κάθε χώρο ονομάτων χρήστη να έχει το **δικό του σύνολο ταυτοτήτων χρήστη και ομάδας**. Αυτή η απομόνωση δίνει τη δυνατότητα σε διεργασίες που εκτελούνται σε διαφορετικούς χώρους ονομάτων να **έχουν διαφορετικά προνόμια και ιδιοκτησίες**, ακόμη κι αν αριθμητικά μοιράζονται τα ίδια user και group IDs.

Οι χώροι ονομάτων χρήστη είναι ιδιαίτερα χρήσιμοι στην οργάνωση με containers, όπου κάθε container θα πρέπει να έχει το δικό του ανεξάρτητο σύνολο ταυτοτήτων χρήστη και ομάδας, επιτρέποντας καλύτερη ασφάλεια και απομόνωση μεταξύ των containers και του host συστήματος.

### Πώς λειτουργεί:

1. Όταν δημιουργείται ένας νέος χώρος ονομάτων χρήστη, **ξεκινά με ένα κενό σύνολο αντιστοιχίσεων ταυτοτήτων χρήστη και ομάδας**. Αυτό σημαίνει ότι οποιαδήποτε διεργασία που τρέχει στον νέο χώρο ονομάτων χρήστη θα **αρχικά δεν θα έχει προνόμια έξω από τον χώρο ονομάτων**.
2. Μπορούν να οριστούν αντιστοιχίσεις ταυτοτήτων μεταξύ των ταυτοτήτων χρήστη και ομάδας στον νέο χώρο ονομάτων και αυτών στον γονικό (ή host) χώρο ονομάτων. Αυτό **επιτρέπει σε διεργασίες στον νέο χώρο να έχουν προνόμια και ιδιοκτησία που αντιστοιχούν σε ταυτοτήτες χρήστη και ομάδας στον γονικό χώρο ονομάτων**. Ωστόσο, οι αντιστοιχίσεις μπορούν να περιοριστούν σε συγκεκριμένα εύρη και υποσύνολα IDs, επιτρέποντας λεπτομερή έλεγχο των προνομίων που χορηγούνται στις διεργασίες του νέου χώρου.
3. Μέσα σε έναν χώρο ονομάτων χρήστη, **οι διεργασίες μπορούν να έχουν πλήρη προνόμια root (UID 0) για λειτουργίες εντός του χώρου ονομάτων**, ενώ εξακολουθούν να έχουν περιορισμένα προνόμια εκτός του χώρου. Αυτό επιτρέπει **στα containers να τρέχουν με δυνατότητες παρόμοιες με του root εντός του δικού τους χώρου ονομάτων χωρίς να έχουν πλήρη προνόμια root στο host σύστημα**.
4. Οι διεργασίες μπορούν να μετακινηθούν μεταξύ χώρων ονομάτων χρησιμοποιώντας το system call `setns()` ή να δημιουργήσουν νέους χώρους ονομάτων χρησιμοποιώντας τα system calls `unshare()` ή `clone()` με τη σημαία `CLONE_NEWUSER`. Όταν μια διεργασία μετακινηθεί σε έναν νέο χώρο ονομάτων ή δημιουργήσει έναν, θα αρχίσει να χρησιμοποιεί τις αντιστοιχίσεις ταυτοτήτων χρήστη και ομάδας που συνδέονται με αυτόν τον χώρο ονομάτων.

## Εργαστήριο:

### Δημιουργία διαφόρων χώρων ονομάτων

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Με το να προσαρτήσετε ένα νέο αντίγραφο του filesystem `/proc` αν χρησιμοποιήσετε την παράμετρο `--mount-proc`, διασφαλίζετε ότι το νέο mount namespace έχει μια **ακριβή και απομονωμένη εικόνα των πληροφοριών διεργασιών που αφορούν συγκεκριμένα εκείνο το namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Εξήγηση του προβλήματος**:

- Ο πυρήνας Linux επιτρέπει σε μια διεργασία να δημιουργεί νέα namespaces χρησιμοποιώντας το system call `unshare`. Ωστόσο, η διεργασία που ξεκινά τη δημιουργία ενός νέου PID namespace (αναφερόμενη ως η διεργασία "unshare") δεν εισέρχεται στο νέο namespace· μόνο οι παραγόμενες διεργασίες της το κάνουν.
- Η εκτέλεση του %unshare -p /bin/bash% ξεκινάει το `/bin/bash` στην ίδια διεργασία με το `unshare`. Συνεπώς, το `/bin/bash` και οι παραγόμενες διεργασίες του βρίσκονται στο αρχικό PID namespace.
- Η πρώτη παραγόμενη διεργασία του `/bin/bash` στο νέο namespace γίνεται PID 1. Όταν αυτή η διεργασία τερματιστεί, προκαλεί τον καθαρισμό του namespace αν δεν υπάρχουν άλλες διεργασίες, καθώς το PID 1 έχει τον ειδικό ρόλο της υιοθεσίας ορφανών διεργασιών. Ο πυρήνας Linux τότε θα απενεργοποιήσει την κατανομή PID σε εκείνο το namespace.

2. **Συνέπεια**:

- Η έξοδος του PID 1 σε ένα νέο namespace οδηγεί στον καθαρισμό του flag `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα η συνάρτηση `alloc_pid` να αποτυγχάνει να εκχωρήσει νέο PID κατά τη δημιουργία μιας νέας διεργασίας, παράγοντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα μπορεί να λυθεί χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να κάνει fork μια νέα διεργασία μετά τη δημιουργία του νέου PID namespace.
- Η εκτέλεση του %unshare -fp /bin/bash% εξασφαλίζει ότι η εντολή `unshare` η ίδια γίνεται PID 1 στο νέο namespace. Το `/bin/bash` και οι παραγόμενες διεργασίες του τότε περιέχονται με ασφάλεια μέσα σε αυτό το νέο namespace, αποτρέποντας τον πρόωρο τερματισμό του PID 1 και επιτρέποντας τη φυσιολογική κατανομή PID.

Εξασφαλίζοντας ότι το `unshare` τρέχει με τη σημαία `-f`, το νέο PID namespace διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και τις υπο-διεργασίες του να λειτουργούν χωρίς να συναντούν το σφάλμα κατανομής μνήμης.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Για να χρησιμοποιηθεί ο χώρος ονομάτων χρήστη, ο Docker daemon πρέπει να ξεκινήσει με **`--userns-remap=default`** (Σε ubuntu 14.04, αυτό μπορεί να γίνει τροποποιώντας το `/etc/default/docker` και στη συνέχεια εκτελώντας `sudo service docker restart`)

### Ελέγξτε σε ποιον χώρο ονομάτων βρίσκεται η διεργασία σας
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Μπορείτε να ελέγξετε το user map από το docker container με:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ή από το host με:
```bash
cat /proc/<pid>/uid_map
```
### Εύρεση όλων των User namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Είσοδος μέσα σε ένα User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Επίσης, μπορείτε να **enter σε άλλο process namespace μόνο αν είστε root**. Και **δεν μπορείτε** να **enter** σε άλλο namespace **χωρίς descriptor** που να δείχνει σε αυτό (όπως `/proc/self/ns/user`).

### Δημιουργία νέου User namespace (με mappings)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Κανόνες αντιστοίχισης UID/GID για μη προνομιακούς

Όταν η διαδικασία που γράφει στα `uid_map`/`gid_map` **δεν έχει CAP_SETUID/CAP_SETGID στο parent user namespace**, ο πυρήνας επιβάλλει αυστηρότερους κανόνες: επιτρέπεται μόνο μία **ενιαία αντιστοίχιση** για το effective UID/GID του καλούντος, και για το `gid_map` **πρέπει πρώτα να απενεργοποιήσετε το `setgroups(2)`** γράφοντας `deny` στο `/proc/<pid>/setgroups`.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

ID-mapped mounts **attach a user namespace mapping to a mount**, so file ownership is remapped when accessed through that mount. This is commonly used by container runtimes (especially rootless) to **share host paths without recursive `chown`**, while still enforcing the user namespace's UID/GID translation.

From an offensive perspective, **if you can create a mount namespace and hold `CAP_SYS_ADMIN` inside your user namespace**, and the filesystem supports ID-mapped mounts, you can remap ownership *views* of bind mounts. This **does not change on-disk ownership**, but it can make otherwise-unwritable files appear owned by your mapped UID/GID within the namespace.

### Ανάκτηση Capabilities

Στην περίπτωση των user namespaces, **όταν δημιουργείται ένα νέο user namespace, η διαδικασία που εισέρχεται στο namespace λαμβάνει ένα πλήρες σετ capabilities εντός αυτού του namespace**. Αυτά τα capabilities επιτρέπουν στη διαδικασία να εκτελεί προνομιούχες ενέργειες όπως **mounting** **filesystems**, δημιουργία συσκευών ή αλλαγή ιδιοκτησίας αρχείων, αλλά **μόνο στο πλαίσιο του user namespace της**.

Για παράδειγμα, όταν έχετε το capability `CAP_SYS_ADMIN` εντός ενός user namespace, μπορείτε να εκτελείτε ενέργειες που συνήθως απαιτούν αυτό το capability, όπως το mounting filesystems, αλλά μόνο στο πλαίσιο του user namespace σας. Οποιεσδήποτε ενέργειες εκτελέσετε με αυτό το capability δεν θα επηρεάσουν το host system ή άλλα namespaces.

> [!WARNING]
> Επομένως, ακόμη και αν η είσοδος μιας νέας διεργασίας σε ένα νέο User namespace **θα σας επιστρέψει όλα τα capabilities** (CapEff: 000001ffffffffff), στην πραγματικότητα μπορείτε **να χρησιμοποιήσετε μόνο αυτά που σχετίζονται με το namespace** (π.χ. mount) και όχι όλα. Έτσι, αυτό από μόνο του δεν αρκεί για να διαφύγετε από ένα Docker container.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Αναφορές

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
