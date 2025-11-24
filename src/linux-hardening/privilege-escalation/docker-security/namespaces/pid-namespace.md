# Χώρος ονομάτων PID

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Ο PID (Process IDentifier) namespace είναι μια λειτουργία του πυρήνα του Linux που παρέχει απομόνωση διεργασιών επιτρέποντας σε μια ομάδα διεργασιών να έχει το δικό της σύνολο μοναδικών PIDs, ξεχωριστό από τα PIDs σε άλλους χώρους ονομάτων. Αυτό είναι ιδιαίτερα χρήσιμο στη χρήση containers, όπου η απομόνωση διεργασιών είναι απαραίτητη για την ασφάλεια και τη διαχείριση πόρων.

Όταν δημιουργείται ένας νέος PID namespace, η πρώτη διεργασία σε αυτό το namespace λαμβάνει το PID 1. Αυτή η διεργασία γίνεται η "init" διεργασία του νέου namespace και είναι υπεύθυνη για τη διαχείριση άλλων διεργασιών εντός του namespace. Κάθε επόμενη διεργασία που δημιουργείται εντός του namespace θα έχει ένα μοναδικό PID μέσα σε αυτό το namespace, και αυτά τα PIDs θα είναι ανεξάρτητα από τα PIDs σε άλλους χώρους ονομάτων.

Από την προοπτική μιας διεργασίας εντός ενός PID namespace, μπορεί να δει μόνο άλλες διεργασίες στο ίδιο namespace. Δεν έχει επίγνωση διεργασιών σε άλλους χώρους ονομάτων και δεν μπορεί να αλληλεπιδράσει με αυτές χρησιμοποιώντας παραδοσιακά εργαλεία διαχείρισης διεργασιών (π.χ., `kill`, `wait`, κ.λπ.). Αυτό προσφέρει ένα επίπεδο απομόνωσης που βοηθάει στην αποτροπή παρεμβολών μεταξύ διεργασιών.

### Πώς λειτουργεί:

1. Όταν δημιουργείται μια νέα διεργασία (π.χ., με χρήση του system call `clone()`), η διεργασία μπορεί να ανατεθεί σε ένα νέο ή υπάρχον PID namespace. **Εάν δημιουργηθεί νέος namespace, η διεργασία γίνεται η "init" διεργασία του συγκεκριμένου namespace**.
2. Ο **πυρήνας** διατηρεί μία **αντιστοίχιση μεταξύ των PIDs στο νέο namespace και των αντίστοιχων PIDs** στο parent namespace (δηλαδή, στο namespace από το οποίο δημιουργήθηκε ο νέος). Αυτή η αντιστοίχιση **επιτρέπει στον πυρήνα να μεταφράζει PIDs όταν είναι απαραίτητο**, όπως όταν αποστέλλονται σήματα μεταξύ διεργασιών σε διαφορετικά namespaces.
3. **Οι διεργασίες εντός ενός PID namespace μπορούν να βλέπουν και να αλληλεπιδρούν μόνο με άλλες διεργασίες στο ίδιο namespace**. Δεν έχουν επίγνωση διεργασιών σε άλλους χώρους ονομάτων και τα PIDs τους είναι μοναδικά εντός του namespace.
4. Όταν **καταστρέφεται ένα PID namespace** (π.χ., όταν η "init" διεργασία του namespace τερματίζει), **όλες οι διεργασίες εντός αυτού του namespace τερματίζονται**. Αυτό διασφαλίζει ότι όλοι οι πόροι που σχετίζονται με το namespace καθαρίζονται σωστά.

## Εργαστήριο:

### Δημιουργία διαφορετικών χώρων ονομάτων

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
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

Τοποθετώντας μια νέα περίπτωση του filesystem `/proc` αν χρησιμοποιήσετε την παράμετρο `--mount-proc`, διασφαλίζετε ότι το νέο mount namespace έχει μια **ακριβή και απομονωμένη εικόνα των πληροφοριών διεργασιών που είναι ειδικές για εκείνο το namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Ελέγξτε σε ποιο namespace βρίσκεται η διεργασία σας
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Βρες όλα τα PID namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Σημειώστε ότι ο χρήστης root από το αρχικό (default) PID namespace μπορεί να δει όλες τις διεργασίες, ακόμα και αυτές που βρίσκονται σε νέα PID namespaces — γι' αυτό μπορούμε να δούμε όλα τα PID namespaces.

### Είσοδος σε PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Όταν εισέρχεσαι μέσα σε ένα PID namespace από το default namespace, θα εξακολουθείς να μπορείς να βλέπεις όλες τις διεργασίες. Και η διεργασία από αυτό το PID ns θα μπορεί να δει το νέο bash στο PID ns.

Επίσης, μπορείς μόνο **να εισέλθεις σε άλλο PID namespace διεργασίας μόνο αν είσαι root**. Και **δεν μπορείς** **να εισέλθεις** σε άλλο namespace **χωρίς έναν περιγραφέα** που να δείχνει σε αυτό (π.χ. `/proc/self/ns/pid`)

## Σημειώσεις Πρόσφατης Εκμετάλλευσης

### CVE-2025-31133: εκμετάλλευση του `maskedPaths` για πρόσβαση στα host PIDs

Το runc ≤1.2.7 επέτρεπε σε επιτιθέμενους που ελέγχουν container images ή workloads `runc exec` να αντικαθιστούν το container-side `/dev/null` λίγο πριν το runtime μασκάρει ευαίσθητα procfs entries. Όταν ο race succeeds, το `/dev/null` μπορεί να μετατραπεί σε symlink που δείχνει σε οποιαδήποτε διαδρομή του host (για παράδειγμα `/proc/sys/kernel/core_pattern`), οπότε το νέο container PID namespace ξαφνικά κληρονομεί πρόσβαση read/write σε host-global procfs ρυθμίσεις παρ’ όλο που ποτέ δεν εγκατέλειψε το δικό του namespace. Μόλις το `core_pattern` ή το `/proc/sysrq-trigger` γίνει εγγράψιμο, η δημιουργία ενός coredump ή η ενεργοποίηση του SysRq οδηγεί σε εκτέλεση κώδικα ή άρνηση υπηρεσίας στο host PID namespace.

Practical workflow:

1. Build an OCI bundle whose rootfs replaces `/dev/null` with a link to the host path you want (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Start the container before the fix so runc bind-mounts the host procfs target over the link.
3. Inside the container namespace, write to the now-exposed procfs file (e.g., point `core_pattern` to a reverse shell helper) and crash any process to force the host kernel to execute your helper as PID 1 context.

Μπορείτε γρήγορα να ελέγξετε αν ένα bundle μασκάρει τα σωστά αρχεία πριν το ξεκινήσετε:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Αν στο runtime λείπει μια εγγραφή μάσκας που περιμένεις (ή την παραλείπει επειδή `/dev/null` εξαφανίστηκε), αντιμετώπισε το container σαν να έχει πιθανή ορατότητα του PID του host.

### Έγχυση namespace με `insject`

Το `insject` της NCC Group φορτώνεται ως LD_PRELOAD payload που κάνει hook σε ένα όψιμο στάδιο του target προγράμματος (προεπιλογή `main`) και εκτελεί μια σειρά κλήσεων `setns()` μετά το `execve()`. Αυτό σου επιτρέπει να προσαρτηθείς από το host (ή από άλλο container) στο PID namespace ενός θύματος *μετά* που το runtime αρχικοποιήθηκε, διατηρώντας την προβολή του `/proc/<pid>` χωρίς να χρειαστεί να αντιγράψεις binaries στο container filesystem. Επειδή το `insject` μπορεί να αναβάλει την ένταξη στο PID namespace μέχρι να κάνει fork, μπορείς να κρατήσεις ένα thread στο host namespace (με CAP_SYS_PTRACE) ενώ ένα άλλο thread εκτελείται στο target PID namespace, δημιουργώντας ισχυρά debugging ή offensive primitives.

Παράδειγμα χρήσης:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Κύρια συμπεράσματα κατά την κατάχρηση ή την άμυνα εναντίον του namespace injection:

- Χρησιμοποιήστε `-S/--strict` για να αναγκάσετε το `insject` να τερματίσει αν τα threads υπάρχουν ήδη ή οι εντάξεις namespace αποτύχουν, αλλιώς μπορεί να αφήσετε μερικώς μετεγκατεστημένα threads που εκτείνονται ανάμεσα στους host και container χώρους PID.
- Μην επισυνάπτετε ποτέ εργαλεία που εξακολουθούν να κρατούν εγγράψιμους host file descriptors εκτός αν επίσης ενταχθείτε στο mount namespace — διαφορετικά οποιαδήποτε διεργασία μέσα στο PID namespace μπορεί να ptrace τον helper σας και να επαναχρησιμοποιήσει αυτούς τους descriptors για να τροποποιήσει πόρους του host.

## Αναφορές

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
