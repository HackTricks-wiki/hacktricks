# Κατάχρηση διεργασιών macOS

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες για τις διεργασίες

Μια διεργασία είναι ένα στιγμιότυπο ενός εκτελούμενου executable, ωστόσο οι διεργασίες δεν εκτελούν κώδικα· αυτό το κάνουν τα threads. Επομένως, **οι διεργασίες είναι απλώς containers για την εκτέλεση threads**, παρέχοντας τη μνήμη, τους descriptors, τις θύρες, τα δικαιώματα...

Παραδοσιακά, οι διεργασίες ξεκινούσαν μέσα σε άλλες διεργασίες (εκτός από την PID 1) μέσω κλήσης της **`fork`**, η οποία δημιουργούσε ένα ακριβές αντίγραφο της τρέχουσας διεργασίας, και στη συνέχεια η **child process** καλούσε συνήθως την **`execve`** για να φορτώσει το νέο executable και να το εκτελέσει. Έπειτα, εισήχθη η **`vfork`** για να γίνει αυτή η διαδικασία ταχύτερη, χωρίς αντιγραφή μνήμης.\
Στη συνέχεια, εισήχθη η **`posix_spawn`**, συνδυάζοντας τις **`vfork`** και **`execve`** σε μία κλήση και δεχόμενη flags:

- `POSIX_SPAWN_RESETIDS`: Επαναφορά των effective ids στα real ids
- `POSIX_SPAWN_SETPGROUP`: Ορισμός της ένταξης σε process group
- `POSUX_SPAWN_SETSIGDEF`: Ορισμός της προεπιλεγμένης συμπεριφοράς των signals
- `POSIX_SPAWN_SETSIGMASK`: Ορισμός του signal mask
- `POSIX_SPAWN_SETEXEC`: Εκτέλεση στο ίδιο process (όπως η `execve` με περισσότερες επιλογές)
- `POSIX_SPAWN_START_SUSPENDED`: Έναρξη σε αναστολή
- `_POSIX_SPAWN_DISABLE_ASLR`: Έναρξη χωρίς ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Χρήση του Nano allocator του libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Επιτρέπει `rwx` σε data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Κλείσιμο όλων των file descriptions κατά το exec(2) από προεπιλογή
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Τυχαιοποίηση των υψηλών bits του ASLR slide

Επιπλέον, η `posix_spawn` επιτρέπει τον καθορισμό ενός array από **`posix_spawnattr`**, το οποίο ελέγχει ορισμένες πτυχές της spawned process, καθώς και **`posix_spawn_file_actions`** για την τροποποίηση της κατάστασης των descriptors.

Όταν μια διεργασία τερματίζει, στέλνει τον **κωδικό επιστροφής στη parent process** (αν η parent process τερμάτισε, η νέα parent είναι η PID 1) με το signal `SIGCHLD`. Η parent πρέπει να λάβει αυτή την τιμή καλώντας τις `wait4()` ή `waitid()` και, μέχρι να συμβεί αυτό, η child παραμένει σε zombie state, όπου εξακολουθεί να εμφανίζεται στη λίστα αλλά δεν καταναλώνει πόρους.

### PIDs

Οι PIDs, δηλαδή οι process identifiers, αναγνωρίζουν μια μοναδική διεργασία. Στο XNU, οι **PIDs** έχουν μέγεθος **64 bits**, αυξάνονται μονοτονικά και **δεν κάνουν ποτέ wrap** (για την αποφυγή καταχρήσεων).

### Process Groups, Sessions & Coalations

Οι **διεργασίες** μπορούν να τοποθετηθούν σε **groups** για να διευκολύνεται η διαχείρισή τους. Για παράδειγμα, οι εντολές σε ένα shell script θα ανήκουν στο ίδιο process group, ώστε να είναι δυνατή η **αποστολή signal σε όλες μαζί** χρησιμοποιώντας, για παράδειγμα, την kill.\
Είναι επίσης δυνατή η **ομαδοποίηση διεργασιών σε sessions**. Όταν μια διεργασία ξεκινά ένα session (`setsid(2)`), οι child processes τοποθετούνται μέσα στο session, εκτός αν ξεκινήσουν το δικό τους session.

Το Coalition είναι ένας ακόμη τρόπος ομαδοποίησης διεργασιών στο Darwin. Η ένταξη μιας διεργασίας σε ένα coalition της επιτρέπει να έχει πρόσβαση σε pool resources, να μοιράζεται ένα ledger ή να αντιμετωπίζει το Jetsam. Τα Coalations έχουν διαφορετικούς ρόλους: Leader, XPC service, Extension.

### Credentials & Personae

Κάθε διεργασία διαθέτει **credentials**, τα οποία **προσδιορίζουν τα δικαιώματά της** στο σύστημα. Κάθε διεργασία θα έχει ένα primary `uid` και ένα primary `gid` (αν και μπορεί να ανήκει σε πολλές groups).\
Είναι επίσης δυνατή η αλλαγή του user και του group id, αν το binary έχει το bit `setuid/setgid`.\
Υπάρχουν αρκετές functions για τον **ορισμό νέων uids/gids**.

Το syscall **`persona`** παρέχει ένα **εναλλακτικό** σύνολο από **credentials**. Η υιοθέτηση ενός persona σημαίνει την ταυτόχρονη ανάληψη του uid, του gid και των memberships των groups του. Στον [**πηγαίο κώδικα**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) είναι δυνατός ο εντοπισμός του struct:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Βασικές πληροφορίες για τα Threads

1. **POSIX Threads (pthreads):** Το macOS υποστηρίζει POSIX threads (`pthreads`), τα οποία αποτελούν μέρος ενός standard threading API για C/C++. Η υλοποίηση των pthreads στο macOS βρίσκεται στο `/usr/lib/system/libsystem_pthread.dylib`, το οποίο προέρχεται από το publicly available project `libpthread`. Αυτή η library παρέχει τις απαραίτητες functions για τη δημιουργία και τη διαχείριση threads.
2. **Δημιουργία Threads:** Η function `pthread_create()` χρησιμοποιείται για τη δημιουργία νέων threads. Εσωτερικά, αυτή η function καλεί τη `bsdthread_create()`, η οποία είναι ένα lower-level system call ειδικό για τον XNU kernel (τον kernel στον οποίο βασίζεται το macOS). Αυτό το system call λαμβάνει διάφορα flags που προέρχονται από το `pthread_attr` (attributes) και καθορίζουν τη συμπεριφορά του thread, συμπεριλαμβανομένων των scheduling policies και του μεγέθους του stack.
- **Προεπιλεγμένο μέγεθος Stack:** Το προεπιλεγμένο μέγεθος stack για νέα threads είναι 512 KB, το οποίο επαρκεί για τυπικές λειτουργίες, αλλά μπορεί να προσαρμοστεί μέσω των thread attributes, αν απαιτείται περισσότερος ή λιγότερος χώρος.
3. **Αρχικοποίηση Thread:** Η function `__pthread_init()` είναι κρίσιμη κατά τη ρύθμιση του thread και χρησιμοποιεί το όρισμα `env[]` για την ανάλυση environment variables, οι οποίες μπορούν να περιλαμβάνουν πληροφορίες σχετικά με τη θέση και το μέγεθος του stack.

#### Τερματισμός Threads στο macOS

1. **Έξοδος από Threads:** Τα threads συνήθως τερματίζονται με την κλήση της `pthread_exit()`. Αυτή η function επιτρέπει σε ένα thread να τερματιστεί καθαρά, εκτελώντας το απαραίτητο cleanup και επιτρέποντας στο thread να στείλει μια return value σε οποιαδήποτε threads κάνουν join.
2. **Cleanup Thread:** Με την κλήση της `pthread_exit()`, καλείται η function `pthread_terminate()`, η οποία χειρίζεται την αφαίρεση όλων των associated thread structures. Αποδεσμεύει τα Mach thread ports (το Mach είναι το communication subsystem στον XNU kernel) και καλεί τη `bsdthread_terminate`, ένα syscall που αφαιρεί τις kernel-level structures που σχετίζονται με το thread.

#### Μηχανισμοί Synchronization

Για τη διαχείριση της πρόσβασης σε shared resources και την αποφυγή race conditions, το macOS παρέχει αρκετά synchronization primitives. Αυτά είναι κρίσιμα σε multi-threading περιβάλλοντα, ώστε να διασφαλίζονται η ακεραιότητα των δεδομένων και η σταθερότητα του συστήματος:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standard mutex με memory footprint 60 bytes (56 bytes για το mutex και 4 bytes για το signature).
- **Fast Mutex (Signature: 0x4d55545A):** Παρόμοιο με ένα regular mutex, αλλά optimized για ταχύτερες operations, επίσης μεγέθους 60 bytes.
2. **Condition Variables:**
- Χρησιμοποιούνται για την αναμονή συγκεκριμένων conditions, με μέγεθος 44 bytes (40 bytes συν ένα 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes για condition variables, μεγέθους 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Διασφαλίζει ότι ένα τμήμα initialization code εκτελείται μόνο μία φορά. Το μέγεθός του είναι 12 bytes.
4. **Read-Write Locks:**
- Επιτρέπουν πολλούς readers ή έναν writer κάθε φορά, διευκολύνοντας την αποδοτική πρόσβαση σε shared data.
- **Read Write Lock (Signature: 0x52574c4b):** Μεγέθους 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes για read-write locks, μεγέθους 20 bytes.

> [!TIP]
> Τα τελευταία 4 bytes αυτών των objects χρησιμοποιούνται για την ανίχνευση overflows.

### Thread Local Variables (TLV)

Οι **Thread Local Variables (TLV)** στο πλαίσιο των αρχείων Mach-O (του format για executables στο macOS) χρησιμοποιούνται για τη δήλωση variables που είναι specific για **κάθε thread** σε μια multi-threaded application. Αυτό διασφαλίζει ότι κάθε thread έχει το δικό του ξεχωριστό instance μιας variable, παρέχοντας έναν τρόπο αποφυγής conflicts και διατήρησης της ακεραιότητας των δεδομένων χωρίς να απαιτούνται explicit synchronization mechanisms, όπως mutexes.

Στη C και σε related languages, μπορείτε να δηλώσετε μια thread-local variable χρησιμοποιώντας το keyword **`__thread`**. Δείτε πώς λειτουργεί στο παράδειγμά σας:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Αυτό το απόσπασμα ορίζει το `tlv_var` ως μεταβλητή thread-local. Κάθε thread που εκτελεί αυτόν τον κώδικα θα έχει το δικό του `tlv_var`, και οι αλλαγές που κάνει ένα thread στο `tlv_var` δεν θα επηρεάζουν το `tlv_var` κάποιου άλλου thread.

Στο Mach-O binary, τα δεδομένα που σχετίζονται με τις thread-local μεταβλητές οργανώνονται σε συγκεκριμένα sections:

- **`__DATA.__thread_vars`**: Αυτό το section περιέχει τα metadata σχετικά με τις thread-local μεταβλητές, όπως τους τύπους τους και την κατάσταση αρχικοποίησής τους.
- **`__DATA.__thread_bss`**: Αυτό το section χρησιμοποιείται για thread-local μεταβλητές που δεν έχουν αρχικοποιηθεί ρητά. Αποτελεί τμήμα της μνήμης που προορίζεται για δεδομένα αρχικοποιημένα σε μηδενική τιμή.

Το Mach-O παρέχει επίσης ένα συγκεκριμένο API που ονομάζεται **`tlv_atexit`** για τη διαχείριση των thread-local μεταβλητών όταν ένα thread τερματίζεται. Αυτό το API επιτρέπει την **καταχώριση destructors**—ειδικών functions που καθαρίζουν τα thread-local δεδομένα όταν ένα thread τερματίζεται.

### Προτεραιότητες Thread

Η κατανόηση των προτεραιοτήτων των thread απαιτεί την εξέταση του τρόπου με τον οποίο το λειτουργικό σύστημα αποφασίζει ποια threads θα εκτελεστούν και πότε. Αυτή η απόφαση επηρεάζεται από το επίπεδο προτεραιότητας που έχει ανατεθεί σε κάθε thread. Σε macOS και Unix-like συστήματα, αυτό γίνεται με τη χρήση εννοιών όπως `nice`, `renice` και κλάσεων Quality of Service (QoS).

#### Nice και Renice

1. **Nice:**
- Η τιμή `nice` μιας διεργασίας είναι ένας αριθμός που επηρεάζει την προτεραιότητά της. Κάθε διεργασία έχει μια τιμή nice από -20 (η υψηλότερη προτεραιότητα) έως 19 (η χαμηλότερη προτεραιότητα). Η προεπιλεγμένη τιμή nice όταν δημιουργείται μια διεργασία είναι συνήθως 0.
- Μια χαμηλότερη τιμή nice (πιο κοντά στο -20) κάνει μια διεργασία πιο «εγωιστική», παρέχοντάς της περισσότερο CPU time σε σύγκριση με άλλες διεργασίες που έχουν υψηλότερες τιμές nice.
2. **Renice:**
- Το `renice` είναι μια command που χρησιμοποιείται για την αλλαγή της τιμής nice μιας ήδη εκτελούμενης διεργασίας. Μπορεί να χρησιμοποιηθεί για τη δυναμική προσαρμογή της προτεραιότητας των διεργασιών, αυξάνοντας ή μειώνοντας την κατανομή του CPU time ανάλογα με τις νέες τιμές nice.
- Για παράδειγμα, αν μια διεργασία χρειάζεται προσωρινά περισσότερους CPU resources, μπορεί να μειωθεί η τιμή nice της χρησιμοποιώντας το `renice`.

#### Κλάσεις Quality of Service (QoS)

Οι κλάσεις QoS αποτελούν μια πιο σύγχρονη προσέγγιση στη διαχείριση των προτεραιοτήτων των thread, ιδιαίτερα σε συστήματα όπως το macOS που υποστηρίζουν **Grand Central Dispatch (GCD)**. Οι κλάσεις QoS επιτρέπουν στους developers να **κατηγοριοποιούν** την εργασία σε διαφορετικά επίπεδα με βάση τη σημασία ή τον επείγοντα χαρακτήρα της. Το macOS διαχειρίζεται αυτόματα την προτεραιοποίηση των thread με βάση αυτές τις κλάσεις QoS:

1. **User Interactive:**
- Αυτή η κλάση αφορά εργασίες που αλληλεπιδρούν εκείνη τη στιγμή με τον χρήστη ή απαιτούν άμεσα αποτελέσματα για την παροχή καλής user experience. Αυτές οι εργασίες λαμβάνουν την υψηλότερη προτεραιότητα, ώστε το interface να παραμένει responsive (π.χ. animations ή event handling).
2. **User Initiated:**
- Εργασίες που ξεκινά ο χρήστης και για τις οποίες αναμένει άμεσα αποτελέσματα, όπως το άνοιγμα ενός document ή το click σε ένα button που απαιτεί computations. Έχουν υψηλή προτεραιότητα, αλλά χαμηλότερη από την User Interactive.
3. **Utility:**
- Αυτές οι εργασίες εκτελούνται για μεγάλο χρονικό διάστημα και συνήθως εμφανίζουν έναν progress indicator (π.χ. downloading files, importing data). Έχουν χαμηλότερη προτεραιότητα από τις user-initiated εργασίες και δεν χρειάζεται να ολοκληρωθούν άμεσα.
4. **Background:**
- Αυτή η κλάση αφορά εργασίες που εκτελούνται στο background και δεν είναι ορατές στον χρήστη. Μπορεί να είναι εργασίες όπως indexing, syncing ή backups. Έχουν τη χαμηλότερη προτεραιότητα και την ελάχιστη επίδραση στην απόδοση του συστήματος.

Χρησιμοποιώντας κλάσεις QoS, οι developers δεν χρειάζεται να διαχειρίζονται τους ακριβείς αριθμούς προτεραιότητας, αλλά να επικεντρώνονται στη φύση της εργασίας, ενώ το σύστημα βελτιστοποιεί ανάλογα τους CPU resources.

Επιπλέον, υπάρχουν διαφορετικές **thread scheduling policies** που χρησιμοποιούνται για τον καθορισμό ενός συνόλου scheduling parameters, τα οποία ο scheduler θα λάβει υπόψη. Αυτό μπορεί να γίνει με τη χρήση του `thread_policy_[set/get]`. Αυτό μπορεί να είναι χρήσιμο σε race condition attacks.

## MacOS Process Abuse

Το MacOS, όπως κάθε άλλο λειτουργικό σύστημα, παρέχει διάφορες μεθόδους και mechanisms για **processes ώστε να αλληλεπιδρούν, να επικοινωνούν και να μοιράζονται δεδομένα**. Παρότι αυτές οι τεχνικές είναι απαραίτητες για την αποτελεσματική λειτουργία του συστήματος, μπορούν επίσης να γίνουν αντικείμενο abuse από threat actors για την **εκτέλεση κακόβουλων ενεργειών**.

### Library Injection

Το Library Injection είναι μια τεχνική κατά την οποία ένας attacker **αναγκάζει ένα process να φορτώσει μια malicious library**. Μετά το injection, η library εκτελείται στο context του target process, παρέχοντας στον attacker τα ίδια permissions και access με το process.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Το Function Hooking περιλαμβάνει την **παρεμβολή σε function calls** ή messages μέσα σε software code. Κάνοντας hooking σε functions, ένας attacker μπορεί να **τροποποιήσει τη συμπεριφορά** ενός process, να παρατηρήσει sensitive data ή ακόμη και να αποκτήσει τον έλεγχο του execution flow.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Το Inter Process Communication (IPC) αναφέρεται στις διάφορες μεθόδους με τις οποίες ξεχωριστά processes **μοιράζονται και ανταλλάσσουν δεδομένα**. Παρότι το IPC είναι θεμελιώδες για πολλές legitimate applications, μπορεί επίσης να γίνει αντικείμενο misuse για την παράκαμψη του process isolation, το leak sensitive information ή την εκτέλεση unauthorized actions.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Οι Electron applications που εκτελούνται με συγκεκριμένες env variables μπορεί να είναι ευάλωτες σε process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Είναι δυνατή η χρήση των flags `--load-extension` και `--use-fake-ui-for-media-stream` για την εκτέλεση **man in the browser attack**, η οποία επιτρέπει την κλοπή keystrokes, traffic και cookies, καθώς και το injection scripts σε pages...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Τα NIB files **ορίζουν user interface (UI) elements** και τις αλληλεπιδράσεις τους μέσα σε μια application. Ωστόσο, μπορούν να **εκτελέσουν arbitrary commands** και το **Gatekeeper δεν εμποδίζει** μια application που έχει ήδη εκτελεστεί από το να εκτελεστεί ξανά, αν τροποποιηθεί ένα **NIB file**. Επομένως, θα μπορούσαν να χρησιμοποιηθούν ώστε arbitrary programs να εκτελούν arbitrary commands:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Είναι δυνατή η εκμετάλλευση ορισμένων δυνατοτήτων της Java (όπως η env variable **`_JAVA_OPTS`**) ώστε μια Java application να εκτελέσει **arbitrary code/commands**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Είναι δυνατή η εισαγωγή code σε .Net applications μέσω **abusing της .Net debugging functionality** (η οποία δεν προστατεύεται από macOS protections όπως το runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Ελέγξτε διαφορετικές options για να κάνετε ένα Perl script να εκτελέσει arbitrary code στο:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Είναι επίσης δυνατή η εκμετάλλευση ruby env variables ώστε arbitrary scripts να εκτελούν arbitrary code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Αν έχει οριστεί η environment variable **`PYTHONINSPECT`**, η python process θα μεταβεί σε python cli μόλις ολοκληρωθεί. Είναι επίσης δυνατή η χρήση του **`PYTHONSTARTUP`** για τον καθορισμό ενός python script που θα εκτελείται στην αρχή μιας interactive session.\
Ωστόσο, σημειώστε ότι το **`PYTHONSTARTUP`** script δεν θα εκτελεστεί όταν το **`PYTHONINSPECT`** δημιουργεί την interactive session.

Άλλες env variables, όπως οι **`PYTHONPATH`** και **`PYTHONHOME`**, θα μπορούσαν επίσης να είναι χρήσιμες ώστε μια python command να εκτελέσει arbitrary code.

Σημειώστε ότι executables που έχουν γίνει compile με **`pyinstaller`** δεν θα χρησιμοποιήσουν αυτές τις environmental variables, ακόμη και αν εκτελούνται με embedded python.

> [!CAUTION]
> Συνολικά, δεν μπόρεσα να βρω τρόπο ώστε η python να εκτελεί arbitrary code μέσω abuse των environment variables.\
> Ωστόσο, οι περισσότεροι εγκαθιστούν την pyhton χρησιμοποιώντας το **Hombrew**, το οποίο εγκαθιστά την pyhton σε μια **writable location** για τον default admin user. Μπορείτε να κάνετε hijack χρησιμοποιώντας κάτι σαν:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Ακόμη και το **root** θα εκτελέσει αυτόν τον code όταν εκτελεί python.


## Detection

### Shield

Το [**Shield**](https://github.com/theevilbit/Shield) είναι μια open source application βασισμένη στο **EndpointSecurity**, η οποία ανιχνεύει και μπλοκάρει process injection. Αποτελεί καλή αναφορά για το ποια signals είναι πράγματι observable από το ES, καθώς ειδοποιεί για:<sup>[[1]](#references)</sup>

- **Injection environment variables** κατά το process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` και `ELECTRON_RUN_AS_NODE`.
- Κλήσεις **`task_for_pid`** — ένα process ζητά το task port κάποιου άλλου, το οποίο αποτελεί prerequisite για injection σε αυτό.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` και `--remote-debugging-port`, τα οποία εκκινούν μια Electron app σε debug mode και επιτρέπουν σε οποιονδήποτε να συνδεθεί και να εκτελέσει code σε αυτή.
- **Δημιουργία symlink/hardlink μεταξύ privilege levels** — το κλασικό primitive «δημιούργησε ένα link ως normal user και δείξε το σε μια privileged location». Σημειώστε ότι τα **symlinks μπορούν να εντοπιστούν αλλά όχι να μπλοκαριστούν**: το EndpointSecurity δεν εκθέτει τον προορισμό του link πριν από τη δημιουργία του.

### Calls made by other processes

Στο [**this blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) μπορείτε να βρείτε πώς είναι δυνατή η χρήση της function **`task_name_for_pid`** για τη λήψη information σχετικά με άλλα **processes που κάνουν code injection σε ένα process** και, στη συνέχεια, τη λήψη information σχετικά με εκείνο το άλλο process.<sup>[[4]](#references)</sup>

Σημειώστε ότι για να καλέσετε αυτήν τη function πρέπει να έχετε **το ίδιο uid** με αυτόν που εκτελεί το process ή να είστε **root** (και επιστρέφει information σχετικά με το process, όχι τρόπο για code injection).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
