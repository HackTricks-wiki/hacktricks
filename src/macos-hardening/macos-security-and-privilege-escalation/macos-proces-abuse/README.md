# Κατάχρηση macOS Processes

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες για τα Processes

Ένα process είναι μια instance ενός εκτελούμενου executable, ωστόσο τα processes δεν εκτελούν κώδικα· αυτό το κάνουν τα threads. Επομένως, **τα processes είναι απλώς containers για την εκτέλεση threads**, παρέχοντας τη μνήμη, τους descriptors, τα ports, τα permissions...

Παραδοσιακά, τα processes ξεκινούσαν μέσα σε άλλα processes (εκτός από το PID 1) καλώντας το **`fork`**, το οποίο δημιουργούσε ένα ακριβές αντίγραφο του τρέχοντος process, και στη συνέχεια το **child process** καλούσε συνήθως το **`execve`** για να φορτώσει το νέο executable και να το εκτελέσει. Έπειτα, εισήχθη το **`vfork`** για να γίνει αυτή η διαδικασία ταχύτερη, χωρίς αντιγραφή μνήμης.\
Στη συνέχεια, εισήχθη το **`posix_spawn`**, συνδυάζοντας τα **`vfork`** και **`execve`** σε μία κλήση και αποδεχόμενο flags:

- `POSIX_SPAWN_RESETIDS`: Επαναφορά των effective ids στα real ids
- `POSIX_SPAWN_SETPGROUP`: Ορισμός της συσχέτισης με το process group
- `POSUX_SPAWN_SETSIGDEF`: Ορισμός της προεπιλεγμένης συμπεριφοράς των signals
- `POSIX_SPAWN_SETSIGMASK`: Ορισμός του signal mask
- `POSIX_SPAWN_SETEXEC`: Εκτέλεση στο ίδιο process (όπως το `execve` με περισσότερες επιλογές)
- `POSIX_SPAWN_START_SUSPENDED`: Εκκίνηση σε suspended κατάσταση
- `_POSIX_SPAWN_DISABLE_ASLR`: Εκκίνηση χωρίς ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Χρήση του Nano allocator του libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ενεργοποίηση `rwx` στα data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Κλείσιμο όλων των file descriptions στο exec(2) από προεπιλογή
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Τυχαιοποίηση των high bits του ASLR slide

Επιπλέον, το `posix_spawn` επιτρέπει τον καθορισμό ενός array από **`posix_spawnattr`**, το οποίο ελέγχει ορισμένες πτυχές του spawned process, καθώς και **`posix_spawn_file_actions`** για την τροποποίηση της κατάστασης των descriptors.

Όταν ένα process τερματίζει, στέλνει τον **return code στο parent process** (αν το parent τερμάτισε, το νέο parent είναι το PID 1) με το signal `SIGCHLD`. Το parent πρέπει να λάβει αυτή την τιμή καλώντας τα `wait4()` ή `waitid()` και, μέχρι να συμβεί αυτό, το child παραμένει σε zombie state, όπου εξακολουθεί να εμφανίζεται στη λίστα αλλά δεν καταναλώνει resources.

### PIDs

Τα PIDs, δηλαδή τα process identifiers, προσδιορίζουν ένα μοναδικό process. Στο XNU, τα **PIDs** είναι **64-bit**, αυξάνονται μονοτονικά και **δεν κάνουν ποτέ wrap** (για την αποφυγή καταχρήσεων).

### Process Groups, Sessions & Coalations

Τα **Processes** μπορούν να τοποθετούνται σε **groups**, ώστε να διευκολύνεται η διαχείρισή τους. Για παράδειγμα, οι εντολές σε ένα shell script θα βρίσκονται στο ίδιο process group, επομένως είναι δυνατή η **αποστολή signal σε όλες μαζί** χρησιμοποιώντας, για παράδειγμα, το kill.\
Είναι επίσης δυνατό να **ομαδοποιούνται processes σε sessions**. Όταν ένα process ξεκινά μια session (`setsid(2)`), τα child processes τοποθετούνται μέσα στη session, εκτός αν ξεκινήσουν τη δική τους session.

Το Coalition είναι ένας ακόμη τρόπος ομαδοποίησης processes στο Darwin. Η συμμετοχή ενός process σε ένα coalition του επιτρέπει να έχει πρόσβαση σε pool resources, να μοιράζεται ένα ledger ή να αντιμετωπίζει Jetsam. Τα Coalations έχουν διαφορετικούς ρόλους: Leader, XPC service, Extension.

### Credentials & Personae

Κάθε process διαθέτει **credentials**, τα οποία **προσδιορίζουν τα privileges του** στο σύστημα. Κάθε process έχει ένα primary `uid` και ένα primary `gid` (αν και μπορεί να ανήκει σε πολλά groups).\
Είναι επίσης δυνατό να αλλάξουν τα user και group ids, αν το binary διαθέτει το bit **`setuid/setgid`**.\
Υπάρχουν διάφορες functions για τον **ορισμό νέων uids/gids**.

Το syscall **`persona`** παρέχει ένα **εναλλακτικό** σύνολο από **credentials**. Η υιοθέτηση ενός persona προϋποθέτει ταυτόχρονα το uid, το gid και τα group memberships του. Στον [**πηγαίο κώδικα**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) είναι δυνατό να βρεθεί το struct:
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
2. **Δημιουργία Threads:** Η function `pthread_create()` χρησιμοποιείται για τη δημιουργία νέων threads. Εσωτερικά, αυτή η function καλεί τη `bsdthread_create()`, η οποία είναι ένα lower-level system call ειδικό για τον XNU kernel (τον kernel στον οποίο βασίζεται το macOS). Αυτό το system call δέχεται διάφορα flags που προέρχονται από το `pthread_attr` (attributes) και καθορίζουν τη συμπεριφορά του thread, συμπεριλαμβανομένων των scheduling policies και του stack size.
- **Προεπιλεγμένο Stack Size:** Το προεπιλεγμένο stack size για νέα threads είναι 512 KB, το οποίο επαρκεί για τυπικές λειτουργίες, αλλά μπορεί να προσαρμοστεί μέσω των thread attributes, αν απαιτείται περισσότερος ή λιγότερος χώρος.
3. **Αρχικοποίηση Thread:** Η function `__pthread_init()` είναι κρίσιμη κατά τη ρύθμιση του thread και χρησιμοποιεί το όρισμα `env[]` για την ανάλυση environment variables, οι οποίες μπορούν να περιλαμβάνουν λεπτομέρειες σχετικά με τη θέση και το μέγεθος του stack.

#### Τερματισμός Threads στο macOS

1. **Έξοδος από Threads:** Τα threads συνήθως τερματίζονται με την κλήση της `pthread_exit()`. Αυτή η function επιτρέπει σε ένα thread να τερματιστεί καθαρά, εκτελώντας το απαραίτητο cleanup και επιτρέποντας στο thread να στείλει μια return value σε οποιαδήποτε threads κάνουν join.
2. **Thread Cleanup:** Μετά την κλήση της `pthread_exit()`, καλείται η function `pthread_terminate()`, η οποία διαχειρίζεται την αφαίρεση όλων των σχετικών thread structures. Αποδεσμεύει τα Mach thread ports (το Mach είναι το communication subsystem στον XNU kernel) και καλεί τη `bsdthread_terminate`, ένα syscall που αφαιρεί τις kernel-level structures που σχετίζονται με το thread.

#### Μηχανισμοί Synchronization

Για τη διαχείριση της πρόσβασης σε shared resources και την αποφυγή race conditions, το macOS παρέχει αρκετά synchronization primitives. Αυτά είναι κρίσιμα σε multi-threading environments, ώστε να διασφαλίζονται η ακεραιότητα των δεδομένων και η σταθερότητα του συστήματος:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standard mutex με memory footprint 60 bytes (56 bytes για το mutex και 4 bytes για το signature).
- **Fast Mutex (Signature: 0x4d55545A):** Παρόμοιο με regular mutex, αλλά optimized για ταχύτερες operations, επίσης με μέγεθος 60 bytes.
2. **Condition Variables:**
- Χρησιμοποιούνται για την αναμονή συγκεκριμένων conditions, με μέγεθος 44 bytes (40 bytes συν ένα signature 4 bytes).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes για condition variables, με μέγεθος 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Διασφαλίζει ότι ένα κομμάτι initialization code εκτελείται μόνο μία φορά. Το μέγεθός του είναι 12 bytes.
4. **Read-Write Locks:**
- Επιτρέπουν πολλαπλούς readers ή έναν writer κάθε φορά, διευκολύνοντας την αποτελεσματική πρόσβαση σε shared data.
- **Read Write Lock (Signature: 0x52574c4b):** Έχει μέγεθος 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes για read-write locks, με μέγεθος 20 bytes.

> [!TIP]
> Τα τελευταία 4 bytes αυτών των objects χρησιμοποιούνται για την ανίχνευση overflows.

### Thread Local Variables (TLV)

Οι **Thread Local Variables (TLV)** στο πλαίσιο των αρχείων Mach-O (το format για executables στο macOS) χρησιμοποιούνται για τη δήλωση variables που είναι ειδικές για **κάθε thread** σε μια multi-threaded application. Έτσι διασφαλίζεται ότι κάθε thread έχει το δικό του ξεχωριστό instance μιας variable, παρέχοντας έναν τρόπο αποφυγής conflicts και διατήρησης της ακεραιότητας των δεδομένων χωρίς να απαιτούνται explicit synchronization mechanisms, όπως τα mutexes.

Στις C και related languages, μπορείτε να δηλώσετε μια thread-local variable χρησιμοποιώντας το keyword **`__thread`**. Έτσι λειτουργεί στο παράδειγμά σας:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Αυτό το απόσπασμα ορίζει το `tlv_var` ως μεταβλητή τοπική σε κάθε thread. Κάθε thread που εκτελεί αυτόν τον κώδικα θα έχει το δικό του `tlv_var`, και οι αλλαγές που κάνει ένα thread στο `tlv_var` δεν θα επηρεάζουν το `tlv_var` κάποιου άλλου thread.

Στο δυαδικό Mach-O, τα δεδομένα που σχετίζονται με τις μεταβλητές τοπικές σε κάθε thread οργανώνονται σε συγκεκριμένα sections:

- **`__DATA.__thread_vars`**: Αυτό το section περιέχει τα metadata σχετικά με τις μεταβλητές τοπικές σε κάθε thread, όπως τους τύπους τους και την κατάσταση αρχικοποίησής τους.
- **`__DATA.__thread_bss`**: Αυτό το section χρησιμοποιείται για μεταβλητές τοπικές σε κάθε thread που δεν έχουν αρχικοποιηθεί ρητά. Αποτελεί μέρος της μνήμης που προορίζεται για δεδομένα αρχικοποιημένα με μηδενικές τιμές.

Το Mach-O παρέχει επίσης ένα συγκεκριμένο API, το **`tlv_atexit`**, για τη διαχείριση των μεταβλητών τοπικών σε κάθε thread όταν ένα thread τερματίζεται. Αυτό το API επιτρέπει την **καταχώριση destructors** — ειδικών functions που καθαρίζουν τα δεδομένα τοπικά στο thread όταν αυτό τερματίζεται.

### Threading Priorities

Η κατανόηση των προτεραιοτήτων των threads απαιτεί την εξέταση του τρόπου με τον οποίο το λειτουργικό σύστημα αποφασίζει ποια threads θα εκτελεστούν και πότε. Αυτή η απόφαση επηρεάζεται από το επίπεδο προτεραιότητας που έχει εκχωρηθεί σε κάθε thread. Σε macOS και Unix-like συστήματα, αυτό γίνεται με τη χρήση εννοιών όπως `nice`, `renice` και Quality of Service (QoS) classes.

#### Nice and Renice

1. **Nice:**
- Η τιμή `nice` μιας διεργασίας είναι ένας αριθμός που επηρεάζει την προτεραιότητά της. Κάθε διεργασία έχει μια τιμή `nice` από -20 (η υψηλότερη προτεραιότητα) έως 19 (η χαμηλότερη προτεραιότητα). Η προεπιλεγμένη τιμή `nice` κατά τη δημιουργία μιας διεργασίας είναι συνήθως 0.
- Μια χαμηλότερη τιμή `nice` (πιο κοντά στο -20) κάνει μια διεργασία πιο "selfish", παρέχοντάς της περισσότερο χρόνο CPU σε σύγκριση με άλλες διεργασίες που έχουν υψηλότερες τιμές `nice`.
2. **Renice:**
- Το `renice` είναι μια command που χρησιμοποιείται για την αλλαγή της τιμής `nice` μιας διεργασίας που εκτελείται ήδη. Μπορεί να χρησιμοποιηθεί για τη δυναμική προσαρμογή της προτεραιότητας των διεργασιών, αυξάνοντας ή μειώνοντας τον χρόνο CPU που τους εκχωρείται, με βάση τις νέες τιμές `nice`.
- Για παράδειγμα, αν μια διεργασία χρειάζεται προσωρινά περισσότερους πόρους CPU, μπορεί να μειώσετε την τιμή `nice` της χρησιμοποιώντας το `renice`.

#### Quality of Service (QoS) Classes

Οι QoS classes αποτελούν μια πιο σύγχρονη προσέγγιση στη διαχείριση των προτεραιοτήτων των threads, ιδιαίτερα σε συστήματα όπως το macOS που υποστηρίζουν το **Grand Central Dispatch (GCD)**. Οι QoS classes επιτρέπουν στους developers να **κατηγοριοποιούν** την εργασία σε διαφορετικά επίπεδα, ανάλογα με τη σημασία ή τον επείγοντα χαρακτήρα της. Το macOS διαχειρίζεται αυτόματα την προτεραιοποίηση των threads με βάση αυτές τις QoS classes:

1. **User Interactive:**
- Αυτή η class αφορά εργασίες που αλληλεπιδρούν εκείνη τη στιγμή με τον χρήστη ή απαιτούν άμεσα αποτελέσματα για την παροχή καλής user experience. Σε αυτές τις εργασίες δίνεται η υψηλότερη προτεραιότητα, ώστε το interface να παραμένει responsive (π.χ. animations ή event handling).
2. **User Initiated:**
- Εργασίες που ξεκινούν από τον χρήστη και για τις οποίες αναμένει άμεσα αποτελέσματα, όπως το άνοιγμα ενός document ή το πάτημα ενός button που απαιτεί υπολογισμούς. Έχουν υψηλή προτεραιότητα, αλλά χαμηλότερη από την user interactive.
3. **Utility:**
- Πρόκειται για εργασίες μεγάλης διάρκειας που συνήθως εμφανίζουν progress indicator (π.χ. downloading files ή importing data). Έχουν χαμηλότερη προτεραιότητα από τις user-initiated εργασίες και δεν χρειάζεται να ολοκληρωθούν αμέσως.
4. **Background:**
- Αυτή η class αφορά εργασίες που εκτελούνται στο background και δεν είναι ορατές στον χρήστη. Μπορεί να είναι εργασίες όπως indexing, syncing ή backups. Έχουν τη χαμηλότερη προτεραιότητα και ελάχιστη επίδραση στην απόδοση του συστήματος.

Χρησιμοποιώντας QoS classes, οι developers δεν χρειάζεται να διαχειρίζονται τους ακριβείς αριθμούς προτεραιότητας, αλλά μπορούν να επικεντρώνονται στη φύση της εργασίας, ενώ το σύστημα βελτιστοποιεί ανάλογα τους πόρους CPU.

Επιπλέον, υπάρχουν διαφορετικές **thread scheduling policies** που χρησιμοποιούνται για τον καθορισμό ενός συνόλου scheduling parameters, τα οποία θα λαμβάνει υπόψη ο scheduler. Αυτό μπορεί να γίνει με τη χρήση του `thread_policy_[set/get]`. Αυτό ενδέχεται να είναι χρήσιμο σε race condition attacks.

## MacOS Process Abuse

Το MacOS, όπως κάθε άλλο λειτουργικό σύστημα, παρέχει διάφορες μεθόδους και μηχανισμούς ώστε οι **διεργασίες να αλληλεπιδρούν, να επικοινωνούν και να μοιράζονται δεδομένα**. Αν και αυτές οι τεχνικές είναι απαραίτητες για την αποδοτική λειτουργία του συστήματος, μπορούν επίσης να γίνουν αντικείμενο abuse από threat actors για την **εκτέλεση malicious activities**.

### Library Injection

Το Library Injection είναι μια τεχνική κατά την οποία ένας attacker **εξαναγκάζει μια διεργασία να φορτώσει μια malicious library**. Μετά το injection, η library εκτελείται στο context της target process, παρέχοντας στον attacker τα ίδια permissions και την ίδια πρόσβαση με τη διεργασία.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Το Function Hooking περιλαμβάνει την **παρεμβολή σε function calls** ή messages μέσα σε software code. Με το hooking functions, ένας attacker μπορεί να **τροποποιήσει τη συμπεριφορά** μιας διεργασίας, να παρατηρήσει sensitive data ή ακόμη και να αποκτήσει τον έλεγχο της execution flow.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Το Inter Process Communication (IPC) αναφέρεται σε διαφορετικές μεθόδους μέσω των οποίων ξεχωριστές διεργασίες **μοιράζονται και ανταλλάσσουν δεδομένα**. Αν και το IPC είναι θεμελιώδες για πολλές legitimate applications, μπορεί επίσης να χρησιμοποιηθεί καταχρηστικά για την υπονόμευση της process isolation, το leak sensitive information ή την εκτέλεση unauthorized actions.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Οι Electron applications που εκτελούνται με συγκεκριμένα env variables ενδέχεται να είναι ευάλωτες σε process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Είναι δυνατή η χρήση των flags `--load-extension` και `--use-fake-ui-for-media-stream` για την εκτέλεση **man in the browser attack**, η οποία επιτρέπει την κλοπή keystrokes, traffic και cookies, καθώς και το injection scripts σε pages...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Τα NIB files **ορίζουν στοιχεία user interface (UI)** και τις αλληλεπιδράσεις τους μέσα σε μια application. Ωστόσο, μπορούν να **εκτελέσουν arbitrary commands** και το **Gatekeeper δεν εμποδίζει** την εκτέλεση μιας application που έχει ήδη εκτελεστεί, αν τροποποιηθεί ένα **NIB file**. Επομένως, μπορούν να χρησιμοποιηθούν ώστε arbitrary programs να εκτελούν arbitrary commands:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Είναι δυνατή η κατάχρηση ορισμένων δυνατοτήτων της java (όπως η env variable **`_JAVA_OPTS`**) ώστε μια java application να εκτελέσει **arbitrary code/commands**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Είναι δυνατή η εισαγωγή code σε .Net applications με **κατάχρηση της .Net debugging functionality** (η οποία δεν προστατεύεται από macOS protections, όπως το runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Δείτε διαφορετικές options για να κάνετε ένα Perl script να εκτελέσει arbitrary code στο:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Είναι επίσης δυνατή η κατάχρηση ruby env variables ώστε arbitrary scripts να εκτελούν arbitrary code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Αν έχει οριστεί η environment variable **`PYTHONINSPECT`**, η python process θα εισέλθει σε python cli μόλις ολοκληρώσει την εκτέλεσή της. Είναι επίσης δυνατή η χρήση του **`PYTHONSTARTUP`** για τον καθορισμό ενός python script που θα εκτελείται στην αρχή μιας interactive session.\
Ωστόσο, σημειώστε ότι το **`PYTHONSTARTUP`** script δεν θα εκτελεστεί όταν το **`PYTHONINSPECT`** δημιουργεί την interactive session.

Άλλες env variables, όπως οι **`PYTHONPATH`** και **`PYTHONHOME`**, θα μπορούσαν επίσης να φανούν χρήσιμες ώστε μια python command να εκτελέσει arbitrary code.

Σημειώστε ότι executables που έχουν γίνει compile με το **`pyinstaller`** δεν θα χρησιμοποιήσουν αυτές τις environmental variables, ακόμη και αν εκτελούνται με embedded python.

> [!CAUTION]
> Συνολικά, δεν μπόρεσα να βρω τρόπο ώστε η python να εκτελεί arbitrary code με κατάχρηση των environment variables.\
> Ωστόσο, οι περισσότεροι εγκαθιστούν την pyhton μέσω του **Hombrew**, το οποίο εγκαθιστά την pyhton σε μια **writable location** για τον default admin user. Μπορείτε να την κάνετε hijack με κάτι όπως:
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
> Ακόμη και το **root** θα εκτελέσει αυτόν τον κώδικα όταν εκτελεί python.


## Detection

### Shield

Το [**Shield**](https://github.com/theevilbit/Shield) είναι μια open source application βασισμένη στο **EndpointSecurity**, η οποία ανιχνεύει και μπλοκάρει process injection. Αποτελεί καλή αναφορά για το ποια signals είναι πράγματι observable από το ES, καθώς πραγματοποιεί alert για:<sup>[1]</sup>

- **Injection environment variables** κατά το process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` και `ELECTRON_RUN_AS_NODE`.
- Calls **`task_for_pid`** — μία διεργασία ζητά το task port μιας άλλης διεργασίας, το οποίο αποτελεί prerequisite για την εισαγωγή code σε αυτή.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` και `--remote-debugging-port`, τα οποία ξεκινούν μια Electron app σε debug mode και επιτρέπουν σε οποιονδήποτε να συνδεθεί και να εκτελέσει code σε αυτή.
- **Δημιουργία symlink/hardlink μεταξύ διαφορετικών privilege levels** — το κλασικό primitive "plant a link as a normal user, point it at a privileged location". Σημειώστε ότι τα **symlinks μπορούν να προκαλέσουν alert αλλά δεν μπορούν να μπλοκαριστούν**: το EndpointSecurity δεν εκθέτει τον προορισμό του link πριν από τη δημιουργία του.

### Calls made by other processes

Στο [**this blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) μπορείτε να βρείτε πώς είναι δυνατή η χρήση της function **`task_name_for_pid`** για τη λήψη πληροφοριών σχετικά με άλλα **processes που κάνουν code injection σε μια process** και, στη συνέχεια, τη λήψη πληροφοριών σχετικά με εκείνη την άλλη process.<sup>[4]</sup>

Σημειώστε ότι για να καλέσετε αυτή τη function πρέπει να έχετε **το ίδιο uid** με αυτόν που εκτελεί τη διεργασία ή να είστε **root** (και επιστρέφει πληροφορίες σχετικά με τη διεργασία, όχι τρόπο για code injection).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
