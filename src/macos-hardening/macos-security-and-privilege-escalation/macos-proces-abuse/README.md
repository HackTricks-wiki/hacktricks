# Κατάχρηση διεργασιών macOS

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες για τις διεργασίες

Μια διεργασία είναι ένα στιγμιότυπο ενός εκτελούμενου εκτελέσιμου αρχείου· ωστόσο, οι διεργασίες δεν εκτελούν κώδικα, αλλά τα threads. Επομένως, **οι διεργασίες είναι απλώς containers για την εκτέλεση threads**, παρέχοντας τη μνήμη, τους descriptors, τις θύρες, τα δικαιώματα...

Παραδοσιακά, οι διεργασίες ξεκινούσαν μέσα από άλλες διεργασίες (εκτός από το PID 1) μέσω της κλήσης της **`fork`**, η οποία δημιουργούσε ένα ακριβές αντίγραφο της τρέχουσας διεργασίας, και στη συνέχεια η **child process** καλούσε συνήθως την **`execve`** για να φορτώσει το νέο εκτελέσιμο αρχείο και να το εκτελέσει. Έπειτα, εισήχθη η **`vfork`** για να γίνει αυτή η διαδικασία ταχύτερη, χωρίς αντιγραφή μνήμης.\
Στη συνέχεια εισήχθη η **`posix_spawn`**, συνδυάζοντας τις **`vfork`** και **`execve`** σε μία κλήση και δεχόμενη flags:

- `POSIX_SPAWN_RESETIDS`: Επαναφορά των effective ids στα real ids
- `POSIX_SPAWN_SETPGROUP`: Ορισμός της συμμετοχής σε process group
- `POSUX_SPAWN_SETSIGDEF`: Ορισμός της προεπιλεγμένης συμπεριφοράς των signals
- `POSIX_SPAWN_SETSIGMASK`: Ορισμός του signal mask
- `POSIX_SPAWN_SETEXEC`: Εκτέλεση στην ίδια διεργασία (όπως η `execve`, με περισσότερες επιλογές)
- `POSIX_SPAWN_START_SUSPENDED`: Έναρξη σε suspended κατάσταση
- `_POSIX_SPAWN_DISABLE_ASLR`: Έναρξη χωρίς ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Χρήση του Nano allocator του libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Επιτρέπεται `rwx` στα data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Κλείσιμο όλων των file descriptions στο exec(2) από προεπιλογή
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Τυχαιοποίηση των high bits του ASLR slide

Επιπλέον, η `posix_spawn` δέχεται ρυθμίσεις **`posix_spawnattr`**, οι οποίες ελέγχουν πτυχές της spawned process, καθώς και entries **`posix_spawn_file_actions`**, οι οποίες τροποποιούν τα file descriptors.

Όταν μια διεργασία τερματίζει, στέλνει τον **return code στη parent process** (αν η parent process έχει τερματίσει, η νέα parent είναι το PID 1) με το signal `SIGCHLD`. Η parent πρέπει να λάβει αυτή την τιμή καλώντας τις `wait4()` ή `waitid()`· μέχρι να συμβεί αυτό, η child παραμένει σε zombie state, όπου εξακολουθεί να εμφανίζεται στη λίστα, αλλά δεν καταναλώνει πόρους.

### PIDs

Τα PIDs, δηλαδή τα process identifiers, προσδιορίζουν μια μοναδική διεργασία. Στο XNU, τα **PIDs** είναι **64-bit**, αυξάνονται μονοτονικά και **δεν κάνουν ποτέ wrap** (για την αποφυγή καταχρήσεων).

### Process Groups, Sessions & Coalations

Οι **διεργασίες** μπορούν να τοποθετούνται σε **groups**, ώστε να είναι ευκολότερη η διαχείρισή τους. Για παράδειγμα, οι εντολές σε ένα shell script βρίσκονται στο ίδιο process group, επομένως είναι δυνατή η **αποστολή signal σε όλες μαζί**, χρησιμοποιώντας, για παράδειγμα, το kill.\
Είναι επίσης δυνατή η **ομαδοποίηση διεργασιών σε sessions**. Όταν μια διεργασία ξεκινά ένα session (`setsid(2)`), οι child processes τοποθετούνται μέσα στο session, εκτός αν ξεκινήσουν το δικό τους session.

Το Coalition είναι ένας ακόμη τρόπος ομαδοποίησης διεργασιών στο Darwin. Η συμμετοχή μιας διεργασίας σε ένα coalition της επιτρέπει να έχει πρόσβαση σε pool resources, να μοιράζεται ένα ledger ή να αντιμετωπίζει Jetsam. Τα Coalitions έχουν διαφορετικούς ρόλους: Leader, XPC service, Extension.

### Credentials & Personae

Κάθε διεργασία διαθέτει **credentials**, τα οποία **προσδιορίζουν τα δικαιώματά της** στο σύστημα. Κάθε διεργασία έχει ένα primary `uid` και ένα primary `gid` (αν και μπορεί να ανήκει σε πολλές groups).\
Είναι επίσης δυνατή η αλλαγή του user και του group id, αν το binary διαθέτει το bit `setuid/setgid`.\
Υπάρχουν αρκετές functions για τον **ορισμό νέων uids/gids**.

Το syscall **`persona`** παρέχει ένα **εναλλακτικό** σύνολο **credentials**. Η υιοθέτηση ενός persona προϋποθέτει ταυτόχρονα το uid, το gid και τις group memberships του. Στον [**πηγαίο κώδικα**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) είναι δυνατός ο εντοπισμός του struct:
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

1. **POSIX Threads (pthreads):** Το macOS υποστηρίζει POSIX threads (`pthreads`), τα οποία αποτελούν μέρος ενός τυπικού threading API για C/C++. Η υλοποίηση των pthreads στο macOS βρίσκεται στο `/usr/lib/system/libsystem_pthread.dylib` και προέρχεται από το publicly available project `libpthread`. Αυτή η βιβλιοθήκη παρέχει τις απαραίτητες functions για τη δημιουργία και τη διαχείριση threads.
2. **Δημιουργία Threads:** Η function `pthread_create()` χρησιμοποιείται για τη δημιουργία νέων threads. Εσωτερικά, αυτή η function καλεί τη `bsdthread_create()`, η οποία είναι ένα lower-level system call ειδικό για τον XNU kernel (τον kernel στον οποίο βασίζεται το macOS). Αυτό το system call λαμβάνει διάφορα flags που προέρχονται από το `pthread_attr` (attributes) και καθορίζουν τη συμπεριφορά του thread, συμπεριλαμβανομένων των scheduling policies και του stack size.
- **Προεπιλεγμένο Stack Size:** Το προεπιλεγμένο stack size για νέα threads είναι 512 KB, το οποίο επαρκεί για τυπικές λειτουργίες, αλλά μπορεί να προσαρμοστεί μέσω των thread attributes αν χρειάζεται περισσότερος ή λιγότερος χώρος.
3. **Αρχικοποίηση Thread:** Η function `__pthread_init()` είναι κρίσιμη κατά τη ρύθμιση του thread και χρησιμοποιεί το όρισμα `env[]` για την ανάλυση environment variables που μπορούν να περιλαμβάνουν πληροφορίες σχετικά με τη θέση και το μέγεθος του stack.

#### Τερματισμός Threads στο macOS

1. **Έξοδος από Threads:** Τα threads συνήθως τερματίζονται με την κλήση της `pthread_exit()`. Αυτή η function επιτρέπει σε ένα thread να τερματιστεί ομαλά, εκτελώντας το απαραίτητο cleanup και επιτρέποντας στο thread να στείλει μια return value σε οποιαδήποτε joiners.
2. **Thread Cleanup:** Κατά την κλήση της `pthread_exit()`, καλείται η function `pthread_terminate()`, η οποία χειρίζεται την αφαίρεση όλων των associated thread structures. Αποδεσμεύει τα Mach thread ports (το Mach είναι το communication subsystem στον XNU kernel) και καλεί τη `bsdthread_terminate`, ένα syscall που αφαιρεί τις kernel-level structures που σχετίζονται με το thread.

#### Μηχανισμοί Synchronization

Για τη διαχείριση της πρόσβασης σε shared resources και την αποφυγή race conditions, το macOS παρέχει αρκετά synchronization primitives. Αυτά είναι κρίσιμα σε multi-threading environments για τη διασφάλιση της ακεραιότητας των δεδομένων και της σταθερότητας του συστήματος:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standard mutex με memory footprint 60 bytes (56 bytes για το mutex και 4 bytes για το signature).
- **Fast Mutex (Signature: 0x4d55545A):** Παρόμοιο με ένα regular mutex, αλλά optimized για ταχύτερες operations, επίσης μεγέθους 60 bytes.
2. **Condition Variables:**
- Χρησιμοποιούνται για την αναμονή μέχρι να συμβούν συγκεκριμένες conditions, με μέγεθος 44 bytes (40 bytes συν ένα signature 4 bytes).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes για condition variables, μεγέθους 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Διασφαλίζει ότι ένα τμήμα initialization code εκτελείται μόνο μία φορά. Το μέγεθός του είναι 12 bytes.
4. **Read-Write Locks:**
- Επιτρέπει σε πολλούς readers ή σε έναν writer κάθε φορά, διευκολύνοντας την efficient πρόσβαση σε shared data.
- **Read Write Lock (Signature: 0x52574c4b):** Μεγέθους 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes για read-write locks, μεγέθους 20 bytes.

> [!TIP]
> Τα τελευταία 4 bytes αυτών των objects χρησιμοποιούνται για την ανίχνευση overflows.

### Thread Local Variables (TLV)

Οι **Thread Local Variables (TLV)** στο πλαίσιο των αρχείων Mach-O (το format για executables στο macOS) χρησιμοποιούνται για τη δήλωση variables που είναι ειδικές για **κάθε thread** σε μια multi-threaded application. Αυτό διασφαλίζει ότι κάθε thread έχει το δικό του ξεχωριστό instance μιας variable, παρέχοντας έναν τρόπο αποφυγής conflicts και διατήρησης της ακεραιότητας των δεδομένων χωρίς να απαιτούνται explicit synchronization mechanisms, όπως mutexes.

Στις C και related languages, μπορείτε να δηλώσετε μια thread-local variable χρησιμοποιώντας το keyword **`__thread`**. Δείτε πώς λειτουργεί στο παράδειγμά σας:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Αυτό το απόσπασμα ορίζει το `tlv_var` ως thread-local μεταβλητή. Κάθε thread που εκτελεί αυτόν τον κώδικα θα έχει το δικό του `tlv_var`, και οι αλλαγές που κάνει ένα thread στο `tlv_var` δεν θα επηρεάζουν το `tlv_var` κάποιου άλλου thread.

Στο Mach-O binary, τα δεδομένα που σχετίζονται με thread local μεταβλητές οργανώνονται σε συγκεκριμένα sections:

- **`__DATA.__thread_vars`**: Αυτό το section περιέχει τα metadata σχετικά με τις thread-local μεταβλητές, όπως τους τύπους τους και την κατάσταση αρχικοποίησής τους.
- **`__DATA.__thread_bss`**: Αυτό το section χρησιμοποιείται για thread-local μεταβλητές που δεν έχουν αρχικοποιηθεί ρητά. Αποτελεί τμήμα της μνήμης που προορίζεται για δεδομένα αρχικοποιημένα σε μηδέν.

Το Mach-O παρέχει επίσης ένα συγκεκριμένο API που ονομάζεται **`tlv_atexit`** για τη διαχείριση των thread-local μεταβλητών όταν ένα thread τερματίζεται. Αυτό το API επιτρέπει την **καταχώριση destructors** — ειδικών functions που καθαρίζουν τα thread-local δεδομένα όταν ένα thread τερματίζεται.

### Προτεραιότητες Thread

Η κατανόηση των προτεραιοτήτων των thread απαιτεί την εξέταση του τρόπου με τον οποίο το λειτουργικό σύστημα αποφασίζει ποια thread θα εκτελούνται και πότε. Αυτή η απόφαση επηρεάζεται από το επίπεδο προτεραιότητας που έχει εκχωρηθεί σε κάθε thread. Σε macOS και Unix-like συστήματα, αυτό γίνεται με τη χρήση εννοιών όπως `nice`, `renice` και Quality of Service (QoS) classes.

#### Nice και Renice

1. **Nice:**
- Η τιμή `nice` μιας διεργασίας είναι ένας αριθμός που επηρεάζει την προτεραιότητά της. Κάθε διεργασία έχει τιμή nice από -20 (η υψηλότερη προτεραιότητα) έως 19 (η χαμηλότερη προτεραιότητα). Η προεπιλεγμένη τιμή nice κατά τη δημιουργία μιας διεργασίας είναι συνήθως 0.
- Μια χαμηλότερη τιμή nice (πιο κοντά στο -20) κάνει μια διεργασία πιο «εγωιστική», δίνοντάς της περισσότερο CPU time σε σύγκριση με άλλες διεργασίες που έχουν υψηλότερες τιμές nice.
2. **Renice:**
- Το `renice` είναι command που χρησιμοποιείται για την αλλαγή της τιμής nice μιας διεργασίας που εκτελείται ήδη. Μπορεί να χρησιμοποιηθεί για τη δυναμική προσαρμογή της προτεραιότητας των διεργασιών, αυξάνοντας ή μειώνοντας την κατανομή CPU time με βάση τις νέες τιμές nice.
- Για παράδειγμα, αν μια διεργασία χρειάζεται προσωρινά περισσότερους CPU resources, μπορείτε να μειώσετε την τιμή nice χρησιμοποιώντας το `renice`.

#### Quality of Service (QoS) Classes

Οι QoS classes αποτελούν μια πιο σύγχρονη προσέγγιση στη διαχείριση των προτεραιοτήτων των thread, ιδιαίτερα σε συστήματα όπως το macOS που υποστηρίζουν το **Grand Central Dispatch (GCD)**. Οι QoS classes επιτρέπουν στους developers να **κατηγοριοποιούν** την εργασία σε διαφορετικά επίπεδα, ανάλογα με τη σημασία ή το επείγον της. Το macOS διαχειρίζεται αυτόματα την προτεραιοποίηση των thread με βάση αυτές τις QoS classes:

1. **User Interactive:**
- Αυτή η class αφορά tasks που αλληλεπιδρούν αυτήν τη στιγμή με τον χρήστη ή απαιτούν άμεσα αποτελέσματα για την παροχή καλής user experience. Σε αυτά τα tasks δίνεται η υψηλότερη προτεραιότητα, ώστε το interface να παραμένει responsive (π.χ. animations ή event handling).
2. **User Initiated:**
- Tasks που ξεκινούν από τον χρήστη και για τα οποία αναμένονται άμεσα αποτελέσματα, όπως το άνοιγμα ενός document ή το κλικ σε ένα button που απαιτεί υπολογισμούς. Έχουν υψηλή προτεραιότητα, αλλά χαμηλότερη από τα user interactive tasks.
3. **Utility:**
- Αυτά τα tasks εκτελούνται για μεγάλο χρονικό διάστημα και συνήθως εμφανίζουν progress indicator (π.χ. downloading files, importing data). Έχουν χαμηλότερη προτεραιότητα από τα user-initiated tasks και δεν χρειάζεται να ολοκληρωθούν άμεσα.
4. **Background:**
- Αυτή η class αφορά tasks που εκτελούνται στο background και δεν είναι ορατά στον χρήστη. Μπορεί να είναι tasks όπως indexing, syncing ή backups. Έχουν τη χαμηλότερη προτεραιότητα και ελάχιστη επίδραση στην απόδοση του συστήματος.

Χρησιμοποιώντας QoS classes, οι developers δεν χρειάζεται να διαχειρίζονται τους ακριβείς αριθμούς προτεραιότητας, αλλά να επικεντρώνονται στη φύση του task, ενώ το σύστημα βελτιστοποιεί ανάλογα τους CPU resources.

Επιπλέον, υπάρχουν διαφορετικές **thread scheduling policies** που καθορίζουν ένα σύνολο scheduling parameters τα οποία ο scheduler θα λάβει υπόψη. Αυτό μπορεί να γίνει με τη χρήση του `thread_policy_[set/get]`. Αυτό ενδέχεται να είναι χρήσιμο σε race condition attacks.

## macOS Process Abuse

Το macOS παρέχει πολλούς μηχανισμούς ώστε οι **διεργασίες να αλληλεπιδρούν, να επικοινωνούν και να μοιράζονται δεδομένα**. Παρόλο που αυτοί οι μηχανισμοί είναι απαραίτητοι για τη φυσιολογική λειτουργία του συστήματος, οι attackers μπορούν να τους εκμεταλλευτούν για injection, code execution ή πρόσβαση σε δεδομένα.

### Library Injection

Το Library Injection είναι τεχνική κατά την οποία ένας attacker **αναγκάζει μια διεργασία να φορτώσει μια κακόβουλη library**. Μετά το injection, η library εκτελείται στο context της target διεργασίας, παρέχοντας στον attacker τα ίδια permissions και access με τη διεργασία.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Το Function Hooking περιλαμβάνει την **παρεμβολή σε function calls** ή messages μέσα σε software code. Με το hooking functions, ένας attacker μπορεί να **τροποποιήσει τη συμπεριφορά** μιας διεργασίας, να παρατηρήσει ευαίσθητα δεδομένα ή ακόμη και να αποκτήσει έλεγχο στη ροή εκτέλεσης.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Το Inter Process Communication (IPC) αναφέρεται σε διαφορετικές μεθόδους με τις οποίες ξεχωριστές διεργασίες **μοιράζονται και ανταλλάσσουν δεδομένα**. Παρόλο που το IPC είναι θεμελιώδες για πολλές νόμιμες εφαρμογές, μπορεί επίσης να χρησιμοποιηθεί καταχρηστικά για την παράκαμψη της απομόνωσης διεργασιών, το leak ευαίσθητων πληροφοριών ή την εκτέλεση μη εξουσιοδοτημένων ενεργειών.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Οι Electron applications που εκτελούνται με συγκεκριμένες env variables ενδέχεται να είναι ευάλωτες σε process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Είναι δυνατή η χρήση των flags `--load-extension` και `--use-fake-ui-for-media-stream` για την πραγματοποίηση **man in the browser attack**, που επιτρέπει την υποκλοπή keystrokes και traffic, την κλοπή cookies, το injection scripts σε pages...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Τα NIB files **ορίζουν στοιχεία user interface (UI)** και τις αλληλεπιδράσεις τους μέσα σε μια εφαρμογή. Ωστόσο, μπορούν να **εκτελέσουν arbitrary commands** και το **Gatekeeper δεν εμποδίζει** την εκ νέου εκτέλεση μιας εφαρμογής που έχει ήδη εκτελεστεί, αν ένα **NIB file τροποποιηθεί**. Επομένως, θα μπορούσαν να χρησιμοποιηθούν ώστε arbitrary programs να εκτελέσουν arbitrary commands:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Είναι δυνατή η εισαγωγή JVM options μέσω των **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ή **`JDK_JAVA_OPTIONS`** και η φόρτωση ενός Java ή native agent πριν ξεκινήσει η εφαρμογή.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

Το **`NODE_OPTIONS`** κάνει preload attacker JavaScript μέσω των `--require` (file) ή `--import data:text/javascript,…` (fileless, Node ≥ 20.6). Το **`NODE_REPL_EXTERNAL_MODULE`** φορτώνει ένα module σε ένα interactive REPL και το **`ELECTRON_RUN_AS_NODE`** επανενεργοποιεί όλα τα παραπάνω σε Electron binaries.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Είναι δυνατή η εισαγωγή code σε .NET applications μέσω του **`DOTNET_STARTUP_HOOKS`** πριν από το `Main` ή μέσω abuse της .NET debugging functionality όταν υπάρχουν τα απαιτούμενα prerequisites.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Το non-interactive Bash διαβάζει το **`BASH_ENV`**. Τα interactive POSIX shells διαβάζουν το **`ENV`**. Το zsh διαβάζει το **`$ZDOTDIR/.zshenv`** και το fish διαβάζει configuration κάτω από το **`XDG_CONFIG_HOME`** ή το **`XDG_DATA_DIRS`**. Καθένα από αυτά μπορεί να εκτελέσει ένα controlled startup file πριν από το intended command. Το Bash εκτελεί επίσης ένα command substitution που βρίσκεται στο **`PS4`** κάθε φορά που ενεργοποιείται το xtrace (π.χ. μέσω inherited **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

Τα **`PHPRC`** ή **`PHP_INI_SCAN_DIR`** μπορούν να φορτώσουν controlled PHP configuration, της οποίας το **`auto_prepend_file`** εκτελείται πριν από το target script.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Ο standalone Lua interpreter εκτελεί code ή ένα `@file` από το **`LUA_INIT`** (ή την αντίστοιχη version-specific variant) πριν από την επεξεργασία του target script.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

Τα **`R_PROFILE_USER`** και **`R_PROFILE`** ανακατευθύνουν startup profiles που περιέχουν R code. Τα **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, μαζί με ένα R library path, μπορούν εναλλακτικά να κάνουν auto-load ένα installed package.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

Το **`JULIA_DEPOT_PATH`** ανακατευθύνει το depot, του οποίου το `config/startup.jl` εκτελείται αυτόματα.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

Τα **`ERL_AFLAGS`**, **`ERL_FLAGS`** ή **`ERL_ZFLAGS`** μπορούν να κάνουν inject μια Erlang VM **`-eval`** expression χωρίς να απαιτείται payload file. Τα Elixir workloads συνήθως ξεκινούν την ίδια VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

Τα **`OCTAVE_SITE_INITFILE`** και **`OCTAVE_VERSION_INITFILE`** ανακατευθύνουν τα Octave startup scripts.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

Το `pwsh` είναι cross-platform .NET app, επομένως αρκετές environment variables επιτρέπουν pre-command execution: το **`XDG_CONFIG_HOME`** ανακατευθύνει τα profile scripts που εκτελούνται κατά το startup, το **`PSModulePath`** κάνει hijack το module auto-loading (ένα planted `.psm1` εκτελείται κατά το import time και μπορεί να κάνει shadow built-in cmdlets) και οι .NET μεταβλητές **`CORECLR_PROFILER`**/**`COR_PROFILER`** και **`DOTNET_STARTUP_HOOKS`** φορτώνουν attacker code στη διεργασία πριν από το `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Ελέγξτε διαφορετικές options ώστε ένα Perl script να εκτελέσει arbitrary code σε:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Είναι επίσης δυνατή η κατάχρηση των ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) ώστε arbitrary scripts να εκτελούν arbitrary code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Η αλυσίδα **`PYTHONWARNINGS`** και **`BROWSER`** της standard library μπορεί να εκτελέσει ένα command κατά το warning-filter parsing. Μια file-backed εναλλακτική τοποθετεί το `sitecustomize.py` στο **`PYTHONPATH`**, ώστε το κανονικό `site` initialization να το κάνει import πριν από το target script. Το **`PYTHONBREAKPOINT`** εκτελεί ένα επιλεγμένο callable/module όταν ο κώδικας φτάσει στο `breakpoint()`. Variables που είναι interactive-only, όπως το **`PYTHONSTARTUP`**, έχουν πιο περιορισμένη εφαρμογή.

Σημειώστε ότι executables που έχουν γίνει compile με **`pyinstaller`** δεν χρησιμοποιούν αυτές τις environmental variables, ακόμη κι αν εκτελούνται με embedded python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

Το **`VIMINIT`** (και το fallback **`EXINIT`**) εκτελείται ως Ex commands κατά το κανονικό startup. Επομένως, τα `:!cmd` / `:call system(...)` παρέχουν code execution όταν ένα victim ανοίγει το Vim/Neovim με controlled environment:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ξεχωριστά, το Homebrew εγκαθιστά συνήθως την Python κάτω από το `/opt/homebrew`, όπου μέλη του local `admin` group ενδέχεται να μπορούν να αντικαταστήσουν τον launcher. Αυτό αποτελεί writable-binary hijack και όχι environment-variable injection. Επαληθεύστε το ownership και τα ACLs πριν το θεωρήσετε exploitable.


## Ανίχνευση

### Shield

Το [**Shield**](https://github.com/theevilbit/Shield) είναι μια open-source εφαρμογή βασισμένη στο **EndpointSecurity**, η οποία ανιχνεύει και μπλοκάρει process injection. Αποτελεί καλή αναφορά για τα signals που είναι observable μέσω του Endpoint Security, καθώς κάνει alert για:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** κατά το process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` και `ELECTRON_RUN_AS_NODE`.
- Κλήσεις **`task_for_pid`** — μία διεργασία ζητά το task port μιας άλλης, κάτι που αποτελεί prerequisite για το injection σε αυτήν.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` και `--remote-debugging-port`, τα οποία ξεκινούν μια Electron app σε debug mode και επιτρέπουν σε οποιονδήποτε να συνδεθεί και να εκτελέσει code σε αυτήν.<sup>[[3]](#references)</sup>
- **Δημιουργία symlink/hardlink μεταξύ διαφορετικών privilege levels** — το κλασικό primitive «τοποθέτησε ένα link ως normal user και δείξε το σε privileged location». Σημειώστε ότι τα **symlinks μπορούν να καταγραφούν ως alerts αλλά όχι να μπλοκαριστούν**: το EndpointSecurity δεν εκθέτει τον προορισμό του link πριν από τη δημιουργία του.

### Κλήσεις από άλλες διεργασίες

Σε [**αυτό το blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) μπορείτε να βρείτε πώς είναι δυνατή η χρήση της function **`task_name_for_pid`** για τη λήψη πληροφοριών σχετικά με άλλες **διεργασίες που κάνουν injection code σε μια διεργασία** και στη συνέχεια τη λήψη πληροφοριών σχετικά με εκείνη την άλλη διεργασία.<sup>[[4]](#references)</sup>

Σημειώστε ότι για να καλέσετε αυτήν τη function πρέπει να έχετε **το ίδιο uid** με αυτόν που εκτελεί τη διεργασία ή να είστε **root** (και επιστρέφει πληροφορίες για τη διεργασία, όχι τρόπο για injection code).

## References

- [1] [Shield — open source ανίχνευση macOS process-injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Γιατί οι Electron apps δεν μπορούν να αποθηκεύσουν τα secrets σας εμπιστευτικά: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Ανίχνευση task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
