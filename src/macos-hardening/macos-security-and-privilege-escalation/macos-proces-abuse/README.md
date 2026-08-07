# Κατάχρηση διεργασιών στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες για τις διεργασίες

Μια διεργασία είναι ένα instance ενός εκτελέσιμου αρχείου που εκτελείται, ωστόσο οι διεργασίες δεν εκτελούν κώδικα· αυτό το κάνουν τα threads. Επομένως, **οι διεργασίες είναι απλώς containers για την εκτέλεση threads**, παρέχοντας τη μνήμη, τους descriptors, τις ports, τα permissions...

Παραδοσιακά, οι διεργασίες ξεκινούσαν μέσα σε άλλες διεργασίες (εκτός από το PID 1), μέσω της κλήσης της **`fork`**, η οποία δημιουργούσε ένα ακριβές αντίγραφο της τρέχουσας διεργασίας, και στη συνέχεια η **child process** καλούσε συνήθως την **`execve`** για να φορτώσει το νέο εκτελέσιμο αρχείο και να το εκτελέσει. Έπειτα, εισήχθη η **`vfork`**, ώστε να γίνει αυτή η διαδικασία ταχύτερη χωρίς αντιγραφή μνήμης.\
Στη συνέχεια εισήχθη η **`posix_spawn`**, συνδυάζοντας τις **`vfork`** και **`execve`** σε μία κλήση και δεχόμενη flags:

- `POSIX_SPAWN_RESETIDS`: Επαναφορά των effective ids στα real ids
- `POSIX_SPAWN_SETPGROUP`: Ορισμός της affiliation της process group
- `POSUX_SPAWN_SETSIGDEF`: Ορισμός της default συμπεριφοράς των signals
- `POSIX_SPAWN_SETSIGMASK`: Ορισμός του signal mask
- `POSIX_SPAWN_SETEXEC`: Εκτέλεση στο ίδιο process (όπως η `execve` με περισσότερες options)
- `POSIX_SPAWN_START_SUSPENDED`: Έναρξη σε suspended κατάσταση
- `_POSIX_SPAWN_DISABLE_ASLR`: Έναρξη χωρίς ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Χρήση του Nano allocator της libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Allow `rwx` στα data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Κλείσιμο όλων των file descriptions στο exec(2) by default
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomize των high bits του ASLR slide

Επιπλέον, η `posix_spawn` επιτρέπει τον καθορισμό ενός array από **`posix_spawnattr`**, το οποίο ελέγχει ορισμένες πτυχές της spawned process, καθώς και **`posix_spawn_file_actions`** για την τροποποίηση της κατάστασης των descriptors.

Όταν μια διεργασία τερματίζει, στέλνει τον **return code στη parent process** (αν ο parent τερμάτισε, ο νέος parent είναι το PID 1) με το signal `SIGCHLD`. Ο parent πρέπει να λάβει αυτή την τιμή καλώντας τις `wait4()` ή `waitid()` και, μέχρι να συμβεί αυτό, το child παραμένει σε zombie state, όπου συνεχίζει να εμφανίζεται στη λίστα αλλά δεν καταναλώνει resources.

### PIDs

Τα PIDs, δηλαδή τα process identifiers, ταυτοποιούν ένα μοναδικό process. Στο XNU, τα **PIDs** είναι **64bits**, αυξάνονται monotonically και **δεν κάνουν ποτέ wrap** (για την αποφυγή abuses).

### Process Groups, Sessions & Coalations

Οι **Processes** μπορούν να τοποθετηθούν σε **groups**, ώστε να είναι ευκολότερη η διαχείρισή τους. Για παράδειγμα, οι commands σε ένα shell script θα βρίσκονται στην ίδια process group, επομένως είναι δυνατό να γίνουν **signal μαζί** χρησιμοποιώντας, για παράδειγμα, το kill.\
Είναι επίσης δυνατό να **ομαδοποιηθούν processes σε sessions**. Όταν ένα process ξεκινά μια session (`setsid(2)`), τα child processes τοποθετούνται μέσα στη session, εκτός αν ξεκινήσουν τη δική τους session.

Το Coalition είναι ένας ακόμη τρόπος ομαδοποίησης processes στο Darwin. Ένα process που συμμετέχει σε coalition μπορεί να έχει πρόσβαση σε pool resources, να μοιράζεται ένα ledger ή να αντιμετωπίζει Jetsam. Τα Coalations έχουν διαφορετικούς ρόλους: Leader, XPC service, Extension.

### Credentials & Personae

Κάθε process διαθέτει **credentials**, τα οποία **ταυτοποιούν τα privileges του** στο σύστημα. Κάθε process θα έχει ένα primary `uid` και ένα primary `gid` (αν και μπορεί να ανήκει σε πολλές groups).\
Είναι επίσης δυνατό να αλλάξει το user και το group id, αν το binary διαθέτει το bit **`setuid/setgid`**.\
Υπάρχουν διάφορες functions για τον **ορισμό νέων uids/gids**.

Το syscall **`persona`** παρέχει ένα **εναλλακτικό** σύνολο από **credentials**. Η υιοθέτηση μιας persona προϋποθέτει τα uid, gid και group memberships της **ταυτόχρονα**. Στον [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) είναι δυνατό να βρεθεί το struct:
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

1. **POSIX Threads (pthreads):** Το macOS υποστηρίζει POSIX threads (`pthreads`), τα οποία αποτελούν μέρος ενός standard threading API για C/C++. Η υλοποίηση των pthreads στο macOS βρίσκεται στο `/usr/lib/system/libsystem_pthread.dylib`, το οποίο προέρχεται από το publicly available project `libpthread`. Αυτή η βιβλιοθήκη παρέχει τις απαραίτητες functions για τη δημιουργία και τη διαχείριση threads.
2. **Δημιουργία Threads:** Η function `pthread_create()` χρησιμοποιείται για τη δημιουργία νέων threads. Εσωτερικά, αυτή η function καλεί τη `bsdthread_create()`, η οποία είναι ένα lower-level system call, συγκεκριμένο για τον XNU kernel (τον kernel στον οποίο βασίζεται το macOS). Αυτό το system call λαμβάνει διάφορα flags που προέρχονται από το `pthread_attr` (attributes) και καθορίζουν τη συμπεριφορά του thread, συμπεριλαμβανομένων των scheduling policies και του stack size.
- **Default Stack Size:** Το default stack size για τα νέα threads είναι 512 KB, το οποίο επαρκεί για τυπικές λειτουργίες, αλλά μπορεί να προσαρμοστεί μέσω thread attributes αν απαιτείται περισσότερος ή λιγότερος χώρος.
3. **Αρχικοποίηση Thread:** Η function `__pthread_init()` είναι κρίσιμη κατά τη ρύθμιση του thread και χρησιμοποιεί το όρισμα `env[]` για την ανάλυση environment variables, οι οποίες μπορούν να περιλαμβάνουν λεπτομέρειες σχετικά με τη θέση και το μέγεθος του stack.

#### Τερματισμός Thread στο macOS

1. **Έξοδος από Threads:** Τα threads συνήθως τερματίζονται με την κλήση της `pthread_exit()`. Αυτή η function επιτρέπει σε ένα thread να εξέλθει καθαρά, εκτελώντας το απαραίτητο cleanup και επιτρέποντας στο thread να στείλει μια return value σε τυχόν joiners.
2. **Thread Cleanup:** Με την κλήση της `pthread_exit()`, καλείται η function `pthread_terminate()`, η οποία διαχειρίζεται την αφαίρεση όλων των associated thread structures. Αποδεσμεύει τα Mach thread ports (το Mach είναι το communication subsystem στον XNU kernel) και καλεί τη `bsdthread_terminate`, ένα syscall που αφαιρεί τις kernel-level structures που σχετίζονται με το thread.

#### Μηχανισμοί Synchronization

Για τη διαχείριση της πρόσβασης σε shared resources και την αποφυγή race conditions, το macOS παρέχει αρκετά synchronization primitives. Αυτά είναι κρίσιμα σε multi-threading environments για τη διασφάλιση της ακεραιότητας των δεδομένων και της σταθερότητας του συστήματος:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standard mutex με memory footprint 60 bytes (56 bytes για το mutex και 4 bytes για το signature).
- **Fast Mutex (Signature: 0x4d55545A):** Παρόμοιο με ένα regular mutex, αλλά optimized για ταχύτερες operations, επίσης με μέγεθος 60 bytes.
2. **Condition Variables:**
- Χρησιμοποιούνται για την αναμονή συγκεκριμένων conditions, με μέγεθος 44 bytes (40 bytes συν ένα 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes για condition variables, με μέγεθος 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Διασφαλίζει ότι ένα τμήμα initialization code εκτελείται μόνο μία φορά. Το μέγεθός του είναι 12 bytes.
4. **Read-Write Locks:**
- Επιτρέπουν πολλούς readers ή έναν writer κάθε φορά, διευκολύνοντας την αποτελεσματική πρόσβαση σε shared data.
- **Read Write Lock (Signature: 0x52574c4b):** Έχει μέγεθος 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes για read-write locks, με μέγεθος 20 bytes.

> [!TIP]
> Τα τελευταία 4 bytes αυτών των objects χρησιμοποιούνται για την ανίχνευση overflows.

### Thread Local Variables (TLV)

Τα **Thread Local Variables (TLV)** στο πλαίσιο των Mach-O files (το format για executables στο macOS) χρησιμοποιούνται για τη δήλωση variables που είναι specific για **κάθε thread** σε μια multi-threaded application. Αυτό διασφαλίζει ότι κάθε thread έχει το δικό του ξεχωριστό instance μιας variable, παρέχοντας έναν τρόπο αποφυγής conflicts και διατήρησης της ακεραιότητας των δεδομένων χωρίς να απαιτούνται explicit synchronization mechanisms, όπως τα mutexes.

Στη C και σε related languages, μπορείτε να δηλώσετε μια thread-local variable χρησιμοποιώντας το keyword **`__thread`**. Δείτε πώς λειτουργεί στο παράδειγμά σας:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Αυτό το απόσπασμα ορίζει το `tlv_var` ως thread-local μεταβλητή. Κάθε thread που εκτελεί αυτόν τον κώδικα θα έχει το δικό του `tlv_var`, και οι αλλαγές που κάνει ένα thread στο `tlv_var` δεν θα επηρεάζουν το `tlv_var` κάποιου άλλου thread.

Στο Mach-O binary, τα δεδομένα που σχετίζονται με thread local variables οργανώνονται σε συγκεκριμένα sections:

- **`__DATA.__thread_vars`**: Αυτό το section περιέχει metadata σχετικά με τα thread-local variables, όπως τους τύπους τους και την κατάσταση αρχικοποίησής τους.
- **`__DATA.__thread_bss`**: Αυτό το section χρησιμοποιείται για thread-local variables που δεν έχουν αρχικοποιηθεί ρητά. Αποτελεί μέρος της μνήμης που προορίζεται για δεδομένα αρχικοποιημένα σε μηδέν.

Το Mach-O παρέχει επίσης ένα συγκεκριμένο API που ονομάζεται **`tlv_atexit`** για τη διαχείριση των thread-local variables όταν ένα thread τερματίζεται. Αυτό το API επιτρέπει την **καταχώριση destructors**—ειδικών functions που καθαρίζουν τα thread-local δεδομένα όταν ένα thread τερματίζεται.

### Προτεραιότητες Thread

Η κατανόηση των προτεραιοτήτων των thread απαιτεί να εξετάσουμε τον τρόπο με τον οποίο το λειτουργικό σύστημα αποφασίζει ποια threads θα εκτελεστούν και πότε. Αυτή η απόφαση επηρεάζεται από το επίπεδο προτεραιότητας που έχει εκχωρηθεί σε κάθε thread. Σε macOS και Unix-like systems, αυτό γίνεται με τη χρήση εννοιών όπως `nice`, `renice` και Quality of Service (QoS) classes.

#### Nice και Renice

1. **Nice:**
- Η τιμή `nice` μιας process είναι ένας αριθμός που επηρεάζει την προτεραιότητά της. Κάθε process έχει μια τιμή nice από -20 (η υψηλότερη προτεραιότητα) έως 19 (η χαμηλότερη προτεραιότητα). Η προεπιλεγμένη τιμή nice κατά τη δημιουργία μιας process είναι συνήθως 0.
- Μια χαμηλότερη τιμή nice (πιο κοντά στο -20) κάνει μια process πιο "selfish", παρέχοντάς της περισσότερο CPU time σε σύγκριση με άλλες processes που έχουν υψηλότερες τιμές nice.
2. **Renice:**
- Το `renice` είναι μια command που χρησιμοποιείται για την αλλαγή της τιμής nice μιας process που εκτελείται ήδη. Μπορεί να χρησιμοποιηθεί για τη δυναμική προσαρμογή της προτεραιότητας των processes, αυξάνοντας ή μειώνοντας την κατανομή του CPU time με βάση τις νέες τιμές nice.
- Για παράδειγμα, αν μια process χρειάζεται προσωρινά περισσότερους CPU resources, μπορείτε να μειώσετε την τιμή nice χρησιμοποιώντας `renice`.

#### Quality of Service (QoS) Classes

Οι QoS classes αποτελούν μια πιο σύγχρονη προσέγγιση στη διαχείριση των προτεραιοτήτων των thread, ιδιαίτερα σε systems όπως το macOS που υποστηρίζουν το **Grand Central Dispatch (GCD)**. Οι QoS classes επιτρέπουν στους developers να **κατηγοριοποιούν** την εργασία σε διαφορετικά επίπεδα, με βάση τη σημασία ή την επείγουσά της. Το macOS διαχειρίζεται αυτόματα την προτεραιοποίηση των thread με βάση αυτές τις QoS classes:

1. **User Interactive:**
- Αυτή η class προορίζεται για tasks που αλληλεπιδρούν τη δεδομένη στιγμή με τον χρήστη ή απαιτούν άμεσα αποτελέσματα για την παροχή καλής user experience. Αυτά τα tasks λαμβάνουν την υψηλότερη προτεραιότητα, ώστε το interface να παραμένει responsive (π.χ. animations ή event handling).
2. **User Initiated:**
- Tasks που ξεκινούν από τον χρήστη και για τα οποία αναμένονται άμεσα αποτελέσματα, όπως το άνοιγμα ενός document ή το click σε ένα button που απαιτεί υπολογισμούς. Αυτά έχουν υψηλή προτεραιότητα, αλλά χαμηλότερη από τα user interactive.
3. **Utility:**
- Αυτά τα tasks εκτελούνται για μεγάλο χρονικό διάστημα και συνήθως εμφανίζουν progress indicator (π.χ. downloading files, importing data). Έχουν χαμηλότερη προτεραιότητα από τα user-initiated tasks και δεν χρειάζεται να ολοκληρωθούν άμεσα.
4. **Background:**
- Αυτή η class προορίζεται για tasks που εκτελούνται στο background και δεν είναι ορατά στον χρήστη. Μπορεί να είναι tasks όπως indexing, syncing ή backups. Έχουν τη χαμηλότερη προτεραιότητα και ελάχιστο αντίκτυπο στην απόδοση του system.

Χρησιμοποιώντας QoS classes, οι developers δεν χρειάζεται να διαχειρίζονται τους ακριβείς αριθμούς προτεραιότητας, αλλά μπορούν να επικεντρώνονται στη φύση του task, ενώ το system βελτιστοποιεί ανάλογα τους CPU resources.

Επιπλέον, υπάρχουν διαφορετικές **thread scheduling policies** που χρησιμοποιούνται για τον καθορισμό ενός συνόλου scheduling parameters, τα οποία ο scheduler θα λάβει υπόψη. Αυτό μπορεί να γίνει με τη χρήση του `thread_policy_[set/get]`. Αυτό ενδέχεται να είναι χρήσιμο σε race condition attacks.

## MacOS Process Abuse

Το MacOS, όπως κάθε άλλο operating system, παρέχει διάφορες μεθόδους και mechanisms για **processes ώστε να αλληλεπιδρούν, να επικοινωνούν και να μοιράζονται δεδομένα**. Παρόλο που αυτές οι τεχνικές είναι απαραίτητες για την αποτελεσματική λειτουργία του system, μπορούν επίσης να γίνουν αντικείμενο abuse από threat actors για την **εκτέλεση malicious activities**.

### Library Injection

Το Library Injection είναι μια τεχνική κατά την οποία ένας attacker **αναγκάζει μια process να φορτώσει μια malicious library**. Μετά το injection, η library εκτελείται στο context της target process, παρέχοντας στον attacker τα ίδια permissions και access με την process.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Το Function Hooking περιλαμβάνει την **παρεμβολή σε function calls** ή messages μέσα σε software code. Με το hooking functions, ένας attacker μπορεί να **τροποποιήσει τη συμπεριφορά** μιας process, να παρατηρήσει sensitive data ή ακόμη και να αποκτήσει control over το execution flow.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Το Inter Process Communication (IPC) αναφέρεται σε διαφορετικές μεθόδους με τις οποίες ξεχωριστές processes **μοιράζονται και ανταλλάσσουν data**. Παρόλο που το IPC είναι θεμελιώδες για πολλές legitimate applications, μπορεί επίσης να γίνει misuse για την παράκαμψη του process isolation, το leak sensitive information ή την εκτέλεση unauthorized actions.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Οι Electron applications που εκτελούνται με συγκεκριμένα env variables ενδέχεται να είναι ευάλωτες σε process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Είναι δυνατό να χρησιμοποιηθούν τα flags `--load-extension` και `--use-fake-ui-for-media-stream` για την εκτέλεση ενός **man in the browser attack**, επιτρέποντας την κλοπή keystrokes και traffic, cookies, το injection scripts σε pages...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Τα NIB files **ορίζουν στοιχεία user interface (UI)** και τις αλληλεπιδράσεις τους μέσα σε μια application. Ωστόσο, μπορούν να **εκτελέσουν arbitrary commands** και το **Gatekeeper δεν σταματά** μια application που έχει ήδη εκτελεστεί από το να εκτελεστεί ξανά, αν τροποποιηθεί ένα **NIB file**. Επομένως, θα μπορούσαν να χρησιμοποιηθούν ώστε arbitrary programs να εκτελούν arbitrary commands:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Είναι δυνατό να γίνει abuse σε ορισμένες δυνατότητες της Java (όπως το **`_JAVA_OPTS`** env variable), ώστε μια Java application να εκτελέσει **arbitrary code/commands**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Είναι δυνατό να γίνει injection κώδικα σε .Net applications μέσω **abuse της .Net debugging functionality** (η οποία δεν προστατεύεται από macOS protections όπως το runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Ελέγξτε διαφορετικές επιλογές για να κάνετε ένα Perl script να εκτελέσει arbitrary code στο:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Είναι επίσης δυνατό να γίνει abuse σε ruby env variables, ώστε arbitrary scripts να εκτελούν arbitrary code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Αν έχει οριστεί το environment variable **`PYTHONINSPECT`**, η python process θα εισέλθει σε python cli μόλις ολοκληρωθεί. Είναι επίσης δυνατό να χρησιμοποιηθεί το **`PYTHONSTARTUP`** για τον καθορισμό ενός python script που θα εκτελείται στην αρχή ενός interactive session.\
Ωστόσο, σημειώστε ότι το **`PYTHONSTARTUP`** script δεν θα εκτελεστεί όταν το **`PYTHONINSPECT`** δημιουργεί το interactive session.

Άλλα env variables, όπως τα **`PYTHONPATH`** και **`PYTHONHOME`**, θα μπορούσαν επίσης να φανούν χρήσιμα για να κάνουν μια python command να εκτελέσει arbitrary code.

Σημειώστε ότι executables που έχουν γίνει compile με το **`pyinstaller`** δεν θα χρησιμοποιούν αυτά τα environmental variables, ακόμη και αν εκτελούνται με embedded python.

> [!CAUTION]
> Συνολικά, δεν μπόρεσα να βρω τρόπο ώστε η python να εκτελεί arbitrary code μέσω abuse των environment variables.\
> Ωστόσο, οι περισσότεροι εγκαθιστούν την pyhton χρησιμοποιώντας το **Hombrew**, το οποίο εγκαθιστά την pyhton σε μια **writable location** για τον default admin user. Μπορείτε να κάνετε hijack με κάτι όπως:
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


## Εντοπισμός

### Shield

Το [**Shield**](https://github.com/theevilbit/Shield) είναι μια open source application βασισμένη στο **EndpointSecurity**, η οποία εντοπίζει και μπλοκάρει το process injection. Αποτελεί καλή αναφορά για τα signals που είναι πράγματι observable από το ES, καθώς ειδοποιεί για:<sup>[[1]](#references)[[2]](#references)</sup>

- **Injection environment variables** κατά το process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` και `ELECTRON_RUN_AS_NODE`.
- Calls σε **`task_for_pid`** — μία process ζητά το task port μιας άλλης process, το οποίο αποτελεί prerequisite για injection σε αυτή.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` και `--remote-debugging-port`, τα οποία ξεκινούν μια Electron app σε debug mode και επιτρέπουν σε οποιονδήποτε να συνδεθεί και να εκτελέσει code σε αυτή.<sup>[[3]](#references)</sup>
- **Δημιουργία symlink/hardlink μεταξύ διαφορετικών privilege levels** — το κλασικό primitive "δημιούργησε ένα link ως normal user και δείξε το σε μια privileged location". Σημειώστε ότι τα **symlinks μπορούν να εντοπιστούν μέσω alert, αλλά δεν μπορούν να μπλοκαριστούν**: το EndpointSecurity δεν εκθέτει τον προορισμό του link πριν από τη δημιουργία του.

### Calls made by other processes

Σε [**αυτό το blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) μπορείτε να βρείτε πώς είναι δυνατό να χρησιμοποιηθεί η function **`task_name_for_pid`** για τη λήψη πληροφοριών σχετικά με άλλες **processes που κάνουν code injection σε μια process** και στη συνέχεια τη λήψη πληροφοριών σχετικά με αυτή την άλλη process.<sup>[[4]](#references)</sup>

Σημειώστε ότι για την κλήση αυτής της function πρέπει να έχετε **το ίδιο uid** με αυτόν που εκτελεί την process ή να είστε **root** (και επιστρέφει πληροφορίες σχετικά με την process, όχι τρόπο για code injection).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
