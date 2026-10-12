# Μεθοδολογία Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Σημασιολογία

Στο **mutational grammar fuzzing**, τα inputs μεταλλάσσονται διατηρώντας την **εγκυρότητα της γραμματικής**. Σε λειτουργία με καθοδήγηση από το coverage, αποθηκεύονται ως corpus seeds μόνο τα δείγματα που προκαλούν **νέο coverage**. Για **στόχους γλωσσών** (parsers, interpreters, engines), έτσι μπορεί να χαθούν bugs που απαιτούν **αλυσίδες σημασιολογίας/dataflow**, όπου η έξοδος μιας δομής γίνεται είσοδος μιας άλλης.<sup>[[1]](#references)</sup>

**Τρόπος αποτυχίας:** ο fuzzer βρίσκει seeds που ασκούν μεμονωμένα τα `document()` και `generate-id()` (ή παρόμοια primitives), αλλά **δεν διατηρεί το chained dataflow**, με αποτέλεσμα να απορρίπτεται το δείγμα που είναι «πιο κοντά στο bug», επειδή δεν προσθέτει coverage. Με **3+ εξαρτημένα βήματα**, ο τυχαίος ανασυνδυασμός γίνεται δαπανηρός και το feedback από το coverage δεν καθοδηγεί την αναζήτηση.<sup>[[1]](#references)</sup>

**Συνέπεια:** για γραμματικές με πολλές εξαρτήσεις, εξετάστε το ενδεχόμενο **συνδυασμού των mutational και generative φάσεων** ή μεροληψίας της παραγωγής προς μοτίβα **αλυσιδωτής σύνδεσης συναρτήσεων** (και όχι μόνο προς το coverage).<sup>[[1]](#references)</sup>

## Παγίδες στην Ποικιλομορφία του Corpus

Η μετάλλαξη με καθοδήγηση από το coverage είναι **άπληστη**: ένα δείγμα που δίνει νέο coverage αποθηκεύεται αμέσως, συχνά διατηρώντας μεγάλες αμετάβλητες περιοχές. Με τον καιρό, τα corpus γεμίζουν με **σχεδόν πανομοιότυπα** δείγματα και έχουν μικρή δομική ποικιλομορφία. Η επιθετική ελαχιστοποίηση μπορεί να αφαιρέσει χρήσιμο πλαίσιο, γι' αυτό ένας πρακτικός συμβιβασμός είναι η **ελαχιστοποίηση με επίγνωση της γραμματικής**, η οποία **σταματά μόλις επιτευχθεί ένα ελάχιστο όριο tokens** (μειώνοντας τον θόρυβο, αλλά διατηρώντας αρκετή περιβάλλουσα δομή ώστε να διευκολύνονται οι μεταλλάξεις).<sup>[[1]](#references)</sup>

Ένας πρακτικός κανόνας για το corpus στο mutational fuzzing είναι ο εξής: **προτιμήστε ένα μικρό σύνολο δομικά διαφορετικών seeds που μεγιστοποιούν το coverage** αντί για μια μεγάλη συλλογή σχεδόν πανομοιότυπων δειγμάτων. Στην πράξη, αυτό συνήθως σημαίνει τα εξής.<sup>[[1]](#references)[[3]](#references)</sup>

- Ξεκινήστε από **δείγματα του πραγματικού κόσμου** (δημόσια corpora, crawling, καταγεγραμμένη κίνηση δικτύου, σύνολα αρχείων από το οικοσύστημα του στόχου).
- Συμπυκνώστε τα με **ελαχιστοποίηση corpus βάσει coverage**, αντί να διατηρείτε κάθε έγκυρο δείγμα.
- Διατηρήστε τα seeds **αρκετά μικρά**, ώστε οι μεταλλάξεις να στοχεύουν ουσιαστικά πεδία αντί να σπαταλούν τους περισσότερους κύκλους σε άσχετα bytes.
- Επαναλάβετε την ελαχιστοποίηση του corpus μετά από σημαντικές αλλαγές στο harness/instrumentation, επειδή το «καλύτερο» corpus αλλάζει όταν αλλάζει η δυνατότητα προσέγγισης κώδικα.

## Mutation με Επίγνωση Συγκρίσεων για Magic Values

Ένας συνηθισμένος λόγος που οι fuzzers φτάνουν σε τέλμα δεν είναι η σύνταξη, αλλά οι **συγκρίσεις που είναι δύσκολο να ικανοποιηθούν**: magic bytes, έλεγχοι μήκους, συμβολοσειρές enum, checksums ή τιμές dispatch των parsers που προστατεύονται από `memcmp`, πίνακες switch ή αλυσιδωτές συγκρίσεις. Η καθαρά τυχαία μετάλλαξη σπαταλά κύκλους προσπαθώντας να μαντέψει αυτές τις τιμές byte προς byte.

Για αυτούς τους στόχους, χρησιμοποιήστε **ιχνηλάτηση συγκρίσεων** (για παράδειγμα, workflows τύπου AFL++ `CMPLOG` / Redqueen), ώστε ο fuzzer να μπορεί να παρατηρεί τα operands των αποτυχημένων συγκρίσεων και να κατευθύνει τις μεταλλάξεις προς τιμές που τις ικανοποιούν.<sup>[[3]](#references)</sup>

```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```

**Πρακτικές σημειώσεις:**

- Αυτό είναι ιδιαίτερα χρήσιμο όταν ο στόχος αποκρύπτει τη βαθύτερη λογική πίσω από **υπογραφές αρχείων**, **ρήματα πρωτοκόλλου**, **ετικέτες τύπου** ή **bits δυνατοτήτων που εξαρτώνται από την έκδοση**.
- Συνδυάστε το με **dictionaries** που έχουν εξαχθεί από πραγματικά δείγματα, προδιαγραφές πρωτοκόλλων ή αρχεία καταγραφής αποσφαλμάτωσης. Ένα μικρό dictionary με tokens γραμματικής, ονόματα chunks, ρήματα και διαχωριστικά είναι συχνά πιο πολύτιμο από μια τεράστια γενική wordlist.
- Αν ο στόχος εκτελεί πολλούς διαδοχικούς ελέγχους, επιλύστε πρώτα τις αρχικές συγκρίσεις “magic” και, στη συνέχεια, ελαχιστοποιήστε ξανά το corpus που προκύπτει, ώστε τα επόμενα στάδια να ξεκινούν από έγκυρα prefixes.

## Πλουσιότερη ανατροφοδότηση όταν το edge coverage συγχωνεύει διαφορετικές διαδρομές

Το κανονικό edge coverage δεν μπορεί να διακρίνει δύο εκτελέσεις που περνούν από τον ίδιο helper μέσω διαφορετικών callers ή ακολουθούν διαφορετικούς συνδυασμούς διακλαδώσεων μέσα σε μια συνάρτηση. Αυτό έχει σημασία σε κοινόχρηστους decoders, dispatchers πρωτοκόλλων και helpers interpreters, όπου η **διαδρομή** προς ένα edge καθορίζει την ενεργή κατάσταση. Η αφελής παρακολούθηση κάθε calling context είναι επίσης επικίνδυνη: ο χάρτης κάλυψης και η ουρά μπορούν να διογκωθούν υπερβολικά. Επομένως, η έρευνα για το context-sensitive fuzzing συνιστά τη βελτίωση μόνο των υποσχόμενων contexts, αντί να αντιμετωπίζεται ολόκληρο το γράφημα κλήσεων ως context-sensitive.<sup>[[14]](#references)</sup>

Οι πρόσφατες εκδόσεις του AFL++ παρέχουν **Ball-Larus per-function path coverage**, επιπλέον του κανονικού edge coverage. Αναθέτει ένα feature σε κάθε άκυκλη διαδρομή μέσα σε μια συνάρτηση· αφαιρούνται οι οπίσθιες ακμές των loops, επομένως αυτή η ανατροφοδότηση διακρίνει συνδυασμούς διακλαδώσεων, αλλά **όχι τον αριθμό των επαναλήψεων των loops**. Ξεκινήστε με το χαλαρό επίπεδο `1` και, στη συνέχεια, περιορίστε τις αυστηρότερες λειτουργίες σε ύποπτο κώδικα parser/state machine, επειδή ο αριθμός των διαδρομών μπορεί να αυξηθεί εκθετικά.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Για μια βοηθητική συνάρτηση που καλείται από πολλές τοποθεσίες σχετικές με την ασφάλεια, η λειτουργία LTO μπορεί να συνδυάσει κάθε διαδρομή συνάρτησης με την άμεση τοποθεσία κλήσης:<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

**Οδηγίες για την campaign:** χρησιμοποιήστε πιο πλούσιο feedback με φειδώ και παρακολουθείτε το κόστος του coverage map και της queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Τρέξτε παράλληλα ένα συνηθισμένο instance με edge coverage· το πιο πλούσιο feedback είναι χρήσιμο μόνο αν το πρόσθετο κόστος της queue/map δεν μειώνει υπερβολικά τις εκτελέσεις ανά δευτερόλεπτο.
- Χρησιμοποιήστε το `AFL_LLVM_ALLOWLIST` για να περιορίσετε το path/caller instrumentation, όταν μεγάλες βιβλιοθήκες με πολλά templates ή γενικός κώδικας βοηθητικών συναρτήσεων κυριαρχούν στο map.
- Οι συναρτήσεις με υπερβολικά πολλά acyclic paths μπορούν να παραλειφθούν από το AFL++· οι προειδοποιήσεις κατά τη μεταγλώττιση υποδεικνύουν ότι ο στόχος χρειάζεται allowlisting ή λιγότερο αυστηρό επίπεδο.
- Το caller + path coverage υποστηρίζει μόνο ένα επίπεδο caller. Μην το συνδυάζετε με βαθύτερα context stacks.
- Τα path IDs μπορεί να αλλάξουν μεταξύ κύριων εκδόσεων του LLVM. Διατηρήστε σταθερό το toolchain σε όλη την campaign και μην συγχρονίζετε corpora που βασίζονται σε PATH σαν να ήταν τα feature IDs σταθερά μεταξύ builds.
- Αυτό το feedback συμπληρώνει το `CMPLOG`: το comparison tracing επιλύει το **ποια τιμή περνά έναν guard**, ενώ το path/caller feedback διατηρεί το **ποια διαδρομή και ποιος συνδυασμός branches οδήγησαν εκεί**.

## Stateful Fuzzing: Οι ακολουθίες είναι seeds

Για **protocols**, **authenticated workflows** και **parsers πολλών σταδίων**, η μονάδα ενδιαφέροντος συχνά δεν είναι ένα μεμονωμένο blob, αλλά μια **ακολουθία μηνυμάτων**. Η συνένωση ολόκληρου του transcript σε ένα αρχείο και η τυφλή μετάλλαξή του είναι συνήθως αναποτελεσματική, επειδή ο fuzzer μεταλλάσσει όλα τα βήματα εξίσου, ακόμη κι όταν μόνο το μεταγενέστερο μήνυμα φτάνει στην εύθραυστη κατάσταση.<sup>[[4]](#references)</sup>

Μια πιο αποτελεσματική προσέγγιση είναι να θεωρείτε την **ίδια την ακολουθία** seed και να χρησιμοποιείτε την **παρατηρήσιμη κατάσταση** (response codes, protocol states, φάσεις parser, τύπους αντικειμένων που επιστρέφονται) ως πρόσθετο feedback.<sup>[[4]](#references)</sup>

- Διατηρήστε σταθερά τα **έγκυρα μηνύματα προθέματος** και εστιάστε τις μεταλλάξεις στο μήνυμα που **οδηγεί στη μετάβαση**.
- Αποθηκεύστε identifiers και τιμές που δημιουργεί ο server από προηγούμενες αποκρίσεις, όταν το επόμενο βήμα εξαρτάται από αυτά.
- Προτιμήστε μετάλλαξη/splicing ανά μήνυμα αντί για μετάλλαξη ολόκληρου του serialized transcript ως αδιαφανούς blob.
- Αν το protocol εκθέτει ουσιαστικά response codes, χρησιμοποιήστε τα ως **φθηνό state oracle** για να δίνετε προτεραιότητα σε ακολουθίες που προχωρούν βαθύτερα.

Για τον ίδιο λόγο, bugs σε authenticated λειτουργίες, κρυφές μεταβάσεις ή bugs parser που εμφανίζονται «μόνο μετά το handshake» συχνά διαφεύγουν από το συνηθισμένο file-style fuzzing: ο fuzzer πρέπει να διατηρεί **τη σειρά, την κατάσταση και τις εξαρτήσεις**, όχι μόνο τη δομή.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing driver με πολλούς clients

Το υψηλό edge coverage μπορεί και πάλι να μην εντοπίσει bugs σε IPC drivers, επειδή το coverage δεν περιγράφει **την ιδιοκτησία αντικειμένων, τα reference counts, τα εκκρεμή μηνύματα, τη σειρά καθαρισμού ή τις εναλλαγές μεταξύ threads**. Η σελίδα [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) καλύπτει το μοντέλο αντικειμένων του driver· αυτό το παράδειγμα εστιάζει στο harness του fuzzer. Το Android Binder αποτελεί χρήσιμο μοντέλο: δεν αρκεί να φτάνει ο fuzzer τόσο στις διαδρομές allocation όσο και στις διαδρομές free, αν δεν μπορεί να κάνει πολλαπλές διεργασίες να ενεργούν στο ίδιο kernel object με την απαιτούμενη σειρά.<sup>[[15]](#references)</sup>

#### Μοντελοποιήστε το protocol, όχι μεμονωμένα buffers `ioctl`

Αναπαραστήστε ένα test case ως διατεταγμένη γραμματική από **ταυτότητα client + operation + δομημένα arguments**. Ο Binder LKL fuzzer χρησιμοποιεί protobuf και `libprotobuf-mutator`, με έναν persistent context-manager client και δύο συνηθισμένους clients. Ένα semantic harness διατηρεί κατόπιν τις σχέσεις που θα κατέστρεφε η τυφλή μετάλλαξη bytes.<sup>[[15]](#references)</sup>

- Αποθηκεύστε τιμές που επιστρέφουν προηγούμενες operations. Για παράδειγμα, το `BC_FREE_BUFFER` πρέπει να επαναχρησιμοποιήσει έναν transaction-buffer pointer που επέστρεψε προηγούμενο `ioctl`.
- Δημιουργήστε έγκυρες προεπιλεγμένες απαντήσεις, ώστε να ολοκληρώνονται οι synchronous transactions και να παραμένουν προσβάσιμες μεταγενέστερες operations.
- Απορρίψτε αδύνατες μεταβάσεις, όπως self-transactions ή πολλαπλές εκκρεμείς transactions προς τον ίδιο στόχο.
- Διατηρήστε την singleton κατάσταση εκκίνησης έξω από το reset ανά input. Το Binder επιτρέπει μόνο μία εγγραφή `BINDER_SET_CONTEXT_MGR` ανά εκκίνηση, επομένως η επανειλημμένη καταστροφή και αναδημιουργία αυτού του client θα καθιστούσε άκυρα τα επόμενα inputs.

Ένα χρήσιμο πρότυπο για lifetime race είναι να κάνει ένας client transfer ενός αντικειμένου, να ξεκινήσει ο καθαρισμός thread ή process και, ταυτόχρονα, ο client που το λαμβάνει να αποδεσμεύσει το transaction buffer. Στο παράδειγμα CVE-2020-0423, ένα transfer `BINDER_TYPE_WEAK_BINDER` ακολουθούμενο από `BINDER_THREAD_EXIT` που συναγωνιζόταν με `BC_FREE_BUFFER` μπορούσε να αποδεσμεύσει ένα ενσωματωμένο `binder_work`, ενώ η διαδρομή καθαρισμού του thread που τερματιζόταν το χρησιμοποιούσε ακόμη.<sup>[[15]](#references)</sup>

#### Επαναφέρετε ελεγχόμενες εναλλαγές εκτέλεσης σε kernel userspace

Η [Linux Kernel Library (LKL)](https://github.com/lkl/linux) συνδέει τον πραγματικό κώδικα του kernel σε ένα userspace harness και εκθέτει τη syscall διεπαφή του μέσω του `lkl_syscall`. Έτσι, ο συντονισμός protobuf state, coverage και KASAN γίνεται εύκολα μέσα σε μία διεργασία. Ωστόσο, το LKL συνήθως εκτελεί μια syscall χωρίς να τη διακόπτει κάποιο άλλο kernel thread. Για race campaigns, εισαγάγετε σημεία `schedule()` γύρω από επιλεγμένα όρια lock/unlock και lifetime και αφήστε το harness να επιλέγει τυχαία τον επόμενο client σε κάθε yield. Διατηρήστε αυτά τα σημεία στοχευμένα, επειδή το καθένα πολλαπλασιάζει τον χώρο αναζήτησης του scheduling. Ο randomized scheduler που περιγράφουν οι ερευνητές **δεν** αποτελεί μέρος του upstream Binder fuzzer.<sup>[[15]](#references)</sup>

#### Δημιουργήστε και αναπαράγετε serialized regression seeds

Το upstream harness κλειδώνει μια συμβατή έκδοση του `libprotobuf-mutator`, ενεργοποιεί το instrumentation fuzzing του LKL και το KASAN με `LKL_FUZZING=1` και ενεργοποιεί το `CONFIG_MMU` για το Binder με `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Αφού κάνετε checkout σε μια σκόπιμα ευάλωτη revision ή εφαρμόσετε τα rollback patches που τεκμηριώνονται upstream, ένα serialized seed μπορεί να αναπαράγει ολόκληρη τη μετάβαση κατάστασης πολλών clients χωρίς να χρειάζεται να την ανασυνθέσετε σε ένα ad-hoc proof of concept σε C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Αντιμετώπισε το KASAN use-after-free που προέκυψε ως επιβεβαίωση ότι το seed έφτασε στη vulnerable διαδρομή lifetime. Δεν αποδεικνύει τις επόμενες primitives που απαιτούνται για εκτέλεση κώδικα στον kernel ή κλιμάκωση προνομίων.<sup>[[16]](#references)</sup>

## Τεχνική ποικιλομορφίας σε ένα μόνο μηχάνημα (τύπου Jackalope)

Ένας πρακτικός τρόπος να συνδυάσεις τη **novelty μέσω generative τεχνικών** με την **επαναχρησιμοποίηση coverage** είναι να **επανεκκινείς workers σύντομης διάρκειας** που εκτελούνται σε έναν persistent server. Κάθε worker ξεκινά με άδειο corpus, συγχρονίζεται μετά από `T` δευτερόλεπτα, εκτελείται για άλλα `T` δευτερόλεπτα με το συνδυασμένο corpus, συγχρονίζεται ξανά και μετά τερματίζεται. Έτσι προκύπτουν **νέες δομές σε κάθε γενιά**, ενώ παράλληλα αξιοποιείται το coverage που έχει συσσωρευτεί.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Ακολουθιακοί workers (παράδειγμα loop):**

<details>
<summary>Loop επανεκκίνησης worker του Jackalope</summary>

```python
import subprocess
import time

T = 3600

while True:
  subprocess.run(["rm", "-rf", "workerout"])
  p = subprocess.Popen([
      "/path/to/fuzzer",
      "-grammar", "grammar.txt",
      "-instrumentation", "sancov",
      "-in", "empty",
      "-out", "workerout",
      "-t", "1000",
      "-delivery", "shmem",
      "-iterations", "10000",
      "-mute_child",
      "-nthreads", "6",
      "-server", "127.0.0.1:8337",
      "-server_update_interval", str(T),
      "--", "./harness", "-m", "@@",
  ])
  time.sleep(T * 2)
  p.kill()
```

</details>

**Σημειώσεις:**

- Το `-in empty` επιβάλλει **νέο corpus** σε κάθε generation.
- Το `-server_update_interval T` προσεγγίζει τον **καθυστερημένο συγχρονισμό** (πρώτα novelty, μετά reuse).
- Στη λειτουργία grammar fuzzing, ο **αρχικός συγχρονισμός με τον server παραλείπεται από προεπιλογή** (δεν χρειάζεται το `-skip_initial_server_sync`).
- Το βέλτιστο `T` εξαρτάται από τον **στόχο**· συνήθως αποδίδει καλύτερα η αλλαγή αφού ο worker έχει ανακαλύψει το μεγαλύτερο μέρος του «εύκολου» coverage.

## Snapshot Fuzzing για στόχους που είναι δύσκολο να γίνουν harness

Όταν ο κώδικας που θέλετε να ελέγξετε γίνεται προσβάσιμος **μόνο μετά από μεγάλο κόστος προετοιμασίας** (εκκίνηση VM, ολοκλήρωση σύνδεσης, λήψη packet, ανάλυση container, αρχικοποίηση service), μια χρήσιμη εναλλακτική είναι το **snapshot fuzzing**: καταγράψτε την έτοιμη κατάσταση της διεργασίας ή της VM, εισαγάγετε κάθε test case στη διαδρομή εισόδου του στόχου, εκτελέστε μέχρι να προκύψει crash/timeout και επαναφέρετε το snapshot. Έτσι αποφεύγεται η επανάληψη της αρχικοποίησης ή των προθεμάτων του πρωτοκόλλου και είναι χρήσιμο για **network services**, **firmware**, **attack surfaces μετά τον έλεγχο ταυτότητας** και **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Εκτελέστε τον στόχο μέχρι να είναι έτοιμη η ενδιαφέρουσα κατάσταση.
2. Δημιουργήστε snapshot της **μνήμης + των registers** σε εκείνο το σημείο.
3. Για κάθε test case, γράψτε το τροποποιημένο input απευθείας στο σχετικό guest/process buffer.
4. Εκτελέστε μέχρι να προκύψει crash/timeout/reset.
5. Επαναφέρετε το snapshot· για VM targets, επαναφέρετε μόνο τις **dirty pages**, εφόσον υποστηρίζεται, και επαναλάβετε.

Τοποθετήστε το snapshot όσο πιο κοντά γίνεται στο πρώτο βήμα ανάλυσης/dispatch που έχει υψηλό κόστος, όπως μετά από ένα σημείο `recv`/`read` ή αποσειριοποίησης packet, και καταγράψτε το input buffer που χρησιμοποιεί ο στόχος. Αυτό ακολουθεί την αρχή της προσαρμοστικής τοποθέτησης: μετακινήστε το snapshot βαθύτερα στην επεξεργασία του input ώστε να αποφύγετε την επανάληψη εργασιών.<sup>[[11]](#references)</sup>

## Διερεύνηση Race Conditions στον Linux Kernel με το MAccConc

Το [MAccConc](https://github.com/googleprojectzero/MAccConc) μετατρέπει τα race conditions στον Linux kernel, που είναι ευαίσθητα στον χρονισμό, σε επαναλήψιμα προγράμματα χρονοπρογραμματισμού προσβάσεων μνήμης. Μπορεί να απαριθμεί αυτόματα εκτελέσεις **A-B-A** σε δύο contexts ή να επιτρέπει στον αναλυτή να επιβάλλει περιορισμούς σειράς μέσω terminal UI/GUI. Πρόκειται για πειραματικό ερευνητικό εργαλείο και όχι για πλήρη concurrency fuzzer: προς το παρόν απαιτεί LLVM 23+ και τον τροποποιημένο kernel του project, τα εργαλεία γραμμής εντολών υποστηρίζουν δύο test threads και το προτεινόμενο userspace fuzzing layer δεν έχει υλοποιηθεί.<sup>[[17]](#references)[[18]](#references)</sup>

### Συλλογή σημείων επικοινωνίας μεταξύ contexts

Δημιουργήστε τον instrumented kernel με KASAN outline callbacks και την τροποποιημένη υποστήριξη καταγραφής μνήμης KCOV. Το README του project συνιστά επίσης την απενεργοποίηση της βελτιστοποίησης sibling-call, ώστε τα call stacks να παραμένουν αξιοποιήσιμα.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

Η λειτουργία outline mode του KASAN (`asan-instrumentation-with-call-threshold=0`) μετατρέπει τις instrumented προσπελάσεις σε κλήσεις helper. Τα patches του kernel για το MAccConc απενεργοποιούν το `asan-opt-same-temp`, ώστε να μη συγχωνεύονται διαδοχικές προσπελάσεις· απενεργοποιήστε και τη βελτιστοποίηση `asan-opt-globals` όταν πρέπει να είναι ορατά τα data races σε global variables. Το KCOV μεταφέρει τις εγγραφές που προκύπτουν στο userspace. Συγκρίνετε προσπελάσεις από διαφορετικά execution contexts και κρατήστε τα ζεύγη των οποίων τα byte ranges επικαλύπτονται και όπου τουλάχιστον η μία πλευρά εκτελεί εγγραφή· μοντελοποιήστε το `kfree()` ως εγγραφή, ώστε και οι μεταβάσεις διάρκειας ζωής να γίνονται υποψήφιες περιπτώσεις.<sup>[[17]](#references)</sup>

Για εργασίες που εκτελούνται εκτός του task που τις ξεκίνησε, όπως η επεξεργασία πακέτων ή τα callbacks του RCU, το subsystem πρέπει να προωθεί ένα handle απομακρυσμένης κάλυψης KCOV. Το upstream remote KCOV είναι προαιρετικό και δεν είναι αυτόματα διαθέσιμο για αυθαίρετες εργασίες παρασκηνίου, επομένως η παράλειψη προώθησης μπορεί να κάνει μια πραγματική αλληλεπίδραση αόρατη.<sup>[[17]](#references)[[19]](#references)</sup>

### Εντοπισμός της ίδιας δυναμικής προσπέλασης σε κάθε εκτέλεση

Μην επαναλαμβάνετε την εκτέλεση με βάση μια συγκεκριμένη διεύθυνση heap, η οποία μπορεί να αλλάξει μετά από κάθε allocation, ή μόνο με βάση μια διεύθυνση instruction, η οποία είναι αμφίσημη μέσα σε helpers όπως τα `memcpy()` και `spin_lock()`. Το MAccConc χρησιμοποιεί ένα **ίχνος στοίβας εμπλουτισμένο με μετρητές**: κάθε frame προσδιορίζει έναν callee μαζί με τον αριθμό κλήσης του μέσα στον caller του, ενώ το τελευταίο στοιχείο προσδιορίζει την instruction προσπέλασης μνήμης. Οι εγγραφές εισόδου/εξόδου συναρτήσεων του SanitizerCoverage επιτρέπουν στο userspace να ανακατασκευάσει αυτό το δυναμικό αναγνωριστικό, το οποίο παραμένει σταθερό παρά τις αλλαγές διευθύνσεων και τον άσχετο θόρυβο στη ροή ελέγχου.<sup>[[17]](#references)</sup>

### Μετατροπή των υποψήφιων ζευγών σε εξαναγκασμένα schedules

Το patched ioctl `KCOV_SET_DI` συσχετίζει ένα αναγνωριστικό προσπέλασης εμπλουτισμένο με μετρητές με μια ενέργεια σε shared flag.<sup>[[17]](#references)</sup>

| Ενέργεια | Σημασιολογία |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Ορίζει το flag *N* ακριβώς πριν από την επιλεγμένη προσπέλαση. |
| `DI_STACK_WAIT` | Πριν από την επιλεγμένη προσπέλαση, περιμένει σε spin μέχρι να οριστεί το flag *N* ή να λήξει το όριο που έχει ρυθμιστεί. |
| `DI_STACK_WAKE_POST` | Ορίζει το flag *N* ακριβώς μετά την επιλεγμένη προσπέλαση. |

Για έναν μερικό περιορισμό **A-happens-before-B**, αντιστοιχίστε το `DI_STACK_WAKE_POST` στο A και το `DI_STACK_WAIT` στο B, χρησιμοποιώντας το ίδιο flag. Για ένα πλήρως καθορισμένο schedule δύο contexts, ξεκινήστε με το B σε αναμονή και, στη συνέχεια, κάντε το A να αφυπνίσει το B και να περιμένει στο πρώτο σημείο μεταβίβασης· το B εκτελεί την αντίστροφη ενέργεια στην επόμενη μεταβίβαση. Το δεύτερο λειτουργεί όπως η ντετερμινιστική εναλλαγή context και χρησιμοποιείται από τον αυτόματο explorer A-B-A.<sup>[[17]](#references)</sup>

Μια ελάχιστη καμπάνια είναι να μεταγλωττίσετε την test case με τα τέσσερα hooks (`test_setup`, δύο συναρτήσεις thread και `test_end`) ως shared library, να συλλέξετε ένα trace χωρίς περιορισμούς και, στη συνέχεια, να απαριθμήσετε υποψήφια A-B-A ή να προσθέσετε χειροκίνητους περιορισμούς γύρω από ύποπτες προσπελάσεις.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Αντιμετώπιζε τα timeouts ξεχωριστά από τις επιτυχείς αναδιατάξεις: μια ζητούμενη σειρά μπορεί να είναι αδύνατη, επειδή ένα lock ή μια εξάρτηση αρχικοποίησης/δημοσίευσης εμποδίζει το δεύτερο context να φτάσει στο σημείο injection. Λάβε επίσης υπόψη τα blind spots του KASAN: οι άμεσες προσπελάσεις στη στοίβα συνήθως δεν παρακολουθούνται, εκτός αν ενδέχεται να είναι εκτός ορίων, τα globals παραλείπονται με τη default βελτιστοποίηση και οι τρέχοντες compilers δεν μπορούν να εκπέμψουν ταυτόχρονα hooks για ASAN και TSAN. Τέλος, το prototype χάνει το KCOV buffer όταν ένα guest κάνει panic, οπότε διατήρησε μια ανεξάρτητη crash console/oracle.<sup>[[17]](#references)</sup>

Για μελλοντικό concurrency-guided fuzzing, κατέγραψε περιλήψεις προσπελάσεων μνήμης ανά input ή syscall, αντιστοίχισε λειτουργίες που θα δημιουργούσαν σημεία επικοινωνίας μεταξύ contexts και έπειτα εξερεύνησε μόνο αυτούς τους συνδυασμούς. Τα VM snapshots σταθεροποιούν την global κατάσταση και τις διευθύνσεις· χωρίς snapshots, τα μεταδεδομένα allocation-site μπορούν να αφαιρούν την εξάρτηση από συγκεκριμένα objects μεταξύ runs. Πρόκειται για προτεινόμενη επέκταση, όχι για δυνατότητα των τρεχόντων userspace tools του MAccConc.<sup>[[17]](#references)</sup>

## Ενδοσκόπηση Harness: Εντόπισε νωρίς τα ρηχά Fuzzers

Όταν μια καμπάνια κολλάει, συχνά δεν φταίει ο mutator αλλά το **harness**. Χρησιμοποίησε **ενδοσκόπηση reachability/coverage** για να εντοπίσεις συναρτήσεις που είναι στατικά προσβάσιμες από τον fuzz target, αλλά καλύπτονται σπάνια ή ποτέ δυναμικά. Αυτές οι συναρτήσεις συνήθως υποδεικνύουν ένα από τα εξής τρία προβλήματα.<sup>[[12]](#references)</sup>

- Το harness εισέρχεται στον target πολύ αργά ή πολύ νωρίς.
- Από το seed corpus λείπει μια ολόκληρη οικογένεια λειτουργιών.
- Ο target χρειάζεται πραγματικά ένα **δεύτερο harness**, αντί για ένα υπερβολικά μεγάλο harness που «τα κάνει όλα».

Αν χρησιμοποιείς workflows τύπου OSS-Fuzz / ClusterFuzz, το Fuzz Introspector μπορεί να συγκρίνει τη στατική reachability με το runtime coverage και να δημιουργήσει αναφορές από μια χρονομετρημένη εκτέλεση ή ένα δημόσιο corpus.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Χρησιμοποιήστε την αναφορά για να αποφασίσετε αν θα προσθέσετε ένα νέο harness για μια μη δοκιμασμένη διαδρομή parser, θα διευρύνετε το corpus για μια συγκεκριμένη λειτουργία ή θα διαχωρίσετε ένα μονολιθικό harness σε μικρότερα entry points.

## Επιλογή στόχων fuzzing με προτεραιότητα στο γράφημα και διαλογή μεταλλάξεων

Αν έχετε ήδη ευρήματα από **static analysis**, **mutation testing** και αναφορές **coverage**, μην τα διαχειρίζεστε ως ανεξάρτητες λίστες. Δημιουργήστε πρώτα ένα **call graph**, προσθέστε στους κόμβους επισημειώσεις για την **cyclomatic complexity**, την **προσβασιμότητα από entrypoint/μη έμπιστη είσοδο** και τυχόν εξωτερικά ευρήματα και, στη συνέχεια, εξετάστε ερωτήματα για το γράφημα.<sup>[[5]](#references)[[6]](#references)</sup>

- Ποιες συναρτήσεις υψηλής πολυπλοκότητας είναι προσβάσιμες από μη έμπιστη είσοδο;
- Ποιοι επιζώντες μεταλλάξεων βρίσκονται σε διαδρομές από parsers/handlers προς κώδικα κρίσιμο για την ασφάλεια;
- Ποιες συναρτήσεις αποτελούν αρχιτεκτονικά σημεία συμφόρησης με ασυνήθιστα μεγάλο **blast radius**;

Αυτό συνήθως αποκαλύπτει καλύτερους στόχους fuzzing από το να επιλέγετε απλώς εκείνους με τη «χαμηλότερη κάλυψη». Ένας parser/decoder με **υψηλή πολυπλοκότητα** και επιβεβαιωμένη **εξωτερική προσβασιμότητα** είναι ισχυρότερος υποψήφιος για harness από έναν απομονωμένο εσωτερικό helper με χαμηλή κάλυψη αλλά χωρίς διαδρομή που ελέγχεται από επιτιθέμενο.

### Πρακτική ροή εργασιών διαλογής

1. Δημιουργήστε ένα **code graph** από το codebase και εξαγάγετε μετρικές πολυπλοκότητας/διακλαδώσεων για κάθε συνάρτηση.
2. Καταγράψτε τα **entrypoints** που δέχονται είσοδο ελεγχόμενη από επιτιθέμενο: request handlers, decoders, importers, protocol parsers, αναγνώστες CLI/αρχείων.
3. Εκτελέστε ερωτήματα διαδρομών από αυτά τα entrypoints προς υποψήφιες συναρτήσεις, ώστε να διαχωρίσετε την προσβάσιμη επιφάνεια επίθεσης από κώδικα που είναι νεκρός ή προσβάσιμος μόνο εσωτερικά.
4. Δώστε προτεραιότητα σε κόμβους που συνδυάζουν:
   - υψηλή **cyclomatic complexity**
   - επιβεβαιωμένη **προσβασιμότητα από μη έμπιστη είσοδο**
   - μεγάλο **blast radius** ή πολλούς εξαρτώμενους κόμβους
   - επιβεβαιωτικά στοιχεία, όπως ευρήματα **SARIF**, σημειώσεις ελέγχου ή επιζώντες μεταλλάξεων
5. Γράψτε εστιασμένα harnesses πρώτα για τους κόμβους με την υψηλότερη βαθμολογία, ειδικά για **parsers/codecs**, όπως decoders hex/Base64/IP/message.

### Επιζώντες μεταλλάξεων: ισοδύναμοι ή αξιοποιήσιμοι

Το mutation testing συχνά παράγει μια θορυβώδη λίστα επιζώντων. Προτού αντιμετωπίσετε κάθε επιζώντα ως κενό ασφαλείας, χρησιμοποιήστε το γράφημα για να εξετάσετε τα εξής:

- Είναι η μεταλλαγμένη συνάρτηση προσβάσιμη από entrypoint που ελέγχεται από επιτιθέμενο;
- Περιορίζονται όλες οι διαδρομές κλήσεων από ισχυρότερες invariants από εκείνη που παραβιάζει ο μεταλλαγμένος έλεγχος;
- Βρίσκεται ο κόμβος σε νεκρό κώδικα, σε λογική που αφορά μόνο τη μορφοποίηση ή σε διαδρομή αριθμητικών πράξεων/parser με μεγάλο αντίκτυπο;

Οι επιζώντες που παραμένουν μη προσβάσιμοι ή περιορίζονται δομικά είναι συχνά **ισοδύναμοι mutants**. Οι επιζώντες που παραμένουν **προσβάσιμοι** και επηρεάζουν **οριακές συνθήκες**, **διαδρομές overflow/carry** ή **αριθμητικές πράξεις/parsing κρίσιμα για την ασφάλεια** θα πρέπει να προωθούνται σε:

- νέα fuzz harnesses
- άμεσα property/invariant tests
- στοχευμένα edge-case vectors

### Συσχετίστε εξωτερικά ευρήματα με το γράφημα

Αν το pipeline SAST εξάγει **SARIF**, αντιστοιχίστε τα ευρήματα στους κόμβους του γραφήματος με βάση το **αρχείο + το εύρος γραμμών** και χρησιμοποιήστε το γράφημα για να διευρύνετε την εκτίμηση επιπτώσεων.<sup>[[6]](#references)</sup>

- υπολογίστε το **blast radius** της επισημασμένης συνάρτησης
- ελέγξτε αν το εύρημα βρίσκεται σε οποιαδήποτε διαδρομή από entrypoint
- ομαδοποιήστε κοντινά ευρήματα που συγκλίνουν στο ίδιο σημείο συμφόρησης

Αυτό είναι χρήσιμο όταν αποφασίζετε αν αξίζει να αφιερώσετε χρόνο σε fuzzing μιας συγκεκριμένης συνάρτησης: ένας κόμβος που είναι **προσβάσιμος**, **σύνθετος** και έχει ήδη **ευρήματα SAST** είναι συχνά καλύτερος στόχος από έναν απλώς σύνθετο κόμβο χωρίς διαδρομή από επιτιθέμενο.

Παράδειγμα ροής εργασιών με το Trailmark.<sup>[[6]](#references)</sup>

```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```

Η σημαντική μεθοδολογία είναι η τομή: **πολυπλοκότητα x έκθεση x αντίκτυπος**. Χρησιμοποιήστε το γράφημα για να επιλέξετε στόχους fuzzing με τη μεγαλύτερη αναμενόμενη αξία ασφάλειας και, στη συνέχεια, χρησιμοποιήστε τις μεταλλάξεις που επιβιώνουν για να αποφασίσετε ποια όρια και ποιες αναλλοίωτες συνθήκες πρέπει να δοκιμάζει εντατικά το harness σας.<sup>[[5]](#references)</sup>

## Fuzzing σε Go με gosentry: Ισχυρότερη μηχανή, τυποποιημένες είσοδοι και διαφορικοί έλεγχοι

Αν ένας στόχος σε Go διαθέτει ήδη ένα εγγενές harness `testing.F`, μια πρακτική διαδρομή αναβάθμισης είναι να εκτελέσετε το ίδιο harness με το [gosentry](https://github.com/trailofbits/gosentry), ένα forked Go toolchain που διατηρεί το `go test -fuzz`, αλλά αλλάζει το backend σε **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Αυτό είναι χρήσιμο όταν ο εγγενής Go fuzzer κολλάει σε **δύσκολες συγκρίσεις**, **τυποποιημένες εισόδους** ή **μορφές με απαιτητικούς parsers**. Η μεθοδολογία παραμένει ίδια:

- Συνεχίστε να χρησιμοποιείτε το `f.Add(...)` για seeds και το `f.Fuzz(...)` για το callback.
- Επαναχρησιμοποιήστε το ίδιο harness, αλλά εκτελέστε το με το δυαδικό αρχείο `go` του gosentry αντί για το τυπικό toolchain.
- Αντιμετωπίστε την εκστρατεία που προκύπτει ως μια κανονική εκτέλεση με καθοδήγηση από την κάλυψη, αλλά με scheduling/mutation του LibAFL και καλύτερους συμπληρωματικούς detectors.

### Μετατρέψτε τις σιωπηλές αποτυχίες σε ευρήματα fuzzing

Ένα επαναλαμβανόμενο πρόβλημα στις αξιολογήσεις Go είναι ότι η επικίνδυνη συμπεριφορά συχνά **δεν** προκαλεί από προεπιλογή crash. Με το gosentry, μπορείτε να μετατρέψετε διάφορες κατηγορίες «κακών αλλά σιωπηλών» καταστάσεων σε ευρήματα.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` για να κάνετε επιλεγμένες διαδρομές καταγραφής/error να συμπεριφέρονται σαν crashes (χρήσιμο για διαδρομές κώδικα τύπου `log.Fatal` που διαφορετικά απλώς καταγράφουν το συμβάν και συνεχίζουν).
- `--catch-races=true` για να επανεκτελείτε τις νέες εγγραφές της ουράς που ανακαλύφθηκαν με τον Go race detector.
- `--catch-leaks=true` για να επανεκτελείτε τις νέες εγγραφές της ουράς με το `goleak` και να σταματάτε σε περίπτωση διαρροών goroutine.
- Χειρισμός hang από το LibAFL, ώστε οι **ατέρμονοι βρόχοι / πολύ αργές είσοδοι** να καταγράφονται ως ευρήματα fuzzing αντί να χάνονται ως timeouts.
- Ενσωματωμένοι έλεγχοι αριθμητικής υπερχείλισης από προεπιλογή, καθώς και προαιρετικοί έλεγχοι αποκοπής μέσω instrumentation τύπου go-panikint.

Αυτό είναι ιδιαίτερα χρήσιμο για στόχους όπου ο αντίκτυπος στην ασφάλεια είναι μια **αποτυχία parser χωρίς panic**, ένα **σφάλμα ταυτόχρονης εκτέλεσης** ή ένα **hang που προκαλεί μόνο DoS**, και όχι αλλοίωση μνήμης.

### Fuzzing με επίγνωση δομών για τυποποιημένα Go API

Το εγγενές Go fuzzing αναμένει κυρίως scalars όπως `[]byte`, `string` και αριθμούς. Αν ο κώδικας που ελέγχεται καταναλώνει τυποποιημένα αντικείμενα, το gosentry μπορεί να κάνει fuzzing απευθείας σε **σύνθετες τιμές** (structs, slices, arrays, pointers), ενώ εξακολουθεί να μεταλλάσσει τα υποκείμενα bytes.<sup>[[7]](#references)[[8]](#references)</sup>

```go
type Input struct {
    Data []byte
    S    string
    N    int
}

func FuzzStructInput(f *testing.F) {
    f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
    f.Fuzz(func(t *testing.T, in Input) {
        Process(in)
    })
}
```

Χρησιμοποιήστε αυτή την προσέγγιση όταν η δημιουργία ενός fake wire format μόνο για fuzzing θα έκρυβε λογικά σφάλματα πίσω από κώδικα parsing που υπάρχει μόνο στο harness. Για differential ή grammar-based campaigns, διατηρήστε την είσοδο του harness ως ένα μόνο `[]byte` ή `string` και κάντε το parsing μέσα στο callback.

### Fuzzing βάσει γραμματικής για parsers και εισόδους πρωτοκόλλων

Για parsers, formats και γλώσσες εισόδου, το gosentry μπορεί να εκτελέσει **Nautilus grammar fuzzing** πάνω από το LibAFL. Η γραμματική είναι ένας πίνακας JSON με production rules, ενώ το harness συνήθως πρέπει να δέχεται ένα μόνο όρισμα `[]byte` ή `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Σημειώσεις μεθοδολογίας:

- Χρησιμοποιήστε grammar mode όταν οι μεταλλάξεις σε επίπεδο byte αποτυγχάνουν κυρίως σε πρώιμους ελέγχους σύνταξης.
- Περιορίστε τη γραμματική στο **υποσύνολο της γλώσσας/του πρωτοκόλλου που σχετίζεται με την ασφάλεια**, αντί να μοντελοποιήσετε ολόκληρη την προδιαγραφή.
- Χρησιμοποιήστε μεγάλες οριακές τιμές σε terminals/nonterminals για να δοκιμάσετε τα όρια ακεραίων, μηκών και μηχανών καταστάσεων.
- Το grammar mode διατηρεί τις εισόδους έγκυρες ως προς τη γραμματική, αλλά ο στόχος εξακολουθεί να λαμβάνει **bytes/strings**, επομένως η ανάλυση και οι σημασιολογικοί έλεγχοι παραμένουν μέσα στον κώδικα που έχει ενσωματωθεί στο harness.

### Differential fuzzing: σύγκριση υλοποιήσεων, όχι μόνο crashes

Ένα ισχυρό μοτίβο στα οικοσυστήματα Go είναι το **grammar-based differential fuzzing**: δημιουργήστε έγκυρες δομημένες εισόδους και τροφοδοτήστε τις σε δύο parsers, clients ή μηχανές μετάβασης καταστάσεων.<sup>[[7]](#references)[[8]](#references)</sup>

```go
f.Fuzz(func(t *testing.T, data []byte) {
    gotA, errA := ParseA(data)
    gotB, errB := ParseB(data)
    if (errA == nil) != (errB == nil) {
        t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
    }
    _ = gotA
    _ = gotB
})
```

Αντιμετωπίστε τα παρακάτω ως ευρήματα:

- μία υλοποίηση κάνει panic, ενώ η άλλη απορρίπτει το input κανονικά
- ασυμφωνίες ως προς την αποδοχή ή την απόρριψη input
- διαφορετικά δέντρα ανάλυσης ή αποκωδικοποιημένα αντικείμενα
- αποκλίνουσες μεταβάσεις κατάστασης, nonces, υπόλοιπα ή state roots

Αυτός είναι ένας πρακτικός τρόπος να εντοπίσετε **ασυμφωνίες συναίνεσης**, **ασάφειες parser** και **αποκλίσεις μεταξύ προδιαγραφής και υλοποίησης**, τις οποίες το απλό crash fuzzing συχνά δεν εντοπίζει.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Επαναχρησιμοποιήστε το corpus της καμπάνιας για αναφορές κάλυψης

Μετά από μια καμπάνια, επαναλάβετε το αποθηκευμένο queue corpus για να δημιουργήσετε μια αναφορά κάλυψης Go, χωρίς να χρειάζεται να εξαγάγετε χειροκίνητα ξεχωριστό corpus.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Εκτελέστε την εντολή από το **ίδιο package** και με τον **ίδιο στόχο `-fuzz`**, ώστε το gosentry να εντοπίσει τη σωστή κατάσταση cached campaign.



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing με AFL++ σε βάθος](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet πέντε χρόνια μετά: fuzzing πρωτοκόλλων με καθοδήγηση κάλυψης](https://arxiv.org/abs/2412.20324)
- [5] [Το Trailmark μετατρέπει τον κώδικα σε γράφους](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Το Go fuzzing στερούνταν τη μισή εργαλειοθήκη. Κάναμε fork το toolchain για να το διορθώσουμε.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ένας γρήγορος greybox fuzzer για stateful πρωτόκολλα δικτύου με χρήση snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Χωρίς grammar, κανένα πρόβλημα: Προς το fuzzing του Linux kernel χωρίς περιγραφές system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Αποδοτικό fuzzing με προσαρμοστικά και μεταβλητά snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM του AFL++: κάλυψη διαδρομών και callers](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Ιστολόγιο Android Offensive Security - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer Binder του LKL για Android - τεκμηρίωση build και regression seeds](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Διερεύνηση race conditions στον Linux kernel με ελεγχόμενες εναλλαγές προσπέλασης μνήμης](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: κάλυψη κώδικα για fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
