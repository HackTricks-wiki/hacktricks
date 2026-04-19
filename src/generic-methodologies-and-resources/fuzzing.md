# Μεθοδολογία Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Στο **mutational grammar fuzzing**, τα inputs μεταλλάσσονται ενώ παραμένουν **grammar-valid**. Σε coverage-guided mode, μόνο τα samples που ενεργοποιούν **new coverage** αποθηκεύονται ως corpus seeds. Για **language targets** (parsers, interpreters, engines), αυτό μπορεί να χάσει bugs που απαιτούν **semantic/dataflow chains** όπου το output μιας κατασκευής γίνεται το input μιας άλλης.

**Failure mode:** το fuzzer βρίσκει seeds που μεμονωμένα ενεργοποιούν `document()` και `generate-id()` (ή παρόμοια primitives), αλλά **δεν διατηρεί το chained dataflow**, οπότε το sample που είναι “closer-to-bug” απορρίπτεται επειδή δεν προσθέτει coverage. Με **3+ dependent steps**, η τυχαία ανασύνθεση γίνεται ακριβή και το coverage feedback δεν κατευθύνει την αναζήτηση.

**Implication:** για grammars με έντονη εξάρτηση, σκέψου να **συνδυάσεις mutational και generative phases** ή να δώσεις bias στη δημιουργία προς patterns **function chaining** (όχι μόνο coverage).

## Corpus Diversity Pitfalls

Η coverage-guided mutation είναι **greedy**: ένα sample με new-coverage αποθηκεύεται αμέσως, συχνά διατηρώντας μεγάλα αμετάβλητα regions. Με τον χρόνο, τα corpora γίνονται **near-duplicates** με χαμηλή structural diversity. Η επιθετική minimization μπορεί να αφαιρέσει χρήσιμο context, οπότε ένας πρακτικός συμβιβασμός είναι **grammar-aware minimization** που **σταματά μετά από ένα minimum token threshold** (μείωση θορύβου ενώ διατηρείται αρκετή γύρω δομή ώστε να παραμένει mutation-friendly).

Ένας πρακτικός κανόνας corpus για mutational fuzzing είναι: **προτίμησε ένα μικρό σύνολο από δομικά διαφορετικά seeds που μεγιστοποιούν το coverage** αντί για έναν μεγάλο σωρό από near-duplicates. Στην πράξη, αυτό συνήθως σημαίνει:

- Ξεκίνα από **real-world samples** (public corpora, crawling, captured traffic, file sets από το target ecosystem).
- Απόσταξέ τα με **coverage-based corpus minimization** αντί να κρατάς κάθε valid sample.
- Κράτα τα seeds **αρκετά μικρά** ώστε οι mutations να πέφτουν σε meaningful fields αντί να ξοδεύονται οι περισσότερες διελεύσεις σε irrelevant bytes.
- Ξανατρέξε corpus minimization μετά από μεγάλες αλλαγές στο harness/instrumentation, γιατί το “καλύτερο” corpus αλλάζει όταν αλλάζει η reachability.

## Comparison-Aware Mutation For Magic Values

Ένας συνηθισμένος λόγος που τα fuzzers plateau είναι όχι η syntax αλλά οι **hard comparisons**: magic bytes, length checks, enum strings, checksums, ή parser dispatch values που προστατεύονται από `memcmp`, switch tables, ή cascaded comparisons. Η καθαρά τυχαία mutation σπαταλά κύκλους προσπαθώντας να μαντέψει αυτές τις τιμές byte-by-byte.

Για αυτούς τους στόχους, χρησιμοποίησε **comparison tracing** (για παράδειγμα AFL++ `CMPLOG` / Redqueen-style workflows) ώστε το fuzzer να μπορεί να παρατηρεί operands από αποτυχημένες comparisons και να δίνει bias στις mutations προς τιμές που τις ικανοποιούν.
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

- Αυτό είναι ιδιαίτερα χρήσιμο όταν ο στόχος κρύβει βαθιά λογική πίσω από **file signatures**, **protocol verbs**, **type tags**, ή **version-dependent feature bits**.
- Συνδύασέ το με **dictionaries** που εξάγονται από πραγματικά samples, protocol specs, ή debug logs. Ένα μικρό dictionary με grammar tokens, chunk names, verbs, και delimiters είναι συχνά πιο πολύτιμο από ένα τεράστιο generic wordlist.
- Αν ο στόχος εκτελεί πολλαπλούς διαδοχικούς ελέγχους, λύσε πρώτα τις πιο πρώιμες “magic” συγκρίσεις και μετά ελαχιστοποίησε ξανά το προκύπτον corpus ώστε τα επόμενα στάδια να ξεκινούν από ήδη-valid prefixes.

## Stateful Fuzzing: Sequences Are Seeds

Για **protocols**, **authenticated workflows**, και **multi-stage parsers**, η ενδιαφέρουσα μονάδα συχνά δεν είναι ένα μεμονωμένο blob αλλά μια **message sequence**. Η συνένωση όλου του transcript σε ένα αρχείο και η τυφλή μεταβολή του είναι συνήθως αναποτελεσματική, επειδή ο fuzzer μεταβάλλει εξίσου κάθε βήμα, ακόμα κι όταν μόνο το μεταγενέστερο μήνυμα φτάνει στην εύθραυστη κατάσταση.

Ένα πιο αποτελεσματικό μοτίβο είναι να αντιμετωπίζεις την ίδια τη **sequence** ως seed και να χρησιμοποιείς την **observable state** (response codes, protocol states, parser phases, returned object types) ως πρόσθετο feedback:

- Κράτα τα **valid prefix messages** σταθερά και εστίασε τις μεταβολές στο μήνυμα που οδηγεί στη **transition-driving** αλλαγή.
- Κάνε cache identifiers και server-generated values από προηγούμενες responses όταν το επόμενο βήμα εξαρτάται από αυτά.
- Προτίμησε per-message mutation/splicing αντί να μεταβάλλεις όλο το serialized transcript ως αδιαφανές blob.
- Αν το protocol εκθέτει ουσιαστικούς response codes, χρησιμοποίησέ τους ως μια **cheap state oracle** για να δίνεις προτεραιότητα σε sequences που προχωρούν βαθύτερα.

Αυτός είναι ο ίδιος λόγος που bugs σε authenticated, κρυφές μεταβάσεις ή parser bugs “only-after-handshake” συχνά χάνονται από vanilla file-style fuzzing: ο fuzzer πρέπει να διατηρεί **order, state, and dependencies**, όχι μόνο τη δομή.

## Single-Machine Diversity Trick (Jackalope-Style)

Ένας πρακτικός τρόπος να υβριδοποιήσεις τη **generative novelty** με την **coverage reuse** είναι να **επανεκκινείς short-lived workers** απέναντι σε έναν persistent server. Κάθε worker ξεκινά από ένα κενό corpus, κάνει sync μετά από `T` seconds, τρέχει για άλλα `T` seconds πάνω στο combined corpus, κάνει sync ξανά, και μετά exits. Αυτό παράγει **fresh structures each generation** ενώ εξακολουθεί να αξιοποιεί το accumulated coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Ακολουθιακοί workers (παράδειγμα loop):**

<details>
<summary>Jackalope worker restart loop</summary>
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

- `-in empty` επιβάλλει ένα **φρέσκο corpus** σε κάθε εκτέλεση.
- `-server_update_interval T` προσεγγίζει το **καθυστερημένο sync** (πρώτα novelty, μετά reuse).
- Στο grammar fuzzing mode, το **initial server sync παραλείπεται από προεπιλογή** (δεν χρειάζεται `-skip_initial_server_sync`).
- Το βέλτιστο `T` εξαρτάται από τον **στόχο**· η αλλαγή αφού ο worker έχει βρει το μεγαλύτερο μέρος του “easy” coverage τείνει να δουλεύει καλύτερα.

## Snapshot Fuzzing For Hard-To-Harness Targets

Όταν ο κώδικας που θέλεις να δοκιμάσεις γίνεται reachable μόνο **μετά από μεγάλο setup cost** (booting a VM, completing a login, receiving a packet, parsing a container, initializing a service), μια χρήσιμη εναλλακτική είναι το **snapshot fuzzing**:

1. Τρέξε το target μέχρι να είναι έτοιμη η ενδιαφέρουσα κατάσταση.
2. Κάνε snapshot τη **memory + registers** σε εκείνο το σημείο.
3. Για κάθε test case, γράψε το mutated input απευθείας στο σχετικό guest/process buffer.
4. Εκτέλεσε μέχρι crash/timeout/reset.
5. Επανέφερε μόνο τα **dirty pages** και επανάλαβε.

Αυτό αποφεύγει να πληρώνεις το πλήρες setup cost σε κάθε iteration και είναι ιδιαίτερα χρήσιμο για **network services**, **firmware**, **post-auth attack surfaces**, και **binary-only targets** που είναι δύσκολο να αναδιαμορφωθούν σε ένα κλασικό in-process harness.

Ένα πρακτικό trick είναι να κάνεις break αμέσως μετά από ένα `recv`/`read`/packet-deserialization point, να σημειώσεις το input buffer address, να κάνεις snapshot εκεί, και μετά να κάνεις mutate αυτό το buffer απευθείας σε κάθε iteration. Αυτό σου επιτρέπει να κάνεις fuzzing στη βαθιά parsing logic χωρίς να ξαναχτίζεις κάθε φορά ολόκληρο το handshake.

## Harness Introspection: Find Shallow Fuzzers Early

Όταν μια campaign σταματά, το πρόβλημα συχνά δεν είναι ο mutator αλλά το **harness**. Χρησιμοποίησε **reachability/coverage introspection** για να βρεις functions που είναι στατικά reachable από το fuzz target σου αλλά σπάνια ή ποτέ δεν καλύπτονται δυναμικά. Αυτές οι functions συνήθως δείχνουν ένα από τρία προβλήματα:

- Το harness μπαίνει στο target πολύ αργά ή πολύ νωρίς.
- Το seed corpus λείπει μια ολόκληρη family of features.
- Το target πραγματικά χρειάζεται ένα **second harness** αντί για ένα υπερμεγέθες “do everything” harness.

Αν χρησιμοποιείς OSS-Fuzz / ClusterFuzz-style workflows, το Fuzz Introspector είναι χρήσιμο για αυτό το triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Χρησιμοποίησε την αναφορά για να αποφασίσεις αν πρέπει να προσθέσεις ένα νέο harness για μια μη δοκιμασμένη διαδρομή parser, να επεκτείνεις το corpus για ένα συγκεκριμένο feature, ή να διαχωρίσεις ένα μονολιθικό harness σε μικρότερα entry points.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
