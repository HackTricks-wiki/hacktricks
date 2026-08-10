# Μεθοδολογία Fuzzing

## Mutational Grammar Fuzzing: Coverage έναντι Semantics

Στο **mutational grammar fuzzing**, τα inputs μεταλλάσσονται ενώ παραμένουν **grammar-valid**. Σε λειτουργία coverage-guided, αποθηκεύονται ως corpus seeds μόνο τα samples που ενεργοποιούν **new coverage**. Για **language targets** (parsers, interpreters, engines), αυτό μπορεί να παραλείψει bugs που απαιτούν **semantic/dataflow chains**, όπου το output ενός construct γίνεται το input ενός άλλου.<sup>[[1]](#references)</sup>

**Failure mode:** το fuzzer βρίσκει seeds που μεμονωμένα ασκούν τα `document()` και `generate-id()` (ή παρόμοια primitives), αλλά **δεν διατηρεί το chained dataflow**, οπότε το sample που βρίσκεται «πιο κοντά στο bug» απορρίπτεται επειδή δεν προσθέτει coverage. Με **3+ dependent steps**, ο random recombination γίνεται ακριβός και το coverage feedback δεν καθοδηγεί την αναζήτηση.<sup>[[1]](#references)</sup>

**Implication:** για grammars με πολλές dependencies, εξετάστε το ενδεχόμενο **hybridizing mutational and generative phases** ή biasing της generation προς μοτίβα **function chaining** (όχι μόνο προς το coverage).<sup>[[1]](#references)</sup>

## Pitfalls της Corpus Diversity

Το coverage-guided mutation είναι **greedy**: ένα sample με new coverage αποθηκεύεται αμέσως, συχνά διατηρώντας μεγάλες μη τροποποιημένες περιοχές. Με την πάροδο του χρόνου, τα corpora γίνονται **near-duplicates** με χαμηλή structural diversity. Το επιθετικό minimization μπορεί να αφαιρέσει χρήσιμο context, επομένως ένας πρακτικός συμβιβασμός είναι το **grammar-aware minimization**, το οποίο **σταματά μετά από ένα minimum token threshold** (μείωση του noise, διατηρώντας αρκετή surrounding structure ώστε να παραμένει mutation-friendly).<sup>[[1]](#references)</sup>

Ένας πρακτικός κανόνας corpus για mutational fuzzing είναι: **προτιμήστε ένα μικρό σύνολο structurally different seeds που μεγιστοποιούν το coverage** αντί για έναν μεγάλο σωρό near-duplicates. Στην πράξη, αυτό συνήθως σημαίνει τα εξής.<sup>[[1]](#references)[[3]](#references)</sup>

- Ξεκινήστε από **real-world samples** (public corpora, crawling, captured traffic, file sets από το ecosystem του target).
- Distillάρετέ τα με **coverage-based corpus minimization**, αντί να διατηρείτε κάθε valid sample.
- Διατηρήστε τα seeds **αρκετά μικρά**, ώστε τα mutations να εφαρμόζονται σε meaningful fields αντί να καταναλώνουν τους περισσότερους κύκλους σε irrelevant bytes.
- Εκτελέστε ξανά corpus minimization μετά από σημαντικές αλλαγές στο harness/instrumentation, επειδή το «καλύτερο» corpus αλλάζει όταν αλλάζει η reachability.

## Comparison-Aware Mutation For Magic Values

Ένας συνηθισμένος λόγος για τον οποίο τα fuzzers φτάνουν σε plateau δεν είναι το syntax αλλά οι **hard comparisons**: magic bytes, length checks, enum strings, checksums ή parser dispatch values που προστατεύονται από `memcmp`, switch tables ή cascaded comparisons. Το pure random mutation σπαταλά κύκλους προσπαθώντας να μαντέψει αυτές τις τιμές byte-by-byte.

Για αυτά τα targets, χρησιμοποιήστε **comparison tracing** (για παράδειγμα workflows τύπου AFL++ `CMPLOG` / Redqueen), ώστε το fuzzer να παρατηρεί operands από failed comparisons και να κατευθύνει τα mutations προς τιμές που τις ικανοποιούν.<sup>[[3]](#references)</sup>
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

- Αυτό είναι ιδιαίτερα χρήσιμο όταν ο στόχος κρύβει βαθύτερη λογική πίσω από **file signatures**, **protocol verbs**, **type tags** ή **version-dependent feature bits**.
- Συνδύασέ το με **dictionaries** που έχουν εξαχθεί από πραγματικά δείγματα, προδιαγραφές πρωτοκόλλων ή debug logs. Ένα μικρό dictionary με grammar tokens, ονόματα chunks, verbs και delimiters είναι συχνά πιο πολύτιμο από ένα τεράστιο generic wordlist.
- Αν ο στόχος εκτελεί πολλούς διαδοχικούς ελέγχους, επίλυσε πρώτα τις αρχαιότερες συγκρίσεις “magic” και, στη συνέχεια, ελαχιστοποίησε ξανά το corpus που προέκυψε, ώστε τα επόμενα στάδια να ξεκινούν από ήδη έγκυρα prefixes.

## Stateful Fuzzing: Οι ακολουθίες είναι Seeds

Για **protocols**, **authenticated workflows** και **multi-stage parsers**, η ενδιαφέρουσα μονάδα συχνά δεν είναι ένα μεμονωμένο blob αλλά μια **message sequence**. Η συνένωση ολόκληρου του transcript σε ένα αρχείο και η τυφλή μετάλλαξή του είναι συνήθως αναποτελεσματική, επειδή το fuzzer μεταλλάσσει κάθε βήμα εξίσου, ακόμη και όταν μόνο το μεταγενέστερο μήνυμα φτάνει στην ευάλωτη κατάσταση.<sup>[[4]](#references)</sup>

Μια πιο αποτελεσματική προσέγγιση είναι να αντιμετωπίζεις την **sequence ως seed** και να χρησιμοποιείς το **observable state** (response codes, protocol states, parser phases, returned object types) ως πρόσθετο feedback.<sup>[[4]](#references)</sup>

- Διατήρησε σταθερά τα **valid prefix messages** και εστίασε τις μεταλλάξεις στο **transition-driving** message.
- Αποθήκευε προσωρινά identifiers και server-generated values από προηγούμενες responses όταν το επόμενο βήμα εξαρτάται από αυτά.
- Προτίμησε mutation/splicing ανά μήνυμα αντί για μετάλλαξη ολόκληρου του serialized transcript ως opaque blob.
- Αν το protocol εκθέτει meaningful response codes, χρησιμοποίησέ τα ως **cheap state oracle** για να δίνεις προτεραιότητα σε sequences που προχωρούν βαθύτερα.

Αυτός είναι ο ίδιος λόγος για τον οποίο authenticated bugs, hidden transitions ή parser bugs που εμφανίζονται “only-after-handshake” συχνά δεν εντοπίζονται από το vanilla file-style fuzzing: το fuzzer πρέπει να διατηρεί **order, state και dependencies**, όχι μόνο structure.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Ένας πρακτικός τρόπος να συνδυάσεις **generative novelty** με **coverage reuse** είναι να κάνεις **restart σε workers μικρής διάρκειας** απέναντι σε έναν persistent server. Κάθε worker ξεκινά από ένα κενό corpus, συγχρονίζεται μετά από `T` δευτερόλεπτα, εκτελείται για ακόμη `T` δευτερόλεπτα πάνω στο combined corpus, συγχρονίζεται ξανά και, στη συνέχεια, τερματίζει. Αυτό παράγει **fresh structures σε κάθε generation**, ενώ ταυτόχρονα αξιοποιεί το accumulated coverage.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Διαδοχικοί workers (παράδειγμα loop):**

<details>
<summary>loop επανεκκίνησης worker του Jackalope</summary>
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

- Το `-in empty` επιβάλλει ένα **fresh corpus** σε κάθε generation.
- Το `-server_update_interval T` προσεγγίζει το **delayed sync** (novelty πρώτα, reuse αργότερα).
- Σε grammar fuzzing mode, το **initial server sync** παραλείπεται από προεπιλογή (δεν χρειάζεται το `-skip_initial_server_sync`).
- Το βέλτιστο `T` εξαρτάται από το **target**· η αλλαγή αφού ο worker έχει βρει το μεγαλύτερο μέρος του «εύκολου» coverage συνήθως λειτουργεί καλύτερα.

## Snapshot Fuzzing Για Targets Με Δύσκολο Harness

Όταν ο κώδικας που θέλετε να ελέγξετε γίνεται προσβάσιμος μόνο **μετά από μεγάλο κόστος αρχικοποίησης** (εκκίνηση ενός VM, ολοκλήρωση ενός login, λήψη ενός packet, parsing ενός container, αρχικοποίηση ενός service), μια χρήσιμη εναλλακτική είναι το **snapshot fuzzing**: καταγράψτε την κατάσταση του έτοιμου process ή VM, εισαγάγετε κάθε test case στη διαδρομή εισόδου του target, εκτελέστε μέχρι να προκύψει crash/timeout και επαναφέρετε το snapshot. Έτσι αποφεύγεται η επανάληψη της αρχικοποίησης ή των protocol prefixes και είναι χρήσιμο για **network services**, **firmware**, **post-auth attack surfaces** και **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Εκτελέστε το target μέχρι να είναι έτοιμη η ενδιαφέρουσα κατάσταση.
2. Καταγράψτε τη **memory + registers** σε εκείνο το σημείο.
3. Για κάθε test case, γράψτε το mutated input απευθείας στο σχετικό guest/process buffer.
4. Εκτελέστε μέχρι να προκύψει crash/timeout/reset.
5. Επαναφέρετε το snapshot· για VM targets, επαναφέρετε μόνο τις **dirty pages** όταν υποστηρίζεται και, στη συνέχεια, επαναλάβετε.

Τοποθετήστε το snapshot όσο πιο κοντά είναι πρακτικά δυνατό στο πρώτο ακριβό parse/dispatch step, όπως μετά από ένα `recv`/`read` ή ένα σημείο packet-deserialization, και καταγράψτε το input buffer που χρησιμοποιεί το target. Αυτό ακολουθεί την αρχή adaptive-placement, δηλαδή τη μετακίνηση του snapshot βαθύτερα στην επεξεργασία του input ώστε να αποφεύγεται η επανάληψη εργασίας.<sup>[[11]](#references)</sup>

## Harness Introspection: Εντοπίστε Νωρίς Τα Shallow Fuzzers

Όταν μια campaign σταματά να προοδεύει, το πρόβλημα συχνά δεν βρίσκεται στον mutator αλλά στο **harness**. Χρησιμοποιήστε **reachability/coverage introspection** για να εντοπίσετε functions που είναι statically reachable από το fuzz target, αλλά καλύπτονται σπάνια ή καθόλου δυναμικά. Αυτές οι functions συνήθως υποδεικνύουν ένα από τα εξής τρία προβλήματα.<sup>[[12]](#references)</sup>

- Το harness εισέρχεται στο target πολύ αργά ή πολύ νωρίς.
- Από το seed corpus λείπει μια ολόκληρη feature family.
- Το target χρειάζεται πραγματικά ένα **second harness** αντί για ένα υπερβολικά μεγάλο harness τύπου «κάνε τα πάντα».

Αν χρησιμοποιείτε workflows τύπου OSS-Fuzz / ClusterFuzz, το Fuzz Introspector μπορεί να συγκρίνει το static reachability με το runtime coverage και να δημιουργεί reports από ένα timed run ή public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Χρησιμοποίησε το report για να αποφασίσεις αν θα προσθέσεις ένα νέο harness για ένα μη ελεγμένο μονοπάτι parser, θα επεκτείνεις το corpus για ένα συγκεκριμένο feature ή θα διασπάσεις ένα monolithic harness σε μικρότερα entry points.

## Επιλογή Fuzz Targets με Προτεραιότητα το Graph και Triage των Mutations

Αν έχεις ήδη **ευρήματα static analysis**, **survivors από mutation testing** και **reports κάλυψης**, μην τα αξιολογείς ως ανεξάρτητες λίστες. Δημιούργησε πρώτα ένα **call graph**, πρόσθεσε στους κόμβους το **cyclomatic complexity**, τη **δυνατότητα προσέγγισης από entrypoints/untrusted input** και τυχόν εξωτερικά ευρήματα, και στη συνέχεια κάνε ερωτήσεις σε επίπεδο graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ποιες functions με υψηλή πολυπλοκότητα είναι προσβάσιμες από untrusted input;
- Ποιοι mutation survivors βρίσκονται σε paths από parsers/handlers προς security-critical code;
- Ποιες functions αποτελούν architectural choke points με ασυνήθιστα μεγάλο **blast radius**;

Αυτό συνήθως αναδεικνύει καλύτερα fuzz targets από το να χρησιμοποιείς μόνο το "χαμηλότερο coverage". Ένας parser/decoder με **υψηλή πολυπλοκότητα** και επιβεβαιωμένη **external reachability** είναι ισχυρότερος υποψήφιος για harness από ένα απομονωμένο internal helper με χαμηλό coverage, αλλά χωρίς path ελεγχόμενο από attacker.

### Πρακτικό workflow triage

1. Δημιούργησε ένα **code graph** από το codebase και εξήγαγε metrics πολυπλοκότητας/branches ανά function.
2. Κατέγραψε τα **entrypoints** που δέχονται input ελεγχόμενο από attacker: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Εκτέλεσε **path queries** από αυτά τα entrypoints προς τις υποψήφιες functions, ώστε να διαχωρίσεις την προσβάσιμη attack surface από dead/internal-only code.
4. Δώσε προτεραιότητα σε κόμβους που συνδυάζουν:
- υψηλό **cyclomatic complexity**
- επιβεβαιωμένη **reachability από untrusted input**
- υψηλό **blast radius** ή πολλούς downstream dependents
- επιπλέον ενδείξεις, όπως ευρήματα **SARIF**, σημειώσεις audit ή mutation survivors
5. Γράψε focused harnesses πρώτα για τους κόμβους με την υψηλότερη βαθμολογία, ειδικά για **parsers/codecs**, όπως hex/Base64/IP/message decoders.

### Mutation survivors: equivalent έναντι actionable

Το mutation testing συχνά παράγει μια θορυβώδη λίστα survivors. Πριν θεωρήσεις κάθε survivor security gap, χρησιμοποίησε το graph για να ρωτήσεις:

- Είναι η mutated function προσβάσιμη από attacker-controlled entrypoint;
- Περιορίζονται όλα τα call paths από ισχυρότερα invariants από το mutated check;
- Βρίσκεται ο κόμβος σε dead code, formatting-only logic ή σε arithmetic/parser path υψηλού αντίκτυπου;

Οι survivors που παραμένουν μη προσβάσιμοι ή δομικά περιορισμένοι είναι συχνά **equivalent mutants**. Οι survivors που παραμένουν **reachable** και επηρεάζουν **boundary conditions**, **overflow/carry paths** ή **security-critical arithmetic/parsing** θα πρέπει να προωθούνται σε:

- νέα fuzz harnesses
- άμεσα property/invariant tests
- στοχευμένα edge-case vectors

### Συσχέτισε τα εξωτερικά ευρήματα με το graph

Αν το SAST pipeline εξάγει **SARIF**, αντιστοίχισε τα ευρήματα στους κόμβους του graph με βάση το **file + line range** και χρησιμοποίησε το graph για να επεκτείνεις την εκτίμηση impact.<sup>[[6]](#references)</sup>

- υπολόγισε το **blast radius** της flagged function
- έλεγξε αν το εύρημα βρίσκεται σε οποιοδήποτε path από ένα entrypoint
- ομαδοποίησε κοντινά ευρήματα που καταλήγουν στο ίδιο choke point

Αυτό είναι χρήσιμο όταν αποφασίζεις αν αξίζει να διαθέσεις χρόνο fuzzing σε μια συγκεκριμένη function: ένας κόμβος που είναι **reachable**, **complex** και έχει ήδη **SAST hits** είναι συχνά καλύτερος στόχος από έναν απλώς complex κόμβο χωρίς attacker path.

Παράδειγμα workflow με το Trailmark.<sup>[[6]](#references)</sup>
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
Η σημαντική μεθοδολογία είναι η τομή: **πολυπλοκότητα x έκθεση x αντίκτυπος**. Χρησιμοποιήστε το γράφημα για να επιλέξετε fuzz targets με τη μεγαλύτερη αναμενόμενη αξία ασφάλειας και, στη συνέχεια, χρησιμοποιήστε τους mutation survivors για να αποφασίσετε ποια boundaries και invariants πρέπει να ελέγχει εντατικά το harness σας.<sup>[[5]](#references)</sup>

## Fuzzing σε Go με το gosentry: Ισχυρότερη μηχανή, Typed Inputs και Differential Checks

Αν ένας target σε Go διαθέτει ήδη ένα native `testing.F` harness, μια πρακτική διαδρομή αναβάθμισης είναι να εκτελέσετε το ίδιο harness με το [gosentry](https://github.com/trailofbits/gosentry), ένα forked Go toolchain που διατηρεί το `go test -fuzz`, αλλά αλλάζει το backend σε **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Αυτό είναι χρήσιμο όταν ο native Go fuzzer κολλάει σε **hard comparisons**, **typed inputs** ή **parser-heavy formats**. Η μεθοδολογία παραμένει ίδια:

- Συνεχίστε να χρησιμοποιείτε `f.Add(...)` για seeds και `f.Fuzz(...)` για το callback.
- Επαναχρησιμοποιήστε το ίδιο harness, αλλά εκτελέστε το με το binary `go` του gosentry αντί για το stock toolchain.
- Αντιμετωπίστε την resulting campaign ως ένα κανονικό coverage-guided run, αλλά με scheduling/mutation από το LibAFL και καλύτερα surrounding detectors.

### Μετατροπή των αθόρυβων failures σε fuzz findings

Ένα συχνό πρόβλημα στα Go assessments είναι ότι η επικίνδυνη συμπεριφορά συχνά **δεν** προκαλεί crash από προεπιλογή. Με το gosentry, μπορείτε να μετατρέψετε διάφορες κατηγορίες “bad but silent” καταστάσεων σε findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` για να κάνετε επιλεγμένα logging/error paths να συμπεριφέρονται σαν crashes (χρήσιμο για `log.Fatal`-style code paths που διαφορετικά απλώς κάνουν log και συνεχίζουν).
- `--catch-races=true` για να κάνετε replay των newly discovered queue entries με τον Go race detector.
- `--catch-leaks=true` για να κάνετε replay των new queue entries με το `goleak` και να σταματάτε σε goroutine leaks.
- Το LibAFL hang handling, ώστε να διατηρούνται τα **infinite loops / very slow inputs** ως fuzz findings αντί να εξαφανίζονται ως timeouts.
- Ενσωματωμένοι έλεγχοι arithmetic overflow από προεπιλογή, καθώς και προαιρετικοί truncation checks μέσω instrumentation τύπου go-panikint.

Αυτό είναι ιδιαίτερα χρήσιμο για targets όπου το security impact είναι ένα **panicless parser failure**, ένα **concurrency bug** ή ένα **DoS-only hang**, αντί για memory corruption.

### Struct-aware fuzzing για typed Go APIs

Το native Go fuzzing αναμένει κυρίως scalars όπως `[]byte`, `string` και αριθμούς. Αν ο κώδικας υπό δοκιμή καταναλώνει typed objects, το gosentry μπορεί να κάνει fuzz απευθείας **composite values** (structs, slices, arrays, pointers), ενώ συνεχίζει να μεταλλάσσει bytes στο υπόβαθρο.<sup>[[7]](#references)[[8]](#references)</sup>
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
Χρησιμοποιήστε το όταν η δημιουργία ενός fake wire format αποκλειστικά για fuzzing θα έκρυβε logic bugs πίσω από parsing code που υπάρχει μόνο στο harness. Για differential ή grammar-based campaigns, διατηρήστε το input του harness ως ένα μόνο `[]byte` ή `string` και κάντε το parsing μέσα στο callback.

### Grammar-based fuzzing για parsers και protocol inputs

Για parsers, formats και input languages, το gosentry μπορεί να εκτελέσει **Nautilus grammar fuzzing** πάνω από το LibAFL. Το grammar είναι ένα JSON array από production rules και το harness συνήθως πρέπει να δέχεται ένα μόνο όρισμα `[]byte` ή `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Σημειώσεις μεθοδολογίας:

- Χρησιμοποίησε grammar mode όταν τα byte-level mutations αποτυγχάνουν κυρίως στους αρχικούς syntax checks.
- Κράτησε το grammar εστιασμένο στο **security-relevant υποσύνολο** της γλώσσας/του protocol, αντί να μοντελοποιήσεις ολόκληρη την προδιαγραφή.
- Χρησιμοποίησε μεγάλες boundary values σε terminals/nonterminals για να πιέσεις τα όρια των integer, length και state-machine.
- Το grammar mode διατηρεί τα inputs έγκυρα ως προς το grammar, αλλά το target εξακολουθεί να λαμβάνει **bytes/strings**, επομένως το parsing και οι semantic checks παραμένουν μέσα στον κώδικα του harness.

### Differential fuzzing: σύγκρινε implementations, όχι μόνο crashes

Ένα ισχυρό pattern για τα Go ecosystems είναι το **grammar-based differential fuzzing**: δημιούργησε έγκυρα structured inputs και τροφοδότησέ τα σε δύο parsers, clients ή state-transition engines.<sup>[[7]](#references)[[8]](#references)</sup>
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

- η μία υλοποίηση προκαλεί panic, ενώ η άλλη απορρίπτει κανονικά
- ασυμφωνίες μεταξύ αποδεκτών και απορριπτόμενων εισόδων
- διαφορετικά parse trees ή decoded objects
- αποκλίνουσες μεταβάσεις κατάστασης, nonces, balances ή state roots

Αυτός είναι ένας πρακτικός τρόπος εντοπισμού **consensus mismatches**, **parser ambiguity** και **spec-vs-implementation drift**, τα οποία το pure crash fuzzing συχνά δεν εντοπίζει.

### Επαναχρησιμοποιήστε το campaign corpus για αναφορά κάλυψης

Μετά από ένα campaign, κάντε replay στο αποθηκευμένο queue corpus για να δημιουργήσετε αναφορά κάλυψης Go χωρίς να κάνετε χειροκίνητη εξαγωγή ξεχωριστού corpus.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Εκτελέστε την εντολή από το **ίδιο package** και με τον **ίδιο στόχο `-fuzz`**, ώστε το gosentry να επιλύσει τη σωστή αποθηκευμένη κατάσταση campaign.

## References

- [1] [Fuzzing με μεταλλακτική γραμματική](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing σε βάθος](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet πέντε χρόνια αργότερα: Fuzzing πρωτοκόλλων με καθοδήγηση από την κάλυψη](https://arxiv.org/abs/2412.20324)
- [5] [Το Trailmark μετατρέπει τον κώδικα σε γράφους](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Από το Go fuzzing έλειπε το μισό toolkit. Κάναμε fork το toolchain για να το διορθώσουμε.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ένας γρήγορος Greybox Fuzzer για Stateful Network Protocols με χρήση Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Χωρίς Grammar, κανένα πρόβλημα: Προς το Fuzzing του Linux Kernel χωρίς περιγραφές System Call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Αποδοτικό Fuzzing με προσαρμοστικά και μεταβλητά Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
