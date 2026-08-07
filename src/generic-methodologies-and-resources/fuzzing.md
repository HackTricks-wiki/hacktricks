# Μεθοδολογία Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Στο **mutational grammar fuzzing**, τα inputs μεταβάλλονται ενώ παραμένουν **grammar-valid**. Σε λειτουργία καθοδηγούμενη από coverage, μόνο τα samples που ενεργοποιούν **new coverage** αποθηκεύονται ως corpus seeds. Για **language targets** (parsers, interpreters, engines), αυτό μπορεί να παραλείψει bugs που απαιτούν **semantic/dataflow chains**, όπου το output ενός construct γίνεται το input ενός άλλου.

**Failure mode:** το fuzzer εντοπίζει seeds που ασκούν μεμονωμένα τα `document()` και `generate-id()` (ή παρόμοια primitives), αλλά **δεν διατηρεί το chained dataflow**, οπότε το sample που βρίσκεται “closer-to-bug” απορρίπτεται επειδή δεν προσθέτει coverage. Με **3+ dependent steps**, το random recombination γίνεται δαπανηρό και το coverage feedback δεν καθοδηγεί την αναζήτηση.

**Implication:** για grammars με πολλές dependencies, εξετάστε το **hybridizing mutational and generative phases** ή την κατεύθυνση της generation προς patterns **function chaining** (όχι μόνο προς το coverage).<sup>[[1]](#references)</sup>

## Προβλήματα Diversity στο Corpus

Το coverage-guided mutation είναι **greedy**: ένα sample με new coverage αποθηκεύεται αμέσως, διατηρώντας συχνά μεγάλες unchanged περιοχές. Με την πάροδο του χρόνου, τα corpora γίνονται **near-duplicates** με χαμηλό structural diversity. Το aggressive minimization μπορεί να αφαιρέσει χρήσιμο context, επομένως ένας πρακτικός συμβιβασμός είναι το **grammar-aware minimization**, το οποίο **σταματά μετά από ένα minimum token threshold** (μειώνοντας τον θόρυβο ενώ διατηρεί αρκετή surrounding structure ώστε να παραμένει mutation-friendly).<sup>[[1]](#references)</sup>

Ένας πρακτικός κανόνας corpus για mutational fuzzing είναι: **προτιμήστε ένα μικρό σύνολο structurally different seeds που μεγιστοποιούν το coverage** αντί για ένα μεγάλο σύνολο από near-duplicates. Στην πράξη, αυτό συνήθως σημαίνει:<sup>[[1]](#references)</sup>

- Ξεκινήστε από **real-world samples** (public corpora, crawling, captured traffic, file sets από το ecosystem του target).
- Distill τα με **coverage-based corpus minimization** αντί να διατηρείτε κάθε valid sample.
- Διατηρήστε τα seeds **αρκετά μικρά**, ώστε τα mutations να καταλήγουν σε meaningful fields αντί να δαπανούν τους περισσότερους κύκλους σε irrelevant bytes.
- Εκτελέστε ξανά corpus minimization μετά από σημαντικές αλλαγές στο harness/instrumentation, επειδή το “best” corpus αλλάζει όταν αλλάζει η reachability.

## Comparison-Aware Mutation Για Magic Values

Ένας συνηθισμένος λόγος για τον οποίο τα fuzzers σταματούν να βελτιώνονται δεν είναι το syntax αλλά τα **hard comparisons**: magic bytes, length checks, enum strings, checksums ή parser dispatch values που προστατεύονται από `memcmp`, switch tables ή cascaded comparisons. Το pure random mutation σπαταλά κύκλους προσπαθώντας να μαντέψει αυτές τις values byte-by-byte.

Για αυτά τα targets, χρησιμοποιήστε **comparison tracing** (για παράδειγμα workflows τύπου AFL++ `CMPLOG` / Redqueen), ώστε το fuzzer να μπορεί να παρατηρεί operands από failed comparisons και να κατευθύνει τα mutations προς values που τις ικανοποιούν.<sup>[[3]](#references)</sup>
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

- Αυτό είναι ιδιαίτερα χρήσιμο όταν ο στόχος εφαρμόζει ελέγχους στη βαθιά λογική με βάση **file signatures**, **protocol verbs**, **type tags** ή **version-dependent feature bits**.
- Συνδύασέ το με **dictionaries** που έχουν εξαχθεί από πραγματικά δείγματα, προδιαγραφές πρωτοκόλλων ή debug logs. Ένα μικρό dictionary με grammar tokens, chunk names, verbs και delimiters είναι συχνά πιο χρήσιμο από ένα τεράστιο generic wordlist.
- Αν ο στόχος εκτελεί πολλούς διαδοχικούς ελέγχους, επίλυσε πρώτα τις πρώιμες συγκρίσεις “magic” και, στη συνέχεια, ελαχιστοποίησε ξανά το corpus που προκύπτει, ώστε τα επόμενα στάδια να ξεκινούν από ήδη έγκυρα prefixes.

## Stateful Fuzzing: Οι ακολουθίες είναι seeds

Για **protocols**, **authenticated workflows** και **multi-stage parsers**, η ενδιαφέρουσα μονάδα συχνά δεν είναι ένα μεμονωμένο blob αλλά μια **message sequence**. Η συνένωση ολόκληρου του transcript σε ένα αρχείο και η τυφλή μετάλλαξή του είναι συνήθως αναποτελεσματική, επειδή ο fuzzer μεταλλάσσει κάθε βήμα εξίσου, ακόμη και όταν μόνο το μεταγενέστερο μήνυμα φτάνει στην ευάλωτη state.

Ένα πιο αποτελεσματικό pattern είναι να αντιμετωπίζεις την **sequence ως seed** και να χρησιμοποιείς την **observable state** (response codes, protocol states, parser phases, returned object types) ως πρόσθετο feedback:<sup>[[4]](#references)</sup>

- Διατήρησε σταθερά τα **valid prefix messages** και επικεντρώσου τις μεταλλάξεις στο μήνυμα που οδηγεί τη **transition**.
- Κάνε cache τα identifiers και τις τιμές που δημιουργεί ο server από προηγούμενες responses, όταν το επόμενο βήμα εξαρτάται από αυτά.
- Προτίμησε mutation/splicing ανά μήνυμα αντί να μεταλλάσσεις ολόκληρο το serialized transcript ως opaque blob.
- Αν το protocol εκθέτει meaningful response codes, χρησιμοποίησέ τα ως **cheap state oracle** για να δίνεις προτεραιότητα σε sequences που προχωρούν βαθύτερα.

Αυτός είναι ο ίδιος λόγος για τον οποίο authenticated bugs, hidden transitions ή parser bugs που εμφανίζονται “only-after-handshake” συχνά δεν εντοπίζονται από το vanilla file-style fuzzing: ο fuzzer πρέπει να διατηρεί **order, state και dependencies**, όχι μόνο structure.

## Τέχνασμα Diversity σε ένα μόνο μηχάνημα (Jackalope-Style)

Ένας πρακτικός τρόπος να συνδυάσεις το **generative novelty** με το **coverage reuse** είναι να κάνεις **restart σε workers μικρής διάρκειας** απέναντι σε έναν persistent server. Κάθε worker ξεκινά από ένα άδειο corpus, κάνει sync μετά από `T` δευτερόλεπτα, εκτελείται για ακόμη `T` δευτερόλεπτα πάνω στο combined corpus, κάνει ξανά sync και, στη συνέχεια, τερματίζει. Έτσι προκύπτουν **fresh structures σε κάθε generation**, ενώ παράλληλα αξιοποιείται το συσσωρευμένο coverage.<sup>[[2]](#references)</sup>

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
- Το `-server_update_interval T` προσεγγίζει το **delayed sync** (πρώτα novelty, έπειτα reuse).
- Σε grammar fuzzing mode, το **initial server sync** παραλείπεται από προεπιλογή (δεν χρειάζεται το `-skip_initial_server_sync`).
- Το βέλτιστο `T` εξαρτάται από το **target**· η αλλαγή αφού ο worker έχει βρει το μεγαλύτερο μέρος του “easy” coverage τείνει να λειτουργεί καλύτερα.

## Snapshot Fuzzing Για Targets Με Δύσκολο Harness

Όταν ο κώδικας που θέλετε να ελέγξετε γίνεται προσβάσιμος μόνο μετά από μεγάλο κόστος προετοιμασίας (εκκίνηση ενός VM, ολοκλήρωση ενός login, λήψη ενός packet, parsing ενός container, αρχικοποίηση μιας υπηρεσίας), μια χρήσιμη εναλλακτική είναι το **snapshot fuzzing**:

1. Εκτελέστε το target μέχρι να είναι έτοιμο το ενδιαφέρον state.
2. Πάρτε snapshot από τη **memory + registers** σε εκείνο το σημείο.
3. Για κάθε test case, γράψτε το mutated input απευθείας στο σχετικό guest/process buffer.
4. Εκτελέστε μέχρι να προκύψει crash/timeout/reset.
5. Επαναφέρετε μόνο τις **dirty pages** και επαναλάβετε.

Έτσι αποφεύγετε το πλήρες κόστος προετοιμασίας σε κάθε iteration και είναι ιδιαίτερα χρήσιμο για **network services**, **firmware**, **post-auth attack surfaces** και **binary-only targets** που είναι δύσκολο να αναδιαμορφωθούν σε ένα κλασικό in-process harness.

Ένα πρακτικό τέχνασμα είναι να κάνετε break αμέσως μετά από ένα σημείο `recv`/`read`/packet-deserialization, να σημειώσετε τη διεύθυνση του input buffer, να πάρετε snapshot εκεί και στη συνέχεια να κάνετε mutate απευθείας αυτό το buffer σε κάθε iteration. Έτσι μπορείτε να κάνετε fuzz τη deep parsing logic χωρίς να ξαναχτίζετε ολόκληρο το handshake κάθε φορά.

## Harness Introspection: Εντοπίστε Νωρίς Τα Shallow Fuzzers

Όταν ένα campaign σταματά να προοδεύει, το πρόβλημα συχνά δεν βρίσκεται στον mutator αλλά στο **harness**. Χρησιμοποιήστε **reachability/coverage introspection** για να εντοπίσετε functions που είναι statically reachable από το fuzz target σας, αλλά καλύπτονται σπάνια ή καθόλου δυναμικά. Αυτές οι functions συνήθως υποδεικνύουν ένα από τα εξής τρία προβλήματα:

- Το harness εισέρχεται στο target πολύ αργά ή πολύ νωρίς.
- Από το seed corpus λείπει μια ολόκληρη feature family.
- Το target χρειάζεται πραγματικά ένα **second harness** αντί για ένα υπερβολικά μεγάλο harness τύπου “do everything”.

Αν χρησιμοποιείτε workflows τύπου OSS-Fuzz / ClusterFuzz, το Fuzz Introspector είναι χρήσιμο για αυτό το triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Χρησιμοποίησε το report για να αποφασίσεις αν θα προσθέσεις ένα νέο harness για ένα μη ελεγμένο parser path, θα επεκτείνεις το corpus για ένα συγκεκριμένο feature ή θα χωρίσεις ένα monolithic harness σε μικρότερα entry points.

## Graph-First Fuzz Target Selection And Mutation Triage

Αν έχεις ήδη **static-analysis findings**, **mutation-testing survivors** και **coverage reports**, μην τα αξιολογείς ως ανεξάρτητες λίστες. Δημιούργησε πρώτα ένα **call graph**, πρόσθεσε στα nodes πληροφορίες για **cyclomatic complexity**, **entrypoint/untrusted-input reachability** και τυχόν εξωτερικά findings, και στη συνέχεια κάνε ερωτήσεις πάνω στο graph:<sup>[[5]](#references)[[6]](#references)</sup>

- Ποιες functions υψηλής πολυπλοκότητας είναι προσβάσιμες από untrusted input;
- Ποια mutation survivors βρίσκονται σε paths από parsers/handlers προς security-critical code;
- Ποιες functions αποτελούν architectural choke points με ασυνήθιστα υψηλό **blast radius**;

Αυτό συνήθως αναδεικνύει καλύτερα fuzz targets από την απλή επιλογή βάσει "lowest coverage". Ένας parser/decoder με **high complexity** και επιβεβαιωμένο **external reachability** είναι ισχυρότερος υποψήφιος για harness από έναν απομονωμένο internal helper με χαμηλό coverage αλλά χωρίς attacker-controlled path.

### Practical triage workflow

1. Δημιούργησε ένα **code graph** από το codebase και εξήγαγε metrics πολυπλοκότητας/branches για κάθε function.
2. Κατέγραψε τα **entrypoints** που δέχονται attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Εκτέλεσε **path queries** από αυτά τα entrypoints προς τις υποψήφιες functions, ώστε να διαχωρίσεις το reachable attack surface από dead/internal-only code.
4. Δώσε προτεραιότητα στα nodes που συνδυάζουν:
- υψηλό **cyclomatic complexity**
- επιβεβαιωμένο **reachability από untrusted input**
- υψηλό **blast radius** ή πολλούς downstream dependents
- υποστηρικτικά στοιχεία, όπως **SARIF** findings, audit notes ή mutation survivors
5. Γράψε focused harnesses πρώτα για τα nodes με την υψηλότερη βαθμολογία, ειδικά για **parsers/codecs** όπως hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Το mutation testing συχνά παράγει μια θορυβώδη λίστα survivors. Πριν θεωρήσεις κάθε survivor security gap, χρησιμοποίησε το graph για να εξετάσεις:

- Είναι η mutated function προσβάσιμη από attacker-controlled entrypoint;
- Όλα τα call paths περιορίζονται από ισχυρότερα invariants από το mutated check;
- Βρίσκεται το node σε dead code, σε formatting-only logic ή σε arithmetic/parser path υψηλού impact;

Οι survivors που παραμένουν unreachable ή περιορίζονται δομικά είναι συχνά **equivalent mutants**. Οι survivors που παραμένουν **reachable** και επηρεάζουν **boundary conditions**, **overflow/carry paths** ή **security-critical arithmetic/parsing** θα πρέπει να προωθούνται σε:

- νέα fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

Αν το SAST pipeline σου εξάγει **SARIF**, αντιστοίχισε τα findings στα graph nodes μέσω **file + line range** και χρησιμοποίησε το graph για να επεκτείνεις το impact:

- υπολόγισε το **blast radius** της flagged function
- έλεγξε αν το finding βρίσκεται σε οποιοδήποτε path από ένα entrypoint
- ομαδοποίησε κοντινά findings που καταλήγουν στο ίδιο choke point

Αυτό είναι χρήσιμο όταν αποφασίζεις αν θα αφιερώσεις fuzzing time σε μια συγκεκριμένη function: ένα node που είναι **reachable**, **complex** και έχει ήδη **SAST hits** είναι συχνά καλύτερος στόχος από ένα απλώς complex node χωρίς attacker path.

Example workflow with Trailmark:<sup>[[6]](#references)</sup>
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
Η σημαντική μεθοδολογία είναι η τομή: **πολυπλοκότητα x έκθεση x αντίκτυπος**. Χρησιμοποιήστε το γράφημα για να επιλέξετε fuzz targets με τη μεγαλύτερη αναμενόμενη αξία ασφάλειας και, στη συνέχεια, χρησιμοποιήστε τους επιζώντες των mutations για να αποφασίσετε ποια όρια και invariants πρέπει να ασκεί το harness σας.

## Fuzzing στο Go με gosentry: Ισχυρότερη μηχανή, Typed Inputs και Differential Checks

Αν ένας Go target διαθέτει ήδη ένα native `testing.F` harness, μια πρακτική διαδρομή αναβάθμισης είναι να εκτελέσετε το ίδιο harness με το [gosentry](https://github.com/trailofbits/gosentry), ένα forked Go toolchain που διατηρεί το `go test -fuzz`, αλλά αντικαθιστά το backend με το **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Αυτό είναι χρήσιμο όταν ο native Go fuzzer σταματά σε **hard comparisons**, **typed inputs** ή **parser-heavy formats**. Η μεθοδολογία παραμένει ίδια:

- Συνεχίστε να χρησιμοποιείτε το `f.Add(...)` για seeds και το `f.Fuzz(...)` για το callback.
- Επαναχρησιμοποιήστε το ίδιο harness, αλλά εκτελέστε το με το `go` binary του gosentry αντί για το stock toolchain.
- Αντιμετωπίστε το campaign που προκύπτει ως μια κανονική coverage-guided εκτέλεση, αλλά με LibAFL scheduling/mutation και καλύτερα surrounding detectors.

### Μετατροπή των silent failures σε fuzz findings

Ένα συχνό πρόβλημα στα Go assessments είναι ότι η επικίνδυνη συμπεριφορά συχνά **δεν** προκαλεί crash από προεπιλογή. Με το gosentry, μπορείτε να μετατρέψετε αρκετές κατηγορίες «κακών αλλά silent» καταστάσεων σε findings:

- `--panic-on=pkg.Func,...` για να κάνετε επιλεγμένες logging/error paths να συμπεριφέρονται σαν crashes (χρήσιμο για code paths τύπου `log.Fatal`, τα οποία διαφορετικά απλώς καταγράφουν το σφάλμα και συνεχίζουν).
- `--catch-races=true` για να επανεκτελείτε τα queue entries που ανακαλύφθηκαν πρόσφατα με τον Go race detector.
- `--catch-leaks=true` για να επανεκτελείτε τα νέα queue entries με το `goleak` και να σταματάτε σε goroutine leaks.
- LibAFL hang handling, ώστε τα **infinite loops / very slow inputs** να παραμένουν fuzz findings αντί να εξαφανίζονται ως timeouts.
- Ενσωματωμένοι έλεγχοι arithmetic overflow από προεπιλογή, καθώς και προαιρετικοί έλεγχοι truncation μέσω instrumentation τύπου go-panikint.

Αυτό είναι ιδιαίτερα πολύτιμο για targets όπου το security impact είναι ένα **panicless parser failure**, ένα **concurrency bug** ή ένα **DoS-only hang**, αντί για memory corruption.

### Struct-aware fuzzing για typed Go APIs

Το native Go fuzzing αναμένει κυρίως scalars όπως `[]byte`, `string` και αριθμούς. Αν ο κώδικας υπό δοκιμή καταναλώνει typed objects, το gosentry μπορεί να κάνει fuzz απευθείας σε **composite values** (structs, slices, arrays, pointers), συνεχίζοντας παράλληλα να μεταλλάσσει bytes στο υπόβαθρο.
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
Χρησιμοποίησέ το όταν η δημιουργία ενός fake wire format αποκλειστικά για fuzzing θα έκρυβε logic bugs πίσω από parsing code που υπάρχει μόνο στο harness. Για differential ή grammar-based campaigns, κράτησε το input του harness ως ένα μόνο `[]byte` ή `string` και κάνε το parsing μέσα στο callback.

### Grammar-based fuzzing για parsers και protocol inputs

Για parsers, formats και input languages, το gosentry μπορεί να εκτελέσει **Nautilus grammar fuzzing** πάνω από το LibAFL. Το grammar είναι ένας JSON array από production rules και το harness συνήθως πρέπει να δέχεται ένα μόνο όρισμα `[]byte` ή `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Σημειώσεις μεθοδολογίας:

- Χρησιμοποίησε grammar mode όταν οι μεταλλάξεις σε επίπεδο byte αποτυγχάνουν κυρίως στους πρώιμους ελέγχους σύνταξης.
- Κράτησε το grammar εστιασμένο στο **security-relevant υποσύνολο** της γλώσσας/του protocol, αντί να μοντελοποιήσεις ολόκληρη την προδιαγραφή.
- Χρησιμοποίησε μεγάλες οριακές τιμές σε terminals/nonterminals, ώστε να ασκήσεις πίεση στα όρια ακεραίων, μήκους και state machine.
- Το grammar mode διατηρεί τα inputs έγκυρα ως προς το grammar, όμως ο στόχος εξακολουθεί να λαμβάνει **bytes/strings**, επομένως οι έλεγχοι parsing και semantics παραμένουν μέσα στον κώδικα του harness.

### Differential fuzzing: σύγκρινε implementations, όχι μόνο crashes

Ένα ισχυρό pattern για τα Go ecosystems είναι το **grammar-based differential fuzzing**: δημιούργησε έγκυρα structured inputs και τροφοδότησέ τα σε δύο parsers, clients ή state-transition engines.
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
- ασυμφωνίες μεταξύ αποδεκτών/απορριπτόμενων εισόδων
- διαφορετικά parse trees ή decoded objects
- αποκλίνουσες μεταβάσεις κατάστασης, nonces, balances ή state roots

Αυτός είναι ένας πρακτικός τρόπος εντοπισμού **consensus mismatches**, **parser ambiguity** και **spec-vs-implementation drift**, τα οποία συχνά δεν ανιχνεύονται με pure crash fuzzing.

### Επαναχρησιμοποιήστε το campaign corpus για αναφορά κάλυψης

Μετά από ένα campaign, κάντε replay στο αποθηκευμένο queue corpus για να δημιουργήσετε μια αναφορά κάλυψης Go χωρίς να κάνετε χειροκίνητη εξαγωγή ξεχωριστού corpus:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Εκτελέστε την εντολή από το **ίδιο package** και με τον **ίδιο στόχο `-fuzz`**, ώστε το gosentry να επιλύει τη σωστή cached κατάσταση του campaign.

## Αναφορές

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
