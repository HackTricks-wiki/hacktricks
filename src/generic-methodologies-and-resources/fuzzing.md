# Μεθοδολογία Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Στο **mutational grammar fuzzing**, τα inputs μεταλλάσσονται ενώ παραμένουν **grammar-valid**. Σε mode guided by coverage, αποθηκεύονται ως corpus seeds μόνο τα samples που ενεργοποιούν **new coverage**. Για **language targets** (parsers, interpreters, engines), αυτό μπορεί να χάσει bugs που απαιτούν **semantic/dataflow chains** όπου το output ενός construct γίνεται το input ενός άλλου.

**Failure mode:** ο fuzzer βρίσκει seeds που ξεχωριστά ενεργοποιούν `document()` και `generate-id()` (ή παρόμοια primitives), αλλά **δεν διατηρεί το chained dataflow**, οπότε το sample “closer-to-bug” απορρίπτεται επειδή δεν προσθέτει coverage. Με **3+ dependent steps**, το τυχαίο recombination γίνεται ακριβό και το feedback από coverage δεν καθοδηγεί την αναζήτηση.

**Implication:** για grammars με έντονα dependencies, σκέψου να **συνδυάσεις mutational και generative phases** ή να δώσεις προτεραιότητα στη generation προς patterns **function chaining** (όχι μόνο coverage).

## Corpus Diversity Pitfalls

Η coverage-guided mutation είναι **greedy**: ένα sample με new coverage αποθηκεύεται αμέσως, συχνά διατηρώντας μεγάλα αμετάβλητα regions. Με τον χρόνο, τα corpora γίνονται **near-duplicates** με χαμηλή structural diversity. Το aggressive minimization μπορεί να αφαιρέσει χρήσιμο context, οπότε ένας πρακτικός συμβιβασμός είναι το **grammar-aware minimization** που **σταματά μετά από ένα minimum token threshold** (μείωση θορύβου ενώ διατηρείται αρκετή surrounding structure ώστε να παραμένει mutation-friendly).

Ένας πρακτικός κανόνας corpus για mutational fuzzing είναι: **προτίμησε ένα μικρό σύνολο από δομικά διαφορετικά seeds που μεγιστοποιούν την coverage** αντί για έναν μεγάλο σωρό από near-duplicates. Στην πράξη, αυτό συνήθως σημαίνει:

- Ξεκίνα από **real-world samples** (public corpora, crawling, captured traffic, file sets από το target ecosystem).
- Απόσταξέ τα με **coverage-based corpus minimization** αντί να κρατάς κάθε valid sample.
- Κράτα τα seeds **αρκετά μικρά** ώστε οι mutations να πέφτουν σε ουσιαστικά fields και όχι να ξοδεύονται οι περισσότερες κύκλοι σε άσχετα bytes.
- Ξανατρέξε corpus minimization μετά από σημαντικές αλλαγές στο harness/instrumentation, επειδή το “best” corpus αλλάζει όταν αλλάζει η reachability.

## Comparison-Aware Mutation For Magic Values

Ένας συνηθισμένος λόγος που τα fuzzers κάνουν plateau δεν είναι η syntax αλλά τα **hard comparisons**: magic bytes, length checks, enum strings, checksums ή parser dispatch values που προστατεύονται από `memcmp`, switch tables ή cascaded comparisons. Η καθαρά τυχαία mutation σπαταλά κύκλους προσπαθώντας να μαντέψει αυτές τις τιμές byte-by-byte.

Για τέτοιους targets, χρησιμοποίησε **comparison tracing** (για παράδειγμα AFL++ `CMPLOG` / Redqueen-style workflows) ώστε το fuzzer να μπορεί να παρατηρεί operands από failed comparisons και να κατευθύνει τις mutations προς τιμές που τα ικανοποιούν.
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
- Συνδύασέ το με **dictionaries** που εξάγονται από πραγματικά samples, protocol specs, ή debug logs. Ένα μικρό dictionary με grammar tokens, chunk names, verbs, και delimiters είναι συχνά πιο πολύτιμο από ένα τεράστιο γενικό wordlist.
- Αν ο στόχος εκτελεί πολλαπλούς διαδοχικούς ελέγχους, λύσε πρώτα τις πιο πρώιμες “magic” συγκρίσεις και μετά ελαχιστοποίησε ξανά το resulting corpus ώστε τα επόμενα στάδια να ξεκινούν από ήδη-valid prefixes.

## Stateful Fuzzing: Sequences Are Seeds

Για **protocols**, **authenticated workflows**, και **multi-stage parsers**, η ενδιαφέρουσα μονάδα συχνά δεν είναι ένα μεμονωμένο blob αλλά μια **message sequence**. Η απλή συνένωση όλου του transcript σε ένα αρχείο και η τυφλή μετάλλαξή του είναι συνήθως αναποτελεσματική, επειδή ο fuzzer μεταλλάσσει κάθε βήμα εξίσου, ακόμα κι όταν μόνο το μεταγενέστερο μήνυμα φτάνει στην εύθραυστη κατάσταση.

Ένα πιο αποτελεσματικό μοτίβο είναι να αντιμετωπίζεις την **sequence** ως seed και να χρησιμοποιείς την **observable state** (response codes, protocol states, parser phases, returned object types) ως επιπλέον feedback:

- Κράτα σταθερά τα **valid prefix messages** και εστίασε τις μεταλλάξεις στο μήνυμα που οδηγεί τη **transition**.
- Αποθήκευσε identifiers και server-generated values από προηγούμενες responses όταν το επόμενο βήμα εξαρτάται από αυτά.
- Προτίμησε per-message mutation/splicing αντί να μεταλλάσσεις όλο το serialized transcript ως opaque blob.
- Αν το protocol εκθέτει ουσιαστικά response codes, χρησιμοποίησέ τα ως έναν **cheap state oracle** για να προτεραιοποιήσεις sequences που προχωρούν βαθύτερα.

Αυτός είναι και ο λόγος που authenticated bugs, hidden transitions, ή parser bugs τύπου “only-after-handshake” συχνά χάνονται από το vanilla file-style fuzzing: ο fuzzer πρέπει να διατηρεί **order, state, και dependencies**, όχι μόνο τη δομή.

## Single-Machine Diversity Trick (Jackalope-Style)

Ένας πρακτικός τρόπος να υβριδοποιήσεις τη **generative novelty** με το **coverage reuse** είναι να **επανεκκινείς short-lived workers** απέναντι σε έναν persistent server. Κάθε worker ξεκινά από ένα empty corpus, syncs μετά από `T` seconds, τρέχει άλλα `T` seconds πάνω στο combined corpus, syncs ξανά, και μετά exits. Αυτό παράγει **φρέσκες δομές σε κάθε generation** ενώ εξακολουθεί να αξιοποιεί το accumulated coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Διαδοχικοί workers (example loop):**

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

- `-in empty` επιβάλλει ένα **φρέσκο corpus** σε κάθε γενιά.
- `-server_update_interval T` προσεγγίζει **καθυστερημένο sync** (πρώτα η novelty, μετά η επαναχρησιμοποίηση).
- Στη λειτουργία grammar fuzzing, το **αρχικό server sync παραλείπεται από προεπιλογή** (δεν χρειάζεται `-skip_initial_server_sync`).
- Το βέλτιστο `T` είναι **target-dependent**· η αλλαγή αφού ο worker έχει βρει το μεγαλύτερο μέρος του “easy” coverage τείνει να λειτουργεί καλύτερα.

## Snapshot Fuzzing For Hard-To-Harness Targets

Όταν ο code που θέλεις να testάρεις γίνεται reachable μόνο **μετά από μεγάλο setup cost** (booting a VM, completing a login, receiving a packet, parsing a container, initializing a service), μια χρήσιμη εναλλακτική είναι το **snapshot fuzzing**:

1. Τρέξε το target μέχρι να είναι έτοιμο το ενδιαφέρον state.
2. Πάρε snapshot της **memory + registers** σε εκείνο το σημείο.
3. Για κάθε test case, γράψε το mutated input απευθείας στο σχετικό guest/process buffer.
4. Εκτέλεσε μέχρι crash/timeout/reset.
5. Επανέφερε μόνο τα **dirty pages** και επανάλαβε.

Αυτό αποφεύγει να πληρώνεις το πλήρες setup cost σε κάθε iteration και είναι ιδιαίτερα χρήσιμο για **network services**, **firmware**, **post-auth attack surfaces**, και **binary-only targets** που είναι δύσκολο να μετατραπούν σε ένα κλασικό in-process harness.

Ένα πρακτικό trick είναι να κάνεις break αμέσως μετά από ένα `recv`/`read`/packet-deserialization point, να σημειώσεις το input buffer address, να πάρεις snapshot εκεί, και μετά να mutate-άρεις αυτό το buffer απευθείας σε κάθε iteration. Αυτό σου επιτρέπει να fuzzάρεις τη deep parsing logic χωρίς να ξαναχτίζεις κάθε φορά ολόκληρο το handshake.

## Harness Introspection: Find Shallow Fuzzers Early

Όταν μια campaign κολλάει, το πρόβλημα συχνά δεν είναι ο mutator αλλά το **harness**. Χρησιμοποίησε **reachability/coverage introspection** για να βρεις functions που είναι στατικά reachable από το fuzz target σου αλλά καλύπτονται σπάνια ή ποτέ δυναμικά. Αυτές οι functions συνήθως δείχνουν ένα από τα τρία προβλήματα:

- Το harness μπαίνει στο target πολύ αργά ή πολύ νωρίς.
- Το seed corpus λείπει μια ολόκληρη family features.
- Το target πραγματικά χρειάζεται ένα **second harness** αντί για ένα υπερβολικά μεγάλο harness τύπου “do everything”.

Αν χρησιμοποιείς OSS-Fuzz / ClusterFuzz-style workflows, το Fuzz Introspector είναι χρήσιμο για αυτό το triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use the report to decide whether to add a new harness for an untested parser path, expand the corpus for a specific feature, or split a monolithic harness into smaller entry points.

## Επιλογή fuzz target και triage mutation με Graph-First

Αν ήδη έχετε **static-analysis findings**, **mutation-testing survivors** και **coverage reports**, μην τα κάνετε triage ως ανεξάρτητες λίστες. Φτιάξτε πρώτα ένα **call graph**, σχολιάστε τους κόμβους με **cyclomatic complexity**, **entrypoint/untrusted-input reachability** και τυχόν εξωτερικά findings, και μετά κάντε ερωτήσεις πάνω στο graph:

- Ποιες functions με υψηλή πολυπλοκότητα είναι reachable από untrusted input;
- Ποια mutation survivors βρίσκονται σε paths από parsers/handlers προς security-critical code;
- Ποιες functions είναι architectural choke points με ασυνήθιστα υψηλό **blast radius**;

Αυτό συνήθως αποκαλύπτει καλύτερα fuzz targets από το "lowest coverage" μόνο. Ένας parser/decoder με **high complexity** και επιβεβαιωμένη **external reachability** είναι ισχυρότερος υποψήφιος harness από ένα απομονωμένο internal helper με αδύναμη κάλυψη αλλά χωρίς attacker-controlled path.

### Practical triage workflow

1. Φτιάξτε ένα **code graph** από το codebase και εξαγάγετε per-function complexity/branch metrics.
2. Καταγράψτε τα **entrypoints** που δέχονται attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Τρέξτε **path queries** από αυτά τα entrypoints προς candidate functions για να ξεχωρίσετε το reachable attack surface από dead/internal-only code.
4. Δώστε προτεραιότητα σε nodes που συνδυάζουν:
- high **cyclomatic complexity**
- επιβεβαιωμένη **reachability from untrusted input**
- υψηλό **blast radius** ή πολλούς downstream dependents
- corroborating evidence όπως **SARIF** findings, audit notes ή mutation survivors
5. Γράψτε focused harnesses για τους καλύτερα βαθμολογημένους nodes πρώτα, ειδικά **parsers/codecs** όπως hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Το mutation testing συχνά παράγει μια θορυβώδη λίστα survivors. Πριν θεωρήσετε κάθε survivor ως security gap, χρησιμοποιήστε το graph για να ρωτήσετε:

- Είναι η mutated function reachable από attacker-controlled entrypoint;
- Περιορίζονται όλα τα call paths από ισχυρότερα invariants από το mutated check;
- Βρίσκεται ο κόμβος σε dead code, formatting-only logic ή σε high-impact arithmetic/parser path;

Survivors που παραμένουν unreachable ή δομικά περιορισμένοι είναι συχνά **equivalent mutants**. Survivors που παραμένουν **reachable** και αγγίζουν **boundary conditions**, **overflow/carry paths** ή **security-critical arithmetic/parsing** θα πρέπει να προωθηθούν σε:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Συσχετίστε external findings πάνω στο graph

Αν το SAST pipeline σας εξάγει **SARIF**, προβάλετε τα findings πάνω σε graph nodes με βάση **file + line range** και χρησιμοποιήστε το graph για να επεκτείνετε τον αντίκτυπο:

- υπολογίστε το **blast radius** της flagged function
- ελέγξτε αν το finding βρίσκεται σε οποιοδήποτε path από ένα entrypoint
- ομαδοποιήστε κοντινά findings που καταλήγουν στο ίδιο choke point

Αυτό είναι χρήσιμο όταν αποφασίζετε αν θα ξοδέψετε χρόνο fuzzing σε μια συγκεκριμένη function: ένας κόμβος που είναι **reachable**, **complex** και ήδη έχει **SAST hits** είναι συχνά καλύτερος στόχος από έναν απλώς complex κόμβο χωρίς attacker path.

Example workflow with Trailmark:
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
Η σημαντική μεθοδολογία είναι η τομή: **complexity x exposure x impact**. Χρησιμοποίησε το γράφημα για να επιλέξεις fuzz targets με τη μεγαλύτερη αναμενόμενη αξία ασφάλειας, και έπειτα χρησιμοποίησε mutation survivors για να αποφασίσεις ποια όρια και invariants πρέπει να πιέσει το harness σου.

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Αν ένας Go target έχει ήδη ένα native `testing.F` harness, μια πρακτική διαδρομή αναβάθμισης είναι να τρέξεις το ίδιο harness με [gosentry](https://github.com/trailofbits/gosentry), ένα forked Go toolchain που διατηρεί το `go test -fuzz` αλλά αντικαθιστά το backend με **LibAFL**.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Αυτό είναι χρήσιμο όταν το native Go fuzzer κολλάει σε **hard comparisons**, **typed inputs**, ή **parser-heavy formats**. Η μεθοδολογία παραμένει η ίδια:

- Συνέχισε να χρησιμοποιείς `f.Add(...)` για seeds και `f.Fuzz(...)` για το callback.
- Επαναχρησιμοποίησε το ίδιο harness, αλλά τρέξ’ το με το `go` binary του gosentry αντί για το stock toolchain.
- Αντιμετώπισε την προκύπτουσα campaign ως ένα κανονικό coverage-guided run, αλλά με LibAFL scheduling/mutation και καλύτερους surrounding detectors.

### Μετατροπή των silent failures σε fuzz findings

Ένα επαναλαμβανόμενο πρόβλημα σε Go assessments είναι ότι η επικίνδυνη συμπεριφορά συχνά **δεν** κάνει crash από προεπιλογή. Με το gosentry, μπορείς να μετατρέψεις αρκετές κατηγορίες από “κακές αλλά silent” καταστάσεις σε findings:

- `--panic-on=pkg.Func,...` για να κάνεις επιλεγμένα logging/error paths να συμπεριφέρονται σαν crashes (χρήσιμο για `log.Fatal`-style code paths που αλλιώς απλώς κάνουν log και συνεχίζουν).
- `--catch-races=true` για να ξαναεκτελείς τα newly discovered queue entries με το Go race detector.
- `--catch-leaks=true` για να ξαναεκτελείς νέα queue entries με το `goleak` και να σταματάς σε goroutine leaks.
- LibAFL hang handling για να κρατάς τα **infinite loops / very slow inputs** ως fuzz findings αντί να εξαφανίζονται ως timeouts.
- Built-in arithmetic overflow checks από προεπιλογή, συν προαιρετικούς truncation checks μέσω go-panikint-style instrumentation.

Αυτό είναι ιδιαίτερα πολύτιμο για targets όπου ο security impact είναι ένα **panicless parser failure**, ένα **concurrency bug**, ή ένα **DoS-only hang** αντί για memory corruption.

### Struct-aware fuzzing για typed Go APIs

Το native Go fuzzing κυρίως περιμένει scalars όπως `[]byte`, `string`, και numbers. Αν το code under test καταναλώνει typed objects, το gosentry μπορεί να fuzzάρει **composite values** απευθείας (structs, slices, arrays, pointers) ενώ εξακολουθεί να mutates bytes από κάτω.
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
Όταν χρησιμοποιείται για την κατασκευή ενός ψεύτικου wire format μόνο για fuzzing, αυτό θα έκρυβε λογικά bugs πίσω από code parsing μόνο για το harness. Για differential ή grammar-based campaigns, κρατήστε το harness input ως ένα μόνο `[]byte` ή `string` και κάντε parse μέσα στο callback αντί γι’ αυτό.

### Grammar-based fuzzing για parsers και protocol inputs

Για parsers, formats, και input languages, το gosentry μπορεί να τρέξει **Nautilus grammar fuzzing** πάνω από το LibAFL. Η grammar είναι ένα JSON array από production rules, και το harness συνήθως θα πρέπει να δέχεται ένα μόνο `[]byte` ή `string` argument.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes:

- Χρησιμοποίησε grammar mode όταν οι byte-level mutations πεθαίνουν κυρίως στα πρώιμα syntax checks.
- Κράτα τη grammar εστιασμένη στο **security-relevant subset** της γλώσσας/protocol αντί να μοντελοποιείς όλη τη specification.
- Χρησιμοποίησε μεγάλα boundary values σε terminals/nonterminals για να στρεσάρεις integer, length, και state-machine edges.
- Το grammar mode κρατά τα inputs grammar-valid, αλλά το target εξακολουθεί να λαμβάνει **bytes/strings**, οπότε τα parsing και semantic checks παραμένουν μέσα στον harnessed code.

### Differential fuzzing: σύγκρινε implementations, όχι μόνο crashes

Ένα ισχυρό pattern για Go ecosystems είναι το **grammar-based differential fuzzing**: δημιούργησε valid structured inputs και δώσ’ τα σε δύο parsers, clients, ή state-transition engines.
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
Θεώρησε τα ακόλουθα ως ευρήματα:

- μία υλοποίηση κάνει panic ενώ η άλλη απορρίπτει καθαρά
- ασυμφωνίες σε accepted/rejected input
- διαφορετικά parse trees ή decoded objects
- αποκλίνουσες state transitions, nonces, balances ή state roots

Αυτός είναι ένας πρακτικός τρόπος για να βρεις **consensus mismatches**, **parser ambiguity** και **spec-vs-implementation drift** που το pure crash fuzzing συχνά χάνει.

### Επαναχρησιμοποίησε το campaign corpus για coverage reporting

Μετά από ένα campaign, κάνε replay το αποθηκευμένο queue corpus για να δημιουργήσεις ένα Go coverage report χωρίς να κάνεις χειροκίνητα export ένα ξεχωριστό corpus:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Εκτέλεσε την εντολή από το **ίδιο package** και με το ίδιο `-fuzz` target, ώστε το gosentry να εντοπίσει τη σωστή cached campaign state.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
