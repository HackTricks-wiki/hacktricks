# Μεθοδολογία Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Στο **mutational grammar fuzzing**, τα inputs υφίστανται μεταλλάξεις παραμένοντας **έγκυρα ως προς τη γραμματική**. Σε λειτουργία coverage-guided, αποθηκεύονται ως corpus seeds μόνο τα samples που ενεργοποιούν **νέο coverage**. Για **language targets** (parsers, interpreters, engines), αυτό μπορεί να παραλείψει bugs που απαιτούν **αλυσίδες semantic/dataflow**, όπου το output ενός construct γίνεται το input ενός άλλου.<sup>[[1]](#references)</sup>

**Failure mode:** το fuzzer βρίσκει seeds που ασκούν μεμονωμένα τα `document()` και `generate-id()` (ή παρόμοια primitives), αλλά **δεν διατηρεί το chained dataflow**, οπότε το sample που βρίσκεται «πιο κοντά στο bug» απορρίπτεται επειδή δεν προσθέτει coverage. Με **3+ dependent steps**, ο τυχαίος ανασυνδυασμός γίνεται δαπανηρός και το coverage feedback δεν καθοδηγεί την αναζήτηση.<sup>[[1]](#references)</sup>

**Implication:** για grammars με πολλές dependencies, εξετάστε το ενδεχόμενο **υβριδοποίησης των mutational και generative phases** ή biasing της generation προς patterns **function chaining** (και όχι μόνο προς coverage).<sup>[[1]](#references)</sup>

## Pitfalls στη Diversity του Corpus

Το Coverage-guided mutation είναι **greedy**: ένα sample με νέο coverage αποθηκεύεται αμέσως, διατηρώντας συχνά μεγάλες, αμετάβλητες περιοχές. Με την πάροδο του χρόνου, τα corpora γίνονται **near-duplicates** με χαμηλή structural diversity. Η επιθετική minimization μπορεί να αφαιρέσει χρήσιμο context, επομένως ένας πρακτικός συμβιβασμός είναι η **grammar-aware minimization**, η οποία **σταματά μετά από ένα minimum token threshold** (μειώνοντας τον θόρυβο, ενώ διατηρεί αρκετή surrounding structure ώστε να παραμένει mutation-friendly).<sup>[[1]](#references)</sup>

Ένας πρακτικός κανόνας corpus για mutational fuzzing είναι: **προτιμήστε ένα μικρό σύνολο structurally different seeds που μεγιστοποιούν το coverage** αντί για έναν μεγάλο σωρό από near-duplicates. Στην πράξη, αυτό συνήθως σημαίνει τα εξής.<sup>[[1]](#references)[[3]](#references)</sup>

- Ξεκινήστε από **real-world samples** (public corpora, crawling, captured traffic, file sets από το ecosystem του target).
- Περιορίστε τα μέσω **coverage-based corpus minimization**, αντί να διατηρείτε κάθε έγκυρο sample.
- Διατηρήστε τα seeds **αρκετά μικρά**, ώστε οι mutations να καταλήγουν σε meaningful fields αντί να δαπανούν τους περισσότερους κύκλους σε irrelevant bytes.
- Εκτελέστε ξανά corpus minimization μετά από σημαντικές αλλαγές στο harness/instrumentation, επειδή το «καλύτερο» corpus αλλάζει όταν αλλάζει το reachability.

## Comparison-Aware Mutation για Magic Values

Ένας συνηθισμένος λόγος για τον οποίο τα fuzzers φτάνουν σε plateau δεν είναι το syntax αλλά οι **hard comparisons**: magic bytes, length checks, enum strings, checksums ή parser dispatch values που προστατεύονται από `memcmp`, switch tables ή cascaded comparisons. Το pure random mutation σπαταλά κύκλους προσπαθώντας να μαντέψει αυτές τις τιμές byte-by-byte.

Για αυτά τα targets, χρησιμοποιήστε **comparison tracing** (για παράδειγμα workflows τύπου AFL++ `CMPLOG` / Redqueen), ώστε το fuzzer να παρατηρεί τα operands από αποτυχημένες comparisons και να κατευθύνει τις mutations προς τιμές που τις ικανοποιούν.<sup>[[3]](#references)</sup>
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

- Αυτό είναι ιδιαίτερα χρήσιμο όταν ο στόχος προστατεύει τη βαθύτερη λογική πίσω από **file signatures**, **protocol verbs**, **type tags** ή **version-dependent feature bits**.
- Συνδύασέ το με **dictionaries** που έχουν εξαχθεί από πραγματικά δείγματα, προδιαγραφές πρωτοκόλλων ή debug logs. Ένα μικρό dictionary με grammar tokens, ονόματα chunks, verbs και delimiters είναι συχνά πιο πολύτιμο από ένα τεράστιο generic wordlist.
- Αν ο στόχος εκτελεί πολλούς διαδοχικούς ελέγχους, επίλυσε πρώτα τις αρχαιότερες συγκρίσεις “magic” και έπειτα ελαχιστοποίησε ξανά το corpus που προκύπτει, ώστε τα επόμενα στάδια να ξεκινούν ήδη από έγκυρα prefixes.

## Stateful Fuzzing: Οι ακολουθίες είναι Seeds

Για **protocols**, **authenticated workflows** και **multi-stage parsers**, η ενδιαφέρουσα μονάδα συχνά δεν είναι ένα μεμονωμένο blob αλλά μια **message sequence**. Η συνένωση ολόκληρου του transcript σε ένα αρχείο και η τυφλή μετάλλαξή του είναι συνήθως αναποτελεσματική, επειδή το fuzzer μεταλλάσσει κάθε βήμα εξίσου, ακόμη και όταν μόνο το μεταγενέστερο μήνυμα φτάνει στην ευάλωτη κατάσταση.<sup>[[4]](#references)</sup>

Μια πιο αποτελεσματική προσέγγιση είναι να αντιμετωπίζεις την **sequence ως seed** και να χρησιμοποιείς το **observable state** (response codes, protocol states, parser phases, returned object types) ως πρόσθετο feedback.<sup>[[4]](#references)</sup>

- Διατήρησε σταθερά τα **valid prefix messages** και εστίασε τις μεταλλάξεις στο **transition-driving** message.
- Αποθήκευε προσωρινά identifiers και τιμές που δημιουργούνται από τον server στις προηγούμενες responses, όταν το επόμενο βήμα εξαρτάται από αυτές.
- Προτίμησε per-message mutation/splicing αντί για μετάλλαξη ολόκληρου του serialized transcript ως opaque blob.
- Αν το protocol εκθέτει meaningful response codes, χρησιμοποίησέ τα ως **cheap state oracle** για να δίνεις προτεραιότητα σε sequences που προχωρούν βαθύτερα.

Αυτός είναι ο ίδιος λόγος για τον οποίο authenticated bugs, hidden transitions ή parser bugs που εμφανίζονται “only-after-handshake” συχνά διαφεύγουν από το vanilla file-style fuzzing: το fuzzer πρέπει να διατηρεί τη **σειρά, την κατάσταση και τις εξαρτήσεις**, όχι μόνο τη δομή.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Ένας πρακτικός τρόπος για να συνδυάσεις **generative novelty** με **coverage reuse** είναι να **επανεκκινείς workers μικρής διάρκειας** απέναντι σε έναν persistent server. Κάθε worker ξεκινά από ένα κενό corpus, συγχρονίζεται μετά από `T` δευτερόλεπτα, εκτελείται για άλλα `T` δευτερόλεπτα πάνω στο combined corpus, συγχρονίζεται ξανά και έπειτα τερματίζει. Αυτό παράγει **νέες δομές σε κάθε generation**, ενώ ταυτόχρονα αξιοποιεί το συσσωρευμένο coverage.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Διαδοχικοί workers (παράδειγμα loop):**

<details>
<summary>Jackalope loop επανεκκίνησης worker</summary>
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
- Το `-server_update_interval T` προσεγγίζει το **delayed sync** (πρώτα novelty, reuse αργότερα).
- Σε grammar fuzzing mode, το **initial server sync** παραλείπεται από προεπιλογή (δεν χρειάζεται το `-skip_initial_server_sync`).
- Το βέλτιστο `T` εξαρτάται από το **target**· συνήθως αποδίδει καλύτερα η αλλαγή αφού ο worker έχει βρει το μεγαλύτερο μέρος του “easy” coverage.

## Snapshot Fuzzing Για Targets Με Δύσκολο Harness

Όταν ο κώδικας που θέλετε να ελέγξετε γίνεται reachable μόνο **μετά από μεγάλο κόστος setup** (εκκίνηση VM, ολοκλήρωση login, λήψη packet, parsing container, αρχικοποίηση service), μια χρήσιμη εναλλακτική είναι το **snapshot fuzzing**: καταγράψτε την κατάσταση του έτοιμου process ή VM, εισαγάγετε κάθε test case στο input path του target, εκτελέστε μέχρι crash/timeout και επαναφέρετε το snapshot. Αυτό αποφεύγει την επανάληψη της αρχικοποίησης ή των protocol prefixes και είναι χρήσιμο για **network services**, **firmware**, **post-auth attack surfaces** και **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Εκτελέστε το target μέχρι να είναι έτοιμη η ενδιαφέρουσα κατάσταση.
2. Καταγράψτε **memory + registers** σε εκείνο το σημείο.
3. Για κάθε test case, γράψτε το mutated input απευθείας στο σχετικό guest/process buffer.
4. Εκτελέστε μέχρι crash/timeout/reset.
5. Επαναφέρετε το snapshot· για VM targets, επαναφέρετε μόνο τις **dirty pages** όταν υποστηρίζεται και, στη συνέχεια, επαναλάβετε.

Τοποθετήστε το snapshot όσο πιο κοντά γίνεται πρακτικά στο πρώτο ακριβό parse/dispatch step, όπως μετά από ένα `recv`/`read` ή ένα σημείο packet-deserialization, και καταγράψτε το input buffer που χρησιμοποιεί το target. Αυτό ακολουθεί την αρχή adaptive-placement, δηλαδή τη μετακίνηση του snapshot βαθύτερα στο input processing ώστε να αποφεύγεται η επανάληψη εργασίας.<sup>[[11]](#references)</sup>

## Harness Introspection: Έγκαιρος Εντοπισμός Shallow Fuzzers

Όταν ένα campaign σταματά να προοδεύει, το πρόβλημα συχνά δεν είναι ο **mutator**, αλλά το **harness**. Χρησιμοποιήστε **reachability/coverage introspection** για να εντοπίσετε functions που είναι statically reachable από το fuzz target, αλλά καλύπτονται σπάνια ή καθόλου dynamically. Αυτές οι functions συνήθως υποδεικνύουν ένα από τα εξής τρία προβλήματα.<sup>[[12]](#references)</sup>

- Το harness εισέρχεται στο target πολύ αργά ή πολύ νωρίς.
- Από το seed corpus λείπει μια ολόκληρη feature family.
- Το target χρειάζεται πραγματικά ένα **second harness** αντί για ένα υπερβολικά μεγάλο harness τύπου “do everything”.

Αν χρησιμοποιείτε workflows τύπου OSS-Fuzz / ClusterFuzz, το Fuzz Introspector μπορεί να συγκρίνει το static reachability με το runtime coverage και να δημιουργήσει reports από ένα timed run ή public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Χρησιμοποιήστε την αναφορά για να αποφασίσετε αν θα προσθέσετε ένα νέο harness για ένα μη ελεγμένο μονοπάτι parser, θα επεκτείνετε το corpus για ένα συγκεκριμένο feature ή θα διαχωρίσετε ένα monolithic harness σε μικρότερα entry points.

## Επιλογή Fuzz Target με Προτεραιότητα στο Graph και Triage Μεταλλάξεων

Αν έχετε ήδη **static-analysis findings**, **mutation-testing survivors** και **coverage reports**, μην τα αξιολογείτε ως ανεξάρτητες λίστες. Δημιουργήστε πρώτα ένα **call graph**, επισημάνετε τους κόμβους με **cyclomatic complexity**, **entrypoint/untrusted-input reachability** και τυχόν εξωτερικά ευρήματα και, στη συνέχεια, υποβάλετε ερωτήματα στο graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ποιες functions υψηλής πολυπλοκότητας είναι προσβάσιμες από untrusted input;
- Ποιοι mutation survivors βρίσκονται σε paths από parsers/handlers προς security-critical code;
- Ποιες functions είναι architectural choke points με ασυνήθιστα υψηλό **blast radius**;

Αυτό συνήθως αναδεικνύει καλύτερα fuzz targets από την επιλογή βάσει «lowest coverage» και μόνο. Ένας parser/decoder με **high complexity** και επιβεβαιωμένο **external reachability** είναι ισχυρότερος υποψήφιος για harness από ένα απομονωμένο internal helper με weak coverage αλλά χωρίς attacker-controlled path.

### Practical triage workflow

1. Δημιουργήστε ένα **code graph** από το codebase και εξαγάγετε metrics πολυπλοκότητας/branches ανά function.
2. Καταγράψτε τα **entrypoints** που δέχονται attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Εκτελέστε **path queries** από αυτά τα entrypoints προς candidate functions, ώστε να διαχωρίσετε το reachable attack surface από dead/internal-only code.
4. Δώστε προτεραιότητα στους κόμβους που συνδυάζουν:
- υψηλό **cyclomatic complexity**
- επιβεβαιωμένο **reachability from untrusted input**
- υψηλό **blast radius** ή πολλούς downstream dependents
- επιβεβαιωμένα στοιχεία, όπως **SARIF** findings, audit notes ή mutation survivors
5. Γράψτε focused harnesses πρώτα για τους nodes με την υψηλότερη βαθμολογία, ειδικά για **parsers/codecs**, όπως hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Το Mutation testing συχνά παράγει μια noisy λίστα survivors. Πριν θεωρήσετε κάθε survivor security gap, χρησιμοποιήστε το graph για να εξετάσετε:

- Είναι η mutated function προσβάσιμη από attacker-controlled entrypoint;
- Όλα τα call paths περιορίζονται από ισχυρότερα invariants από το mutated check;
- Ο node βρίσκεται σε dead code, formatting-only logic ή σε arithmetic/parser path υψηλού impact;

Οι survivors που παραμένουν unreachable ή structurally constrained είναι συχνά **equivalent mutants**. Οι survivors που παραμένουν **reachable** και επηρεάζουν **boundary conditions**, **overflow/carry paths** ή **security-critical arithmetic/parsing** θα πρέπει να προωθούνται σε:

- νέα fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

Αν το SAST pipeline εξάγει **SARIF**, αντιστοιχίστε τα findings στους graph nodes με βάση **file + line range** και χρησιμοποιήστε το graph για να επεκτείνετε το impact.<sup>[[6]](#references)</sup>

- υπολογίστε το **blast radius** της flagged function
- ελέγξτε αν το finding βρίσκεται σε οποιοδήποτε path από ένα entrypoint
- ομαδοποιήστε nearby findings που συγκλίνουν στο ίδιο choke point

Αυτό είναι χρήσιμο όταν αποφασίζετε αν αξίζει να διαθέσετε fuzzing χρόνο σε μια συγκεκριμένη function: ένας node που είναι **reachable**, **complex** και έχει ήδη **SAST hits** είναι συχνά καλύτερος στόχος από έναν απλώς complex node χωρίς attacker path.

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
Η σημαντική μεθοδολογία είναι η τομή: **πολυπλοκότητα x έκθεση x αντίκτυπος**. Χρησιμοποίησε το γράφημα για να επιλέξεις fuzz targets με την υψηλότερη αναμενόμενη αξία ασφάλειας και, στη συνέχεια, χρησιμοποίησε τους επιζώντες των μεταλλάξεων για να αποφασίσεις ποια όρια και invariants πρέπει να ασκήσει έντονα το harness σου.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Ισχυρότερη Engine, Typed Inputs και Differential Checks

Αν ένας στόχος Go διαθέτει ήδη ένα native `testing.F` harness, μια πρακτική διαδρομή αναβάθμισης είναι να εκτελέσεις το ίδιο harness με το [gosentry](https://github.com/trailofbits/gosentry), ένα forked Go toolchain που διατηρεί το `go test -fuzz`, αλλά αλλάζει το backend σε **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Αυτό είναι χρήσιμο όταν ο native Go fuzzer κολλά σε **hard comparisons**, **typed inputs** ή **parser-heavy formats**. Η μεθοδολογία παραμένει ίδια:

- Συνεχίστε να χρησιμοποιείτε `f.Add(...)` για seeds και `f.Fuzz(...)` για το callback.
- Επαναχρησιμοποιήστε το ίδιο harness, αλλά εκτελέστε το με το `go` binary του gosentry αντί για το stock toolchain.
- Αντιμετωπίστε την resulting campaign ως κανονική coverage-guided εκτέλεση, αλλά με LibAFL scheduling/mutation και καλύτερους surrounding detectors.

### Μετατροπή των silent failures σε fuzz findings

Ένα συχνό πρόβλημα στα Go assessments είναι ότι η επικίνδυνη συμπεριφορά συχνά **δεν** προκαλεί crash από προεπιλογή. Με το gosentry, μπορείτε να μετατρέψετε διάφορες κατηγορίες «κακών αλλά αθόρυβων» καταστάσεων σε findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` για να κάνετε επιλεγμένα logging/error paths να συμπεριφέρονται σαν crashes — χρήσιμο για code paths τύπου `log.Fatal`, τα οποία διαφορετικά απλώς καταγράφουν το σφάλμα και συνεχίζουν.
- `--catch-races=true` για να επανεκτελείτε τα newly discovered queue entries με τον Go race detector.
- `--catch-leaks=true` για να επανεκτελείτε τα νέα queue entries με το `goleak` και να σταματάτε σε goroutine leaks.
- LibAFL hang handling για να διατηρείτε τα **infinite loops / very slow inputs** ως fuzz findings αντί να εξαφανίζονται ως timeouts.
- Ενσωματωμένοι έλεγχοι arithmetic overflow από προεπιλογή, καθώς και προαιρετικοί truncation checks μέσω instrumentation τύπου go-panikint.

Αυτό είναι ιδιαίτερα χρήσιμο για targets όπου το security impact είναι ένα **panicless parser failure**, ένα **concurrency bug** ή ένα **DoS-only hang**, αντί για memory corruption.

### Struct-aware fuzzing για typed Go APIs

Το native Go fuzzing αναμένει κυρίως scalars όπως `[]byte`, `string` και numbers. Αν ο κώδικας υπό δοκιμή καταναλώνει typed objects, το gosentry μπορεί να κάνει fuzz **composite values** απευθείας (structs, slices, arrays, pointers), ενώ συνεχίζει να κάνει mutation στα bytes από κάτω.<sup>[[7]](#references)[[8]](#references)</sup>
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
Η χρήση αυτού κατά την κατασκευή ενός fake wire format αποκλειστικά για fuzzing θα έκρυβε logic bugs πίσω από parsing code που υπάρχει μόνο στο harness. Για differential ή grammar-based campaigns, διατήρησε το input του harness ως ένα μόνο `[]byte` ή `string` και κάνε το parsing μέσα στο callback.

### Grammar-based fuzzing για parsers και protocol inputs

Για parsers, formats και input languages, το gosentry μπορεί να εκτελέσει **Nautilus grammar fuzzing** πάνω από το LibAFL. Το grammar είναι ένας πίνακας JSON με production rules και το harness συνήθως θα πρέπει να δέχεται ένα μόνο όρισμα `[]byte` ή `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Σημειώσεις μεθοδολογίας:

- Χρησιμοποίησε grammar mode όταν οι μεταλλάξεις σε επίπεδο byte συνήθως αποτυγχάνουν στους αρχικούς ελέγχους σύνταξης.
- Διατήρησε το grammar επικεντρωμένο στο **security-relevant υποσύνολο** της γλώσσας/του πρωτοκόλλου, αντί να μοντελοποιήσεις ολόκληρη την προδιαγραφή.
- Χρησιμοποίησε μεγάλες οριακές τιμές σε terminals/nonterminals για να καταπονήσεις τα όρια ακεραίων, μήκους και state machines.
- Το grammar mode διατηρεί τα inputs έγκυρα ως προς το grammar, αλλά ο στόχος εξακολουθεί να λαμβάνει **bytes/strings**, επομένως το parsing και οι semantic checks παραμένουν μέσα στον κώδικα που έχει ενσωματωθεί στο harness.

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
- ασυμφωνίες μεταξύ αποδεκτών/απορριπτόμενων inputs
- διαφορετικά parse trees ή decoded objects
- αποκλίνουσες μεταβάσεις κατάστασης, nonces, balances ή state roots

Αυτός είναι ένας πρακτικός τρόπος εντοπισμού **consensus mismatches**, **parser ambiguity** και **spec-vs-implementation drift**, τα οποία το απλό crash fuzzing συχνά δεν εντοπίζει.

### Επαναχρησιμοποιήστε το campaign corpus για αναφορά κάλυψης

Μετά από ένα campaign, κάντε replay στο αποθηκευμένο queue corpus για να δημιουργήσετε μια αναφορά κάλυψης Go χωρίς να κάνετε χειροκίνητα export ξεχωριστού corpus.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Εκτέλεσε την εντολή από το **ίδιο package** και με τον **ίδιο στόχο `-fuzz`**, ώστε το gosentry να επιλύσει τη σωστή αποθηκευμένη κατάσταση του campaign.

## References

- [1] [Fuzzing με μεταλλακτική γραμματική](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing σε βάθος](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet πέντε χρόνια αργότερα: Σχετικά με το coverage-guided protocol fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Το Trailmark μετατρέπει κώδικα σε graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Στο Go fuzzing έλειπε το μισό toolkit. Κάναμε fork το toolchain για να το διορθώσουμε.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ένα γρήγορο greybox fuzzer για stateful network protocols με χρήση snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Χωρίς grammar, κανένα πρόβλημα: Προς το fuzzing του Linux kernel χωρίς περιγραφές system calls](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Αποτελεσματικό fuzzing με adaptive και mutable snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
