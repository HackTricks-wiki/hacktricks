# Μεθοδολογία Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Στο **mutational grammar fuzzing**, τα inputs μεταλλάσσονται ενώ παραμένουν **grammar-valid**. Σε λειτουργία coverage-guided, μόνο τα δείγματα που ενεργοποιούν **new coverage** αποθηκεύονται ως corpus seeds. Για **language targets** (parsers, interpreters, engines), αυτό μπορεί να χάσει bugs που απαιτούν **semantic/dataflow chains** όπου το output μιας δομής γίνεται το input μιας άλλης.

**Failure mode:** το fuzzer βρίσκει seeds που μεμονωμένα ενεργοποιούν `document()` και `generate-id()` (ή παρόμοια primitives), αλλά **δεν διατηρεί την αλυσιδωτή dataflow**, οπότε το δείγμα που είναι “πιο κοντά στο bug” απορρίπτεται επειδή δεν προσθέτει coverage. Με **3+ dependent steps**, ο τυχαίος ανασυνδυασμός γίνεται ακριβός και το coverage feedback δεν καθοδηγεί την αναζήτηση.

**Implication:** για grammars με πολλές εξαρτήσεις, σκέψου να **συνδυάσεις mutational και generative phases** ή να δώσεις προτεραιότητα στη δημιουργία με μοτίβα **function chaining** (όχι μόνο coverage).

## Corpus Diversity Pitfalls

Το coverage-guided mutation είναι **greedy**: ένα sample με new-coverage αποθηκεύεται αμέσως, συχνά διατηρώντας μεγάλες αμετάβλητες περιοχές. Με τον χρόνο, τα corpora γίνονται **near-duplicates** με χαμηλή δομική ποικιλία. Το επιθετικό minimization μπορεί να αφαιρέσει χρήσιμο context, οπότε ένα πρακτικό συμβιβαστικό είναι το **grammar-aware minimization** που **σταματά μετά από ένα ελάχιστο token threshold** (μείωση θορύβου ενώ διατηρείται αρκετή γύρω δομή ώστε να παραμένει mutation-friendly).

Ένας πρακτικός κανόνας για corpus στο mutational fuzzing είναι: **προτίμησε ένα μικρό σύνολο δομικά διαφορετικών seeds που μεγιστοποιούν το coverage** αντί για έναν μεγάλο σωρό από near-duplicates. Στην πράξη, αυτό συνήθως σημαίνει:

- Ξεκίνα από **real-world samples** (public corpora, crawling, captured traffic, file sets από το target ecosystem).
- Συμπύκνωσέ τα με **coverage-based corpus minimization** αντί να κρατάς κάθε valid sample.
- Κράτα τα seeds **αρκετά μικρά** ώστε οι μεταλλάξεις να πέφτουν σε ουσιαστικά πεδία αντί να ξοδεύονται οι περισσότερες προσπάθειες σε άσχετα bytes.
- Τρέξε ξανά corpus minimization μετά από μεγάλες αλλαγές στο harness/instrumentation, επειδή το “καλύτερο” corpus αλλάζει όταν αλλάζει το reachability.

## Comparison-Aware Mutation For Magic Values

Ένας συνηθισμένος λόγος που τα fuzzers φτάνουν σε plateau δεν είναι η σύνταξη αλλά τα **hard comparisons**: magic bytes, length checks, enum strings, checksums ή parser dispatch values που προστατεύονται από `memcmp`, switch tables ή cascaded comparisons. Η καθαρά τυχαία mutation σπαταλά κύκλους προσπαθώντας να μαντέψει αυτές τις τιμές byte-by-byte.

Για αυτούς τους στόχους, χρησιμοποίησε **comparison tracing** (για παράδειγμα AFL++ `CMPLOG` / Redqueen-style workflows) ώστε το fuzzer να μπορεί να παρατηρεί operands από failed comparisons και να κατευθύνει τις mutations προς τιμές που τις ικανοποιούν.
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
- Αν ο στόχος εκτελεί πολλούς διαδοχικούς ελέγχους, επίλυσε πρώτα τις πιο πρώιμες “magic” συγκρίσεις και μετά κάνε ξανά minimize το resulting corpus ώστε τα μεταγενέστερα στάδια να ξεκινούν από ήδη-valid prefixes.

## Stateful Fuzzing: Sequences Are Seeds

Για **protocols**, **authenticated workflows**, και **multi-stage parsers**, η ενδιαφέρουσα μονάδα δεν είναι συχνά ένα μεμονωμένο blob αλλά μια **message sequence**. Το να ενώσεις όλο το transcript σε ένα αρχείο και να το mutates τυφλά είναι συνήθως αναποτελεσματικό, επειδή ο fuzzer μεταλλάσσει κάθε βήμα εξίσου, ακόμα και όταν μόνο το τελευταίο μήνυμα φτάνει στην εύθραυστη κατάσταση.

Ένα πιο αποτελεσματικό pattern είναι να αντιμετωπίζεις την **sequence itself ως seed** και να χρησιμοποιείς το **observable state** (response codes, protocol states, parser phases, returned object types) ως επιπλέον feedback:

- Κράτα σταθερά τα **valid prefix messages** και εστίασε τις μεταλλάξεις στο μήνυμα που οδηγεί τη **transition**.
- Αποθήκευσε identifiers και server-generated values από προηγούμενες responses όταν το επόμενο βήμα εξαρτάται από αυτά.
- Προτίμησε per-message mutation/splicing αντί να μεταλλάσσεις όλο το serialized transcript ως opaque blob.
- Αν το protocol εκθέτει meaningful response codes, χρησιμοποίησέ τα ως ένα **cheap state oracle** για να δίνεις προτεραιότητα σε sequences που προχωρούν βαθύτερα.

Αυτός είναι ο ίδιος λόγος που authenticated bugs, hidden transitions, ή parser bugs του τύπου “only-after-handshake” συχνά χάνονται από vanilla file-style fuzzing: ο fuzzer πρέπει να διατηρεί **order, state, and dependencies**, όχι μόνο structure.

## Single-Machine Diversity Trick (Jackalope-Style)

Ένας πρακτικός τρόπος να συνδυάσεις **generative novelty** με **coverage reuse** είναι να **restarts short-lived workers** απέναντι σε έναν persistent server. Κάθε worker ξεκινά από ένα empty corpus, syncs μετά από `T` seconds, τρέχει άλλα `T` seconds πάνω στο combined corpus, syncs ξανά, και μετά exits. Αυτό δίνει **fresh structures each generation** ενώ εξακολουθεί να αξιοποιεί το accumulated coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Διαδοχικοί workers (παράδειγμα loop):**

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
- `-server_update_interval T` προσεγγίζει το **καθυστερημένο sync** (novelty πρώτα, reuse αργότερα).
- Στο grammar fuzzing mode, το **αρχικό server sync παραλείπεται από προεπιλογή** (δεν χρειάζεται `-skip_initial_server_sync`).
- Το βέλτιστο `T` είναι **εξαρτώμενο από το target**· η αλλαγή αφού ο worker έχει βρει το μεγαλύτερο μέρος της «εύκολης» coverage τείνει να λειτουργεί καλύτερα.

## Snapshot Fuzzing For Hard-To-Harness Targets

Όταν ο κώδικας που θέλεις να δοκιμάσεις γίνεται προσβάσιμος μόνο **μετά από μεγάλο setup cost** (booting a VM, completing a login, receiving a packet, parsing a container, initializing a service), μια χρήσιμη εναλλακτική είναι το **snapshot fuzzing**:

1. Τρέξε το target μέχρι να είναι έτοιμη η ενδιαφέρουσα κατάσταση.
2. Πάρε snapshot τη **memory + registers** σε εκείνο το σημείο.
3. Για κάθε test case, γράψε το mutated input απευθείας στο σχετικό guest/process buffer.
4. Εκτέλεσε μέχρι crash/timeout/reset.
5. Επαναφορά μόνο των **dirty pages** και επανάληψη.

Αυτό αποφεύγει να πληρώνεις το πλήρες setup cost σε κάθε iteration και είναι ιδιαίτερα χρήσιμο για **network services**, **firmware**, **post-auth attack surfaces**, και **binary-only targets** που είναι δύσκολο να αναδιαμορφωθούν σε ένα κλασικό in-process harness.

Ένα πρακτικό κόλπο είναι να κάνεις break αμέσως μετά από ένα `recv`/`read`/packet-deserialization point, να σημειώσεις τη διεύθυνση του input buffer, να πάρεις snapshot εκεί, και μετά να μεταβάλλεις απευθείας αυτό το buffer σε κάθε iteration. Αυτό σου επιτρέπει να κάνεις fuzzing στη deep parsing logic χωρίς να ξαναχτίζεις κάθε φορά ολόκληρο το handshake.

## Harness Introspection: Find Shallow Fuzzers Early

Όταν μια campaign κολλάει, το πρόβλημα συχνά δεν είναι το mutator αλλά το **harness**. Χρησιμοποίησε **reachability/coverage introspection** για να βρεις functions που είναι στατικά reachable από το fuzz target σου αλλά σπάνια ή ποτέ δεν καλύπτονται δυναμικά. Αυτές οι functions συνήθως δείχνουν ένα από τα τρία προβλήματα:

- Το harness μπαίνει στο target πολύ αργά ή πολύ νωρίς.
- Το seed corpus λείπει ολόκληρη feature family.
- Το target πραγματικά χρειάζεται ένα **second harness** αντί για ένα υπερμεγέθες “do everything” harness.

Αν χρησιμοποιείς workflows τύπου OSS-Fuzz / ClusterFuzz, το Fuzz Introspector είναι χρήσιμο για αυτό το triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Χρησιμοποίησε την αναφορά για να αποφασίσεις αν πρέπει να προσθέσεις ένα νέο harness για ένα untested parser path, να επεκτείνεις το corpus για ένα συγκεκριμένο feature, ή να χωρίσεις ένα μονολιθικό harness σε μικρότερα entry points.

## Graph-First Fuzz Target Selection And Mutation Triage

Αν ήδη έχεις **static-analysis findings**, **mutation-testing survivors**, και **coverage reports**, μην τα κάνεις triage ως ανεξάρτητες λίστες. Φτιάξε πρώτα ένα **call graph**, σημείωσε τους κόμβους με **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, και τυχόν external findings, και μετά κάνε graph ερωτήσεις:

- Ποιες functions με υψηλή complexity είναι reachable από untrusted input;
- Ποια mutation survivors βρίσκονται σε paths από parsers/handlers προς security-critical code;
- Ποιες functions είναι architectural choke points με ασυνήθιστα υψηλό **blast radius**;

Αυτό συνήθως αναδεικνύει καλύτερα fuzz targets από το "lowest coverage" μόνο. Ένας parser/decoder με **high complexity** και επιβεβαιωμένο **external reachability** είναι ισχυρότερος harness candidate από έναν απομονωμένο internal helper με χαμηλό coverage αλλά χωρίς attacker-controlled path.

### Practical triage workflow

1. Φτιάξε ένα **code graph** από τον codebase και εξήγαγε per-function complexity/branch metrics.
2. Κατέγραψε τα **entrypoints** που δέχονται attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Τρέξε **path queries** από αυτά τα entrypoints προς candidate functions ώστε να ξεχωρίσεις το reachable attack surface από dead/internal-only code.
4. Δώσε προτεραιότητα σε κόμβους που συνδυάζουν:
- υψηλό **cyclomatic complexity**
- επιβεβαιωμένο **reachability from untrusted input**
- υψηλό **blast radius** ή πολλούς downstream dependents
- επιβεβαιωμένα στοιχεία όπως **SARIF** findings, audit notes, ή mutation survivors
5. Γράψε focused harnesses πρώτα για τους καλύτερα βαθμολογημένους κόμβους, ειδικά **parsers/codecs** όπως hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Το mutation testing συχνά παράγει μια noisy survivor list. Πριν αντιμετωπίσεις κάθε survivor ως security gap, χρησιμοποίησε το graph για να ρωτήσεις:

- Είναι η mutated function reachable από attacker-controlled entrypoint;
- Περιορίζονται όλα τα call paths από ισχυρότερα invariants από το mutated check;
- Βρίσκεται ο κόμβος σε dead code, formatting-only logic, ή σε high-impact arithmetic/parser path;

Survivors που παραμένουν unreachable ή structurally constrained είναι συχνά **equivalent mutants**. Survivors που παραμένουν **reachable** και αγγίζουν **boundary conditions**, **overflow/carry paths**, ή **security-critical arithmetic/parsing** θα πρέπει να προωθούνται σε:

- νέα fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

Αν το SAST pipeline σου εξάγει **SARIF**, project findings πάνω σε graph nodes με βάση **file + line range** και χρησιμοποίησε το graph για να επεκτείνεις το impact:

- υπολόγισε το **blast radius** της flagged function
- έλεγξε αν το finding βρίσκεται σε οποιοδήποτε path από ένα entrypoint
- ομαδοποίησε κοντινά findings που καταλήγουν στο ίδιο choke point

Αυτό είναι χρήσιμο όταν αποφασίζεις αν αξίζει να αφιερώσεις fuzzing χρόνο σε μια συγκεκριμένη function: ένας κόμβος που είναι **reachable**, **complex**, και έχει ήδη **SAST hits** είναι συχνά καλύτερος στόχος από έναν απλώς complex node χωρίς attacker path.

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
Η σημαντική μεθοδολογία είναι η τομή: **complexity x exposure x impact**. Χρησιμοποίησε το γράφημα για να επιλέξεις fuzz targets με την υψηλότερη αναμενόμενη αξία ασφάλειας, έπειτα χρησιμοποίησε mutation survivors για να αποφασίσεις ποιες οριακές τιμές και invariants πρέπει να πιέζει το harness σου.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
