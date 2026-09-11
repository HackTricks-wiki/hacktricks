# Μεθοδολογία Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage έναντι Semantics

Στο **mutational grammar fuzzing**, τα inputs μεταλλάσσονται ενώ παραμένουν **grammar-valid**. Σε λειτουργία καθοδηγούμενη από coverage, αποθηκεύονται ως corpus seeds μόνο τα samples που προκαλούν **new coverage**. Για **language targets** (parsers, interpreters, engines), αυτό μπορεί να παραλείψει bugs που απαιτούν **semantic/dataflow chains**, όπου το output μιας construct γίνεται το input μιας άλλης.<sup>[[1]](#references)</sup>

**Failure mode:** το fuzzer εντοπίζει seeds που μεμονωμένα ασκούν τις `document()` και `generate-id()` (ή παρόμοια primitives), αλλά **δεν διατηρεί το chained dataflow**, με αποτέλεσμα το sample που είναι «closer-to-bug» να απορρίπτεται επειδή δεν προσθέτει coverage. Με **3+ dependent steps**, ο τυχαίος ανασυνδυασμός γίνεται δαπανηρός και το feedback από το coverage δεν καθοδηγεί την αναζήτηση.<sup>[[1]](#references)</sup>

**Implication:** για grammars με πολλές dependencies, εξετάστε το ενδεχόμενο **hybridizing mutational and generative phases** ή να κατευθύνετε τη generation προς patterns **function chaining** (και όχι μόνο προς το coverage).<sup>[[1]](#references)</sup>

## Προβλήματα Diversity του Corpus

Το mutation που καθοδηγείται από coverage είναι **greedy**: ένα sample με new coverage αποθηκεύεται αμέσως, διατηρώντας συχνά μεγάλες αμετάβλητες περιοχές. Με την πάροδο του χρόνου, τα corpora γίνονται **near-duplicates** με χαμηλή structural diversity. Το επιθετικό minimization μπορεί να αφαιρέσει χρήσιμο context, επομένως ένας πρακτικός συμβιβασμός είναι το **grammar-aware minimization**, το οποίο **σταματά μετά από ένα minimum token threshold** (μείωση του noise, διατηρώντας παράλληλα αρκετή surrounding structure ώστε να παραμένει mutation-friendly).<sup>[[1]](#references)</sup>

Ένας πρακτικός κανόνας corpus για mutational fuzzing είναι: **προτιμήστε ένα μικρό σύνολο structurally different seeds που μεγιστοποιούν το coverage** αντί για έναν μεγάλο σωρό από near-duplicates. Στην πράξη, αυτό συνήθως σημαίνει τα εξής.<sup>[[1]](#references)[[3]](#references)</sup>

- Ξεκινήστε από **real-world samples** (public corpora, crawling, captured traffic, file sets από το ecosystem του target).
- Συμπυκνώστε τα με **coverage-based corpus minimization** αντί να διατηρείτε κάθε valid sample.
- Διατηρείτε τα seeds **αρκετά μικρά**, ώστε τα mutations να καταλήγουν σε meaningful fields αντί να δαπανάται το μεγαλύτερο μέρος των cycles σε irrelevant bytes.
- Εκτελέστε ξανά corpus minimization μετά από σημαντικές αλλαγές στο harness/instrumentation, επειδή το «best» corpus αλλάζει όταν αλλάζει η reachability.

## Comparison-Aware Mutation Για Magic Values

Ένας συνηθισμένος λόγος για τον οποίο τα fuzzers φτάνουν σε plateau δεν είναι το syntax αλλά οι **hard comparisons**: magic bytes, length checks, enum strings, checksums ή parser dispatch values που προστατεύονται από `memcmp`, switch tables ή cascaded comparisons. Το pure random mutation σπαταλά cycles προσπαθώντας να μαντέψει αυτές τις τιμές byte-by-byte.

Για αυτά τα targets, χρησιμοποιήστε **comparison tracing** (για παράδειγμα workflows τύπου AFL++ `CMPLOG` / Redqueen), ώστε το fuzzer να μπορεί να παρατηρεί operands από failed comparisons και να κατευθύνει τα mutations προς τιμές που τις ικανοποιούν.<sup>[[3]](#references)</sup>
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

- Αυτό είναι ιδιαίτερα χρήσιμο όταν το target προστατεύει τη βαθύτερη λογική πίσω από **file signatures**, **protocol verbs**, **type tags** ή **version-dependent feature bits**.
- Συνδύασέ το με **dictionaries** που έχουν εξαχθεί από πραγματικά δείγματα, προδιαγραφές πρωτοκόλλων ή debug logs. Ένα μικρό dictionary με grammar tokens, ονόματα chunks, verbs και delimiters είναι συχνά πιο χρήσιμο από ένα τεράστιο generic wordlist.
- Αν το target εκτελεί πολλούς διαδοχικούς ελέγχους, επίλυσε πρώτα τις αρχαιότερες συγκρίσεις “magic” και, στη συνέχεια, ελαχιστοποίησε ξανά το corpus που προκύπτει, ώστε τα επόμενα στάδια να ξεκινούν από prefixes που είναι ήδη έγκυρα.

## Πλουσιότερο Feedback όταν το Edge Coverage συγχωνεύει διαφορετικά Paths

Το κανονικό edge coverage δεν μπορεί να διακρίνει δύο executions που περνούν από τον ίδιο helper μέσω διαφορετικών callers ή ακολουθούν διαφορετικούς συνδυασμούς branches μέσα σε μια function. Αυτό έχει σημασία σε shared decoders, protocol dispatchers και interpreter helpers, όπου το **route** προς ένα edge καθορίζει το ενεργό state. Η αφελής παρακολούθηση κάθε calling context είναι επίσης επικίνδυνη: το coverage map και το queue μπορούν να διογκωθούν ανεξέλεγκτα. Επομένως, η έρευνα στο context-sensitive fuzzing συνιστά να βελτιώνονται μόνο τα υποσχόμενα contexts, αντί να αντιμετωπίζεται ολόκληρο το call graph ως context-sensitive.<sup>[[14]](#references)</sup>

Οι πρόσφατες εκδόσεις του AFL++ παρέχουν **Ball-Larus per-function path coverage** επιπλέον του κανονικού edge coverage. Αντιστοιχίζει ένα feature σε κάθε acyclic path μέσα σε μια function· τα loop back-edges αφαιρούνται, επομένως αυτό το feedback διακρίνει συνδυασμούς branches, αλλά **όχι τον αριθμό των loop iterations**. Ξεκίνα με το χαλαρό level `1` και, στη συνέχεια, περιόρισε τα αυστηρότερα modes σε ύποπτο parser/state-machine code, επειδή ο αριθμός των paths μπορεί να αυξηθεί εκθετικά.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Για έναν helper που καλείται από πολλά σημεία με σημασία για την ασφάλεια, το LTO mode μπορεί να συνδυάσει κάθε function path με το άμεσο call site:<sup>[[13]](#references)</sup>
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
**Καθοδήγηση καμπάνιας:** εφαρμόστε πλουσιότερο feedback συντηρητικά και παρακολουθείτε το κόστος σε coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Εκτελέστε παράλληλα ένα συνηθισμένο instance με edge-coverage· το πλουσιότερο feedback είναι χρήσιμο μόνο αν το επιπλέον κόστος σε queue/map δεν μειώνει υπερβολικά τις executions ανά δευτερόλεπτο.
- Χρησιμοποιήστε το `AFL_LLVM_ALLOWLIST` για να περιορίσετε το path/caller instrumentation όταν βιβλιοθήκες με πολλά templates ή generic utility code κυριαρχούν στο map.
- Οι functions με υπερβολικά πολλούς acyclic paths μπορούν να παραλειφθούν από το AFL++· οι προειδοποιήσεις κατά το compilation αποτελούν ένδειξη ότι ο στόχος χρειάζεται allowlisting ή λιγότερο αυστηρό level.
- Το Caller + path coverage υποστηρίζει μόνο ένα caller depth. Μην το συνδυάζετε με βαθύτερα context stacks.
- Τα Path IDs μπορούν να αλλάξουν μεταξύ major εκδόσεων του LLVM. Διατηρήστε σταθερό το toolchain για μια καμπάνια και μην συγχρονίζετε PATH-based corpora σαν να ήταν σταθερά τα feature IDs μεταξύ builds.
- Αυτό το feedback συμπληρώνει το `CMPLOG`: το comparison tracing επιλύει **ποια τιμή περνά ένα guard**, ενώ το path/caller feedback διατηρεί **ποια διαδρομή και ποιος συνδυασμός branches το έφτασε**.

## Stateful Fuzzing: Οι ακολουθίες είναι seeds

Για **protocols**, **authenticated workflows** και **multi-stage parsers**, η ενδιαφέρουσα μονάδα συχνά δεν είναι ένα μεμονωμένο blob αλλά μια **message sequence**. Η συνένωση ολόκληρου του transcript σε ένα αρχείο και η τυφλή μετάλλαξή του είναι συνήθως αναποτελεσματικές, επειδή ο fuzzer μεταλλάσσει κάθε βήμα εξίσου, ακόμη και όταν μόνο το μεταγενέστερο μήνυμα φτάνει στην ευάλωτη κατάσταση.<sup>[[4]](#references)</sup>

Ένα αποτελεσματικότερο μοτίβο είναι να αντιμετωπίζετε την **sequence 자체** ως seed και να χρησιμοποιείτε το **observable state** (response codes, protocol states, parser phases, returned object types) ως πρόσθετο feedback.<sup>[[4]](#references)</sup>

- Διατηρείτε σταθερά τα **valid prefix messages** και επικεντρώνετε τις μεταλλάξεις στο **transition-driving** μήνυμα.
- Αποθηκεύετε σε cache τα identifiers και τις server-generated values από προηγούμενες αποκρίσεις, όταν το επόμενο βήμα εξαρτάται από αυτά.
- Προτιμάτε per-message mutation/splicing αντί για μετάλλαξη ολόκληρου του serialized transcript ως opaque blob.
- Αν το protocol εκθέτει meaningful response codes, χρησιμοποιήστε τα ως ένα **cheap state oracle** για να δίνετε προτεραιότητα σε sequences που προχωρούν βαθύτερα.

Αυτός είναι ο ίδιος λόγος για τον οποίο authenticated bugs, hidden transitions ή parser bugs που εμφανίζονται “only-after-handshake” συχνά δεν εντοπίζονται από το vanilla file-style fuzzing: ο fuzzer πρέπει να διατηρεί **τη σειρά, την κατάσταση και τις εξαρτήσεις**, όχι μόνο τη δομή.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Ένας πρακτικός τρόπος συνδυασμού του **generative novelty** με το **coverage reuse** είναι η **επανεκκίνηση workers μικρής διάρκειας** απέναντι σε έναν persistent server. Κάθε worker ξεκινά από ένα κενό corpus, κάνει sync μετά από `T` δευτερόλεπτα, εκτελείται για ακόμη `T` δευτερόλεπτα πάνω στο combined corpus, κάνει ξανά sync και στη συνέχεια τερματίζει. Έτσι προκύπτουν **νέες δομές σε κάθε generation**, ενώ παράλληλα αξιοποιείται το συσσωρευμένο coverage.<sup>[[1]](#references)[[2]](#references)</sup>

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

- Το `-in empty` επιβάλλει ένα **νέο corpus** σε κάθε generation.
- Το `-server_update_interval T` προσεγγίζει το **delayed sync** (πρώτα novelty, αργότερα reuse).
- Στο grammar fuzzing mode, το **initial server sync** παραλείπεται από προεπιλογή (δεν χρειάζεται το `-skip_initial_server_sync`).
- Το βέλτιστο `T` **εξαρτάται από το target**· η αλλαγή αφού ο worker έχει βρει το μεγαλύτερο μέρος του «εύκολου» coverage τείνει να λειτουργεί καλύτερα.

## Snapshot Fuzzing For Hard-To-Harness Targets

Όταν ο κώδικας που θέλετε να ελέγξετε γίνεται προσβάσιμος μόνο **μετά από μεγάλο κόστος προετοιμασίας** (εκκίνηση VM, ολοκλήρωση login, λήψη packet, parsing container, αρχικοποίηση service), μια χρήσιμη εναλλακτική είναι το **snapshot fuzzing**: καταγράψτε την έτοιμη κατάσταση του process ή του VM, εισαγάγετε κάθε test case στη διαδρομή εισόδου του target, εκτελέστε μέχρι να προκύψει crash/timeout και επαναφέρετε το snapshot. Αυτό αποφεύγει την επανάληψη της αρχικοποίησης ή των protocol prefixes και είναι χρήσιμο για **network services**, **firmware**, **post-auth attack surfaces** και **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Εκτελέστε το target μέχρι να είναι έτοιμη η ενδιαφέρουσα κατάσταση.
2. Δημιουργήστε snapshot της **memory + registers** σε εκείνο το σημείο.
3. Για κάθε test case, γράψτε το mutated input απευθείας στο σχετικό guest/process buffer.
4. Εκτελέστε μέχρι να προκύψει crash/timeout/reset.
5. Επαναφέρετε το snapshot· για VM targets, επαναφέρετε μόνο τις **dirty pages** όταν υποστηρίζεται και, στη συνέχεια, επαναλάβετε.

Τοποθετήστε το snapshot όσο πιο κοντά γίνεται στο πρώτο ακριβό βήμα parse/dispatch, όπως μετά από ένα σημείο `recv`/`read` ή packet-deserialization, και καταγράψτε το input buffer που χρησιμοποιεί το target. Αυτό ακολουθεί την αρχή adaptive-placement, σύμφωνα με την οποία μετακινείτε το snapshot βαθύτερα στην επεξεργασία του input, ώστε να αποφεύγετε την επανάληψη εργασίας.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

Όταν μια καμπάνια σταματά να προοδεύει, το πρόβλημα συχνά δεν είναι ο mutator αλλά το **harness**. Χρησιμοποιήστε **reachability/coverage introspection** για να εντοπίσετε functions που είναι στατικά reachable από το fuzz target, αλλά καλύπτονται σπάνια ή καθόλου δυναμικά. Αυτές οι functions συνήθως υποδεικνύουν ένα από τρία ζητήματα.<sup>[[12]](#references)</sup>

- Το harness εισέρχεται στο target πολύ αργά ή πολύ νωρίς.
- Από το seed corpus λείπει μια ολόκληρη feature family.
- Το target χρειάζεται πραγματικά ένα **δεύτερο harness** αντί για ένα υπερβολικά μεγάλο harness τύπου «κάνε τα πάντα».

Αν χρησιμοποιείτε workflows τύπου OSS-Fuzz / ClusterFuzz, το Fuzz Introspector μπορεί να συγκρίνει τη στατική reachability με το runtime coverage και να δημιουργεί reports από ένα timed run ή public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Χρησιμοποίησε το report για να αποφασίσεις αν πρέπει να προσθέσεις ένα νέο harness για ένα μη ελεγμένο μονοπάτι parser, να επεκτείνεις το corpus για ένα συγκεκριμένο feature ή να διαχωρίσεις ένα μονολιθικό harness σε μικρότερα entry points.

## Επιλογή Fuzz Target με προτεραιότητα στο Graph και Triage μεταλλάξεων

Αν έχεις ήδη **static-analysis findings**, **mutation-testing survivors** και **coverage reports**, μην τα αξιολογείς ως ανεξάρτητες λίστες. Δημιούργησε πρώτα ένα **call graph**, πρόσθεσε στους κόμβους σχολιασμούς με την **cyclomatic complexity**, τη δυνατότητα προσέγγισης από **entrypoint/untrusted-input** και τυχόν εξωτερικά ευρήματα, και στη συνέχεια υπέβαλε ερωτήματα στο graph.<sup>[[5]](#references)[[6]](#references)</sup>

- Ποιες συναρτήσεις υψηλής πολυπλοκότητας είναι προσβάσιμες από untrusted input;
- Ποιοι mutation survivors βρίσκονται σε paths από parsers/handlers προς security-critical code;
- Ποιες συναρτήσεις αποτελούν architectural choke points με ασυνήθιστα υψηλό **blast radius**;

Αυτό συνήθως αναδεικνύει καλύτερα fuzz targets από το να εξετάζεις μόνο το "lowest coverage". Ένας parser/decoder με **high complexity** και επιβεβαιωμένο **external reachability** είναι ισχυρότερος υποψήφιος για harness από έναν απομονωμένο internal helper με χαμηλό coverage αλλά χωρίς attacker-controlled path.

### Πρακτικό workflow triage

1. Δημιούργησε ένα **code graph** από το codebase και εξήγαγε metrics πολυπλοκότητας/branches ανά function.
2. Κατάγραψε τα **entrypoints** που δέχονται attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Εκτέλεσε **path queries** από αυτά τα entrypoints προς τις υποψήφιες συναρτήσεις, ώστε να διαχωρίσεις το reachable attack surface από τον dead/internal-only code.
4. Δώσε προτεραιότητα στους κόμβους που συνδυάζουν:
- υψηλή **cyclomatic complexity**
- επιβεβαιωμένο **reachability από untrusted input**
- υψηλό **blast radius** ή πολλούς downstream dependents
- επιβεβαιωμένα στοιχεία, όπως **SARIF** findings, audit notes ή mutation survivors
5. Γράψε focused harnesses πρώτα για τους κόμβους με την υψηλότερη βαθμολογία, ειδικά για **parsers/codecs**, όπως hex/Base64/IP/message decoders.

### Mutation survivors: equivalent έναντι actionable

Το mutation testing συχνά παράγει μια θορυβώδη λίστα survivors. Πριν θεωρήσεις κάθε survivor security gap, χρησιμοποίησε το graph για να εξετάσεις:

- Είναι η mutated function προσβάσιμη από attacker-controlled entrypoint;
- Περιορίζονται όλα τα call paths από ισχυρότερα invariants σε σχέση με το mutated check;
- Βρίσκεται ο κόμβος σε dead code, σε logic που αφορά μόνο το formatting ή σε arithmetic/parser path υψηλού αντίκτυπου;

Οι survivors που παραμένουν unreachable ή περιορίζονται δομικά είναι συχνά **equivalent mutants**. Οι survivors που παραμένουν **reachable** και επηρεάζουν **boundary conditions**, **overflow/carry paths** ή **security-critical arithmetic/parsing** θα πρέπει να προωθούνται σε:

- νέα fuzz harnesses
- άμεσα property/invariant tests
- στοχευμένα edge-case vectors

### Συσχέτισε τα εξωτερικά ευρήματα με το graph

Αν το SAST pipeline σου εξάγει **SARIF**, αντιστοίχισε τα findings στους κόμβους του graph με βάση τα **file + line range** και χρησιμοποίησε το graph για να επεκτείνεις τον αντίκτυπο.<sup>[[6]](#references)</sup>

- υπολόγισε το **blast radius** της flagged function
- έλεγξε αν το finding βρίσκεται σε οποιοδήποτε path από ένα entrypoint
- ομαδοποίησε κοντινά findings που καταλήγουν στο ίδιο choke point

Αυτό είναι χρήσιμο όταν αποφασίζεις αν αξίζει να αφιερώσεις χρόνο στο fuzzing μιας συγκεκριμένης function: ένας κόμβος που είναι **reachable**, **complex** και έχει ήδη **SAST hits** είναι συχνά καλύτερος στόχος από έναν απλώς complex κόμβο χωρίς attacker path.

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
Η σημαντική μεθοδολογία είναι η τομή: **complexity x exposure x impact**. Χρησιμοποιήστε το γράφημα για να επιλέξετε fuzz targets με την υψηλότερη αναμενόμενη αξία ασφάλειας και, στη συνέχεια, χρησιμοποιήστε τους mutation survivors για να αποφασίσετε ποια boundaries και invariants πρέπει να υποβάλει σε stress το harness σας.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Ισχυρότερος Engine, Typed Inputs και Differential Checks

Αν ένας Go target διαθέτει ήδη ένα native `testing.F` harness, μια πρακτική διαδρομή αναβάθμισης είναι να εκτελέσετε το ίδιο harness με το [gosentry](https://github.com/trailofbits/gosentry), ένα forked Go toolchain που διατηρεί το `go test -fuzz`, αλλά αλλάζει το backend σε **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Αυτό είναι χρήσιμο όταν ο native Go fuzzer κολλά σε **hard comparisons**, **typed inputs** ή **parser-heavy formats**. Η μεθοδολογία παραμένει η ίδια:

- Συνεχίστε να χρησιμοποιείτε `f.Add(...)` για seeds και `f.Fuzz(...)` για το callback.
- Επαναχρησιμοποιήστε το ίδιο harness, αλλά εκτελέστε το με το binary `go` του gosentry αντί για το stock toolchain.
- Αντιμετωπίστε το resulting campaign ως μια κανονική coverage-guided εκτέλεση, αλλά με scheduling/mutation από το LibAFL και καλύτερους surrounding detectors.

### Μετατροπή των σιωπηρών αποτυχιών σε fuzz findings

Ένα συχνό πρόβλημα στις αξιολογήσεις Go είναι ότι η επικίνδυνη συμπεριφορά συχνά **δεν** προκαλεί crash από προεπιλογή. Με το gosentry, μπορείτε να μετατρέψετε διάφορες κατηγορίες «κακών αλλά σιωπηρών» καταστάσεων σε findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` για να κάνετε επιλεγμένες logging/error διαδρομές να συμπεριφέρονται σαν crashes (χρήσιμο για code paths τύπου `log.Fatal`, τα οποία διαφορετικά απλώς καταγράφουν το σφάλμα και συνεχίζουν).
- `--catch-races=true` για να επανεκτελείτε τα νεοανακαλυφθέντα queue entries με τον Go race detector.
- `--catch-leaks=true` για να επανεκτελείτε τα νέα queue entries με το `goleak` και να σταματάτε σε περίπτωση goroutine leaks.
- Διαχείριση hang από το LibAFL, ώστε τα **infinite loops / πολύ αργά inputs** να παραμένουν fuzz findings αντί να εξαφανίζονται ως timeouts.
- Ενσωματωμένοι έλεγχοι arithmetic overflow από προεπιλογή, καθώς και προαιρετικοί έλεγχοι truncation μέσω instrumentation τύπου go-panikint.

Αυτό είναι ιδιαίτερα χρήσιμο για targets όπου ο αντίκτυπος στην ασφάλεια είναι ένα **parser failure χωρίς panic**, ένα **concurrency bug** ή ένα **hang που προκαλεί μόνο DoS**, αντί για memory corruption.

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
Χρησιμοποιήστε το όταν η δημιουργία ενός fake wire format μόνο για fuzzing θα έκρυβε logic bugs πίσω από κώδικα parsing που υπάρχει μόνο στο harness. Για differential ή grammar-based campaigns, διατηρήστε το input του harness ως ένα μόνο `[]byte` ή `string` και κάντε το parsing μέσα στο callback.

### Grammar-based fuzzing για parsers και protocol inputs

Για parsers, formats και input languages, το gosentry μπορεί να εκτελέσει **Nautilus grammar fuzzing** πάνω από το LibAFL. Το grammar είναι ένας JSON array από production rules και το harness θα πρέπει συνήθως να δέχεται ένα μόνο όρισμα `[]byte` ή `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Σημειώσεις methodology:

- Χρησιμοποίησε grammar mode όταν οι μεταλλάξεις σε επίπεδο byte αποτυγχάνουν κυρίως σε πρώιμους ελέγχους σύνταξης.
- Διατήρησε το grammar εστιασμένο στο **security-relevant υποσύνολο** της γλώσσας/του protocol, αντί να μοντελοποιείς ολόκληρη την προδιαγραφή.
- Χρησιμοποίησε μεγάλες οριακές τιμές σε terminals/nonterminals για να δοκιμάσεις τα όρια ακεραίων, μήκους και state machine.
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
- ασυμφωνίες μεταξύ αποδεκτών/απορριπτόμενων input
- διαφορετικά parse trees ή decoded objects
- αποκλίνουσες μεταβάσεις κατάστασης, nonces, balances ή state roots

Αυτός είναι ένας πρακτικός τρόπος εντοπισμού **consensus mismatches**, **parser ambiguity** και **spec-vs-implementation drift**, τα οποία συχνά δεν εντοπίζονται με pure crash fuzzing.

### Επαναχρησιμοποιήστε το campaign corpus για αναφορά κάλυψης

Μετά από ένα campaign, επαναλάβετε το saved queue corpus για να δημιουργήσετε μια αναφορά κάλυψης Go χωρίς να εξάγετε χειροκίνητα ξεχωριστό corpus.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Εκτελέστε την εντολή από το **ίδιο package** και με τον **ίδιο στόχο `-fuzz`**, ώστε το gosentry να επιλύσει τη σωστή κατάσταση του cached campaign.



## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing σε βάθος](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Πέντε χρόνια αργότερα: Σχετικά με το Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Το Trailmark μετατρέπει τον κώδικα σε γραφήματα](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Στο Go fuzzing έλειπε το μισό toolkit. Κάναμε fork στο toolchain για να το διορθώσουμε.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ένας γρήγορος Greybox Fuzzer για Stateful Network Protocols με χρήση Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Χωρίς Grammar, κανένα πρόβλημα: Προς το Fuzzing του Linux Kernel χωρίς περιγραφές System Call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Αποδοτικό Fuzzing με Adaptive και Mutable Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [LLVM instrumentation του AFL++: path και caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
