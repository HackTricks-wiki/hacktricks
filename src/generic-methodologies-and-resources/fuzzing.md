# Fuzzing Μεθοδολογία

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Στο **mutational grammar fuzzing**, τα inputs μεταλλάσσονται ενώ παραμένουν **grammar-valid**. Σε coverage-guided mode, μόνο δείγματα που ενεργοποιούν **new coverage** αποθηκεύονται ως corpus seeds. Για **language targets** (parsers, interpreters, engines), αυτό μπορεί να χάσει σφάλματα που απαιτούν **semantic/dataflow chains** όπου το output ενός construct γίνεται το input σε άλλο.

**Failure mode:** ο fuzzer βρίσκει seeds που μεμονωμένα ασκούν τις `document()` και `generate-id()` (ή παρόμοια primitives), αλλά **δεν διατηρεί την αλυσιδωτή ροή δεδομένων (chained dataflow)**, οπότε το δείγμα «πιο κοντά στο bug» απορρίπτεται επειδή δεν προσθέτει coverage. Με **3+ dependent steps**, η τυχαία ανασύνθεση γίνεται δαπανηρή και το coverage feedback δεν καθοδηγεί την αναζήτηση.

**Implication:** για γραμματικές με πολλές εξαρτήσεις, σκεφτείτε το **hybridizing mutational and generative phases** ή την προκατάληψη της γενιάς προς πρότυπα **function chaining** (όχι μόνο coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation είναι **greedy**: ένα δείγμα με νέα κάλυψη αποθηκεύεται αμέσως, συχνά διατηρώντας μεγάλες αμετάβλητες περιοχές. Με την πάροδο του χρόνου, τα corpora γίνονται **near-duplicates** με χαμηλή δομική ποικιλία. Επιθετική μείωση μπορεί να αφαιρέσει χρήσιμο context, οπότε ένας πρακτικός συμβιβασμός είναι **grammar-aware minimization** που **σταματά μετά από ένα ελάχιστο όριο token** (μειώνει τον θόρυβο διατηρώντας όμως αρκετή γύρω δομή για να παραμείνει mutation-friendly).

## Single-Machine Diversity Trick (Jackalope-Style)

Ένας πρακτικός τρόπος να υβριδοποιήσετε τη **generative novelty** με την **coverage reuse** είναι να **restart short-lived workers** ενάντια σε persistent server. Κάθε worker ξεκινά από άδειο corpus, συγχρονίζει μετά από `T` δευτερόλεπτα, τρέχει άλλα `T` δευτερόλεπτα στο συνδυασμένο corpus, συγχρονίζει ξανά και μετά τερματίζει. Αυτό παράγει **fresh structures each generation** ενώ εξακολουθεί να αξιοποιεί το συσσωρευμένο coverage.

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

- `-in empty` αναγκάζει τη δημιουργία ενός **fresh corpus** σε κάθε γενιά.
- `-server_update_interval T` προσεγγίζει έναν **delayed sync** (novelty first, reuse later).
- Στη λειτουργία grammar fuzzing, **initial server sync is skipped by default** (no need for `-skip_initial_server_sync`).
- Το βέλτιστο `T` είναι **target-dependent**· η εναλλαγή αφού ο worker έχει βρει τα περισσότερα “easy” coverage τείνει να λειτουργεί καλύτερα.

## Αναφορές

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
