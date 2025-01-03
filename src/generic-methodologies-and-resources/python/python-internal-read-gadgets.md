# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Різні вразливості, такі як [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) або [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), можуть дозволити вам **читати внутрішні дані python, але не дозволять виконувати код**. Тому, пентестер повинен максимально використати ці дозволи на читання, щоб **отримати чутливі привілеї та ескалувати вразливість**.

### Flask - Читання секретного ключа

Головна сторінка додатку Flask, ймовірно, міститиме глобальний об'єкт **`app`**, де цей **секрет налаштовано**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
У цьому випадку можливо отримати доступ до цього об'єкта, просто використовуючи будь-який гаджет для **доступу до глобальних об'єктів** з [**сторінки обходу пісочниць Python**](bypass-python-sandboxes/).

У випадку, коли **вразливість знаходиться в іншому файлі python**, вам потрібен гаджет для переходу між файлами, щоб дістатися до основного, щоб **отримати доступ до глобального об'єкта `app.secret_key`**, щоб змінити секретний ключ Flask і мати можливість [**підвищити привілеї**, знаючи цей ключ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Пейлоад, подібний до цього [з цього опису](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Використовуйте цей payload, щоб **змінити `app.secret_key`** (ім'я у вашому додатку може бути іншим), щоб мати можливість підписувати нові та більш привілейовані flask cookies.

### Werkzeug - machine_id та node uuid

[**Використовуючи ці payload з цього опису**](https://vozec.fr/writeups/tweedle-dum-dee/) ви зможете отримати доступ до **machine_id** та **uuid** node, які є **основними секретами**, необхідними для [**генерації Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md), який ви можете використовувати для доступу до python консолі в `/console`, якщо **режим налагодження увімкнено:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Зверніть увагу, що ви можете отримати **локальний шлях сервера до `app.py`**, викликавши деякі **помилки** на веб-сторінці, які **нададуть вам шлях**.

Якщо вразливість знаходиться в іншому файлі python, перевірте попередній трюк Flask для доступу до об'єктів з основного файлу python.

{{#include ../../banners/hacktricks-training.md}}
