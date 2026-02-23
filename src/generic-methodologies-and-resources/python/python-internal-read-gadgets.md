# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Različite ranjivosti kao što su [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ili [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) mogu vam omogućiti da **čitате interne python podatke ali vam neće dozvoliti da izvršite kod**. Zbog toga će pentester morati maksimalno da iskoristi ove dozvole za čitanje da bi **dobio osetljive privilegije i eskalirao ranjivost**.

### Flask - Read secret key

Glavna stranica Flask aplikacije verovatno će imati globalni objekat **`app`** gde je ovaj **tajni ključ konfigurisan**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
U ovom slučaju moguće je pristupiti ovom objektu koristeći bilo koji gadget za **pristup globalnim objektima** sa [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

U slučaju kada je **the vulnerability is in a different python file**, treba ti gadget za prolazak kroz fajlove da bi stigao do glavnog i **pristupio globalnom objektu `app.secret_key`** kako bi promenio Flask secret key i bio u mogućnosti da [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload poput ovog [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Iskoristite ovaj payload da **promenite `app.secret_key`** (ime u vašoj aplikaciji može biti drugačije) kako biste mogli da potpisujete nove i privilegovane flask cookies.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) moći ćete da pristupite **machine_id** i **uuid** čvoru, koji su **glavne tajne** koje su vam potrebne da [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) koji možete koristiti za pristup python konzoli u `/console` ako je **debug mode** omogućen:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Imajte na umu da možete dobiti **lokalnu putanju servera do `app.py`** izazivanjem neke **greške** na web stranici koja će vam **prikazati tu putanju**.

Ako je ranjivost u drugom python fajlu, pogledajte prethodni Flask trik za pristup objektima iz glavnog python fajla.

### Django - SECRET_KEY i settings modul

Objekat Django settings-a se kešira u `sys.modules` čim se aplikacija pokrene. Sa samo read primitives možete leak-ovati **`SECRET_KEY`**, database credentials ili signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Ako se ranjiv gadget nalazi u drugom module, prvo pređi kroz globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Kada je ključ poznat, možete falsifikovati Django signed cookies ili tokens na sličan način kao kod Flask.

### Environment variables / cloud creds via loaded modules

Mnogi jails i dalje importuju `os` ili `sys` negde. Možete zloupotrebiti bilo koju dostupnu funkciju `__init__.__globals__` da pivot to the already-imported `os` module and dump **environment variables** containing API tokens, cloud keys or flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Ako je indeks podklase filtriran, koristite loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Promenljive okruženja su često jedine tajne potrebne da se pređe iz read u full compromise (cloud IAM keys, database URLs, signing keys, itd.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) je dozvoljavao **class pollution** putem crafted component requests. Postavljanjem property path-a kao `__init__.__globals__` napadač može dohvatiti component module globals i bilo koje importovane module (npr. `settings`, `os`, `sys`). Odatle možete leak `SECRET_KEY`, `DATABASES` ili service credentials bez izvršenja koda. Exploit chain je u potpunosti read-based i koristi iste dunder-gadget obrasce kao gore.

### Gadget collections for chaining

Recent CTFs (e.g. jailCTF 2025) pokazuju pouzdane read chains izgrađene samo pomoću attribute access i subclass enumeration. Komunitetom održavane liste kao što je [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogizuju stotine minimalnih gadgeta koje možete kombinovati da biste prešli od objekata do `__globals__`, `sys.modules` i na kraju do osetljivih podataka. Koristite ih da se brzo prilagodite kada se indeksi ili imena klasa razlikuju između Python minor verzija.



## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
