# Vifaa vya Kusoma vya Ndani vya Python

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Udhaifu mbalimbali kama [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) au [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) zinaweza kukuruhusu **kusoma data za ndani za python lakini hazitaturuhusu kuendesha code**. Kwa hiyo, pentester atahitaji kutumia vizuri vibali hivi vya kusoma ili **kupata vibali nyeti na kuongeza kiwango cha udhaifu**.

### Flask - Soma ufunguo wa siri

Ukurasa mkuu wa programu ya Flask huenda ukawa na global object **`app`** ambako **ufunguo wa siri umewekwa**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Katika kesi hii inawezekana kufikia kitu hiki kwa kutumia gadget yoyote tu ili **access global objects** kutoka kwenye [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

Katika kesi ambapo **udhaifu uko katika faili tofauti ya python**, unahitaji gadget kuvuka faili ili kufikia faili kuu ili **access the global object `app.secret_key`** kubadilisha Flask secret key na kuwa na uwezo wa [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload kama hii [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Tumia payload hii ili **kubadilisha `app.secret_key`** (jina katika app yako linaweza kuwa tofauti) ili uweze kusaini flask cookies mpya zenye ruhusa zaidi.

### Werkzeug - machine_id na node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) utaweza kupata **machine_id** na nodi ya **uuid**, ambazo ni **siri kuu** unazohitaji ili [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) unaweza kutumia kufikia python console katika `/console` ikiwa **debug mode** imewezeshwa:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Kumbuka kuwa unaweza kupata **njia ya ndani ya server kwa `app.py`** kwa kusababisha baadhi ya **makosa** kwenye ukurasa wa wavuti ambayo itakupa njia.

If the vulnerability is in a different python file, check the previous Flask trick to access the objects from the main python file.

### Django - SECRET_KEY and settings module

Object ya settings ya Django imehifadhiwa kwenye `sys.modules` mara tu application inapozinduliwa. Kwa primitives za kusoma pekee unaweza leak **`SECRET_KEY`**, database credentials au signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Ikiwa vulnerable gadget iko katika module nyingine, walk globals kwanza:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Mara tu key itakapojulikana unaweza kutengeneza Django signed cookies au tokens kwa njia inayofanana na Flask.

### Environment variables / cloud creds kupitia modules zilizopakuliwa

Jails nyingi bado huimport `os` au `sys` mahali fulani. Unaweza kutumia vibaya function yoyote inayoweza kufikiwa `__init__.__globals__` ili kupiga pivot hadi module ya `os` ambayo tayari imeimportiwa na ku-dump **environment variables** zenye API tokens, cloud keys au flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Ikiwa index ya subclass imechujwa, tumia loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables mara nyingi ndio secrets pekee zinazohitajika kusonga kutoka read hadi full compromise (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) iliruhusu **class pollution** kupitia crafted component requests. Kuweka property path kama `__init__.__globals__` kumruhusu mshambuliaji kufikia component module globals na modules yoyote zilizo imported (e.g. `settings`, `os`, `sys`). Kutoka huko unaweza leak `SECRET_KEY`, `DATABASES` au service credentials bila code execution. The exploit chain ni purely read-based na inatumia same dunder-gadget patterns kama hapo juu.

### Gadget collections for chaining

Recent CTFs (e.g. jailCTF 2025) zinaonyesha reliable read chains zilizojengwa tu kwa attribute access na subclass enumeration. Community-maintained lists such as [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) zinakatalogia mamia ya minimal gadgets unaweza kuziunganisha ili kuvuka kutoka objects hadi `__globals__`, `sys.modules` na hatimaye sensitive data. Zitumie kujirekebisha haraka wakati indices au class names zinatofautiana kati ya Python minor versions.



## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
