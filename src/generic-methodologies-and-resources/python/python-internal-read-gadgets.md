# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

Different vulnerabilities such as [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) or [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) might allow you to **kusoma data za ndani za python lakini hazitakuruhusu kuendesha code**. Therefore, a pentester will need to make the most of these read permissions to **kupata mamlaka nyeti na kuongeza udhaifu**.

### Flask - Read secret key

The main page of a Flask application will probably have the **`app`** global object where this **siri imewekwa**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Katika kesi hii inawezekana kufikia kitu hiki kwa kutumia gadget yoyote ili **kufikia vitu vya kimataifa** kutoka kwenye [**ukurasa wa Bypass Python sandboxes**](bypass-python-sandboxes/).

Katika kesi ambapo **udhaifu uko katika faili tofauti la python**, unahitaji gadget ili kupita faili ili kufikia faili kuu ili **kufikia kitu cha kimataifa `app.secret_key`** kubadilisha funguo za siri za Flask na kuwa na uwezo wa [**kuinua mamlaka** ukijua funguo hii](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload kama hii [kutoka kwenye andiko hili](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Tumia payload hii kubadilisha **`app.secret_key`** (jina katika programu yako linaweza kuwa tofauti) ili uweze kusaini vidakuzi vya flask vipya na vya kibali zaidi.

### Werkzeug - machine_id na node uuid

[**Kwa kutumia payload hizi kutoka kwa andiko hili**](https://vozec.fr/writeups/tweedle-dum-dee/) utaweza kufikia **machine_id** na **uuid** node, ambazo ni **siri kuu** unazohitaji ili [**kuunda pin ya Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) unayoweza kutumia kufikia konso ya python katika `/console` ikiwa **mode ya debug imewezeshwa:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Kumbuka kwamba unaweza kupata **njia ya ndani ya seva kwa `app.py`** kwa kuzalisha **kosa** kwenye ukurasa wa wavuti ambayo itakupa **njia**.

Ikiwa udhaifu uko katika faili tofauti la python, angalia hila ya Flask ya awali ili kufikia vitu kutoka kwa faili kuu la python.

{{#include ../../banners/hacktricks-training.md}}
