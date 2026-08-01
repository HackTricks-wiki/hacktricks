# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

不同的漏洞，例如 [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) 或 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md)，可能允许你**读取 Python 内部数据，但无法执行代码**。因此，pentester 需要充分利用这些读取权限，以**获取敏感权限并提升漏洞影响**。

### Flask - 读取 secret key

Flask 应用的主页中可能会有 **`app`** 全局对象，其中配置了这个 **secret**。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
在这种情况下，只需使用 [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) 中用于 **access global objects** 的任意 gadget，即可访问此对象。

如果 **the vulnerability is in a different python file**，则需要一个能够遍历文件的 gadget，以找到主文件，从而 **access the global object `app.secret_key`**，并能够在获知该密钥后 [**escalate privileges**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)。

例如，以下 payload [from this writeup](https://ctftime.org/writeup/36082)：
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
使用此 payload **读取 `app.secret_key`**。如果原始 bug 还为你提供了 write primitive（例如 class pollution），则可以使用相同的路径替换它，并为权限更高的 Flask cookies 进行签名。

### Werkzeug - machine_id and node uuid

[**使用此 writeup 中的 payload**](https://vozec.fr/writeups/tweedle-dum-dee/) 你将能够访问 **machine_id** 和 **uuid** node，它们是你需要用来[**生成 Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md)并在 `/console` 访问 python console 的 **private bits**，前提是已启用 **debug mode**：
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> 注意，你可以在网页中生成一些**错误**，从而获取**服务器上 `app.py` 的本地路径**，该路径会显示在网页中。

如果漏洞位于其他 Python 文件中，请检查之前的 Flask 技巧，以从主 Python 文件访问这些对象。

### Django - SECRET_KEY 和 settings module

Django settings 对象会在应用启动后缓存到 `sys.modules` 中。仅使用 read primitives，你就可以 leak **`SECRET_KEY`**、备用密钥、数据库凭据或签名 salts：
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
如果存在漏洞的 gadget 位于另一个 module 中，请先遍历 globals：
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` 与当前的 `SECRET_KEY` 同样有价值：在密钥轮换期间，它们仍会验证旧的签名值。此外，还应泄露 `SESSION_ENGINE` 和 `SESSION_SERIALIZER`，以便快速判断影响是否仅限于伪造 cookie，还是存在更严重的影响。有关 Web 影响的详细信息，请查看 [**Django pentesting 页面**](../../network-services-pentesting/pentesting-web/django.md)。

### Module loader gadgets - 读取源代码和文件

已加载的 Python 模块通常会保留一个 `__loader__`。基于文件的 loader 通常会公开 `get_source()` 和 `get_data()`，当你已经能够访问模块对象但无法使用 `open()` 时，它们正是理想的**只读原语**：
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
这对于 dump **config modules、blueprints、helper files 或 hidden routes** 非常有用，可以恢复 API keys、DSNs、flag paths 或其他 gadget entry points。

如果你只有 subclass enumeration，请按名称搜索 loader，而不是硬编码索引：
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

如果你可以创建或访问 generator/coroutine 对象，其 frame 可以在**不需要任何函数 `__globals__` gadget** 的情况下 leak globals。这对于绕过只阻止 dunder names、却忽略 `gi_frame`、`ag_frame`、`cr_frame` 或 `f_globals` 等 frame 属性的 filters 很有用：
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
获取 frame globals 后，继续完全按照其他 gadgets 的方式操作（`sys.modules`、settings objects、`os.environ` 等）。近期的 sandbox escape 仍在不断重新发现这一点，因为 `gi_frame` 和 `f_globals` 不是 dunder attributes，且通常能够绕过简单的 deny-lists。

### 通过已加载的 modules 获取环境变量 / cloud creds

许多 jail 仍会在某处导入 `os` 或 `sys`。你可以利用任何可访问函数的 `__init__.__globals__`，跳转到已经导入的 `os` module，并导出包含 API tokens、cloud keys 或 flags 的 **environment variables**：
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
如果子类索引被过滤，请使用 loaders：
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
环境变量通常是从 read 发展到 full compromise 所需的唯一 secrets（cloud IAM keys、database URLs、signing keys 等）。

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)，`<0.62.0`）允许通过构造的 component requests 进行 **class pollution**。设置类似 `__init__.__globals__` 的 property path，可以让 attacker 访问 component module globals 以及其中导入的 modules（例如 `settings`、`os`、`sys`）。之后无需 code execution，即可 leak `SECRET_KEY`、`DATABASES` 或 service credentials。该 exploit chain 完全基于 read，并使用与上文相同的 dunder-gadget patterns。

### 用于 chaining 的 gadget 集合

近期的 CTF 和 pyjail research 表明，仅通过 attribute access 和 subclass enumeration，就能构建可靠的 read chains。社区维护的列表，例如 [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker)，收录了数百个 minimal gadgets，可以将它们组合起来，从 objects 遍历到 `__globals__`、`sys.modules`，最终访问 sensitive data。相比 raw subclass indexes，优先使用基于 attribute/name 的搜索，因为 `os._wrap_close`、`FileLoader`、`warnings.catch_warnings` 等对象的位置会随 Python 版本以及额外导入的 libraries 而变化。

## References

- [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
