# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

不同的漏洞，如 [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) 或 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md)，可能允许你 **读取 Python 内部数据，但不允许你执行代码**。因此，渗透测试人员需要充分利用这些读取权限，以 **获取敏感权限并升级漏洞**。

### Flask - 读取密钥

Flask 应用程序的主页面可能会有 **`app`** 全局对象，在这里 **配置了这个密钥**。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
在这种情况下，可以使用任何小工具来**访问全局对象**，来自[**绕过 Python 沙箱页面**](bypass-python-sandboxes/)。

在**漏洞位于不同的 Python 文件**的情况下，您需要一个小工具来遍历文件，以便到达主文件以**访问全局对象 `app.secret_key`**，以更改 Flask 秘钥并能够[**提升权限**，知道这个密钥](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)。

像这样的有效载荷[来自这篇文章](https://ctftime.org/writeup/36082)：
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
使用此有效载荷来**更改 `app.secret_key`**（您应用中的名称可能不同），以便能够签署新的和更高级的 Flask cookies。

### Werkzeug - machine_id 和 node uuid

[**使用此写作中的有效载荷**](https://vozec.fr/writeups/tweedle-dum-dee/)，您将能够访问**machine_id**和**uuid**节点，这些是您需要的**主要秘密**，以[**生成 Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md)，您可以在**调试模式启用时**使用它来访问 `/console` 中的 Python 控制台：
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> 请注意，您可以通过在网页上生成一些**错误**来获取**服务器本地路径到 `app.py`**，这将**给您路径**。

如果漏洞在另一个python文件中，请检查之前的Flask技巧以访问主python文件中的对象。

{{#include ../../banners/hacktricks-training.md}}
