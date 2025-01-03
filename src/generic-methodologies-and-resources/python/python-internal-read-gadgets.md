# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

[**Pythonフォーマット文字列**](bypass-python-sandboxes/#python-format-string)や[**クラス汚染**](class-pollution-pythons-prototype-pollution.md)などの異なる脆弱性は、**Python内部データを読み取ることはできるが、コードを実行することはできない**かもしれません。したがって、ペンテスターはこれらの読み取り権限を最大限に活用して、**機密特権を取得し、脆弱性をエスカレートさせる**必要があります。

### Flask - 秘密鍵の読み取り

Flaskアプリケーションのメインページには、**`app`**グローバルオブジェクトがあり、ここでこの**秘密が設定されています**。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
この場合、[**Pythonサンドボックスをバイパスするページ**](bypass-python-sandboxes/)から**グローバルオブジェクトにアクセス**するために、任意のガジェットを使用してこのオブジェクトにアクセスすることが可能です。

**脆弱性が異なるPythonファイルにある場合**、メインのファイルに到達するためにファイルを横断するガジェットが必要で、**グローバルオブジェクト `app.secret_key`** にアクセスしてFlaskの秘密鍵を変更し、この鍵を知って[**権限を昇格させる**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)ことができます。

このようなペイロードは、[この解説から](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
このペイロードを使用して、**`app.secret_key`**（あなたのアプリでは名前が異なる場合があります）を変更し、新しいより多くの権限を持つフラスククッキーに署名できるようにします。

### Werkzeug - machine_id と node uuid

[**この書き込みからのペイロードを使用することで**](https://vozec.fr/writeups/tweedle-dum-dee/)、**machine_id** と **uuid** ノードにアクセスでき、これらは **主な秘密** であり、[**Werkzeug pin を生成するために必要です**](../../network-services-pentesting/pentesting-web/werkzeug.md)。これを使用して、**デバッグモードが有効な場合**に `/console` で Python コンソールにアクセスできます。
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> **app.py**の**サーバーのローカルパス**を取得するには、ウェブページでいくつかの**エラー**を生成する必要があります。これにより、**パス**が得られます。

脆弱性が別のPythonファイルにある場合は、メインPythonファイルからオブジェクトにアクセスするための前のFlaskトリックを確認してください。

{{#include ../../banners/hacktricks-training.md}}
