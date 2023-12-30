# Python Internal Read Gadgets

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## 基本情報

[**Python Format Strings**](bypass-python-sandboxes/#python-format-string)や[**Class Pollution**](class-pollution-pythons-prototype-pollution.md)などのさまざまな脆弱性により、**Pythonの内部データを読み取ることができるが、コードを実行することはできない**場合があります。したがって、ペネトレーションテスターは、これらの読み取り権限を最大限に活用して、**機密特権を取得し、脆弱性をエスカレートする**必要があります。

### Flask - シークレットキーの読み取り

Flaskアプリケーションのメインページには、この**シークレットが設定されている** **`app`** グローバルオブジェクトがおそらく存在します。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
この場合、[**Bypass Python sandboxes page**](bypass-python-sandboxes/)から**グローバルオブジェクトにアクセスする**ための任意のガジェットを使用して、このオブジェクトにアクセスすることが可能です。

**異なるPythonファイルに脆弱性がある場合**は、メインのファイルにたどり着き**グローバルオブジェクト`app.secret_key`にアクセスして**Flaskのシークレットキーを変更し、このキーを知ることで[**権限昇格を図る**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)ことができるようにするためのガジェットが必要です。

以下のようなペイロード[このライトアップから](https://ctftime.org/writeup/36082)：

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

このペイロードを使用して、`app.secret_key`を変更します（アプリ内の名前は異なる場合があります）。これにより、新しく、より多くの権限を持つflaskクッキーを署名することができます。

### Werkzeug - machine\_id と node uuid

[**このライトアップからのペイロードを使用することで**](https://vozec.fr/writeups/tweedle-dum-dee/)、**machine\_id** と **uuid** ノードにアクセスできます。これらは、[**Werkzeugピンを生成する**](../../network-services-pentesting/pentesting-web/werkzeug.md)ために必要な**主要なシークレット**です。**デバッグモードが有効になっている場合**、`/console`でpythonコンソールにアクセスするために使用できます。
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
**`app.py`のサーバーローカルパス**を取得するには、ウェブページで**エラー**を発生させ、それによって**パスを教えてもらう**ことができます。
{% endhint %}

異なるPythonファイルに脆弱性がある場合は、メインPythonファイルからオブジェクトにアクセスするための前述のFlaskのトリックを確認してください。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
