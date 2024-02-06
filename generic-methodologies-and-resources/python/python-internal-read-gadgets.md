# Python Internal Read Gadgets

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

- **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする
- **ハッキングトリックを共有するには、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## 基本情報

[**Python Format Strings**](bypass-python-sandboxes/#python-format-string)や[**Class Pollution**](class-pollution-pythons-prototype-pollution.md)などのさまざまな脆弱性は、**Python内部データを読み取ることを可能にするが、コードの実行は許可しない**かもしれません。したがって、ペンテスターはこれらの読み取り権限を最大限に活用して、**機密特権を取得し脆弱性をエスカレート**する必要があります。

### Flask - シークレットキーの読み取り

Flaskアプリケーションのメインページにはおそらく**`app`**グローバルオブジェクトがあり、ここに**シークレットが設定されている**でしょう。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
この場合、[**Pythonサンドボックス回避ページ**](bypass-python-sandboxes/)から**グローバルオブジェクトにアクセス**するためのガジェットを使用してこのオブジェクトにアクセスすることが可能です。

**脆弱性が別のPythonファイルにある場合**、メインのファイルにアクセスするためのガジェットが必要で、Flaskのシークレットキーを変更して[**このキーを知って特権を昇格**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)するために**グローバルオブジェクト `app.secret_key` にアクセス**する必要があります。

[この解説](https://ctftime.org/writeup/36082)からのこのようなペイロード：

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

このペイロードを使用して、`app.secret_key`（アプリ内の名前が異なる場合があります）を変更し、新しい特権を持つflaskクッキーに署名できるようにします。

### Werkzeug - machine\_id と node uuid

[**この解説からのペイロードを使用すると**](https://vozec.fr/writeups/tweedle-dum-dee/)、**machine\_id** と **uuid** ノードにアクセスできるようになります。これらは、[**Werkzeugピンを生成するために必要な主要な秘密**](../../network-services-pentesting/pentesting-web/werkzeug.md)であり、**デバッグモードが有効**の場合に `/console` でPythonコンソールにアクセスするために使用できます。
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
**`app.py`**への**サーバーのローカルパス**を取得するには、ウェブページで**エラー**を発生させることで、**パスを取得**できます。
{% endhint %}

もし脆弱性が別のPythonファイルにある場合は、メインのPythonファイルからオブジェクトにアクセスするFlaskの以前のトリックをチェックしてください。

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**Telegramグループ**](https://t.me/peass)に**参加**したり、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)で**フォロー**してください。
* **ハッキングトリックを共有するために、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
