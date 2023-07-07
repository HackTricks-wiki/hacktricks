# Python内部の読み取りガジェット

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

[**Pythonフォーマット文字列**](bypass-python-sandboxes/#python-format-string)や[**クラスの汚染**](class-pollution-pythons-prototype-pollution.md)などのさまざまな脆弱性は、**Pythonの内部データを読み取ることはできますが、コードの実行は許可されません**。したがって、ペンテスターはこれらの読み取り権限を最大限に活用して、**機密特権を取得し、脆弱性をエスカレーション**させる必要があります。

### Flask - シークレットキーの読み取り

Flaskアプリケーションのメインページにはおそらく**`app`**というグローバルオブジェクトがあり、この**シークレットが設定**されています。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
この場合、[**Pythonサンドボックス回避ページ**](bypass-python-sandboxes/)から**グローバルオブジェクトにアクセスする**ためのガジェットを使用して、このオブジェクトにアクセスすることが可能です。

もし**脆弱性が別のPythonファイルにある場合**、メインのファイルにたどり着くためのガジェットが必要です。これにより、Flaskのシークレットキーを変更して、[**このキーを知ることで特権を昇格**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)することができます。

このようなペイロードは、[この解説記事](https://ctftime.org/writeup/36082)から取得できます：

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

このペイロードを使用して、`app.secret_key`（アプリ内の名前は異なる場合があります）を変更し、新しい特権を持つflaskクッキーに署名できるようにします。

### Werkzeug - machine\_id と node uuid

[**この解説からのペイロードを使用すると**](https://vozec.fr/writeups/tweedle-dum-dee/)、**machine\_id** と **uuid** ノードにアクセスできるようになります。これらは、[**Werkzeugピンを生成するために必要な主要な秘密**](../../network-services-pentesting/pentesting-web/werkzeug.md)です。デバッグモードが有効な場合、`/console` でPythonコンソールにアクセスするために使用できます。
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
`app.py`への**サーバーのローカルパス**を取得するには、ウェブページでいくつかの**エラー**を生成し、それによって**パスを取得**することができます。
{% endhint %}

もし脆弱性が別のPythonファイルにある場合は、メインのPythonファイルからオブジェクトにアクセスするための前のFlaskのトリックをチェックしてください。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
