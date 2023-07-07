# その他のウェブトリック

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **ハッキングのトリックを共有する**には、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

### ホストヘッダー

バックエンドは、何らかのアクションを実行するために**ホストヘッダー**を信頼することがあります。たとえば、**パスワードリセットの送信先ドメイン**としてその値を使用することがあります。したがって、パスワードをリセットするためのリンクが含まれたメールを受け取った場合、使用されているドメインはホストヘッダーに入力したものです。そのため、他のユーザーのパスワードリセットをリクエストし、ドメインを自分が制御するドメインに変更して、彼らのパスワードリセットコードを盗むことができます。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)。

{% hint style="warning" %}
ユーザーがリセットパスワードリンクをクリックするのを待つ必要はないかもしれません。**スパムフィルターや他の中間デバイス/ボットがリンクをクリックして分析する**可能性があります。
{% endhint %}

### セッションブール値

バックエンドがいくつかの検証を正しく完了すると、セッションに**値が「True」のブール値をセキュリティ属性として追加**することがあります。その後、別のエンドポイントは、そのチェックに成功したかどうかを知ることができます。\
ただし、チェックに合格し、セッションがセキュリティ属性に「True」の値を持つ場合、**アクセス権を持っていないはずの同じ属性に依存する他のリソースにアクセス**を試みることができます。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)。

### 登録機能

既に存在するユーザーとして登録してみてください。また、同等の文字（ドット、多くのスペース、Unicode）を使用してみてください。

### メールの乗っ取り

メールを登録し、確認する前にメールを変更してください。その後、新しい確認メールが最初に登録したメールに送信される場合、任意のメールを乗っ取ることができます。または、最初のメールを有効にすることができれば、2番目のメールを確認して任意のアカウントを乗っ取ることもできます。

### Atlassianを使用した企業の内部サービスデスクへのアクセス

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACEメソッド

開発者は、本番環境でさまざまなデバッグオプションを無効にするのを忘れることがあります。たとえば、HTTPの`TRACE`メソッドは診断目的で設計されています。有効になっている場合、Webサーバーは`TRACE`メソッドを使用するリクエストに対して、受信した正確なリクエストをレスポンスでエコーします。この動作は通常無害ですが、場合によっては、リバースプロキシによってリクエストに追加される内部認証ヘッダーの名前など、情報の漏洩につながることがあります。![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **ハッキングのトリックを共有する**には、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlo
