# macOS 防御アプリ

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## ファイアウォール

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 各プロセスが行うすべての接続を監視します。モードによって（接続を許可する、接続を拒否する、アラート）、新しい接続が確立されるたびに**アラートを表示**します。また、この情報を表示するための非常に素敵なGUIも備えています。
* [**LuLu**](https://objective-see.org/products/lulu.html): Objective-Seeファイアウォール。これは基本的なファイアウォールで、**疑わしい接続に対してアラートを表示**します（GUIはLittle Snitchのものほど洗練されていません）。

## 持続性の検出

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-Seeアプリケーションで、**マルウェアが持続する可能性のある**複数の場所を検索します（ワンショットツールであり、監視サービスではありません）。
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): KnockKnockと同様に、持続性を生成するプロセスを監視します。

## キーロガーの検出

* [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-Seeアプリケーションで、キーボードの「イベントタップ」をインストールする**キーロガー**を検出します。

## ランサムウェアの検出

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html): Objective-Seeアプリケーションで、**ファイルの暗号化**アクションを検出します。

## マイクとウェブカメラの検出

* [**OverSight**](https://objective-see.org/products/oversight.html): Objective-Seeアプリケーションで、**ウェブカメラとマイクを使用し始めるアプリケーション**を検出します。

## プロセスインジェクションの検出

* [**Shield**](https://theevilbit.github.io/shield/): 異なるプロセスインジェクションの**検出**技術を備えたアプリケーション。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
