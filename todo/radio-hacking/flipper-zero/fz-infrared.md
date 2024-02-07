# FZ - 赤外線

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか、または**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけます
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れます
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**します。
* **ハッキングトリックを共有するには、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)**と**[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出**してください。

</details>

## イントロ <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

赤外線の動作についての詳細は、以下をチェックしてください：

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zeroの赤外線信号受信機能 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipperはデジタル赤外線信号受信機TSOPを使用しており、**IRリモコンからの信号を傍受**することができます。Xiaomiなどの**一部のスマートフォン**にはIRポートが搭載されていますが、**ほとんどは送信のみ**であり、**受信はできません**。

Flipperの赤外線**受信機能は非常に敏感**です。TVとリモコンの間の**どこかにいる**状態でも信号を**キャッチ**することができます。FlipperのIRポートにリモコンを直接向ける必要はありません。これは、誰かがTVの近くでチャンネルを切り替えているときに便利です。あなたとFlipperが離れた場所にいる場合でも、信号を受信できます。

赤外線の**デコード**は**ソフトウェア**側で行われるため、Flipper Zeroは潜在的に**任意のIRリモコンコードの受信と送信**をサポートします。**認識できない**プロトコルの場合、受信したままの生の信号を**記録して再生**します。

## アクション

### ユニバーサルリモコン

Flipper Zeroは、**どんなTV、エアコン、メディアセンターでも制御するためのユニバーサルリモコン**として使用できます。このモードでは、FlipperはSDカードからの辞書に従って、すべてのサポートされているメーカーの**すべての既知のコードをブルートフォース**します。特定のリモコンを選択してレストランのTVの電源を切る必要はありません。

ユニバーサルリモコンモードで電源ボタンを押すだけで、Flipperは知っているすべてのTV（Sony、Samsung、Panasonicなど）に「電源オフ」コマンドを順次送信します。TVがその信号を受信すると、反応して電源が切れます。

このようなブルートフォースには時間がかかります。辞書が大きいほど、終了するのに時間がかかります。TVが正確にどの信号を認識したかを特定することは不可能です。TVからのフィードバックがないためです。

### 新しいリモコンの学習

Flipper Zeroで赤外線信号を**キャプチャ**することが可能です。Flipperがデータベースで信号を**見つけると**、自動的に**どのデバイスかを知り**、それとやり取りできるようにします。\
見つからない場合、Flipperは**信号を保存**し、**再生**することができます。

## 参考文献

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
