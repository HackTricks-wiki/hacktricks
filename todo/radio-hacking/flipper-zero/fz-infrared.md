# FZ - 赤外線

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## イントロ <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

赤外線の動作についての詳細は、次を参照してください：

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zeroの赤外線信号受信機能 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipperは、IRリモコンからの信号を傍受することができるデジタルIR信号受信機TSOPを使用しています。Xiaomiなどの一部の**スマートフォン**にもIRポートがありますが、**ほとんどのスマートフォンは送信のみ**であり、受信はできません。

Flipperの赤外線受信機能は非常に感度が高いです。リモコンとテレビの間のどこかにいながら、信号を**キャッチ**することができます。FlipperのIRポートにリモコンを直接向ける必要はありません。これは、誰かがテレビの近くでチャンネルを切り替えているときに便利です。あなたとFlipperはお互いに離れている場合でも、信号をキャッチすることができます。

赤外線のデコードはソフトウェア側で行われるため、Flipper Zeroは原則として**任意のIRリモコンコードの受信と送信**をサポートしています。認識できないプロトコルの場合は、受信した生の信号を**記録して再生**します。

## アクション

### ユニバーサルリモコン

Flipper Zeroは、**どのテレビ、エアコン、メディアセンター**でも使用できるユニバーサルリモコンとして使用することができます。このモードでは、FlipperはSDカードの辞書に基づいて、すべてのサポートされているメーカーの**すべての既知のコードをブルートフォース**します。特定のリモコンを選ぶ必要はありません。

ユニバーサルリモコンモードで電源ボタンを押すだけで、Flipperは知っているすべてのテレビ（Sony、Samsung、Panasonicなど）に「電源オフ」コマンドを順番に送信します。テレビが信号を受け取ると、反応して電源が切れます。

このようなブルートフォースには時間がかかります。辞書が大きいほど、終了するまでに時間がかかります。テレビが正確にどの信号を認識したかはわかりません。テレビからのフィードバックはありません。

### 新しいリモコンの学習

Flipper Zeroで赤外線信号を**キャプチャ**することができます。Flipperがデータベースで信号を**見つけると、どのデバイスかを自動的に知り**、それとやり取りすることができます。\
見つからない場合、Flipperは信号を**保存**し、再生することができます。

## 参考文献

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
