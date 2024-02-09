# FZ - 赤外線

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私をフォローする 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングトリックを共有するには、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

## イントロ <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

赤外線の動作についての詳細は、以下をチェックしてください：

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zeroの赤外線信号受信機能 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipperはデジタル赤外線信号受信機TSOPを使用しており、**IRリモコンからの信号を傍受**することができます。 Xiaomiなどの**一部のスマートフォン**にはIRポートが搭載されていますが、**ほとんどの場合送信のみ**であり、**受信はできません**。

Flipperの赤外線受信機能は**非常に感度が高い**です。リモコンとTVの間の**どこかにいる**状態でも信号を**キャッチ**することができます。リモコンをFlipperのIRポートに直接向ける必要はありません。これは、誰かがTVの近くでチャンネルを切り替えているときに便利です。あなたとFlipperが離れた場所にいる場合でも、信号をキャッチできます。

赤外線信号の**デコード**は**ソフトウェア側で行われる**ため、Flipper Zeroは潜在的に**任意のIRリモコンコードの受信と送信**をサポートしています。**認識できない**プロトコルの場合、受信したままの生の信号を**記録して再生**します。

## アクション

### ユニバーサルリモコン

Flipper Zeroは、**どんなTV、エアコン、メディアセンターでも制御するためのユニバーサルリモコン**として使用できます。このモードでは、FlipperはSDカードからの辞書に従って、すべてのサポートされているメーカーの**すべての既知のコードをブルートフォース**します。特定のリモコンを選択してレストランのTVの電源を切る必要はありません。

ユニバーサルリモコンモードで電源ボタンを押すだけで、Flipperは知っているすべてのTV（Sony、Samsung、Panasonicなど）に「電源オフ」コマンドを順次送信します。 TVがその信号を受信すると、反応して電源が切れます。

このようなブルートフォースには時間がかかります。辞書が大きいほど、終了するのに時間がかかります。 TVが正確にどの信号を認識したかを特定することは不可能です。 TVからのフィードバックがないためです。

### 新しいリモコンの学習

Flipper Zeroで赤外線信号を**キャプチャ**することが可能です。Flipperがデータベースで信号を**見つけると、自動的にどのデバイスかを知り**、それとやり取りすることができます。\
見つからない場合、Flipperは**信号を保存**し、**再生**することができます。

## 参考文献

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
