<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。

</details>


# JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)は、Raspberry PIまたはArduinoと組み合わせて未知のチップからJTAGピンを見つけるために使用できるツールです。\
**Arduino**では、**2から11のピンをJTAGに属する可能性のある10ピンに接続**します。Arduinoにプログラムをロードし、すべてのピンをブルートフォースしてJTAGに属するかどうかを見つけます。\
**Raspberry PI**では、**1から6のピン**のみを使用できます（6つのピンなので、各潜在的なJTAGピンをテストするのに時間がかかります）。

## Arduino

Arduinoでは、ケーブルを接続した後（ピン2から11をJTAGピンに、Arduino GNDをベースボードGNDに接続）、ArduinoにJTAGenumプログラムをロードし、シリアルモニターに**`h`**（ヘルプコマンド）を送信してヘルプを表示する必要があります：

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

**「行末なし」と115200ボー**ドで構成します。\
スキャンを開始するには、コマンドsを送信します：

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

JTAGに接続している場合、JTAGのピンを示す**FOUND!**で始まる1つまたは複数の行が見つかります。


<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。

</details>
