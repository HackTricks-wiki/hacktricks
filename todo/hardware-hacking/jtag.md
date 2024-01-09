<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>


# JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum)は、未知のチップからJTAGピンを試すためにRaspberry PIまたはArduinoで使用できるツールです。\
**Arduino**では、**2番から11番のピンをJTAGに属する可能性のある10ピンに接続します**。Arduinoにプログラムをロードすると、すべてのピンをブルートフォースして、JTAGに属するピンがあるかどうか、そしてそれぞれがどれであるかを見つけます。\
**Raspberry PI**では、**1番から6番のピンのみ使用できます**（6ピンなので、潜在的なJTAGピンをテストするのに時間がかかります）。

## Arduino

Arduinoでは、ケーブルを接続した後（2番から11番のピンをJTAGピンに、Arduino GNDをベースボードGNDに接続）、**ArduinoにJTAGenumプログラムをロード**し、シリアルモニターで**`h`**（ヘルプのためのコマンド）を送信すると、ヘルプが表示されます：

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

**"No line ending"と115200baudを設定します**。\
スキャンを開始するためにコマンドsを送信します：

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

JTAGに接触している場合、JTAGのピンを示す**FOUND!で始まる一行または複数の行**が見つかります。


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
