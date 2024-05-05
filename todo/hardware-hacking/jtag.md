# JTAG

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **Discordグループ**に参加する 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) または [**telegram group**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローする。**
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)は、Raspberry PIまたはArduinoと組み合わせて使用できるツールで、不明なチップからJTAGピンを見つけるために使用できます。\
**Arduino**では、**2から11のピンをJTAGに属する可能性のある10ピンに接続**します。Arduinoにプログラムをロードし、すべてのピンをブルートフォースして、JTAGに属するピンがあるかどれがそれかを見つけようとします。\
**Raspberry PI**では、**1から6のピン**（6ピン）しか使用できないため、各潜在的なJTAGピンをテストするのに時間がかかります。

### Arduino

Arduinoでは、ケーブルを接続した後（ピン2から11をJTAGピンに、Arduino GNDをベースボードGNDに接続）、ArduinoにJTAGenumプログラムをロードし、シリアルモニターで**`h`**（ヘルプコマンド）を送信して、ヘルプが表示されるはずです：

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

**「行末なし」および115200ボー**ドで構成します。\
スキャンを開始するには、コマンドsを送信します：

![](<../../.gitbook/assets/image (774).png>)

JTAGに接続している場合、JTAGのピンを示す**FOUND!**で始まる1つまたは複数の行が見つかります。
