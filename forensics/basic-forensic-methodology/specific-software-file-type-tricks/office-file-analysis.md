# オフィスファイルの分析

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

- **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** または [telegramグループ](https://t.me/peass) に **参加** または **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live) を **フォロー** してください。
- **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) を使用して、世界で最も高度なコミュニティツールによって強化された **ワークフローを簡単に構築** および **自動化** できます。\
今すぐアクセスを取得:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

**詳細については [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) をチェックしてください**

Microsoft は多くのオフィス文書形式を作成しており、主なタイプは **OLE形式**（RTF、DOC、XLS、PPTなど）と **Office Open XML（OOXML）形式**（DOCX、XLSX、PPTXなど）です。これらの形式にはマクロが含まれることがあり、それによりフィッシングやマルウェアの標的となります。OOXMLファイルはzipコンテナとして構造化されており、解凍してファイルとフォルダの階層、XMLファイルの内容を表示できます。

OOXMLファイル構造を探るために、ドキュメントを解凍するコマンドと出力構造が提供されています。これらのファイルにデータを隠す技術が文書化されており、CTFチャレンジ内でのデータの隠蔽に関する革新が続いています。

分析のために、**oletools** と **OfficeDissector** は、OLEおよびOOXMLドキュメントを調査するための包括的なツールセットを提供しています。これらのツールは、埋め込まれたマクロを特定し分析するのに役立ちます。これらのマクロはしばしばマルウェアの配信ベクトルとして機能し、通常は追加の悪意のあるペイロードをダウンロードして実行します。VBAマクロの分析は、Libre Officeを使用してMicrosoft Officeなしで行うことができ、ブレークポイントとウォッチ変数でデバッグが可能です。

**oletools** のインストールと使用は簡単で、pipを使用してインストールするコマンドが提供されています。`AutoOpen`、`AutoExec`、または `Document_Open` などの関数によって、マクロの自動実行がトリガーされます。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
