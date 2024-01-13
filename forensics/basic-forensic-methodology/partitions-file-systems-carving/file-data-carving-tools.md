<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>


# Carvingツール

## Autopsy

フォレンジックで画像からファイルを抽出するために最も一般的に使用されるツールは[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、"隠された"ファイルを見つけるためにファイルを取り込んでください。Autopsyはディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルはサポートしていません。

## Binwalk <a id="binwalk"></a>

**Binwalk**は、埋め込まれたファイルやデータを検索するためのバイナリファイル（画像やオーディオファイルなど）用のツールです。
`apt`でインストールできますが、[ソース](https://github.com/ReFirmLabs/binwalk)はGitHubで見つけることができます。
**役立つコマンド**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

隠されたファイルを見つけるための一般的なツールは**foremost**です。foremostの設定ファイルは`/etc/foremost.conf`にあります。特定のファイルだけを検索したい場合は、それらのコメントを外してください。何もコメントを外さない場合、foremostはデフォルトで設定されているファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** は、**ファイルに埋め込まれたファイル**を見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプに応じて、設定ファイル（_/etc/scalpel/scalpel.conf_）からコメントを外す必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

このツールはKaliに含まれていますが、こちらで見つけることができます: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

このツールはイメージをスキャンし、内部の**pcapsを抽出**し、**ネットワーク情報\(URL、ドメイン、IP、MAC、メール\)** などの**ファイル**を抽出します。次の操作をするだけです:
```text
bulk_extractor memory.img -o out_folder
```
ツールが収集した**すべての情報**をナビゲートし（パスワード？）、**パケット**を**分析**します（[**Pcaps分析**](../pcap-inspection/)を読む）、**奇妙なドメイン**を探します（**マルウェア**に関連するドメインや**存在しない**ドメイン）。

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)で見つけることができます。

GUIとCLIバージョンがあります。PhotoRecに検索させたい**ファイルタイプ**を選択できます。

![](../../../.gitbook/assets/image%20%28524%29.png)

# 特定のデータカービングツール

## FindAES

AESキーをそのキースケジュールを検索することで探します。TrueCryptやBitLockerなどに使用される128、192、256ビットキーを見つけることができます。

[こちら](https://sourceforge.net/projects/findaes/)からダウンロードしてください。

# 補助ツール

[**viu**](https://github.com/atanunq/viu)を使用して、ターミナルから画像を表示することができます。
Linuxコマンドラインツールの**pdftotext**を使用して、PDFをテキストに変換し、読むことができます。



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
