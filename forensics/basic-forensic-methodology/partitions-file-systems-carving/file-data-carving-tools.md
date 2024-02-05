<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする
* **ハッキングトリックを共有するためにPRを提出して** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリに

</details>


# Carving tools

## Autopsy

ファイルを抽出するためにフォレンジックで最も一般的に使用されるツールは[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、ファイルを取り込んで「隠れた」ファイルを見つけるようにします。Autopsy はディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していません。

## Binwalk <a id="binwalk"></a>

**Binwalk** は画像や音声ファイルなどのバイナリファイルを検索して埋め込まれたファイルやデータを見つけるためのツールです。
`apt` を使用してインストールできますが、[ソース](https://github.com/ReFirmLabs/binwalk)はgithubで見つけることができます。
**便利なコマンド**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

もう1つの一般的な隠しファイルを見つけるためのツールは**foremost**です。 foremostの設定ファイルは`/etc/foremost.conf`にあります。特定のファイルを検索したい場合は、それらのコメントを外してください。何もコメントアウトしない場合、foremostはデフォルトで構成されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**は、ファイルに埋め込まれたファイルを見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプを設定ファイル（_/etc/scalpel/scalpel.conf_）からコメントアウトする必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

このツールはKaliに含まれていますが、こちらで見つけることができます: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

このツールは画像をスキャンし、その中から**pcapsを抽出**し、**ネットワーク情報（URL、ドメイン、IP、MAC、メール）**や他の**ファイル**を抽出することができます。行う必要があるのは以下の通りです:
```text
bulk_extractor memory.img -o out_folder
```
**すべての情報**をツールが収集したものをナビゲートし（パスワード？）、**パケット**を**分析**し（[**Pcaps分析**](../pcap-inspection/)を参照）、**異常なドメイン**（**マルウェア**や**存在しない**ドメインに関連するドメイン）を検索します。

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) で見つけることができます。

GUIバージョンとCLIバージョンが付属しています。PhotoRecが検索する**ファイルタイプ**を選択できます。

![](../../../.gitbook/assets/image%20%28524%29.png)

# 特定のデータカービングツール

## FindAES

キースケジュールを検索してAESキーを検索します。TrueCryptやBitLockerで使用される128、192、256ビットのキーなどを見つけることができます。

[こちら](https://sourceforge.net/projects/findaes/)からダウンロードできます。

# 補足ツール

[**viu** ](https://github.com/atanunq/viu)を使用してターミナルから画像を表示できます。
Linuxコマンドラインツール**pdftotext**を使用して、pdfをテキストに変換して読むことができます。
