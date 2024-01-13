<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正しましょう。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまで、テックスタック全体にわたる問題を見つけます。今日[**無料でお試し**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)ください。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Carving & Recovery tools

より多くのツールは[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)で見つけることができます。

## Autopsy

フォレンジックで画像からファイルを抽出するために最も一般的に使用されるツールは[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、"隠された"ファイルを見つけるためにファイルを取り込ませます。Autopsyはディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルはサポートしていないことに注意してください。

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**は、埋め込まれたファイルやデータを検索するためのバイナリファイル（画像やオーディオファイルなど）用のツールです。
`apt`でインストールすることができますが、[ソース](https://github.com/ReFirmLabs/binwalk)はgithubで見つけることができます。
**便利なコマンド**：
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

隠されたファイルを見つけるための一般的なツールは**foremost**です。foremostの設定ファイルは`/etc/foremost.conf`にあります。特定のファイルだけを検索したい場合は、それらのコメントを外してください。何もコメントを外さない場合、foremostはデフォルトで設定されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** は、**ファイルに埋め込まれたファイル**を見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプに応じて、設定ファイル (_/etc/scalpel/scalpel.conf_) からコメントアウトを解除する必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

このツールはKaliに含まれていますが、こちらで見つけることができます: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

このツールはイメージをスキャンし、内部の**pcapsを抽出**し、**ネットワーク情報（URL、ドメイン、IP、MAC、メール）**などの**ファイル**を抽出します。次の操作をするだけです:
```
bulk_extractor memory.img -o out_folder
```
ツールが収集した**すべての情報**をナビゲートし（パスワード？）、**パケット**を**分析**します（[**Pcaps分析**](../pcap-inspection/)を読む）、**奇妙なドメイン**を探します（**マルウェア**に関連するドメインや**存在しない**ドメイン）。

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)で見つけることができます。

GUIとCLIのバージョンがあります。PhotoRecに検索してほしい**ファイルタイプ**を選択できます。

![](<../../../.gitbook/assets/image (524).png>)

## binvis

[コード](https://code.google.com/archive/p/binvis/)と[ウェブページツール](https://binvis.io/#/)をチェックしてください。

### BinVisの特徴

* 視覚的でアクティブな**構造ビューア**
* 異なる焦点に対する複数のプロット
* サンプルの一部に焦点を当てる
* PEやELF実行ファイルなどでの**文字列やリソースの表示**
* ファイルに対する暗号解析のための**パターン**の取得
* パッカーやエンコーダーアルゴリズムの**特定**
* パターンによるステガノグラフィーの**識別**
* **視覚的**なバイナリ差分

BinVisは、ブラックボックスシナリオで未知のターゲットに慣れるための素晴らしい**出発点**です。

# 特定のデータカービングツール

## FindAES

AESキーをそのキースケジュールを検索することで探します。TrueCryptやBitLockerで使用される128、192、256ビットキーを見つけることができます。

[こちら](https://sourceforge.net/projects/findaes/)からダウンロードしてください。

# 補完ツール

ターミナルから画像を見るために[**viu**](https://github.com/atanunq/viu)を使用できます。
Linuxコマンドラインツール**pdftotext**を使用して、PDFをテキストに変換し、読むことができます。

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正できるようにします。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまで、テックスタック全体にわたる問題を見つけます。今日[**無料でお試し**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)ください。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
