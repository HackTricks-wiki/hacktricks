<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**する
* **ハッキングトリックを共有するためにPRを送信して** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて修正を迅速化します。Intruder は攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今すぐ。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Carving & Recovery tools

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)にさらに多くのツールがあります

## Autopsy

イメージからファイルを抽出するために最も一般的に使用されるツールは [**Autopsy**](https://www.autopsy.com/download/) です。ダウンロードしてインストールし、ファイルを取り込んで「隠れた」ファイルを見つけるようにします。Autopsy はディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルはサポートしていません。

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** はバイナリファイルを分析して埋め込まれたコンテンツを見つけるためのツールです。`apt` を介してインストール可能で、そのソースは [GitHub](https://github.com/ReFirmLabs/binwalk) にあります。

**便利なコマンド**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

もう1つの一般的な隠しファイルを見つけるためのツールは **foremost** です。 foremost の設定ファイルは `/etc/foremost.conf` にあります。特定のファイルを検索したい場合は、それらのコメントを外してください。何もコメントアウトしない場合、foremost はデフォルトで構成されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**は、ファイルに埋め込まれたファイルを見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプを構成ファイル（_/etc/scalpel/scalpel.conf_）からコメントアウトする必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

このツールはKaliに含まれていますが、こちらで見つけることができます: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

このツールは画像をスキャンし、その中から**pcapsを抽出**し、**ネットワーク情報（URL、ドメイン、IP、MAC、メール）**や他の**ファイル**を取得することができます。行う必要があるのは次の通りです:
```
bulk_extractor memory.img -o out_folder
```
**ツール**が収集した**すべての情報**（パスワード？）を調査し、**パケット**を分析し、**奇妙なドメイン**（マルウェアや存在しないドメインに関連するドメイン）を検索します。

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download) で見つけることができます。

GUI バージョンと CLI バージョンがあります。PhotoRec が検索する**ファイルタイプ**を選択できます。

![](<../../../.gitbook/assets/image (524).png>)

## binvis

[コード](https://code.google.com/archive/p/binvis/)と[ウェブページツール](https://binvis.io/#/)をチェックしてください。

### BinVis の機能

* 視覚的でアクティブな**構造ビューア**
* 異なる焦点点のための複数のプロット
* サンプルの一部に焦点を当てる
* PE や ELF 実行可能ファイルで**文字列やリソース**を見る
* ファイルの暗号解読のための**パターン**を取得
* パッカーやエンコーダーアルゴリズムを**特定**
* パターンによるステガノグラフィの**識別**
* **ビジュアル**バイナリ差分

BinVis は、ブラックボックスシナリオで未知のターゲットに慣れるための素晴らしい**スタートポイント**です。

# 特定のデータカービングツール

## FindAES

TrueCrypt や BitLocker で使用されるような 128、192、256 ビットの鍵を見つけるために、鍵スケジュールを検索することで AES 鍵を検索します。

[こちら](https://sourceforge.net/projects/findaes/)からダウンロードできます。

# 補足ツール

ターミナルから画像を表示するために [**viu** ](https://github.com/atanunq/viu)を使用できます。\
PDF をテキストに変換して読むために Linux コマンドラインツール **pdftotext** を使用できます。

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて修正を迅速化します。Intruder は攻撃面を追跡し、積極的な脅威スキャンを実行し、API から Web アプリケーション、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今すぐ。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法：

* **HackTricks で企業を宣伝**したり、**PDF で HackTricks をダウンロード**したりするには、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
* 独占的な[NFT](https://opensea.io/collection/the-peass-family)コレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)や[**telegram グループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)の GitHub リポジトリに PR を提出して、あなたのハッキングトリックを共有してください。

</details>
