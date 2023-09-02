<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて修正できるようにしましょう。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Carving & Recovery tools

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)にはさらに多くのツールがあります。

## Autopsy

イメージからファイルを抽出するために最も一般的に使用されるツールは[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、ファイルを取り込んで「隠れた」ファイルを見つけるように設定します。ただし、Autopsyはディスクイメージやその他のイメージをサポートするように構築されていますが、単純なファイルには対応していません。

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**は、画像や音声ファイルなどのバイナリファイルを検索して埋め込まれたファイルやデータを見つけるためのツールです。\
`apt`を使用してインストールすることができますが、[ソース](https://github.com/ReFirmLabs/binwalk)はgithubで見つけることができます。\
**便利なコマンド**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

もう一つの隠れたファイルを見つけるための一般的なツールは**foremost**です。`/etc/foremost.conf`にforemostの設定ファイルがあります。特定のファイルを検索したい場合は、コメントを外してください。何もコメントを外さない場合、foremostはデフォルトで設定されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**は、ファイルに埋め込まれたファイルを見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルの種類を設定ファイル（_/etc/scalpel/scalpel.conf_）からコメントアウトする必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

このツールはKaliに含まれていますが、ここから入手することもできます：[https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

このツールはイメージをスキャンし、**pcapファイル**、**ネットワーク情報（URL、ドメイン、IP、MAC、メール）**、およびその他の**ファイル**を抽出することができます。以下の手順を実行するだけです：
```
bulk_extractor memory.img -o out_folder
```
ツールが収集した**すべての情報**（パスワード？）を調査し、**パケット**を分析します（[**Pcaps解析**](../pcap-inspection/)を参照）。**異常なドメイン**（マルウェアや存在しないドメインに関連するドメイン）を検索します。

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)で入手できます。

GUIとCLIのバージョンがあります。PhotoRecが検索する**ファイルタイプ**を選択できます。

![](<../../../.gitbook/assets/image (524).png>)

## binvis

[コード](https://code.google.com/archive/p/binvis/)と[ウェブページツール](https://binvis.io/#/)を確認してください。

### BinVisの特徴

* 視覚的でアクティブな**構造ビューア**
* 異なる焦点ポイントのための複数のプロット
* サンプルの一部に焦点を当てる
* PEやELF実行可能ファイルなどの**文字列とリソース**を表示
* ファイルの暗号解析のための**パターン**の取得
* パッカーやエンコーダのアルゴリズムを**特定**
* パターンによるステガノグラフィの**識別**
* **ビジュアル**バイナリ差分

BinVisは、ブラックボックスシナリオで未知のターゲットに慣れるための素晴らしい**スタートポイント**です。

# 特定のデータカービングツール

## FindAES

TrueCryptやBitLockerで使用されるような128、192、256ビットのAESキーを検索するためのキースケジュールを検索します。

[こちらからダウンロード](https://sourceforge.net/projects/findaes/)できます。

# 補完ツール

ターミナルから画像を表示するために[**viu**](https://github.com/atanunq/viu)を使用できます。\
Linuxのコマンドラインツール**pdftotext**を使用して、PDFをテキストに変換して読むことができます。

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて修正を迅速化します。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、当社の独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう

- **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)または[Telegramグループ](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
