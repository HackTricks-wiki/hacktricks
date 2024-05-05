# ファイル/データの彫刻と回復ツール

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード**したい場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に **参加** または **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live) を **フォロー** してください。
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに PR を提出してください。

</details>

**Try Hard Security Group**

<figure><img src="../../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## 彫刻と回復ツール

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)にさらに多くのツールがあります。

### Autopsy

画像からファイルを抽出するために最も一般的に使用されるツールは [**Autopsy**](https://www.autopsy.com/download/) です。ダウンロードしてインストールし、ファイルを取り込んで「隠れた」ファイルを見つけるようにします。Autopsy はディスクイメージや他の種類のイメージをサポートするように構築されていますが、単純なファイルはサポートしていません。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** はバイナリファイルを分析して埋め込まれたコンテンツを見つけるためのツールです。`apt` を介してインストール可能で、そのソースは [GitHub](https://github.com/ReFirmLabs/binwalk) にあります。

**便利なコマンド**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

もう1つの一般的な隠しファイルを見つけるためのツールは **foremost** です。 foremost の設定ファイルは `/etc/foremost.conf` にあります。特定のファイルを検索したい場合は、それらのコメントを外してください。何もコメントアウトしない場合、foremost はデフォルトで構成されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**は、ファイルに埋め込まれたファイルを見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプを構成ファイル（_/etc/scalpel/scalpel.conf_）からコメントアウトする必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

このツールはKaliに含まれていますが、こちらで見つけることができます: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

このツールは画像をスキャンし、その中に含まれる**pcapsを抽出**し、**ネットワーク情報（URL、ドメイン、IP、MAC、メール）**や他の**ファイル**を取得することができます。以下の手順のみを実行する必要があります:
```
bulk_extractor memory.img -o out_folder
```
### PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download) で見つけることができます。

GUI と CLI のバージョンがあります。PhotoRec が検索する**ファイルタイプ**を選択できます。

![](<../../../.gitbook/assets/image (242).png>)

### binvis

[コード](https://code.google.com/archive/p/binvis/) と [web ページツール](https://binvis.io/#/) をチェックしてください。

#### BinVis の特徴

- ビジュアルでアクティブな**構造ビューア**
- 異なる焦点点のための複数のプロット
- サンプルの一部に焦点を当てる
- PE や ELF 実行可能ファイル内の**文字列やリソース**を見る
- ファイルの暗号解読のための**パターン**を取得
- パッカーやエンコーダーアルゴリズムを**見つける**
- パターンによるステガノグラフィを**特定する**
- **ビジュアル**バイナリ差分

BinVis は、ブラックボックスシナリオで未知のターゲットに慣れるための素晴らしい**スタートポイント**です。

## 特定のデータカービングツール

### FindAES

TrueCrypt や BitLocker で使用されるような 128、192、256 ビットの鍵を見つけるために、鍵スケジュールを検索することで AES 鍵を検索します。

[こちらからダウンロード](https://sourceforge.net/projects/findaes/)できます。

## 補足ツール

画像を端末から見るために [**viu** ](https://github.com/atanunq/viu)を使用できます。\
Linux コマンドラインツール **pdftotext** を使用して、pdf をテキストに変換して読むことができます。
