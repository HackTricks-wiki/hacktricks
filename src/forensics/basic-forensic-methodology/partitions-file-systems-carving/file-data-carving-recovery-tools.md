# ファイル/データ カービング & 回復ツール

{{#include ../../../banners/hacktricks-training.md}}

## カービング & 回復ツール

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

フォレンジックで画像からファイルを抽出するために最も一般的に使用されるツールは [**Autopsy**](https://www.autopsy.com/download/) です。ダウンロードしてインストールし、ファイルを取り込んで「隠れた」ファイルを見つけます。Autopsyはディスクイメージや他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していないことに注意してください。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** は、埋め込まれたコンテンツを見つけるためにバイナリファイルを分析するツールです。`apt`を介してインストール可能で、そのソースは [GitHub](https://github.com/ReFirmLabs/binwalk) にあります。

**Useful commands**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

もう一つの一般的なツールは**foremost**です。foremostの設定ファイルは`/etc/foremost.conf`にあります。特定のファイルを検索したい場合は、それらのコメントを外してください。何もコメントを外さなければ、foremostはデフォルトで設定されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **スカルペル**

**スカルペル**は、**ファイルに埋め込まれたファイル**を見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプを設定ファイル (_/etc/scalpel/scalpel.conf_) からコメント解除する必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

このツールはKaliに含まれていますが、ここでも見つけることができます: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

このツールはイメージをスキャンし、その中にある**pcaps**を**抽出**し、**ネットワーク情報（URL、ドメイン、IP、MAC、メール）**やその他の**ファイル**を取得します。あなたがする必要があるのは:
```
bulk_extractor memory.img -o out_folder
```
すべての情報（パスワードなど）をツールが収集したものをナビゲートし、パケットを分析し（[**Pcaps分析**](../pcap-inspection/)を読む）、奇妙なドメイン（マルウェアや存在しないドメインに関連する）を検索します。

### PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)で見つけることができます。

GUIとCLIのバージョンがあります。PhotoRecが検索するファイルタイプを選択できます。

![](<../../../images/image (524).png>)

### binvis

[コード](https://code.google.com/archive/p/binvis/)と[ウェブページツール](https://binvis.io/#/)を確認してください。

#### BinVisの特徴

- 視覚的でアクティブな構造ビューア
- 異なる焦点のための複数のプロット
- サンプルの一部に焦点を当てる
- PEまたはELF実行可能ファイルの文字列やリソースを見る
- ファイルの暗号解析のためのパターンを取得
- パッカーやエンコーダアルゴリズムを特定
- パターンによるステガノグラフィの識別
- 視覚的なバイナリ差分

BinVisは、ブラックボックスシナリオで未知のターゲットに慣れるための素晴らしい出発点です。

## 特定のデータカービングツール

### FindAES

AESキーのスケジュールを検索することでAESキーを検索します。TrueCryptやBitLockerで使用される128、192、256ビットのキーを見つけることができます。

[こちらからダウンロード](https://sourceforge.net/projects/findaes/)。

## 補完ツール

ターミナルから画像を見るために[**viu**](https://github.com/atanunq/viu)を使用できます。\
PDFをテキストに変換して読むために、Linuxコマンドラインツール**pdftotext**を使用できます。

{{#include ../../../banners/hacktricks-training.md}}
