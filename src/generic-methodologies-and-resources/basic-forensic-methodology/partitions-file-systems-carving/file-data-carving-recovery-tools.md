# ファイル/データ カービング & 回復ツール

{{#include ../../../banners/hacktricks-training.md}}

## カービング & 回復ツール

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

フォレンジックで画像からファイルを抽出するために最も一般的に使用されるツールは[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、ファイルを取り込んで「隠れた」ファイルを見つけます。Autopsyはディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していないことに注意してください。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**は、埋め込まれたコンテンツを見つけるためにバイナリファイルを分析するツールです。`apt`を介してインストール可能で、そのソースは[GitHub](https://github.com/ReFirmLabs/binwalk)にあります。

**Useful commands**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

もう一つの一般的なツールは**foremost**です。foremostの設定ファイルは`/etc/foremost.conf`にあります。特定のファイルを検索したい場合は、それらのコメントを外してください。何もコメントを外さない場合、foremostはデフォルトで設定されたファイルタイプを検索します。
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

このツールはkaliに含まれていますが、ここで見つけることができます: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

このツールはイメージをスキャンし、**pcaps**を抽出し、**ネットワーク情報（URL、ドメイン、IP、MAC、メール）**やその他の**ファイル**を取得します。あなたがする必要があるのは:
```
bulk_extractor memory.img -o out_folder
```
すべての情報（パスワード？）をツールが収集した中からナビゲートし、パケットを分析します（**Pcaps analysis**を参照してください）。奇妙なドメイン（**マルウェア**や**存在しない**ドメインに関連する）を検索します。

### PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)で見つけることができます。

GUIとCLIのバージョンが付属しています。PhotoRecが検索する**ファイルタイプ**を選択できます。

![](<../../../images/image (242).png>)

### binvis

[コード](https://code.google.com/archive/p/binvis/)と[ウェブページツール](https://binvis.io/#/)を確認してください。

#### BinVisの特徴

- 視覚的でアクティブな**構造ビューワー**
- 異なる焦点のための複数のプロット
- サンプルの一部に焦点を当てる
- PEまたはELF実行可能ファイルの**文字列とリソース**を見る
- ファイルの暗号解析のための**パターン**を取得
- パッカーやエンコーダアルゴリズムを**特定**
- パターンによるステガノグラフィの**識別**
- **視覚的**なバイナリ差分

BinVisは、ブラックボックスシナリオで未知のターゲットに慣れるための素晴らしい**出発点**です。

## 特定のデータカービングツール

### FindAES

AESキーのスケジュールを検索することでAESキーを検索します。TrueCryptやBitLockerで使用される128、192、256ビットのキーを見つけることができます。

[こちらからダウンロード](https://sourceforge.net/projects/findaes/)。

## 補完ツール

ターミナルから画像を見るために[**viu**](https://github.com/atanunq/viu)を使用できます。\
PDFをテキストに変換して読むために、Linuxコマンドラインツール**pdftotext**を使用できます。

{{#include ../../../banners/hacktricks-training.md}}
