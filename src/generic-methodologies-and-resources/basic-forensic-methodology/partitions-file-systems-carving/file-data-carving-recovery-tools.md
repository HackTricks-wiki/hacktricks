# ファイル/データカービングと回復ツール

{{#include ../../../banners/hacktricks-training.md}}

## カービングと回復ツール

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

フォレンジックで画像からファイルを抽出するために最も一般的に使用されるツールは[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、ファイルを取り込んで「隠れた」ファイルを見つけます。Autopsyはディスクイメージや他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していないことに注意してください。

> **2024-2025年の更新** – バージョン**4.21**（2025年2月リリース）では、**SleuthKit v4.13**に基づいて再構築された**カービングモジュール**が追加され、マルチテラバイトイメージを扱う際に明らかに迅速で、マルチコアシステムでの並列抽出をサポートしています。¹ 小さなCLIラッパー（`autopsycli ingest <case> <image>`）も導入され、CI/CDや大規模なラボ環境内でのカービングをスクリプト化することが可能になりました。
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**は、埋め込まれたコンテンツを見つけるためにバイナリファイルを分析するツールです。`apt`を介してインストール可能で、そのソースは[GitHub](https://github.com/ReFirmLabs/binwalk)にあります。

**便利なコマンド**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **セキュリティノート** – バージョン **≤2.3.3** は **パス・トラバーサル** 脆弱性 (CVE-2022-4510) の影響を受けます。信頼できないサンプルをカービングする前に、アップグレードするか（またはコンテナ/非特権UIDで隔離してください）。

### Foremost

隠れたファイルを見つけるためのもう一つの一般的なツールは **foremost** です。foremost の設定ファイルは `/etc/foremost.conf` にあります。特定のファイルを検索したい場合は、それらのコメントを外してください。何もコメントを外さない場合、foremost はデフォルトで設定されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **スカルペル**

**スカルペル**は、**ファイルに埋め込まれたファイル**を見つけて抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプを設定ファイル (_/etc/scalpel/scalpel.conf_) からコメント解除する必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

このツールはkaliに含まれていますが、ここでも見つけることができます: <https://github.com/simsong/bulk_extractor>

Bulk Extractorは証拠画像をスキャンし、**pcapフラグメント**、**ネットワークアーティファクト（URL、ドメイン、IP、MAC、電子メール）**、および他の多くのオブジェクトを**複数のスキャナーを使用して並行して**カービングすることができます。
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
有用なポストプロセッシングスクリプト（`bulk_diff`、`bulk_extractor_reader.py`）は、2つのイメージ間でアーティファクトの重複を排除したり、結果をSIEM取り込み用のJSONに変換したりできます。

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download> で見つけることができます。

GUIとCLIのバージョンが付属しています。PhotoRecに検索してほしい**ファイルタイプ**を選択できます。

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview（故障ドライブのイメージング）

物理ドライブが不安定な場合は、**最初にイメージを作成**し、そのイメージに対してのみカービングツールを実行するのがベストプラクティスです。`ddrescue`（GNUプロジェクト）は、読み取れないセクターのログを保持しながら、悪化したディスクを信頼性高くコピーすることに焦点を当てています。
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
バージョン **1.28** (2024年12月) では **`--cluster-size`** が導入され、従来のセクターサイズがフラッシュブロックと一致しなくなった高容量SSDのイメージングを高速化できます。

### Extundelete / Ext4magic (EXT 3/4 アンデリート)

ソースファイルシステムがLinux EXTベースの場合、最近削除されたファイルを **フルカービングなしで** 回復できる可能性があります。両方のツールは読み取り専用イメージ上で直接動作します:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 ファイルシステムが削除後にマウントされた場合、データブロックはすでに再利用されている可能性があります。その場合、適切なカービング（Foremost/Scalpel）が依然として必要です。

### binvis

[コード](https://code.google.com/archive/p/binvis/)と[ウェブページツール](https://binvis.io/#/)を確認してください。

#### BinVisの特徴

- 視覚的でアクティブな**構造ビューワー**
- 異なる焦点のための複数のプロット
- サンプルの一部に焦点を当てる
- **PEまたはELF実行可能ファイル**内のストリングやリソースを見る
- ファイルの暗号解析用の**パターン**を取得
- **パッカーやエンコーダアルゴリズム**を特定
- パターンによる**ステガノグラフィーの識別**
- **視覚的**なバイナリ差分

BinVisは、ブラックボックスシナリオで未知のターゲットに慣れるための素晴らしい**出発点**です。

## 特定のデータカービングツール

### FindAES

AESキーのスケジュールを検索することでAESキーを検索します。TrueCryptやBitLockerで使用される128、192、256ビットのキーを見つけることができます。

[こちらからダウンロード](https://sourceforge.net/projects/findaes/)。

### YARA-X（カービングされたアーティファクトのトリアージ）

[YARA-X](https://github.com/VirusTotal/yara-x)は、2024年にリリースされたYARAのRustによる書き換えです。従来のYARAよりも**10-30倍速い**で、数千のカービングされたオブジェクトを非常に迅速に分類するために使用できます：
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
スピードアップにより、大規模な調査で**自動タグ付け**をすべてのカーブファイルに対して現実的に行うことができます。

## 補完ツール

ターミナルから画像を見るために[**viu** ](https://github.com/atanunq/viu)を使用できます。  \
PDFをテキストに変換して読むために、Linuxコマンドラインツール**pdftotext**を使用できます。

## 参考文献

1. Autopsy 4.21 リリースノート – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
