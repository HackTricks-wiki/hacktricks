# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

その他のツールは [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery) にあります。

### Autopsy

フォレンジックでイメージからファイルを抽出するために最も一般的に使用されるツールは [**Autopsy**](https://www.autopsy.com/download/) です。ダウンロードしてインストールし、ファイルを ingest して「hidden」なファイルを見つけます。Autopsy はディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していない点に注意してください。

> **2024-2025 update** – Version **4.21**（2025年2月リリース）では、**SleuthKit v4.13** をベースにした再構築済みの **carving module** が追加され、マルチテラバイトのイメージを処理する際の速度が大幅に向上しました。また、マルチコアシステムでの並列抽出にも対応しています。小規模な CLI wrapper（`autopsycli ingest <case> <image>`）も導入され、CI/CD や大規模なラボ環境内で carving をスクリプト化できるようになりました。<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** は、バイナリファイルを解析して埋め込まれたコンテンツを見つけるための tool です。`apt` でインストールでき、source は [GitHub](https://github.com/ReFirmLabs/binwalk) にあります。

**便利なコマンド**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – **2.3.3以下**のバージョンは**Path Traversal**の脆弱性（CVE-2022-4510）の影響を受けます。信頼できないサンプルをcarvingする前に、アップグレードするか、container／non-privileged UIDを使用して隔離してください。<sup>[[2]](#references)</sup>

### Foremost

隠しファイルを見つけるためによく使われる別のツールが**foremost**です。foremostの設定ファイルは`/etc/foremost.conf`にあります。特定のファイルだけを検索したい場合は、そのファイルのコメントを解除してください。何もコメントを解除しない場合、foremostはデフォルトで設定されたファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** は、**ファイル内に埋め込まれたファイル**を検索して抽出するために使用できる別の tool です。この場合、抽出したい file types のコメントを設定ファイル（_/etc/scalpel/scalpel.conf_）から解除する必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

この tool は kali に含まれていますが、こちらから入手できます: <https://github.com/simsong/bulk_extractor>

Bulk Extractor は evidence image を scan し、**pcap fragments**、**network artefacts (URLs, domains, IPs, MACs, e-mails)**、その他多数の object を、**multiple scanners** を使用して **parallel** に carve できます。
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
有用な post-processing scripts（`bulk_diff`、`bulk_extractor_reader.py`）を使うと、2つの image 間で artefact の重複を排除したり、SIEM への取り込み用に結果を JSON に変換したりできます。

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download> で入手できます。

GUI 版と CLI 版が用意されています。PhotoRec に検索させる **file-types** を選択できます。

![すべての scanner を実行し、JPEG を積極的に carve して bodyfile を生成 - PhotoRec: GUI 版と CLI 版が用意されています。PhotoRec に検索させる file-types を選択できます](<../../../images/image (242).png>)

### ddrescue + ddrescueview（障害が発生している drive の imaging）

物理 drive が不安定な場合は、まず **image 化**し、その image に対してのみ carving tools を実行するのが best practice です。`ddrescue`（GNU project）は、読み取り不能な sector の log を保持しながら、bad disk を確実にコピーすることに重点を置いています。
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28**（2024年12月）では、従来のセクターサイズがフラッシュブロックと一致しなくなった大容量SSDのイメージ取得を高速化できる **`--cluster-size`** が導入されました。

### Extundelete / Ext4magic（EXT 3/4 undelete）

ソースファイルシステムがLinuxのEXTベースの場合、**full carving**を行わずに最近削除されたファイルを復元できる可能性があります。どちらのツールもread-onlyイメージ上で直接動作します：
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 削除後にファイルシステムがマウントされた場合、データブロックはすでに再利用されている可能性があります。その場合でも、適切なcarving（Foremost/Scalpel）が必要です。

### binvis

[code](https://code.google.com/archive/p/binvis/)と[web page tool](https://binvis.io/#/)を確認してください。

#### BinVisの機能

- **structure viewer**による視覚的かつアクティブな分析
- 異なるフォーカスポイントに対応する複数のプロット
- サンプルの一部分へのフォーカス
- PEまたはELF executableなどに含まれる**stringsとresourcesの確認**
- ファイル上の暗号解析用**patternsの取得**
- **packerまたはencoder algorithmsの特定**
- パターンによる**Steganographyの識別**
- **visual binary-diffing**

BinVisは、black-boxing scenarioで**未知のtargetに慣れるための優れた開始点**です。

## Specific Data Carving Tools

### FindAES

key scheduleを検索してAES keysを探索します。TrueCryptやBitLockerで使用されるものなど、128、192、256 bit keysを検出できます。

[こちら](https://sourceforge.net/projects/findaes/)からDownloadできます。

### YARA-X（carved artefactsのtriaging）

[YARA-X](https://github.com/VirusTotal/yara-x)は、2024年にリリースされたYARAのRust rewriteです。classic YARAよりも**10-30倍高速**で、数千個のcarved objectsを非常に高速にclassifyするために使用できます。<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
この高速化により、大規模な調査でcarved filesをすべて**自動タグ付け**することが現実的になります。

## 補助ツール

ターミナルから画像を見るには、[**viu** ](https://github.com/atanunq/viu)を使用できます。  \
linuxのコマンドラインツール **pdftotext** を使用すると、pdfをテキストに変換して読み取れます。



## 参考資料

- [1] [Autopsy 4.21のリリースノート](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [binwalkのPath traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARAは死んだ。YARA-X万歳 - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
