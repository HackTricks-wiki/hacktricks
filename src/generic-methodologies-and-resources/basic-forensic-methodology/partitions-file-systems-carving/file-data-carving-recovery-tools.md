# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

その他のツールについては [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery) を参照してください。

### Autopsy

フォレンジックでイメージからファイルを抽出するために最もよく使用されるツールは [**Autopsy**](https://www.autopsy.com/download/) です。ダウンロードしてインストールし、ファイルを取り込ませて「hidden」ファイルを探します。Autopsy はディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していない点に注意してください。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** は、バイナリファイルを分析して埋め込まれたコンテンツを見つけるためのツールです。`apt` 経由でインストールでき、source は [GitHub](https://github.com/ReFirmLabs/binwalk) にあります。

**Useful commands**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – **2.1.2b から 2.3.3** のバージョンは **Path Traversal** の脆弱性（CVE-2022-4510）の影響を受けます。advisory には、パッチ適用済みの pip バージョンは記載されていません。影響を受けるリリースで信頼できないサンプルを展開することは避けるか、container または非特権 UID を使用してツールを分離してください。<sup>[[4]](#references)</sup>

### Foremost

隠しファイルを見つけるための一般的なツールとして、**foremost** もあります。foremost の configuration file は `/etc/foremost.conf` にあります。特定のファイルだけを検索したい場合は、それらのコメントを解除してください。何もコメント解除しない場合、foremost はデフォルトで設定されているファイルタイプを検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** は、**ファイル内に埋め込まれたファイル**を検索して抽出するために使用できる別のツールです。この場合、抽出したいファイルタイプを設定ファイル（_/etc/scalpel/scalpel.conf_）でコメント解除する必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

このツールは kali に含まれていますが、こちらでも入手できます: <https://github.com/simsong/bulk_extractor>

Bulk Extractor は証拠イメージをスキャンし、**pcap フラグメント**、**network artefacts（URL、ドメイン、IP、MAC、メールアドレス）**、その他多数のオブジェクトを、複数の scanner を使用して**並列に**carve できます。

v2.1.1 リリースでは、Autotools によるビルドと、連続する JPEG をすべて carve するための `-S jpeg_carve_mode=2` 設定が文書化されています。<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
同梱されている `bulk_diff.py` は2つの bulk_extractor の実行結果を比較し、`bulk_extractor_reader.py` はレポートおよび feature ファイルを読み取ります。<sup>[[3]](#references)</sup>

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download> にあります。

GUI 版と CLI 版が用意されています。PhotoRec で検索する **file-types** を選択できます。

![すべての scanner を実行し、JPEG を積極的に carve して bodyfile を生成 - PhotoRec: GUI 版と CLI 版が用意されています。PhotoRec で検索する file-types を選択できます](<../../../images/image (242).png>)

### ddrescue + ddrescueview（障害が発生しているドライブのイメージ化）

物理ドライブが不安定な場合は、まず **イメージ化** し、そのイメージに対してのみ carving tools を実行するのがベストプラクティスです。`ddrescue`（GNU project）は、読み取り不能なセクターのログを保持しながら、障害のあるディスクを確実にコピーすることに重点を置いています。
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`**オプションは、一度にコピーするセクタ数を制御します。小さい値にすると、低速なドライブで役立つ場合があります。<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic（EXT 3/4 undelete）

ソースファイルシステムが Linux EXT ベースの場合、**full carving**を行わずに最近削除されたファイルを復元できる可能性があります。これらのジャーナルベースのツールは、アンマウントされたファイルシステムまたは読み取り専用イメージ上で動作します。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **互換性に関する注意** – ext4magic は放棄されており、プロジェクトページでは、現在のファイルシステムはもはや互換性がないと警告されています。<sup>[[10]](#references)</sup>

> 🛈 削除後にファイルシステムがマウントされていた場合、データブロックはすでに再利用されている可能性があります。その場合でも、適切な carving（Foremost/Scalpel）が必要です。

### binvis

[code](https://code.google.com/archive/p/binvis/) と [web page tool](https://binvis.io/#/) を確認してください。

#### BinVis の機能

- 視覚的かつアクティブな **構造ビューア**
- 異なるフォーカスポイントに対応する複数のプロット
- サンプルの一部分へのフォーカス
- PE や ELF executable などにおける **strings とリソースの確認**
- ファイルの暗号解析用 **パターン** の取得
- **packer または encoder アルゴリズムの検出**
- パターンによる **Steganography の識別**
- **視覚的な** binary-diffing

BinVis は、black-boxing の状況で **未知のターゲットに慣れるための出発点** として非常に優れています。

## Specific Data Carving Tools

### FindAES

key schedule を検索することで AES keys を検索します。TrueCrypt や BitLocker で使用されるものなど、128、192、256 bit の keys を検出できます。

[here](https://sourceforge.net/projects/findaes/) から Download できます。

### YARA-X (carved artefacts の triaging)

[YARA-X](https://github.com/VirusTotal/yara-x) は、2024 年に導入された YARA の Rust rewrite です。VirusTotal によると、一部の regular-expression および complex-loop rules は大幅に高速に実行できます。<sup>[[5]](#references)</sup> CLI の名称は `yr` で、`scan` command は recursive scans、thread count、metadata output をサポートしています。<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## 補完ツール

ターミナルから画像を見るには [**viu** ](https://github.com/atanunq/viu)を使用できます。  \
Linuxのコマンドラインツール **pdftotext** を使用して、pdfをテキストに変換して読み取ることができます。



## References

- [1] [Autopsy 4.21 リリースノート](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalkにおけるPath traversal（CVE-2022-4510） - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARAは死んだ、YARA-X万歳 - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI commands](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue manual](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic manual](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic project status](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
