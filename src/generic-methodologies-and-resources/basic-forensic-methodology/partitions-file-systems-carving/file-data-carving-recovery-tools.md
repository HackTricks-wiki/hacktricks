# File/Data Carving & Recovery Tools

## Carving & Recovery tools

その他のツールは [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery) にあります。

### Autopsy

フォレンジックでイメージからファイルを抽出するために最も一般的に使用されるツールは [**Autopsy**](https://www.autopsy.com/download/) です。ダウンロードしてインストールし、ファイルを ingest して「hidden」ファイルを探します。Autopsy はディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していない点に注意してください。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** は、バイナリファイルを分析して埋め込まれたコンテンツを探すためのツールです。`apt` 経由でインストールでき、ソースは [GitHub](https://github.com/ReFirmLabs/binwalk) にあります。

**Useful commands**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – **2.1.2b から 2.3.3** までのバージョンは **Path Traversal** 脆弱性（CVE-2022-4510）の影響を受けます。advisory には、patch 済みの pip version は記載されていません。影響を受ける release で untrusted な sample を extract することは避けるか、container または non-privileged UID を使用して tool を isolate してください。<sup>[[4]](#references)</sup>

### Foremost

hidden file を見つけるためによく使われる別の tool は **foremost** です。foremost の configuration file は `/etc/foremost.conf` にあります。特定の file だけを検索したい場合は、それらの comment を解除してください。何も comment を解除しない場合、foremost はデフォルトで設定されている file type を検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** は、**ファイル内に埋め込まれたファイル**を検索して抽出するために使用できる別のツールです。この場合、抽出するファイルタイプを設定ファイル（_/etc/scalpel/scalpel.conf_）でコメント解除する必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

このツールは kali に含まれていますが、こちらから入手できます: <https://github.com/simsong/bulk_extractor>

Bulk Extractor は、evidence image をスキャンし、**pcap フラグメント**、**ネットワークアーティファクト（URLs、domains、IPs、MACs、e-mails）**、その他多数のオブジェクトを、**複数の scanner を使用して並列に carve**できます。

v2.1.1 リリースでは、Autotools によるビルドと、連続するすべての JPEG を carve するための `-S jpeg_carve_mode=2` 設定が文書化されています。<sup>[[2]](#references)</sup>
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
同梱の `bulk_diff.py` は2つの bulk_extractor の実行結果を比較し、`bulk_extractor_reader.py` はレポートおよび feature ファイルを読み取ります。<sup>[[3]](#references)</sup>

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download> にあります。

GUI 版と CLI 版が付属しています。PhotoRec で検索する **file-types** を選択できます。

![すべての scanner を実行し、JPEG を積極的に carve して bodyfile を生成する - PhotoRec: GUI 版と CLI 版が付属しています。検索する file-types を選択できます](<../../../images/image (242).png>)

### ddrescue + ddrescueview（不安定なドライブのイメージ取得）

物理ドライブが不安定な場合は、まず **イメージを取得し**、そのイメージに対してのみ carving tools を実行するのがベストプラクティスです。`ddrescue`（GNU project）は、読み取り不能なセクタのログを保持しながら、不良ディスクを確実にコピーすることに重点を置いています。
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`** オプションは一度にコピーするセクタ数を制御します。小さい値にすると、低速なドライブで役立つ場合があります。<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic（EXT 3/4 undelete）

対象のファイルシステムが Linux EXT ベースの場合、**完全な carving を行わずに**最近削除されたファイルを復元できる可能性があります。これらのジャーナルベースのツールは、アンマウントされたファイルシステムまたは読み取り専用イメージ上で動作します。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **互換性に関する注意** – ext4magic は放棄されており、プロジェクトページでは、現在のファイルシステムはもはや互換性がないと警告されています。<sup>[[10]](#references)</sup>

> 🛈 ファイルシステムが削除後にマウントされていた場合、データブロックはすでに再利用されている可能性があります。この場合でも、適切なcarving（Foremost/Scalpel）が必要です。

### binvis

[コード](https://code.google.com/archive/p/binvis/)と[Webページのツール](https://binvis.io/#/)を確認してください。

#### BinVisの機能

- **構造ビューア**
- 異なるフォーカスポイントに対応した複数のプロット
- サンプルの一部にフォーカス
- PEやELFの実行ファイルなどにおける**文字列とリソースの可視化**
- ファイルの暗号解析用**パターン**の取得
- **packerまたはencoderアルゴリズムの検出**
- パターンによる**Steganographyの特定**
- **可視化された**binary-diffing

BinVisは、black-boxingのシナリオで**未知のターゲットに慣れるための出発点**として優れています。

## Specific Data Carving Tools

### FindAES

鍵スケジュールを検索することでAES keysを検索します。TrueCryptやBitLockerで使用される128、192、256ビットの鍵などを検出できます。

[こちら](https://sourceforge.net/projects/findaes/)からDownloadできます。

### YARA-X（carved artefactsのtriaging）

[YARA-X](https://github.com/VirusTotal/yara-x)は、2024年に導入されたYARAのRustによる書き直しです。VirusTotalによると、一部のregular-expressionルールやcomplex-loopルールを大幅に高速実行できます。<sup>[[5]](#references)</sup> CLIの名前は`yr`で、`scan`コマンドは再帰的なスキャン、スレッド数、メタデータ出力に対応しています。<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## 補完ツール

ターミナルから画像を見るには [**viu** ](https://github.com/atanunq/viu)を使用できます。  \
linux のコマンドラインツール **pdftotext** を使用して、pdf をテキストに変換して読み取ることができます。



## References

- [1] [Autopsy 4.21 リリースノート](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk における Path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA は死んだ、YARA-X 万歳 - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI commands](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue manual](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic manual](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic project status](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
