# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

元のデバイスではなく、**検証済みのコピー**を必ずcarveしてください。読み取り専用での取得とハッシュ化のワークフローについては、[Image Acquisition & Mount](../image-acquisition-and-mount.md)を参照してください。

その他のツールについては、[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)を参照してください。

### Autopsy

イメージからファイルを抽出するためにforensicsで最もよく使用されるツールは、[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、ファイルを取り込ませて「hidden」ファイルを探します。Autopsyはディスクイメージやその他の種類のイメージをサポートするように構築されていますが、単純なファイルには対応していない点に注意してください。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**は、埋め込まれたコンテンツを見つけるためにバイナリファイルを分析するツールです。**Binwalk v3**はRustで書き直されており、自動抽出（`-e`）、既知および未知のオブジェクトのraw carving（`-c`）、再帰的/Matryoshkaスキャン（`-M`）、設定可能なworker threadsを備えています。すべての外部extractorsが必要な場合、プロジェクトではDocker buildを推奨しています。`cargo install binwalk`ではRust CLIがインストールされますが、それらの外部dependenciesはインストールされません。<sup>[[11]](#references)</sup>

**Useful v3 commands**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
legacy v2 の `--dd='.*'` recipe は、v3 における `-c` と同等ではありません。古い CTF/write-up のコマンドに従う場合は、まず `binwalk --version` を確認してください。<sup>[[11]](#references)</sup>

⚠️  **Security note** – **2.1.2b から 2.3.3** のバージョンは **Path Traversal** vulnerability (CVE-2022-4510) の影響を受けます。advisory には、patch 済みの pip version は記載されていません。影響を受ける release で untrusted samples を extract することは避けるか、container/non-privileged UID で tool を isolate してください。<sup>[[4]](#references)</sup>

### Foremost

hidden files を見つけるためのもう1つの一般的な tool は **foremost** です。foremost の configuration file は `/etc/foremost.conf` にあります。特定の files だけを検索したい場合は、それらのコメントアウトを解除してください。何もコメントアウトを解除しなければ、foremost はデフォルトで設定されている file types を検索します。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** は、**ファイル内に埋め込まれたファイル**を検索して抽出するためにも使用できる別のツールです。この場合、抽出したいファイルタイプを設定ファイル（_/etc/scalpel/scalpel.conf_）でコメント解除する必要があります。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

この tool は kali に含まれていますが、こちらから入手できます: <https://github.com/simsong/bulk_extractor>

Bulk Extractor は、evidence image をスキャンし、**pcap fragments**、**network artefacts (URLs, domains, IPs, MACs, e-mails)**、その他多数のオブジェクトを、**複数の scanner を使用して並列に** carve できます。

v2.1.1 release では、Autotools build と、連続するすべての JPEG を carve するための `-S jpeg_carve_mode=2` setting が documented されています。<sup>[[2]](#references)</sup>
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
付属の `bulk_diff.py` は2つの bulk_extractor の実行結果を比較し、`bulk_extractor_reader.py` はレポートと feature ファイルを読み取ります。<sup>[[3]](#references)</sup>

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download> から入手できます。

GUI 版と CLI 版が付属しています。PhotoRec で検索する **file-types** を選択できます。

![すべての scanner を実行し、JPEG を積極的に carve して bodyfile を生成する - PhotoRec: GUI 版と CLI 版が付属しています。PhotoRec で検索する file-types を選択できます](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover`（metadata-first）

raw signature carving の前に、volume metadata がまだ parse 可能であれば、filesystem-aware recovery を試してください。デフォルトでは、`tsk_recover` は unallocated files のみをエクスポートします。`-a` は allocated files を選択し、`-e` は両方をエクスポートします。ディスク全体の image の場合は、`mmls` で確認した partition の **start sector** を `-o` に渡します（bytes に変換しないでください）。入力がすでに partition image の場合は、`-o` を省略します。<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
このパスでは、header/footer carving では保持できないファイルシステム由来の名前やパスを保持できます。メタデータが欠落している、または使用できないエントリに対しては、その後に Foremost、Scalpel、または PhotoRec を実行してください。<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview（故障しているドライブのイメージ取得）

物理ドライブが不安定な場合は、まず**イメージ化**し、そのイメージに対してのみ carving tools を実行するのがベストプラクティスです。`ddrescue`（GNU project）は、読み取り不能なセクターのログを保持しながら、故障したディスクを確実にコピーすることに重点を置いています。
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`** オプションは、一度にコピーするセクタ数を制御します。値を小さくすると、低速なドライブで役立つ場合があります。<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic（EXT 3/4 undelete）

ソースファイルシステムが Linux EXT ベースの場合、**full carving** を行わずに最近削除されたファイルを復元できる可能性があります。これらのジャーナルベースのツールは、アンマウントされたファイルシステムまたは読み取り専用イメージ上で動作します。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **互換性に関する注意** – ext4magic は放棄されており、プロジェクトページでは、現在のファイルシステムはもはや互換性がないと警告されています。<sup>[[10]](#references)</sup>

> 🛈 削除後にファイルシステムがマウントされていた場合、データブロックはすでに再利用されている可能性があります。この場合も、適切な carving（Foremost/Scalpel）が必要です。

### binvis

[code](https://code.google.com/archive/p/binvis/) と [web page tool](https://binvis.io/#/) を確認してください。

#### BinVis の機能

- **structure viewer** による構造の視覚化とアクティブな分析
- 異なるフォーカスポイント向けの複数のプロット
- サンプルの一部へのフォーカス
- PE または ELF executable などに含まれる **strings と resources の確認**
- ファイルの cryptanalysis 用 **patterns** の取得
- **packer または encoder algorithms の特定**
- パターンによる **Steganography の特定**
- **Visual** binary-diffing

BinVis は、black-boxing のシナリオで **未知の target に慣れるための優れた start-point** です。

## Specific Data Carving Tools

### FindAES

key schedule を検索して AES keys を探します。TrueCrypt や BitLocker で使用されるものなど、128、192、256 bit keys を見つけることができます。

[ここ](https://sourceforge.net/projects/findaes/) から Download できます。

### YARA-X (carved artefacts の triaging)

[YARA-X](https://github.com/VirusTotal/yara-x) は、2024 年に導入された YARA の Rust rewrite です。VirusTotal によると、一部の regular-expression および complex-loop rules は大幅に高速に実行できます。<sup>[[5]](#references)</sup> CLI の名前は `yr` で、`scan` command は recursive scans、thread count、metadata output をサポートしています。<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## 補完ツール

ターミナルから画像を見るには、[**viu** ](https://github.com/atanunq/viu)を使用できます。  \
linux command line tool **pdftotext**を使用して、pdfをテキストに変換して読み取ることができます。





## References

- [1] [Autopsy 4.21 リリースノート](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalkのPath traversal（CVE-2022-4510）- GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA is dead, long live YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI commands](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue manual](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic manual](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic project status](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover manual](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
