# File/Data Carving & Recovery ツール

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery ツール

元のデバイスではなく、**検証済みのコピー**を必ずカービングしてください。読み取り専用での取得とハッシュ化の手順については、[イメージの取得とマウント](../image-acquisition-and-mount.md)を参照してください。

その他のツールは[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)を参照してください。

### Autopsy

イメージからファイルを抽出するフォレンジックで最も一般的なツールは[**Autopsy**](https://www.autopsy.com/download/)です。ダウンロードしてインストールし、ファイルを取り込ませて「隠し」ファイルを見つけます。Autopsyはディスクイメージなどのイメージに対応するように作られており、単純なファイルには対応していない点に注意してください。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**は、バイナリファイルを解析して埋め込まれたコンテンツを見つけるツールです。**Binwalk v3**はRustで書き直され、自動抽出（`-e`）、既知および未知のオブジェクトのraw carving（`-c`）、再帰的な（Matryoshka）スキャン（`-M`）、設定可能なワーカースレッドに対応しています。すべての外部extractorが必要な場合、プロジェクトではDockerビルドの使用を推奨しています。`cargo install binwalk`でインストールされるRust CLIには、これらの外部依存関係は含まれません。<sup>[[11]](#references)</sup>

**便利なv3コマンド**：

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

古い v2 の `--dd='.*'` レシピは、v3 の `-c` に相当するものではありません。古い CTF/write-up のコマンドを使う場合は、まず `binwalk --version` を確認してください。<sup>[[11]](#references)</sup>

⚠️  **セキュリティに関する注意** – **2.1.2b から 2.3.3** までのバージョンは、**Path Traversal** の脆弱性（CVE-2022-4510）の影響を受けます。この勧告には、修正済みの pip バージョンは記載されていません。影響を受けるリリースを使って信頼できないサンプルを展開することは避けるか、コンテナまたは非特権 UID でツールを隔離してください。<sup>[[4]](#references)</sup>

### Foremost

隠しファイルを見つけるためによく使われるもう1つのツールは **foremost** です。foremost の設定ファイルは `/etc/foremost.conf` にあります。特定のファイルだけを検索したい場合は、それらのコメントを解除してください。何もコメント解除しない場合、foremost はデフォルトで設定されているファイルタイプを検索します。

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel**は、**ファイル内に埋め込まれたファイル**を検索して抽出するために使用できる別のツールです。この場合、抽出するファイルの種類を設定ファイル（_/etc/scalpel/scalpel.conf_）でコメント解除する必要があります。

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3 による断片化ファイルのカービング

metadata-first recovery と contiguous carvers で分割ファイルが不完全なままの場合、**Scalpel3** は file/block validators を使って対応形式を再構成できます。これは、上記の legacy `scalpel` コマンドとは異なるコードベースです。まず、カービングに使うものと**同じブロックサイズ**で、必須の blockmap を作成します。サイズが分かる場合は `fsstat` からファイルシステムのクラスタサイズを取得し、不明な場合はパーティションイメージをスキャンする前に、妥当性を説明できる値を決めてください。検証済みのコピーだけを対象に実行し、出力先には別のボリュームを使用してください。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

`4096`を選択したブロックサイズに置き換えます。`-w`は検証済みの候補に加えて**有望な**候補も保持し、`-b`は再構築したレイアウトの確認に役立つblockvectorを書き出します。PROMISINGにあるファイルや、見慣れた拡張子が付いたファイルであっても、完全に復元された証拠にはなりません。使用前に内容を検証してください。<sup>[[13]](#references)[[14]](#references)</sup> carvingの前に削除されたパーティションやギャップを見つけるには、[一覧にないパーティションの外部にあるデータを見つける](./#finding-data-outside-listed-partitions)を参照してください。

### Bulk Extractor 2.x   

このツールはKaliに含まれていますが、こちらから入手できます: <https://github.com/simsong/bulk_extractor>

Bulk Extractorは証拠イメージをスキャンし、**pcapの断片**、**ネットワーク関連データ (URL、ドメイン、IP、MAC、メールアドレス)**など、さまざまなオブジェクトを**複数のscannerで並列に**carveできます。

v2.1.1リリースでは、Autotoolsによるビルドと、連続するすべてのJPEGをcarveするための設定`-S jpeg_carve_mode=2`が説明されています。<sup>[[2]](#references)</sup>

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

同梱の `bulk_diff.py` は2つの bulk_extractor の実行結果を比較し、`bulk_extractor_reader.py` はレポートファイルと feature ファイルを読み込みます。<sup>[[3]](#references)</sup>

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download> から入手できます。

GUI版とCLI版があります。PhotoRecで検索する **ファイルタイプ** を選択できます。

![すべてのスキャナーを実行し、JPEGを積極的にカービングして、bodyfileを生成 - PhotoRec：GUI版とCLI版があります。PhotoRecで検索するファイルタイプを選択できます](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover`（メタデータ優先）

raw signature carving の前に、ボリュームのメタデータをまだ解析できる場合は、ファイルシステムを考慮した復元を試してください。`tsk_recover` はデフォルトで未割り当てのファイルのみをエクスポートします。`-a` は割り当て済みのファイルを選択し、`-e` は両方をエクスポートします。ディスク全体のイメージでは、`mmls` で確認したパーティションの **開始セクター** を `-o` に渡してください（バイト数に変換しないでください）。入力がすでにパーティションイメージの場合は、`-o` を省略してください。<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

この手法では、header/footer carvingでは復元できない、filesystem由来の名前やパスを保持できます。metadataが欠落している、または使用できないエントリには、その後Foremost、Scalpel、またはPhotoRecを実行してください。<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview（故障しつつあるドライブのイメージ取得）

物理ドライブが不安定な場合は、まず**イメージを取得**し、そのイメージに対してのみcarving toolsを実行するのがベストプラクティスです。GNUプロジェクトの`ddrescue`は、読み取り不能なセクターのログを保持しながら、故障したディスクを確実にコピーすることに重点を置いています。

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

**`--cluster-size`** オプションは一度にコピーするセクター数を制御します。値を小さくすると、低速ドライブで役立つことがあります。<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

ソースのファイルシステムが Linux の EXT ベースであれば、**完全な carving を行わずに**最近削除されたファイルを復元できる場合があります。これらのジャーナルベースのツールは、アンマウントされたファイルシステムまたは読み取り専用イメージで動作します。<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **互換性に関する注意** – ext4magic は開発が放棄されており、プロジェクトページでは、現在のファイルシステムとは互換性がないと警告されています。<sup>[[10]](#references)</sup>

> 🛈 削除後にファイルシステムがマウントされていた場合、データブロックはすでに再利用されている可能性があります。その場合は、適切な carving（Foremost/Scalpel）が引き続き必要です。

### binvis

[コード](https://code.google.com/archive/p/binvis/)と[Webページのツール](https://binvis.io/#/)を確認してください。

#### BinVis の機能

- 視覚的で対話的な**構造ビューア**
- 注目点の異なる複数のプロット
- サンプルの一部にフォーカス
- PE や ELF の実行ファイルなどで、**文字列やリソースを確認**
- ファイルの暗号解析に使う**パターン**を取得
- パッカーやエンコーダーのアルゴリズムを**特定**
- パターンからステガノグラフィを**特定**
- 視覚的なバイナリ差分解析

BinVis は、black-boxing のシナリオで**未知のターゲットに慣れるための出発点**として最適です。

## 特定のデータ carving ツール

### FindAES

鍵スケジュールを検索して AES キーを探します。TrueCrypt や BitLocker で使われているような、128、192、256 ビットのキーを検出できます。

[こちら](https://sourceforge.net/projects/findaes/)からダウンロードできます。

### YARA-X（carving したアーティファクトのトリアージ）

[YARA-X](https://github.com/VirusTotal/yara-x) は、2024 年に登場した YARA の Rust による書き直し版です。VirusTotal によると、一部の正規表現ルールや複雑なループを含むルールを大幅に高速に実行できます。<sup>[[5]](#references)</sup> CLI の名前は `yr` で、`scan` コマンドは再帰スキャン、スレッド数の指定、メタデータの出力に対応しています。<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## 補助ツール

[**viu** ](https://github.com/atanunq/viu)を使うと、ターミナルから画像を確認できます。  \
Linuxのコマンドラインツール **pdftotext** を使うと、pdfをテキストに変換して読み取れます。







## References

- [1] [Autopsy 4.21 リリースノート](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalkのパストラバーサル (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARAは死んだ、YARA-X万歳 - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLIコマンド](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescueマニュアル](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magicマニュアル](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magicプロジェクトのステータス](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recoverマニュアル](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Scalpel3 README](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Scalpel3マニュアル](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Scalpel3テストワークフロー](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
