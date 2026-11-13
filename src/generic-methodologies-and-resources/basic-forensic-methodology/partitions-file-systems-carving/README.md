# パーティション/ファイルシステム/カービング

{{#include ../../../banners/hacktricks-training.md}}

## パーティション

ディスクには複数の**パーティション**を含めることができます。パーティションはブロックの論理的な範囲であり、物理的に分かれたストレージではありません。パーティションの開始位置と長さは**論理セクター**単位で表されます。すべてのイメージが512バイトのセクターを使用すると想定しないでください。4096バイトの論理セクターも存在します。<sup>[[4]](#references)</sup>

### MBR（マスターブートレコード）

MBRは最初の論理セクター（LBA 0）を占め、4つの16バイトのパーティションエントリはバイト446から始まります。その前の領域にはブートコードが含まれ、ディスク署名が含まれる場合もあります。<sup>[[4]](#references)</sup>\
最大**4つのパーティション**を使用できます（アクティブ/**ブート可能**にできるのは**最大1つ**です）。ただし、さらにパーティションが必要な場合は、**拡張パーティション**を使用できます。512バイトのMBRの最後の**2バイト**は、ブート署名**0x55 0xAA**です。アクティブとしてマークできるパーティションは1つだけです。\
論理セクターが512バイトの場合、MBRの32ビットのセクターフィールドにより、アドレス指定可能な容量は約**2 TiB**（2.2 TB）に制限されます。<sup>[[4]](#references)</sup>

![パーティション - MBR（マスターブートレコード）：MBRで扱える容量は最大2.2TB](<../../../images/image (350).png>)

![パーティション - MBR（マスターブートレコード）：MBRで扱える容量は最大2.2TB](<../../../images/image (304).png>)

MBRの**バイト440～443**には、（Windowsが使用されている場合）**Windowsディスク署名**があります。ハードディスクの論理ドライブ文字は、Windowsディスク署名に依存します。この署名を変更すると、Windowsが起動できなくなることがあります（ツール：[**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**。

![パーティション - MBR（マスターブートレコード）：（Windowsが使用されている場合）MBRのバイト440～443にはWindowsディスク署名があります。ハードディスクの論理ドライブ文字は……](<../../../images/image (310).png>)

**形式**

| オフセット   | 長さ       | 項目                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | ブートコード        |
| 446 (0x1BE) | 16 (0x10)  | 第1パーティション   |
| 462 (0x1CE) | 16 (0x10)  | 第2パーティション   |
| 478 (0x1DE) | 16 (0x10)  | 第3パーティション   |
| 494 (0x1EE) | 16 (0x10)  | 第4パーティション   |
| 510 (0x1FE) | 2 (0x2)    | 署名 0x55 0xAA      |

**パーティションレコードの形式**

| オフセット | 長さ     | 項目                                                      |
| --------- | -------- | --------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | アクティブフラグ（0x80 = ブート可能）                    |
| 1 (0x01)  | 1 (0x01) | 開始ヘッド                                                |
| 2 (0x02)  | 1 (0x01) | 開始セクター（ビット0～5）；シリンダーの上位ビット（6～7） |
| 3 (0x03)  | 1 (0x01) | 開始シリンダーの下位8ビット                               |
| 4 (0x04)  | 1 (0x01) | パーティションタイプコード（0x83 = Linux）                |
| 5 (0x05)  | 1 (0x01) | 終了ヘッド                                                |
| 6 (0x06)  | 1 (0x01) | 終了セクター（ビット0～5）；シリンダーの上位ビット（6～7） |
| 7 (0x07)  | 1 (0x01) | 終了シリンダーの下位8ビット                               |
| 8 (0x08)  | 4 (0x04) | パーティションより前のセクター数（リトルエンディアン）    |
| 12 (0x0C) | 4 (0x04) | パーティション内のセクター数                              |

ディスク全体のMBRイメージ内のパーティションを調べるには、まず開始LBAと論理セクターサイズを取得します。`mount`が受け取るのはLBAではなく**バイトオフセット**です。以下の例が有効なのは、512バイトセクターのイメージで、パーティションがLBA 63から始まる場合に限られます。信頼できないイメージやジャーナリングファイルシステムを扱う場合は、代わりに[Image Acquisition & Mount](../image-acquisition-and-mount.md)の隔離された読み取り専用の手順を使用してください。<sup>[[5]](#references)[[11]](#references)</sup>

![パーティション - MBR（マスターブートレコード）：LinuxでMBRをマウントするには、まず開始オフセットを取得する必要があります（fdiskのpコマンドを使用できます）](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) は、コンピューターのストレージデバイス、一般にハードディスクドライブなどの二次ストレージシステムに保存されたデータブロックの**位置を指定する**ために使われる一般的な方式です。LBAは特に単純な線形アドレス方式で、**ブロックは整数のインデックスで位置が示されます**。最初のブロックはLBA 0、2番目はLBA 1、以下同様です。

### GPT (GUID Partition Table)

GUID Partition Table (GPT) は各パーティションに一意のGUIDを格納し、プライマリとバックアップのメタデータを使用します。レイアウトはMBRと以下の点で異なります:<sup>[[4]](#references)</sup>

- **位置とサイズ**: LBA 0には**protective MBR**が格納されます。プライマリGPTヘッダーはLBA 1にあり、その後にパーティションエントリー配列が続きます。バックアップ配列とヘッダーはディスクの末尾にあります。GPTは64ビットのLBAフィールドを使用しますが、MBRのパーティションエントリーは32ビットのLBAフィールドを使用します。
- **パーティション数の上限**: 一般的な16 KiBのエントリー配列には、**128バイトのエントリーが128個**格納されます。ただし、エントリー数はGPTで固定されておらず、ヘッダーに記録されます。アドレス可能なサイズは論理セクターサイズにも依存します（512バイトセクターの場合、約**9.4 ZB**）。<sup>[[4]](#references)</sup>
- **パーティション名**: 最大36個のUnicode文字でパーティションに名前を付けられます。

**データの耐障害性と復旧**:

- **冗長性**: MBRとは異なり、GPTではパーティション情報とブートデータを1か所だけに限定しません。ディスク全体にこのデータを複製することで、データの完全性と耐障害性を高めます。
- **Cyclic Redundancy Check (CRC)**: ヘッダーとパーティションエントリー配列には、それぞれCRC32があります。CRCは不整合を検出しますが、継続的に監視したり、それ自体でディスクを修復したりするものではありません。プライマリコピーが無効な場合は、復旧を行う前に、作業用コピー上で最終LBAにあるバックアップを検証してください。<sup>[[4]](#references)</sup>

**Protective MBR (LBA0)**:

- GPTはprotective MBRによって後方互換性を維持します。この機能はレガシーMBR領域にありますが、古いMBRベースのユーティリティが誤ってGPTディスクを上書きしないように設計されており、GPT形式のディスク上のデータの完全性を保護します。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

EFIではなく**BIOS**サービスを介した**GPTベースのブート**に対応するオペレーティングシステムでは、最初のセクターを**bootloader**コードの第1段階の格納に引き続き使用する場合があります。ただし、**GPT** **partitions**を認識できるように**変更**されます。MBR内のbootloaderは、セクターサイズが512バイトだと仮定してはなりません。

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

パーティションテーブルヘッダーは、ディスク上で使用可能なブロックを定義します。また、パーティションテーブルを構成するパーティションエントリーの数とサイズも定義します（テーブル内のオフセット80と84）。

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)on little-endian machines) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8向けRevision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | リトルエンディアンのヘッダーサイズ（バイト単位。通常は5Ch 00h 00h 00h、つまり92バイト）                                                                                                 |
| 16 (0x10) | 4 bytes  | リトルエンディアンのヘッダーの[CRC32](https://en.wikipedia.org/wiki/CRC32)（オフセット+0からヘッダーサイズまで）。計算時はこのフィールドをゼロにする                             |
| 20 (0x14) | 4 bytes  | 予約済み。ゼロでなければならない                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | 現在のLBA（このヘッダーコピーの位置）                                                                                                                                   |
| 32 (0x20) | 8 bytes  | バックアップLBA（もう一方のヘッダーコピーの位置）                                                                                                                               |
| 40 (0x28) | 8 bytes  | パーティションで使用可能な最初のLBA（プライマリパーティションテーブルの最終LBA + 1）                                                                                                       |
| 48 (0x30) | 8 bytes  | 使用可能な最終LBA（セカンダリパーティションテーブルの最初のLBA − 1）                                                                                                                    |
| 56 (0x38) | 16 bytes | 混合エンディアン形式のディスクGUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | パーティションエントリー配列の開始LBA（プライマリコピーでは常に2）                                                                                                     |
| 80 (0x50) | 4 bytes  | 配列内のパーティションエントリー数                                                                                                                                         |
| 84 (0x54) | 4 bytes  | 1つのパーティションエントリーのサイズ（通常は80hまたは128）                                                                                                                        |
| 88 (0x58) | 4 bytes  | リトルエンディアン形式のパーティションエントリー配列のCRC32                                                                                                                            |
| 92 (0x5C) | \*       | 予約済み。ブロックの残りの部分はゼロでなければならない（セクターサイズが512バイトの場合は420バイト。より大きなセクターサイズではさらに大きくなる場合がある）                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [パーティションタイプGUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs)（混合エンディアン） |
| 16 (0x10)                   | 16 bytes | 一意なパーティションGUID（混合エンディアン）                                                                          |
| 32 (0x20)                   | 8 bytes  | 最初のLBA（[リトルエンディアン](https://en.wikipedia.org/wiki/Little_endian)）                                      |
| 40 (0x28)                   | 8 bytes  | 最終LBA（包含。通常は奇数）                                                                             |
| 48 (0x30)                   | 8 bytes  | 属性フラグ（例: ビット60は読み取り専用を示す）                                                               |
| 56 (0x38)                   | 72 bytes | パーティション名（36個の[UTF-16](https://en.wikipedia.org/wiki/UTF-16)LEコードユニット）                               |

**パーティションタイプ**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | パーティション名（36個のUTF-16LEコードユニット）](<../../../images/image (83).png>)

その他のパーティションタイプについては、[https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)を参照してください。<sup>[[1]](#references)</sup>

### 確認

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)でforensics imageをマウントした後、Windowsツールの[**Active Disk Editor**](https://www.disk-editor.org/index.html)**を使って**最初のセクターを確認できます。次の画像では、**sector 0**で**MBR**が検出され、解析されています。

![GPT (GUID Partition Table) - 確認: ArsenalImageMounterでforensics imageをマウントした後、WindowsツールのActive Disk Editorを使って最初のセクターを確認できます。次の画像では...](<../../../images/image (354).png>)

GPTの場合、**LBA 1**のプライマリヘッダーにある_EFI PART_シグネチャを探してください。LBA 0には引き続きprotective MBRが格納されています。<sup>[[4]](#references)</sup>

### 一覧にないパーティション外のデータを見つける

削除されたパーティションエントリーや意図的に使用されていない領域によって、現在のパーティションマップの外側にファイルシステムが残っていることがあります。**検証済みのraw作業用コピー**で未割り当て領域を一覧表示し、候補となる開始LBAをファイルシステムとして調べてください。`mmls`と`fsstat`は**セクターオフセット**を使用します。実際の論理セクターサイズを両方に指定してください。GPTメタデータのセクターを隠しボリュームと誤認しないでください。<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

`fsstat`がギャップの開始位置でファイルシステムを識別できない場合は、TestDiskの**Analyse → Quick Search**を実行し、必要に応じて**Deeper Search**を実行します。候補を選んで`P`を押すとファイルを確認できます。証拠に対して**Write**は選択しないでください。GPTイメージでは、`sgdisk --verify disk.img`でCRCとプライマリ／バックアップ間の整合性を確認できます。ただし、パーティション再設定後はバックアップヘッダーが古くなっている場合があるため、復旧前にファイルシステム構造を使って候補の境界を照合してください。<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## ファイルシステム

### Windowsのファイルシステム一覧

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)**ファイルシステムは、その中核コンポーネントであるファイル割り当てテーブルをボリュームの先頭に配置する設計です。一般的なボリュームには**2つのFATコピー**がありますが、BPBでは1つも許容されています。FAT12/16ではルートディレクトリは固定領域に置かれます。FAT32では、`BPB_RootClus`で指定されたクラスタのデータ領域にルートディレクトリが格納されます。<sup>[[7]](#references)</sup>

割り当て単位は**クラスタ**であり、そのサイズは`BPB_BytsPerSec × BPB_SecPerClus`です。必ずしも512バイトとは限りません。FATの種類は、ブートセクター内のバージョン文字列ではなく、データクラスタ数によって決まります。クラスタ数の境界は次のとおりです。<sup>[[7]](#references)</sup>

- **FAT12**: データクラスタ数が4,085未満。
- **FAT16**: データクラスタ数が4,085～65,524。
- **FAT32**: データクラスタ数が65,525以上。各32ビットFATエントリのうち、クラスタ番号には28ビットだけが使われます。

32ビットのファイルサイズフィールドにより、通常のファイルの最大サイズは**2³²−1バイト**（4 GiB弱）に制限されます。<sup>[[7]](#references)</sup>

ルートディレクトリの主な構成要素（特にFAT12およびFAT16）は次のとおりです。

- **ファイル／フォルダー名**（最大8文字）
- **属性**
- **作成日、変更日、最終アクセス日**
- **FATテーブルアドレス**（ファイルの開始クラスタを示す）
- **ファイルサイズ**

### EXT

**Ext2**は、ブートパーティションのような**ジャーナリングを行わない**（**あまり変更されないパーティション**）ファイルシステムとして最も一般的です。**Ext3/4**は**ジャーナリングを行い**、通常は**その他のパーティション**で使われます。

## **メタデータ**

一部のファイルにはメタデータが含まれています。これはファイルの内容に関する情報であり、ファイルの種類によっては、分析者にとって興味深い情報が含まれている場合があります。たとえば次のような情報です。

- タイトル
- 使用されたMS Officeのバージョン
- 作成者
- 作成日時および最終変更日時
- カメラのモデル
- GPS座標
- 画像情報

[**exiftool**](https://exiftool.org)や[**Metadiver**](https://www.easymetadata.com/metadiver-2/)などのツールで、ファイルのメタデータを取得できます。

## **削除されたファイルの復元**

### ログに残る削除済みファイル

前述のように、ファイルが「削除」された後も、ファイルが保存されたままの場所がいくつかあります。通常、ファイルシステムからファイルを削除すると、削除済みとしてマークされるだけで、データ自体は変更されないためです。そのため、MFTなどのファイルレジストリを調べて、削除されたファイルを見つけることができます。<sup>[[2]](#references)</sup>

また、OSは通常、ファイルシステムの変更やバックアップに関する多くの情報を保存するため、それらを使ってファイル、または可能な限り多くの情報を復元できる場合があります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**は、大量のデータの中から**ファイルを見つけようとする**手法です。このようなツールの主な動作方式は3つあります。**ファイルタイプのヘッダーとフッターに基づく方式**、ファイルタイプの**構造に基づく方式**、そして**コンテンツ**自体に基づく方式です。

単純なヘッダー／フッター carving は、データブロックが連続していることを前提とするため、ファイルが分割されている場合は断片しか返せないことがあります。ただし、これは絶対的な制約ではありません。PhotoRecには、断片化した一部のJPEGを対象とするCPU負荷の高い**Paranoid → bruteforce**オプションがあり、形式を考慮した断片の再構成によって、ほかの対応形式も復元できます。現在の断片再構成ワークフローについては、[file carving and recovery tools](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving)を参照してください。<sup>[[8]](#references)</sup>

検索するファイルタイプを指定してFile Carvingを行えるツールがいくつかあります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### データストリーム **C**arving

Data Stream CarvingはFile Carvingに似ていますが、**完全なファイルではなく、興味深い情報の断片を探します**。\
たとえば、ログに記録されたURLを含む完全なファイルを探す代わりに、この手法ではURLを検索します。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### 安全な削除

もちろん、ファイルやそのログの一部を**「安全に」削除する**方法もあります。たとえば、ファイルの内容をジャンクデータで何度も**上書き**し、その後、ファイルに関する**$MFT**および**$LOGFILE**内の**ログ**を**削除**し、**Volume Shadow Copies**を**削除**できます。<sup>[[3]](#references)</sup>\
この操作を行っても、ファイルの存在が記録されたままの場所がほかにあることに気づくかもしれません。そのとおりであり、それらを見つけることもフォレンジック専門家の仕事の一部です。



## References

- [1] [GUIDパーティションテーブル - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [削除されたファイルの証拠を見つけるためにNTFS $I30（ディレクトリエントリ）をスキャンする方法](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [ボリュームシャドウコピーサービス (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [UEFI仕様: GPTディスクレイアウト](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [The Sleuth Kit mmlsマニュアル](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [The Sleuth Kit fsstatマニュアル](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Microsoft FAT仕様](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [PhotoRecの復元オプション](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [TestDiskによる削除済みパーティションの復元](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [sgdiskマニュアル](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [mount(8)マニュアル](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
