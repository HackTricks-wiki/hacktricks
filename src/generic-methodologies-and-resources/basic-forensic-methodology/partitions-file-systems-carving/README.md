# パーティション/ファイルシステム/Carving

{{#include ../../../banners/hacktricks-training.md}}

## パーティション

ハードドライブまたは**SSDディスクには、データを物理的に分離する目的で異なるパーティションを含めることができます**。\
ディスクの**最小**単位は**セクター**です（通常は512Bで構成されます）。そのため、各パーティションのサイズはこのサイズの倍数である必要があります。

### MBR（master Boot Record）

これは、**446Bのブートコードの後にあるディスクの最初のセクター**に割り当てられます。このセクターは、どのパーティションをどこからPCにマウントするかを示すために不可欠です。\
最大**4つのパーティション**に対応します（**アクティブ/**ブート可能**にできるのは最大1つだけです**）。ただし、さらにパーティションが必要な場合は、**拡張パーティション**を使用できます。この最初のセクターの**最後のバイト**は、ブートレコードのシグネチャ**0x55AA**です。アクティブとしてマークできるパーティションは1つだけです。\
MBRは**最大2.2TB**まで対応します。

![パーティション - MBR（master Boot Record）：MBRは最大2.2TBまで対応](<../../../images/image (350).png>)

![パーティション - MBR（master Boot Record）：MBRは最大2.2TBまで対応](<../../../images/image (304).png>)

MBRの**440～443バイト**には、（Windowsが使用されている場合）**Windows Disk Signature**があります。ハードディスクの論理ドライブ文字は、Windows Disk Signatureに依存します。このシグネチャを変更すると、Windowsが起動できなくなる可能性があります（tool：[**Active Disk Editor**](https://www.disk-editor.org/index.html)**）。

![パーティション - MBR（master Boot Record）：MBRの440～443バイトには、（Windowsが使用されている場合）Windows Disk Signatureがあります。ハードディスクの論理ドライブ文字は、Windows Disk Signatureに依存します。...](<../../../images/image (310).png>)

**フォーマット**

| オフセット      | 長さ     | 項目                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | ブートコード           |
| 446 (0x1BE) | 16 (0x10)  | 第1パーティション     |
| 462 (0x1CE) | 16 (0x10)  | 第2パーティション     |
| 478 (0x1DE) | 16 (0x10)  | 第3パーティション     |
| 494 (0x1EE) | 16 (0x10)  | 第4パーティション     |
| 510 (0x1FE) | 2 (0x2)    | シグネチャ 0x55 0xAA |

**パーティションレコードのフォーマット**

| オフセット    | 長さ   | 項目                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | アクティブフラグ（0x80 = ブート可能）                          |
| 1 (0x01)  | 1 (0x01) | 開始ヘッド                                             |
| 2 (0x02)  | 1 (0x01) | 開始セクター（ビット0～5）；シリンダー上位ビット（6～7） |
| 3 (0x03)  | 1 (0x01) | 開始シリンダー下位8ビット                           |
| 4 (0x04)  | 1 (0x01) | パーティションタイプコード（0x83 = Linux）                     |
| 5 (0x05)  | 1 (0x01) | 終了ヘッド                                               |
| 6 (0x06)  | 1 (0x01) | 終了セクター（ビット0～5）；シリンダー上位ビット（6～7）   |
| 7 (0x07)  | 1 (0x01) | 終了シリンダー下位8ビット                             |
| 8 (0x08)  | 4 (0x04) | パーティションより前にあるセクター数（リトルエンディアン）            |
| 12 (0x0C) | 4 (0x04) | パーティション内のセクター数                                   |

LinuxでMBRをマウントするには、まず開始オフセットを取得する必要があります（`fdisk`と`p`コマンドを使用できます）。

![パーティション - MBR（master Boot Record）：LinuxでMBRをマウントするには、まず開始オフセットを取得する必要があります（fdiskとpコマンドを使用できます）](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

次に、以下のコードを使用します。
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) は、コンピューターのストレージデバイス、一般的にはハードディスクドライブなどの二次ストレージシステムに保存されたデータの**ブロックの位置を指定する**ために使用される一般的な方式です。LBA は特に単純な線形アドレス方式であり、**ブロックは整数インデックスによって配置されます**。最初のブロックが LBA 0、2 番目が LBA 1、その後も同様です。

### GPT (GUID Partition Table)

GUID Partition Table（GPT）は、MBR (Master Boot Record) と比較して機能が強化されているため、好んで使用されています。パーティションに対する**グローバル一意識別子**が特徴であり、GPT には次のような特徴があります。

- **位置とサイズ**: GPT と MBR はどちらも**セクター 0**から始まります。ただし、GPT は **64bits** で動作するのに対し、MBR は 32bits です。
- **パーティションの制限**: GPT は Windows システム上で最大 **128 個のパーティション**をサポートし、最大 **9.4ZB** のデータを扱えます。
- **パーティション名**: 最大 36 文字の Unicode 文字でパーティションに名前を付けられます。

**データの耐障害性と復旧**:

- **冗長性**: MBR とは異なり、GPT はパーティション情報とブートデータを 1 か所に限定しません。これらのデータをディスク全体に複製することで、データの完全性と耐障害性を高めます。
- **巡回冗長検査 (CRC)**: GPT はデータの完全性を保証するために CRC を使用します。データの破損を能動的に監視し、破損が検出された場合は、GPT はディスク上の別の場所から破損したデータを復旧しようとします。

**Protective MBR (LBA0)**:

- GPT は Protective MBR によって後方互換性を維持します。この機能は従来の MBR 領域に存在しますが、古い MBR ベースのユーティリティが GPT ディスクを誤って上書きするのを防ぐように設計されており、GPT 形式のディスク上のデータの完全性を保護します。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Wikipedia より](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

EFI ではなく **BIOS** サービスを通じた **GPT ベースのブート**をサポートするオペレーティングシステムでは、最初のセクターが **bootloader** コードの第 1 段階の保存にも引き続き使用される場合があります。ただし、**GPT** **パーティション**を認識するように変更されています。MBR 内の bootloader は、セクターサイズが 512 bytes であると仮定してはなりません。

**Partition table header (LBA 1)**

[Wikipedia より](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

パーティションテーブルヘッダーは、ディスク上で使用可能なブロックを定義します。また、パーティションテーブルを構成するパーティションエントリの数とサイズも定義します（テーブル内のオフセット 80 と 84）。

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h または little-endian マシン上での 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h)、UEFI 2.8 用                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | little endian のヘッダーサイズ（bytes 単位、通常は 5Ch 00h 00h 00h または 92 bytes）                                                                                       |
| 16 (0x10) | 4 bytes  | little endian のヘッダーの [CRC32](https://en.wikipedia.org/wiki/CRC32)（オフセット +0 からヘッダーサイズまで）。計算時にはこのフィールドを 0 にする                       |
| 20 (0x14) | 4 bytes  | Reserved、0 でなければならない                                                                                                                                               |
| 24 (0x18) | 8 bytes  | Current LBA（このヘッダーコピーの位置）                                                                                                                                      |
| 32 (0x20) | 8 bytes  | Backup LBA（もう一方のヘッダーコピーの位置）                                                                                                                                |
| 40 (0x28) | 8 bytes  | パーティションに使用できる最初の LBA（primary partition table の最後の LBA + 1）                                                                                              |
| 48 (0x30) | 8 bytes  | 使用可能な最後の LBA（secondary partition table の最初の LBA − 1）                                                                                                            |
| 56 (0x38) | 16 bytes | mixed endian の Disk GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | パーティションエントリ配列の Starting LBA（primary copy では常に 2）                                                                                                         |
| 80 (0x50) | 4 bytes  | 配列内のパーティションエントリ数                                                                                                                                             |
| 84 (0x54) | 4 bytes  | 1 つのパーティションエントリのサイズ（通常は 80h または 128）                                                                                                                |
| 88 (0x58) | 4 bytes  | little endian のパーティションエントリ配列の CRC32                                                                                                                           |
| 92 (0x5C) | \*       | Reserved。ブロックの残りの部分は 0 でなければならない（セクターサイズが 512 bytes の場合は 420 bytes。ただし、セクターサイズが大きい場合はさらに増える可能性がある）      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs)（mixed endian） |
| 16 (0x10)                   | 16 bytes | 一意のパーティション GUID（mixed endian）                                                                      |
| 32 (0x20)                   | 8 bytes  | First LBA（[little endian](https://en.wikipedia.org/wiki/Little_endian)）                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA（inclusive、通常は奇数）                                                                              |
| 48 (0x30)                   | 8 bytes  | Attribute flags（例: bit 60 は read-only を示す）                                                               |
| 56 (0x38)                   | 72 bytes | パーティション名（36 個の [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units）                         |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

その他のパーティションタイプについては [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table) を参照してください。

### Inspecting

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) で forensics image を mount した後、Windows ツールの [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** を使用して最初のセクターを調査できます。以下の画像では、**MBR** が**セクター 0**で検出され、解釈されています。

![GPT (GUID Partition Table) - Inspecting: ArsenalImageMounter で forensics image を mount した後、Windows ツールの Active Disk Editor を使用して最初のセクターを調査できます。以下の画像では...](<../../../images/image (354).png>)

**MBR** ではなく **GPT table** の場合、**sector 1**（前の画像では空）に _EFI PART_ という signature が表示されます。

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system は、その中核コンポーネントである file allocation table を volume の先頭に配置する設計になっています。このシステムは、table のコピーを**2 つ**保持することでデータを保護し、一方が破損してもデータの完全性を維持します。table と root folder は、システムの startup process に不可欠であるため、**固定された場所**に配置される必要があります。

file system の基本的な storage unit は **cluster（通常は 512B）**で、複数の sector から構成されます。FAT は次のように進化してきました。

- **FAT12**: 12-bit の cluster address をサポートし、最大 4078 個の cluster（UNIX では 4084 個）を扱えます。
- **FAT16**: 16-bit address に拡張され、最大 65,517 個の cluster を扱えます。
- **FAT32**: 32-bit address にさらに拡張され、volume あたり最大 268,435,456 個の cluster を扱えます。

FAT の各バージョンに共通する大きな制限は、file size の保存に使用される 32-bit field による **4GB の最大ファイルサイズ**です。

root directory の主要なコンポーネント、特に FAT12 と FAT16 では、次のものが含まれます。

- **File/Folder Name**（最大 8 文字）
- **Attributes**
- **Creation、Modification、Last Access の日付**
- **FAT Table Address**（ファイルの start cluster を示す）
- **File Size**

### EXT

**Ext2** は、boot partition のような **journaling を行わない**パーティション（**あまり変更されないパーティション**）で最も一般的な file system です。**Ext3/4** は **journaling** を行い、通常は**その他のパーティション**に使用されます。

## **Metadata**

一部のファイルには metadata が含まれています。この情報はファイルの内容に関するもので、ファイルタイプによっては analyst にとって興味深い情報が含まれている場合があります。

- Title
- 使用された MS Office Version
- Author
- Creation および last modification の日付
- カメラの Model
- GPS coordinates
- Image information

[**exiftool**](https://exiftool.org) や [**Metadiver**](https://www.easymetadata.com/metadiver-2/) などの tools を使用して、ファイルの metadata を取得できます。

## **Deleted Files Recovery**

### Logged Deleted Files

前述のとおり、ファイルが「deleted」された後も保存されている場所がいくつかあります。これは通常、file system からファイルを削除しても、削除済みとしてマークされるだけで、データ自体には変更が加えられないためです。そのため、ファイルの registry（MFT など）を調査し、deleted files を見つけることが可能です。<sup>[[2]](#references)</sup>

また、OS は通常、file system の変更や backup に関する多くの情報を保存するため、それらを使用してファイル、または可能な限り多くの情報を復旧できる可能性があります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** は、**大量のデータの中からファイルを見つける**ための technique です。このような tools が動作する主な方法は 3 つあります。**file types の headers と footers に基づく方法**、file types の **structures に基づく方法**、そして**content 自体に基づく方法**です。

この technique は **fragmented files の取得には機能しない**ことに注意してください。ファイルが**連続した sectors に保存されていない**場合、この technique ではファイル全体、または少なくともその一部を見つけることができません。

File Carving には、検索対象の file types を指定して使用できる tools が複数あります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving は File Carving に似ていますが、**完全なファイルを探すのではなく、興味深い情報の断片を探します**。\
たとえば、logged URLs を含む完全なファイルを探す代わりに、この technique は URLs を検索します。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

当然ながら、ファイルとそのファイルに関する logs の一部を**「secure に」削除する**方法があります。たとえば、ファイルの**content を junk data で複数回 overwrite**し、その後、ファイルに関する **$MFT** と **$LOGFILE** の **logs** を**削除**し、さらに **Volume Shadow Copies** を**削除**できます。<sup>[[3]](#references)</sup>\
この操作を実行しても、ファイルの存在が記録された**他の場所**が残っている可能性があることに気付くでしょう。これは事実であり、それらを見つけることは forensics professional の仕事の一部です。

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [削除されたファイルの証拠を求めて NTFS $I30 (directory) entries を scan する方法](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
