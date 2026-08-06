# パーティション/ファイルシステム/Carving

{{#include ../../../banners/hacktricks-training.md}}

## パーティション

ハードドライブまたは **SSD disk には、データを物理的に分離する目的で異なるパーティションを含めることができます**。\
ディスクの**最小**単位は**sector**（通常は512Bで構成）です。そのため、各パーティションのサイズはこのサイズの倍数である必要があります。

### MBR (master Boot Record)

これは、**446Bのboot codeの後にあるディスクの最初のsector**に割り当てられます。このsectorは、どのパーティションをどこからmountするかをPCに示すために不可欠です。\
最大**4つのパーティション**を使用できます（**active/**bootable**にできるのは最大で1つだけです）。ただし、さらにパーティションが必要な場合は、**extended partitions**を使用できます。この最初のsectorの**final byte**は、boot record signature **0x55AA**です。activeとしてマークできるパーティションは1つだけです。\
MBRは**最大2.2TB**まで対応します。

![Partitions - MBR (master Boot Record): MBRは最大2.2TBまで対応](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBRは最大2.2TBまで対応](<../../../images/image (304).png>)

MBRの**bytes 440から443**には、（Windowsが使用されている場合）**Windows Disk Signature**があります。ハードディスクのlogical drive letterはWindows Disk Signatureに依存します。このsignatureを変更すると、Windowsがbootできなくなる可能性があります（tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**）。

![Partitions - MBR (master Boot Record): MBRのbytes 440から443には、（Windowsが使用されている場合）Windows Disk Signatureがあります。ハードディスクのlogical drive letter...](<../../../images/image (310).png>)

**フォーマット**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**パーティションレコードのフォーマット**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Active flag (0x80 = bootable)                          |
| 1 (0x01)  | 1 (0x01) | Start head                                             |
| 2 (0x02)  | 1 (0x01) | Start sector (bits 0-5); upper bits of cylinder (6- 7) |
| 3 (0x03)  | 1 (0x01) | Start cylinder lowest 8 bits                           |
| 4 (0x04)  | 1 (0x01) | Partition type code (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | End head                                               |
| 6 (0x06)  | 1 (0x01) | End sector (bits 0-5); upper bits of cylinder (6- 7)   |
| 7 (0x07)  | 1 (0x01) | End cylinder lowest 8 bits                             |
| 8 (0x08)  | 4 (0x04) | Sectors preceding partition (little endian)            |
| 12 (0x0C) | 4 (0x04) | Sectors in partition                                   |

LinuxでMBRをmountするには、まずstart offsetを取得する必要があります（`fdisk`と`p`コマンドを使用できます）。

![Partitions - MBR (master Boot Record): LinuxでMBRをmountするには、まずstart offsetを取得する必要があります（fdiskとpコマンドを使用できます）](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

次に、以下のcodeを使用します。
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) は、コンピュータの storage device に保存されたデータの**ブロックの位置を指定する**ために使用される一般的な方式であり、一般に hard disk drive などの secondary storage system で使用されます。LBA は特にシンプルな線形アドレス方式です。**ブロックは整数のインデックスで特定され**、最初のブロックは LBA 0、2 番目は LBA 1、その後も同様に続きます。

### GPT (GUID Partition Table)

GUID Partition Table（GPT）は、MBR (Master Boot Record) と比較して機能が強化されているため、好まれています。パーティションに対する**globally unique identifier** が特徴であり、GPT には次のような特徴があります。

- **位置とサイズ**: GPT と MBR はどちらも**セクター 0**から開始します。ただし、GPT は **64bits** で動作するのに対し、MBR は 32bits です。
- **パーティションの上限**: GPT は Windows system 上で最大 **128 個のパーティション**をサポートし、最大 **9.4ZB** のデータを扱えます。
- **パーティション名**: 最大 36 文字の Unicode 文字でパーティションに名前を付けられます。

**データの耐障害性と Recovery**:

- **冗長性**: MBR とは異なり、GPT はパーティション情報と boot data を 1 か所に限定しません。このデータを disk 全体に複製することで、データの整合性と耐障害性を高めます。
- **Cyclic Redundancy Check (CRC)**: GPT はデータの整合性を確保するために CRC を使用します。データ corruption を能動的に監視し、検出した場合は、GPT は別の disk 上の場所から corruption したデータを recovery しようとします。

**Protective MBR (LBA0)**:

- GPT は protective MBR によって後方互換性を維持します。この機能は legacy MBR の領域に存在しますが、古い MBR ベースの utility が誤って GPT disk を上書きするのを防ぐよう設計されており、GPT 形式の disk 上のデータ整合性を保護します。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

**EFI** ではなく **BIOS** service を介した **GPT-based boot** をサポートする operating system では、最初の sector が **bootloader** code の第 1 stage の保存にも引き続き使用される場合があります。ただし、**GPT** **partition** を認識できるよう変更されています。MBR の bootloader は、sector size が 512 bytes であると仮定してはいけません。

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

partition table header は disk 上で使用可能な block を定義します。また、partition table を構成する partition entry の数とサイズ（table 内の offset 80 と 84）も定義します。

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h または little-endian machine 上では 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8 における Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | little endian での Header size（bytes 単位。通常は 5Ch 00h 00h 00h または 92 bytes）                                                                                                 |
| 16 (0x10) | 4 bytes  | little endian での header の [CRC32](https://en.wikipedia.org/wiki/CRC32)（offset +0 から header size まで）。計算時、この field は zero にする                             |
| 20 (0x14) | 4 bytes  | Reserved。zero でなければならない                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA（この header copy の位置）                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA（もう一方の header copy の位置）                                                                                                                               |
| 40 (0x28) | 8 bytes  | partition で使用可能な最初の LBA（primary partition table の last LBA + 1）                                                                                                       |
| 48 (0x30) | 8 bytes  | 使用可能な最後の LBA（secondary partition table の first LBA − 1）                                                                                                                    |
| 56 (0x38) | 16 bytes | mixed endian での Disk GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | partition entry の array の開始 LBA（primary copy では常に 2）                                                                                                     |
| 80 (0x50) | 4 bytes  | array 内の partition entry 数                                                                                                                                         |
| 84 (0x54) | 4 bytes  | 1 つの partition entry のサイズ（通常は 80h または 128）                                                                                                                        |
| 88 (0x58) | 4 bytes  | little endian での partition entry array の CRC32                                                                                                                            |
| 92 (0x5C) | \*       | Reserved。block の残りの部分は zeroes でなければならない（sector size が 512 bytes の場合は 420 bytes。ただし、sector size が大きい場合はさらに大きくなる可能性がある）                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs)（mixed endian） |
| 16 (0x10)                   | 16 bytes | Unique partition GUID（mixed endian）                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA（[little endian](https://en.wikipedia.org/wiki/Little_endian)）                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA（inclusive。通常は odd）                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags（例: bit 60 は read-only を示す）                                                               |
| 56 (0x38)                   | 72 bytes | Partition name（36 個の [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code unit）                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

その他の partition type については [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup> を参照してください。

### Inspecting

forensics image を [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) で mount した後、Windows tool の [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** を使用して最初の sector を inspect できます。次の画像では、**MBR** が**sector 0** 上で検出され、解釈されています。

![GPT (GUID Partition Table) - Inspecting: ArsenalImageMounter で forensics image を mount した後、Windows tool の Active Disk Editor を使用して最初の sector を inspect できます。次の画像では...](<../../../images/image (354).png>)

**MBR** ではなく **GPT table** の場合、**sector 1**（前の画像では空）に signature _EFI PART_ が表示されます。

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system は、その中核 component である file allocation table を volume の先頭に配置するよう設計されています。この system は table を**2 つ保持**することでデータを保護し、一方が corruption してもデータの整合性を確保します。table と root folder は**固定位置**に存在する必要があり、これは system の startup process において重要です。

file system の基本的な storage unit は**通常 512B の cluster**で、複数の sector から構成されます。FAT には次の version があります。

- **FAT12**: 12-bit の cluster address をサポートし、最大 4078 cluster（UNIX では 4084）を処理します。
- **FAT16**: 16-bit address に拡張され、最大 65,517 cluster を扱えます。
- **FAT32**: 32-bit address にさらに拡張され、1 volume あたり最大 268,435,456 cluster を扱えます。

すべての FAT version に共通する大きな制限として、file size の保存に使用される 32-bit field により、**最大 file size が 4GB** に制限されます。

root directory の主要な component、特に FAT12 と FAT16 には次のものが含まれます。

- **File/Folder Name**（最大 8 文字）
- **Attributes**
- **Creation、Modification、Last Access の日付**
- **FAT Table Address**（file の start cluster を示す）
- **File Size**

### EXT

**Ext2** は、boot partition のような**journaling を行わない**partition（**あまり変更されない partition**）で最も一般的な file system です。**Ext3/4** は **journaling** を行い、通常は**残りの partition**に使用されます。

## **Metadata**

一部の file には metadata が含まれています。この情報は file の内容に関するもので、file type によっては analyst にとって興味深い情報が含まれている場合があります。たとえば次のようなものです。

- Title
- 使用された MS Office Version
- Author
- 作成日と最終変更日
- Camera の Model
- GPS coordinates
- Image information

[**exiftool**](https://exiftool.org) や [**Metadiver**](https://www.easymetadata.com/metadiver-2/) などの tool を使用して、file の metadata を取得できます。

## **Deleted Files Recovery**

### Logged Deleted Files

前述のとおり、file が「deleted」された後も保存されている場所がいくつかあります。これは通常、file system から file を削除しても、削除済みとして mark されるだけで、データ自体には触れないためです。そのため、file の registry（MFT など）を inspect して deleted file を見つけることが可能です。<sup>[[2]](#references)</sup>

また、OS は通常、file system の変更と backup に関する多くの情報を保存するため、それらを使用して file または可能な限り多くの情報を recovery できる可能性があります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** は、**大量のデータの中から file を見つける** technique です。このような tool が動作する主な方法は 3 つあります。**file type の header と footer に基づく方法**、file type の **structure** に基づく方法、そして**content** 自体に基づく方法です。

この technique は**fragmented file の retrieve には機能しない**ことに注意してください。file が**連続した sector に保存されていない**場合、この technique では file 全体、または少なくともその一部を見つけることはできません。

File Carving には、検索対象の file type を指定して使用できる tool がいくつかあります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving は File Carving に似ていますが、**完全な file を探す代わりに、興味深い情報の fragment を探します**。\
たとえば、logged URL を含む完全な file を探す代わりに、この technique では URL を検索します。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

当然ながら、file とその file に関する log の一部を**「secure に」削除**する方法があります。たとえば、file の**content を junk data で複数回 overwrite**した後、file に関する **$MFT** と **$LOGFILE** の **log** を**削除**し、**Volume Shadow Copies** を**削除**できます。<sup>[[3]](#references)</sup>\
ただし、その操作を実行しても、file の存在が引き続き**別の場所に log されている可能性**があることに気付くかもしれません。これは事実であり、それらを見つけることは forensics professional の仕事の一部です。

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
