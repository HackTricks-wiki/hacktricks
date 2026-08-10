# パーティション/ファイルシステム/Carving

## パーティション

ハードドライブまたは **SSD disk には、データを物理的に分離する目的で異なるパーティションを含めることができます**。\
ディスクの **最小** 単位は **sector**（通常は512Bで構成される）です。そのため、各パーティションのサイズはこのサイズの倍数である必要があります。

### MBR (master Boot Record)

これは、**446Bのboot codeの後にあるディスクの最初のsector** に割り当てられます。このsectorは、どのパーティションをどこからPCにmountするかを示すために不可欠です。\
最大 **4つのパーティション** を使用できます（**active/**bootable**にできるのは最大** 1つだけです）。ただし、さらにパーティションが必要な場合は、**extended partitions** を使用できます。この最初のsectorの **final byte** は、boot record signature **0x55AA** です。activeとしてマークできるパーティションは1つだけです。\
MBRは **最大2.2TB** を許可します。

![Partitions - MBR (master Boot Record): MBRは最大2.2TBを許可します](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBRは最大2.2TBを許可します](<../../../images/image (304).png>)

MBRの **bytes 440から443** には、（Windowsが使用されている場合）**Windows Disk Signature** があります。ハードディスクのlogical drive letterはWindows Disk Signatureに依存します。このsignatureを変更すると、Windowsがbootできなくなる可能性があります（tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**。

![Partitions - MBR (master Boot Record): MBRのbytes 440から443には、（Windowsが使用されている場合）Windows Disk Signatureがあります。ハードディスクのlogical drive letterはWindows Disk Signatureに依存します...](<../../../images/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Partition Record Format**

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

LinuxでMBRをmountするには、まずstart offsetを取得する必要があります（`fdisk`と`p` commandを使用できます）。

![Partitions - MBR (master Boot Record): LinuxでMBRをmountするには、まずstart offsetを取得する必要があります（fdiskとp commandを使用できます）](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

そして、次のcodeを使用します
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) は、コンピューターのストレージデバイス、一般的にはハードディスクドライブなどの二次ストレージシステムに保存されたデータの**ブロックの位置を指定するため**に使用される一般的な方式です。LBA は特にシンプルな線形アドレス方式であり、**ブロックは整数インデックスによって位置が指定されます**。最初のブロックは LBA 0、2 番目は LBA 1、その後も同様です。

### GPT (GUID Partition Table)

GUID Partition Table（GPT）は、MBR（Master Boot Record）と比較して機能が強化されているため、広く使用されています。パーティションに対する**グローバル一意識別子**を持つことが特徴で、GPT には以下のような特徴があります。

- **位置とサイズ**: GPT と MBR はどちらも**セクター 0**から始まります。ただし、GPT は **64bits** で動作するのに対し、MBR は 32bits です。
- **パーティション数の制限**: GPT は Windows システム上で最大 **128 個のパーティション**をサポートし、最大 **9.4ZB** のデータを扱えます。
- **パーティション名**: 最大 36 文字の Unicode を使用してパーティションに名前を付けられます。

**データの耐障害性とリカバリ**:

- **冗長性**: MBR とは異なり、GPT はパーティション情報とブート情報を 1 か所に限定しません。これらのデータをディスク全体に複製することで、データの完全性と耐障害性を高めています。
- **Cyclic Redundancy Check (CRC)**: GPT はデータの完全性を確認するために CRC を使用します。データの破損を能動的に監視し、破損が検出された場合、GPT は別のディスク位置から破損したデータをリカバリしようとします。

**Protective MBR (LBA0)**:

- GPT は Protective MBR によって後方互換性を維持します。この機能は従来の MBR 領域に存在しますが、古い MBR ベースのユーティリティが GPT ディスクを誤って上書きするのを防ぐよう設計されており、GPT でフォーマットされたディスク上のデータの完全性を保護します。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Wikipedia より](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

EFI ではなく **BIOS** サービスを介した **GPT ベースのブート**をサポートするオペレーティングシステムでは、最初のセクターが **bootloader** コードの第 1 段階の保存にも使用される場合があります。ただし、**GPT** **partitions** を認識できるように**変更**されています。MBR 内の bootloader は、セクターサイズが 512 バイトであると仮定してはいけません。

**Partition table header (LBA 1)**

[Wikipedia より](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

パーティションテーブルヘッダーは、ディスク上で使用可能なブロックを定義します。また、パーティションテーブルを構成するパーティションエントリの数とサイズも定義します（テーブル内のオフセット 80 と 84）。

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h または 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)little-endian マシン上) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8 における Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | little endian のヘッダーサイズ（バイト単位。通常は 5Ch 00h 00h 00h または 92 バイト）                                                                                                 |
| 16 (0x10) | 4 bytes  | little endian のヘッダーの [CRC32](https://en.wikipedia.org/wiki/CRC32)（オフセット +0 からヘッダーサイズまで）。計算時にはこのフィールドをゼロにする                             |
| 20 (0x14) | 4 bytes  | Reserved。ゼロでなければならない                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA（このヘッダーコピーの位置）                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA（もう一方のヘッダーコピーの位置）                                                                                                                               |
| 40 (0x28) | 8 bytes  | パーティションで使用可能な最初の LBA（primary partition table の最終 LBA + 1）                                                                                                       |
| 48 (0x30) | 8 bytes  | 使用可能な最後の LBA（secondary partition table の最初の LBA − 1）                                                                                                                    |
| 56 (0x38) | 16 bytes | mixed endian の Disk GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | パーティションエントリ配列の開始 LBA（primary copy では常に 2）                                                                                                     |
| 80 (0x50) | 4 bytes  | 配列内のパーティションエントリ数                                                                                                                                         |
| 84 (0x54) | 4 bytes  | 1 つのパーティションエントリのサイズ（通常は 80h または 128）                                                                                                                        |
| 88 (0x58) | 4 bytes  | little endian のパーティションエントリ配列の CRC32                                                                                                                            |
| 92 (0x5C) | \*       | Reserved。ブロックの残りの部分はゼロでなければならない（セクターサイズが 512 バイトの場合は 420 バイト。ただし、セクターサイズが大きい場合はさらに増える可能性がある）                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs)（mixed endian） |
| 16 (0x10)                   | 16 bytes | 一意なパーティション GUID（mixed endian）                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA（[little endian](https://en.wikipedia.org/wiki/Little_endian)）                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA（inclusive、通常は奇数）                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags（例: bit 60 は read-only を示す）                                                               |
| 56 (0x38)                   | 72 bytes | Partition name（36 個の [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units）                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

その他のパーティションタイプについては [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

### Inspecting

forensics image を [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) でマウントした後、Windows ツールの [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** を使用して最初のセクターを調査できます。次の画像では、**sector 0** に **MBR** が検出され、解釈されています。

![GPT (GUID Partition Table) - Inspecting: ArsenalImageMounter で forensics image をマウントした後、Windows ツールの Active Disk Editor を使用して最初のセクターを調査できます。次の画像では...](<../../../images/image (354).png>)

**MBR** ではなく **GPT table** の場合、**sector 1**（前の画像では空）に _EFI PART_ という signature が表示されます。

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system は、その中核となる file allocation table を volume の先頭に配置する設計になっています。このシステムは table を**2 コピー**保持することでデータを保護し、一方が破損した場合でもデータの完全性を確保します。table と root folder は**固定位置**に存在する必要があり、これはシステムの startup process において重要です。

file system の基本的なストレージ単位は、複数のセクターで構成される **cluster（通常は 512B）** です。FAT には次のようなバージョンがあります。

- **FAT12**: 12-bit の cluster address をサポートし、最大 4078 個の cluster（UNIX では 4084 個）を扱います。
- **FAT16**: 16-bit address に拡張され、最大 65,517 個の cluster を扱えます。
- **FAT32**: さらに 32-bit address に拡張され、volume あたり最大 268,435,456 個の cluster を扱えます。

FAT の全バージョンに共通する大きな制限は、**最大ファイルサイズが 4GB** であることです。これはファイルサイズの保存に使用される 32-bit field によるものです。

root directory の主要な構成要素、特に FAT12 と FAT16 には、以下が含まれます。

- **File/Folder Name**（最大 8 文字）
- **Attributes**
- **Creation, Modification, and Last Access Dates**
- **FAT Table Address**（ファイルの start cluster を示す）
- **File Size**

### EXT

**Ext2** は、boot partition のような **not journaling** partition（**あまり変更されない partition**）で最も一般的な file system です。**Ext3/4** は **journaling** であり、通常は**その他の partition**に使用されます。

## **Metadata**

一部のファイルには metadata が含まれています。この情報はファイルの内容に関するもので、ファイルタイプによっては analyst にとって興味深い情報が含まれている場合があります。例えば以下のような情報です。

- Title
- 使用された MS Office Version
- Author
- 作成日時と最終変更日時
- カメラの Model
- GPS coordinates
- Image information

[**exiftool**](https://exiftool.org) や [**Metadiver**](https://www.easymetadata.com/metadiver-2/) などの tools を使用して、ファイルの metadata を取得できます。

## **Deleted Files Recovery**

### Logged Deleted Files

前述のとおり、ファイルが「deleted」された後も、ファイルが保存されたままになっている場所がいくつかあります。これは通常、file system からファイルを削除しても、削除済みとしてマークされるだけで、データ自体は変更されないためです。そのため、ファイルの registry（MFT など）を調査し、deleted files を見つけることが可能です。<sup>[[2]](#references)</sup>

また、OS は通常、file system の変更や backups に関する多くの情報を保存するため、それらを使用してファイル、または可能な限り多くの情報をリカバリできる可能性があります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** は、**大量のデータの中からファイルを見つける** technique です。このような tools が動作する主な方法は 3 つあります。**file types の headers と footers に基づく方法**、file types の **structures** に基づく方法、そして**content**自体に基づく方法です。

この technique は**fragmented files の取得には機能しない**ことに注意してください。ファイルが**連続したセクターに保存されていない**場合、この technique ではファイル全体、または少なくともその一部を見つけることができません。

File Carving には、検索したい file types を指定して使用できる tools がいくつかあります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving は File Carving に似ていますが、**完全なファイルを探すのではなく、興味深い情報の断片を探します**。\
例えば、logged URLs を含む完全なファイルを探す代わりに、この technique は URLs を検索します。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

当然ながら、ファイルやファイルに関する logs の一部を**「securely」削除**する方法があります。例えば、ファイルの**content を junk data で複数回 overwrite**し、その後、ファイルに関する **$MFT** と **$LOGFILE** から **logs** を**削除**し、**Volume Shadow Copies** を**削除**できます。<sup>[[3]](#references)</sup>\
ただし、その操作を実行しても、ファイルの存在が記録されたままになっている**別の場所**が存在する可能性があることに気付くでしょう。これは事実であり、それらを見つけることも forensics professional の仕事の一部です。

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [NTFS $I30（directory）エントリをスキャンして deleted files の証拠を探す方法](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
