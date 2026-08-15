# パーティション/ファイルシステム/Carving

{{#include ../../../banners/hacktricks-training.md}}

## パーティション

ハードドライブまたは**SSDディスクには、データを物理的に分離する目的で異なるパーティションを含めることができます**。\
ディスクの**最小**単位は**セクター**（通常は512Bで構成）です。そのため、各パーティションのサイズはこのサイズの倍数である必要があります。

### MBR（master Boot Record）

これは、**446Bのブートコードの後にあるディスクの最初のセクター**に割り当てられます。このセクターは、どのパーティションをどこからPCにマウントすべきかを示すために不可欠です。\
最大**4つのパーティション**を使用できます（そのうち**アクティブ/**ブート可能**にできるのは最大**1つ**）。ただし、さらにパーティションが必要な場合は、**拡張パーティション**を使用できます。この最初のセクターの**最後のバイト**は、ブートレコードのシグネチャ **0x55AA** です。アクティブとしてマークできるパーティションは1つだけです。\
MBRで扱える最大容量は**2.2TB**です。

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (304).png>)

MBRの**440～443バイト**には、（Windowsが使用されている場合）**Windows Disk Signature**があります。ハードディスクの論理ドライブ文字は、Windows Disk Signatureに依存します。このシグネチャを変更すると、Windowsが起動できなくなる可能性があります（tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**。

![Partitions - MBR (master Boot Record): From the bytes 440 to the 443 of the MBR you can find the Windows Disk Signature (if Windows is used). The logical drive letter of the hard disk...](<../../../images/image (310).png>)

**形式**

| オフセット      | 長さ     | 項目                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | ブートコード           |
| 446 (0x1BE) | 16 (0x10)  | 第1パーティション     |
| 462 (0x1CE) | 16 (0x10)  | 第2パーティション    |
| 478 (0x1DE) | 16 (0x10)  | 第3パーティション     |
| 494 (0x1EE) | 16 (0x10)  | 第4パーティション     |
| 510 (0x1FE) | 2 (0x2)    | シグネチャ 0x55 0xAA |

**パーティションレコード形式**

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
| 8 (0x08)  | 4 (0x04) | パーティションより前のセクター数（リトルエンディアン）            |
| 12 (0x0C) | 4 (0x04) | パーティション内のセクター数                                   |

LinuxでMBRをマウントするには、まず開始オフセットを取得する必要があります（`fdisk`と`p`コマンドを使用できます）。

![Partitions - MBR (master Boot Record): In order to mount an MBR in Linux you first need to get the start offset (you can use fdisk and the p command)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

次に、以下のコードを使用します
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA（Logical block addressing）**

**Logical block addressing**（**LBA**）は、コンピュータのストレージデバイスに保存されたデータの**ブロックの位置を指定する**ために使用される一般的な方式であり、一般的にはハードディスクドライブなどの二次ストレージシステムで使用されます。LBAは特に単純な線形アドレス方式であり、**ブロックは整数のインデックスで位置指定されます**。最初のブロックはLBA 0、2番目はLBA 1、その後も同様です。

### GPT（GUID Partition Table）

GUID Partition Table（GPT）は、MBR（Master Boot Record）と比較して機能が強化されているため、広く使用されています。パーティションごとに**globally unique identifier**を持つことが特徴で、GPTには次のような特徴があります。

- **位置とサイズ**: GPTとMBRはいずれも**セクタ0**から開始します。ただし、GPTは**64bits**で動作するのに対し、MBRは32bitsです。
- **パーティションの上限**: GPTはWindowsシステムで最大**128個のパーティション**をサポートし、最大**9.4ZB**のデータを扱えます。
- **パーティション名**: 最大36文字のUnicode文字でパーティションに名前を付けられます。

**データの耐障害性と復旧**:

- **冗長性**: MBRとは異なり、GPTはパーティション情報とbootデータを1か所に限定しません。このデータをディスク全体に複製することで、データの完全性と耐障害性を高めます。
- **Cyclic Redundancy Check（CRC）**: GPTはデータの完全性を確保するためにCRCを使用します。データの破損を能動的に監視し、破損が検出された場合、GPTは別のディスク位置から破損したデータを復旧しようとします。

**Protective MBR（LBA0）**:

- GPTはprotective MBRによって後方互換性を維持します。この機能は従来のMBR領域に存在しますが、古いMBRベースのutilityが誤ってGPTディスクを上書きすることを防ぐよう設計されており、GPT形式のディスク上のデータの完全性を保護します。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR（LBA 0 + GPT）**

[Wikipediaより](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

EFIではなく**BIOS**サービスを通じた**GPTベースのboot**をサポートするOSでは、最初のセクタが**bootloader**コードの第1段階の保存にも引き続き使用される場合があります。ただし、**GPT** **パーティション**を認識するように**modified**されます。MBR内のbootloaderは、セクタサイズが512バイトであると想定してはなりません。

**Partition table header（LBA 1）**

[Wikipediaより](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

パーティションテーブルヘッダーは、ディスク上で使用可能なブロックを定義します。また、パーティションテーブルを構成するパーティションエントリの数とサイズも定義します（テーブル内のオフセット80および84）。

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature（"EFI PART"、45h 46h 49h 20h 50h 41h 52h 54h、またはlittle-endianマシンでは0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)） |
| 8 (0x08)  | 4 bytes  | UEFI 2.8向けRevision 1.0（00h 00h 01h 00h）                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | little endianでのHeader size（バイト単位。通常は5Ch 00h 00h 00hまたは92 bytes）                                                                                                 |
| 16 (0x10) | 4 bytes  | little endianでのheaderの[CRC32](https://en.wikipedia.org/wiki/CRC32)（offset +0からheader sizeまで）。計算時にはこのフィールドをゼロにする                             |
| 20 (0x14) | 4 bytes  | Reserved。ゼロでなければならない                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA（このheaderコピーの位置）                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA（もう一方のheaderコピーの位置）                                                                                                                               |
| 40 (0x28) | 8 bytes  | パーティションで使用可能な最初のLBA（primary partition tableの最終LBA + 1）                                                                                                       |
| 48 (0x30) | 8 bytes  | 最後に使用可能なLBA（secondary partition tableの最初のLBA − 1）                                                                                                                    |
| 56 (0x38) | 16 bytes | mixed endianでのDisk GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | パーティションエントリ配列のStarting LBA（primary copyでは常に2）                                                                                                     |
| 80 (0x50) | 4 bytes  | 配列内のパーティションエントリ数                                                                                                                                         |
| 84 (0x54) | 4 bytes  | 1つのパーティションエントリのSize（通常は80hまたは128）                                                                                                                        |
| 88 (0x58) | 4 bytes  | little endianでのパーティションエントリ配列のCRC32                                                                                                                            |
| 92 (0x5C) | \*       | Reserved。ブロックの残りの部分はゼロでなければならない（セクタサイズが512 bytesの場合は420 bytes。ただし、セクタサイズが大きい場合はさらに増える可能性がある）                                      |

**Partition entries（LBA 2–33）**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs)（mixed endian） |
| 16 (0x10)                   | 16 bytes | Unique partition GUID（mixed endian）                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA（[little endian](https://en.wikipedia.org/wiki/Little_endian)）                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA（inclusive、通常は奇数）                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags（例：bit 60はread-onlyを示す）                                                               |
| 56 (0x38)                   | 72 bytes | Partition name（36個の[UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units）                               |

**Partitions Types**

![MBR（master Boot Record） - GPT（GUID Partition Table）: 56 (0x38) | 72 bytes | Partition name（36 UTF-16LE code units）](<../../../images/image (83).png>)

その他のパーティションタイプについては、[https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)を参照してください。<sup>[[1]](#references)</sup>

### Inspecting

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)でforensics imageをmountした後、Windows toolの[**Active Disk Editor**](https://www.disk-editor.org/index.html)**.**を使用して最初のセクタをinspectできます。次の画像では、**sector 0**に**MBR**が検出され、解釈されています。

![GPT（GUID Partition Table） - Inspecting: ArsenalImageMounterでforensics imageをmountした後、Windows toolのActive Disk Editorを使用して最初のセクタをinspectできます。画像では...](<../../../images/image (354).png>)

**MBR**ではなく**GPT table**の場合、**sector 1**にsignature _EFI PART_ が表示されるはずです（前の画像では空になっている場所です）。

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT（File Allocation Table）file system**は、volumeの先頭に配置された中心的なコンポーネントであるfile allocation tableを中心に設計されています。このsystemはtableを**2つコピー**保持することでデータを保護し、一方が破損した場合でもデータの完全性を確保します。tableとroot folderは**固定位置**に配置する必要があり、これはsystemのstartup processにおいて重要です。

file systemにおける基本的なstorage unitは**cluster、通常は512B**で、複数のsectorから構成されます。FATは次のように進化してきました。

- **FAT12**: 12-bitのcluster addressをサポートし、最大4078個のcluster（UNIXでは4084個）を扱えます。
- **FAT16**: 16-bit addressに拡張され、最大65,517個のclusterを扱えます。
- **FAT32**: さらに32-bit addressへ進化し、volumeごとに最大268,435,456個のclusterを使用できます。

FATの各versionに共通する大きな制限は、file sizeの保存に使用される32-bit fieldによって**最大file sizeが4GB**に制限されることです。

root directoryの主要なcomponent、特にFAT12およびFAT16では、次のものが含まれます。

- **File/Folder Name**（最大8文字）
- **Attributes**
- **Creation、Modification、Last Access Dates**
- **FAT Table Address**（fileのstart clusterを示す）
- **File Size**

### EXT

**Ext2**は、boot partitionのような**not journaling** partition（**あまり変更されないpartition**）で最も一般的なfile systemです。**Ext3/4**は**journaling**を行い、通常は**rest partition**に使用されます。

## **Metadata**

一部のfileにはmetadataが含まれています。この情報はfileのcontentに関するもので、file typeによっては次のような情報が含まれるため、analystにとって興味深い場合があります。

- Title
- 使用されたMS Office Version
- Author
- Creationおよびlast modificationの日付
- cameraのModel
- GPS coordinates
- Image information

[**exiftool**](https://exiftool.org)や[**Metadiver**](https://www.easymetadata.com/metadiver-2/)などのtoolを使用して、fileのmetadataを取得できます。

## **Deleted Files Recovery**

### Logged Deleted Files

前述のように、fileが「deleted」された後もfileが保存されている場所がいくつかあります。これは通常、file systemからfileを削除しても、削除済みとしてmarkされるだけで、data自体には触れないためです。そのため、fileのregistry（MFTなど）をinspectして、deleted fileを見つけることが可能です。<sup>[[2]](#references)</sup>

また、OSは通常、file systemの変更やbackupに関する多くの情報を保存するため、それらを使用してfile、または可能な限り多くの情報を復旧できる可能性があります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**は、**大量のdataの中からfileを見つける**techniqueです。このようなtoolが動作する主な方法は3つあります。**file typeのheaderとfooterに基づく方法**、file typeの**structure**に基づく方法、そして**content**自体に基づく方法です。

このtechniqueは**fragmented fileの取得には機能しない**ことに注意してください。fileが**contiguous sectorに保存されていない**場合、このtechniqueではfile全体、または少なくともその一部を見つけることができません。

File Carvingには、検索するfile typeを指定して使用できるtoolがいくつかあります。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream CarvingはFile Carvingに似ていますが、**complete fileを探すのではなく、興味深い情報のfragmentを探します**。\
たとえば、logged URLを含むcomplete fileを探す代わりに、このtechniqueではURLを検索します。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

当然ながら、fileおよびfileに関するlogの一部を**「secureに」削除**する方法があります。たとえば、fileの**contentをjunk dataで複数回overwrite**してから、fileに関する**$MFT**および**$LOGFILE**の**log**を**remove**し、**Volume Shadow Copies**を**remove**できます。<sup>[[3]](#references)</sup>\
この操作を実行しても、fileの存在が**他の場所にlogとして残っている**可能性があることに気付くかもしれません。実際そのとおりであり、それらを見つけることもforensics professionalの仕事の一部です。

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [削除されたfileの証拠を見つけるためにNTFS $I30（directory）entryをscanする方法](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service（VSS）](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
