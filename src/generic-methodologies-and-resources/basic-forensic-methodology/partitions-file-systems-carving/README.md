# 分区/文件系统/Carving

{{#include ../../../banners/hacktricks-training.md}}

## 分区

硬盘或 **SSD disk 可以包含不同的分区**，用于在物理上分隔数据。\
磁盘的**最小**单位是**扇区**（通常由 512B 组成）。因此，每个分区的大小必须是该大小的倍数。

### MBR (master Boot Record)

它位于**磁盘的第一个扇区中，紧接着 446B 的 boot code 之后**。该扇区对于指示 PC 应挂载哪个分区以及从何处挂载分区至关重要。\
它最多支持 **4 个分区**（最多**只能有 1 个**处于 active/**bootable** 状态）。但是，如果需要更多分区，可以使用 **extended partitions**。该第一个扇区的**最后一个字节**是 boot record signature **0x55AA**。只能将一个分区标记为 active。\
MBR 支持的最大容量为 **2.2TB**。

![分区 - MBR (master Boot Record)：MBR 支持的最大容量为 2.2TB](<../../../images/image (350).png>)

![分区 - MBR (master Boot Record)：MBR 支持的最大容量为 2.2TB](<../../../images/image (304).png>)

在 MBR 的 **440 到 443 字节**中，可以找到 **Windows Disk Signature**（如果使用 Windows）。硬盘的逻辑驱动器号取决于 Windows Disk Signature。更改此 signature 可能会导致 Windows 无法 boot（工具：[**Active Disk Editor**](https://www.disk-editor.org/index.html)**）。

![分区 - MBR (master Boot Record)：在 MBR 的 440 到 443 字节中，可以找到 Windows Disk Signature（如果使用 Windows）。硬盘的逻辑驱动器号……](<../../../images/image (310).png>)

**格式**

| 偏移量      | 长度       | 项目                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**分区记录格式**

| 偏移量    | 长度     | 项目                                                   |
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

为了在 Linux 中挂载 MBR，首先需要获取 start offset（可以使用 `fdisk` 和 `p` 命令）。

![分区 - MBR (master Boot Record)：为了在 Linux 中挂载 MBR，首先需要获取 start offset（可以使用 fdisk 和 p 命令）](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

然后使用以下 code
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing**（**LBA**）是一种常见方案，用于**指定计算机存储设备中数据块的位置**，通常用于硬盘驱动器等二级存储系统。LBA 是一种非常简单的线性寻址方案；**数据块通过整数索引定位**，第一个数据块为 LBA 0，第二个为 LBA 1，依此类推。

### GPT (GUID Partition Table)

GUID Partition Table（称为 GPT）因其相比 MBR（Master Boot Record）增强的功能而更受青睐。GPT 的显著特点是为分区提供**全局唯一标识符**，并在以下方面表现突出：

- **位置和大小**：GPT 和 MBR 都从**扇区 0**开始。但是，GPT 使用 **64bits**，而 MBR 使用 32bits。
- **分区限制**：GPT 在 Windows 系统上最多支持 **128 个分区**，并可容纳最多 **9.4ZB** 的数据。
- **分区名称**：支持使用最多 36 个 Unicode 字符命名分区。

**数据弹性和恢复**：

- **冗余**：与 MBR 不同，GPT 不会将分区和 boot 数据限制在单一位置。它会在磁盘中复制这些数据，从而增强数据完整性和弹性。
- **循环冗余校验（CRC）**：GPT 使用 CRC 确保数据完整性。它会主动监控数据损坏情况，并在检测到损坏时尝试从磁盘的其他位置恢复损坏的数据。

**保护性 MBR（LBA0）**：

- GPT 通过保护性 MBR 保持向后兼容性。此功能位于传统 MBR 空间中，但其设计目的是防止旧版基于 MBR 的工具错误覆盖 GPT 磁盘，从而保护 GPT 格式磁盘上的数据完整性。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

在通过 **BIOS** 服务而非 EFI 支持**基于 GPT 的 boot** 的操作系统中，第一个扇区可能仍用于存储 **bootloader** 代码的第一阶段，但会对其进行**修改**，使其能够识别 **GPT** **分区**。MBR 中的 bootloader 不得假设扇区大小为 512 字节。

**分区表头（LBA 1）**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

分区表头定义了磁盘上可用的数据块。它还定义了组成分区表的分区条目数量和大小（表中的偏移量 80 和 84）。

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)on little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) for UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size in little endian (in bytes, usually 5Ch 00h 00h 00h or 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) of header (offset +0 up to header size) in little endian, with this field zeroed during calculation                             |
| 20 (0x14) | 4 bytes  | Reserved; must be zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (location of this header copy)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (location of the other header copy)                                                                                                                               |
| 40 (0x28) | 8 bytes  | First usable LBA for partitions (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Disk GUID in mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Starting LBA of an array of partition entries (always 2 in primary copy)                                                                                                     |
| 80 (0x50) | 4 bytes  | Number of partition entries in array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Size of a single partition entry (usually 80h or 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 of partition entries array in little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; must be zeroes for the rest of the block (420 bytes for a sector size of 512 bytes; but can be more with larger sector sizes)                                      |

**分区条目（LBA 2–33）**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

更多分区类型请参见 [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

### 检查

使用 [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) 挂载 forensic image 后，可以使用 Windows 工具 [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** 检查第一个扇区。在下图中，**sector 0** 上检测到了一个 **MBR**，并对其进行了分析：

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

如果是 **GPT table 而不是 MBR**，则应在 **sector 1** 中看到签名 _EFI PART_（在前一张图中该扇区为空）。

## 文件系统

### Windows 文件系统列表

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT（File Allocation Table）**文件系统围绕其核心组件 file allocation table 设计，该表位于 volume 的起始位置。该系统通过维护该表的**两个副本**来保护数据，即使其中一个副本损坏，也能确保数据完整性。该表以及 root folder 必须位于**固定位置**，这对系统启动过程至关重要。

文件系统的基本存储单位是 **cluster，通常为 512B**，由多个扇区组成。FAT 已发展出多个版本：

- **FAT12**，支持 12-bit cluster 地址，最多处理 4078 个 cluster（使用 UNIX 时为 4084 个）。
- **FAT16**，将地址扩展为 16-bit，因此最多可容纳 65,517 个 cluster。
- **FAT32**，进一步使用 32-bit 地址，使每个 volume 最多可容纳 268,435,456 个 cluster。

所有 FAT 版本的一个重要限制是**4GB 的最大文件大小**，这是由用于存储文件大小的 32-bit 字段造成的。

root directory 的关键组件，尤其是 FAT12 和 FAT16 中的组件，包括：

- **File/Folder Name**（最多 8 个字符）
- **Attributes**
- **Creation、Modification 和 Last Access Dates**
- **FAT Table Address**（表示文件的起始 cluster）
- **File Size**

### EXT

**Ext2** 是最常见的用于**不进行 journaling** 的分区（**不经常发生变化的分区**，例如 boot 分区）的文件系统。**Ext3/4** 支持 **journaling**，通常用于**其余分区**。

## **Metadata**

一些文件包含 metadata。这些信息描述文件的内容，有时可能对 analyst 很有价值，因为根据文件类型的不同，其中可能包含以下信息：

- Title
- 使用的 MS Office Version
- Author
- Creation 和 last modification 的日期
- Camera 的 Model
- GPS coordinates
- Image information

可以使用 [**exiftool**](https://exiftool.org) 和 [**Metadiver**](https://www.easymetadata.com/metadiver-2/) 等工具获取文件的 metadata。

## **已删除文件恢复**

### 已记录的已删除文件

如前所述，文件在被“删除”后，仍可能保存在多个位置。这是因为从文件系统中删除文件通常只会将其标记为已删除，而不会触碰数据。因此，可以检查文件的 registry（例如 MFT），并找到已删除的文件。<sup>[[2]](#references)</sup>

此外，OS 通常会保存大量关于文件系统变更和 backups 的信息，因此可以尝试利用这些信息恢复文件，或恢复尽可能多的信息。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** 是一种尝试在**大量数据中查找文件**的技术。这类工具主要有 3 种工作方式：**基于文件类型的 headers 和 footers**、基于文件类型的 **structures**，以及基于文件**本身的 content**。

请注意，这种技术**无法恢复 fragmented files**。如果文件**没有存储在连续扇区中**，那么该技术将无法找到文件，或者至少无法找到文件的完整内容。

有多种工具可用于 file Carving，并可以指定要搜索的文件类型。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving 与 File Carving 类似，但**它不是查找完整文件，而是查找有价值的信息片段**。\
例如，这种技术不会查找包含已记录 URLs 的完整文件，而是搜索 URLs。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

显然，有一些方法可以**“安全地”删除文件以及关于文件的部分 logs**。例如，可以将文件的 **content** 多次覆盖为无意义的数据，然后从 **$MFT** 和 **$LOGFILE** 中删除关于该文件的 **logs**，并**删除 Volume Shadow Copies**。<sup>[[3]](#references)</sup>\
你可能会注意到，即使执行了这些操作，仍可能存在**其他记录文件存在的部分**，这确实如此，而 forensic professional 的部分工作就是找到这些记录。

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [如何扫描 NTFS $I30（目录）条目以寻找已删除文件的证据](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [卷影复制服务（VSS）](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
