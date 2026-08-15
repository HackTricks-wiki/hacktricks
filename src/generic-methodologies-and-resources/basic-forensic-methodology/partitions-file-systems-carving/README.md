# 分区/文件系统/Carving

{{#include ../../../banners/hacktricks-training.md}}

## 分区

硬盘或 **SSD 磁盘可以包含不同的分区**，目的是在物理上分隔数据。\
磁盘的**最小**单位是**扇区**（通常由 512B 组成）。因此，每个分区的大小都必须是该大小的倍数。

### MBR（主引导记录）

它位于**磁盘的第一个扇区中，紧接着 446B 的引导代码之后**。该扇区对于向 PC 指示应挂载哪个分区以及从何处挂载分区至关重要。\
它最多支持 **4 个分区**（最多**只有 1 个**可以处于活动/**可引导**状态）。但是，如果需要更多分区，可以使用**扩展分区**。该第一个扇区的**最后一个字节**是引导记录签名 **0x55AA**。只有一个分区可以标记为活动分区。\
MBR 支持的最大容量为 **2.2TB**。

![分区 - MBR（主引导记录）：MBR 支持的最大容量为 2.2TB](<../../../images/image (350).png>)

![分区 - MBR（主引导记录）：MBR 支持的最大容量为 2.2TB](<../../../images/image (304).png>)

在 MBR 的 **440 到 443 字节**中，可以找到 **Windows 磁盘签名**（如果使用 Windows）。硬盘的逻辑驱动器号取决于 Windows 磁盘签名。更改此签名可能会导致 Windows 无法启动（工具：[**Active Disk Editor**](https://www.disk-editor.org/index.html)**）。

![分区 - MBR（主引导记录）：在 MBR 的 440 到 443 字节中，可以找到 Windows 磁盘签名（如果使用 Windows）。硬盘的逻辑驱动器号……](<../../../images/image (310).png>)

**格式**

| 偏移量      | 长度       | 项目                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | 引导代码            |
| 446 (0x1BE) | 16 (0x10)  | 第一个分区          |
| 462 (0x1CE) | 16 (0x10)  | 第二个分区          |
| 478 (0x1DE) | 16 (0x10)  | 第三个分区          |
| 494 (0x1EE) | 16 (0x10)  | 第四个分区          |
| 510 (0x1FE) | 2 (0x2)    | 签名 0x55 0xAA      |

**分区记录格式**

| 偏移量    | 长度     | 项目                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | 活动标志（0x80 = 可引导）                              |
| 1 (0x01)  | 1 (0x01) | 起始磁头                                             |
| 2 (0x02)  | 1 (0x01) | 起始扇区（位 0-5）；柱面的高位（6-7）                 |
| 3 (0x03)  | 1 (0x01) | 起始柱面的最低 8 位                                   |
| 4 (0x04)  | 1 (0x01) | 分区类型代码（0x83 = Linux）                           |
| 5 (0x05)  | 1 (0x01) | 结束磁头                                             |
| 6 (0x06)  | 1 (0x01) | 结束扇区（位 0-5）；柱面的高位（6-7）                 |
| 7 (0x07)  | 1 (0x01) | 结束柱面的最低 8 位                                   |
| 8 (0x08)  | 4 (0x04) | 分区之前的扇区数（小端序）                             |
| 12 (0x0C) | 4 (0x04) | 分区中的扇区数                                         |

为了在 Linux 中挂载 MBR，首先需要获取起始偏移量（可以使用 `fdisk` 和 `p` 命令）

![分区 - MBR（主引导记录）：为了在 Linux 中挂载 MBR，首先需要获取起始偏移量（可以使用 fdisk 和 p 命令）](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

然后使用以下代码
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA（Logical block addressing）**

**Logical block addressing**（**LBA**）是一种常见方案，用于**指定计算机存储设备上数据块的位置**，通常用于硬盘驱动器等辅助存储系统。LBA 是一种特别简单的线性寻址方案；**数据块通过整数索引定位**，第一个数据块为 LBA 0，第二个为 LBA 1，依此类推。

### GPT（GUID Partition Table）

GUID Partition Table，简称 GPT。与 MBR（Master Boot Record）相比，GPT 因其更强的功能而更受青睐。GPT 以分区的**全局唯一标识符**为特征，主要具有以下特点：

- **位置和大小**：GPT 和 MBR 都从**扇区 0**开始。但是，GPT 使用 **64bits**，而 MBR 使用 32bits。
- **分区限制**：GPT 在 Windows 系统上最多支持 **128 个分区**，并可容纳最多 **9.4ZB** 的数据。
- **分区名称**：支持使用最多 36 个 Unicode 字符命名分区。

**数据可靠性和恢复**：

- **冗余**：与 MBR 不同，GPT 不会将分区和引导数据限制在单一位置。它会在磁盘上复制这些数据，从而增强数据完整性和弹性。
- **循环冗余校验（CRC）**：GPT 使用 CRC 确保数据完整性。它会主动监控数据损坏情况；检测到损坏后，GPT 会尝试从磁盘的其他位置恢复损坏的数据。

**保护性 MBR（LBA0）**：

- GPT 通过保护性 MBR 保持向后兼容。此功能位于传统 MBR 空间中，但设计目的是防止旧版基于 MBR 的工具错误覆盖 GPT 磁盘，从而保护 GPT 格式磁盘上的数据完整性。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR（LBA 0 + GPT）**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

在通过 BIOS 服务而不是 EFI 支持**基于 GPT 的引导**的操作系统中，第一个扇区也可能仍被用于存储**bootloader**代码的第一阶段，但该代码会被**修改**为能够识别 **GPT** **分区**。MBR 中的 bootloader 不得假设扇区大小为 512 字节。

**分区表头（LBA 1）**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

分区表头定义磁盘上可用的数据块。它还定义组成分区表的分区条目数量和大小（表中的偏移量 80 和 84）。

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)on little-endian machines) |
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

**分区类型**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

更多分区类型参见 [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

### 检查

使用 [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) 挂载取证镜像后，可以使用 Windows 工具 [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** 检查第一个扇区。在下图中，**sector 0** 上检测到 **MBR** 并对其进行了分析：

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

如果是 **GPT 表而不是 MBR**，则 **sector 1** 中应显示签名 _EFI PART_（在前一张图中该扇区为空）。

## 文件系统

### Windows 文件系统列表

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT（File Allocation Table）**文件系统围绕其核心组件文件分配表设计，该表位于卷的起始位置。该系统通过维护**两份表副本**来保护数据，即使其中一份损坏，也能确保数据完整性。该表以及根文件夹必须位于**固定位置**，这对系统启动过程至关重要。

该文件系统的基本存储单位是**簇，通常为 512B**，由多个扇区组成。FAT 已演变出多个版本：

- **FAT12**，支持 12 位簇地址，最多处理 4078 个簇（使用 UNIX 时为 4084 个）。
- **FAT16**，扩展为 16 位地址，因此最多可容纳 65,517 个簇。
- **FAT32**，进一步采用 32 位地址，允许每个卷包含最多 268,435,456 个簇。

所有 FAT 版本的一个重要限制是**4GB 的最大文件大小**，这是由用于存储文件大小的 32 位字段造成的。

根目录的关键组件，尤其是 FAT12 和 FAT16 中的组件，包括：

- **文件/文件夹名称**（最多 8 个字符）
- **属性**
- **创建、修改和最后访问日期**
- **FAT 表地址**（表示文件的起始簇）
- **文件大小**

### EXT

**Ext2** 是**非 journaling** 分区（**变化不频繁的分区**）最常见的文件系统，例如 boot 分区。**Ext3/4** 支持 **journaling**，通常用于**其余分区**。

## **Metadata**

某些文件包含 metadata。这些信息描述文件内容，对分析人员来说有时很有价值，因为根据文件类型的不同，其中可能包含以下信息：

- 标题
- 使用的 MS Office 版本
- 作者
- 创建和最后修改日期
- 相机型号
- GPS 坐标
- 图像信息

可以使用 [**exiftool**](https://exiftool.org) 和 [**Metadiver**](https://www.easymetadata.com/metadiver-2/) 等工具获取文件的 metadata。

## **已删除文件恢复**

### 已记录的已删除文件

如前所述，文件在被“删除”后，仍可能保存在多个位置。这是因为从文件系统中删除文件通常只会将其标记为已删除，而不会触碰数据。因此，可以检查文件的注册表（例如 MFT），并找到已删除的文件。<sup>[[2]](#references)</sup>

此外，OS 通常会保存大量有关文件系统更改和备份的信息，因此可以尝试利用这些信息恢复文件，或尽可能多地恢复相关信息。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** 是一种尝试**在大量数据中查找文件**的技术。这类工具主要有 3 种工作方式：**基于文件类型的 headers 和 footers**、基于文件类型的**结构**，以及基于文件**内容**本身。

注意，该技术**无法用于恢复 fragmented files**。如果文件**未存储在连续扇区中**，则该技术无法找到完整文件，至少无法找到文件的完整内容。

有多种工具可用于 File Carving，并指定要搜索的文件类型。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving 与 File Carving 类似，但**不是查找完整文件，而是查找有价值的信息片段**。\
例如，该技术不会查找包含已记录 URL 的完整文件，而是搜索 URL。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

显然，有多种方法可以**“安全地”删除文件以及有关文件的部分日志**。例如，可以使用垃圾数据多次**覆盖文件内容**，然后从 **$MFT** 和 **$LOGFILE** 中**删除**有关该文件的**日志**，并**删除 Volume Shadow Copies**。<sup>[[3]](#references)</sup>\
需要注意的是，即使执行了这些操作，可能仍有**其他位置记录着文件的存在**；这确实如此，而取证专业人员的部分工作就是找到这些记录。

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [扫描 NTFS $I30（目录）条目以查找已删除文件的证据](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
