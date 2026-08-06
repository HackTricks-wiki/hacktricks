# 分区/文件系统/文件雕刻

{{#include ../../../banners/hacktricks-training.md}}

## 分区

硬盘或 **SSD disk 可以包含不同的分区**，目的是在物理上分隔数据。\
磁盘的**最小**单位是 **sector**（通常由 512B 组成）。因此，每个分区的大小必须是该大小的倍数。

### MBR（master Boot Record）

它位于**磁盘的第一个 sector 中，紧跟在 446B boot code 之后**。该 sector 对于向 PC 指示应挂载哪个分区以及从何处挂载分区至关重要。\
它最多支持 **4 个分区**（最多**只能有 1 个**处于 active/**bootable** 状态）。不过，如果需要更多分区，可以使用 **extended partitions**。该 sector 的**最后一个字节**是 boot record signature **0x55AA**。只能将一个分区标记为 active。\
MBR 支持的最大容量为 **2.2TB**。

![Partitions - MBR（master Boot Record）：MBR 支持的最大容量为 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR（master Boot Record）：MBR 支持的最大容量为 2.2TB](<../../../images/image (304).png>)

在 MBR 的 **bytes 440 到 443** 中，可以找到 **Windows Disk Signature**（如果使用 Windows）。硬盘的逻辑驱动器号取决于 Windows Disk Signature。更改此 signature 可能会导致 Windows 无法 boot（tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**）。

![Partitions - MBR（master Boot Record）：在 MBR 的 bytes 440 到 443 中，可以找到 Windows Disk Signature（如果使用 Windows）。硬盘的逻辑驱动器号……](<../../../images/image (310).png>)

**格式**

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

要在 Linux 中挂载 MBR，首先需要获取 start offset（可以使用 `fdisk` 和 `p` 命令）

![Partitions - MBR（master Boot Record）：要在 Linux 中挂载 MBR，首先需要获取 start offset（可以使用 fdisk 和 p 命令）](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

然后使用以下 code
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA（Logical block addressing）**

**Logical block addressing**（**LBA**）是一种常见方案，用于**指定计算机存储设备中数据块的位置**，通常用于硬盘驱动器等二级存储系统。LBA 是一种特别简单的线性寻址方案；**数据块通过整数索引定位**，第一个数据块为 LBA 0，第二个为 LBA 1，以此类推。

### GPT（GUID Partition Table）

GUID Partition Table，简称 GPT，相较于 MBR（Master Boot Record）具有更强的功能，因此更受青睐。GPT 的显著特点是为分区提供**全局唯一标识符**，并在以下方面表现突出：

- **位置和大小**：GPT 和 MBR 都从**扇区 0**开始。不过，GPT 使用 **64bits**，而 MBR 使用 32bits。
- **分区限制**：GPT 在 Windows 系统上最多支持 **128 个分区**，并可容纳最多 **9.4ZB** 的数据。
- **分区名称**：支持使用最多 36 个 Unicode 字符命名分区。

**数据弹性与恢复**：

- **冗余**：与 MBR 不同，GPT 不会将分区和启动数据限制在单一位置。它会在磁盘各处复制这些数据，从而增强数据完整性和弹性。
- **循环冗余校验（CRC）**：GPT 使用 CRC 确保数据完整性。它会主动监控数据损坏情况，并在检测到损坏时，尝试从磁盘的其他位置恢复损坏的数据。

**保护性 MBR（LBA0）**：

- GPT 通过保护性 MBR 保持向后兼容性。此功能位于传统 MBR 空间中，但其设计目的是防止较旧的基于 MBR 的工具错误覆盖 GPT 磁盘，从而保护 GPT 格式磁盘上的数据完整性。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR（LBA 0 + GPT）**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

在支持通过 **BIOS** 服务而非 EFI 进行**基于 GPT 的启动**的操作系统中，第一个扇区也可能仍用于存储 **bootloader** 代码的第一阶段，但会进行**修改**以识别 **GPT** **分区**。MBR 中的 bootloader 不得假定扇区大小为 512 字节。

**分区表标头（LBA 1）**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

分区表标头定义磁盘上的可用数据块。它还定义组成分区表的分区条目数量和大小（表中的偏移量 80 和 84）。

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | 签名（"EFI PART"，在 little-endian 机器上为 45h 46h 49h 20h 50h 41h 52h 54h 或 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)） |
| 8 (0x08)  | 4 bytes  | Revision 1.0（00h 00h 01h 00h），用于 UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | 以 little endian 表示的标头大小（以字节为单位，通常为 5Ch 00h 00h 00h 或 92 字节）                                                                                                 |
| 16 (0x10) | 4 bytes  | 以 little endian 表示的标头 [CRC32](https://en.wikipedia.org/wiki/CRC32)（从偏移量 +0 到标头大小），计算期间此字段置零                             |
| 20 (0x14) | 4 bytes  | 保留；必须为零                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | 当前 LBA（此标头副本的位置）                                                                                                                                   |
| 32 (0x20) | 8 bytes  | 备份 LBA（另一个标头副本的位置）                                                                                                                               |
| 40 (0x28) | 8 bytes  | 分区的第一个可用 LBA（主分区表最后一个 LBA + 1）                                                                                                       |
| 48 (0x30) | 8 bytes  | 最后一个可用 LBA（次分区表第一个 LBA − 1）                                                                                                                    |
| 56 (0x38) | 16 bytes | mixed endian 格式的磁盘 GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | 分区条目数组的起始 LBA（主副本中始终为 2）                                                                                                     |
| 80 (0x50) | 4 bytes  | 数组中的分区条目数量                                                                                                                                         |
| 84 (0x54) | 4 bytes  | 单个分区条目的大小（通常为 80h 或 128）                                                                                                                        |
| 88 (0x58) | 4 bytes  | 以 little endian 表示的分区条目数组 CRC32                                                                                                                            |
| 92 (0x5C) | \*       | 保留；该数据块的其余部分必须为零（扇区大小为 512 字节时为 420 字节；扇区大小更大时可以更多）                                      |

**分区条目（LBA 2–33）**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [分区类型 GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs)（mixed endian） |
| 16 (0x10)                   | 16 bytes | 唯一分区 GUID（mixed endian）                                                                          |
| 32 (0x20)                   | 8 bytes  | 第一个 LBA（[little endian](https://en.wikipedia.org/wiki/Little_endian)）                                      |
| 40 (0x28)                   | 8 bytes  | 最后一个 LBA（包含该 LBA，通常为奇数）                                                                             |
| 48 (0x30)                   | 8 bytes  | 属性标志（例如 bit 60 表示只读）                                                               |
| 56 (0x38)                   | 72 bytes | 分区名称（36 个 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units）                               |

**Partitions Types**

![MBR（master Boot Record）- GPT（GUID Partition Table）：56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

更多分区类型请参阅 [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

### 检查

使用 [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) 挂载 forensics image 后，可以使用 Windows 工具 [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** 检查第一个扇区。在下图中，工具在**扇区 0**上检测到了 **MBR** 并对其进行了分析：

![GPT（GUID Partition Table）- 检查：使用 ArsenalImageMounter 挂载 forensics image 后，可以使用 Windows 工具 Active Disk Editor 检查第一个扇区。在……](<../../../images/image (354).png>)

如果是 **GPT table 而不是 MBR**，则应在**扇区 1**中看到签名 _EFI PART_（在上一张图中该扇区为空）。

## 文件系统

### Windows 文件系统列表

- **FAT12/16**：MSDOS、WIN95/98/NT/200
- **FAT32**：95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**：2008/2012/2016/VISTA/7/8/10
- **NTFS**：XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**：2012/2016

### FAT

**FAT（File Allocation Table）** 文件系统围绕其核心组件——文件分配表进行设计，该表位于卷的起始位置。该系统通过维护**两份表副本**来保护数据，即使其中一份损坏，也能确保数据完整性。该表以及根文件夹必须位于**固定位置**，这对系统启动过程至关重要。

文件系统的基本存储单位是一个**cluster，通常为 512B**，由多个扇区组成。FAT 经历了多个版本的发展：

- **FAT12** 支持 12 位 cluster 地址，最多处理 4078 个 cluster（使用 UNIX 时为 4084 个）。
- **FAT16** 将地址扩展为 16 位，因此最多可容纳 65,517 个 cluster。
- **FAT32** 进一步使用 32 位地址，使每个卷最多可容纳 268,435,456 个 cluster。

所有 FAT 版本的一个重要限制是**4GB 的最大文件大小**，这是由用于存储文件大小的 32 位字段造成的。

根目录的主要组件（尤其是 FAT12 和 FAT16）包括：

- **文件/文件夹名称**（最多 8 个字符）
- **属性**
- **创建、修改和最后访问日期**
- **FAT 表地址**（表示文件的起始 cluster）
- **文件大小**

### EXT

**Ext2** 是最常见的用于**非 journaling** 分区（**变化不大的分区**，例如 boot 分区）的文件系统。**Ext3/4** 支持 **journaling**，通常用于**其余分区**。

## **Metadata**

某些文件包含 metadata。这些信息描述文件的内容，有时可能对 analyst 很有价值，因为根据文件类型的不同，其中可能包含以下信息：

- 标题
- 使用的 MS Office 版本
- 作者
- 创建日期和最后修改日期
- 相机型号
- GPS 坐标
- 图像信息

可以使用 [**exiftool**](https://exiftool.org) 和 [**Metadiver**](https://www.easymetadata.com/metadiver-2/) 等工具获取文件的 metadata。

## **已删除文件恢复**

### 已记录的删除文件

如前文所述，文件在被“删除”后，仍可能保存在多个位置。这是因为通常从文件系统中删除文件只会将其标记为已删除，而不会触碰数据。因此，可以检查文件的 registry（例如 MFT），并找到已删除的文件。<sup>[[2]](#references)</sup>

此外，OS 通常会保存大量有关文件系统更改和备份的信息，因此可以尝试利用这些信息恢复文件，或尽可能多地恢复相关信息。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** 是一种尝试在**大量数据中查找文件**的技术。这类工具主要有 3 种工作方式：**基于文件类型的 headers 和 footers**、基于文件类型的 **structures**，以及基于文件**自身的内容**。

请注意，该技术**无法恢复 fragmented files**。如果文件**没有存储在连续扇区中**，则该技术无法找到完整文件，甚至无法找到其中的一部分。

有多种工具可用于 file Carving，你可以指定要搜索的文件类型。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving 与 File Carving 类似，但**它不查找完整文件，而是查找有价值的信息片段**。\
例如，该技术不会查找包含已记录 URL 的完整文件，而是直接搜索 URL。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### 安全删除

显然，有多种方法可以**“安全地”删除文件以及关于文件的部分日志**。例如，可以多次使用垃圾数据**覆盖文件内容**，然后从 **$MFT** 和 **$LOGFILE** 中**删除**有关该文件的**日志**，并**删除 Volume Shadow Copies**。<sup>[[3]](#references)</sup>\
你可能会注意到，即使执行了这些操作，仍可能在**其他位置记录着文件存在过的痕迹**；这确实如此，而 forensics professional 的工作之一就是找到这些痕迹。

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
