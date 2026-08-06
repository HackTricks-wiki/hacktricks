# 分区/文件系统/Carving

{{#include ../../../banners/hacktricks-training.md}}

## 分区

硬盘或 **SSD disk 可以包含不同的分区**，目的是在物理上分离数据。\
磁盘的**最小**单位是 **sector**（通常由 512B 组成）。因此，每个分区的大小必须是该大小的整数倍。

### MBR（master Boot Record）

它位于**磁盘的第一个 sector 中，排除前 446B 的 boot code 后**。该 sector 对于告知 PC 应挂载哪个分区以及从哪里挂载分区至关重要。\
它最多支持 **4 个分区**（最多**只能有 1 个**处于 active/**bootable** 状态）。但是，如果需要更多分区，可以使用 **extended partitions**。第一个 sector 的**最后一个字节**是 boot record 签名 **0x55AA**。只能将一个分区标记为 active。\
MBR 支持的最大容量为 **2.2TB**。

![分区 - MBR（master Boot Record）：MBR 支持的最大容量为 2.2TB](<../../../images/image (350).png>)

![分区 - MBR（master Boot Record）：MBR 支持的最大容量为 2.2TB](<../../../images/image (304).png>)

在 MBR 的 **440 到 443 字节**中，可以找到 **Windows Disk Signature**（如果使用 Windows）。硬盘的逻辑驱动器盘符取决于 Windows Disk Signature。更改此签名可能导致 Windows 无法启动（工具：[**Active Disk Editor**](https://www.disk-editor.org/index.html)**）。

![分区 - MBR（master Boot Record）：在 MBR 的 440 到 443 字节中，可以找到 Windows Disk Signature（如果使用 Windows）。硬盘的逻辑驱动器盘符...](<../../../images/image (310).png>)

**格式**

| 偏移量      | 长度       | 项目                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | 第一个分区     |
| 462 (0x1CE) | 16 (0x10)  | 第二个分区    |
| 478 (0x1DE) | 16 (0x10)  | 第三个分区     |
| 494 (0x1EE) | 16 (0x10)  | 第四个分区    |
| 510 (0x1FE) | 2 (0x2)    | 签名 0x55 0xAA |

**分区记录格式**

| 偏移量    | 长度   | 项目                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Active flag（0x80 = bootable）                          |
| 1 (0x01)  | 1 (0x01) | 起始 head                                             |
| 2 (0x02)  | 1 (0x01) | 起始 sector（bits 0-5）；cylinder 的高位（6- 7） |
| 3 (0x03)  | 1 (0x01) | 起始 cylinder 的最低 8 位                           |
| 4 (0x04)  | 1 (0x01) | 分区类型代码（0x83 = Linux）                     |
| 5 (0x05)  | 1 (0x01) | 结束 head                                               |
| 6 (0x06)  | 1 (0x01) | 结束 sector（bits 0-5）；cylinder 的高位（6- 7）   |
| 7 (0x07)  | 1 (0x01) | 结束 cylinder 的最低 8 位                             |
| 8 (0x08)  | 4 (0x04) | 分区之前的 sector 数（little endian）            |
| 12 (0x0C) | 4 (0x04) | 分区中的 sector 数                                   |

要在 Linux 中挂载 MBR，首先需要获取起始偏移量（可以使用 `fdisk` 和 `p` 命令）

![分区 - MBR（master Boot Record）：要在 Linux 中挂载 MBR，首先需要获取起始偏移量（可以使用 fdisk 和 p 命令）](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

然后使用以下 code
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing**（**LBA**）是一种常见方案，用于**指定计算机存储设备中数据块的位置**，通常用于硬盘驱动器等辅助存储系统。LBA 是一种非常简单的线性寻址方案；**数据块通过整数索引定位**，第一个数据块为 LBA 0，第二个为 LBA 1，依此类推。

### GPT (GUID Partition Table)

GUID Partition Table（简称 GPT）相比 MBR（Master Boot Record）具备更强大的功能，因此更受青睐。GPT 通过为分区提供**全局唯一标识符**而具有鲜明特征，主要特点如下：

- **位置和大小**：GPT 和 MBR 都从**扇区 0**开始。不过，GPT 使用 **64bits**，而 MBR 使用 32bits。
- **分区限制**：GPT 在 Windows 系统上最多支持 **128 个分区**，并可容纳最多 **9.4ZB** 的数据。
- **分区名称**：支持为分区命名，最多可使用 36 个 Unicode 字符。

**数据弹性和恢复**：

- **冗余**：与 MBR 不同，GPT 不会将分区和启动数据限制在单一位置。它会在磁盘中复制这些数据，从而增强数据完整性和弹性。
- **循环冗余校验（CRC）**：GPT 使用 CRC 确保数据完整性。它会主动监控数据损坏情况；检测到损坏时，GPT 会尝试从磁盘中的其他位置恢复损坏的数据。

**保护性 MBR（LBA0）**：

- GPT 通过保护性 MBR 保持向后兼容性。该功能位于传统 MBR 空间中，但旨在防止较旧的基于 MBR 的工具错误覆盖 GPT 磁盘，从而保护 GPT 格式磁盘上的数据完整性。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

在支持通过 **BIOS** 服务而非 EFI 进行**基于 GPT 的启动**的操作系统中，第一个扇区仍可能用于存储 **bootloader** 代码的第一阶段，但会进行修改以识别 **GPT** **分区**。MBR 中的 bootloader 不得假设扇区大小为 512 字节。

**分区表头（LBA 1）**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

分区表头定义磁盘上可使用的数据块。它还定义了组成分区表的分区条目数量和大小（表中的偏移量 80 和 84）。

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | 签名（"EFI PART"，45h 46h 49h 20h 50h 41h 52h 54h，或在 little-endian 机器上为 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)） |
| 8 (0x08)  | 4 bytes  | UEFI 2.8 的修订版本 1.0（00h 00h 01h 00h）                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | 以 little endian 表示的头大小（以字节为单位，通常为 5Ch 00h 00h 00h 或 92 字节）                                                                                                 |
| 16 (0x10) | 4 bytes  | 以 little endian 表示的头部 [CRC32](https://en.wikipedia.org/wiki/CRC32)（从偏移量 +0 到头大小），计算期间该字段置零                             |
| 20 (0x14) | 4 bytes  | 保留；必须为零                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | 当前 LBA（此头副本的位置）                                                                                                                                   |
| 32 (0x20) | 8 bytes  | 备份 LBA（另一个头副本的位置）                                                                                                                               |
| 40 (0x28) | 8 bytes  | 分区的第一个可用 LBA（主分区表最后一个 LBA + 1）                                                                                                       |
| 48 (0x30) | 8 bytes  | 最后一个可用 LBA（次分区表第一个 LBA − 1）                                                                                                                    |
| 56 (0x38) | 16 bytes | mixed endian 格式的磁盘 GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | 分区条目数组的起始 LBA（主副本中始终为 2）                                                                                                     |
| 80 (0x50) | 4 bytes  | 数组中的分区条目数量                                                                                                                                         |
| 84 (0x54) | 4 bytes  | 单个分区条目的大小（通常为 80h 或 128）                                                                                                                        |
| 88 (0x58) | 4 bytes  | 以 little endian 表示的分区条目数组 CRC32                                                                                                                            |
| 92 (0x5C) | \*       | 保留；块的其余部分必须为零（扇区大小为 512 字节时为 420 字节；扇区大小更大时可以更多）                                      |

**分区条目（LBA 2–33）**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [分区类型 GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs)（mixed endian） |
| 16 (0x10)                   | 16 bytes | 唯一分区 GUID（mixed endian）                                                                          |
| 32 (0x20)                   | 8 bytes  | 第一个 LBA（[little endian](https://en.wikipedia.org/wiki/Little_endian)）                                      |
| 40 (0x28)                   | 8 bytes  | 最后一个 LBA（包含该 LBA，通常为奇数）                                                                             |
| 48 (0x30)                   | 8 bytes  | 属性标志（例如 bit 60 表示只读）                                                               |
| 56 (0x38)                   | 72 bytes | 分区名称（36 个 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE 代码单元）                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

更多分区类型请参阅 [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### Inspecting

使用 [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) 挂载 forensics 镜像后，可以使用 Windows 工具 [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** 检查第一个扇区。在下图中，**MBR** 在**扇区 0**中被检测并解析：

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

如果是 **GPT 表而非 MBR**，则应在**扇区 1**中看到签名 _EFI PART_（在前一张图中该扇区为空）。

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT（File Allocation Table）**文件系统围绕其核心组件文件分配表设计，该表位于卷的起始位置。该系统通过维护**两份表副本**来保护数据，即使其中一份损坏，也能确保数据完整性。该表以及根文件夹必须位于**固定位置**，这对系统启动过程至关重要。

文件系统的基本存储单位是**cluster，通常为 512B**，由多个扇区组成。FAT 已经历多个版本：

- **FAT12**：支持 12 位 cluster 地址，最多处理 4078 个 cluster（使用 UNIX 时为 4084 个）。
- **FAT16**：升级为 16 位地址，最多可容纳 65,517 个 cluster。
- **FAT32**：进一步升级为 32 位地址，每个卷最多可容纳 268,435,456 个 cluster。

所有 FAT 版本都有一个重要限制：**文件大小最大为 4GB**，这是由用于存储文件大小的 32 位字段造成的。

根目录的重要组件，尤其是在 FAT12 和 FAT16 中，包括：

- **文件/文件夹名称**（最多 8 个字符）
- **属性**
- **创建、修改和最后访问日期**
- **FAT Table 地址**（表示文件的起始 cluster）
- **文件大小**

### EXT

**Ext2** 是**非 journaling** 分区（**变化不频繁的分区**，例如 boot 分区）中最常见的文件系统。**Ext3/4** 支持 **journaling**，通常用于**其余分区**。

## **Metadata**

某些文件包含 metadata。这些信息描述文件内容，有时可能对 analyst 很有价值，因为根据文件类型不同，其中可能包含以下信息：

- 标题
- 使用的 MS Office 版本
- 作者
- 创建和最后修改日期
- 相机型号
- GPS 坐标
- 图像信息

可以使用 [**exiftool**](https://exiftool.org) 和 [**Metadiver**](https://www.easymetadata.com/metadiver-2/) 等工具获取文件的 metadata。

## **Deleted Files Recovery**

### Logged Deleted Files

如前所述，文件在被“删除”后仍可能保存在多个位置。这是因为从文件系统中删除文件通常只会将其标记为已删除，而不会触碰数据。因此，可以检查文件的 registry（例如 MFT），并找到已删除的文件。<sup>[[2]](#references)</sup>

此外，OS 通常会保存大量有关文件系统更改和备份的信息，因此可以尝试利用这些信息恢复文件，或尽可能恢复相关信息。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** 是一种尝试**在大量数据中查找文件**的技术。此类工具主要有 3 种工作方式：**基于文件类型的 headers 和 footers**、基于文件类型的 **structures**，以及基于文件**自身的 content**。

请注意，该技术**无法用于恢复 fragmented files**。如果文件**未存储在连续扇区中**，则该技术将无法找到文件，或者至少无法找到文件的完整内容。

有多种工具可用于 file Carving，并可指定要搜索的文件类型。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving 与 File Carving 类似，但**它不是查找完整文件，而是查找有价值的信息片段**。\
例如，该技术不是查找包含已记录 URL 的完整文件，而是搜索 URL。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

显然，有多种方法可以**“安全地”删除文件以及与其相关的部分 logs**。例如，可以对文件内容使用垃圾数据进行多次**覆盖**，然后从 **$MFT** 和 **$LOGFILE** 中删除与该文件相关的 **logs**，并**删除 Volume Shadow Copies**。<sup>[[3]](#references)</sup>\
你可能会注意到，即使执行了这些操作，仍可能在**其他位置记录文件的存在**；事实确实如此，而 forensics professional 的部分工作就是找到这些记录。

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
