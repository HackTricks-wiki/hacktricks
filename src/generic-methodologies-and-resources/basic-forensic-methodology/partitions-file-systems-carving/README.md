# 分区/文件系统/Carving

{{#include ../../../banners/hacktricks-training.md}}

## 分区

磁盘可以包含多个**分区**：它们是逻辑上的块范围，并非物理上独立的存储空间。分区的起始位置和长度以**逻辑扇区**为单位；不要假设每个镜像都使用 512 字节扇区，因为也存在 4096 字节逻辑扇区。<sup>[[4]](#references)</sup>

### MBR（master Boot Record）

MBR 占用第一个逻辑扇区（LBA 0）；其四个 16 字节的分区项从字节 446 开始。前面的区域包含引导代码，也可能包含磁盘签名。<sup>[[4]](#references)</sup>\
它最多支持 **4 个分区**（其中**最多只有 1 个**可以设为活动/**可引导**分区）。如果需要更多分区，可以使用**扩展分区**。512 字节 MBR 的最后**两个字节**是引导签名 **0x55 0xAA**。只能将一个分区标记为活动分区。\
对于 512 字节逻辑扇区，MBR 的 32 位扇区字段将可寻址容量限制在约 **2 TiB**（2.2 TB）。<sup>[[4]](#references)</sup>

![分区 - MBR（master Boot Record）：MBR 最多支持 2.2TB](<../../../images/image (350).png>)

![分区 - MBR（master Boot Record）：MBR 最多支持 2.2TB](<../../../images/image (304).png>)

如果使用 Windows，可以在 MBR 的**字节 440 到 443**处找到 **Windows 磁盘签名**。硬盘的逻辑驱动器号取决于 Windows 磁盘签名。更改此签名可能导致 Windows 无法启动（工具：[**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**。

![分区 - MBR（master Boot Record）：如果使用 Windows，可以在 MBR 的字节 440 到 443 处找到 Windows 磁盘签名。硬盘的逻辑驱动器号……](<../../../images/image (310).png>)

**格式**

| 偏移量      | 长度       | 项目                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | 引导代码            |
| 446 (0x1BE) | 16 (0x10)  | 第一个分区          |
| 462 (0x1CE) | 16 (0x10)  | 第二个分区          |
| 478 (0x1DE) | 16 (0x10)  | 第三个分区          |
| 494 (0x1EE) | 16 (0x10)  | 第四个分区          |
| 510 (0x1FE) | 2 (0x2)    | 签名 0x55 0xAA       |

**分区记录格式**

| 偏移量    | 长度     | 项目                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | 活动标志（0x80 = 可引导）                              |
| 1 (0x01)  | 1 (0x01) | 起始磁头                                               |
| 2 (0x02)  | 1 (0x01) | 起始扇区（位 0-5）；柱面高位（位 6-7）                 |
| 3 (0x03)  | 1 (0x01) | 起始柱面最低 8 位                                      |
| 4 (0x04)  | 1 (0x01) | 分区类型代码（0x83 = Linux）                           |
| 5 (0x05)  | 1 (0x01) | 结束磁头                                               |
| 6 (0x06)  | 1 (0x01) | 结束扇区（位 0-5）；柱面高位（位 6-7）                 |
| 7 (0x07)  | 1 (0x01) | 结束柱面最低 8 位                                      |
| 8 (0x08)  | 4 (0x04) | 分区前的扇区数（小端序）                               |
| 12 (0x0C) | 4 (0x04) | 分区中的扇区数                                         |

要在整盘 MBR 镜像中检查某个分区，首先获取其起始 LBA 和逻辑扇区大小。`mount` 接受的是**字节偏移量**，而不是 LBA；以下示例仅适用于扇区大小为 512 字节且分区从 LBA 63 开始的镜像。对于不可信镜像或使用日志的文件系统，请改用 [Image Acquisition & Mount](../image-acquisition-and-mount.md) 中介绍的隔离、只读工作流程。<sup>[[5]](#references)[[11]](#references)</sup>

![分区 - MBR（master Boot Record）：要在 Linux 中挂载 MBR，首先需要获取起始偏移量（可以使用 fdisk 并运行 p 命令）](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA（逻辑块寻址）**

**逻辑块寻址**（**LBA**）是一种常见方案，用于**指定**计算机存储设备上数据块的**位置**，通常用于硬盘驱动器等辅助存储系统。LBA 是一种特别简单的线性寻址方案；**通过整数索引定位数据块**，第一个数据块为 LBA 0，第二个为 LBA 1，以此类推。

### GPT（GUID 分区表）

GUID 分区表（GPT）为每个分区存储一个唯一的 GUID，并使用主元数据和备份元数据。其布局与 MBR 的区别如下：<sup>[[4]](#references)</sup>

- **位置和大小**：LBA 0 包含一个**保护性 MBR**。主 GPT 头位于 LBA 1；其后是分区项数组，而备份数组和头位于磁盘末尾。GPT 使用 64 位 LBA 字段，而 MBR 分区项使用 32 位 LBA 字段。
- **分区限制**：常见的 16-KiB 分区项数组包含 **128 个 128 字节的项**，但项数记录在头中，并非由 GPT 固定。可寻址容量也取决于逻辑扇区大小（使用 512 字节扇区时约为 **9.4 ZB**）。<sup>[[4]](#references)</sup>
- **分区名称**：支持为分区命名，名称最长可包含 36 个 Unicode 字符。

**数据弹性与恢复**：

- **冗余**：与 MBR 不同，GPT 不会将分区和启动数据限制在单一位置。它会在磁盘上复制这些数据，从而增强数据完整性和弹性。
- **循环冗余校验（CRC）**：头和分区项数组各自都有一个 CRC32。CRC 用于检测不一致；它不会持续监控磁盘，也不会自行修复磁盘。如果主副本无效，请在对工作副本执行任何恢复操作之前，验证位于最后一个 LBA 的备份。<sup>[[4]](#references)</sup>

**保护性 MBR（LBA0）**：

- GPT 通过保护性 MBR 保持向后兼容。该功能位于旧版 MBR 空间中，旨在防止较旧的、基于 MBR 的实用程序错误覆盖 GPT 磁盘，从而保护 GPT 格式磁盘上的数据完整性。

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**混合 MBR（LBA 0 + GPT）**

[来自维基百科](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

在支持通过 **BIOS** 服务而非 EFI 进行 **基于 GPT 的启动**的操作系统中，第一个扇区也仍可用于存储**引导加载程序**代码的第一阶段，但需要经过**修改**才能识别 **GPT** **分区**。MBR 中的引导加载程序不得假定扇区大小为 512 字节。

**分区表头（LBA 1）**

[来自维基百科](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

分区表头定义磁盘上的可用数据块。它还定义构成分区表的分区项数量和大小（表中的偏移量 80 和 84）。

| 偏移量    | 长度   | 内容                                                                                                                                                                     |
| --------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 字节  | 签名（"EFI PART"，45h 46h 49h 20h 50h 41h 52h 54h；在小端序机器上为 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)） |
| 8 (0x08)  | 4 字节  | UEFI 2.8 的修订版 1.0（00h 00h 01h 00h）                                                                                                                                  |
| 12 (0x0C) | 4 字节  | 小端序的头大小（以字节为单位，通常为 5Ch 00h 00h 00h，即 92 字节）                                                                                                 |
| 16 (0x10) | 4 字节  | 小端序的头 [CRC32](https://en.wikipedia.org/wiki/CRC32)（从偏移量 +0 到头大小），计算时此字段置零                             |
| 20 (0x14) | 4 字节  | 保留；必须为零                                                                                                                                                       |
| 24 (0x18) | 8 字节  | 当前 LBA（此头副本的位置）                                                                                                                                   |
| 32 (0x20) | 8 字节  | 备份 LBA（另一个头副本的位置）                                                                                                                               |
| 40 (0x28) | 8 字节  | 分区的第一个可用 LBA（主分区表最后一个 LBA + 1）                                                                                                       |
| 48 (0x30) | 8 字节  | 最后一个可用 LBA（次分区表第一个 LBA − 1）                                                                                                                    |
| 56 (0x38) | 16 字节 | 磁盘 GUID，混合端序                                                                                                                                                    |
| 72 (0x48) | 8 字节  | 分区项数组的起始 LBA（主副本中始终为 2）                                                                                                     |
| 80 (0x50) | 4 字节  | 数组中的分区项数量                                                                                                                                         |
| 84 (0x54) | 4 字节  | 单个分区项的大小（通常为 80h 或 128）                                                                                                                        |
| 88 (0x58) | 4 字节  | 分区项数组的 CRC32，小端序                                                                                                                            |
| 92 (0x5C) | \*       | 保留；数据块剩余部分必须为零（扇区大小为 512 字节时为 420 字节；扇区较大时可以更多）                                      |

**分区项（LBA 2–33）**

| GUID 分区项格式 |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| 偏移量                      | 长度   | 内容                                                                                                      |
| 0 (0x00)                    | 16 字节 | [分区类型 GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs)，混合端序 |
| 16 (0x10)                   | 16 字节 | 唯一分区 GUID，混合端序                                                                          |
| 32 (0x20)                   | 8 字节  | 第一个 LBA（[小端序](https://en.wikipedia.org/wiki/Little_endian)）                                      |
| 40 (0x28)                   | 8 字节  | 最后一个 LBA（包含在内，通常为奇数）                                                                             |
| 48 (0x30)                   | 8 字节  | 属性标志（例如，位 60 表示只读）                                                               |
| 56 (0x38)                   | 72 字节 | 分区名称（36 个 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE 代码单元）                               |

**分区类型**

![MBR（主引导记录）- GPT（GUID 分区表）：56 (0x38) | 72 字节 | 分区名称（36 个 UTF-16LE 代码单元）](<../../../images/image (83).png>)

更多分区类型请参阅 [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)。<sup>[[1]](#references)</sup>

### 检查

使用 [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) 挂载取证镜像后，你可以使用 Windows 工具 [**Active Disk Editor**](https://www.disk-editor.org/index.html)** 检查第一个扇区。**下图中检测到并解析了 **扇区 0** 中的 **MBR**：

![GPT（GUID 分区表）- 检查：使用 ArsenalImageMounter 挂载取证镜像后，你可以使用 Windows 工具 Active Disk Editor 检查第一个扇区。下图中……](<../../../images/image (354).png>)

对于 GPT，请在 **LBA 1** 的主头中查找 _EFI PART_ 签名；LBA 0 仍包含保护性 MBR。<sup>[[4]](#references)</sup>

### 查找已列出分区之外的数据

已删除的分区项或有意保留的未使用间隙，可能导致文件系统位于当前分区映射之外。在**已验证的原始工作副本**上，列出未分配范围，然后将候选起始 LBA 作为文件系统进行检查。`mmls` 和 `fsstat` 使用**扇区偏移量**；请为两者提供实际逻辑扇区大小。不要将 GPT 元数据扇区误认为隐藏卷。<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

如果 `fsstat` 无法识别间隙起始处的文件系统，请使用 TestDisk **Analyse → Quick Search**，必要时再使用 **Deeper Search**。在候选项上按 `P` 可检查文件；不要在证据上选择 **Write**。对于 GPT 镜像，`sgdisk --verify disk.img` 会检查 CRC 和主、备分区表是否一致，但重新分区后备份头可能已过时，因此在恢复前应根据文件系统结构核实候选边界。<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## 文件系统

### Windows 文件系统列表

- **FAT12/16**：MSDOS、WIN95/98/NT/200
- **FAT32**：95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**：2008/2012/2016/VISTA/7/8/10
- **NTFS**：XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**：2012/2016

### FAT

**FAT（文件分配表）**文件系统围绕其核心组件——文件分配表设计，该表位于卷的起始处。一个卷通常有**两份 FAT 副本**，但 BPB 允许只有一份。FAT12/16 将根目录存放在固定区域；FAT32 则将根目录存放在数据区中由 `BPB_RootClus` 指定的簇内。<sup>[[7]](#references)</sup>

分配单位是**簇**：`BPB_BytsPerSec × BPB_SecPerClus`，不一定是 512 字节。FAT 类型由数据簇数量决定，而不是由引导扇区中的版本字符串决定。簇数量的边界如下：<sup>[[7]](#references)</sup>

- **FAT12**：少于 4,085 个数据簇。
- **FAT16**：4,085 至 65,524 个数据簇。
- **FAT32**：至少 65,525 个数据簇；每个 32 位 FAT 表项中只有 28 位用于表示簇号。

32 位文件大小字段将普通文件的大小限制为 **2³²−1 字节**（略小于 4 GiB）。<sup>[[7]](#references)</sup>

根目录的关键组成部分（尤其是 FAT12 和 FAT16）包括：

- **文件/文件夹名称**（最多 8 个字符）
- **属性**
- **创建、修改和最后访问日期**
- **FAT 表地址**（指示文件的起始簇）
- **文件大小**

### EXT

**Ext2** 是最常见的**非日志记录**分区文件系统（用于**变化不大的分区**），例如引导分区。**Ext3/4** 支持**日志记录**，通常用于**其余分区**。

## **元数据**

有些文件包含元数据。这些信息描述文件内容，有时对分析人员很有价值；根据文件类型不同，元数据可能包含：

- 标题
- 使用的 MS Office 版本
- 作者
- 创建和最后修改日期
- 相机型号
- GPS 坐标
- 图像信息

可以使用 [**exiftool**](https://exiftool.org) 和 [**Metadiver**](https://www.easymetadata.com/metadiver-2/) 等工具获取文件的元数据。

## **已删除文件恢复**

### 已记录的已删除文件

如前所述，文件被“删除”后，仍有多个位置保存着该文件。这是因为文件系统通常只是将文件标记为已删除，而不会触碰其中的数据。因此，可以检查文件记录（如 MFT），并查找已删除的文件。<sup>[[2]](#references)</sup>

此外，操作系统通常会保存大量文件系统变更和备份信息，因此可以尝试利用这些信息恢复文件，或尽可能多地恢复相关信息。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **文件雕刻**

**文件雕刻**是一种尝试在**大量数据中查找文件**的技术。这类工具主要有三种工作方式：**基于文件类型的文件头和文件尾**、基于文件类型的**结构**，以及基于**内容**本身。

简单的文件头/文件尾雕刻假设数据块连续，因此文件被拆分时可能只能返回片段。但这并非绝对限制：对于某些碎片化 JPEG，PhotoRec 提供了 CPU 密集型的 **Paranoid → bruteforce** 选项；而基于格式的碎片重组也能恢复其他受支持的类型。有关当前碎片重组工作流程，请参阅 [文件雕刻和恢复工具](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving)。<sup>[[8]](#references)</sup>

有多种工具可用于文件雕刻，你可以指定要搜索的文件类型。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### 数据流**雕刻**

数据流雕刻与文件雕刻类似，但**它不是查找完整文件，而是查找有价值的信息片段**。\
例如，这种技术不会查找包含已记录 URL 的完整文件，而是直接搜索 URL。


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### 安全删除

显然，有办法**“安全地”删除文件及其部分日志记录**。例如，可以用无用数据多次**覆盖文件内容**，然后从 **$MFT** 和 **$LOGFILE** 中**删除**该文件的**日志记录**，并**删除卷影副本**。<sup>[[3]](#references)</sup>\
你可能会注意到，即使执行了这些操作，仍可能有**其他位置记录着该文件曾经存在**；确实如此，而查找这些记录也是取证专业人员工作的一部分。



## References

- [1] [GUID 分区表 - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [如何扫描 NTFS $I30（目录）条目以查找已删除文件的证据](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [卷影复制服务（VSS）](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [UEFI 规范：GPT 磁盘布局](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [The Sleuth Kit mmls 手册](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [The Sleuth Kit fsstat 手册](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Microsoft FAT 规范](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [PhotoRec 恢复选项](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [TestDisk 已删除分区恢复](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [sgdisk 手册](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [mount(8) 手册](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
