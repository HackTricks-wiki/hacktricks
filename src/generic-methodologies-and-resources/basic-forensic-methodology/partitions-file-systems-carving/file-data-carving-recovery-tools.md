# 文件/数据 Carving 与恢复工具

{{#include ../../../banners/hacktricks-training.md}}

## Carving 与恢复工具

更多工具见 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

在取证中，用于从镜像中提取文件的最常用工具是 [**Autopsy**](https://www.autopsy.com/download/)。下载并安装它，然后让它 ingest 该文件，以查找“隐藏”文件。请注意，Autopsy 专为支持磁盘镜像和其他类型的镜像而构建，但不支持简单文件。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** 是一款用于分析二进制文件、查找嵌入内容的工具。它可以通过 `apt` 安装，其源代码位于 [GitHub](https://github.com/ReFirmLabs/binwalk)。

**实用命令**：
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – Versions **2.1.2b through 2.3.3** are affected by a **Path Traversal** vulnerability (CVE-2022-4510); the advisory lists no patched pip version. Avoid extracting untrusted samples with affected releases, or isolate the tool with a container/non-privileged UID.<sup>[[4]](#references)</sup>

### Foremost

另一个用于查找隐藏文件的常用工具是 **foremost**。你可以在 `/etc/foremost.conf` 中找到 foremost 的配置文件。如果你只想搜索某些特定文件，请取消对应行的注释。如果不取消任何注释，foremost 将搜索其默认配置的文件类型。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** 是另一个可用于查找和提取**嵌入在文件中的文件**的工具。在这种情况下，你需要在配置文件（_/etc/scalpel/scalpel.conf_）中取消注释要提取的文件类型。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

此工具包含在 kali 中，但你也可以在此处找到它：<https://github.com/simsong/bulk_extractor>

Bulk Extractor 可以扫描证据镜像，并使用多个 scanner 并行 carve **pcap 片段**、**网络 artefacts（URLs、domains、IPs、MACs、e-mails）**以及许多其他对象。

v2.1.1 版本记录了 Autotools 构建方式，以及用于 carve 所有连续 JPEG 的 `-S jpeg_carve_mode=2` 设置。<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
捆绑的 `bulk_diff.py` 用于比较两次 bulk_extractor 运行结果，而 `bulk_extractor_reader.py` 用于读取报告和 feature 文件。<sup>[[3]](#references)</sup>

### PhotoRec

你可以在 <https://www.cgsecurity.org/wiki/TestDisk_Download> 找到它。

它同时提供 GUI 和 CLI 版本。你可以选择 PhotoRec 要搜索的 **file-types**。

![运行每个 scanner、积极 carving JPEG 并生成 bodyfile - PhotoRec：它同时提供 GUI 和 CLI 版本。你可以选择 PhotoRec 要搜索的 file-types](<../../../images/image (242).png>)

### ddrescue + ddrescueview（对故障驱动器进行 imaging）

当物理驱动器不稳定时，最佳实践是**先对其进行 imaging**，然后仅针对该 image 运行 carving 工具。`ddrescue`（GNU project）专注于可靠地复制损坏的磁盘，同时记录无法读取的扇区。
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`** 选项控制每次复制的 sector 数量；较小的值有助于处理速度较慢的驱动器。<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic（EXT 3/4 文件恢复）

如果源文件系统基于 Linux EXT，则可能无需进行完整 carving 即可恢复最近删除的文件；这些基于 journal 的工具可在未挂载的文件系统或只读 image 上运行。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **兼容性说明** – ext4magic 已被弃用；其项目页面警告称，当前文件系统已不再与其兼容。<sup>[[10]](#references)</sup>

> 🛈 如果文件系统在删除操作后曾被挂载，数据块可能已经被重新使用——在这种情况下，仍需要执行适当的 carving（Foremost/Scalpel）。

### binvis

查看[代码](https://code.google.com/archive/p/binvis/)和[网页工具](https://binvis.io/#/)。

#### BinVis 的功能

- 可视化且主动的**结构查看器**
- 针对不同关注点的多个图表
- 聚焦于样本的部分内容
- 在 PE 或 ELF 可执行文件中**查看字符串和资源**等
- 获取用于文件密码分析的**模式**
- **识别** packer 或 encoder 算法
- 通过模式**识别**Steganography
- **可视化**二进制 diff

BinVis 是在 black-boxing 场景中**熟悉未知目标的良好起点**。

## Specific Data Carving Tools

### FindAES

通过搜索 AES 密钥调度来查找 AES 密钥。能够查找 128、192 和 256 位密钥，例如 TrueCrypt 和 BitLocker 使用的密钥。

在[此处](https://sourceforge.net/projects/findaes/)下载。

### YARA-X（对 carving 得到的 artefacts 进行 triaging）

[YARA-X](https://github.com/VirusTotal/yara-x) 是 YARA 的 Rust 重写版本，于 2024 年推出；VirusTotal 报告称，某些正则表达式和复杂循环规则的运行速度可以显著提高。<sup>[[5]](#references)</sup>其 CLI 名称为 `yr`，`scan` 命令支持递归扫描、线程数设置和元数据输出。<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Complementary tools

你可以使用 [**viu** ](https://github.com/atanunq/viu)从终端查看图像。  \
你可以使用 Linux 命令行工具 **pdftotext** 将 PDF 转换为文本并阅读。



## References

- [1] [Autopsy 4.21 发布说明](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python 工具 README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk 中的路径遍历（CVE-2022-4510）- GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA 已死，YARA-X 万岁 - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI 命令](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue 手册](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic 手册](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic 项目状态](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
