# 文件/数据雕刻与恢复工具

{{#include ../../../banners/hacktricks-training.md}}

## 雕刻与恢复工具

更多工具在 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

在取证中提取图像中的文件最常用的工具是 [**Autopsy**](https://www.autopsy.com/download/)。下载并安装它，然后让它处理文件以查找“隐藏”文件。请注意，Autopsy 是为支持磁盘映像和其他类型的映像而构建的，但不支持简单文件。

> **2024-2025 更新** – 版本 **4.21**（于2025年2月发布）增加了基于 SleuthKit v4.13 重建的 **雕刻模块**，在处理多TB图像时明显更快，并支持在多核系统上进行并行提取。¹  还引入了一个小型 CLI 包装器（`autopsycli ingest <case> <image>`），使得在 CI/CD 或大规模实验室环境中脚本化雕刻成为可能。
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** 是一个用于分析二进制文件以查找嵌入内容的工具。可以通过 `apt` 安装，其源代码在 [GitHub](https://github.com/ReFirmLabs/binwalk) 上。

**有用的命令**：
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **安全提示** – 版本 **≤2.3.3** 受到 **路径遍历** 漏洞 (CVE-2022-4510) 的影响。在雕刻不受信任的样本之前，请升级（或使用容器/非特权 UID 隔离）。

### Foremost

另一个常用的查找隐藏文件的工具是 **foremost**。您可以在 `/etc/foremost.conf` 中找到 foremost 的配置文件。如果您只想搜索某些特定文件，请取消注释它们。如果您不取消注释任何内容，foremost 将搜索其默认配置的文件类型。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** 是另一个可以用来查找和提取 **嵌入在文件中的文件** 的工具。在这种情况下，您需要从配置文件 (_/etc/scalpel/scalpel.conf_) 中取消注释您希望提取的文件类型。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

这个工具包含在kali中，但你可以在这里找到它：<https://github.com/simsong/bulk_extractor>

Bulk Extractor可以扫描证据镜像并并行使用多个扫描器雕刻**pcap片段**、**网络工件（URLs、域名、IPs、MACs、电子邮件）**和许多其他对象。
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
有用的后处理脚本（`bulk_diff`，`bulk_extractor_reader.py`）可以在两个镜像之间去重工件或将结果转换为 JSON 以供 SIEM 吸收。

### PhotoRec

您可以在 <https://www.cgsecurity.org/wiki/TestDisk_Download> 找到它。

它提供 GUI 和 CLI 版本。您可以选择 PhotoRec 要搜索的 **文件类型**。

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview（映像故障驱动器）

当物理驱动器不稳定时，最佳实践是 **先对其进行成像**，然后仅对镜像运行雕刻工具。 `ddrescue`（GNU 项目）专注于可靠地复制坏磁盘，同时保持不可读扇区的日志。
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
版本 **1.28**（2024年12月）引入了 **`--cluster-size`**，可以加速高容量SSD的成像，因为传统的扇区大小不再与闪存块对齐。

### Extundelete / Ext4magic (EXT 3/4 恢复删除文件)

如果源文件系统是基于Linux EXT的，您可能能够 **在不进行完整雕刻的情况下** 恢复最近删除的文件。这两个工具直接在只读映像上工作：
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 如果文件系统在删除后被挂载，数据块可能已经被重用 – 在这种情况下，仍然需要进行适当的雕刻（Foremost/Scalpel）。

### binvis

查看 [code](https://code.google.com/archive/p/binvis/) 和 [web page tool](https://binvis.io/#/)。

#### BinVis 的特点

- 视觉和主动的 **结构查看器**
- 针对不同焦点的多个图表
- 专注于样本的部分
- **查看 PE 或 ELF 可执行文件中的字符串和资源**
- 获取文件的 **模式** 以进行密码分析
- **识别** 压缩器或编码器算法
- 通过模式 **识别** 隐写术
- **视觉** 二进制差异比较

BinVis 是一个很好的 **起点，以熟悉未知目标** 在黑箱场景中。

## 特定数据雕刻工具

### FindAES

通过搜索其密钥调度来搜索 AES 密钥。能够找到 128、192 和 256 位密钥，例如 TrueCrypt 和 BitLocker 使用的密钥。

在 [这里下载](https://sourceforge.net/projects/findaes/)。

### YARA-X（对雕刻的工件进行分类）

[YARA-X](https://github.com/VirusTotal/yara-x) 是 YARA 的 Rust 重写版本，于 2024 年发布。它比经典 YARA **快 10-30 倍**，可以非常快速地对数千个雕刻对象进行分类：
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
加速使得在大规模调查中**自动标记**所有雕刻文件变得现实。

## 补充工具

您可以使用 [**viu** ](https://github.com/atanunq/viu) 从终端查看图像。  \
您可以使用 Linux 命令行工具 **pdftotext** 将 PDF 转换为文本并阅读。

## 参考文献

1. Autopsy 4.21 发布说明 – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
