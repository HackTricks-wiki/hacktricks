# 文件/数据 Carving 与 Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving 与 Recovery tools

更多工具请参见 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

在取证中，用于从镜像中提取文件的最常用工具是 [**Autopsy**](https://www.autopsy.com/download/)。下载并安装它，然后让它 ingest 该文件，以查找“隐藏”文件。请注意，Autopsy 的设计目标是支持磁盘镜像和其他类型的镜像，但不支持简单文件。

> **2024-2025 更新** – **4.21** 版本（于 2025 年 2 月发布）新增了基于 SleuthKit v4.13 重构的 **carving module**，在处理多 TB 镜像时明显更快，并支持在多核系统上进行并行提取。同时还引入了一个小型 CLI wrapper（`autopsycli ingest <case> <image>`），从而可以在 CI/CD 或大规模实验室环境中编写 carving 脚本。<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** 是一个用于分析二进制文件以查找嵌入内容的工具。可通过 `apt` 安装，其源代码位于 [GitHub](https://github.com/ReFirmLabs/binwalk)。

**实用命令**：
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – Versions **≤2.3.3** are affected by a **Path Traversal** vulnerability (CVE-2022-4510). 请在 carving 不受信任的样本前进行升级（或使用 container/非特权 UID 进行隔离）。<sup>[[2]](#references)</sup>

### Foremost

另一个用于查找隐藏文件的常用工具是 **foremost**。你可以在 `/etc/foremost.conf` 中找到 foremost 的配置文件。如果只想搜索某些特定文件，请取消对应配置行的注释。如果不取消任何配置行的注释，foremost 将搜索其默认配置的文件类型。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** 是另一个可用于查找和提取**嵌入文件中的文件**的工具。在这种情况下，你需要在配置文件（_/etc/scalpel/scalpel.conf_）中取消注释希望提取的文件类型。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

此工具包含在 kali 中，但你也可以在此处找到它：<https://github.com/simsong/bulk_extractor>

Bulk Extractor 可以扫描证据镜像，并通过多个 scanners 并行 carve **pcap fragments**、**network artefacts (URLs, domains, IPs, MACs, e-mails)** 以及许多其他对象。
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
有用的后处理脚本（`bulk_diff`、`bulk_extractor_reader.py`）可以对两个镜像之间的 artefacts 进行去重，或将结果转换为 JSON 以供 SIEM 导入。

### PhotoRec

你可以在 <https://www.cgsecurity.org/wiki/TestDisk_Download> 找到它。

它提供 GUI 和 CLI 版本。你可以选择希望 PhotoRec 搜索的 **file-types**。

![运行每个 scanner、积极 carve JPEG 并生成 bodyfile - PhotoRec：它提供 GUI 和 CLI 版本。你可以选择希望 PhotoRec 搜索的 file-types](<../../../images/image (242).png>)

### ddrescue + ddrescueview（对故障驱动器进行 imaging）

当物理驱动器不稳定时，最佳实践是**先对其进行 imaging**，然后仅针对镜像运行 carving tools。`ddrescue`（GNU project）专注于可靠地复制损坏的磁盘，同时保留不可读取 sectors 的日志。
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28**（2024 年 12 月）引入了 **`--cluster-size`**，可加快高容量 SSD 的 imaging 速度，因为传统 sector size 已不再与 flash block 对齐。

### Extundelete / Ext4magic（EXT 3/4 undelete）

如果源文件系统基于 Linux EXT，则可能无需进行完整 carving 即可恢复最近删除的文件。两个工具都可以直接在 read-only image 上运行：
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 如果文件系统是在删除操作之后挂载的，数据块可能已经被重新使用——在这种情况下，仍然需要进行适当的 carving（Foremost/Scalpel）。

### binvis

查看 [code](https://code.google.com/archive/p/binvis/) 和 [web page tool](https://binvis.io/#/)。

#### BinVis 的功能

- 可视化且主动的 **structure viewer**
- 针对不同关注点的多种绘图
- 聚焦样本的部分内容
- 在 PE 或 ELF 可执行文件中查看 **strings and resources**
- 获取文件中用于密码分析的 **patterns**
- **识别** packer 或 encoder 算法
- 通过模式**识别** Steganography
- **可视化** binary-diffing

在 black-boxing 场景中，BinVis 是熟悉未知目标的绝佳**起点**。

## Specific Data Carving Tools

### FindAES

通过搜索 AES key schedules 来查找 AES keys。能够找到 128、192 和 256 bit keys，例如 TrueCrypt 和 BitLocker 使用的 keys。

从[这里](https://sourceforge.net/projects/findaes/)下载。

### YARA-X（triaging carved artefacts）

[YARA-X](https://github.com/VirusTotal/yara-x) 是 YARA 的 Rust 重写版本，于 2024 年发布。它比 classic YARA **快 10-30 倍**，可用于非常快速地对数千个 carved objects 进行分类：<sup>[[3]](#references)</sup>。
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
速度的提升使得在大规模调查中对所有 carved files 进行 **auto-tag** 变得切实可行。

## Complementary tools

你可以使用 [**viu** ](https://github.com/atanunq/viu)从终端查看图像。  \
你可以使用 Linux 命令行工具 **pdftotext** 将 PDF 转换为文本并读取。



## References

- [1] [Autopsy 4.21 release notes](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA is dead, long live YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
