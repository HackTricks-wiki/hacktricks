# 文件/数据 Carving 与恢复工具

{{#include ../../../banners/hacktricks-training.md}}

## Carving 与恢复工具

始终对**已验证的副本**执行 carving，而不是对原始设备执行。有关只读采集和哈希工作流，请参阅 [Image Acquisition & Mount](../image-acquisition-and-mount.md)。

更多工具请参阅 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

在取证中，用于从镜像中提取文件的最常用工具是 [**Autopsy**](https://www.autopsy.com/download/)。下载并安装它，然后让它 ingest 该文件，以查找“隐藏”文件。请注意，Autopsy 专为支持磁盘镜像和其他类型的镜像而构建，但不支持简单文件。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** 是一款用于分析二进制文件以查找嵌入内容的工具。**Binwalk v3** 是使用 Rust 重写的版本，支持自动提取（`-e`）、已知和未知对象的 raw carving（`-c`）、递归/Matryoshka 扫描（`-M`）以及可配置的 worker 线程数。当需要所有外部提取器时，项目建议使用其 Docker 构建；`cargo install binwalk` 会安装 Rust CLI，但不会安装这些外部依赖。<sup>[[11]](#references)</sup>

**Useful v3 commands**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
旧版 v2 的 `--dd='.*'` 配方**并不是** v3 中 `-c` 的等效项；在执行旧版 CTF/write-up 命令时，请先检查 `binwalk --version`。<sup>[[11]](#references)</sup>

⚠️  **安全提示** – **2.1.2b 到 2.3.3** 版本受到 **Path Traversal** 漏洞（CVE-2022-4510）的影响；该公告未列出已修复的 pip 版本。请避免使用受影响的版本提取不受信任的样本，或通过容器/非特权 UID 隔离该工具。<sup>[[4]](#references)</sup>

### Foremost

另一个用于查找隐藏文件的常用工具是 **foremost**。你可以在 `/etc/foremost.conf` 中找到 foremost 的配置文件。如果只想搜索某些特定文件，请取消对应行的注释。如果不取消任何注释，foremost 将搜索其默认配置的文件类型。
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** 是另一个可用于查找和提取**嵌入文件中的文件**的工具。在这种情况下，你需要在配置文件（_/etc/scalpel/scalpel.conf_）中取消注释要提取的文件类型。
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

This tool comes inside kali but you can find it here: <https://github.com/simsong/bulk_extractor>

Bulk Extractor 可以扫描证据镜像，并使用多个 scanners **并行 carve 出 pcap fragments**、**网络 artefacts（URLs、domains、IPs、MACs、e-mails）**以及许多其他对象。

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

它提供 GUI 和 CLI 版本。你可以选择希望 PhotoRec 搜索的**文件类型**。

![运行所有 scanner、积极 carve JPEG 并生成 bodyfile - PhotoRec：它提供 GUI 和 CLI 版本。你可以选择希望 PhotoRec 搜索的文件类型](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover`（metadata-first）

在进行 raw signature carving 之前，如果卷 metadata 仍可解析，请先尝试 filesystem-aware recovery。默认情况下，`tsk_recover` 只导出未分配文件；`-a` 选择已分配文件，`-e` 导出两者。对于整个磁盘的 image，将 `mmls` 输出的分区**起始扇区**传递给 `-o`（不要将其转换为字节）。如果输入本身已经是分区 image，则省略 `-o`。<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
此过程可以保留基于文件系统的名称和路径，而 header/footer carving 无法做到这一点；对于元数据缺失或不可用的条目，随后运行 Foremost、Scalpel 或 PhotoRec。<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview（对故障驱动器进行 imaging）

当物理驱动器不稳定时，最佳实践是**先对其进行 imaging**，然后仅针对该 image 运行 carving 工具。`ddrescue`（GNU project）专注于可靠地复制损坏的磁盘，同时保留不可读扇区的日志。
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`** 选项控制每次复制的扇区数；较小的值有助于处理速度较慢的驱动器。<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic（EXT 3/4 undelete）

如果源文件系统基于 Linux EXT，则可能无需进行完整 carving 即可恢复最近删除的文件；这些基于 journal 的工具可在已卸载的文件系统或只读镜像上运行。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **兼容性说明** – ext4magic 已被放弃；其项目页面警告称，当前的文件系统已不再与其兼容。<sup>[[10]](#references)</sup>

> 🛈 如果文件系统是在删除操作之后挂载的，数据块可能已经被重新使用——在这种情况下，仍需要进行适当的 carving（Foremost/Scalpel）。

### binvis

查看[代码](https://code.google.com/archive/p/binvis/)和[网页工具](https://binvis.io/#/)。

#### BinVis 的功能

- 可视化且主动的**结构查看器**
- 针对不同关注点的多个图表
- 聚焦样本的部分内容
- **查看字符串和资源**，例如 PE 或 ELF 可执行文件中的内容
- 获取文件中用于密码分析的**模式**
- **识别**打包器或编码器算法
- 通过模式**识别**Steganography
- **可视化**二进制差异分析

在 black-boxing 场景中，BinVis 是**熟悉未知目标的良好起点**。

## 特定的数据 carving 工具

### FindAES

通过搜索 AES 密钥调度来查找 AES 密钥。能够查找 128、192 和 256 位密钥，例如 TrueCrypt 和 BitLocker 使用的密钥。

从[这里](https://sourceforge.net/projects/findaes/)下载。

### YARA-X（对 carving 产物进行初步分析）

[YARA-X](https://github.com/VirusTotal/yara-x) 是 YARA 的 Rust 重写版本，于 2024 年推出；VirusTotal 报告称，某些正则表达式规则和复杂循环规则的运行速度可以显著提升。<sup>[[5]](#references)</sup> 其 CLI 名称为 `yr`，`scan` 命令支持递归扫描、线程数设置和元数据输出。<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Complementary tools

你可以使用 [**viu** ](https://github.com/atanunq/viu)从终端查看图像。  \
你可以使用 Linux 命令行工具 **pdftotext** 将 pdf 转换为文本并阅读。





## References

- [1] [Autopsy 4.21 发布说明](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python 工具 README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk 中的路径遍历（CVE-2022-4510）- GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA 已死，YARA-X 永存 - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI 命令](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue 手册](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic 手册](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic 项目状态](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit：tsk_recover 手册](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
