# 文件/数据 Carving 与恢复工具

{{#include ../../../banners/hacktricks-training.md}}

## Carving 与恢复工具

始终对**已验证的副本**进行 carve，而不是原始设备。有关只读获取和哈希工作流程，请参阅[镜像获取与挂载](../image-acquisition-and-mount.md)。

更多工具见 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

取证中最常用于从镜像中提取文件的工具是 [**Autopsy**](https://www.autopsy.com/download/)。下载并安装，然后让它摄取文件以查找“隐藏”文件。请注意，Autopsy 支持磁盘镜像和其他类型的镜像，但不支持简单文件。

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** 是一款用于分析二进制文件、查找嵌入内容的工具。**Binwalk v3** 是用 Rust 重写的版本，支持自动提取（`-e`）、对已知和未知对象进行原始 carving（`-c`）、递归/Matryoshka 扫描（`-M`）以及可配置的工作线程。项目建议在需要所有外部提取器时使用其 Docker 构建；`cargo install binwalk` 会安装 Rust CLI，但不包含这些外部依赖。<sup>[[11]](#references)</sup>

**实用的 v3 命令**：

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

旧版 v2 的 `--dd='.*'` 配方**并不**等同于 v3 的 `-c`；执行旧的 CTF/写-up 命令时，先检查 `binwalk --version`。<sup>[[11]](#references)</sup>

⚠️  **安全说明** – **2.1.2b 到 2.3.3** 版本受 **Path Traversal** 漏洞（CVE-2022-4510）影响；公告中没有列出已修复的 pip 版本。不要使用受影响版本提取不可信样本，或者使用容器/非特权 UID 隔离该工具。<sup>[[4]](#references)</sup>

### Foremost

**foremost** 是另一款常用的隐藏文件查找工具。你可以在 `/etc/foremost.conf` 中找到 foremost 的配置文件。如果只想搜索某些特定文件，就取消它们的注释。如果不取消任何注释，foremost 将搜索默认配置的文件类型。

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** 是另一款可用于查找并提取**嵌入文件中的文件**的工具。此时，你需要在配置文件（_/etc/scalpel/scalpel.conf_）中取消注释要提取的文件类型。

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3 分片文件 carving

当基于元数据的恢复和连续 carving 工具无法完整恢复分片文件时，**Scalpel3** 可以使用文件/块验证器重新组装受支持的格式。它的代码库与上文的旧版 `scalpel` 命令不同。首先，使用 carving 时相同的块大小创建其所需的 blockmap；如果已知，可使用 `fsstat` 获取文件系统簇大小；否则，应在扫描分区映像前确定一个合理的值。仅对已验证的副本运行，并将输出写入单独的卷。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

将 `4096` 替换为选定的块大小。`-w` 会保留 **PROMISING** 候选项以及已验证的候选项，`-b` 会写入 blockvectors，以帮助检查重建后的布局。文件被列为 PROMISING，或具有常见扩展名，都不能证明其已完整恢复；使用前请验证内容。<sup>[[13]](#references)[[14]](#references)</sup> 如需在 carving 前定位已删除的分区或间隙，请参阅[查找已列出分区以外的数据](./#finding-data-outside-listed-partitions)。

### Bulk Extractor 2.x   

此工具包含在 Kali 中，但也可以在此处获取：<https://github.com/simsong/bulk_extractor>

Bulk Extractor 可以扫描取证镜像，并使用多个扫描器并行 carve **pcap 片段**、**网络 artefacts（URL、域名、IP、MAC、电子邮件）**以及许多其他对象。

v2.1.1 版本文档介绍了 Autotools 构建方式，以及用于 carving 所有连续 JPEG 的 `-S jpeg_carve_mode=2` 设置。<sup>[[2]](#references)</sup>

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

捆绑的 `bulk_diff.py` 用于比较两次 bulk_extractor 运行结果，而 `bulk_extractor_reader.py` 用于读取报告和特征文件。<sup>[[3]](#references)</sup>

### PhotoRec

可在 <https://www.cgsecurity.org/wiki/TestDisk_Download> 获取。

它包含 GUI 和 CLI 版本。你可以选择要让 PhotoRec 搜索的**文件类型**。

![运行所有扫描器，积极地 carve JPEG 并生成 bodyfile - PhotoRec：它包含 GUI 和 CLI 版本。你可以选择要让 PhotoRec 搜索的文件类型](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover`（元数据优先）

在进行原始签名 carving 之前，如果卷元数据仍可解析，请先尝试使用文件系统感知的恢复方式。默认情况下，`tsk_recover` 只导出未分配文件；`-a` 选择已分配文件，`-e` 则导出两者。对于整盘映像，将 `mmls` 输出的分区**起始扇区**传给 `-o`（不要将其转换为字节）。如果输入已经是分区映像，则省略 `-o`。<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

此方法可以保留文件系统派生的名称和路径，而 header/footer carving 无法做到这一点；对于元数据缺失或不可用的条目，之后再运行 Foremost、Scalpel 或 PhotoRec。<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview（对故障硬盘进行映像）

当物理硬盘不稳定时，最佳做法是**先制作映像**，然后只针对映像运行 carving 工具。`ddrescue`（GNU 项目）专注于可靠地复制故障磁盘，同时记录无法读取的扇区。

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

**`--cluster-size`** 选项控制每次复制的扇区数量；较小的值有助于处理速度较慢的驱动器。<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic（EXT 3/4 undelete）

如果源文件系统基于 Linux EXT，或许无需完整 carving 即可恢复最近删除的文件；这些基于日志的工具可用于未挂载的文件系统或只读镜像。<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **兼容性说明** – ext4magic 已停止维护；其项目页面警告称，当前文件系统已不再与其兼容。<sup>[[10]](#references)</sup>

> 🛈 如果文件系统在删除后曾被挂载，数据块可能已经被重用——这种情况下仍需进行适当的 carving（Foremost/Scalpel）。

### binvis

查看[代码](https://code.google.com/archive/p/binvis/)和[网页工具](https://binvis.io/#/)。

#### BinVis 的功能

- 可视化且交互式的**结构查看器**
- 针对不同关注点提供多种绘图
- 聚焦样本的特定部分
- **查看字符串和资源**，例如 PE 或 ELF 可执行文件中的内容
- 获取文件的**模式**，用于密码分析
- **发现**打包器或编码器算法
- 通过模式**识别**隐写术
- **可视化**二进制差分

在黑盒场景中，BinVis 是**熟悉未知目标的绝佳起点**。

## 专用 Data Carving 工具

### FindAES

通过搜索 AES 密钥的密钥调度来查找 AES 密钥。能够查找 128、192 和 256 位密钥，例如 TrueCrypt 和 BitLocker 使用的密钥。

[在此](https://sourceforge.net/projects/findaes/)下载。

### YARA-X（对 carving 提取的工件进行分类）

[YARA-X](https://github.com/VirusTotal/yara-x) 是 YARA 的 Rust 重写版本，于 2024 年推出；VirusTotal 报告称，某些正则表达式规则和复杂循环规则的运行速度可显著提升。<sup>[[5]](#references)</sup> 其 CLI 名为 `yr`，`scan` 命令支持递归扫描、设置线程数以及输出元数据。<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## 配套工具

你可以使用 [**viu** ](https://github.com/atanunq/viu)在终端中查看图像。  \
你可以使用 linux 命令行工具 **pdftotext** 将 pdf 转换为文本并阅读。







## References

- [1] [Autopsy 4.21 发布说明](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 自述文件](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python 工具自述文件](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk 中的路径遍历（CVE-2022-4510）- GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA 已死，YARA-X 万岁 - VirusTotal 博客](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI 命令](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue 手册](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic 手册](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic 项目状态](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 自述文件](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit：tsk_recover 手册](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Scalpel3 自述文件](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Scalpel3 手册](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Scalpel3 测试工作流](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
