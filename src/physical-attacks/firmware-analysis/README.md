# 固件分析

{{#include ../../banners/hacktricks-training.md}}

## **介绍**

固件是使设备正常运行的基本软件，通过管理和促进硬件组件与用户交互的软件之间的通信。它存储在永久内存中，确保设备在开机时能够访问重要指令，从而启动操作系统。检查和可能修改固件是识别安全漏洞的关键步骤。

## **收集信息**

**收集信息**是理解设备构成和所用技术的关键初步步骤。此过程涉及收集以下数据：

- CPU架构和运行的操作系统
- 引导加载程序的具体信息
- 硬件布局和数据表
- 代码库指标和源位置
- 外部库和许可证类型
- 更新历史和监管认证
- 架构和流程图
- 安全评估和已识别的漏洞

为此，**开源情报（OSINT）**工具是不可或缺的，分析任何可用的开源软件组件通过手动和自动审查过程也同样重要。像[Coverity Scan](https://scan.coverity.com)和[Semmle’s LGTM](https://lgtm.com/#explore)这样的工具提供免费的静态分析，可以用来发现潜在问题。

## **获取固件**

获取固件可以通过多种方式进行，每种方式的复杂程度不同：

- **直接**从源头（开发者、制造商）
- **根据**提供的说明进行**构建**
- **从**官方支持网站**下载**
- 利用**Google dork**查询查找托管的固件文件
- 直接访问**云存储**，使用像[S3Scanner](https://github.com/sa7mon/S3Scanner)这样的工具
- 通过中间人技术**拦截**更新
- 通过**UART**、**JTAG**或**PICit**等连接**提取**设备中的固件
- 在设备通信中**嗅探**更新请求
- 识别并使用**硬编码的更新端点**
- 从引导加载程序或网络**转储**
- 在万不得已时，**拆卸并读取**存储芯片，使用适当的硬件工具

## 分析固件

现在你**拥有固件**，你需要提取有关它的信息，以了解如何处理它。你可以使用的不同工具有：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果你使用这些工具没有找到太多信息，可以使用 `binwalk -E <bin>` 检查图像的 **entropy**，如果熵低，那么它不太可能被加密。如果熵高，则可能被加密（或以某种方式压缩）。

此外，你可以使用这些工具提取 **嵌入固件中的文件**：

{{#ref}}
../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 来检查文件。

### 获取文件系统

使用之前提到的工具，如 `binwalk -ev <bin>`，你应该能够 **提取文件系统**。\
Binwalk 通常会将其提取到一个 **以文件系统类型命名的文件夹** 中，通常是以下之一：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动文件系统提取

有时，binwalk **在其签名中没有文件系统的魔术字节**。在这些情况下，使用 binwalk **查找文件系统的偏移量并从二进制文件中切割压缩的文件系统**，并根据其类型使用以下步骤 **手动提取** 文件系统。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行以下 **dd 命令** 切割 Squashfs 文件系统。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
另外，可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（在上面的示例中使用）

`$ unsquashfs dir.squashfs`

文件将随后位于 "`squashfs-root`" 目录中。

- CPIO 存档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于带 NAND 闪存的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 分析固件

一旦获得固件，拆解它以理解其结构和潜在漏洞是至关重要的。此过程涉及利用各种工具分析和提取固件映像中的有价值数据。

### 初步分析工具

提供了一组命令用于对二进制文件（称为 `<bin>`）进行初步检查。这些命令有助于识别文件类型、提取字符串、分析二进制数据以及理解分区和文件系统的细节：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
为了评估图像的加密状态，使用 `binwalk -E <bin>` 检查 **entropy**。低熵表明缺乏加密，而高熵则表示可能存在加密或压缩。

对于提取 **embedded files**，推荐使用 **file-data-carving-recovery-tools** 文档和 **binvis.io** 进行文件检查的工具和资源。

### 提取文件系统

使用 `binwalk -ev <bin>`，通常可以提取文件系统，通常提取到一个以文件系统类型命名的目录中（例如，squashfs，ubifs）。然而，当 **binwalk** 由于缺少魔术字节而无法识别文件系统类型时，需要手动提取。这涉及使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令提取文件系统：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
之后，根据文件系统类型（例如，squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取内容。

### 文件系统分析

提取文件系统后，开始寻找安全漏洞。关注不安全的网络守护进程、硬编码的凭据、API 端点、更新服务器功能、未编译的代码、启动脚本和编译的二进制文件以进行离线分析。

**关键位置**和**项目**检查包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 配置和脚本文件中的潜在漏洞
- 嵌入的二进制文件以进行进一步分析
- 常见 IoT 设备的网络服务器和二进制文件

几个工具有助于揭示文件系统中的敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 用于敏感信息搜索
- [**固件分析和比较工具 (FACT)**](https://github.com/fkie-cad/FACT_core) 用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba) 用于静态和动态分析

### 对编译二进制文件的安全检查

必须仔细检查文件系统中发现的源代码和编译的二进制文件以寻找漏洞。像 **checksec.sh** 这样的工具用于 Unix 二进制文件，**PESecurity** 用于 Windows 二进制文件，帮助识别可能被利用的未保护二进制文件。

## 模拟固件进行动态分析

模拟固件的过程使得可以对设备的操作或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖性的问题，但将根文件系统或特定二进制文件转移到具有匹配架构和字节序的设备（例如 Raspberry Pi）或预构建的虚拟机上，可以促进进一步的测试。

### 模拟单个二进制文件

检查单个程序时，识别程序的字节序和 CPU 架构至关重要。

#### MIPS 架构示例

要模拟 MIPS 架构的二进制文件，可以使用以下命令：
```bash
file ./squashfs-root/bin/busybox
```
并安装必要的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
对于 MIPS（大端），使用 `qemu-mips`，而对于小端二进制文件，选择 `qemu-mipsel`。

#### ARM 架构仿真

对于 ARM 二进制文件，过程类似，使用 `qemu-arm` 模拟器进行仿真。

### 完整系统仿真

像 [Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具，促进完整固件仿真，自动化过程并帮助动态分析。

## 实践中的动态分析

在这个阶段，使用真实或仿真的设备环境进行分析。保持对操作系统和文件系统的 shell 访问是至关重要的。仿真可能无法完美模拟硬件交互，因此需要偶尔重新启动仿真。分析应重新访问文件系统，利用暴露的网页和网络服务，并探索引导加载程序漏洞。固件完整性测试对于识别潜在后门漏洞至关重要。

## 运行时分析技术

运行时分析涉及在其操作环境中与进程或二进制文件交互，使用工具如 gdb-multiarch、Frida 和 Ghidra 设置断点，并通过模糊测试和其他技术识别漏洞。

## 二进制利用和概念验证

为识别的漏洞开发 PoC 需要对目标架构和低级语言编程有深入理解。嵌入式系统中的二进制运行时保护很少，但在存在时，可能需要使用如返回导向编程（ROP）等技术。

## 准备好的操作系统用于固件分析

像 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的操作系统提供预配置的固件安全测试环境，配备必要的工具。

## 准备好的操作系统用于分析固件

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个旨在帮助您对物联网（IoT）设备进行安全评估和渗透测试的发行版。它通过提供一个预配置的环境，加载所有必要的工具，为您节省了大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装固件安全测试工具。

## 漏洞固件练习

要练习发现固件中的漏洞，可以使用以下漏洞固件项目作为起点。

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## 参考文献

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## 培训和认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
