# 固件分析

{{#include ../../banners/hacktricks-training.md}}

## **简介**

### 相关资源


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


固件是使设备能够正确运行的关键软件，负责管理并促进硬件组件与用户交互的软件之间的通信。它存储在永久存储器中，确保设备通电时即可访问重要指令，从而启动操作系统。检查并可能修改固件是识别安全漏洞的重要步骤。

## **信息收集**

**信息收集** 是了解设备构成和所用技术的关键初始步骤。此过程包括收集有关以下内容的数据：

- CPU 架构及其运行的操作系统
- bootloader 具体信息
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库和许可类型
- 更新历史和监管认证
- 架构和流程图
- 安全评估和已识别的漏洞

为此，**open-source intelligence (OSINT)** 工具非常有价值，同时对任何可用的开源软件组件进行人工和自动化审查也同样重要。像 [Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 这样的工具提供免费静态分析，可用于发现潜在问题。

## **获取固件**

获取固件可以通过多种方式进行，每种方式都有不同的复杂度：

- **Directly** 来自来源（开发者、制造商）
- **Building** 根据提供的说明构建
- **Downloading** 从官方支持站点下载
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问 **cloud storage**，使用像 [S3Scanner](https://github.com/sa7mon/S3Scanner) 这样的工具
- 通过 **man-in-the-middle** 技术拦截 **updates**
- 通过 UART、JTAG 或 PICit 等连接 **Extracting** 出设备中的固件
- 在设备通信中 **Sniffing** 更新请求
- 识别并使用 **hardcoded update endpoints**
- 从 bootloader 或网络 **Dumping**
- 当其他方法均失败时，使用适当的硬件工具 **Removing and reading** 存储芯片

## 分析固件

现在你 **have the firmware**，需要从中提取信息以决定如何处理它。可以使用的不同工具包括：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果用那些工具找不到太多内容，可以用 `binwalk -E <bin>` 检查镜像的**熵（entropy）**：熵低则不太可能被加密；熵高则很可能被加密（或以某种方式被压缩）。

此外，你可以使用这些工具来提取固件中嵌入的**文件**：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）来检查文件。

### Getting the Filesystem

使用前面提到的工具，例如 `binwalk -ev <bin>`，你应该能够**提取文件系统**。\
Binwalk 通常会将其解压到一个以文件系统类型命名的**文件夹**中，该类型通常为以下之一：squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs。

#### Manual Filesystem Extraction

有时，binwalk 的签名中**不包含文件系统的魔数（magic byte）**。在这种情况下，使用 binwalk 查找文件系统的偏移量，并从二进制中**切出（carve）被压缩的文件系统**，然后根据其类型**手动提取**文件系统，按下面的步骤操作。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行以下 **dd command** 来对 Squashfs filesystem 进行 carving。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
或者，也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（在上面的示例中使用）

`$ unsquashfs dir.squashfs`

文件随后将位于 "`squashfs-root`" 目录中。

- CPIO 存档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于带有 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 固件分析

一旦获取到固件，就必须将其拆解以了解其结构和潜在漏洞。此过程涉及使用各种工具来分析并从固件镜像中提取有价值的数据。

### 初步分析工具

下面提供了一组用于初步检查二进制文件（称为 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和文件系统的详细信息：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
要评估镜像的加密状态，使用 `binwalk -E <bin>` 检查 **entropy**。低 entropy 表明可能未加密，而高 entropy 则表示可能已加密或已压缩。

要提取 **embedded files**，建议使用像 **file-data-carving-recovery-tools** 文档和用于文件检查的 **binvis.io** 等工具和资源。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，通常会将其解压到以文件系统类型命名的目录（例如 squashfs、ubifs）。然而，当 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型时，就需要手动提取。此过程包括使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令提取出文件系统：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），会使用不同的命令手动提取内容。

### 文件系统分析

在提取文件系统后，就开始寻找安全漏洞。重点关注不安全的网络守护进程、硬编码凭证、API 端点、更新服务器功能、未编译的代码、启动脚本以及用于离线分析的已编译二进制文件。

**关键位置** 和 **要检查的项目** 包括：

- **etc/shadow** 和 **etc/passwd**（用于用户凭证）
- **etc/ssl** 中的 SSL 证书和密钥
- 用于查找潜在漏洞的配置和脚本文件
- 用于进一步分析的嵌入二进制文件
- 常见 IoT 设备的 web 服务器和二进制文件

有若干工具可以帮助在文件系统中发现敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### 已编译二进制文件的安全检查

必须对在文件系统中发现的源代码和已编译二进制文件进行漏洞审查。像 **checksec.sh**（用于 Unix 二进制）和 **PESecurity**（用于 Windows 二进制）这样的工具可以帮助识别可能被利用的未受保护二进制。

## 仿真固件以进行 dynamic analysis

通过仿真固件可以对设备的运行或单个程序进行 **dynamic analysis**。该方法可能会遇到硬件或架构依赖的问题，但将 root filesystem 或特定二进制文件转移到具有匹配架构和字节序（endianness）的设备（例如 Raspberry Pi）或预构建的虚拟机上，可以促进进一步测试。

### 仿真单个二进制文件

在检查单个程序时，确定程序的字节序（endianness）和 CPU 架构至关重要。

#### MIPS 架构示例

要仿真一个 MIPS 架构的二进制文件，可以使用以下命令：
```bash
file ./squashfs-root/bin/busybox
```
并安装必要的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
对于 MIPS（大端），使用 `qemu-mips`；对于小端二进制，使用 `qemu-mipsel`。

#### ARM Architecture Emulation

对于 ARM 二进制，过程类似，使用 `qemu-arm` 进行仿真。

### Full System Emulation

像 [Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可以简化完整系统固件仿真，自动化流程并辅助动态分析。

## Dynamic Analysis in Practice

在此阶段，可使用真实设备或仿真环境进行分析。保持对操作系统和文件系统的 shell 访问至关重要。仿真可能无法完全模拟硬件交互，因此有时需要重启仿真。分析应反复检查文件系统、利用暴露的网页和网络服务，并探索 bootloader 漏洞。固件完整性检测对于发现潜在后门漏洞非常关键。

## Runtime Analysis Techniques

运行时分析涉及在目标运行环境中与进程或二进制交互，使用诸如 gdb-multiarch、Frida 和 Ghidra 的工具设置断点，并通过 fuzzing 等技术识别漏洞。

## Binary Exploitation and Proof-of-Concept

为已识别的漏洞开发 PoC 需要深入理解目标架构并使用低级语言编程。嵌入式系统中的二进制运行时保护较少见，但如果存在，可能需要使用像 Return Oriented Programming (ROP) 这样的技术。

## Prepared Operating Systems for Firmware Analysis

像 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的操作系统提供预配置的固件安全测试环境，内置所需工具。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS 是一个旨在帮助你对 Internet of Things (IoT) 设备进行安全评估和 penetration testing 的发行版。它通过提供预配置环境和所有必要工具，节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装了固件安全测试工具。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

即使厂商对固件镜像实施了加密签名校验，**版本回滚（downgrade）保护经常被遗漏**。如果 boot- 或 recovery-loader 仅使用嵌入的公钥验证签名，但不比较 *version*（或单调计数器）被刷写镜像的版本，攻击者就可以合法地安装一个仍然带有有效签名的 **旧的、存在漏洞的固件**，从而重新引入已修补的漏洞。

典型攻击流程：

1. **Obtain an older signed image**
   * 从厂商的公开下载门户、CDN 或支持网站获取。
   * 从配套的移动/桌面应用中提取（例如在 Android APK 的 `assets/firmware/` 目录内）。
   * 从第三方仓库检索，例如 VirusTotal、互联网存档、论坛等。
2. **Upload or serve the image to the device** via any exposed update channel:
   * 通过任何暴露的更新通道将镜像上传或提供给设备：Web UI、mobile-app API、USB、TFTP、MQTT 等。
   * 许多消费级 IoT 设备暴露 *unauthenticated* 的 HTTP(S) 端点，这些端点接受 Base64 编码的固件 blobs，在服务端解码并触发恢复/升级。
3. 降级后，利用在新版中已被修补的漏洞（例如后来添加的 command-injection 过滤器）。
4. 可选择在获得持久性后再刷回最新镜像，或禁用更新以避免被发现。

### 示例：降级后的 Command Injection
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在存在漏洞（被降级）的 firmware 中，`md5` 参数被直接串接到 shell 命令里且没有进行消毒，导致可注入任意命令（此处用于启用基于密钥的 SSH root 访问）。后来的 firmware 版本加入了一个基本的字符过滤，但缺乏降级保护使该修复无效。

### 从移动应用提取 firmware

许多厂商将完整的 firmware 镜像捆绑在其配套的移动应用中，以便应用通过 Bluetooth/Wi‑Fi 更新设备。这些包通常以未加密形式存放在 APK/APEX 的路径如 `assets/fw/` 或 `res/raw/` 下。像 `apktool`、`ghidra`，甚至普通的 `unzip` 等工具可以在不接触物理硬件的情况下提取已签名的镜像。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 评估更新逻辑的检查清单

* update endpoint 的传输/认证是否得到充分保护（TLS + 认证）？
* 设备在刷写前是否比较 **版本号** 或 **monotonic anti-rollback counter**？
* 镜像是否在 secure boot chain 中被验证（例如签名由 ROM code 检查）？
* userland code 是否执行额外的合理性检查（例如允许的 partition map、型号）？
* *partial* 或 *backup* 更新流程是否重用相同的验证逻辑？

> 💡 如果以上任何一项缺失，平台很可能容易受到 rollback attacks。

## 用于练习的易受攻击的 firmware

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## 参考资料

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## 培训与证书

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
