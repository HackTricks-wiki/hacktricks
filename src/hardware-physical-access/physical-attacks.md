# 物理攻击

{{#include ../banners/hacktricks-training.md}}

## BIOS 密码恢复和系统安全

**重置 BIOS** 可以通过几种方式实现。大多数主板都包含一个 **电池**，当移除约 **30 分钟** 后，将重置 BIOS 设置，包括密码。或者，可以通过调整 **主板上的跳线** 来重置这些设置，方法是连接特定的引脚。

对于无法或不实用进行硬件调整的情况，**软件工具** 提供了解决方案。使用 **Kali Linux** 等发行版从 **Live CD/USB** 启动系统，可以访问像 **_killCmos_** 和 **_CmosPWD_** 这样的工具，帮助进行 BIOS 密码恢复。

在 BIOS 密码未知的情况下，错误输入 **三次** 通常会导致错误代码。可以在像 [https://bios-pw.org](https://bios-pw.org) 这样的网站上使用该代码，可能会检索到可用的密码。

### UEFI 安全

对于使用 **UEFI** 而非传统 BIOS 的现代系统，可以利用工具 **chipsec** 来分析和修改 UEFI 设置，包括禁用 **安全启动**。这可以通过以下命令完成：
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM分析和冷启动攻击

RAM在断电后会短暂保留数据，通常为**1到2分钟**。通过施加冷物质，如液氮，这种持久性可以延长到**10分钟**。在此延长期内，可以使用**dd.exe**和**volatility**等工具创建**内存转储**进行分析。

---

## 直接内存访问（DMA）攻击

**INCEPTION**是一个旨在通过DMA进行**物理内存操作**的工具，兼容**FireWire**和**Thunderbolt**等接口。它允许通过修补内存以接受任何密码来绕过登录程序。然而，它对**Windows 10**系统无效。

---

## 使用Live CD/USB进行系统访问

更改系统二进制文件，如**_sethc.exe_**或**_Utilman.exe_**，为**_cmd.exe_**的副本，可以提供具有系统权限的命令提示符。可以使用**chntpw**等工具编辑Windows安装的**SAM**文件，从而允许更改密码。

**Kon-Boot**是一个工具，可以在不知道密码的情况下登录Windows系统，通过临时修改Windows内核或UEFI。更多信息可以在[https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)找到。

---

## 处理Windows安全功能

### 启动和恢复快捷键

- **Supr**：访问BIOS设置。
- **F8**：进入恢复模式。
- 在Windows横幅后按**Shift**可以绕过自动登录。

### 坏USB设备

像**Rubber Ducky**和**Teensyduino**这样的设备作为创建**坏USB**设备的平台，能够在连接到目标计算机时执行预定义的有效载荷。

### 卷影副本

管理员权限允许通过PowerShell创建敏感文件的副本，包括**SAM**文件。

---

## 绕过BitLocker加密

如果在内存转储文件（**MEMORY.DMP**）中找到**恢复密码**，则可能绕过BitLocker加密。可以使用**Elcomsoft Forensic Disk Decryptor**或**Passware Kit Forensic**等工具实现此目的。

---

## 社会工程学用于恢复密钥添加

可以通过社会工程学策略添加新的BitLocker恢复密钥，说服用户执行一个命令，添加一个由零组成的新恢复密钥，从而简化解密过程。

---

## 利用机箱入侵/维护开关恢复BIOS出厂设置

许多现代笔记本电脑和小型桌面电脑都包括一个**机箱入侵开关**，由嵌入式控制器（EC）和BIOS/UEFI固件监控。虽然开关的主要目的是在设备被打开时发出警报，但供应商有时会实现一个**未记录的恢复快捷键**，当开关以特定模式切换时触发。

### 攻击如何工作

1. 开关连接到EC上的**GPIO中断**。
2. 运行在EC上的固件跟踪**按压的时间和次数**。
3. 当识别到硬编码模式时，EC调用*主板重置*例程，**擦除系统NVRAM/CMOS的内容**。
4. 在下次启动时，BIOS加载默认值——**超级用户密码、安全启动密钥和所有自定义配置被清除**。

> 一旦安全启动被禁用且固件密码消失，攻击者可以简单地启动任何外部操作系统映像，并获得对内部驱动器的无限制访问。

### 现实世界示例 – Framework 13 笔记本电脑

Framework 13（第11/12/13代）的恢复快捷键是：
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
在第十个周期后，EC 设置一个标志，指示 BIOS 在下次重启时擦除 NVRAM。整个过程大约需要 40 秒，并且**只需要一个螺丝刀**。

### 通用利用程序

1. 开机或挂起-恢复目标，以便 EC 正在运行。
2. 移除底部盖以暴露入侵/维护开关。
3. 复制特定于供应商的切换模式（查阅文档、论坛或逆向工程 EC 固件）。
4. 重新组装并重启 – 固件保护应被禁用。
5. 启动一个实时 USB（例如 Kali Linux）并执行常规后渗透（凭证转储、数据外泄、植入恶意 EFI 二进制文件等）。

### 检测与缓解

* 在操作系统管理控制台中记录机箱入侵事件，并与意外的 BIOS 重置进行关联。
* 在螺丝/盖上使用**防篡改密封**以检测开启。
* 将设备放置在**物理控制区域**内；假设物理访问等于完全妥协。
* 在可用的情况下，禁用供应商的“维护开关重置”功能，或要求额外的加密授权以进行 NVRAM 重置。

---

## 参考文献

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
