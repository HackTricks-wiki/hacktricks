# 物理攻击

{{#include ../banners/hacktricks-training.md}}

## BIOS 密码恢复和系统安全

**重置 BIOS** 可以通过几种方式实现。大多数主板都包含一个 **电池**，当移除约 **30 分钟** 后，将重置 BIOS 设置，包括密码。或者，可以通过调整 **主板上的跳线** 来重置这些设置，方法是连接特定的引脚。

对于无法或不实用进行硬件调整的情况，**软件工具** 提供了解决方案。使用 **Kali Linux** 等发行版从 **Live CD/USB** 运行系统，可以访问像 **_killCmos_** 和 **_CmosPWD_** 这样的工具，帮助进行 BIOS 密码恢复。

在 BIOS 密码未知的情况下，错误输入 **三次** 通常会导致错误代码。可以在像 [https://bios-pw.org](https://bios-pw.org) 这样的网站上使用此代码来检索可用的密码。

### UEFI 安全

对于使用 **UEFI** 而非传统 BIOS 的现代系统，可以利用工具 **chipsec** 来分析和修改 UEFI 设置，包括禁用 **安全启动**。可以使用以下命令完成此操作：

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM 分析和冷启动攻击

在断电后，RAM 会短暂保留数据，通常为 **1 到 2 分钟**。通过施加冷物质，如液氮，可以将这种持续时间延长至 **10 分钟**。在此延长期间，可以使用像 **dd.exe** 和 **volatility** 这样的工具创建 **内存转储** 进行分析。

### 直接内存访问 (DMA) 攻击

**INCEPTION** 是一个旨在通过 DMA 进行 **物理内存操作** 的工具，兼容 **FireWire** 和 **Thunderbolt** 等接口。它允许通过修补内存以接受任何密码来绕过登录程序。然而，它对 **Windows 10** 系统无效。

### Live CD/USB 进行系统访问

通过用 **_cmd.exe_** 的副本替换系统二进制文件，如 **_sethc.exe_** 或 **_Utilman.exe_**，可以提供具有系统权限的命令提示符。可以使用 **chntpw** 等工具编辑 Windows 安装的 **SAM** 文件，从而允许更改密码。

**Kon-Boot** 是一个工具，可以在不知道密码的情况下登录 Windows 系统，通过临时修改 Windows 内核或 UEFI。更多信息可以在 [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) 找到。

### 处理 Windows 安全功能

#### 启动和恢复快捷键

- **Supr**: 访问 BIOS 设置。
- **F8**: 进入恢复模式。
- 在 Windows 横幅后按 **Shift** 可以绕过自动登录。

#### BAD USB 设备

像 **Rubber Ducky** 和 **Teensyduino** 这样的设备作为创建 **坏 USB** 设备的平台，能够在连接到目标计算机时执行预定义的有效载荷。

#### 卷影副本

管理员权限允许通过 PowerShell 创建敏感文件的副本，包括 **SAM** 文件。

### 绕过 BitLocker 加密

如果在内存转储文件 (**MEMORY.DMP**) 中找到 **恢复密码**，则可能绕过 BitLocker 加密。可以使用像 **Elcomsoft Forensic Disk Decryptor** 或 **Passware Kit Forensic** 这样的工具来实现这一目的。

### 社会工程学用于恢复密钥添加

可以通过社会工程学策略添加新的 BitLocker 恢复密钥，说服用户执行一个命令，添加一个由零组成的新恢复密钥，从而简化解密过程。

{{#include ../banners/hacktricks-training.md}}
