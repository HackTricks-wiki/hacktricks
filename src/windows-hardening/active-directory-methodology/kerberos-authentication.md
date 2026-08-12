# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

如需了解下方总结的交互过程的 protocol-level walkthrough，请参阅 Tarlogic 的 Kerberos article。<sup>[[3]](#references)</sup>

## 攻击者 TL;DR
- Kerberos 是默认的 AD auth protocol；大多数 lateral-movement chains 都会涉及它。
- 可以将其理解为 **三个 operator phases**：<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → 使用 password/hash/certificate 获取 **TGT**。**AS-REP roasting**、**over-pass-the-hash / pass-the-key** 和 **PKINIT** 都发生在这一阶段。
- **TGS-REQ / TGS-REP** → 使用 TGT 获取 **service tickets**。**Kerberoasting**、**S4U abuse**、**delegation abuse** 以及大多数 **ticket-forging tradecraft** 都与此阶段相关。
- **AP-REQ / AP-REP** → 将 ticket 提交给 service。这是 **pass-the-ticket** 和基于 service 的 lateral movement 发生的阶段。
- 如需实战 cheatsheets（AS-REP/Kerberoasting、ticket forgery、delegation abuse 等），请参阅：
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- 将本页面作为 **overview / “what changed recently”** 索引，然后跳转到 [Kerberoast](kerberoast.md)、[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)、[AD Certificates / PKINIT abuse](ad-certificates.md) 或 [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) 的专用页面。

## 最新 attack notes（2024-2026）
- **RC4 hardening 改变的是默认设置，而不是 Kerberos 本身** – 现代 DC hardening 主要关注未显式设置 `msDS-SupportedEncryptionTypes` 的 account 所使用的 **default assumed encryption types**。在 2026 rollout 之后，这些 account 在 patched DC 上越来越多地默认使用 **AES-only**，因此盲目假设使用 `/rc4` 进行 Kerberoast 更容易失败。不过，**显式启用 RC4 的 service accounts 仍然是非常好的 offline-crack targets**。<sup>[[1]](#references)</sup>
- **PAC validation enforcement 对 forged tickets 很重要** – 2024 PAC-signature hardening 意味着，**golden/diamond/sapphire/extraSID-style abuses** 需要更真实的 PAC data 以及正确的 signing context。未打补丁的 domains，或仍处于 compatibility/audit-style deployments 的 domains，仍是更脆弱的 targets。<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos 已发生两次变化**：
- **Strong certificate binding**（KB5014754 timeline）使得在 fully enforced environments 中，不严谨的 certificate-to-account mappings 可靠性降低。
- **CVE-2025-26647** 围绕使用 certificate 的 Subject Key Identifier 的 `altSecurityIdentities` mappings 增加了另一层 hardening。因此，在评估 pass-the-certificate 及相关 certificate-based paths 时，patch level、enforcement 或 audit state，以及 explicit mapping configuration 都很重要。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> 对于 PKINIT，KDC 还会验证 certificate path，并检查其 issuer 是否通过 NTAuth store 受到信任。<sup>[[8]](#references)</sup>
- **Cross-domain / cross-forest delegation abuse 仍然非常活跃** – Windows 支持现代 cross-realm **S4U2Self/S4U2Proxy** flows，因此，另一个 domain 中可写的 delegation attributes 仍然很有价值。通常的阻碍是 tooling fidelity 和 trust/policy details，而不是 protocol support。
- **Recursive multi-domain RBCD 在实际操作中很重要** – 在包含 3 个以上 domains 的 forests 中，**S4U2Self/S4U2Proxy** 可以通过 trust referrals 递归执行，而 **SPN-less** abuse 可能需要最终的 **`S4U2Self+U2U`** hop，以及依赖 RC4 的 ticket handling。请参阅 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)。<sup>[[4]](#references)</sup>
- **Windows Server 2025 引入了 delegated Managed Service Accounts（dMSAs）** 及其 migration logic。如果在 2025 domain 中发现对 OUs 或 service-account objects 的 delegated rights，请查看专门的 [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md)，不要将其当作“另一个 gMSA”。<sup>[[7]](#references)</sup>

## 现代 domains 中的快速 operator checks

在选择 Kerberos attack path 之前，快速回答以下四个问题：

1. **哪些 accounts 仍然支持 RC4？**
2. **哪些 users 不要求 pre-auth？**
3. **哪些 objects 暴露了 delegation abuse？**
4. **domain 的哪些部分足够新，可以 enforcement 最近的 hardening？**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
实际解读：
- 如果**有趣的 SPN 账户明确支持 RC4**，Kerberoasting 仍然成本低且速度快。
- 如果大多数服务账户**没有显式的 etype 配置**，请预计更新后的 2026 DC 将表现为**仅支持 AES**，并规划更慢的离线破解或其他路径。
- 如果存在 **RBCD / KCD / unconstrained delegation**，S4U 通常优于 brute-force。
- 如果涉及**证书身份验证**，请记住：失败的 PKINIT 路径**并不总是意味着证书无用**；在许多环境中，同一证书仍可用于滥用 **Schannel/LDAPS**（参见 [AD Certificates / PKINIT abuse](ad-certificates.md)）。

## 常见的会改变攻击计划的 Kerberos 错误
- **`KDC_ERR_ETYPE_NOTSUPP`** → 目标账户 / DC 不会使用你请求的加密类型。停止仅使用 RC4 重试；提供 **AES keys**，或改为请求 **AES** roast material。
- **`KRB_AP_ERR_MODIFIED`** → 你可能拥有**错误的 service key**、**错误的 SPN**，或伪造的 ticket 与实际解密它的服务账户不匹配。
- **`KRB_AP_ERR_SKEW`** → 你的时间不准确。在进行其他调试之前，先与 DC 同步时间。
- S4U / delegation 流程期间出现 **`KDC_ERR_BADOPTION`** → 通常表示存在**敏感/不可委派用户**、使用了错误的 delegation 模型，或者你正在尝试使用 **classic KCD**，而只有 **RBCD** 才会接受不可转发的 S4U2Self ticket。

## References
- [1] [Microsoft Learn - 检测并修复 Kerberos 中的 RC4 使用](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - 最新 Windows 强化指南和关键日期](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Kerberos 如何工作？– 理论](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - 在跨域和跨林环境中利用 RBCD：第 2 部分](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - KB5014754 基于证书的身份验证变更](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647 Kerberos 证书映射漏洞](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Delegated Managed Service Accounts 概述](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - 智能卡证书要求和 KDC 验证](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
