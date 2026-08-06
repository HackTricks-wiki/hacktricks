# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**查看这篇精彩文章：** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## 面向攻击者的 TL;DR
- Kerberos 是默认的 AD auth protocol；大多数 lateral-movement 链都会涉及它。
- 可以将其理解为 **三个 operator 阶段**：<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → 使用 password/hash/certificate 获取 **TGT**。**AS-REP roasting**、**over-pass-the-hash / pass-the-key** 和 **PKINIT** 都属于这一阶段。
- **TGS-REQ / TGS-REP** → 使用 TGT 获取 **service tickets**。**Kerberoasting**、**S4U abuse**、**delegation abuse** 以及大多数 **ticket-forging tradecraft** 都与此相关。
- **AP-REQ / AP-REP** → 向 service 出示 ticket。**pass-the-ticket** 和面向特定 service 的 lateral movement 发生在这一阶段。
- 如需实操 cheatsheets（AS-REP/Kerberoasting、ticket forgery、delegation abuse 等），请参阅：
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- 将本页面作为 **overview / “近期发生了什么变化”** 索引，然后跳转到 [Kerberoast](kerberoast.md)、[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)、[AD Certificates / PKINIT abuse](ad-certificates.md) 或 [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md) 的专门页面。

## 最新攻击笔记（2024-2026）
- **RC4 hardening 改变的是默认值，而不是 Kerberos 本身** —— 现代 DC hardening 重点关注未显式设置 `msDS-SupportedEncryptionTypes` 的账户所使用的 **default assumed encryption types**。2026 rollout 之后，在已打补丁的 DC 上，这些账户越来越多地默认使用 **AES-only**，因此盲目假设使用 `/rc4` 进行 Kerberoast 的情况更容易失败。不过，**显式启用 RC4 的 service accounts 仍然是非常理想的 offline-crack 目标**。<sup>[[1]](#references)</sup>
- **PAC validation enforcement 对 forged tickets 很重要** —— 2024 年的 PAC-signature hardening 意味着，**golden/diamond/sapphire/extraSID-style abuses** 需要更真实的 PAC 数据以及正确的 signing context。未打补丁的 domains，或仍处于 compatibility/audit-style deployments 的 domains，仍然是更容易攻击的目标。<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos 发生了两次变化**：<sup>[[2]](#references)</sup>
- **Strong certificate binding**（KB5014754 timeline）使得在 fully enforced environments 中，不严谨的 certificate-to-account mappings 变得不太可靠。
- **CVE-2025-26647** 围绕 **altSecID / SKI certificate mappings** 增加了另一层 hardening。如果 DCs 未打补丁、仍处于 auditing 状态，或明确绕过 NTAuth validation，那么 pass-the-certificate / shadow-credential follow-on abuse 仍然更具可行性。
- **Cross-domain / cross-forest delegation abuse 仍然非常活跃** —— Windows 支持现代的 cross-realm **S4U2Self/S4U2Proxy** flows，因此另一个 domain 中可写的 delegation attributes 仍然很有价值。通常的阻碍是 tooling fidelity 和 trust/policy details，而不是 protocol support。
- **Recursive multi-domain RBCD 在实际操作中很重要** —— 在拥有 3 个或更多 domains 的 forests 中，**S4U2Self/S4U2Proxy** 可以通过 trust referrals 递归执行，而 **SPN-less** abuse 可能需要最后增加一个 **`S4U2Self+U2U`** hop，以及依赖 RC4 的 ticket handling。请参阅 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)。<sup>[[4]](#references)</sup>
- **Windows Server 2025 通过 **dMSA** migration logic 引入了新的 Kerberos-adjacent attack surface。如果在 2025 domain 中发现针对 OUs 或 service-account objects 的 delegated rights，请查看专门的 [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md)，不要将其当作“又一个 gMSA”。

## 现代 domains 中的快速 operator 检查

在选择 Kerberos attack path 之前，快速回答四个问题：

1. **哪些 accounts 仍然支持 RC4？**
2. **哪些 users 不要求 pre-auth？**
3. **哪些 objects 暴露了 delegation abuse？**
4. **domain 的哪些部分足够新，已经执行了最新的 hardening？**
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
- 如果**有价值的 SPN 账户明确支持 RC4**，Kerberoasting 仍然成本低、速度快。
- 如果大多数服务账户都**没有显式的 etype 配置**，预计在已更新的 2026 DC 上会表现为**仅支持 AES**，并规划更慢的离线破解或采用其他路径。
- 如果存在 **RBCD / KCD / unconstrained delegation**，S4U 通常比 brute-force 更有效。
- 如果涉及**证书认证**，请记住，PKINIT 路径失败**并不总是意味着证书无用**；在许多环境中，同一证书仍可用于 **Schannel/LDAPS** abuse（参见 [AD Certificates / PKINIT abuse](ad-certificates.md)）。

## 会改变攻击计划的常见 Kerberos 错误
- **`KDC_ERR_ETYPE_NOTSUPP`** → 目标账户 / DC 不会使用你请求的加密类型。不要继续仅使用 RC4 重试；请提供 **AES keys**，或改为请求 **AES** roast material。
- **`KRB_AP_ERR_MODIFIED`** → 你很可能使用了**错误的 service key**、**错误的 SPN**，或者伪造的 ticket 与实际解密它的服务账户不匹配。
- **`KRB_AP_ERR_SKEW`** → 你的时间不正确。先与 DC 同步，再调试其他问题。
- 在 S4U / delegation 流程中出现 **`KDC_ERR_BADOPTION`** → 通常表示存在**敏感 / 不可委派用户**、使用了错误的 delegation 模型，或者你正在尝试使用 **classic KCD**，而只有 **RBCD** 才会接受不可转发的 S4U2Self ticket。

## 参考资料
- [1] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): How does Kerberos work? – Theory](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
