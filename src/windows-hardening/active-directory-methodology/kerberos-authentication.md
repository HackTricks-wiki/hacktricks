# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Check the amazing post from:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- Kerberos 是默认的 AD auth protocol；大多数 lateral-movement 链都会接触到它。
- 从 **three operator phases** 来理解：
- **AS-REQ / AS-REP** → 使用 password/hash/certificate 获取 **TGT**。这里涉及 **AS-REP roasting**、**over-pass-the-hash / pass-the-key** 和 **PKINIT**。
- **TGS-REQ / TGS-REP** → 使用 TGT 获取 **service tickets**。这里涉及 **Kerberoasting**、**S4U abuse**、**delegation abuse**，以及大多数 **ticket-forging tradecraft**。
- **AP-REQ / AP-REP** → 将 ticket 呈递给 service。这里涉及 **pass-the-ticket** 和特定服务的 lateral movement。
- 关于实操 cheatsheets（AS-REP/Kerberoasting、ticket forgery、delegation abuse 等），见：
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- 将此页作为 **overview / “what changed recently”** 索引，然后跳转到专门页面： [Kerberoast](kerberoast.md)、[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)、[AD Certificates / PKINIT abuse](ad-certificates.md)、或 [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md)。

## Fresh attack notes (2024-2026)
- **RC4 hardening changed the defaults, not Kerberos itself** – 现代 DC hardening 关注的是那些**没有显式设置** `msDS-SupportedEncryptionTypes` 的账户所使用的**默认假定 encryption types**。在 2026 rollout 之后，这些账户在已打补丁的 DC 上越来越多地默认变成 **AES-only**，因此盲目的 `/rc4` Kerberoast 假设会更频繁失败。不过，**显式启用 RC4 的 service accounts 仍然是很好的 offline-crack targets**。
- **PAC validation enforcement matters for forged tickets** – 2024 的 PAC-signature hardening 意味着 **golden/diamond/sapphire/extraSID-style abuses** 需要更真实的 PAC 数据和正确的 signing context。未打补丁的域，或仍处于 compatibility/audit-style 部署的域，依然更脆弱。
- **Certificate-based Kerberos changed twice**：
- **Strong certificate binding**（KB5014754 timeline）使得在 fully enforced 环境中，粗糙的 certificate-to-account mappings 不再那么可靠。
- **CVE-2025-26647** 在 **altSecID / SKI certificate mappings** 周围增加了另一层 hardening。若 DC 未打补丁、仍在 auditing，或显式绕过 NTAuth validation，pass-the-certificate / shadow-credential 后续 abuse 仍更实用。
- **Cross-domain / cross-forest delegation abuse is still very alive** – Windows 支持现代跨 realm **S4U2Self/S4U2Proxy** flows，因此另一个 domain 中可写的 delegation attributes 仍然很有价值。真正的阻碍通常是 tooling fidelity 和 trust/policy 细节，而不是 protocol support。
- **Windows Server 2025 introduced new Kerberos-adjacent attack surface** through **dMSA** migration logic. 如果你在 2025 domain 中看到对 OUs 或 service-account objects 的 delegated rights，不要把它简单当作“又一个 gMSA”，而是去看专门的 [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md)。

## Fast operator checks in modern domains

在选择 Kerberos attack path 之前，先快速回答四个问题：

1. **Which accounts are still RC4-friendly?**
2. **Which users do not require pre-auth?**
3. **Which objects expose delegation abuse?**
4. **Which parts of the domain are new enough to enforce recent hardening?**
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
- 如果 **interesting SPN accounts** 明确支持 RC4，那么 Kerberoasting 仍然便宜且快速。
- 如果大多数 service accounts **没有显式 etype 配置**，在已更新的 2026 DC 上预计会是 **AES-only** 行为，并应计划更慢的离线破解，或改走其他路径。
- 如果存在 **RBCD / KCD / unconstrained delegation**，S4U 往往比暴力破解更有效。
- 如果正在使用 **certificate auth**，请记住，失败的 PKINIT 路径 **并不总是** 代表该 cert 没用；在许多环境中，同一个 cert 仍可用于 **Schannel/LDAPS** abuse（见 [AD Certificates / PKINIT abuse](ad-certificates.md)）。

## 会改变攻击计划的常见 Kerberos 错误
- **`KDC_ERR_ETYPE_NOTSUPP`** → 目标 account / DC 不会使用你请求的 encryption type。不要只反复尝试 RC4；改为提供 **AES keys**，或改为请求 **AES** roast material。
- **`KRB_AP_ERR_MODIFIED`** → 你很可能拿错了 **service key**、**SPN**，或者 forged ticket 与实际解密它的 service account 不匹配。
- **`KRB_AP_ERR_SKEW`** → 你的时间不同步。先和 DC 同步，再排查其他问题。
- 在 S4U / delegation 流程中出现 **`KDC_ERR_BADOPTION`** → 通常意味着 **sensitive/not-delegable users**、错误的 delegation model，或者你正在尝试使用 **classic KCD**，而实际上只有 **RBCD** 才会接受一个 non-forwardable 的 S4U2Self ticket。

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
