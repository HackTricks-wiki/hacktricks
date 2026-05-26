# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- 任何使用辅助类 **`dynamicObject`** 创建的对象都会获得 **`entryTTL`**（秒倒计时）和 **`msDS-Entry-Time-To-Die`**（绝对到期时间）。当 `entryTTL` 归零时，**Garbage Collector 会直接删除它，不经过 tombstone/recycle-bin**，从而清除创建者/时间戳并阻止恢复。
- **`entryTTL` 是一个 operational/constructed attribute**：在 LDAP 查询中需要显式请求它。TTL 可以通过在到期前更新 `entryTTL` 来刷新，也可以通过 LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** 刷新。
- TTL 的最小值/默认值在 **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** 中强制执行。Microsoft 文档将 **86400s** 作为默认 TTL，将 **900s** 作为默认最小有效 TTL；二者都支持 **1s–1y**。Dynamic objects **不支持在 Configuration/Schema 分区中使用**。
- 不存在 **static→dynamic** 转换，过期后也没有 tombstone 阶段。IR 团队不能依赖 deleted-object 控制或 Recycle Bin；他们必须在 GC 删除对象前捕获该 live object/metadata。
- 刷新对 **replica-sensitive**：如果 TTL 在临近到期时才续期，另一个 writable replica 或 GC 仍可能先在本地删除该对象，然后刷新才完成复制。因此，极短 TTL 最适合攻击者明确知道哪个 DC 会处理 abuse 的场景；而防守者在 triage 时应查询 **所有 naming contexts / replicas**。
- 在 uptime 较短（<24h）的 DC 上，删除可能会延迟几分钟，留下一个很窄的响应窗口用于查询/备份属性。可通过 **对带有 `entryTTL`/`msDS-Entry-Time-To-Die` 的新对象告警**，并与 orphan SIDs/broken links 关联来检测。## Fast Enumeration / Live Triage

- 查询 **RootDSE 中所有 `namingContexts`**，不要只查 domain NC。Dynamic abuse 可能存在于 **`DomainDnsZones`/`ForestDnsZones`**（`dnsNode`）或 application partitions 中。
- 当对象仍然存活时，立即导出 **replication metadata** 和任何 linked attributes/ACLs。过期后你可能只剩下 **broken `gPLink` values、orphan SIDs 或缓存的 DNS answers**。
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## 带自删除 Computers 的 MAQ Evasion

- 默认 **`ms-DS-MachineAccountQuota` = 10** 允许任何已认证用户创建 computers。创建时加入 `dynamicObject`，让 computer 自删除并**释放 quota slot**，同时擦除证据。
- Powermad 在 `New-MachineAccount` 中的调整（objectClass list）：
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 如果请求的 TTL **低于 `DynamicObjectMinTTL`**，则根据创建路径，预期会被服务器端调整或拒绝；在许多 domains 中，有效下限是 **900s**，而回退/默认值仍是 **86400s**。ADUC 可能隐藏 `entryTTL`，但 LDP/LDAP queries 能看到它。
- 在 object 存在期间，defenders 仍可从 computer object 上的 **`msDS-CreatorSID`** 恢复创建它的非特权用户。dynamic computer 过期后，这种归因也会随 object 一起消失。

## 隐蔽的 Primary Group Membership

- 创建一个 **dynamic security group**，然后把某个 user 的 **`primaryGroupID`** 设为该 group 的 RID，就能获得有效 membership；它**不会显示在 `memberOf`** 中，但会在 Kerberos/access tokens 中被认可。
- TTL 到期会**删除该 group，即使存在 primary-group delete protection**，从而让 user 带着一个损坏的 `primaryGroupID`，它指向一个不存在的 RID，并且没有 tombstone 可供调查该特权是如何被授予的。
- 报告结果取决于 tool：**`Get-ADGroupMember` / `net group`** 通常会解析基于 primary-group 的 membership，而 **`memberOf`** 和 **`Get-ADGroup -Properties member`** 不会。关于更广泛的 `primaryGroupID` tradecraft，见 [this other page about DCShadow and PGID abuse](dcshadow.md)。
- 对于**非 AdminSDHolder 保护**的 targets，attackers 可以将 dynamic-group trick 与 **DACL deny on reading `primaryGroupID`**（或 group 的 `member` attribute）结合，在 group 过期前就对许多 LDAP/PowerShell workflows 隐藏这条关联。

## AdminSDHolder Orphan-SID Pollution

- 为 **短命的 dynamic user/group** 向 **`CN=AdminSDHolder,CN=System,...`** 添加 ACEs。TTL 到期后，该 SID 会在 template ACL 中变成**无法解析（“Unknown SID”）**，而 **SDProp (~60 min)** 会把这个 orphan SID 传播到所有受保护的 Tier-0 objects 上。
- forensic 会失去归因，因为 principal 已经消失（没有 deleted-object DN）。监控 **新的 dynamic principals + AdminSDHolder/privileged ACLs 上突然出现的 orphan SIDs**。

## 带自毁证据的 Dynamic GPO Execution

- 创建一个带恶意 **`gPCFileSysPath`** 的 **dynamic `groupPolicyContainer`** object（例如，像 GPODDITY 那样指向 SMB share），并通过 **`gPLink`** 将其链接到目标 OU。
- Clients 会处理该 policy 并从 attacker SMB 拉取内容。TTL 到期后，GPO object（以及 `gPCFileSysPath`）会消失；只剩下一个**损坏的 `gPLink`** GUID，从而移除已执行 payload 的 LDAP evidence。
- 这在 operationally 上比经典 **GPODDITY-style** 清理更干净：你不需要自己恢复原始 `gPCFileSysPath`，AD 会在计时器到期后自动移除恶意 GPC。

## 短暂的 AD-Integrated DNS Redirection

- AD DNS records 是 **DomainDnsZones/ForestDnsZones** 中的 **`dnsNode`** objects。把它们创建为 **dynamic objects** 可实现临时 host redirection（credential capture/MITM）。Clients 会缓存恶意的 A/AAAA response；之后 record 会自删除，因此 zone 看起来很干净（DNS Manager 可能需要 reload zone 才会刷新视图）。
- Detection：通过 replication/event logs 对**任何携带 `dynamicObject`/`entryTTL` 的 DNS record** 发出告警；短暂 records 很少出现在标准 DNS logs 中。

## 混合 Entra ID Delta-Sync Gap（注意）

- Entra Connect delta sync 依赖 **tombstones** 来检测删除。一个 **dynamic on-prem user** 可以同步到 Entra ID，随后过期并删除，但没有 tombstone——delta sync 不会移除 cloud account，导致一个**孤立但仍 सक्रिय 的 Entra user**，直到强制执行 **initial/full sync** 或手动清理 cloud。

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
