# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## 机制与检测基础

- 任何使用辅助类 **`dynamicObject`** 创建的对象都会获得 **`entryTTL`**（秒倒计时）和 **`msDS-Entry-Time-To-Die`**（绝对过期时间）。当 `entryTTL` 归零时，**Garbage Collector 会将其删除，不经过 tombstone/recycle-bin**，从而抹去创建者/时间戳并阻止恢复。
- **`entryTTL` 是一个 operational/constructed 属性**：在 LDAP 查询中需要显式请求它。TTL 可以通过在到期前更新 `entryTTL` 来刷新，也可以通过 LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** 刷新。
- TTL 的最小值/默认值由 **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** 强制执行。Microsoft 文档说明默认 TTL 为 **86400s**，默认最小有效 TTL 为 **900s**；两者都支持 **1s–1y**。dynamic objects **不支持在 Configuration/Schema partitions 中使用**。
- 不存在 **static→dynamic** 转换，过期后也没有 tombstone 阶段。IR teams 不能依赖 deleted-object 控制或 Recycle Bin；他们必须在 GC 删除对象前捕获 live object/metadata。
- 刷新对 **replica-sensitive**：如果 TTL 在接近过期时才续期，另一个 writable replica 或 GC 仍可能在刷新复制之前在本地删除对象。因此，极短 TTL 最适合攻击者已经知道哪个 DC 将处理 abuse 的场景，而防御者在 triage 时应查询 **所有 naming contexts / replicas**。
- 在 uptime 较短（<24h）的 DC 上，删除可能会延迟几分钟，从而留出很小的响应窗口来查询/备份属性。可通过 **对携带 `entryTTL`/`msDS-Entry-Time-To-Die` 的新对象进行告警**，并与 orphan SIDs/broken links 进行关联来检测。

## 快速枚举 / 实时 triage

- 查询 **RootDSE 中的所有 `namingContexts`**，不要只查 domain NC。Dynamic abuse 可能存在于 **`DomainDnsZones`/`ForestDnsZones`**（`dnsNode`）或 application partitions 中。
- 在对象仍存活时，立即转储 **replication metadata** 以及任何 linked attributes/ACLs。过期后你可能只剩下 **broken `gPLink` values、orphan SIDs 或缓存的 DNS answers**。
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## 使用自删除计算机规避 MAQ

- 默认 **`ms-DS-MachineAccountQuota` = 10** 允许任何已认证用户创建计算机。在创建时添加 `dynamicObject`，让计算机自动删除并**释放配额槽位**，同时清除痕迹。
- Powermad 在 `New-MachineAccount` 中的调整（objectClass list）：
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 如果请求的 TTL **低于 `DynamicObjectMinTTL`**，根据创建路径不同，预期会被服务器端调整或拒绝；在很多域中有效下限是 **900s**，回退/默认值仍是 **86400s**。ADUC 可能隐藏 `entryTTL`，但 LDP/LDAP 查询可以看到它。
- 在对象存在期间，防御者仍可从计算机对象上的 **`msDS-CreatorSID`** 恢复创建它的非特权用户。一旦动态计算机过期，这种归因就会随着对象一起消失。

## 隐蔽的 Primary Group 成员关系

- 创建一个 **dynamic security group**，然后把某个用户的 **`primaryGroupID`** 设为该组的 RID，就能获得有效成员关系；这种关系**不会显示在 `memberOf`** 中，但 Kerberos/access tokens 仍会认可。
- TTL 过期后，**即使有 primary-group delete protection，组也会被删除**，留下一个指向不存在 RID 的损坏 `primaryGroupID`，并且没有 tombstone 可供调查权限是如何被授予的。
- 报告结果依赖工具：**`Get-ADGroupMember` / `net group`** 通常会解析由 primary-group 派生的成员关系，而 **`memberOf`** 和 **`Get-ADGroup -Properties member`** 不会。关于更广泛的 `primaryGroupID` 玩法，参见 [this other page about DCShadow and PGID abuse](dcshadow.md)。
- 对于**未受 AdminSDHolder 保护**的目标，攻击者可以将动态组技巧与**拒绝读取 `primaryGroupID` 的 DACL**（或组的 `member` 属性）结合使用，即使在组过期前，也能在许多 LDAP/PowerShell 流程中隐藏这条关联。

## AdminSDHolder 孤儿 SID 污染

- 为一个**短生命周期的 dynamic user/group** 向 **`CN=AdminSDHolder,CN=System,...`** 添加 ACE。TTL 过期后，该 SID 在模板 ACL 中会变成**无法解析的（“Unknown SID”）**，而 **SDProp（约 60 分钟）** 会把这个孤儿 SID 扩散到所有受保护的 Tier-0 对象上。
- 由于主体已经消失，取证会失去归因（也没有 deleted-object DN）。监控 **新建 dynamic principal + AdminSDHolder/特权 ACL 上突然出现的孤儿 SID**。

## 带自毁痕迹的 Dynamic GPO 执行

- 创建一个带恶意 **`gPCFileSysPath`** 的 **dynamic `groupPolicyContainer`** 对象（例如像 GPODDITY 一样指向 SMB share），并通过 **`gPLink`** 把它链接到目标 OU。
- 客户端会处理该 policy 并从攻击者的 SMB 拉取内容。TTL 过期后，GPO 对象（以及 `gPCFileSysPath`）会消失；只剩下一个损坏的 **`gPLink`** GUID，从 LDAP 证据中移除了已执行 payload 的痕迹。
- 这在操作上比经典的 **GPODDITY-style** 清理更干净：你不需要自己恢复原始 `gPCFileSysPath`，AD 会在计时器过期后自动移除恶意 GPC。

## 短暂的 AD 集成 DNS 重定向

- AD DNS 记录是位于 **DomainDnsZones/ForestDnsZones** 中的 **`dnsNode`** 对象。将它们创建为 **dynamic objects** 可以实现临时主机重定向（credential capture/MITM）。客户端会缓存恶意的 A/AAAA 响应；随后记录会自动删除，因此 zone 看起来是干净的（DNS Manager 可能需要重新加载 zone 才能刷新视图）。
- 检测：通过复制/event logs 针对**任何携带 `dynamicObject`/`entryTTL` 的 DNS 记录**发出告警；短暂记录很少出现在标准 DNS logs 中。

## 混合 Entra ID Delta-Sync 缺口（说明）

- Entra Connect delta sync 依赖 **tombstones** 来检测删除。一个**动态的本地用户**可以同步到 Entra ID、过期并删除，但没有 tombstone——delta sync 不会移除云端账户，导致一个**孤立的活跃 Entra user**，直到强制执行 **initial/full sync** 或手动清理云端。

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
