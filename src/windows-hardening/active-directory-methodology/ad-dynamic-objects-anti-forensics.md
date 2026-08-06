# AD Dynamic Objects (dynamicObject) 反取证

{{#include ../../banners/hacktricks-training.md}}

## 机制与检测基础

- 使用辅助类 **`dynamicObject`** 创建的任何对象都会获得 **`entryTTL`**（秒倒计时）和 **`msDS-Entry-Time-To-Die`**（绝对到期时间）。当 **`entryTTL`** 达到 0 时，**Garbage Collector** 会删除该对象，且不会经过 tombstone/recycle-bin，从而擦除创建者信息和时间戳，并阻止恢复。
- **`entryTTL` 是一个 operational/constructed attribute**：在 LDAP 查询中必须显式请求。可以在到期前更新 **`entryTTL`** 来刷新 TTL，也可以通过 LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** 进行刷新。
- TTL 的最小值和默认值由 **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** 强制执行。Microsoft 记录的默认 TTL 为 **86400s**，默认最小有效 TTL 为 **900s**；两者均支持 **1s–1y**。Configuration/Schema partitions 不支持 dynamic objects。
- 不存在 static→dynamic 转换，过期后也没有 tombstone 阶段。IR 团队无法依赖 deleted-object controls 或 Recycle Bin；必须在 GC 删除对象之前捕获 live object/metadata。
- 刷新操作与 replica 密切相关：如果 TTL 在接近到期时才续期，其他 writable replica 或 GC 仍可能在刷新操作完成复制前于本地删除对象。因此，极短 TTL 最适合攻击者明确知道哪个 DC 将处理 abuse 的情况；防御者则应在 triage 期间查询 **所有 naming contexts / replicas**。
- 在 uptime 较短（<24h）的 DC 上，删除操作可能延迟数分钟，从而留下一个狭窄的响应窗口，可用于查询/备份属性。可以通过对携带 **`entryTTL`**/ **`msDS-Entry-Time-To-Die`** 的新对象设置告警，并与 orphan SIDs/broken links 进行关联来检测。<sup>[[1]](#references)</sup>

## 快速枚举 / Live Triage

- 从 RootDSE 查询 **所有 `namingContexts`**，不要只查询 domain NC。Dynamic abuse 可能存在于 **`DomainDnsZones`**/ **`ForestDnsZones`**（`dnsNode`）或 application partitions 中。
- 在对象仍然存在时，立即导出 **replication metadata** 以及所有 linked attributes/ACLs。过期后，可能只剩下 **broken `gPLink` values、orphan SIDs 或 cached DNS answers**。<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion with Self-Deleting Computers

- 默认 **`ms-DS-MachineAccountQuota` = 10**，允许任意已认证用户创建计算机。在创建时添加 `dynamicObject`，可使计算机自动删除自身并**释放配额槽位**，同时清除痕迹。
- 在 `New-MachineAccount`（objectClass 列表）中修改 Powermad：
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 如果请求的 TTL **低于 `DynamicObjectMinTTL`**，根据创建路径的不同，服务器可能会调整或拒绝该请求；在许多域中，有效下限为 **900s**，而回退值/默认值仍为 **86400s**。ADUC 可能隐藏 `entryTTL`，但 LDP/LDAP 查询可以显示它。
- 对象存在期间，defenders 仍可通过计算机对象上的 **`msDS-CreatorSID`** 找到未授权创建者。动态计算机过期后，该归属信息会随对象一同消失。<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- 创建一个**动态 security group**，然后将用户的 **`primaryGroupID`** 设置为该组的 RID，从而获得有效组成员身份；该身份**不会显示在 `memberOf` 中**，但会被 Kerberos/access tokens 认可。<sup>[[1]](#references)</sup>
- TTL 到期后，即使存在 primary-group delete protection，该组仍会被删除，使用户留下指向不存在 RID 的损坏 `primaryGroupID`，并且没有 tombstone 可用于调查该权限是如何授予的。
- 报告结果取决于工具：**`Get-ADGroupMember` / `net group`** 通常会解析由 primary group 派生的成员身份，而 **`memberOf`** 和 **`Get-ADGroup -Properties member`** 不会。有关更广泛的 `primaryGroupID` tradecraft，请参阅[这个关于 DCShadow 和 PGID abuse 的页面](dcshadow.md)。
- 对于**未受 AdminSDHolder 保护**的目标，攻击者可以将动态组技巧与**拒绝读取 `primaryGroupID` 的 DACL deny**（或拒绝读取组 `member` 属性）结合使用，从而在组过期前就对许多 LDAP/PowerShell 工作流隐藏该关联。<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- 将短期存在的**动态用户/组**的 ACE 添加到 **`CN=AdminSDHolder,CN=System,...`**。TTL 到期后，该 SID 在模板 ACL 中变为**无法解析的 (“Unknown SID”)**，并由 **SDProp（约 60 分钟）**将该 orphan SID 传播到所有受保护的 Tier-0 对象。
- 由于主体已经消失（没有 deleted-object DN），取证将失去归属信息。监控**新的动态主体 + AdminSDHolder/特权 ACL 上突然出现的 orphan SID**。<sup>[[1]](#references)</sup>

## Dynamic GPO Execution with Self-Destructing Evidence

- 创建一个**动态 `groupPolicyContainer`**对象，并设置恶意的 **`gPCFileSysPath`**（例如类似 GPODDITY 的 SMB share），再通过 **`gPLink`** 将其链接到目标 OU。
- 客户端处理该策略，并从攻击者的 SMB 拉取内容。TTL 到期后，GPO 对象（以及 `gPCFileSysPath`）消失；只留下一个**失效的 `gPLink`** GUID，从而删除已执行 payload 的 LDAP 证据。
- 这在操作上比经典的 **GPODDITY-style** 清理更简洁：无需自行恢复原始 `gPCFileSysPath`，AD 会在计时器到期后自动移除恶意 GPC。<sup>[[1]](#references)</sup>

## Ephemeral AD-Integrated DNS Redirection

- AD DNS 记录是 **DomainDnsZones/ForestDnsZones** 中的 **`dnsNode`** 对象。将它们创建为**动态对象**后，可以进行临时主机重定向（credential capture/MITM）。客户端会缓存恶意的 A/AAAA 响应；随后记录自动删除，使 zone 看起来保持干净（DNS Manager 可能需要重新加载 zone 才能刷新视图）。
- 检测：通过 replication/event logs 对携带 **`dynamicObject`/`entryTTL`** 的**任何 DNS 记录**发出告警；临时记录很少会出现在标准 DNS logs 中。<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync 依赖 **tombstones** 来检测删除操作。一个**动态 on-prem user** 可以同步到 Entra ID，随后过期并在没有 tombstone 的情况下被删除；delta sync 不会移除 cloud account，从而留下一个**孤立且活动的 Entra user**，直到强制执行**初始/完整同步**或手动进行 cloud cleanup。<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
