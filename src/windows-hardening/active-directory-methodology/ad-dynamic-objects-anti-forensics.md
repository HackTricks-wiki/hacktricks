# AD Dynamic Objects（dynamicObject）Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## 机制与检测基础

- 使用辅助类 **`dynamicObject`** 创建的任何对象都会获得 **`entryTTL`**（秒数倒计时）和 **`msDS-Entry-Time-To-Die`**（绝对到期时间）。当 `entryTTL` 达到 0 **且对象没有后代对象**时，Garbage Collector 会删除该对象，不经过 tombstone/recycle-bin，从而擦除创建者和时间戳信息，并阻止恢复。<sup>[[4]](#references)</sup>
- **`entryTTL` 是 operational/constructed attribute**：在 LDAP 查询中必须显式请求。可以在到期前更新 `entryTTL`，或通过 LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** 刷新 TTL。
- TTL 的最小值/默认值是 forest-wide AVA，位于 **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**：`DynamicObjectMinTTLSeconds=<seconds>` 和 `DynamicObjectDefaultTTLSeconds=<seconds>`。Microsoft 记录的默认 TTL 为 **86400s**，默认最小有效 TTL 为 **900s**；`entryTTL` schema 范围为 **1–31557600s**（一秒至一年）。<sup>[[3]](#references)</sup> Dynamic objects 在 **Configuration/Schema partitions** 中不受支持。
- **不存在 static→dynamic 转换**，到期后也没有 tombstone 阶段。IR 团队不能依赖 deleted-object controls 或 Recycle Bin；必须在 GC 删除对象前捕获存活对象及其 metadata。
- Refresh 具有 **replica-sensitive** 特性：如果 TTL 在接近到期时才续期，另一台 writable replica 或 GC 仍可能在 refresh 完成复制前于本地删除对象。因此，极短 TTL 最适合攻击者明确知道哪台 DC 将处理该 abuse 的场景；防御者则应在 triage 期间查询**所有 naming contexts / replicas**。
- 在运行时间较短（<24h）的 DC 上，删除可能延迟几分钟，从而留下一个狭窄的响应窗口，用于查询/备份属性。可通过**对携带 `entryTTL`/`msDS-Entry-Time-To-Die` 的新对象设置 alert**，并将其与 orphan SIDs/broken links 关联来检测。<sup>[[1]](#references)</sup>

### 到期图与引用清理边界情况

- Dynamic object 下的每个 descendant 都必须自身为 dynamic。过期的 dynamic parent 只有在成为 leaf 后才会被 garbage-collected；如果某个 descendant 的 `msDS-Entry-Time-To-Die` 更晚，DC 会将 parent 的到期时间推进到所有 descendant 到期时间中的最大值。因此，一个 writable dynamic subtree 可以**固定/延长一个看似即将消失的 parent**：枚举其整个 subtree，不要将 parent 观察到的 `entryTTL` 作为清理截止时间。<sup>[[4]](#references)</sup>
- 到期清理会识别 **schema-link**。Replicas 会移除引用已删除 dynamic object 的 linked attribute 值，但会保留 nonlinked 值。预期普通的 forward/back-link membership 会被清理，而诸如 `primaryGroupID`、嵌入 `nTSecurityDescriptor` 中的 SIDs 或 `gPLink` 文本中的 integer/SID/string 引用可能会作为取证残留继续存在。<sup>[[4]](#references)</sup>

## 快速枚举 / Live Triage

- 从 RootDSE 查询**所有 `namingContexts`**，而不只是 domain NC。Dynamic abuse 可能存在于 **`DomainDnsZones`/`ForestDnsZones`**（`dnsNode`）或 application partitions 中。
- 对象仍存活时，立即导出 **replication metadata** 以及所有 linked attributes/ACLs。到期后，你可能只剩下 **broken `gPLink` values、orphan SIDs 或 cached DNS answers**。<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## 使用自删除计算机规避 MAQ

- 默认 **`ms-DS-MachineAccountQuota` = 10** 允许任何已认证用户创建计算机。在创建时添加 `dynamicObject`，即可让计算机自行删除并**释放配额槽位**，同时清除证据。
- Powermad 中 `New-MachineAccount` 的调整（objectClass 列表）：
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 如果请求的 TTL **低于 `DynamicObjectMinTTL`**，根据创建路径的不同，可能会由服务器调整或拒绝；在许多域中，有效下限为 **900s**，而回退值/默认值仍为 **86400s**。ADUC 可能会隐藏 `entryTTL`，但 LDP/LDAP 查询可以显示它。
- 对象存在期间，防御者仍可通过计算机对象上的 **`msDS-CreatorSID`** 找到未提权创建者。动态计算机过期后，该归属信息会随对象一同消失。<sup>[[1]](#references)</sup>

## 隐蔽的 Primary Group 成员身份

- 创建一个**动态 security group**，然后将用户的 **`primaryGroupID`** 设置为该组的 RID，以获得有效成员身份；这种身份**不会显示在 `memberOf` 中**，但会在 Kerberos/access token 中生效。<sup>[[1]](#references)</sup>
- TTL 过期后，即使存在 primary-group 删除保护，该组仍会被删除，使用户留下一个指向不存在 RID 的损坏 **`primaryGroupID`**，且没有 tombstone 可用于调查权限是如何授予的。
- 报告结果取决于工具：**`Get-ADGroupMember` / `net group`** 通常会解析由 primary group 派生的成员身份，而 **`memberOf`** 和 **`Get-ADGroup -Properties member`** 不会。有关更广泛的 **`primaryGroupID`** tradecraft，请参阅[此处关于 DCShadow 和 PGID abuse 的页面](dcshadow.md)。
- 对于**未受 AdminSDHolder 保护**的目标，攻击者可以将动态组技巧与**拒绝读取 `primaryGroupID` 的 DACL**（或拒绝读取组的 `member` 属性）结合使用，从而即使在组过期前，也能通过许多 LDAP/PowerShell 工作流隐藏该关联。<sup>[[2]](#references)</sup>

## AdminSDHolder 孤立 SID 污染

- 为**短生命周期的动态用户/组**在 **`CN=AdminSDHolder,CN=System,...`** 上添加 ACE。TTL 过期后，该 SID 会在模板 ACL 中变为**无法解析的（“Unknown SID”）**，而 **SDProp（约每 60 分钟）**会将该孤立 SID 传播到所有受保护的 Tier-0 对象。
- 取证会失去归属信息，因为该主体已经消失（没有 deleted-object DN）。监控 **AdminSDHolder/特权 ACL 上新出现的动态主体 + 突然出现的孤立 SID**。<sup>[[1]](#references)</sup>

## 使用自毁证据执行动态 GPO

- 创建一个带有恶意 **`gPCFileSysPath`**（例如类似 GPODDITY 的 SMB share）的**动态 `groupPolicyContainer`**对象，并通过 **`gPLink`** 将其链接到目标 OU。
- 客户端处理该策略并从攻击者的 SMB 拉取内容。TTL 过期后，GPO 对象（以及 **`gPCFileSysPath`**）会消失；只剩下一个**失效的 `gPLink`** GUID，从而移除已执行 payload 的 LDAP 证据。
- 与经典的 **GPODDITY-style** 清理相比，这种方式在操作上更简洁：无需自行恢复原始 `gPCFileSysPath`，AD 会在计时器到期后自动删除恶意 GPC。<sup>[[1]](#references)</sup> 有关协议和工具的详细信息，请参阅 [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity)，此处不再重复。

## 短暂的 AD-Integrated DNS 重定向

- AD DNS 记录是 **DomainDnsZones/ForestDnsZones** 中的 **`dnsNode`** 对象。将其创建为**动态对象**可以实现临时主机重定向（credential capture/MITM）。客户端会缓存恶意的 A/AAAA 响应；之后记录会自行删除，使 zone 看起来保持干净（DNS Manager 可能需要重新加载 zone 才能刷新视图）。
- 检测：通过 replication/event logs 对**任何携带 `dynamicObject`/`entryTTL` 的 DNS 记录**发出告警；临时记录很少会出现在标准 DNS logs 中。<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap（注意）

- Entra Connect delta sync 依靠 **tombstone** 检测删除操作。一个**动态 on-prem user**可以同步到 Entra ID，随后过期并在没有 tombstone 的情况下被删除——delta sync 不会移除 cloud account，导致一个**孤立且仍处于活动状态的 Entra user**，直到执行**初始/完整同步**或强制进行手动 cloud cleanup。<sup>[[1]](#references)</sup>



## References

- [1] [Active Directory 中的 Dynamic Objects：隐蔽的威胁](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Primary Group 行为、报告与利用实践](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [TTL 限制的配置](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]：DynamicObject 要求](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
