# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## 机制与检测基础

- 任何用辅助类 **`dynamicObject`** 创建的对象都会获得 **`entryTTL`**（秒倒计时）和 **`msDS-Entry-Time-To-Die`**（绝对到期时间）。当 `entryTTL` 到 0 时，**Garbage Collector 会在没有 tombstone/recycle-bin 的情况下删除它**，抹去创建者/时间戳并阻止恢复。
- 可以通过更新 `entryTTL` 刷新 TTL；最小/默认值在 **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** 强制执行（支持 1s–1y，但通常默认 86,400s/24h）。动态对象 **不支持在 Configuration/Schema 分区** 中使用。
- 在运行时间较短（<24h）的 DC 上，删除可能滞后几分钟，留下一段窄窄的响应窗口来查询/备份属性。通过 **对携带 `entryTTL`/`msDS-Entry-Time-To-Die` 的新对象发出告警并与孤立 SID/断链关联** 来检测。

## 使用自删除计算机绕过 MAQ

- 默认 **`ms-DS-MachineAccountQuota` = 10** 允许任何已认证用户创建计算机。在创建时添加 `dynamicObject`，使计算机自我删除并 **释放配额槽位**，同时抹除证据。
- 在 `New-MachineAccount` 中的 Powermad 调整（objectClass 列表）：
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 短 TTL（例如 60s）对普通用户通常无效；AD 会回退到 **`DynamicObjectDefaultTTL`**（例：86,400s）。ADUC 可能隐藏 `entryTTL`，但 LDP/LDAP 查询会显示它。

## 隐蔽的主组成员关系

- 创建一个 **dynamic security group**，然后将用户的 **`primaryGroupID`** 设置为该组的 RID，从而获得不会显示在 `memberOf` 中但在 Kerberos/访问令牌中生效的隐蔽成员身份。
- TTL 到期会 **删除该组，即使存在主组删除保护也无效**，使用户的 `primaryGroupID` 指向一个不存在的 RID 且没有 tombstone 可供调查该权限如何被授予。

## AdminSDHolder 孤立 SID 污染

- 向 **`CN=AdminSDHolder,CN=System,...`** 添加对短期动态用户/组的 ACE。TTL 到期后，该 SID 在模板 ACL 中变得 **不可解析（“Unknown SID”）**，并且 **SDProp（约 60 分钟）** 会将该孤立 SID 传播到所有受保护的 Tier-0 对象。
- 取证因此失去归因，因为主体已消失（无已删除对象 DN）。监控 **新的 dynamic principals + AdminSDHolder/特权 ACL 上突现的孤立 SID**。

## 动态 GPO 执行与自毁证据

- 创建一个带有恶意 **`gPCFileSysPath`**（例如指向攻击者 SMB，共同作案模式如 GPODDITY）的 **dynamic `groupPolicyContainer`** 对象，并通过 `gPLink` 将其链接到目标 OU。
- 客户端处理该策略并从攻击者的 SMB 拉取内容。TTL 到期后，GPO 对象（和 `gPCFileSysPath`）消失；只剩下一个破损的 `gPLink` GUID，移除了执行负载的 LDAP 证据。

## 短暂的 AD 集成 DNS 重定向

- AD DNS 记录是位于 **DomainDnsZones/ForestDnsZones** 的 **`dnsNode`** 对象。将它们作为 **dynamic objects** 创建可以实现临时主机重定向（凭证捕获/MITM）。客户端会缓存恶意 A/AAAA 响应；记录随后自我删除，使区域看起来干净（DNS Manager 可能需要重载区域以刷新视图）。
- 检测：通过复制/事件日志对 **携带 `dynamicObject`/`entryTTL` 的任何 DNS 记录发出告警**；短暂记录很少出现在标准 DNS 日志中。

## 混合 Entra ID 增量同步缺口（注）

- Entra Connect 的 delta sync 依赖于 **tombstones** 来检测删除。一个 **动态的 on-prem 用户** 可以同步到 Entra ID、到期并在没有 tombstone 的情况下删除——delta sync 不会移除云端账户，直到强制执行一次手动 **full sync**，会留下一个 **孤立的活跃 Entra 用户**。

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
