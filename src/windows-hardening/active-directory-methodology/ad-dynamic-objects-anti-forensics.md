# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## 机制与检测基础

- 任何使用辅助类 **`dynamicObject`** 创建的对象都会获得 **`entryTTL`**（秒倒计时）和 **`msDS-Entry-Time-To-Die`**（绝对到期时间）。当 `entryTTL` 达到 0 时，**Garbage Collector 会在没有 tombstone/recycle-bin 的情况下删除它**，抹去创建者/时间戳并阻止恢复。
- 可以通过更新 `entryTTL` 来刷新 TTL；最小/默认值在 **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** 中强制执行（支持 1s–1y，但通常默认为 86,400s/24h）。动态对象 **不支持在 Configuration/Schema 分区** 中创建。
- 在启动时间短（<24h）的 DC 上删除可能会滞后几分钟，这会留下一个查询/备份属性的狭窄响应窗口。检测方法：**对携带 `entryTTL`/`msDS-Entry-Time-To-Die` 的新对象触发告警**，并与孤立 SID/断链关联。

## MAQ Evasion with Self-Deleting Computers

- 默认 **`ms-DS-MachineAccountQuota` = 10** 允许任何已验证用户创建计算机。在创建时添加 `dynamicObject`，使该计算机自我删除并 **释放 quota 插槽** 同时抹除证据。
- 在 `New-MachineAccount` 内的 Powermad tweak（objectClass 列表）：
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 短 TTL（例如 60s）通常对普通用户无效；AD 会回退到 **`DynamicObjectDefaultTTL`**（示例：86,400s）。ADUC 可能隐藏 `entryTTL`，但 LDP/LDAP 查询会显示它。

## 隐蔽的 primary group 成员资格

- 创建一个 **动态安全组**，然后将用户的 **`primaryGroupID`** 设置为该组的 RID，以获得有效的成员资格，该成员资格 **不会出现在 `memberOf` 中**，但在 Kerberos/访问令牌中有效。
- TTL 到期会 **删除该组，尽管存在 primary-group 删除保护**，这会使用户拥有指向不存在 RID 的损坏 `primaryGroupID`，且没有 tombstone 可供调查该权限如何授予。

## AdminSDHolder Orphan-SID 污染

- 将 ACE 添加到 **短寿命的动态用户/组** 到 **`CN=AdminSDHolder,CN=System,...`**。TTL 到期后，该 SID 在模板 ACL 中变为 **不可解析（“Unknown SID”）**，并且 **SDProp（~60 分钟）** 会将该孤立 SID 传播到所有受保护的 Tier-0 对象。
- 取证会失去归因，因为主体已消失（没有已删除对象的 DN）。对策：监控 **新的动态主体 + AdminSDHolder/特权 ACL 上突然出现的孤立 SID**。

## 带自毁证据的动态 GPO 执行

- 创建一个带有恶意 **`gPCFileSysPath`**（例如指向攻击者 SMB 的 GPODDITY 风格）的 **动态 `groupPolicyContainer`** 对象，并通过 `gPLink` 将其链接到目标 OU。
- 客户端处理策略并从攻击者 SMB 拉取内容。TTL 到期后，GPO 对象（及 `gPCFileSysPath`）消失；只剩下一个 **损坏的 `gPLink`** GUID，移除执行负载的 LDAP 证据。

## 短暂的 AD-Integrated DNS 重定向

- AD DNS 记录是位于 **DomainDnsZones/ForestDnsZones** 的 **`dnsNode`** 对象。将它们作为 **dynamic objects** 创建可以实现临时的主机重定向（凭据捕获/MITM）。客户端会缓存恶意的 A/AAAA 响应；记录随后自我删除，使区域看起来干净（DNS Manager 可能需要重新加载区域以刷新视图）。
- 检测：通过复制/事件日志对 **携带 `dynamicObject`/`entryTTL` 的任何 DNS 记录触发告警**；短暂记录很少出现在标准 DNS 日志中。

## Hybrid Entra ID Delta-Sync Gap（注）

- Entra Connect delta sync 依赖 **tombstones** 来检测删除。一个 **dynamic 的本地用户** 可以同步到 Entra ID，过期并删除而没有 tombstone——delta sync 不会移除云端账户，留下一个 **孤立的活动 Entra 用户**，直到强制执行手动 **full sync**。

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
