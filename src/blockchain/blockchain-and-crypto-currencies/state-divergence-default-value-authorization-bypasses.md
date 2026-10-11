# 状态分歧与默认值授权 bypass

{{#include ../../banners/hacktricks-training.md}}

授权有时取决于派生的经济状态，而非显式角色——例如，“调用者拥有全部 supply”。如果该判断中的值来自不同存储，过时的副本就可能把合法的所有权捷径变成 authorization bypass。Provenance marker 模块展示了这种危险组合：它将调用者的实时余额与 marker 本地的 supply 元数据进行比较，而对于非固定 supply 的资产，该元数据并未更新。<sup>[[1]](#references)</sup>

## 审计重复状态，将其视为授权边界

对于权限检查中使用的每个值，枚举其**所有表示形式**：规范模块状态、对象字段、缓存的聚合值、索引、快照、桥接记录和链下镜像。然后追踪每条创建、mint、burn、transfer、重置、迁移和同步路径，确定在每种对象模式下会更新哪个副本。某个字段可能在一种模式下是权威数据，而在另一种模式下仅供参考。<sup>[[1]](#references)</sup>

实用的审查流程如下：<sup>[[1]](#references)</sup>

1. 找出受保护的操作，并将每个授权分支简化为布尔判断。
2. 对每个操作数，记录其存储位置、更新路径、生命周期状态和数据源。
3. 生成只更新一种表示形式的状态转换，然后比较所有副本。
4. 每次状态转换后，都尝试从一个新账户执行受保护的操作。
5. 不要止步于 bypass：如果该操作会修改 ACL，就自行授予自己持久角色，并调用常规特权 API。

如果两侧遵循不同的同步规则，那么 `cachedSupply == balance`、`metadataOwner == caller` 或 `snapshotShares == currentShares` 等可疑模式就可能存在风险。即使其中一个操作数查询的是权威值，也不能让比较变得安全，因为另一个操作数可能已经过时。<sup>[[1]](#references)</sup>

## 默认值相等 bypass

如果两个操作数都可能独立地取相同默认值，相等判断同样不安全。下面的检查会在 `supply` 为零时，将“完全控制 supply”的权限授予任何空账户，不论零值是由过时的元数据造成，还是源于一个确实尚未注资的对象。<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

切换到规范存储可以修复状态分歧，但**无法解决空对象情况**。安全属性必须包含独立的有效性条件；Provenance 补丁使用实时银行供应量，并在比较调用者余额之前拒绝 nil 或零供应量。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

对 quorum 数量、所有权百分比、债务、抵押品、epochs、nonces、时间戳和计数器，也应采用相同的推理：`callerValue == protectedValue` 不能授权调用者，除非受保护值本身有效且属于预期的 domain。<sup>[[1]](#references)</sup>

## ACL 接管并执行合法特权操作

ACL 编辑操作中的 bypass 是一种持久的权限提升原语。在 Provenance 案例中，一个没有 token 的非特权账户可以通过过时的 `0 == 0` 供应量检查，为自己授予管理员、铸造和提取权限，然后使用普通消息处理程序铸造资产或提取托管资金。因此，在 ACL 修改后，利用过程不再需要第二个漏洞。<sup>[[1]](#references)</sup>

一般利用流程：<sup>[[1]](#references)</sup>

1. 找到一个其非权威字段与实时状态不一致的对象，或其受保护值为默认值的对象。
2. 使用新的/空身份，使其本地值与该过时值/默认值相匹配。
3. 调用角色管理、所有权转移或策略更新端点，为自己授予持久能力。
4. 通过从规范状态读取 ACL 来确认权限变更已持久化。
5. 调用合法的高影响操作（铸造、提取、升级、转移所有权或更改策略）。

评估影响时，应检查新角色可访问的所有能力，而不要止步于授权 bypass。类似托管账户的账户可能保管着与导致接管的过时元数据对象无关的资产。<sup>[[1]](#references)</sup>

## 不变量和有状态 fuzzing 的测试目标

授权逻辑应独立于实现进行定义。对于 full-supply 快捷路径，最小不变量为：<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

使用 model/state-machine fuzzer 生成操作序列，而非孤立调用，覆盖创建、零值初始化、激活/终结、铸造、销毁、转账、重置、迁移、sync 调用和 ACL 变更。每次状态转换后，都比较重复表示，并断言新账户无法执行任何受保护操作。明确测试零值、一个单位、部分所有权、完全所有权、陈旧偏低值和陈旧偏高值等情况。<sup>[[1]](#references)[[2]](#references)</sup>

高信号回归属性包括：<sup>[[1]](#references)[[2]](#references)</sup>

- 权威供应量为零时，绝不意味着拥有所有权或管理权限。
- 当重复供应量等于其余额时，部分持有者不能因此成为管理员。
- 当实时供应量大于零时，真正的全额持有者仍保有预期的快捷权限。
- 失败的自我授权不会修改 ACL，也不会启用后续特权调用。
- 模式变更不能悄然改变授权检查所认定的权威表示。

## References

- [1] [状态分歧导致未授权访问（Trail of Bits）](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - 修复陈旧供应量检查](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - 在总供应量授权快捷方式中拒绝零供应量](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
