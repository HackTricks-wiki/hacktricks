# 状态分歧与默认值授权绕过

{{#include ../../banners/hacktricks-training.md}}

授权有时依赖派生的经济状态，而不是显式角色——例如“调用者拥有全部 supply”。如果该谓词中的值来自不同存储，一份过时的重复数据就可能将合法的所有权快捷方式变成 authorization bypass。Provenance marker module 展示了这种危险组合：实时的调用者余额与 marker-local supply metadata 进行比较，而对于 non-fixed-supply assets，该 metadata 并未更新。<sup>[[1]](#references)</sup>

## 将重复状态作为授权边界进行审计

对于权限检查使用的每个值，枚举**所有表示形式**：canonical module state、object fields、cached aggregates、indexes、snapshots、bridge records 以及 off-chain mirrors。然后跟踪每条 create、mint、burn、transfer、reset、migration 和 synchronization 路径，确定每种 object mode 下更新的是哪个副本。某个字段可能在一种 mode 下是权威数据，而在另一种 mode 下仅提供信息。<sup>[[1]](#references)</sup>

一种实用的 review workflow 是：<sup>[[1]](#references)</sup>

1. 定位受保护的操作，并将每个 authorization 分支化简为布尔谓词。
2. 对每个操作数记录其存储位置、更新路径、生命周期状态以及 source of truth。
3. 生成仅更新一种表示形式的状态转换，然后比较所有副本。
4. 在每次状态转换后，尝试从一个 fresh account 执行受保护的操作。
5. 不要在 bypass 后停止：如果该操作会编辑 ACL，则为自身授予 persistent roles，并调用正常的 privileged APIs。

可疑模式包括 `cachedSupply == balance`、`metadataOwner == caller` 或 `snapshotShares == currentShares`，尤其是在两侧具有不同 synchronization 规则时。为其中一个操作数查询 authoritative value，并不能在另一个操作数过时时使比较变得安全。<sup>[[1]](#references)</sup>

## 默认值相等绕过

当两个操作数都可以独立地取相同的默认值时，相等谓词同样不安全。下面的检查会在 `supply` 为零时，将“full supply control”授予任何空账户，而不管零值是由过时的 metadata 还是由合法的、未获得资金的对象造成的。<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
切换到 canonical store 可以修复 divergence，但**无法**解决 empty-object case。安全属性必须包含独立的有效性条件；Provenance patch 使用实时 bank supply，并在比较调用者余额之前拒绝 nil 或零 supply。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
对 quorum counts、ownership percentages、debt、collateral、epochs、nonces、timestamps 和 counters 采用相同的判断：在受保护值经过独立验证且属于预期域之前，`callerValue == protectedValue` 不得用于授权调用者。<sup>[[1]](#references)</sup>

## ACL takeover to legitimate privileged operations

ACL 编辑操作中的 bypass 是一种持久的 privilege-escalation primitive。在 Provenance 案例中，一个拥有零 token 的未授权账户可以通过过时的 `0 == 0` supply 检查，为自己授予 administrative、mint 和 withdrawal 权限，然后使用普通的 message handlers 来 mint assets 或 withdraw escrow。因此，ACL 修改之后不需要第二个 vulnerability，exploit 就能完成。<sup>[[1]](#references)</sup>

General exploitation sequence:<sup>[[1]](#references)</sup>

1. 找到一个 non-authoritative field 与 live state 不同的对象，或其 protected value 为 default 的对象。
2. 使用一个新的/空 identity，使其 local value 与该 stale/default value 匹配。
3. 调用 role-management、ownership-transfer 或 policy-update endpoint，为自己授予持久 capabilities。
4. 通过读取 canonical state 中的 ACL，确认持久化已生效。
5. 调用合法的 high-impact operation（mint、withdraw、upgrade、transfer ownership 或 change policy）。

评估影响时，应检查新 role 可访问的每项 capability，而不要在发现 authorization bypass 后就停止。类似 escrow 的账户可能托管与其 stale metadata 导致 takeover 的对象无关的 assets。<sup>[[1]](#references)</sup>

## Invariant and stateful-fuzzing targets

应独立于实现来指定 authorization。对于 full-supply shortcut，最小 invariant 为：<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
使用 model/state-machine fuzzer 生成序列，而不是孤立调用，覆盖创建、零值初始化、激活/最终化、minting、burning、转账、重置、迁移、sync 调用和 ACL 变更。在每次状态转换后，比较重复的表示形式，并断言新账户无法执行任何受保护操作。为零值、一个单位、部分所有权、完全所有权、过低的过时值和过高的过时值设置明确的种子用例。<sup>[[1]](#references)[[2]](#references)</sup>

高信号回归属性包括：<sup>[[1]](#references)[[2]](#references)</sup>

- 权威 supply 为零绝不意味着拥有所有权或管理权限。
- 当重复的 supply 等于其余额时，部分持有者不能成为管理员。
- 当 live supply 为正时，真正的完全持有者仍保留预期的 shortcut。
- 失败的 self-grants 不会修改 ACL，也不会启用后续的 privileged 调用。
- 模式变更不能无声地改变授权检查所视为权威的表示形式。

## References

- [1] [状态分歧会导致未授权访问（Trail of Bits）](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - 修复过时的 supply 检查](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - 在 total-supply 授权 shortcut 中拒绝零 supply](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
