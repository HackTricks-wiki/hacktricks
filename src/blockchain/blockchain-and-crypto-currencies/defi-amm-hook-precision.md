# DeFi/AMM Exploitation：Uniswap v4 Hook 精度/舍入滥用

{{#include ../../banners/hacktricks-training.md}}

本文介绍针对 Uniswap v4 风格 DEX 的一类 DeFi/AMM exploitation 技术。这类 DEX 通过 custom hooks 扩展核心数学逻辑。近期 Bunni V2 事件利用了 Liquidity Distribution Function (LDF) 在每次 swap 中执行时存在的舍入/精度缺陷，使攻击者能够累积正向 credits 并抽走 liquidity。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

核心思路是：如果 hook 实现的额外 accounting 依赖 fixed-point math、tick rounding 和 threshold logic，攻击者就可以构造跨越特定阈值的 exact-input swaps，使舍入差异持续对自己有利。重复这一模式，然后提取被夸大的 balance，即可实现获利，通常通过 flash loan 提供资金。

## 背景：Uniswap v4 hooks 和 swap 流程

- Hooks 是由 PoolManager 在特定生命周期节点调用的 contracts（例如 beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）。<sup>[[3]](#references)[[6]](#references)</sup>
- Pools 使用包含 hooks address 的 PoolKey 进行初始化。如果该值非零，PoolManager 会在每个相关操作中执行 callbacks。<sup>[[6]](#references)</sup>
- Hooks 可以返回 **custom deltas**，用于修改 swap 或 liquidity 操作最终的 balance changes（custom accounting）。这些 deltas 会在调用结束时作为 net balances 进行结算，因此 hook math 中的任何 rounding error 都会在结算前累积。<sup>[[5]](#references)</sup>
- 核心 math 使用 Q64.96 等 fixed-point 格式表示 sqrtPriceX96，并使用基于 1.0001^tick 的 tick arithmetic。任何叠加在其上的 custom math 都必须严格匹配 rounding semantics，以避免 invariant drift。<sup>[[4]](#references)[[8]](#references)</sup>
- Swaps 可以是 exactInput 或 exactOutput。在 v3/v4 中，price 会沿着 ticks 移动；跨越 tick boundary 可能会激活/停用 range liquidity。Hooks 可能会在 threshold/tick crossings 时实现额外逻辑。<sup>[[5]](#references)</sup>

## Vulnerability archetype：跨越阈值时的精度/舍入漂移

Custom hooks 中常见的易受攻击模式：

1. Hook 使用 integer division、mulDiv 或 fixed-point conversions 计算每次 swap 的 liquidity 或 balance deltas（例如使用 sqrtPrice 和 tick ranges 在 token 与 liquidity 之间转换）。
2. 当 swap size 或 price movement 跨越内部 boundary 时，threshold logic（例如 rebalancing、stepwise redistribution 或 per-range activation）会被触发。
3. Forward calculation 与 settlement path 之间的 rounding 不一致（例如向零截断、floor 与 ceil 不一致）。微小差异不会相互抵消，反而会 credit 给调用者。
4. 将 exact-input swaps 精确调整到跨越这些 boundaries，便可以反复收割正向 rounding remainder。攻击者随后提取累积的 credit。

Attack 前提
- Pool 使用执行 custom math 的 v4 hook，例如 LDF/rebalancer。
- 至少存在一条在 threshold crossings 中使 rounding 有利于 swap initiator 的执行路径。
- 能够以 atomic 方式重复执行大量 swaps（flash loans 非常适合提供临时资金并分摊 gas）。

## Practical attack methodology

1) 识别带有 hooks 的 candidate pools
- 枚举 v4 pools，并检查 PoolKey.hooks != address(0)。
- 检查 hook bytecode/ABI 中的 callbacks：beforeSwap/afterSwap，以及任何 custom rebalancing methods。
- 查找以下 math：除以 liquidity、在 token amounts 与 liquidity 之间转换，或结合 rounding 聚合 BalanceDelta。

2) 建模 hook 的 math 和 thresholds
- 重现 hook 的 liquidity/redistribution formula：输入通常包括 sqrtPriceX96、tickLower/Upper、currentTick、fee tier 和 net liquidity。
- 映射 threshold/step functions：ticks、bucket boundaries 或 LDF breakpoints。确定每个 boundary 的哪一侧会进行 rounding。
- 确认 uint256/int256 之间进行转换的位置、使用 SafeCast 的位置，或依赖隐式 floor 的 mulDiv。

3) 调整 exact-input swaps 以跨越 boundaries
- 使用 Foundry/Hardhat simulations 计算将 price 推动到刚好跨越 boundary 并触发 hook 分支所需的最小 Δin。
- 验证 afterSwap settlement 给 caller 的 credit 大于成本，从而在 hook accounting 中留下正的 BalanceDelta 或 credit。
- 重复 swaps 以累积 credit，然后调用 hook 的 withdrawal/settlement path。

Example Foundry-style test harness (pseudocode)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: address(bunniHook)
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
for (uint i; i < N; ++i) {
pm.swap(
key,
IPoolManager.SwapParams({
zeroForOne: true,
amountSpecified: int256(exactIn), // exactInput
sqrtPriceLimitX96: 0 // allow tick crossing
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
校准 exactInput
- 计算一个 tick 步长对应的 ΔsqrtP：sqrtP_next = sqrtP_current × 1.0001^(Δtick)。
- 使用 v3/v4 公式近似计算 Δin：Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current))。确保舍入方向与 core math 一致。
- 在边界附近将 Δin 调整 ±1 wei，以找到 hook 向有利于你的方向进行舍入的分支。

4) 使用 flash loans 放大
- 借入大额名义价值（例如 3M USDT 或 2000 WETH），以原子方式运行多次迭代。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- 执行经过校准的 swap 循环，然后在 flash loan callback 中提取并偿还贷款。

Aave V3 flash loan skeleton
```solidity
function executeOperation(
address[] calldata assets,
uint256[] calldata amounts,
uint256[] calldata premiums,
address initiator,
bytes calldata params
) external returns (bool) {
// run threshold‑crossing swap loop here
for (uint i; i < N; ++i) {
_exactInBoundaryCrossingSwap();
}
// realize credits / withdraw inflated balances
bunniHook.withdrawCredits(address(this));
// repay
for (uint j; j < assets.length; ++j) {
IERC20(assets[j]).approve(address(POOL), amounts[j] + premiums[j]);
}
return true;
}
```
5) 退出与跨链复制
- 如果 hooks 部署在多条链上，则在每条链上重复相同的校准。
- 将收益通过 Bridge 转回目标链，并可选择经由 lending protocols 进行循环，以混淆资金流向。<sup>[[2]](#references)</sup>

## hook math 中的常见根因

- 舍入语义混用：`mulDiv` 向下取整，而后续路径实际上向上取整；或者 token/liquidity 转换采用了不同的舍入方式。
- Tick 对齐错误：一条路径使用未舍入的 tick，另一条路径使用按 tick 间隔舍入的值。
- 在结算期间于 `int256` 和 `uint256` 之间转换时，BalanceDelta 的符号/溢出问题。
- Q64.96 转换（sqrtPriceX96）中的精度损失未在反向映射中进行镜像处理。
- 累积路径：将每次 swap 的余数作为可由 caller 提取的 credits 进行跟踪，而不是销毁或纳入零和处理。

## Custom accounting 与 delta amplification

- Uniswap v4 custom accounting 允许 hooks 返回可直接调整 caller 应付/应收金额的 deltas。如果 hook 在内部跟踪 credits，舍入残差可能在许多次小额操作中累积，直到最终结算发生。<sup>[[5]](#references)</sup>
- 这会增强边界/阈值滥用：attacker 可以在同一笔 tx 中交替执行 `swap → withdraw → swap`，迫使 hook 在所有余额仍处于 pending 状态时，根据略有不同的 state 重新计算 deltas。
- 审查 hooks 时，始终追踪 BalanceDelta/HookDelta 的生成与结算过程。某个分支中的一次偏向性舍入，可能在 deltas 被反复重新计算时变成不断复合的 credit。

## 防御建议

- Differential testing：将 hook 的 math 与使用高精度有理数运算的 reference implementation 进行比对，并断言结果相等，或误差始终处于对用户不利的有界范围内（绝不能对 caller 有利）。
- Invariant/property tests：
- 所有 swap 路径和 hook 调整中的 delta（tokens、liquidity）之和，除 fees 外必须保持价值守恒。
- 在反复执行 exactInput iterations 时，任何路径都不应为 swap initiator 创建正的净 credit。
- 针对 exactInput/exactOutput，在 ±1 wei 输入附近测试 threshold/tick boundary。
- 舍入策略：集中实现始终对用户不利地舍入的舍入辅助函数；消除不一致的 casts 和隐式向下取整。
- Settlement sinks：将不可避免的舍入残差累积至 protocol treasury 或销毁；绝不要将其归属于 msg.sender。
- Rate-limits/guardrails：为 rebalancing triggers 设置最小 swap size；如果 deltas 小于 1 wei，则禁用 rebalances；根据预期范围对 deltas 进行 sanity-check。
- 全面审查 hook callbacks：beforeSwap/afterSwap 以及流动性变更前后的 callbacks，应在 tick 对齐和 delta 舍入方面保持一致。

## Case study: Bunni V2（2025-09-02）

- Protocol：Bunni V2（Uniswap v4 hook），每次 swap 应用 LDF 进行 rebalance。<sup>[[7]](#references)</sup>
- 受影响的 pools：Ethereum 上的 USDC/USDT，以及 Unichain 上的 weETH/ETH，总计约 $8.4M。<sup>[[1]](#references)[[2]](#references)</sup>
- Step 1（推动价格）：attacker flash-borrowed 约 3M USDT 并进行 swap，将 tick 推至约 5000，使 **active** USDC balance 缩减至约 28 wei。<sup>[[7]](#references)</sup>
- Step 2（舍入 drain）：44 次小额 withdrawals 利用 `BunniHubLogic::withdraw()` 中的向下取整，将 active USDC balance 从 28 wei 降至 4 wei（-85.7%），而只销毁了极小一部分 LP shares。Total liquidity 被低估了约 84.4%。<sup>[[2]](#references)[[7]](#references)</sup>
- Step 3（liquidity rebound sandwich）：一次 large swap 将 tick 推至约 839,189（1 USDC ≈ 2.77e36 USDT）。Liquidity estimates 发生反转并增加约 16.8%，从而实现 sandwich：attacker 以 inflated price swap 回去并获利退出。<sup>[[7]](#references)</sup>
- Post-mortem 中确定的修复方案：将 idle-balance update 改为向上取整，使 repeated micro-withdrawals 无法逐步向下压低 pool 的 active balance。<sup>[[7]](#references)</sup>

存在漏洞的简化代码行（以及 post-mortem 修复方案）<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting 检查清单

- 池是否使用非零的 hooks address？启用了哪些 callbacks？
- 是否存在使用 custom math 的逐 swap redistributions/rebalances？是否有 tick/threshold 逻辑？
- 在哪里使用了 divisions/mulDiv、Q64.96 conversions 或 SafeCast？rounding semantics 是否全局一致？
- 能否构造一个仅略微跨过 boundary 的 Δin，并触发有利的 rounding branch？测试两个方向，以及 exactInput 和 exactOutput。
- hook 是否跟踪每个 caller 的 credits 或 deltas，以便之后提取？确保 residue 被 neutralized。

## References

- [1] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
