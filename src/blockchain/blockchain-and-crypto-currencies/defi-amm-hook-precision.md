# DeFi/AMM Exploitation：Uniswap v4 Hook 精度/舍入滥用

{{#include ../../banners/hacktricks-training.md}}

本文记录了一类针对 Uniswap v4 风格 DEX 的 DeFi/AMM exploitation 技术：这类 DEX 通过 custom hooks 扩展核心数学逻辑。Bunni V2 事件展示了一个相关故障：提款 accounting 中的舍入方向 bug 低估了 active liquidity，随后一次 swap 在获利 sandwich 中暴露了这一低估。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

核心思路是：如果一个 hook 实现的额外 accounting 依赖 fixed-point math、tick rounding 和 threshold logic，攻击者就可以构造精确的 exact-input swaps，使其跨越特定阈值，从而让舍入差异不断累积并有利于攻击者。重复该模式，然后提取膨胀后的 balance 即可实现获利，通常使用 flash loan 提供资金。

## Background：Uniswap v4 hooks 和 swap 流程

- Hooks 是由 PoolManager 在特定生命周期节点调用的合约（例如 beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）。<sup>[[4]](#references)</sup>
- Pools 初始化时会包含一个带有 hook 合约的 PoolKey。非零的 hook 地址会启用该 pool 所选择的 callbacks。<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks 可以返回 **custom deltas**，修改 swap 或 liquidity 操作最终的 balance 变化（custom accounting）。这些 deltas 会在调用结束时作为 net balances 进行结算，因此 hook math 中的任何舍入误差都会在结算前累积。<sup>[[4]](#references)</sup>
- 核心数学使用 Q64.96 等 fixed-point 格式表示 sqrtPriceX96，并使用基于 1.0001^tick 的 tick arithmetic。其上叠加的任何 custom math 都必须仔细匹配舍入语义，以避免 invariant drift。<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps 可以是 exactInput 或 exactOutput。在 v3/v4 中，价格沿 ticks 移动；跨越 tick boundary 可能会激活或停用 range liquidity。Hooks 可能会在 threshold/tick crossings 时实现额外逻辑。<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype：跨越 threshold 导致的精度/舍入漂移

custom hooks 中典型的易受攻击模式：

1. Hook 使用 integer division、mulDiv 或 fixed-point conversions 计算每次 swap 的 liquidity 或 balance deltas（例如使用 sqrtPrice 和 tick ranges 在 token 与 liquidity 之间进行转换）。
2. 当 swap size 或 price movement 跨越内部 boundary 时，threshold logic（例如 rebalancing、stepwise redistribution 或 per-range activation）会被触发。
3. Forward calculation 和 settlement path 使用了不一致的舍入方式（例如向零截断、floor 与 ceil 不一致）。微小差异不会相互抵消，反而会 credit caller。
4. 精确调整大小、用于跨越这些 boundary 的 exact-input swaps 会反复收割正的舍入余数。攻击者随后提取累积的 credit。

Attack 前提条件
- 一个使用 custom v4 hook 的 pool，该 hook 会在每次 swap 时执行额外 math（例如 LDF/rebalancer）。
- 至少存在一条 execution path，使舍入结果在跨越 threshold 时有利于 swap initiator。
- 能够以 atomic 方式重复执行大量 swaps（flash loans 非常适合提供临时资金并分摊 gas）。

## Practical attack methodology

1) 识别带有 hooks 的候选 pools
- 枚举 v4 pools，并检查 PoolKey.hooks != address(0)。
- 检查 hook 的 bytecode/ABI，寻找 callbacks：beforeSwap/afterSwap 以及任何 custom rebalancing methods。
- 寻找以下 math：除以 liquidity、在 token amounts 与 liquidity 之间转换，或使用舍入聚合 BalanceDelta。

2) 建模 hook 的 math 和 thresholds
- 还原 hook 的 liquidity/redistribution formula：输入通常包括 sqrtPriceX96、tickLower/Upper、currentTick、fee tier 和 net liquidity。
- 映射 threshold/step functions：ticks、bucket boundaries 或 LDF breakpoints。确定每个 boundary 的哪一侧会进行舍入。
- 查找 uint256/int256 之间的 conversions cast、使用 SafeCast 的位置，或依赖隐式 floor 的 mulDiv。

3) 校准用于跨越 boundaries 的 exact-input swaps
- 使用 Foundry/Hardhat simulations 计算使价格刚好跨过 boundary 并触发 hook 分支所需的最小 Δin。
- 验证 afterSwap settlement 是否向 caller credit 超过成本的金额，从而在 hook accounting 中留下正的 BalanceDelta 或 credit。
- 重复执行 swaps 以累积 credit，然后调用 hook 的 withdrawal/settlement path。

在 v4 中，swap loop 必须从 PoolManager unlock callback 中运行；负的 `amountSpecified` 表示 exact input，而 `sqrtPriceLimitX96` 必须严格位于有效范围之内。价格限制为零会 revert，因此下面的 pseudocode 对 zero-for-one swap 使用下界。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Example Foundry-style test harness（pseudocode）
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: IHooks(address(bunniHook))
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
// This loop runs inside the PoolManager unlockCallback.
for (uint i; i < N; ++i) {
pm.swap(
key,
SwapParams({
zeroForOne: true,
amountSpecified: -int256(exactIn), // exactInput
sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1 // allow movement to the lower bound
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
校准 exactInput
- 使用 core TickMath 计算目标值：在实际数值层面，sqrtP_next = sqrtP_current × 1.0001^(Δtick)；Q64.96 结果由 TickMath 进行舍入。<sup>[[13]](#references)</sup>
- 使用感知 Q64.96 的公式近似计算 token0（zero-for-one）输入：Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)。匹配 core routine 针对方向的舍入方式。<sup>[[12]](#references)</sup>
- 在边界附近将 Δin 调整 ±1 wei，以找到 hook 舍入结果对你有利的分支。

4) 使用 flash loans 放大
- 借入较大的名义金额（例如 3M USDT 或 2000 WETH），以原子方式运行多次迭代。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 执行校准后的 swap loop，然后在 flash loan callback 中提取并偿还。

Aave V3 flash loan 骨架
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
- 在 Bunni 事件中，各条链上的 flash-loan 流动性和 bridge 路由不同，因此在复现分析时要考虑这些特定于链的约束。<sup>[[1]](#references)[[2]](#references)</sup>

## hook 数学中的常见根因

- 混合的舍入语义：mulDiv 向下舍入，而后续路径实际上向上舍入；或者 token/liquidity 之间的转换采用了不同的舍入方式。
- Tick 对齐错误：一条路径使用未舍入的 tick，而另一条路径使用按 tick 间距舍入的值。
- 在结算期间于 int256 和 uint256 之间转换时，BalanceDelta 的符号/溢出问题。
- Q64.96 转换（sqrtPriceX96）中的精度损失未在反向映射中得到对称处理。
- 累积路径：将每次 swap 的余数记为可由 caller 提取的 credits，而不是销毁这些余数或使其保持零和。

## 自定义记账与 delta 放大

- Uniswap v4 的 custom accounting 允许 hooks 返回直接调整 caller 应付/应收金额的 deltas。如果 hook 在内部追踪 credits，则舍入余数可能在许多次小额操作中累积，**直到**最终结算发生。<sup>[[4]](#references)</sup>
- 如果 hook 暴露了兼容的 withdrawal 路径，攻击者可以在同一个 PoolManager unlock callback 中交替执行 `swap → withdraw → swap`，迫使 hook 在略有不同的状态下重新计算 deltas，同时余额在 unlock 结算前仍处于待处理状态。<sup>[[4]](#references)[[10]](#references)</sup>
- 审查 hooks 时，始终追踪 BalanceDelta/HookDelta 的生成与结算过程。某个分支中的一次有偏舍入，可能在反复重新计算 deltas 时变成不断累积的 credit。

## 防御建议

- Differential testing：将 hook 的数学逻辑与使用高精度有理数运算的 reference implementation 对照，并断言结果相等，或误差始终处于有界范围内且总是对 caller 不利。
- Invariant/property tests：
- swap 路径和 hook 调整中的 delta 总和（tokens、liquidity）必须在扣除 fees 后保持价值守恒。
- 在重复执行 exactInput iterations 时，任何路径都不应为 swap initiator 创建正的净 credit。
- 针对 exactInput/exactOutput，在 ±1 wei 输入附近测试 threshold/tick 边界。
- 舍入策略：集中管理舍入 helper，使其始终朝不利于 user 的方向舍入；消除不一致的 casts 和隐式向下舍入。
- Settlement sinks：将无法避免的舍入余数累积到 protocol treasury 或销毁；绝不能归于 msg.sender。
- Rate-limits/guardrails：为 rebalancing triggers 设置最小 swap size；如果 deltas 小于一个 wei，则禁用 rebalances；根据预期范围对 deltas 执行合理性检查。
- 全面审查 hook callbacks：beforeSwap/afterSwap 以及 before/after liquidity changes 应在 tick 对齐和 delta 舍入方面保持一致。

## 案例研究：Bunni V2（2025-09-02）

- Protocol：Bunni V2，一个使用 Liquidity Density Function（LDF）计算 token density 和 total-liquidity estimates 的 Uniswap v4 hook。<sup>[[1]](#references)[[2]](#references)</sup>
- 受影响的 pools：Ethereum 上的 USDC/USDT，以及 Unichain 上的 weETH/ETH，总金额约为 840 万美元。<sup>[[1]](#references)</sup>
- Step 1（推动价格）：攻击者 flash-borrowed 约 300 万 USDT，并通过 swap 将 tick 推至约 5000，使 **active** USDC balance 降至约 28 wei。<sup>[[1]](#references)</sup>
- Step 2（舍入抽取）：44 次小额 withdrawals 利用 `BunniHubLogic::withdraw()` 中的向下舍入，将 active USDC balance 从 28 wei 降至 4 wei（-85.7%），而只销毁了极小部分 LP shares。Total liquidity 下降了约 84.4%。<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3（流动性反弹 sandwich）：一次大额 swap 将 tick 移至约 839,189（1 USDC ≈ 2.77e36 USDT）。Liquidity estimates 发生反转并增加约 16.8%，从而形成 sandwich：攻击者以被抬高的价格 swap 回来并获利退出。<sup>[[1]](#references)</sup>
- Post-mortem 中确定的修复方案：将 idle-balance update 改为向上舍入，使重复的小额 withdrawals 不再逐步压低 pool 的 active balance。<sup>[[1]](#references)</sup>

简化的易受攻击代码行（以及 post-mortem 修复）。<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting 清单

- Pool 是否使用非零的 hooks 地址？启用了哪些 callbacks？
- 是否存在使用 custom math 的逐 swap redistribution/rebalance？是否包含 tick/threshold 逻辑？
- 在哪里使用了 divisions/mulDiv、Q64.96 conversions 或 SafeCast？rounding 语义是否全局一致？
- 能否构造一个几乎跨过边界的 Δin，使其进入有利的 rounding 分支？测试两个方向，以及 exactInput 和 exactOutput。
- hook 是否跟踪每个 caller 的 credits 或 deltas，并允许稍后提取？确保 residue 被中和。

## References

- [1] [Bunni Exploit 事后分析（2025 年 9 月）](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit：完整 Hack 分析](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit：通过流动性缺陷耗尽 830 万美元（摘要）](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 背景介绍（QuillAudits 研究）](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 core 中的流动性机制](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 core 中的 Swap 机制](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks 与安全注意事项](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
