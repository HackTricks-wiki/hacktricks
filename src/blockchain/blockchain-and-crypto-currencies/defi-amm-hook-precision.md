# DeFi/AMM Exploitation：Uniswap v4 Hook Precision/Rounding Abuse

本文记录了一类针对 Uniswap v4 风格 DEX 的 DeFi/AMM exploitation techniques。这类 DEX 通过 custom hooks 扩展核心数学逻辑。Bunni V2 incident 展示了相关 failure：withdrawal accounting 中的 rounding-direction bug 低估了 active liquidity，随后的一次 swap 在 profitable sandwich 中暴露了这一低估。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

核心思路：如果 hook 实现了依赖 fixed-point math、tick rounding 和 threshold logic 的额外 accounting，attacker 可以构造 exact-input swaps，使其跨越特定 thresholds，从而让 rounding discrepancies 持续向自身有利的方向累积。重复这一模式后，再 withdraw inflated balance 即可实现 profit，通常会使用 flash loan 提供资金。

## Background：Uniswap v4 hooks and swap flow

- Hooks 是 PoolManager 在特定 lifecycle points 调用的 contracts（例如 beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）。<sup>[[4]](#references)</sup>
- Pools 使用包含 hook contract 的 PoolKey 进行 initialized。非零的 hook address 会启用为该 pool 选择的 callbacks。<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks 可以返回 **custom deltas**，用于修改 swap 或 liquidity action 的最终 balance changes（custom accounting）。这些 deltas 会在 call 结束时作为 net balances 进行 settled，因此 hook math 中的任何 rounding error 都会在 settlement 前累积。<sup>[[4]](#references)</sup>
- Core math 使用 Q64.96 等 fixed-point formats 表示 sqrtPriceX96，并使用基于 1.0001^tick 的 tick arithmetic。任何叠加在其上的 custom math 都必须仔细匹配 rounding semantics，以避免 invariant drift。<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps 可以是 exactInput 或 exactOutput。在 v3/v4 中，price 会沿 ticks 移动；跨越 tick boundary 可能会 activate/deactivate range liquidity。Hooks 可能会在 threshold/tick crossings 时实现额外逻辑。<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype：threshold-crossing precision/rounding drift

custom hooks 中常见的 vulnerable pattern：

1. Hook 使用 integer division、mulDiv 或 fixed-point conversions 计算每次 swap 的 liquidity 或 balance deltas（例如使用 sqrtPrice 和 tick ranges 在 token 与 liquidity 之间转换）。
2. 当 swap size 或 price movement 跨越内部 boundary 时，threshold logic（例如 rebalancing、stepwise redistribution 或 per-range activation）会被触发。
3. Forward calculation 与 settlement path 使用了不一致的 rounding（例如 toward zero 的 truncation、floor 与 ceil 不一致）。微小 discrepancy 不会相互抵消，反而会 credit caller。
4. 精确调整大小、用于跨越这些 boundaries 的 exact-input swaps 会反复 harvest positive rounding remainder。Attacker 随后 withdraw 累积的 credit。

Attack preconditions
- 使用 custom v4 hook 的 pool，该 hook 会在每次 swap 时执行额外 math（例如 LDF/rebalancer）。
- 至少存在一条 execution path，使 rounding 在 threshold crossings 中有利于 swap initiator。
- 能够以 atomic 方式重复执行多次 swaps（flash loans 非常适合提供临时 float 并分摊 gas）。

## Practical attack methodology

1) Identify candidate pools with hooks
- 枚举 v4 pools，并检查 PoolKey.hooks != address(0)。
- 棷查 hook bytecode/ABI 中的 callbacks：beforeSwap/afterSwap 以及任何 custom rebalancing methods。
- 查找以下 math：除以 liquidity、在 token amounts 与 liquidity 之间转换，或对 BalanceDelta 进行带 rounding 的 aggregation。

2) Model the hook’s math and thresholds
- 重现 hook 的 liquidity/redistribution formula：输入通常包括 sqrtPriceX96、tickLower/Upper、currentTick、fee tier 和 net liquidity。
- 映射 threshold/step functions：ticks、bucket boundaries 或 LDF breakpoints。确定每个 boundary 的哪一侧会对 delta 进行 rounding。
- 确定 uint256/int256 之间发生 cast 的位置、使用 SafeCast 的位置，或依赖带 implicit floor 的 mulDiv 的位置。

3) Calibrate exact-input swaps to cross boundaries
- 使用 Foundry/Hardhat simulations 计算移动 price、刚好跨越 boundary 并触发 hook 分支所需的最小 Δin。
- 验证 afterSwap settlement 是否向 caller credit 高于成本的金额，从而在 hook accounting 中留下 positive BalanceDelta 或 credit。
- 重复 swaps 以累积 credit，然后调用 hook 的 withdrawal/settlement path。

在 v4 中，swap loop 必须从 PoolManager unlock callback 运行；负的 `amountSpecified` 表示 exact input，且 `sqrtPriceLimitX96` 必须严格位于有效范围之内。零 price limit 会 revert，因此以下 pseudocode 对 zero-for-one swap 使用 lower bound。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Example Foundry-style test harness (pseudocode)
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
- 使用 core TickMath 计算目标：在实际数值层面，sqrtP_next = sqrtP_current × 1.0001^(Δtick)；Q64.96 结果由 TickMath 进行舍入。<sup>[[13]](#references)</sup>
- 使用考虑 Q64.96 的公式近似 token0（zero-for-one）输入：Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)。匹配 core routine 针对方向的舍入方式。<sup>[[12]](#references)</sup>
- 在边界附近将 Δin 调整 ±1 wei，以找到 hook 舍入对你有利的分支。

4) 使用 flash loans 放大
- 借入大额名义金额（例如 3M USDT 或 2000 WETH），以原子方式运行多次迭代。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 执行校准后的 swap loop，然后在 flash loan callback 中提现并偿还。

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
- 在 Bunni incident 中，各链的 flash-loan liquidity 和 bridge routes 不同，因此在复现分析时应考虑这些链特定的约束。<sup>[[1]](#references)[[2]](#references)</sup>

## Common root causes in hook math

- 混合的 rounding 语义：mulDiv 向下取整，而后续路径实际上向上取整；或者 token/liquidity 之间的转换使用了不同的 rounding。
- Tick 对齐错误：一条路径使用未取整的 ticks，另一条路径使用按 tick 间隔取整。
- 在结算期间于 int256 和 uint256 之间转换时出现 BalanceDelta 符号/溢出问题。
- Q64.96 转换（sqrtPriceX96）中的精度损失没有在反向映射中得到对应处理。
- 累积路径：将每次 swap 的余数作为可由 caller 提取的 credits 进行跟踪，而不是将其销毁或保持 zero-sum。

## Custom accounting & delta amplification

- Uniswap v4 custom accounting 允许 hooks 返回 deltas，直接调整 caller 应支付/接收的金额。如果 hook 在内部跟踪 credits，则 rounding residue 可能在许多小额操作中累积，**直到**最终 settlement 发生。<sup>[[4]](#references)</sup>
- 如果 hook 暴露了兼容的 withdrawal path，attacker 可以在同一个 PoolManager unlock callback 中交替执行 `swap → withdraw → swap`，迫使 hook 在略有不同的 state 上重新计算 deltas，同时 balances 会一直处于 pending 状态，直到 unlock 完成 settlement。<sup>[[4]](#references)[[10]](#references)</sup>
- 审查 hooks 时，始终追踪 BalanceDelta/HookDelta 的生成与 settlement 过程。某个分支中的一次 biased rounding，可能在 deltas 被反复重新计算时变成不断累积的 credit。

## Defensive guidance

- Differential testing：使用高精度 rational arithmetic，将 hook 的 math 与 reference implementation 对照，并断言结果相等或误差有界，且该误差始终对 caller 不利（绝不能对 caller 有利）。
- Invariant/property tests：
- swap paths 与 hook adjustments 中的 deltas 总和（tokens、liquidity）必须守恒，手续费除外。
- 在反复执行 exactInput iterations 时，任何路径都不应为 swap initiator 创建正的净 credit。
- 针对 exactInput/exactOutput，在 ±1 wei inputs 附近的 threshold/tick boundary 进行测试。
- Rounding policy：集中管理 rounding helpers，使其始终对 user 不利地取整；消除不一致的 casts 和隐式 floors。
- Settlement sinks：将无法避免的 rounding residue 累积到 protocol treasury 或销毁；绝不能归属于 msg.sender。
- Rate-limits/guardrails：为 rebalancing triggers 设置 minimum swap sizes；如果 deltas 小于一个 wei，则禁用 rebalances；根据预期范围对 deltas 进行 sanity-check。
- 全面审查 hook callbacks：beforeSwap/afterSwap 以及 before/after liquidity changes 应在 tick alignment 和 delta rounding 上保持一致。

## Case study: Bunni V2 (2025‑09‑02)

- Protocol：Bunni V2，一个使用 Liquidity Density Function (LDF) 计算 token density 和 total-liquidity estimates 的 Uniswap v4 hook。<sup>[[1]](#references)[[2]](#references)</sup>
- 受影响的 pools：Ethereum 上的 USDC/USDT 和 Unichain 上的 weETH/ETH，总计约 $8.4M。<sup>[[1]](#references)</sup>
- Step 1（price push）：attacker flash-borrowed 约 3M USDT 并执行 swap，将 tick 推至约 5000，使 **active** USDC balance 缩减至约 28 wei。<sup>[[1]](#references)</sup>
- Step 2（rounding drain）：44 次微小 withdrawals 利用 `BunniHubLogic::withdraw()` 中的 floor rounding，将 active USDC balance 从 28 wei 降至 4 wei（-85.7%），而只 burn 了极小一部分 LP shares。Total liquidity 下降了约 84.4%。<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3（liquidity rebound sandwich）：一次 large swap 将 tick 移至约 839,189（1 USDC ≈ 2.77e36 USDT）。Liquidity estimates 发生翻转并增加约 16.8%，从而实现 sandwich：attacker 以 inflated price swap 回去并获利退出。<sup>[[1]](#references)</sup>
- post-mortem 中确定的修复方案：将 idle-balance update 改为向上取整，使 repeated micro-withdrawals 不再持续向下压低 pool 的 active balance。<sup>[[1]](#references)</sup>

简化的 vulnerable line（以及 post-mortem fix）。<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- Pool 是否使用了非零的 hooks address？启用了哪些 callbacks？
- 是否存在使用 custom math 的逐笔 swap redistribution/rebalance？是否有 tick/threshold 逻辑？
- 在哪里使用了 divisions/mulDiv、Q64.96 conversions 或 SafeCast？舍入语义是否全局一致？
- 能否构造一个刚好跨过边界的 Δin，使其触发有利的舍入分支？测试两个方向，以及 exactInput 和 exactOutput。
- hook 是否跟踪了每个 caller 的 credits 或 deltas，并允许稍后提取？确保 residue 被中和。

## References

- [1] [Bunni Exploit Post Mortem（2025 年 9 月）](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit：完整 Hack 分析](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit：通过 Liquidity Flaw 排出 830 万美元（摘要）](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 背景（QuillAudits 研究）](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 core 中的 Liquidity mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 core 中的 Swap mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks 和 Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
