# DeFi/AMM 利用：Uniswap v4 Hook 精度/舍入 滥用

{{#include ../../banners/hacktricks-training.md}}

本页记录了一类针对 Uniswap v4 风格 DEX 的 DeFi/AMM 利用技术，这类 DEX 在核心数学之上扩展了自定义 hooks。近期 Bunni V2 的一起事件利用了在每次 swap 上执行的 Liquidity Distribution Function (LDF) 中的舍入/精度缺陷，使攻击者能够累积正向 credit 并抽干流动性。

关键思想：如果一个 hook 实现了依赖定点数运算、tick 舍入和阈值逻辑的额外记账，攻击者可以构造精确的 exact‑input swaps 去跨越特定阈值，从而使舍入差异朝有利于攻击者的方向累积。重复该模式然后提取被放大的余额即可实现利润，通常用 flash loan 提供资金。

## 背景：Uniswap v4 hooks 和 swap 流程

- Hooks 是 PoolManager 在特定生命周期点调用的合约（例如 beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity）。
- Pools 使用包含 hooks 地址的 PoolKey 初始化。如果非零，PoolManager 会在每次相关操作上执行回调。
- 核心数学使用诸如 Q64.96 的定点格式用于 sqrtPriceX96，并使用基于 1.0001^tick 的 tick 算术。任何叠加的自定义数学必须小心匹配舍入语义以避免不变量漂移。
- Swaps 可以是 exactInput 或 exactOutput。在 v3/v4 中，价格沿 tick 移动；跨越 tick 边界可能激活/停用区间流动性。Hooks 可能在阈值/tick 跨越时实现额外逻辑。

## 漏洞原型：阈值跨越的精度/舍入漂移

自定义 hook 中常见的易受攻击模式：

1. Hook 使用整数除法、mulDiv 或定点转换（例如用 sqrtPrice 和 tick 范围在 token ↔ liquidity 之间转换）来计算每次 swap 的流动性或余额增量。
2. 阈值逻辑（例如再平衡、分步重分配或按区间激活）在 swap 大小或价格移动跨越内部边界时触发。
3. 在前向计算和结算路径之间不一致地应用舍入（例如向零截断、floor 与 ceil 的差异）。小的差异不会相互抵消，反而记入调用者的账户。
4. 精确的 exact‑input swaps 被精心设计为跨越这些边界并重复收割正向舍入余数。攻击者随后提取累计的 credit。

攻击先决条件
- 池使用对每次 swap 执行额外数学的自定义 v4 hook（例如 LDF/rebalancer）。
- 至少存在一条执行路径使舍入在阈值跨越时有利于 swap 发起者。
- 能够原子地重复许多 swaps（flash loans 非常适合提供临时资金并摊薄 gas 成本）。

## 实际攻击方法论

1) 识别带有 hooks 的候选池
- 枚举 v4 池并检查 PoolKey.hooks != address(0)。
- 检查 hook 的 bytecode/ABI，查找回调：beforeSwap/afterSwap 及任何自定义的 rebalancing 方法。
- 寻找那种会：按流动性除法、在 token 数量与流动性之间转换，或聚合 BalanceDelta 且带有舍入的数学逻辑。

2) 建模 hook 的数学与阈值
- 还原 hook 的流动性/重分配公式：输入通常包括 sqrtPriceX96、tickLower/Upper、currentTick、fee tier 和净流动性。
- 映射阈值/步进函数：ticks、bucket 边界或 LDF 分段点。确定在每个边界的哪一侧 delta 会被舍入。
- 找出在哪些地方进行 uint256/int256 之间的转换、使用 SafeCast，或依赖隐式 floor 的 mulDiv。

3) 校准精确输入以跨越边界
- 使用 Foundry/Hardhat 模拟来计算将价格刚好跨过边界并触发 hook 分支所需的最小 Δin。
- 验证 afterSwap 结算后是否记入调用者的金额多于成本，留下正的 BalanceDelta 或 hook 的记账信用。
- 重复 swaps 以累计 credit；然后调用 hook 的提现/结算路径。

示例 Foundry‑style 测试 harness（伪代码）
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
- 计算 tick 步长对应的 ΔsqrtP：sqrtP_next = sqrtP_current × 1.0001^(Δtick)。
- 使用 v3/v4 公式近似 Δin：Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current))。确保舍入方向与核心实现的数学一致。
- 在边界附近将 Δin 上下调整 ±1 wei，以找到 hook 对你有利的舍入分支。

4) 使用 flash loans 放大
- 借入大额名义资金（例如 3M USDT 或 2000 WETH），以在原子交易中运行多次迭代。
- 执行已校准的 swap 循环，然后在 flash loan callback 中提取并偿还。

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
- 如果 hooks 部署在多条链上，对每条链重复相同的校准。
- 通过桥接将资金回到目标链，并可选择通过借贷协议循环以混淆资金流。

## hook 数学中的常见根本原因

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## 防御性建议

- Differential testing: mirror the hook’s math vs a reference implementation using high‑precision rational arithmetic and assert equality or bounded error that is always adversarial (never favorable to caller).
- Invariant/property tests:
- Sum of deltas (tokens, liquidity) across swap paths and hook adjustments must conserve value modulo fees.
- No path should create positive net credit for the swap initiator over repeated exactInput iterations.
- Threshold/tick boundary tests around ±1 wei inputs for both exactInput/exactOutput.
- Rounding policy: centralize rounding helpers that always round against the user; eliminate inconsistent casts and implicit floors.
- Settlement sinks: accumulate unavoidable rounding residue to protocol treasury or burn it; never attribute to msg.sender.
- Rate‑limits/guardrails: minimum swap sizes for rebalancing triggers; disable rebalances if deltas are sub‑wei; sanity‑check deltas against expected ranges.
- Review hook callbacks holistically: beforeSwap/afterSwap and before/after liquidity changes should agree on tick alignment and delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Root cause: rounding/precision error in LDF liquidity accounting during threshold‑crossing swaps; per‑swap discrepancies accrued as positive credits for the caller.
- Ethereum leg: attacker took a ~3M USDT flash loan, performed calibrated exact‑input swaps on USDC/USDT to build credits, withdrew inflated balances, repaid, and routed funds via Aave.
- UniChain leg: repeated the exploit with a 2000 WETH flash loan, siphoning ~1366 WETH and bridging to Ethereum.
- Impact: ~USD 8.3M drained across chains. No user interaction required; entirely on‑chain.

## Hunting checklist

- Does the pool use a non‑zero hooks address? Which callbacks are enabled?
- Are there per‑swap redistributions/rebalances using custom math? Any tick/threshold logic?
- Where are divisions/mulDiv, Q64.96 conversions, or SafeCast used? Are rounding semantics globally consistent?
- Can you construct Δin that barely crosses a boundary and yields a favorable rounding branch? Test both directions and both exactInput and exactOutput.
- Does the hook track per‑caller credits or deltas that can be withdrawn later? Ensure residue is neutralized.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
