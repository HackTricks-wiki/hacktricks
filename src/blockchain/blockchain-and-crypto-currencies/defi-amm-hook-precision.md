# DeFi/AMM 利用：Uniswap v4 Hook 精度/舍入 滥用

{{#include ../../banners/hacktricks-training.md}}



本页记录了一类针对 Uniswap v4 风格 DEXes 的 DeFi/AMM 利用技术，这类 DEX 在核心数学之上扩展了自定义 hooks。近期 Bunni V2 事件利用了在每次 swap 中执行的 Liquidity Distribution Function (LDF) 的舍入/精度缺陷，使攻击者累积正的 credit 并抽干流动性。

关键思想：如果 hook 实现了依赖于定点数学、tick 舍入和阈值逻辑的额外记账，攻击者可以构造精确输入的 swap（exact‑input swaps），跨越特定阈值，使舍入差异累积到有利于攻击者的一端。重复该模式然后提取被放大的余额即可实现利润，通常以 flash loan 融资。

## 背景：Uniswap v4 hooks 与 swap 流程

- Hooks 是 PoolManager 在特定生命周期点调用的合约（例如 beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）。
- 池在初始化时以包含 hooks 地址的 PoolKey 启动。如果非零，PoolManager 会在每次相关操作上执行回调。
- Hooks 可以返回自定义 delta（custom deltas），以修改 swap 或流动性操作的最终余额变化（自定义记账）。这些 delta 在调用结束时作为净余额结算，因此 hook 内部的任何舍入误差都会在结算前累积。
- 核心数学使用诸如 Q64.96 的定点格式用于 sqrtPriceX96，并使用 1.0001^tick 的 tick 算术。任何叠加在其上的自定义数学必须小心匹配舍入语义以避免不变式漂移。
- Swaps 可以是 exactInput 或 exactOutput。在 v3/v4 中，价格沿 tick 移动；跨越 tick 边界可能激活/停用区间流动性。Hooks 可能在阈值/ tick 跨越时实现额外逻辑。

## 漏洞范式：阈值跨越导致的精度/舍入漂移

自定义 hook 中常见的易受攻击模式：

1. Hook 使用整除、mulDiv 或定点转换来为每次 swap 计算流动性或余额变化（例如使用 sqrtPrice 和 tick 范围在 token ↔ liquidity 之间转换）。
2. 阈值逻辑（例如再平衡、分步重分配或按区间激活）在 swap 大小或价格移动跨越内部边界时触发。
3. 前向计算与结算路径之间对舍入的处理不一致（例如向零截断、floor 与 ceil 不同），小的差异不会相互抵消，反而记入调用者。
4. 精确输入的 swaps 被精心设计以跨越这些边界，重复收割正的舍入余数。攻击者随后提取累积的 credit。

攻击前置条件
- 池使用对每次 swap 执行额外数学的自定义 v4 hook（例如 LDF/rebalancer）。
- 至少存在一条执行路径使得舍入在阈值跨越时使 swap 发起者受益。
- 能够以原子方式重复多次 swap（flash loans 非常适合提供临时资金并摊薄 gas 成本）。

## 实用攻击方法论

1) 识别带有 hooks 的候选池
- 枚举 v4 池并检查 PoolKey.hooks != address(0)。
- 检查 hook 的字节码/ABI，寻找回调：beforeSwap/afterSwap 以及任何自定义的再平衡方法。
- 寻找会除以流动性、在 token 数量与流动性间转换，或带舍入的 BalanceDelta 聚合等相关数学逻辑。

2) 建模 hook 的数学与阈值
- 重建 hook 的流动性/重分配公式：输入通常包括 sqrtPriceX96、tickLower/Upper、currentTick、fee tier 和净流动性。
- 映射阈值/步进函数：ticks、bucket 边界或 LDF 的断点。确定在每个边界的哪一侧 delta 会被舍入。
- 识别在哪些地方进行 uint256/int256 的类型转换、使用 SafeCast，或依赖带隐式 floor 的 mulDiv。

3) 校准以跨越边界的 exact‑input swaps
- 使用 Foundry/Hardhat 模拟计算移动价格刚好跨越某边界并触发 hook 分支所需的最小 Δin。
- 验证 afterSwap 结算是否比成本多记入调用者，使得在 hook 的记账中留下正的 BalanceDelta 或 credit。
- 重复 swaps 以累积 credit；然后调用 hook 的提现/结算路径。

Example Foundry‑style test harness (pseudocode)
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
Calibrating the exactInput
- 计算一个 tick 步长的 ΔsqrtP: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- 使用 v3/v4 公式近似 Δin: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). 确保舍入方向与核心数学一致。
- 在边界附近将 Δin ±1 wei 调整，找到 hook 在舍入时有利于你的分支。

4) Amplify with flash loans
- 借入大额名义（例如 3M USDT 或 2000 WETH），以原子方式运行多次迭代。
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
- 如果 hooks 部署在多个链上，针对每条链重复相同的校准。
- 将资金通过桥回到目标链，并可选择通过借贷协议循环以混淆资金流。

## Common root causes in hook math

- Mixed rounding semantics: mulDiv 向下取整，而后续路径实际上向上舍入；或在 token/liquidity 之间转换时应用了不同的舍入策略。
- Tick alignment errors: 在一条路径中使用未对齐的 ticks，而另一条路径使用了 tick‑spacing 的舍入。
- BalanceDelta 符号/溢出问题：在结算期间在 int256 与 uint256 之间转换时出现错误。
- Q64.96 转换（sqrtPriceX96）中的精度损失在反向映射中未被镜像。
- 累积途径：每次 swap 的剩余作为可由调用者提取的 credit 跟踪，而不是被烧掉/置零和。

## Custom accounting & delta amplification

- Uniswap v4 custom accounting 允许 hooks 返回直接调整调用方应付/应收的 deltas。如果 hook 在内部追踪 credits，舍入残差可以在最终结算发生之前在许多小操作中累积。
- 这会放大边界/阈值滥用：攻击者可以在同一 tx 中交替执行 `swap → withdraw → swap`，迫使 hook 在状态略有不同的情况下重新计算 deltas，而所有余额仍处于待决状态。
- 在审查 hooks 时，务必追踪 BalanceDelta/HookDelta 的产生和结算方式。单个分支中的偏置舍入在 deltas 被反复重新计算时可能会成为复利式的 credit。

## Defensive guidance

- Differential testing：用高精度有理数运算将 hook 的数学与参考实现镜像比对，并断言相等或在始终对抗调用方（绝不利于调用方）的有界误差内。
- Invariant/property tests：
- 跨 swap 路径和 hook 调整的 deltas（tokens、liquidity）之和必须在扣除手续费后守恒。
- 任何路径都不应在重复的 exactInput 迭代中为 swap 发起者创造正的净 credit。
- 在 ±1 wei 附近对 exactInput/exactOutput 进行阈值/tick 边界测试。
- Rounding policy：集中舍入助手，始终朝对用户不利的方向舍入；消除不一致的类型转换和隐式向下取整。
- Settlement sinks：将不可避免的舍入残差累积到协议金库或燃烧；绝不归属给 msg.sender。
- Rate‑limits/guardrails：为再平衡触发设置最小 swap 大小；如果 deltas 小于 sub‑wei 则禁用再平衡；对 deltas 做合理范围校验。
- 从整体上审查 hook 回调：beforeSwap/afterSwap 以及 before/after liquidity 变更应在 tick 对齐和 delta 舍入上保持一致。

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) 每次 swap 应用一个 LDF 进行再平衡。
- 受影响池：Ethereum 上的 USDC/USDT 以及 Unichain 上的 weETH/ETH，总计约 840 万美元。
- Step 1 (price push)：攻击者 flash‑borrowed 约 300 万 USDT 并 swapped 将 tick 推到约 5000，使 **active** 的 USDC 余额缩减到约 28 wei。
- Step 2 (rounding drain)：44 次微小的 withdrawals 利用了 `BunniHubLogic::withdraw()` 中的向下取整，将 active USDC 余额从 28 wei 降至 4 wei（‑85.7%），而仅燃烧了极小一部分 LP 份额。总流动性被低估约 84.4%。
- Step 3 (liquidity rebound sandwich)：一次大额 swap 将 tick 推到约 839,189（1 USDC ≈ 2.77e36 USDT）。流动性估计翻转并增加约 16.8%，使得攻击者能够在被抬高的价格回换并带着利润退出，形成夹击套利。
- post‑mortem 中确定的修复：将 idle‑balance 更新改为向上舍入（round **up**），以避免重复微量 withdraw 将池的 active 余额向下棘轮化。

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## 漏洞狩猎检查清单

- 池子是否使用非零 hooks 地址？哪些 callbacks 被启用？
- 是否存在每次 swap 的重新分配/再平衡并使用自定义数学？是否有任何 tick/阈值 逻辑？
- 在哪些地方使用了 divisions/mulDiv、Q64.96 转换或 SafeCast？舍入语义在全局上是否一致？
- 能否构造一个刚好跨越边界并触发有利舍入分支的 Δin？在两个方向以及 exactInput 和 exactOutput 下都要测试。
- hook 是否跟踪每个调用者的 credits 或 deltas（可在之后提取）？确保残留被中和。

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
