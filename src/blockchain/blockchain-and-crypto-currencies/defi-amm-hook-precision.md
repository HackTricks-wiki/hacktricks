# DeFi/AMM Exploitation：Uniswap v4 Hook 精度/舍入滥用

{{#include ../../banners/hacktricks-training.md}}

本文介绍针对 Uniswap v4 风格 DEX 的一类 DeFi/AMM exploitation 技术，这类 DEX 通过自定义 hooks 扩展核心数学逻辑。Bunni V2 事件展示了一个相关故障：提款记账中的舍入方向 bug 低估了活跃流动性，之后的一笔 swap 在有利可图的 sandwich 中暴露了这一低估。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

核心思路：如果 hook 实现的额外记账逻辑依赖定点数学、tick 舍入和阈值判断，攻击者就可以构造精确的 exact-input swaps，跨越特定阈值，使舍入差异累积并对自己有利。重复此模式，之后提取虚增的余额即可获利，通常会使用 flash loan 进行资金周转。

## 背景：Uniswap v4 hooks 和 swap 流程

- Hooks 是 PoolManager 在特定生命周期节点调用的合约（例如 beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）。<sup>[[4]](#references)</sup>
- Pool 使用包含 hook 合约的 PoolKey 进行初始化。非零的 hook 地址会启用该 pool 所选的 callbacks。<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks 可以返回 **custom deltas**，以修改 swap 或流动性操作最终产生的余额变化（custom accounting）。这些 deltas 会在调用结束时按净余额结算，因此 hook 数学逻辑中的任何舍入误差都会在结算前累积。<sup>[[4]](#references)</sup>
- 核心数学逻辑使用 Q64.96 等定点格式表示 sqrtPriceX96，并使用基于 1.0001^tick 的 tick 算术。叠加在其上的任何自定义数学逻辑都必须仔细匹配舍入语义，以避免不变量漂移。<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps 可以是 exactInput 或 exactOutput。在 v3/v4 中，价格沿 ticks 变动；跨越 tick 边界可能会激活/停用范围流动性。Hooks 可能会在跨越阈值/tick 时实现额外逻辑。<sup>[[9]](#references)[[11]](#references)</sup>

## 漏洞模式：跨越阈值时的精度/舍入漂移

自定义 hooks 中常见的易受攻击模式：

1. Hook 使用整数除法、mulDiv 或定点转换（例如，使用 sqrtPrice 和 tick 范围在 token 与 liquidity 之间转换）计算每笔 swap 的流动性或余额增量。
2. 当 swap 数量或价格变动跨越内部边界时，触发阈值逻辑（例如重新平衡、分步再分配或逐范围激活）。
3. 前向计算与结算路径中的舍入方式不一致（例如向零截断、向下取整与向上取整不一致）。微小差异无法相互抵消，反而会给调用方记入余额。
4. 攻击者精确设定 exact-input swaps 的数量，使其跨过这些边界，反复获取正向舍入余数。之后，攻击者提取累积的余额。

攻击前提
- Pool 使用了会在每次 swap 时执行额外数学计算的自定义 v4 hook（例如 LDF/rebalancer）。
- 至少有一条执行路径会在跨越阈值时通过舍入使 swap 发起方受益。
- 能够原子性地重复执行大量 swaps（flash loans 非常适合提供临时资金并分摊 gas 成本）。

## 实用攻击方法

1) 识别候选 pools（带 hooks）
- 枚举 v4 pools 并检查 PoolKey.hooks != address(0)。
- 检查 hook 字节码/ABI，寻找 callbacks：beforeSwap/afterSwap，以及任何自定义重新平衡方法。
- 查找以下数学操作：除以流动性、在 token 数量与流动性之间转换，或以舍入方式聚合 BalanceDelta。

2) 对 hook 的数学逻辑和阈值建模
- 复现 hook 的流动性/再分配公式：输入通常包括 sqrtPriceX96、tickLower/Upper、currentTick、fee tier 和净流动性。
- 绘制阈值/阶跃函数：ticks、bucket 边界或 LDF 断点。确定每个边界两侧的 delta 如何舍入。
- 找出类型在 uint256/int256 之间转换、使用 SafeCast，或依赖隐式向下取整的 mulDiv 的位置。

3) 校准 exact-input swaps 以跨越边界
- 使用 Foundry/Hardhat 模拟，计算刚好使价格跨过边界并触发 hook 分支所需的最小 Δin。
- 验证 afterSwap 结算记入调用方的余额是否超过成本，从而在 hook 的记账中留下正的 BalanceDelta 或余额。
- 重复 swaps 以累积余额，然后调用 hook 的提款/结算路径。

在 v4 中，swap 循环必须通过 PoolManager unlock callback 运行；负的 `amountSpecified` 表示 exact input，且 `sqrtPriceLimitX96` 必须严格位于有效范围内。价格限制为零会导致 revert，因此下方伪代码在 zero-for-one swap 中使用下界。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Foundry 风格测试 harness 示例（伪代码）
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
- 使用 core TickMath 计算目标值：以实际值计算，sqrtP_next = sqrtP_current × 1.0001^(Δtick)；Q64.96 结果由 TickMath 舍入。<sup>[[13]](#references)</sup>
- 使用兼容 Q64.96 的公式近似计算 token0（zero-for-one）输入：Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)。按照 core 例程针对方向的舍入方式进行匹配。<sup>[[12]](#references)</sup>
- 在边界附近将 Δin 调整 ±1 wei，找出 hook 舍入对你有利的分支。

4) 使用闪电贷放大
- 借入大额名义金额（例如 3M USDT 或 2000 WETH），以原子方式运行多次迭代。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 执行校准后的 swap 循环，然后在闪电贷回调中提取并偿还。

Aave V3 闪电贷框架
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
- 如果 hooks 部署在多条链上，应在每条链上重复相同的校准。
- 在 Bunni 事件中，各链上的闪电贷流动性和跨链桥路由各不相同，因此在复现分析时应考虑这些链特定的限制。<sup>[[1]](#references)[[2]](#references)</sup>

## hook 数学计算中的常见根本原因

- 混用舍入语义：mulDiv 向下取整，而后续路径实际上向上取整；或者代币与流动性之间的转换采用了不同的舍入方式。
- Tick 对齐错误：一条路径使用未舍入的 tick，另一条路径则按 tick 间距舍入。
- 在结算期间将 int256 转换为 uint256 时，BalanceDelta 出现符号或溢出问题。
- Q64.96 转换（sqrtPriceX96）中的精度损失未在反向映射中得到对应处理。
- 累积路径：每次 swap 产生的余数被记作调用者可提取的 credit，而不是销毁或保持零和。

## 自定义记账与 delta 放大

- Uniswap v4 的自定义记账允许 hooks 返回 delta，直接调整调用者应付或应收的金额。如果 hook 在内部跟踪 credit，那么在最终结算发生之前，舍入余数可能在多次小额操作中累积。<sup>[[4]](#references)</sup>
- 如果 hook 提供了兼容的提款路径，攻击者可以在同一个 PoolManager unlock callback 中交替执行 `swap → withdraw → swap`，迫使 hook 在余额仍待 unlock 结算时，根据略有不同的状态重新计算 delta。<sup>[[4]](#references)[[10]](#references)</sup>
- 审查 hooks 时，务必追踪 BalanceDelta/HookDelta 的生成和结算过程。某个分支中的一次有偏舍入，就可能在 delta 被反复重新计算时转化为不断累积的 credit。

## 防御指南

- 差分测试：使用高精度有理数运算，将 hook 的数学计算与参考实现进行比对，并断言结果相等，或误差始终有界且对抗性成立（绝不对调用者有利）。
- 不变量/属性测试：
  - swap 路径与 hook 调整中各项 delta（代币、流动性）之和必须在扣除费用后守恒。
  - 在重复执行 exactInput 时，任何路径都不应为 swap 发起者创造正的净 credit。
  - 针对 exactInput/exactOutput，在阈值和 tick 边界附近测试 ±1 wei 的输入。
- 舍入策略：集中管理舍入辅助函数，始终向不利于用户的方向舍入；消除不一致的类型转换和隐式向下取整。
- 结算去向：将不可避免的舍入余数累积到协议金库或销毁；绝不要将其记给 msg.sender。
- 限速/防护措施：为再平衡触发设定最小 swap 金额；如果 delta 小于 1 wei，则禁用再平衡；检查 delta 是否处于预期范围内。
- 全面审查 hook callbacks：beforeSwap/afterSwap 以及流动性变更前后的回调，应对 tick 对齐和 delta 舍入采用一致的规则。

## 案例研究：Bunni V2（2025‑09‑02）

- 协议：Bunni V2，这是一个 Uniswap v4 hook，使用 Liquidity Density Function（LDF）计算代币密度和总流动性估值。<sup>[[1]](#references)[[2]](#references)</sup>
- 受影响的池：Ethereum 上的 USDC/USDT 和 Unichain 上的 weETH/ETH，总金额约为 840 万美元。<sup>[[1]](#references)</sup>
- 步骤 1（推高价格）：攻击者闪电借入约 300 万 USDT 并进行 swap，将 tick 推至约 5000，使**活跃** USDC 余额缩减至约 28 wei。<sup>[[1]](#references)</sup>
- 步骤 2（舍入抽取）：44 次小额提款利用 `BunniHubLogic::withdraw()` 中的向下取整，将活跃 USDC 余额从 28 wei 降至 4 wei（-85.7%），而销毁的 LP 份额仅占极小部分。总流动性下降约 84.4%。<sup>[[1]](#references)[[2]](#references)</sup>
- 步骤 3（流动性反弹夹击）：一次大额 swap 将 tick 移至约 839,189（1 USDC ≈ 2.77e36 USDT）。流动性估值发生反转并增加约 16.8%，从而形成夹击机会：攻击者以被抬高的价格换回资产并获利退出。<sup>[[1]](#references)</sup>
- 事后分析中提出的修复方案：将闲置余额更新改为向上取整，避免重复的小额提款持续压低池中的活跃余额。<sup>[[1]](#references)</sup>

简化后的易受攻击代码行（及事后分析提出的修复方案）。<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Hunting checklist

- Pool 是否使用非零的 hooks 地址？启用了哪些 callbacks？
- 是否存在使用自定义数学逻辑的逐笔 swap 重新分配/再平衡？是否有 tick/阈值逻辑？
- 在哪里使用了除法、mulDiv、Q64.96 转换或 SafeCast？舍入语义是否全局一致？
- 能否构造一个刚好越过边界的 Δin，从而触发有利的舍入分支？测试两个方向，以及 exactInput 和 exactOutput。
- hook 是否跟踪可在之后提取的每个调用者的 credits 或 deltas？确保 residue 被中和。

## References

- [1] [Bunni Exploit 事后分析（2025 年 9 月）](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit：完整攻击分析](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit：流动性漏洞导致 830 万美元被盗（摘要）](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core 白皮书](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 背景介绍（QuillAudits 研究）](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 core 中的流动性机制](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 core 中的 swap 机制](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks 与安全注意事项](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
