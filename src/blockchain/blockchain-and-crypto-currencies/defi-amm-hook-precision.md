# DeFi/AMM Exploit：Uniswap v4 Hook 精度/舍入滥用

{{#include ../../banners/hacktricks-training.md}}

本页介绍针对 Uniswap v4 风格 DEX 的一类 DeFi/AMM exploit 技术：这类 DEX 通过自定义 hooks 扩展核心数学逻辑。Bunni V2 事件展示了相关故障：提取资产的账目计算中出现舍入方向错误，导致活跃流动性被低估；之后的一次 swap 暴露了这一低估，并在一次有利可图的 sandwich 中被利用。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

核心思路：如果 hook 实现的额外账目计算依赖定点数学、tick 舍入和阈值逻辑，攻击者就可以构造精确输入 swap，使其跨越特定阈值，从而让舍入差异累积并使自己获利。重复此模式，随后提取虚增的余额即可兑现利润，通常会使用 flash loan 提供资金。

## 背景：Uniswap v4 hooks 与 swap 流程

- Hooks 是 PoolManager 在特定生命周期节点调用的合约（例如 beforeSwap/afterSwap、beforeAddLiquidity/afterAddLiquidity、beforeRemoveLiquidity/afterRemoveLiquidity、beforeInitialize/afterInitialize、beforeDonate/afterDonate）。<sup>[[4]](#references)</sup>
- Pool 初始化时会使用包含 hook 合约的 PoolKey。非零 hook 地址会启用该 pool 所选的回调。<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks 可以返回**自定义 delta**，用于修改 swap 或流动性操作最终产生的余额变化（自定义记账）。这些 delta 会在调用结束时按净余额结算，因此 hook 数学逻辑中的任何舍入误差都会在结算前累积。<sup>[[4]](#references)</sup>
- 核心数学逻辑使用 Q64.96 等定点格式表示 sqrtPriceX96，并使用基于 1.0001^tick 的 tick 算术。任何叠加在其上的自定义数学逻辑都必须谨慎匹配舍入语义，以避免不变量漂移。<sup>[[12]](#references)[[13]](#references)</sup>
- Swap 可以是 exactInput 或 exactOutput。在 v3/v4 中，价格会沿着 ticks 移动；跨越 tick 边界可能会激活/停用区间流动性。Hooks 可能会在跨越阈值/tick 时执行额外逻辑。<sup>[[9]](#references)[[11]](#references)</sup>

## 漏洞模式：跨越阈值时的精度/舍入漂移

自定义 hooks 中一种常见的易受攻击模式：

1. Hook 使用整数除法、mulDiv 或定点转换（例如使用 sqrtPrice 和 tick 区间进行 token 与流动性的转换）来计算每次 swap 的流动性或余额 delta。
2. 阈值逻辑（例如重新平衡、分步重新分配或按区间激活）会在 swap 数量或价格变动跨越内部边界时触发。
3. 前向计算路径与结算路径中的舍入方式不一致（例如向零截断，或 floor 与 ceil 不一致）。微小差异不会相互抵消，反而会为调用者记入余额。
4. 攻击者将 exact-input swap 精确设置为跨越这些边界，反复收割正向舍入余数。之后再提取累积的信用额。

攻击前提
- Pool 使用了会在每次 swap 时执行额外数学计算的自定义 v4 hook（例如 LDF/rebalancer）。
- 至少有一条执行路径会在跨越阈值时通过舍入使 swap 发起方获利。
- 能够原子化地重复执行许多次 swap（flash loan 非常适合提供临时资金并分摊 gas）。

## 实际攻击方法

1) 识别候选 pools 和 hooks
- 枚举 v4 pools，并检查 PoolKey.hooks != address(0)。
- 检查 hook 字节码/ABI，确认其回调：beforeSwap/afterSwap 以及任何自定义重新平衡方法。
- 查找以下数学运算：除以流动性、在 token 数量与流动性之间转换，或对 BalanceDelta 进行舍入聚合。

2) 建模 hook 的数学逻辑和阈值
- 重现 hook 的流动性/重新分配公式：输入通常包括 sqrtPriceX96、tickLower/Upper、currentTick、手续费等级和净流动性。
- 绘制阈值/阶梯函数：ticks、bucket 边界或 LDF 断点。确定 delta 在边界的哪一侧进行舍入。
- 找出 uint256/int256 之间的转换、SafeCast 的使用位置，以及依赖隐式 floor 的 mulDiv 调用。

3) 校准用于跨越边界的 exact-input swap
- 使用 Foundry/Hardhat 模拟，计算使价格刚好跨越边界并触发 hook 分支所需的最小 Δin。
- 验证 afterSwap 结算是否给调用者记入了超出成本的金额，从而在 hook 账目中留下正的 BalanceDelta 或信用额。
- 重复 swap 以累积信用额，然后调用 hook 的提取/结算路径。

在 v4 中，swap 循环必须从 PoolManager unlock 回调中运行；负的 `amountSpecified` 表示 exact input，且 `sqrtPriceLimitX96` 必须严格处于有效范围内。价格限制为零会导致 revert，因此下面的伪代码在 zero-for-one swap 中使用下界。<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Foundry 风格的测试 harness 示例（伪代码）
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
- 使用 core TickMath 计算目标值：sqrtP_next = sqrtP_current × 1.0001^(Δtick)，这里按实际值计算；Q64.96 结果会由 TickMath 舍入。<sup>[[13]](#references)</sup>
- 使用兼容 Q64.96 的公式近似计算 token0（zero-for-one）输入：Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)。按照 core 例程针对方向的舍入方式进行匹配。<sup>[[12]](#references)</sup>
- 在边界附近将 Δin 调整 ±1 wei，找到 hook 会按有利于你的方向舍入的分支。

4) 使用 flash loan 放大
- 借入大量名义金额（例如 3M USDT 或 2000 WETH），以原子方式执行多次迭代。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 执行校准后的 swap 循环，然后在 flash loan 回调中提取并还款。

Aave V3 flash loan 框架
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
- 在 Bunni 事件中，各链上的闪电贷流动性和跨链桥路由各不相同，因此复现分析时要考虑这些链特有的限制。<sup>[[1]](#references)[[2]](#references)</sup>

## hook 数学计算中的常见根本原因

- 舍入语义混杂：mulDiv 向下取整，而后续路径实际上向上取整；或代币与流动性之间的转换采用不同的舍入方式。
- Tick 对齐错误：一条路径使用未舍入的 tick，另一条路径则按 tick 间距舍入。
- 在结算过程中将 BalanceDelta 从 int256 转换为 uint256 时出现符号/溢出问题。
- Q64.96 转换（sqrtPriceX96）中的精度损失，在反向映射中没有得到对应处理。
- 累积路径：每次 swap 的余数被记为可由调用者提取的额度，而不是被销毁或保持零和。

## 自定义会计与 delta 放大

- Uniswap v4 自定义会计允许 hooks 返回 delta，直接调整调用者应付/应收的金额。如果 hook 在内部追踪额度，那么在最终结算发生之前，舍入余数可能会在多次小额操作中累积。<sup>[[4]](#references)</sup>
- 如果 hook 提供兼容的提取路径，攻击者可以在同一个 PoolManager unlock callback 中交替执行 `swap → withdraw → swap`，迫使 hook 在余额仍待 unlock 结算期间，根据略有不同的状态重新计算 delta。<sup>[[4]](#references)[[10]](#references)</sup>
- 审查 hooks 时，务必追踪 BalanceDelta/HookDelta 的生成和结算过程。某个分支中的一次舍入偏差，就可能在反复重新计算 delta 后变成不断累积的额度。

## 防御指南

- 差分测试：使用高精度有理数运算，将 hook 的数学计算与参考实现进行比较，并断言结果相等，或误差始终有界且对抗性（绝不有利于调用者）。
- 不变量/属性测试：
  - swap 路径和 hook 调整中的 delta 总和（代币、流动性）必须守恒，手续费除外。
  - 对 swap 发起者反复执行 exactInput，不应在任何路径中产生正的净额度。
  - 针对 exactInput/exactOutput，测试 ±1 wei 输入附近的阈值/tick 边界。
- 舍入策略：集中管理舍入辅助函数，始终对用户不利地舍入；消除不一致的类型转换和隐式向下取整。
- 结算去向：将无法避免的舍入余数累积到协议金库或销毁；绝不要归属给 msg.sender。
- 速率限制/防护措施：为再平衡触发设置最小 swap 金额；如果 delta 小于 1 wei，则禁用再平衡；根据预期范围检查 delta 是否合理。
- 整体审查 hook 回调：beforeSwap/afterSwap 和流动性变更前后回调应在 tick 对齐和 delta 舍入上保持一致。

## 案例研究：Bunni V2 (2025‑09‑02)

- 协议：Bunni V2，一个使用流动性密度函数（LDF）计算代币密度和总流动性估算值的 Uniswap v4 hook。<sup>[[1]](#references)[[2]](#references)</sup>
- 受影响的池：Ethereum 上的 USDC/USDT 和 Unichain 上的 weETH/ETH，总计约 840 万美元。<sup>[[1]](#references)</sup>
- 步骤 1（推高价格）：攻击者闪电借入约 300 万 USDT 并进行 swap，将 tick 推至约 5000，使**活跃** USDC 余额缩减至约 28 wei。<sup>[[1]](#references)</sup>
- 步骤 2（舍入抽取）：44 次小额提取利用 `BunniHubLogic::withdraw()` 中的向下取整，将活跃 USDC 余额从 28 wei 降至 4 wei（-85.7%），而销毁的 LP 份额仅占极小比例。总流动性减少约 84.4%。<sup>[[1]](#references)[[2]](#references)</sup>
- 步骤 3（流动性反弹夹击）：一次大额 swap 将 tick 移至约 839,189（1 USDC ≈ 2.77e36 USDT）。流动性估算值发生反转并增加约 16.8%，从而形成夹击：攻击者以虚高价格 swap 回来并获利退出。<sup>[[1]](#references)</sup>
- 事后分析中指出的修复方案：将闲置余额更新改为向上取整，避免反复进行微额提取时持续压低池的活跃余额。<sup>[[1]](#references)</sup>

简化后的易受攻击代码行（及事后分析中提出的修复方案）。<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Hunting 清单

- 池是否使用非零 hooks 地址？启用了哪些 callbacks？
- 是否存在使用自定义数学逻辑的逐次 swap 重新分配/再平衡？是否有 tick/阈值逻辑？
- 在哪里使用了除法、mulDiv、Q64.96 转换或 SafeCast？舍入语义是否全局一致？
- 能否构造一个 Δin，使其刚好跨过边界并触发有利的舍入分支？测试两个方向，以及 exactInput 和 exactOutput。
- hook 是否跟踪可在之后提取的逐调用方额度或差值？确保将残余部分归零。

## References

- [1] [Bunni 漏洞利用事件事后分析（2025 年 9 月）](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 漏洞利用：完整攻击分析](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 漏洞利用：流动性缺陷导致 830 万美元被盗（摘要）](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 核心白皮书](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 背景介绍（QuillAudits 研究）](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 核心中的流动性机制](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 核心中的 swap 机制](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks 与安全注意事项](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 核心 Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 核心 PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 核心 SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 核心 TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
