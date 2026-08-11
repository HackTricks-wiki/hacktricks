# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 custom hooks를 사용해 core math를 확장하는 Uniswap v4–style DEX를 대상으로 한 DeFi/AMM exploitation 기법을 설명합니다. Bunni V2 incident는 이와 관련된 failure를 보여줍니다. withdrawal accounting의 rounding-direction bug가 active liquidity를 실제보다 적게 계산했고, 이후 swap이 이 과소평가를 수익성 있는 sandwich로 노출했습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

핵심 아이디어는 다음과 같습니다. hook이 fixed-point math, tick rounding, threshold logic에 의존하는 추가 accounting을 구현한 경우, attacker는 특정 threshold를 통과하도록 exact-input swaps를 구성할 수 있습니다. 그러면 rounding discrepancy가 attacker에게 유리한 방향으로 누적됩니다. 이 패턴을 반복한 다음 inflated balance를 withdraw하면 profit을 실현할 수 있으며, flash loan으로 자금을 조달하는 경우가 많습니다.

## Background: Uniswap v4 hooks 및 swap flow

- Hooks는 PoolManager가 특정 lifecycle point에서 호출하는 contracts입니다(예: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools는 hook contract를 포함하는 PoolKey로 initialized됩니다. non-zero hook address는 해당 pool에 대해 선택된 callbacks를 활성화합니다.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks는 **custom deltas**를 반환하여 swap 또는 liquidity action의 최종 balance changes를 변경할 수 있습니다(custom accounting). 이러한 deltas는 call 종료 시 net balances로 settled되므로, hook math 내부의 모든 rounding error는 settlement 전에 누적됩니다.<sup>[[4]](#references)</sup>
- Core math는 sqrtPriceX96에 Q64.96과 같은 fixed-point format을 사용하며, tick arithmetic에는 1.0001^tick을 사용합니다. 그 위에 추가되는 custom math는 invariant drift를 방지하기 위해 rounding semantics를 신중하게 일치시켜야 합니다.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps는 exactInput 또는 exactOutput일 수 있습니다. v3/v4에서 price는 ticks를 따라 이동하며, tick boundary를 crossing하면 range liquidity가 activate/deactivate될 수 있습니다. Hooks는 threshold/tick crossings에 대한 추가 logic를 구현할 수 있습니다.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold-crossing precision/rounding drift

Custom hooks에서 일반적으로 취약한 pattern은 다음과 같습니다.

1. Hook이 integer division, mulDiv 또는 fixed-point conversions를 사용해 swap별 liquidity 또는 balance deltas를 계산합니다(예: sqrtPrice 및 tick ranges를 사용한 token ↔ liquidity 변환).
2. Threshold logic(예: rebalancing, stepwise redistribution 또는 per-range activation)은 swap size 또는 price movement가 내부 boundary를 crossing할 때 trigger됩니다.
3. Forward calculation과 settlement path 사이에 rounding이 일관되지 않게 적용됩니다(예: truncation toward zero, floor와 ceil의 차이). 작은 discrepancy가 상쇄되지 않고 caller에게 credit됩니다.
4. 해당 boundary를 넘도록 정확히 sizing된 exact-input swaps가 positive rounding remainder를 반복적으로 수확합니다. 이후 attacker는 누적된 credit을 withdraw합니다.

Attack preconditions
- 각 swap에서 추가 math를 수행하는 custom v4 hook을 사용하는 pool(예: LDF/rebalancer).
- threshold crossings 전반에서 rounding이 swap initiator에게 유리하게 작용하는 execution path가 하나 이상 존재할 것.
- 많은 swaps를 atomically 반복할 수 있을 것(flash loans는 temporary float를 제공하고 gas를 amortize하는 데 적합합니다).

## Practical attack methodology

1) Hooks가 있는 candidate pools 식별
- v4 pools를 enumerate하고 PoolKey.hooks != address(0)인지 확인합니다.
- Hook bytecode/ABI에서 callbacks를 검사합니다: beforeSwap/afterSwap 및 custom rebalancing methods.
- 다음과 같은 math를 찾습니다: liquidity로 나누거나, token amounts와 liquidity 사이를 변환하거나, BalanceDelta를 rounding과 함께 aggregate하는 로직.

2) Hook의 math 및 thresholds 모델링
- Hook의 liquidity/redistribution formula를 재현합니다. inputs에는 일반적으로 sqrtPriceX96, tickLower/Upper, currentTick, fee tier 및 net liquidity가 포함됩니다.
- Threshold/step functions를 mapping합니다: ticks, bucket boundaries 또는 LDF breakpoints. 각 boundary의 어느 쪽에서 delta가 rounded되는지 확인합니다.
- uint256/int256 사이의 conversions가 발생하는 위치, SafeCast를 사용하는 위치 또는 implicit floor를 사용하는 mulDiv에 의존하는 위치를 식별합니다.

3) Boundaries를 crossing하도록 exact-input swaps calibrate
- Foundry/Hardhat simulations를 사용해 price를 boundary 바로 너머로 이동시키고 hook의 branch를 trigger하는 데 필요한 최소 Δin을 계산합니다.
- afterSwap settlement이 caller에게 cost보다 많은 금액을 credit하여 hook accounting에 positive BalanceDelta 또는 credit을 남기는지 검증합니다.
- Swaps를 반복해 credit을 accumulate한 다음 hook의 withdrawal/settlement path를 호출합니다.

v4에서는 swap loop가 PoolManager unlock callback에서 실행되어야 합니다. negative `amountSpecified`는 exact input을 나타내며, `sqrtPriceLimitX96`은 valid range 내부에 엄격하게 위치해야 합니다. zero price limit은 revert되므로, 아래 pseudocode는 zero-for-one swap에 lower bound를 사용합니다.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
exactInput 보정
- core TickMath를 사용해 목표값을 계산합니다. 실제 값 기준으로 sqrtP_next = sqrtP_current × 1.0001^(Δtick)이며, Q64.96 결과는 TickMath에 의해 반올림됩니다.<sup>[[13]](#references)</sup>
- Q64.96을 고려한 공식을 사용해 token0(zero-for-one) input을 근사합니다. Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). core routine의 방향별 반올림과 일치시킵니다.<sup>[[12]](#references)</sup>
- 경계 주변에서 Δin을 ±1 wei만큼 조정해 hook이 유리하게 반올림하는 branch를 찾습니다.

4) flash loans로 증폭
- 큰 notional(예: 3M USDT 또는 2000 WETH)을 빌려 여러 iteration을 원자적으로 실행합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 보정된 swap loop을 실행한 다음, flash loan callback 내에서 인출하고 상환합니다.

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
5) Exit 및 cross-chain replication
- hooks가 여러 chain에 deploy된 경우, chain별로 동일한 calibration을 반복합니다.
- Bunni incident에서는 chain마다 flash-loan liquidity와 bridge routes가 달랐으므로, analysis를 재현할 때 해당 chain별 제약 조건을 반영해야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## hook math의 일반적인 근본 원인

- 혼합된 rounding semantics: mulDiv는 floor를 적용하지만 이후 경로는 사실상 round up을 적용하거나, token/liquidity 간 conversion에서 서로 다른 rounding을 적용하는 경우.
- Tick alignment 오류: 한 경로에서는 반올림하지 않은 tick을 사용하고, 다른 경로에서는 tick-spaced rounding을 사용하는 경우.
- Settlement 중 int256과 uint256 간 변환 시 BalanceDelta 부호/overflow 문제.
- Q64.96 conversion(sqrtPriceX96)에서 발생한 precision loss가 역방향 mapping에 반영되지 않는 경우.
- Accumulation pathways: swap별 remainder를 credit으로 추적하고, 이를 burn하거나 zero-sum 처리하지 않고 caller가 withdraw할 수 있게 하는 경우.

## Custom accounting 및 delta amplification

- Uniswap v4 custom accounting을 사용하면 hooks가 caller의 지불액/수령액을 직접 조정하는 deltas를 반환할 수 있습니다. hook가 내부적으로 credits를 추적하는 경우, rounding residue가 최종 settlement가 이루어지기 **전에** 여러 소규모 작업에 걸쳐 누적될 수 있습니다.<sup>[[4]](#references)</sup>
- hook가 호환 가능한 withdrawal path를 노출하는 경우, attacker는 동일한 PoolManager unlock callback 내에서 `swap → withdraw → swap`을 반복하여, unlock이 settle될 때까지 balances가 pending 상태로 유지되는 동안 hook가 조금씩 다른 state에서 deltas를 다시 계산하도록 만들 수 있습니다.<sup>[[4]](#references)[[10]](#references)</sup>
- hooks를 검토할 때는 BalanceDelta/HookDelta가 어떻게 생성되고 settled되는지 항상 추적해야 합니다. 한 branch에서 발생한 단일 biased rounding이 deltas가 반복적으로 다시 계산될 때 누적되는 credit으로 변할 수 있습니다.

## Defensive guidance

- Differential testing: high-precision rational arithmetic를 사용하는 reference implementation과 hook의 math를 대조하고, 항상 adversarial하도록(절대 caller에게 유리하지 않도록) equality 또는 bounded error를 assert합니다.
- Invariant/property tests:
- swap paths와 hook adjustments 전반의 deltas(tokens, liquidity) 합계는 fees를 제외하면 value를 보존해야 합니다.
- 반복되는 exactInput iterations 동안 어떤 path도 swap initiator에게 positive net credit을 생성해서는 안 됩니다.
- exactInput/exactOutput 모두에 대해 ±1 wei input 주변의 threshold/tick boundary tests.
- Rounding policy: 항상 user에게 불리하게 round하는 rounding helpers를 중앙화하고, 일관되지 않은 casts와 implicit floors를 제거합니다.
- Settlement sinks: 피할 수 없는 rounding residue는 protocol treasury에 누적하거나 burn해야 하며, 절대 msg.sender에게 귀속해서는 안 됩니다.
- Rate-limits/guardrails: rebalancing triggers에 minimum swap sizes 적용; deltas가 sub-wei인 경우 rebalances 비활성화; 예상 범위와 비교하여 deltas의 sanity-check 수행.
- hook callbacks를 전체적으로 검토합니다. beforeSwap/afterSwap 및 before/after liquidity changes는 tick alignment와 delta rounding에 대해 일관된 동작을 보여야 합니다.

## Case study: Bunni V2 (2025-09-02)

- Protocol: Bunni V2. Liquidity Density Function (LDF)를 사용하는 Uniswap v4 hook으로, token density 및 total-liquidity estimates를 계산합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- Affected pools: Ethereum의 USDC/USDT 및 Unichain의 weETH/ETH로, 총 규모는 약 $8.4M입니다.<sup>[[1]](#references)</sup>
- Step 1 (price push): attacker는 약 3M USDT를 flash-borrow한 뒤 swap하여 tick을 약 5000까지 밀어 올렸고, **active** USDC balance를 약 28 wei로 줄였습니다.<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44회의 tiny withdrawals가 `BunniHubLogic::withdraw()`의 floor rounding을 악용하여 active USDC balance를 28 wei에서 4 wei로(-85.7%) 줄였으며, LP shares는 극히 일부만 burn되었습니다. Total liquidity는 약 84.4% 감소했습니다.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): 대규모 swap으로 tick이 약 839,189까지 이동했습니다(1 USDC ≈ 2.77e36 USDT). Liquidity estimates가 반전되며 약 16.8% 증가했고, attacker는 부풀려진 가격으로 swap back한 뒤 profit을 남기고 exit하는 sandwich가 가능해졌습니다.<sup>[[1]](#references)</sup>
- Post-mortem에서 확인된 fix: idle-balance update를 **round up**하도록 변경하여, 반복되는 micro-withdrawals가 더 이상 pool의 active balance를 지속적으로 낮추지 못하게 합니다.<sup>[[1]](#references)</sup>

취약한 line의 간소화 버전(및 post-mortem fix).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- Pool이 non-zero hooks address를 사용하는가? 어떤 callbacks가 활성화되어 있는가?
- custom math를 사용하는 per-swap redistribution/rebalance가 있는가? tick/threshold 로직이 있는가?
- divisions/mulDiv, Q64.96 conversions 또는 SafeCast가 사용되는 곳은 어디인가? rounding semantics가 전역적으로 일관적인가?
- 경계를 간신히 넘고 유리한 rounding branch를 유도하는 Δin을 구성할 수 있는가? 양방향과 exactInput 및 exactOutput을 모두 테스트하라.
- hook이 caller별 credits 또는 나중에 인출할 수 있는 deltas를 추적하는가? residue가 neutralized되는지 확인하라.

## References

- [1] [Bunni Exploit 사후 분석 (2025년 9월)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: 전체 Hack 분석](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: Liquidity 결함으로 $8.3M Drain (요약)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 배경 (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 core의 Liquidity mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 core의 Swap mechanics](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks 및 Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
