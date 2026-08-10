# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

이 페이지는 custom hooks를 사용해 core math를 확장하는 Uniswap v4–style DEX를 대상으로 한 DeFi/AMM exploitation 기법을 설명합니다. Bunni V2 incident는 이와 관련된 failure를 보여줍니다. withdrawal accounting의 rounding-direction bug로 active liquidity가 실제보다 적게 계산되었고, 이후 swap을 통해 이 과소평가가 수익성 있는 sandwich로 악용되었습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

핵심 아이디어는 다음과 같습니다. hook이 fixed‑point math, tick rounding, threshold logic에 의존하는 추가 accounting을 구현하는 경우, attacker는 특정 threshold를 넘도록 exact‑input swaps를 정밀하게 구성할 수 있습니다. 이를 통해 rounding discrepancy가 attacker에게 유리한 방향으로 누적됩니다. 이 패턴을 반복한 다음 증가한 balance를 withdraw하면 profit을 실현할 수 있으며, flash loan으로 자금을 조달하는 경우가 많습니다.

## Background: Uniswap v4 hooks and swap flow

- Hooks는 PoolManager가 특정 lifecycle point에서 호출하는 contracts입니다(예: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools는 hook contract를 포함하는 PoolKey로 initialized됩니다. 0이 아닌 hook address는 해당 pool에 대해 선택된 callbacks를 활성화합니다.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks는 **custom deltas**를 반환하여 swap 또는 liquidity action의 최종 balance changes를 수정할 수 있습니다(custom accounting). 이러한 deltas는 call 종료 시 net balances로 settled되므로, hook math 내부의 rounding error는 settlement 전에 누적됩니다.<sup>[[4]](#references)</sup>
- Core math는 sqrtPriceX96에 Q64.96과 같은 fixed-point formats를 사용하며, tick arithmetic에는 1.0001^tick이 사용됩니다. 그 위에 추가되는 custom math는 invariant drift를 방지하기 위해 rounding semantics를 신중하게 일치시켜야 합니다.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps는 exactInput 또는 exactOutput일 수 있습니다. v3/v4에서는 price가 ticks를 따라 이동하며, tick boundary를 crossing하면 range liquidity가 activate/deactivate될 수 있습니다. Hooks는 threshold/tick crossing에 대한 추가 logic을 구현할 수 있습니다.<sup>[[9]](#references)[[11]](#references)</sup>

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Custom hooks에서 일반적으로 취약한 pattern은 다음과 같습니다.

1. Hook은 integer division, mulDiv 또는 fixed-point conversions를 사용해 swap마다 liquidity 또는 balance deltas를 계산합니다(예: sqrtPrice와 tick ranges를 사용한 token ↔ liquidity 변환).
2. Threshold logic(예: rebalancing, stepwise redistribution 또는 per-range activation)은 swap size 또는 price movement가 내부 boundary를 crossing할 때 trigger됩니다.
3. Forward calculation과 settlement path 사이에서 rounding이 일관되지 않게 적용됩니다(예: truncation toward zero, floor와 ceil의 차이). 작은 discrepancy가 상쇄되지 않고 caller에게 credit됩니다.
4. 해당 boundary를 넘도록 정밀하게 size를 조정한 exact‑input swaps가 positive rounding remainder를 반복적으로 수확합니다. 이후 attacker는 누적된 credit을 withdraw합니다.

Attack preconditions
- 각 swap에서 추가 math를 수행하는 custom v4 hook을 사용하는 pool(예: LDF/rebalancer).
- Threshold crossings 전반에서 rounding이 swap initiator에게 유리하게 작용하는 execution path가 최소 하나 존재해야 합니다.
- 많은 swaps를 atomically 반복할 수 있어야 합니다(flash loans는 임시 float를 공급하고 gas를 amortize하는 데 적합합니다).

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pools를 enumerate하고 PoolKey.hooks != address(0)인지 확인합니다.
- Hook bytecode/ABI를 검사하여 callbacks인 beforeSwap/afterSwap 및 custom rebalancing methods를 확인합니다.
- 다음과 같은 math를 찾습니다: liquidity로 나누기, token amounts와 liquidity 간 변환 또는 rounding을 적용한 BalanceDelta 집계.

2) Model the hook’s math and thresholds
- Hook의 liquidity/redistribution formula를 재현합니다. Inputs에는 일반적으로 sqrtPriceX96, tickLower/Upper, currentTick, fee tier 및 net liquidity가 포함됩니다.
- Threshold/step functions를 map합니다: ticks, bucket boundaries 또는 LDF breakpoints. 각 boundary의 어느 쪽에서 delta가 rounding되는지 확인합니다.
- uint256/int256 간 변환을 위해 cast하는 지점, SafeCast를 사용하는 지점 또는 implicit floor가 적용되는 mulDiv에 의존하는 지점을 식별합니다.

3) Calibrate exact‑input swaps to cross boundaries
- Foundry/Hardhat simulations를 사용하여 price를 boundary 바로 너머로 이동시키고 hook의 branch를 trigger하는 데 필요한 최소 Δin을 계산합니다.
- afterSwap settlement이 caller에게 cost보다 많은 금액을 credit하여 hook accounting에 positive BalanceDelta 또는 credit을 남기는지 확인합니다.
- Swaps를 반복하여 credit을 누적한 다음 hook의 withdrawal/settlement path를 호출합니다.

v4에서는 swap loop가 PoolManager unlock callback에서 실행되어야 합니다. 음수 `amountSpecified`는 exact input을 의미하며, `sqrtPriceLimitX96`은 valid range 내부에 엄격히 위치해야 합니다. Price limit이 0이면 revert되므로, 아래 pseudocode는 zero-for-one swap에 lower bound를 사용합니다.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Example Foundry‑style test harness (pseudocode)
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
- core TickMath를 사용해 목표를 계산합니다. 실제 값 기준으로 `sqrtP_next = sqrtP_current × 1.0001^(Δtick)`이며, Q64.96 결과는 TickMath에 의해 반올림됩니다.<sup>[[13]](#references)</sup>
- Q64.96을 고려한 공식으로 token0 (zero-for-one) 입력을 근사합니다. `Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current)`. core routine의 방향별 반올림과 일치시킵니다.<sup>[[12]](#references)</sup>
- 경계 주변에서 `Δin`을 ±1 wei씩 조정해 hook이 유리하게 반올림하는 branch를 찾습니다.

4) flash loans로 증폭
- 큰 notional(예: 3M USDT 또는 2000 WETH)을 빌려 여러 iteration을 원자적으로 실행합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 보정된 swap loop를 실행한 다음, flash loan callback 내에서 인출하고 상환합니다.

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
5) 종료 및 cross-chain 복제
- 여러 chain에 hooks가 배포되어 있다면 chain별로 동일한 calibration을 반복합니다.
- Bunni incident에서는 flash-loan liquidity와 bridge routes가 chain마다 달랐으므로, 분석을 재현할 때 해당 chain별 제약 조건을 반영해야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## hook math의 일반적인 근본 원인

- 혼합된 rounding semantics: mulDiv는 내림하지만 이후 경로에서는 사실상 올림이 적용되거나, token/liquidity 간 변환에서 서로 다른 rounding이 적용되는 경우.
- Tick 정렬 오류: 한 경로에서는 반올림되지 않은 tick을 사용하고 다른 경로에서는 tick 간격에 맞춰 rounding하는 경우.
- 정산 중 int256과 uint256 간 변환 시 BalanceDelta의 부호/overflow 문제.
- Q64.96 변환(sqrtPriceX96)에서 precision이 손실되고 역매핑에서는 이를 동일하게 반영하지 않는 경우.
- Accumulation 경로: swap별 잔여분을 caller가 인출할 수 있는 credit으로 추적하고, 이를 소각하거나 zero-sum 처리하지 않는 경우.

## Custom accounting 및 delta amplification

- Uniswap v4의 custom accounting을 사용하면 hooks가 deltas를 반환하여 caller가 지불하거나 수령할 금액을 직접 조정할 수 있습니다. hook가 내부적으로 credits를 추적하는 경우, 최종 settlement가 이루어지기 **전에** 여러 번의 소규모 작업을 거치며 rounding 잔여분이 누적될 수 있습니다.<sup>[[4]](#references)</sup>
- hook가 호환 가능한 withdrawal 경로를 노출하는 경우, attacker는 동일한 PoolManager unlock callback 내에서 `swap → withdraw → swap`을 반복하여, unlock이 settlement를 완료할 때까지 balances가 pending 상태로 유지되는 동안 hook가 약간 다른 state에서 deltas를 다시 계산하도록 만들 수 있습니다.<sup>[[4]](#references)[[10]](#references)</sup>
- hooks를 검토할 때는 BalanceDelta/HookDelta가 어떻게 생성되고 settled되는지 항상 추적해야 합니다. 한 branch에 존재하는 단일 biased rounding이 deltas를 반복해서 재계산할 때 누적되는 credit으로 변할 수 있습니다.

## 방어 지침

- Differential testing: high-precision rational arithmetic을 사용하는 reference implementation과 hook의 math를 대조하고, 항상 adversarial한(절대로 caller에게 유리하지 않은) equality 또는 bounded error를 검증합니다.
- Invariant/property tests:
- swap 경로와 hook 조정 전반의 deltas 합계(tokens, liquidity)는 fees를 제외하면 value를 보존해야 합니다.
- 반복적인 exactInput iteration에서 어떤 경로도 swap initiator에게 positive net credit을 생성해서는 안 됩니다.
- exactInput/exactOutput 모두에 대해 ±1 wei input 주변의 threshold/tick boundary를 테스트합니다.
- Rounding policy: 항상 user에게 불리하게 round하는 rounding helper를 중앙화하고, 일관되지 않은 casts와 implicit floors를 제거합니다.
- Settlement sinks: 피할 수 없는 rounding 잔여분은 protocol treasury에 누적하거나 소각하고, 절대로 msg.sender에게 귀속하지 않습니다.
- Rate-limits/guardrails: rebalancing trigger에 minimum swap size를 적용하고, deltas가 sub-wei인 경우 rebalances를 비활성화하며, deltas가 예상 범위를 벗어나지 않는지 sanity-check합니다.
- Hook callbacks를 종합적으로 검토합니다. beforeSwap/afterSwap과 before/after liquidity changes는 tick alignment와 delta rounding에 대해 일치해야 합니다.

## Case study: Bunni V2 (2025-09-02)

- Protocol: Bunni V2. Liquidity Density Function (LDF)를 사용하는 Uniswap v4 hook으로, token density와 total-liquidity estimates를 계산합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- Affected pools: Ethereum의 USDC/USDT와 Unichain의 weETH/ETH로, 총 규모는 약 $8.4M입니다.<sup>[[1]](#references)</sup>
- Step 1 (price push): attacker는 약 3M USDT를 flash-borrow한 뒤 swap하여 tick을 약 5000까지 밀어 올렸고, **active** USDC balance를 약 28 wei까지 감소시켰습니다.<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44회의 소규모 withdrawal이 `BunniHubLogic::withdraw()`의 floor rounding을 악용하여 active USDC balance를 28 wei에서 4 wei로(-85.7%) 줄이는 동안, LP shares는 극히 일부만 burn되었습니다. Total liquidity는 약 84.4% 감소했습니다.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): 대규모 swap으로 tick이 약 839,189까지 이동했습니다(1 USDC ≈ 2.77e36 USDT). Liquidity estimates가 반전되며 약 16.8% 증가했고, attacker는 inflated price에서 다시 swap하여 수익을 얻고 빠져나가는 sandwich를 실행할 수 있었습니다.<sup>[[1]](#references)</sup>
- Post-mortem에서 확인된 fix: idle-balance update를 **올림**하도록 변경하여, 반복적인 micro-withdrawal이 pool의 active balance를 더 이상 단계적으로 낮추지 못하게 합니다.<sup>[[1]](#references)</sup>

취약한 line의 단순화된 형태(및 post-mortem fix).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting 체크리스트

- 풀이 0이 아닌 hooks address를 사용하는가? 어떤 callbacks가 활성화되어 있는가?
- 스왑마다 custom math를 사용하는 재분배/재밸런싱이 있는가? tick/threshold 로직이 있는가?
- divisions/mulDiv, Q64.96 conversions 또는 SafeCast는 어디에서 사용되는가? rounding semantics가 전체적으로 일관적인가?
- 경계를 간신히 넘으면서 유리한 rounding branch를 유도하는 Δin을 구성할 수 있는가? 양방향과 exactInput 및 exactOutput을 모두 테스트하라.
- hook이 caller별 credits 또는 나중에 withdraw할 수 있는 deltas를 추적하는가? residue가 중화되는지 확인하라.

## References

- [1] [Bunni Exploit 사후 분석 (2025년 9월)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: 전체 Hack 분석](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: Liquidity Flaw를 통한 $8.3M Drain (요약)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
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
