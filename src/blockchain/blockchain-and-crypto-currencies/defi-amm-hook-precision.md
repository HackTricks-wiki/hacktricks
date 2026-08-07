# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 custom hooks를 사용해 core math를 확장하는 Uniswap v4–style DEX를 대상으로 한 DeFi/AMM exploitation 기법을 다룹니다. 최근 Bunni V2 incident에서는 각 swap마다 실행되는 Liquidity Distribution Function (LDF)의 rounding/precision flaw를 악용하여 attacker가 positive credits를 축적하고 liquidity를 drain할 수 있었습니다.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

핵심 아이디어는 다음과 같습니다. hook이 fixed‑point math, tick rounding, threshold logic에 의존하는 추가 accounting을 구현하는 경우, attacker는 특정 threshold를 통과하도록 exact‑input swaps를 구성할 수 있습니다. 이때 rounding discrepancy가 attacker에게 유리한 방향으로 누적됩니다. 이 패턴을 반복한 다음 inflated balance를 withdraw하면 profit을 실현할 수 있으며, 일반적으로 flash loan으로 자금을 조달합니다.

## Background: Uniswap v4 hooks and swap flow

- Hooks는 PoolManager가 특정 lifecycle point(예: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)에서 호출하는 contracts입니다.<sup>[[3]](#references)[[6]](#references)</sup>
- Pools는 hooks address를 포함하는 PoolKey로 initialize됩니다. 0이 아닌 경우 PoolManager는 관련 operation마다 callbacks를 수행합니다.<sup>[[6]](#references)</sup>
- Hooks는 swap 또는 liquidity action의 최종 balance changes를 수정하는 **custom deltas**를 반환할 수 있습니다(custom accounting). 이러한 deltas는 call 종료 시 net balances로 settle되므로, settlement 전에 hook math 내부의 rounding error가 누적될 수 있습니다.<sup>[[5]](#references)</sup>
- Core math는 sqrtPriceX96에 Q64.96과 같은 fixed‑point format을 사용하며, tick arithmetic에는 1.0001^tick을 사용합니다. 그 위에 추가되는 custom math는 invariant drift를 방지하기 위해 rounding semantics를 정확히 일치시켜야 합니다.<sup>[[4]](#references)[[8]](#references)</sup>
- Swaps는 exactInput 또는 exactOutput일 수 있습니다. v3/v4에서는 price가 ticks를 따라 이동하며, tick boundary를 통과하면 range liquidity가 activate/deactivate될 수 있습니다. Hooks는 threshold/tick crossing 시 추가 logic을 구현할 수 있습니다.<sup>[[5]](#references)</sup>

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Custom hooks에서 일반적으로 취약한 pattern은 다음과 같습니다.

1. Hook이 integer division, mulDiv 또는 fixed‑point conversion을 사용하여 swap별 liquidity 또는 balance deltas를 계산합니다(예: sqrtPrice 및 tick ranges를 사용한 token ↔ liquidity 변환).
2. Threshold logic(예: rebalancing, stepwise redistribution 또는 per‑range activation)은 swap size 또는 price movement가 내부 boundary를 통과할 때 trigger됩니다.
3. Forward calculation과 settlement path 사이에서 rounding이 일관되지 않게 적용됩니다(예: zero 방향 truncation, floor와 ceil의 불일치). 작은 discrepancy가 상쇄되지 않고 caller에게 credit됩니다.
4. 해당 boundary를 걸치도록 정확히 sizing된 exact‑input swaps가 positive rounding remainder를 반복적으로 harvest합니다. 이후 attacker는 축적된 credit을 withdraw합니다.

Attack preconditions
- 각 swap에서 추가 math를 수행하는 custom v4 hook을 사용하는 pool(예: LDF/rebalancer).
- Threshold crossing 과정에서 rounding이 swap initiator에게 유리하게 작용하는 execution path가 하나 이상 존재해야 합니다.
- 많은 swaps를 atomically 반복할 수 있어야 합니다(flash loan은 temporary float를 제공하고 gas를 amortize하는 데 적합합니다).

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pools를 enumerate하고 PoolKey.hooks != address(0)인지 확인합니다.
- Hook bytecode/ABI를 inspect하여 callbacks인 beforeSwap/afterSwap 및 custom rebalancing methods를 확인합니다.
- 다음과 같은 math를 찾습니다: liquidity로 나누기, token amounts와 liquidity 간 변환 또는 rounding을 적용한 BalanceDelta aggregation.

2) Model the hook’s math and thresholds
- Hook의 liquidity/redistribution formula를 재현합니다. 일반적인 inputs에는 sqrtPriceX96, tickLower/Upper, currentTick, fee tier 및 net liquidity가 포함됩니다.
- Threshold/step functions를 map합니다: ticks, bucket boundaries 또는 LDF breakpoints. 각 boundary의 어느 쪽에서 delta가 rounding되는지 확인합니다.
- uint256/int256 간 conversion을 수행하거나, SafeCast를 사용하거나, implicit floor가 적용된 mulDiv에 의존하는 지점을 식별합니다.

3) Calibrate exact‑input swaps to cross boundaries
- Foundry/Hardhat simulations를 사용하여 price를 boundary 바로 너머로 이동시키고 hook의 branch를 trigger하는 데 필요한 최소 Δin을 계산합니다.
- afterSwap settlement이 caller에게 cost보다 많은 금액을 credit하여 positive BalanceDelta 또는 hook accounting상의 credit을 남기는지 검증합니다.
- Credit이 누적될 때까지 swaps를 반복한 다음 hook의 withdrawal/settlement path를 호출합니다.

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
- tick step에 대한 ΔsqrtP 계산: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- v3/v4 formulas를 사용해 Δin 근사: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). rounding 방향이 core math와 일치하는지 확인합니다.
- 경계 주변에서 Δin을 ±1 wei씩 조정하여 hook이 공격자에게 유리하게 rounding하는 branch를 찾습니다.

4) flash loans로 증폭
- 큰 notional(예: 3M USDT 또는 2000 WETH)을 borrow하여 여러 iteration을 atomic하게 실행합니다.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- calibrated swap loop를 실행한 다음, flash loan callback 내에서 withdraw하고 repay합니다.

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
- hooks가 여러 chain에 배포되어 있다면, 각 chain에서 동일한 calibration을 반복합니다.
- proceeds를 target chain으로 다시 Bridge하고, 선택적으로 lending protocols를 통해 cycle하여 flows를 obfuscate합니다.<sup>[[2]](#references)</sup>

## hook math의 일반적인 root cause

- Mixed rounding semantics: mulDiv는 floor하지만 이후 경로에서는 사실상 round up하거나, token/liquidity 간 conversion에 서로 다른 rounding을 적용하는 경우.
- Tick alignment errors: 한 경로에서는 round되지 않은 tick을 사용하고, 다른 경로에서는 tick-spaced rounding을 사용하는 경우.
- Settlement 중 int256과 uint256 간 conversion 시 BalanceDelta의 sign/overflow 문제.
- Q64.96 conversion(sqrtPriceX96)에서 발생한 precision loss가 reverse mapping에서 동일하게 반영되지 않는 경우.
- Accumulation pathways: per-swap remainder가 caller가 withdraw할 수 있는 credit로 추적되고, burn되거나 zero-sum 처리되지 않는 경우.

## Custom accounting 및 delta amplification

- Uniswap v4 custom accounting을 사용하면 hooks가 caller가 지불하거나 수령해야 하는 금액을 직접 조정하는 deltas를 반환할 수 있습니다. hook가 내부적으로 credits를 추적하는 경우, 최종 settlement가 실행되기 **전에** 여러 소규모 operation에 걸쳐 rounding residue가 누적될 수 있습니다.<sup>[[5]](#references)</sup>
- 이로 인해 boundary/threshold abuse가 더욱 강력해집니다. attacker는 동일한 tx에서 `swap → withdraw → swap`을 반복하여, 모든 balance가 여전히 pending인 상태에서 hook가 약간씩 다른 state를 기준으로 deltas를 다시 계산하도록 만들 수 있습니다.
- hooks를 review할 때는 BalanceDelta/HookDelta가 어떻게 생성되고 settled되는지 항상 추적해야 합니다. 한 branch의 단일 biased rounding이 deltas가 반복적으로 재계산될 때 compounding credit으로 변할 수 있습니다.

## Defensive guidance

- Differential testing: high-precision rational arithmetic를 사용하는 reference implementation과 hook의 math를 대조하고, equality 또는 항상 adversarial한 bounded error를 assert합니다. 즉, caller에게 유리한 결과가 나와서는 안 됩니다.
- Invariant/property tests:
- swap paths와 hook adjustments 전체에서 deltas(tokens, liquidity)의 합은 fees를 제외하면 value를 보존해야 합니다.
- 반복적인 exactInput iteration에서 어떤 path도 swap initiator에게 positive net credit을 생성해서는 안 됩니다.
- exactInput/exactOutput 모두에 대해 ±1 wei input을 사용하여 threshold/tick boundary를 테스트합니다.
- Rounding policy: 항상 user에게 불리하게 round하는 rounding helper를 centralize하고, 일관되지 않은 cast와 implicit floor를 제거합니다.
- Settlement sinks: 피할 수 없는 rounding residue는 protocol treasury에 누적하거나 burn하며, 절대 msg.sender에게 귀속하지 않습니다.
- Rate-limits/guardrails: rebalancing trigger에 minimum swap size를 적용하고, deltas가 sub-wei인 경우 rebalances를 비활성화하며, deltas가 예상 범위를 벗어나지 않는지 sanity-check합니다.
- hook callbacks를 holistic하게 review합니다. beforeSwap/afterSwap 및 before/after liquidity changes는 tick alignment와 delta rounding에 대해 서로 일치해야 합니다.

## Case study: Bunni V2 (2025-09-02)

- Protocol: rebalancing을 위해 swap마다 LDF가 적용되는 Bunni V2 (Uniswap v4 hook).<sup>[[7]](#references)</sup>
- Affected pools: Ethereum의 USDC/USDT 및 Unichain의 weETH/ETH로, 총 약 $8.4M입니다.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 1 (price push): attacker는 약 3M USDT를 flash-borrow한 후 swap하여 tick을 약 5000까지 밀어 올렸고, **active** USDC balance를 약 28 wei까지 줄였습니다.<sup>[[7]](#references)</sup>
- Step 2 (rounding drain): 44회의 tiny withdrawal이 `BunniHubLogic::withdraw()`의 floor rounding을 exploit하여 active USDC balance를 28 wei에서 4 wei로 줄였습니다(-85.7%). 이 과정에서 burn된 LP shares는 극히 일부에 불과했습니다. Total liquidity는 약 84.4% 과소평가되었습니다.<sup>[[2]](#references)[[7]](#references)</sup>
- Step 3 (liquidity rebound sandwich): large swap으로 tick이 약 839,189까지 이동했습니다(1 USDC ≈ 2.77e36 USDT). Liquidity estimates가 반전되며 약 16.8% 증가했고, attacker는 inflated price에서 swap back하는 sandwich를 실행하여 profit을 얻고 exit할 수 있었습니다.<sup>[[7]](#references)</sup>
- Post-mortem에서 확인된 fix: idle-balance update를 **round up**하도록 변경하여 repeated micro-withdrawals가 pool의 active balance를 계속 낮추지 못하게 합니다.<sup>[[7]](#references)</sup>

Simplified vulnerable line (and post-mortem fix)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting 체크리스트

- 풀이 non-zero hooks address를 사용하는가? 어떤 callbacks가 활성화되어 있는가?
- custom math를 사용하는 per-swap redistribution/rebalance가 있는가? tick/threshold 로직이 있는가?
- divisions/mulDiv, Q64.96 conversions 또는 SafeCast가 사용되는 위치는 어디인가? rounding semantics가 전체적으로 일관적인가?
- 경계를 간신히 넘어서 유리한 rounding branch를 발생시키는 Δin을 구성할 수 있는가? 양방향과 exactInput 및 exactOutput을 모두 테스트하라.
- hook이 caller별 credits 또는 이후 인출 가능한 deltas를 추적하는가? residue가 neutralized되는지 확인하라.

## References

- [1] [Bunni V2 Exploit: Liquidity Flaw로 $8.3M Drained (요약)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
