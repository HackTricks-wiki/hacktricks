# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



이 페이지는 Uniswap v4 스타일 DEX에서 core math 위에 custom hooks를 확장한 경우에 발생하는 DeFi/AMM 공격 기법군을 문서화합니다. 최근 Bunni V2 사건은 Liquidity Distribution Function (LDF) 내 반올림/정밀도 결함을 악용하여 각 swap 실행 시 공격자가 양의 크레딧을 축적하고 유동성을 탈취할 수 있게 했습니다.

핵심 아이디어: hook이 fixed‑point 연산, tick 반올림, 임계값 로직에 의존하는 추가 회계 처리를 구현하면, 공격자는 정확입력(exact‑input) swaps를 설계해 특정 임계값을 넘나들며 반올림 불일치가 자신에게 누적되도록 만들 수 있습니다. 이 패턴을 반복하고 누적된 잔액을 인출하면 이익을 실현할 수 있으며, 보통은 flash loans로 자금을 조달합니다.

## Background: Uniswap v4 hooks and swap flow

- Hooks는 PoolManager가 특정 라이프사이클 시점(예: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)에 호출하는 계약입니다.
- Pools는 hooks 주소를 포함한 PoolKey로 초기화됩니다. non‑zero일 경우 PoolManager는 모든 관련 연산에서 콜백을 수행합니다.
- Hooks는 **custom deltas**를 반환하여 swap이나 liquidity 액션의 최종 잔액 변동을 변경할 수 있습니다(custom accounting). 이러한 델타는 호출 종료 시 순잔액으로 정산되므로 hook 내부의 반올림 오차는 정산 전에 누적됩니다.
- Core math는 sqrtPriceX96에 대해 Q64.96 같은 fixed‑point 포맷과 1.0001^tick를 이용한 tick 연산을 사용합니다. 그 위에 쌓이는 모든 custom math는 불변성 드리프트를 피하기 위해 반올림 의미(semantics)를 정확히 맞춰야 합니다.
- Swaps는 exactInput 또는 exactOutput이 될 수 있습니다. v3/v4에서는 가격이 ticks를 따라 이동하며, tick 경계 교차는 range liquidity의 활성화/비활성화를 야기할 수 있습니다. Hooks는 임계값/틱 교차 시 추가 로직을 구현할 수 있습니다.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

custom hooks에서 자주 보이는 취약 패턴:

1. Hook이 integer division, mulDiv, 또는 fixed‑point 변환(예: token ↔ liquidity 변환에 sqrtPrice와 tick 범위를 사용)을 사용해 스왑당 유동성 또는 잔액 델타를 계산합니다.
2. 임계값 로직(예: 리밸런싱, 단계별 재분배, 또는 범위별 활성화)이 스왑 크기나 가격 이동이 내부 경계를 넘을 때 트리거됩니다.
3. 순전달 계산(forward calculation)과 정산 경로(settlement path) 사이에 반올림이 일관되게 적용되지 않습니다(예: 0쪽으로 절단(truncation toward zero), floor vs ceil). 작은 불일치들이 상쇄되지 않고 대신 호출자에게 크레딧으로 귀속됩니다.
4. 정확입력(exact‑input) swaps를 경계 바로 넘도록 정밀하게 조정하면 양의 반올림 잔류분을 반복적으로 수확할 수 있습니다. 공격자는 이후 축적된 크레딧을 인출합니다.

Attack preconditions
- 각 스왑마다 추가 연산을 수행하는 custom v4 hook을 사용하는 풀(예: LDF/rebalancer).
- 임계값 교차 시 스왑 실행자에 유리하게 반올림이 적용되는 적어도 하나의 실행 경로.
- 많은 스왑을 원자적으로 반복 실행할 수 있는 능력(일시적 자금을 공급하고 gas를 분산시키기 위해 flash loans가 이상적).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerate v4 pools and check PoolKey.hooks != address(0).
- Inspect hook bytecode/ABI for callbacks: beforeSwap/afterSwap and any custom rebalancing methods.
- Look for math that: divides by liquidity, converts between token amounts and liquidity, or aggregates BalanceDelta with rounding.

2) Model the hook’s math and thresholds
- Recreate the hook’s liquidity/redistribution formula: inputs typically include sqrtPriceX96, tickLower/Upper, currentTick, fee tier, and net liquidity.
- Map threshold/step functions: ticks, bucket boundaries, or LDF breakpoints. Determine which side of each boundary the delta is rounded on.
- Identify where conversions cast between uint256/int256, use SafeCast, or rely on mulDiv with implicit floor.

3) Calibrate exact‑input swaps to cross boundaries
- Use Foundry/Hardhat simulations to compute the minimal Δin needed to move price just across a boundary and trigger the hook’s branch.
- Verify that afterSwap settlement credits the caller more than the cost, leaving a positive BalanceDelta or credit in the hook’s accounting.
- Repeat swaps to accumulate credit; then call the hook’s withdrawal/settlement path.

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
exactInput 보정
- 틱 단계에 대한 ΔsqrtP 계산: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- v3/v4 공식을 사용해 Δin을 근사: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). 반올림 방향이 핵심 수학과 일치하는지 확인.
- 경계 근처에서 Δin을 ±1 wei만큼 조정해 hook이 당신에게 유리하게 반올림하는 branch를 찾으세요.

4) flash loans로 증폭
- 많은 반복을 원자적으로 실행하기 위해 큰 명목액(예: 3M USDT 또는 2000 WETH)을 빌리세요.
- 보정된 swap loop를 실행한 다음, flash loan callback 내에서 출금하고 상환하세요.

Aave V3 flash loan 스켈레톤
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
5) Exit 및 크로스체인 복제
- hooks가 여러 체인에 배포된 경우, 체인별로 동일한 보정을 반복합니다.
- 브리지는 자금을 대상 체인으로 되돌리고, 흐름을 은폐하기 위해 선택적으로 대출 프로토콜을 경유해 순환시킬 수 있습니다.

## hook 수학에서의 일반적인 근본 원인

- Mixed rounding semantics: mulDiv는 내림(floor)하는 반면 이후 경로에서는 실질적으로 올림(round up)함; 또는 token/liquidity 간 변환이 서로 다른 반올림 규칙을 적용함.
- Tick alignment errors: 한 경로에서는 반올림되지 않은 ticks를 사용하고 다른 경로에서는 tick‑spaced 반올림을 사용하는 경우.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement: 정산(settlement) 중 int256과 uint256 간 변환 시 BalanceDelta의 부호/오버플로우 문제가 발생할 수 있음.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping: Q64.96 변환(sqrtPriceX96)에서의 정밀도 손실이 역 매핑에서는 반영되지 않음.
- Accumulation pathways: 스왑별 잔여분이 소각되거나 제로섬이 되는 대신 호출자가 인출할 수 있는 크레딧으로 추적되는 경우.

## Custom accounting & delta amplification

- Uniswap v4의 커스텀 회계는 hooks가 호출자가 빚지거나 받을 금액을 직접 조정하는 델타를 반환하도록 허용합니다. 만약 hook이 내부적으로 크레딧을 추적한다면, 반올림 잔여가 최종 정산이 일어나기 **전에** 많은 작은 연산에 걸쳐 누적될 수 있습니다.
- 이로 인해 경계/임계값 악용이 더 강력해집니다: 공격자는 동일한 tx 내에서 `swap → withdraw → swap`을 번갈아 실행하여, 모든 잔액이 아직 보류 중인 상태에서 hook이 약간 다른 상태로 델타를 재계산하도록 강요할 수 있습니다.
- hooks를 검토할 때는 항상 BalanceDelta/HookDelta가 어떻게 생성되고 정산되는지 추적하세요. 한 경로에서의 단일 편향된 반올림이 델타가 반복적으로 재계산될 때 누적되는 크레딧으로 증폭될 수 있습니다.

## 방어 지침

- Differential testing: 고정밀 유리수 연산을 사용해 hook의 수학을 레퍼런스 구현과 대조하고, 항상 공격자(호출자에게 유리하지 않음)를 가정한 동등성 또는 허용 오차를 검증하세요.
- 불변량/속성 테스트:
- swap 경로와 hook 조정 전반의 델타 합(토큰, 유동성)은 수수료를 제외하고 가치 보존이 되어야 합니다.
- 반복된 exactInput 반복에서 어떤 경로도 스왑 시작자에게 긍정적 순 크레딧을 발생시켜선 안 됩니다.
- exactInput/exactOutput 양쪽에 대해 ±1 wei 입력 주변의 임계값/tick 경계 테스트를 수행하세요.
- 반올림 정책: 항상 사용자에게 불리하게 반올림하는 중앙화된 반올림 헬퍼를 사용하고, 일관되지 않은 캐스트와 암묵적 floor를 제거하세요.
- 정산 싱크: 불가피한 반올림 잔여는 프로토콜 금고(treasury)에 누적하거나 소각하고, 절대 msg.sender에 귀속시키지 마세요.
- 속도 제한/가드레일: 리밸런스 트리거에 대한 최소 스왑 크기 설정; 델타가 sub‑wei인 경우 리밸런스를 비활성화; 델타를 기대 범위와 비교해 정상성 검사 수행.
- hook 콜백을 전체적으로 검토하세요: beforeSwap/afterSwap 및 before/after의 유동성 변경은 tick 정렬과 델타 반올림에 대해 일치해야 합니다.

## 사례 연구: Bunni V2 (2025‑09‑02)

- 프로토콜: Bunni V2 (Uniswap v4 hook)로, 각 스왑마다 리밸런스를 위해 LDF가 적용됨.
- 영향을 받은 풀: Ethereum의 USDC/USDT 및 Unichain의 weETH/ETH, 총 약 $8.4M.
- Step 1 (price push): 공격자는 약 3M USDT를 flash‑borrow하고 스왑하여 tick을 약 5000으로 밀어 **active** USDC 잔액을 약 28 wei로 축소시켰습니다.
- Step 2 (rounding drain): 44회의 작은 인출로 `BunniHubLogic::withdraw()`의 floor 반올림을 악용해 active USDC 잔액을 28 wei에서 4 wei로 (‑85.7%) 줄였고, LP 지분은 극히 일부만 소각되었습니다. 이로 인해 총 유동성은 약 84.4% 과소평가되었습니다.
- Step 3 (liquidity rebound sandwich): 대규모 스왑으로 tick이 약 839,189로 이동(1 USDC ≈ 2.77e36 USDT). 유동성 추정이 뒤집히며 약 16.8% 증가했고, 공격자는 부풀려진 가격에서 다시 스왑해 이익을 남기고 탈출하는 sandwich를 가능하게 했습니다.
- 사후 분석에서 확인된 수정: idle‑balance 업데이트를 **up**(올림)으로 변경하여 반복되는 마이크로 인출이 풀의 active 잔액을 하향으로 고정시키지 못하도록 했습니다.

단순화된 취약 라인(및 사후 수정)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## 헌팅 체크리스트

- Pool이 non‑zero hooks address를 사용하나? 어떤 callbacks가 활성화되어 있나?
- per‑swap redistributions/rebalances가 custom math를 사용하나? tick/threshold logic가 있나?
- divisions/mulDiv, Q64.96 conversions, 또는 SafeCast가 어디에서 사용되나? 반올림 동작(rounded semantics)이 전역적으로 일관되는가?
- 경계를 간신히 넘는 Δin을 구성하여 유리한 rounding branch를 유도할 수 있나? 양 방향과 exactInput 및 exactOutput 모두 테스트하라.
- Hook이 per‑caller credits 또는 deltas를 추적하여 나중에 출금될 수 있게 하나? 잔류(residue)가 중화되었는지 확인하라.

## 참고자료

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
