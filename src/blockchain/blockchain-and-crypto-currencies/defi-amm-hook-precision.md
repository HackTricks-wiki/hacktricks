# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 custom hooks로 코어 수학을 확장하는 Uniswap v4 스타일 DEX들에 대한 일련의 DeFi/AMM 공격 기법을 설명한다. 최근 Bunni V2 사고에서는 Liquidity Distribution Function (LDF)의 반올림/정밀도 결함을 이용해 각 스왑에서 공격자가 양(+)의 크레딧을 축적하고 유동성을 탈취할 수 있었다.

핵심 아이디어: 훅이 고정 소수점 연산, tick 반올림, 임계값 로직에 의존하는 추가 회계(accounting)를 구현하면, 공격자는 특정 임계값을 넘도록 가격을 정확히 이동시키는 exact‑input 스왑을 설계해 반올림 차이가 자신에게 유리하게 누적되도록 할 수 있다. 이 패턴을 반복하고 증식된 잔액을 인출하면 이익을 실현하며, 종종 flash loan으로 자금을 조달한다.

## Background: Uniswap v4 hooks and swap flow

- Hooks는 PoolManager가 특정 생명주기 지점에서 호출하는 contracts이다(예: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pools는 PoolKey에 hooks 주소로 초기화된다. non‑zero인 경우 PoolManager는 관련된 모든 작업에서 콜백을 호출한다.
- 코어 수학은 sqrtPriceX96에 대해 Q64.96 같은 fixed‑point 포맷과 1.0001^tick을 사용하는 tick 산술을 사용한다. 그 위에 추가된 모든 custom math는 불변성 드리프트를 피하기 위해 반올림 의미론을 정확히 맞춰야 한다.
- Swaps는 exactInput 또는 exactOutput일 수 있다. v3/v4에서 가격은 ticks를 따라 움직이고, tick 경계를 넘으면 범위 유동성이 활성화/비활성화될 수 있다. Hooks는 임계값/틱 교차에서 추가 로직을 구현할 수 있다.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

custom hooks에서 흔한 취약 패턴:

1. 훅이 per‑swap 유동성 또는 잔액 델타를 integer division, mulDiv, 또는 fixed‑point 변환(예: token ↔ liquidity 변환에 sqrtPrice와 tick ranges 사용)으로 계산한다.
2. 임계값 로직(예: 리밸런싱, 단계별 재분배, 또는 범위별 활성화)이 스왑 크기나 가격 이동이 내부 경계를 넘을 때 트리거된다.
3. 전진 계산과 정산 경로 사이에 반올림이 일관되게 적용되지 않는다(예: 0으로 절단(truncation toward zero), floor 대 ceil). 작은 불일치가 상쇄되지 않고 대신 호출자에게 크레딧으로 귀속된다.
4. 임계값을 가로지르도록 정밀하게 조정된 exact‑input 스왑은 양(+)의 반올림 잔여분을 반복적으로 수확한다. 공격자는 이후 축적된 크레딧을 인출한다.

Attack preconditions
- 각 스왑에서 추가 연산을 수행하는 custom v4 hook을 사용하는 풀(예: LDF/rebalancer).
- 임계값 교차에서 스왑 시작자에게 반올림 이익을 주는 적어도 하나의 실행 경로.
- 많은 수의 스왑을 원자적으로 반복할 수 있는 능력(flash loans는 임시 유동성 제공과 가스 분산에 이상적).

## Practical attack methodology

1) Identify candidate pools with hooks
- v4 pools를 열거하고 PoolKey.hooks != address(0)을 확인한다.
- beforeSwap/afterSwap 같은 콜백과 custom rebalancing 메서드를 위해 hook bytecode/ABI를 검사한다.
- 다음과 같은 수학을 찾는다: liquidity로 나누기, token과 liquidity 사이 변환, 또는 반올림을 포함한 BalanceDelta 집계 등.

2) Model the hook’s math and thresholds
- 훅의 liquidity/redistribution 공식을 재현한다: 입력에는 일반적으로 sqrtPriceX96, tickLower/Upper, currentTick, fee tier, net liquidity 등이 포함된다.
- 임계값/스텝 함수들을 매핑한다: ticks, 버킷 경계, 또는 LDF 분기점. 각 경계의 어느 쪽에서 델타가 반올림되는지 결정한다.
- 어디에서 uint256/int256 간 캐스트가 일어나는지, SafeCast를 쓰는지, 또는 암묵적 floor를 가진 mulDiv를 사용하는지 식별한다.

3) Calibrate exact‑input swaps to cross boundaries
- Foundry/Hardhat 시뮬레이션을 사용해 가격을 경계 바로 넘어가게 하고 훅의 분기를 트리거하기 위한 최소 Δin을 계산한다.
- afterSwap 정산이 비용보다 호출자에게 더 많은 크레딧을 부여해 positive BalanceDelta 또는 훅 회계상 크레딧을 남기는지 검증한다.
- 크레딧을 축적하기 위해 스왑을 반복한 뒤 훅의 withdrawal/settlement 경로를 호출한다.

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
- 틱 스텝에 대한 ΔsqrtP 계산: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- v3/v4 공식을 사용해 Δin을 근사: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). 반올림 방향이 핵심 수학과 일치하는지 확인하세요.
- 경계 주변에서 Δin을 ±1 wei만큼 조정해 hook이 당신에게 유리하게 반올림하는 분기를 찾으세요.

4) flash loans로 증폭하기
- 원자적으로 여러 반복을 실행하기 위해 큰 명목액(예: 3M USDT 또는 2000 WETH)을 빌리세요.
- 보정된 swap 루프를 실행한 다음, flash loan callback 내에서 출금하고 상환하세요.

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
5) Exit and cross‑chain replication
- If hooks are deployed on multiple chains, repeat the same calibration per chain.
- Bridge proceeds back to the target chain and optionally cycle via lending protocols to obfuscate flows.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## Defensive guidance

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
