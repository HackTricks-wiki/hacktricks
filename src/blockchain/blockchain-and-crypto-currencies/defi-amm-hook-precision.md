# DeFi/AMM Exploitation: Uniswap v4 Hook 정밀도/반올림 악용

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 custom hook으로 핵심 수학 로직을 확장하는 Uniswap v4 스타일 DEX를 대상으로 한 DeFi/AMM exploitation 기법을 다룹니다. Bunni V2 incident는 이와 관련된 실패 사례를 보여줍니다. 출금 회계에서 반올림 방향 버그로 활성 유동성이 실제보다 적게 계산되었고, 이후 swap에서 이 과소 계산이 드러나 수익성 있는 sandwich 공격으로 이어졌습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

핵심 아이디어: hook이 fixed-point math, tick 반올림, threshold 로직에 의존하는 추가 회계를 구현한다면, 공격자는 특정 threshold를 넘도록 exact-input swap을 구성해 반올림 오차가 자신에게 유리하게 누적되도록 할 수 있습니다. 이 패턴을 반복한 뒤 부풀려진 잔액을 출금해 수익을 실현하며, flash loan으로 자금을 조달하는 경우가 많습니다.

## 배경: Uniswap v4 hooks와 swap 흐름

- Hooks는 PoolManager가 특정 lifecycle 지점(예: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)에서 호출하는 컨트랙트입니다.<sup>[[4]](#references)</sup>
- Pool은 hook 컨트랙트를 포함하는 PoolKey로 초기화됩니다. 0이 아닌 hook 주소를 지정하면 해당 pool에 선택된 callback이 활성화됩니다.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks는 swap 또는 liquidity 작업의 최종 잔액 변화를 수정하는 **custom delta**를 반환할 수 있습니다(custom accounting). 이러한 delta는 호출이 끝날 때 순 잔액으로 정산되므로, hook math 내부의 반올림 오류는 정산 전에 누적됩니다.<sup>[[4]](#references)</sup>
- 핵심 math는 sqrtPriceX96에 사용되는 Q64.96 등의 fixed-point 형식과 1.0001^tick을 사용하는 tick 연산을 활용합니다. 그 위에 추가되는 custom math는 invariant drift를 방지하기 위해 반올림 규칙을 정확히 일치시켜야 합니다.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps는 exactInput 또는 exactOutput일 수 있습니다. v3/v4에서는 가격이 tick을 따라 움직이며, tick 경계를 넘으면 구간 유동성이 활성화되거나 비활성화될 수 있습니다. Hooks는 tick 또는 threshold 통과 시 추가 로직을 구현할 수 있습니다.<sup>[[9]](#references)[[11]](#references)</sup>

## 취약점 유형: threshold 통과에 따른 정밀도/반올림 오차 누적

Custom hook에서 흔히 볼 수 있는 취약한 패턴:

1. Hook이 정수 나눗셈, mulDiv, 또는 fixed-point 변환(예: sqrtPrice 및 tick 범위를 이용한 token ↔ liquidity 변환)으로 swap별 유동성 또는 잔액 delta를 계산합니다.
2. Threshold 로직(예: rebalancing, 단계별 재분배, 또는 구간별 활성화)은 swap 규모나 가격 변동이 내부 경계를 넘을 때 실행됩니다.
3. 계산 과정과 정산 경로에서 반올림이 일관되지 않게 적용됩니다(예: 0 방향 절삭, floor와 ceil의 혼용). 작은 오차는 상쇄되지 않고 호출자에게 잔액을 더해 줍니다.
4. 해당 경계를 넘도록 정밀하게 조정한 exact-input swap으로 양의 반올림 잔여분을 반복해서 챙깁니다. 이후 공격자는 누적된 credit을 출금합니다.

공격 전제 조건
- 각 swap에서 추가 math(예: LDF/rebalancer)를 수행하는 custom v4 hook을 사용하는 pool.
- threshold 통과 시 swap을 시작한 쪽에 유리한 반올림이 발생하는 실행 경로가 하나 이상 존재할 것.
- 많은 swap을 원자적으로 반복할 수 있을 것(임시 자금을 마련하고 gas 비용을 분산하기에 flash loan이 적합).

## 실전 공격 방법론

1) Hook이 있는 후보 pool 식별
- v4 pool을 열거하고 PoolKey.hooks != address(0)인지 확인합니다.
- Hook bytecode/ABI에서 beforeSwap/afterSwap callback 및 custom rebalancing 메서드를 살펴봅니다.
- 다음과 같은 math를 찾습니다. liquidity로 나누거나, token amount와 liquidity 사이를 변환하거나, BalanceDelta를 반올림과 함께 합산하는 로직입니다.

2) Hook의 math 및 threshold 모델링
- Hook의 liquidity/redistribution 공식을 재현합니다. 입력에는 일반적으로 sqrtPriceX96, tickLower/Upper, currentTick, fee tier, net liquidity가 포함됩니다.
- Threshold/step function을 매핑합니다. 예를 들어 tick, bucket 경계, LDF breakpoint 등이 있습니다. 각 경계의 어느 쪽에서 delta가 반올림되는지 확인합니다.
- uint256/int256 간 변환, SafeCast 사용, 또는 암묵적으로 floor를 적용하는 mulDiv 사용 지점을 찾습니다.

3) 경계를 넘도록 exact-input swap 조정
- Foundry/Hardhat simulation을 사용해 가격을 경계 바로 너머로 이동시키고 hook의 분기를 실행하는 데 필요한 최소 Δin을 계산합니다.
- afterSwap 정산에서 호출자에게 비용보다 많은 금액이 credit되어 양의 BalanceDelta 또는 hook 회계상의 credit이 남는지 확인합니다.
- Swap을 반복해 credit을 누적한 다음 hook의 withdrawal/settlement 경로를 호출합니다.

v4에서는 swap loop가 PoolManager unlock callback에서 실행되어야 합니다. 음수 `amountSpecified`는 exact input을 뜻하며, `sqrtPriceLimitX96`은 유효 범위 안에 있어야 합니다. 가격 제한을 0으로 설정하면 revert되므로, 아래 pseudocode에서는 zero-for-one swap에 하한을 사용합니다.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Foundry 스타일 테스트 harness 예시(pseudocode)
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
- core TickMath로 목표값을 계산합니다. 실수값 기준으로 sqrtP_next = sqrtP_current × 1.0001^(Δtick)이며, Q64.96 결과는 TickMath에서 반올림됩니다.<sup>[[13]](#references)</sup>
- Q64.96을 고려한 공식으로 token0(zero-for-one) 입력값을 근사합니다. Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). core 루틴의 방향별 반올림 방식을 적용합니다.<sup>[[12]](#references)</sup>
- 경계값 주변에서 Δin을 ±1 wei씩 조정해 hook이 유리하게 반올림하는 분기를 찾습니다.

4) flash loan으로 증폭
- 큰 명목 금액(예: 3M USDT 또는 2000 WETH)을 빌려 여러 차례 반복 실행합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 보정된 swap 루프를 실행한 다음, flash loan 콜백 내에서 자금을 인출하고 상환합니다.

Aave V3 flash loan 기본 구조
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

5) Exit 및 cross-chain 복제
- 여러 체인에 hook을 배포했다면 체인별로 동일한 보정을 반복합니다.
- Bunni 사고에서는 flash-loan 유동성과 bridge 경로가 체인마다 달랐으므로, 분석을 재현할 때 체인별 제약 조건을 고려합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## hook 수학에서 흔한 근본 원인

- 반올림 의미의 혼용: mulDiv는 내림하지만 이후 경로에서는 사실상 올림하거나, 토큰과 유동성 간 변환에서 서로 다른 반올림 방식을 적용하는 경우.
- Tick 정렬 오류: 한 경로에서는 반올림하지 않은 tick을 사용하고, 다른 경로에서는 tick 간격에 맞춰 반올림하는 경우.
- 정산 중 int256과 uint256 간 변환에서 BalanceDelta 부호/오버플로 문제가 발생하는 경우.
- Q64.96 변환(sqrtPriceX96)에서 정밀도가 손실되지만, 역변환에는 이를 반영하지 않는 경우.
- 누적 경로: swap별 잔여분을 caller가 인출할 수 있는 credit으로 추적해 소각하거나 합계가 0이 되도록 처리하지 않는 경우.

## 사용자 지정 accounting 및 delta 증폭

- Uniswap v4 custom accounting을 사용하면 hook이 caller의 지불액/수령액을 직접 조정하는 delta를 반환할 수 있습니다. hook이 내부적으로 credit을 추적한다면, 최종 정산 전에 여러 번의 소규모 작업을 거치며 반올림 잔여분이 누적될 수 있습니다.<sup>[[4]](#references)</sup>
- hook에 호환되는 인출 경로가 있다면, 공격자는 동일한 PoolManager unlock callback 내에서 `swap → withdraw → swap`을 반복해 hook이 약간 달라진 상태에서 delta를 다시 계산하도록 할 수 있습니다. 이때 잔액은 unlock이 정산될 때까지 미결 상태로 유지됩니다.<sup>[[4]](#references)[[10]](#references)</sup>
- hook을 검토할 때는 BalanceDelta/HookDelta가 생성되고 정산되는 과정을 항상 추적합니다. 한 분기에서의 편향된 반올림도 delta를 반복 계산하면 누적 credit으로 이어질 수 있습니다.

## 방어 지침

- 차등 테스트: hook의 수학 연산을 고정밀 유리수 연산을 사용하는 참조 구현과 비교하고, 결과가 일치하거나 제한된 오차 범위 내에 있으며 항상 공격자에게 불리한지(절대로 caller에게 유리하지 않은지) 확인합니다.
- 불변식/속성 테스트:
  - swap 경로와 hook 조정 전반의 delta 합계(토큰, 유동성)는 수수료를 제외하고 가치를 보존해야 합니다.
  - 반복적인 exactInput 실행에서 어떤 경로도 swap initiator에게 양의 순 credit을 생성해서는 안 됩니다.
  - exactInput/exactOutput 모두에서 ±1 wei 입력을 사용해 임계값/tick 경계 테스트를 수행합니다.
- 반올림 정책: 사용자에게 항상 불리하게 반올림하는 helper를 중앙화하고, 일관되지 않은 형 변환과 암묵적 내림을 제거합니다.
- 정산 잔여분 처리: 불가피한 반올림 잔여분은 protocol treasury에 누적하거나 소각해야 하며, msg.sender에게 귀속해서는 안 됩니다.
- Rate limit/보호 장치: 리밸런싱 트리거의 최소 swap 규모를 설정하고, delta가 sub-wei라면 리밸런싱을 비활성화하며, delta가 예상 범위 내에 있는지 검증합니다.
- hook callback 전체 검토: beforeSwap/afterSwap과 유동성 변경 전후 callback에서 tick 정렬 및 delta 반올림 방식이 일치해야 합니다.

## 사례 연구: Bunni V2 (2025-09-02)

- 프로토콜: Uniswap v4 hook인 Bunni V2는 Liquidity Density Function (LDF)을 사용해 토큰 밀도와 총 유동성을 추정합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- 영향을 받은 pool: Ethereum의 USDC/USDT와 Unichain의 weETH/ETH로, 총 피해 규모는 약 $8.4M입니다.<sup>[[1]](#references)</sup>
- 1단계 (가격 변동): 공격자는 약 3M USDT를 flash-borrow한 뒤 swap하여 tick을 약 5000까지 밀어 올리고, **active** USDC 잔액을 약 28 wei로 줄였습니다.<sup>[[1]](#references)</sup>
- 2단계 (반올림을 이용한 탈취): 44회의 소액 인출로 `BunniHubLogic::withdraw()`의 내림 반올림을 악용해 LP 지분은 극히 일부만 소각하면서 active USDC 잔액을 28 wei에서 4 wei로 줄였습니다(-85.7%). 총 유동성은 약 84.4% 감소했습니다.<sup>[[1]](#references)[[2]](#references)</sup>
- 3단계 (유동성 반등 샌드위치): 대규모 swap으로 tick을 약 839,189까지 이동시켰습니다(1 USDC ≈ 2.77e36 USDT). 유동성 추정치가 뒤집히며 약 16.8% 증가했고, 이를 이용한 샌드위치 공격에서 공격자는 부풀려진 가격에 되팔아 수익을 내고 빠져나왔습니다.<sup>[[1]](#references)</sup>
- 사후 분석에서 확인된 수정 사항: 유휴 잔액 업데이트를 올림 처리해 반복적인 소액 인출로 pool의 active 잔액이 계속 감소하지 않도록 합니다.<sup>[[1]](#references)</sup>

취약한 코드와 사후 분석에서 제시한 수정 사항을 단순화한 예시입니다.<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Hunting 체크리스트

- 풀이 0이 아닌 hooks 주소를 사용하나요? 어떤 callbacks가 활성화되어 있나요?
- custom math를 사용하는 스왑별 재분배/리밸런싱이 있나요? tick/threshold 로직은 있나요?
- 나눗셈, mulDiv, Q64.96 변환 또는 SafeCast는 어디에서 사용되나요? 반올림 방식이 전체적으로 일관적인가요?
- 경계를 간신히 넘어서 유리한 반올림 분기를 유도하는 Δin을 구성할 수 있나요? 양쪽 방향과 exactInput, exactOutput 모두 테스트하세요.
- hook이 나중에 출금할 수 있는 caller별 크레딧이나 델타를 추적하나요? 잔여분이 중립화되는지 확인하세요.

## References

- [1] [Bunni 익스플로잇 사후 분석 (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 익스플로잇: 전체 해킹 분석](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 익스플로잇: 유동성 결함으로 830만 달러 유출 (요약)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 코어 백서](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 배경 (QuillAudits 연구)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 코어의 유동성 메커니즘](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 코어의 스왑 메커니즘](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks 및 보안 고려 사항](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 코어 Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 코어 PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 코어 SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 코어 TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
