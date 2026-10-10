# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 custom hook으로 core math를 확장하는 Uniswap v4 스타일 DEX를 대상으로 한 DeFi/AMM exploitation 기법을 설명합니다. Bunni V2 incident는 이와 관련된 실패 사례입니다. withdrawal accounting에서 rounding 방향 버그로 인해 active liquidity가 실제보다 적게 계산되었고, 이후 swap에서 이 과소 계산이 수익성 있는 sandwich로 이어졌습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

핵심 아이디어: hook이 fixed-point math, tick rounding, threshold logic에 의존하는 추가 accounting을 구현하는 경우, 공격자는 특정 threshold를 넘도록 정확한 크기의 exact-input swap을 만들어 rounding 차이가 자신에게 유리하게 누적되도록 할 수 있습니다. 이 패턴을 반복한 다음 부풀려진 잔액을 인출해 수익을 실현하며, 이때 flash loan을 이용해 자금을 조달하는 경우가 많습니다.

## 배경: Uniswap v4 hooks와 swap 흐름

- Hooks는 PoolManager가 특정 lifecycle 시점(예: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate)에 호출하는 contract입니다.<sup>[[4]](#references)</sup>
- Pool은 hook contract를 포함하는 PoolKey로 초기화됩니다. 0이 아닌 hook address는 해당 pool에 선택된 callback을 활성화합니다.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks는 swap 또는 liquidity 작업의 최종 잔액 변화를 수정하는 **custom deltas**를 반환할 수 있습니다(custom accounting). 해당 delta는 호출이 끝날 때 net balance로 정산되므로, hook math 내부의 rounding error는 정산 전에 누적됩니다.<sup>[[4]](#references)</sup>
- Core math는 sqrtPriceX96의 Q64.96 같은 fixed-point 형식과 1.0001^tick을 사용하는 tick arithmetic을 사용합니다. 그 위에 추가되는 custom math는 invariant drift를 방지하도록 rounding semantics를 신중히 맞춰야 합니다.<sup>[[12]](#references)[[13]](#references)</sup>
- Swap은 exactInput 또는 exactOutput 방식일 수 있습니다. v3/v4에서는 가격이 tick을 따라 움직이며, tick 경계를 넘으면 range liquidity가 활성화되거나 비활성화될 수 있습니다. Hooks는 tick 경계나 threshold를 넘을 때 추가 로직을 실행할 수 있습니다.<sup>[[9]](#references)[[11]](#references)</sup>

## 취약점 유형: threshold crossing에 따른 precision/rounding drift

Custom hook에서 흔히 볼 수 있는 취약한 패턴:

1. Hook이 integer division, mulDiv 또는 fixed-point 변환(예: sqrtPrice와 tick range를 사용한 token ↔ liquidity 변환)으로 swap마다 발생하는 liquidity 또는 balance delta를 계산합니다.
2. Swap 크기나 가격 변동이 내부 경계를 넘으면 threshold logic(예: rebalancing, 단계별 redistribution 또는 range별 activation)이 작동합니다.
3. Forward calculation과 settlement 경로에서 rounding이 일관되지 않게 적용됩니다(예: 0 방향 truncation, floor와 ceil의 혼용). 작은 차이가 상쇄되지 않고 caller에게 이익으로 돌아갑니다.
4. 해당 경계를 아슬아슬하게 넘도록 크기를 조절한 exact-input swap으로 양의 rounding remainder를 반복해서 수확합니다. 이후 누적된 credit을 인출합니다.

공격 전제 조건
- 각 swap에서 추가 math를 수행하는 custom v4 hook을 사용하는 pool(예: LDF/rebalancer).
- Threshold crossing에서 rounding이 swap initiator에게 이익이 되는 execution path가 하나 이상 존재.
- 다수의 swap을 원자적으로 반복할 수 있는 능력(flash loan은 임시 자금을 공급하고 gas 비용을 분산하는 데 이상적).

## 실전 공격 방법론

1) Hook이 있는 pool 식별
- v4 pool을 열거하고 PoolKey.hooks != address(0)인지 확인합니다.
- Hook bytecode/ABI에서 callback인 beforeSwap/afterSwap과 custom rebalancing method를 살펴봅니다.
- 다음과 같은 math를 찾습니다. liquidity로 나누거나, token amount와 liquidity를 변환하거나, BalanceDelta를 rounding과 함께 집계하는 로직입니다.

2) Hook의 math와 threshold 모델링
- Hook의 liquidity/redistribution formula를 재현합니다. 입력에는 보통 sqrtPriceX96, tickLower/Upper, currentTick, fee tier, net liquidity가 포함됩니다.
- Threshold/step function을 파악합니다. tick, bucket boundary 또는 LDF breakpoint를 살펴보고 각 경계에서 delta의 rounding 방향을 확인합니다.
- uint256/int256 간 cast, SafeCast 사용 또는 암묵적으로 floor를 적용하는 mulDiv 사용 여부를 확인합니다.

3) 경계를 넘도록 exact-input swap 조정
- Foundry/Hardhat simulation으로 가격을 경계 바로 너머까지 움직여 hook의 branch를 실행하는 데 필요한 최소 Δin을 계산합니다.
- afterSwap settlement가 caller에게 swap 비용보다 많은 금액을 credit하여 양의 BalanceDelta 또는 hook accounting상의 credit을 남기는지 확인합니다.
- Swap을 반복해 credit을 누적한 다음 hook의 withdrawal/settlement 경로를 호출합니다.

v4에서는 swap loop를 PoolManager unlock callback 안에서 실행해야 합니다. 음수 `amountSpecified`는 exact input을 의미하며, `sqrtPriceLimitX96`은 유효 범위 안에 있어야 합니다. Price limit이 0이면 revert되므로, 아래 pseudocode에서는 zero-for-one swap에 하한값을 사용합니다.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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

exactInput 정밀 조정
- core TickMath로 목표값을 계산합니다. 실수값 기준으로 sqrtP_next = sqrtP_current × 1.0001^(Δtick)이며, Q64.96 결과는 TickMath에서 반올림됩니다.<sup>[[13]](#references)</sup>
- Q64.96을 고려한 공식을 사용해 token0(zero-for-one) 입력량을 근사합니다. Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). core 루틴의 방향별 반올림 방식에 맞춥니다.<sup>[[12]](#references)</sup>
- 경계값 전후로 Δin을 ±1 wei씩 조정해 hook이 유리하게 반올림하는 분기를 찾습니다.

4) flash loan으로 규모 확대
- 대규모 명목 금액(예: 3M USDT 또는 2000 WETH)을 빌려 여러 번의 반복을 원자적으로 실행합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- 보정된 swap loop를 실행한 다음, flash loan callback 내에서 자금을 인출하고 상환합니다.

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
- 여러 체인에 hook이 배포되어 있다면, 체인별로 동일한 보정 작업을 반복합니다.
- Bunni 사고에서는 flash-loan 유동성과 bridge 경로가 체인마다 달랐으므로, 분석을 재현할 때 체인별 제약 조건을 고려합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## hook 수학에서 흔한 근본 원인

- 혼합된 반올림 방식: mulDiv는 내림하지만 이후 경로에서는 사실상 올림하거나, 토큰과 유동성 간 변환에 서로 다른 반올림 방식을 적용합니다.
- tick 정렬 오류: 한 경로에서는 반올림하지 않은 tick을 사용하고, 다른 경로에서는 tick 간격에 맞춰 반올림합니다.
- 정산 중 int256과 uint256 사이를 변환할 때 발생하는 BalanceDelta 부호/오버플로 문제.
- Q64.96 변환(sqrtPriceX96)에서 정밀도가 손실되지만 역변환에서는 이를 반영하지 않습니다.
- 누적 경로: 스왑별 나머지를 caller가 출금할 수 있는 크레딧으로 추적해, 소각하거나 합계가 0이 되도록 처리하지 않습니다.

## 커스텀 회계 및 delta 증폭

- Uniswap v4의 커스텀 회계를 사용하면 hook이 delta를 반환해 caller가 갚거나 받을 금액을 직접 조정할 수 있습니다. hook이 내부적으로 크레딧을 추적한다면, 최종 정산 전에 여러 소규모 작업을 거치며 반올림 잔여분이 누적될 수 있습니다.<sup>[[4]](#references)</sup>
- hook에 호환되는 출금 경로가 있다면 공격자는 동일한 PoolManager unlock callback 내에서 `swap → withdraw → swap`을 반복할 수 있습니다. 이렇게 하면 잔액이 unlock 종료 시 정산될 때까지 미결 상태로 남아 있는 동안 hook이 조금씩 달라진 상태에서 delta를 다시 계산하게 됩니다.<sup>[[4]](#references)[[10]](#references)</sup>
- hook을 검토할 때는 BalanceDelta/HookDelta가 어떻게 생성되고 정산되는지 항상 추적합니다. 한 분기에서 발생한 단 한 번의 편향된 반올림도 delta를 반복 계산하면 누적 크레딧이 될 수 있습니다.

## 방어 지침

- 차등 테스트: 고정밀 유리수 연산을 사용하는 참조 구현과 hook의 수학적 연산을 비교하고, 항상 공격자에게 불리한(절대 caller에게 유리하지 않은) 오차 범위 내에 있거나 결과가 일치하는지 확인합니다.
- 불변 조건/속성 테스트:
  - 스왑 경로와 hook 조정 전반에서 token 및 유동성 delta의 합은 수수료를 제외하고 가치를 보존해야 합니다.
  - 반복되는 exactInput 연산에서 스왑 시작자가 순 크레딧을 얻는 경로가 없어야 합니다.
  - exactInput/exactOutput 모두에서 ±1 wei 입력을 사용해 임계값/tick 경계 테스트를 수행합니다.
- 반올림 정책: 사용자에게 항상 불리하게 반올림하는 헬퍼를 중앙화하고, 일관되지 않은 캐스팅과 암시적 내림을 제거합니다.
- 정산 대상: 불가피한 반올림 잔여분은 프로토콜 treasury에 적립하거나 소각하고, 절대로 msg.sender에게 귀속하지 않습니다.
- 속도 제한/보호 장치: 리밸런싱 트리거에 최소 스왑 크기를 적용하고, delta가 sub-wei이면 리밸런싱을 비활성화하며, delta가 예상 범위에 있는지 검사합니다.
- hook callback을 전체적으로 검토합니다. beforeSwap/afterSwap과 유동성 변경 전후의 callback은 tick 정렬 및 delta 반올림 방식이 일치해야 합니다.

## 사례 연구: Bunni V2 (2025-09-02)

- 프로토콜: Bunni V2는 Liquidity Density Function (LDF)을 사용해 token 밀도와 총 유동성 추정치를 계산하는 Uniswap v4 hook입니다.<sup>[[1]](#references)[[2]](#references)</sup>
- 영향을 받은 pool: Ethereum의 USDC/USDT 및 Unichain의 weETH/ETH로, 총 피해액은 약 $8.4M입니다.<sup>[[1]](#references)</sup>
- 1단계 (가격 밀기): 공격자는 약 3M USDT를 flash-borrow한 뒤 스왑을 수행해 tick을 약 5000으로 밀어 올리고, **active** USDC 잔액을 약 28 wei까지 줄였습니다.<sup>[[1]](#references)</sup>
- 2단계 (반올림을 이용한 탈취): 44회의 소액 출금으로 `BunniHubLogic::withdraw()`의 내림 반올림을 악용해, LP 지분 중 극히 일부만 소각하면서 active USDC 잔액을 28 wei에서 4 wei로 줄였습니다(-85.7%). 총 유동성은 약 84.4% 감소했습니다.<sup>[[1]](#references)[[2]](#references)</sup>
- 3단계 (유동성 반등 sandwich): 대규모 스왑으로 tick이 약 839,189로 이동했습니다 (1 USDC ≈ 2.77e36 USDT). 유동성 추정치가 뒤집히며 약 16.8% 증가했고, 이로 인해 공격자는 sandwich를 통해 부풀려진 가격으로 되팔아 수익을 얻을 수 있었습니다.<sup>[[1]](#references)</sup>
- 사후 분석에서 확인된 수정 사항: idle balance 업데이트를 올림하도록 변경해, 반복되는 소액 출금으로 pool의 active balance가 계속 감소하는 현상을 방지합니다.<sup>[[1]](#references)</sup>

취약한 코드 한 줄의 단순화 버전(및 사후 분석에서 제안한 수정 사항).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## 헌팅 체크리스트

- 풀이 non-zero hooks 주소를 사용하나요? 어떤 콜백이 활성화되어 있나요?
- 커스텀 수학 연산을 사용하는 스왑별 재분배/리밸런싱이 있나요? 틱/임계값 로직은 어떤가요?
- 나눗셈/mulDiv, Q64.96 변환, SafeCast는 어디에서 사용되나요? 반올림 방식이 전역적으로 일관적인가요?
- 경계를 간신히 넘으면서 유리한 반올림 분기로 이어지는 Δin을 만들 수 있나요? 양방향과 exactInput, exactOutput을 모두 테스트하세요.
- 훅이 나중에 출금할 수 있도록 호출자별 크레딧이나 델타를 추적하나요? 잔여분이 상쇄되는지 확인하세요.

## References

- [1] [Bunni 익스플로잇 사후 분석 (2025년 9월)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 익스플로잇: 전체 해킹 분석](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 익스플로잇: 유동성 결함으로 830만 달러 유출 (요약)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core 백서](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 배경 (QuillAudits 연구)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Uniswap v4 Core의 유동성 메커니즘](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Uniswap v4 Core의 스왑 메커니즘](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks 및 보안 고려 사항](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 Core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 Core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 Core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 Core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
