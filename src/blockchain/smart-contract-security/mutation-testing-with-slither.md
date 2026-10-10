# 스마트 컨트랙트 변이 테스트 (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

변이 테스트는 컨트랙트 코드에 작은 변경(mutant)을 체계적으로 적용한 뒤 테스트 스위트를 다시 실행하여 "테스트를 테스트"합니다. 테스트가 실패하면 mutant는 제거됩니다. 테스트가 계속 통과하면 mutant가 살아남으며, 이는 라인/분기 커버리지로는 감지할 수 없는 사각지대를 드러냅니다.

핵심 아이디어: 커버리지는 코드가 실행되었음을 보여주고, 변이 테스트는 동작이 실제로 검증되는지를 보여줍니다.<sup>[[2]](#references)</sup>

## 커버리지가 오해를 불러일으킬 수 있는 이유

다음의 간단한 임계값 검사를 살펴보세요:

```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
    if (deposit >= 1 ether) {
        return true;
    } else {
        return false;
    }
}
```

값이 임계값보다 작을 때와 클 때만 확인하는 단위 테스트는 동등 경계(`==`)를 검증하지 않으면서도 라인/브랜치 커버리지 100%를 달성할 수 있습니다. `deposit >= 2 ether`로 리팩터링해도 이런 테스트는 계속 통과하므로 프로토콜 로직이 조용히 깨질 수 있습니다.<sup>[[2]](#references)</sup>

Mutation testing은 조건을 변이시키고 테스트가 실패하는지 확인해 이러한 간극을 드러냅니다.

스마트 컨트랙트에서 살아남은 뮤턴트는 다음 항목의 검증 누락과 자주 연관됩니다.
- 권한 부여 및 역할 경계
- 회계/값 전송 불변 조건
- revert 조건 및 실패 경로
- 경계 조건 (`==`, 0 값, 빈 배열, 최댓값/최솟값)

## 보안 신호가 가장 강한 mutation operator

컨트랙트 감사를 위한 유용한 변이 클래스:<sup>[[1]](#references)[[2]](#references)</sup>
- **심각도 높음**: 문을 `revert()`로 대체해 실행되지 않은 경로를 드러냄
- **심각도 중간**: 줄을 주석 처리하거나 로직을 제거해 검증되지 않은 부수 효과를 드러냄
- **심각도 낮음**: `>=` -> `>` 또는 `+` -> `-` 같은 미묘한 연산자 또는 상수 교체
- 그 외 일반적인 수정: 할당문 교체, 불리언 반전, 조건 부정, 타입 변경

실질적인 목표는 의미 있는 뮤턴트를 모두 제거하고, 중요하지 않거나 의미적으로 동등한 뮤턴트가 살아남은 경우 그 이유를 명확히 설명하는 것입니다.

## 정규식보다 구문 인식 mutation이 더 나은 이유

이전 mutation 엔진은 정규식이나 줄 단위 재작성에 의존했습니다. 작동은 하지만 중요한 한계가 있습니다.<sup>[[1]](#references)</sup>
- 여러 줄에 걸친 문을 안전하게 변이하기 어려움
- 언어 구조를 이해하지 못하므로 주석/토큰을 잘못 대상으로 삼을 수 있음
- 약한 줄에서 가능한 모든 변형을 생성하면 런타임이 크게 낭비됨

AST 또는 Tree-sitter 기반 도구는 원시 줄 대신 구조화된 노드를 대상으로 삼아 이를 개선합니다.<sup>[[1]](#references)</sup>
- **slither-mutate**는 Slither의 Solidity AST를 사용합니다.<sup>[[4]](#references)</sup>
- **mewt**는 언어에 구애받지 않는 핵심으로 Tree-sitter를 사용합니다.<sup>[[6]](#references)</sup>
- **MuTON**은 `mewt`를 기반으로 하며 FunC, Tolk, Tact 같은 TON 언어를 기본 지원합니다.<sup>[[7]](#references)</sup>

따라서 여러 줄로 된 구문과 표현식 수준의 변이를 정규식만 사용하는 방식보다 훨씬 안정적으로 처리할 수 있습니다.

## slither-mutate로 mutation testing 실행하기

요구 사항: Slither v0.10.2 이상.

- 옵션과 mutator 목록 보기:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Foundry 예시(결과를 캡처하고 전체 로그를 보관):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Foundry를 사용하지 않는 경우, `--test-cmd`를 테스트 실행 방법(예: `npx hardhat test`, `npm test`)으로 바꾸세요.

Artifacts는 기본적으로 `./mutation_campaign`에 저장됩니다. 포착되지 않은(살아남은) mutants는 검사를 위해 해당 위치에 복사됩니다.<sup>[[5]](#references)</sup>

### 출력 이해하기

Report 줄은 다음과 같습니다:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- 대괄호 안의 태그는 mutator alias입니다(예: `CR` = Comment Replacement).
- `UNCAUGHT`는 변경된 동작에서도 테스트가 통과했음을 의미합니다 → assertion 누락입니다.

## 실행 시간 줄이기: 영향력 있는 mutant 우선 처리

Mutation campaign은 몇 시간 또는 며칠이 걸릴 수 있습니다. 비용을 줄이는 팁:<sup>[[1]](#references)[[2]](#references)</sup>
- 범위: 중요도가 높은 contract/directory만 대상으로 시작한 다음 범위를 넓힙니다.
- Mutator 우선순위 지정: 한 줄에서 우선순위가 높은 mutant가 살아남으면(예: `revert()` 또는 주석 처리), 해당 줄의 우선순위가 낮은 variant는 건너뜁니다.
- 2단계 campaign 실행: 먼저 범위를 좁힌 빠른 테스트를 실행한 다음, 전체 테스트 suite로 uncaught mutant만 다시 테스트합니다.
- 가능하면 mutation target을 특정 테스트 명령에 연결합니다(예: auth 코드 -> auth 테스트).
- 시간이 부족하면 심각도가 높거나 중간인 mutant만 대상으로 campaign을 제한합니다.
- 테스트 runner에서 허용하면 테스트를 병렬로 실행하고 dependency/build를 캐시합니다.
- Fail-fast: 변경으로 assertion 누락이 명확히 드러나면 조기에 중단합니다.

실행 시간 계산은 가혹합니다. `1000 mutants x 5-minute tests ~= 83 hours`이므로 campaign 설계는 mutator 자체만큼이나 중요합니다.<sup>[[1]](#references)</sup>

## 대규모 campaign 지속 및 분류

기존 workflow의 약점 중 하나는 결과를 `stdout`에만 출력하는 것입니다. 장시간 campaign에서는 이 때문에 일시 중지/재개, 필터링, 검토가 어려워집니다.<sup>[[1]](#references)</sup>

`mewt`/`MuTON`은 mutant와 결과를 SQLite 기반 campaign에 저장해 이 문제를 개선합니다. 장점:<sup>[[1]](#references)</sup>
- 진행 상황을 잃지 않고 장시간 실행을 일시 중지하고 재개
- 특정 파일 또는 mutation class의 uncaught mutant만 필터링
- 검토 도구용으로 결과를 SARIF로 내보내기/변환
- AI 지원 분류에 원시 terminal 로그 대신 작고 필터링된 결과 집합 제공

Mutation testing이 일회성 수동 검토가 아닌 audit pipeline의 일부가 되면 지속성 있는 결과가 특히 유용합니다.

## 살아남은 mutant 분류 workflow

1) 변경된 줄과 동작을 살펴봅니다.
   - 변경된 줄을 적용하고 범위를 좁힌 테스트를 실행해 로컬에서 재현합니다.

2) 반환값뿐 아니라 상태도 검증하도록 테스트를 강화합니다.
   - 동등 경계 검사 추가(예: threshold `==` 테스트).
   - 사후 조건 검증: 잔액, 총 supply, 권한 효과, 발생한 event.

3) 지나치게 관대한 mock을 실제 동작에 가깝게 바꿉니다.
   - mock이 on-chain에서 발생하는 transfer, 실패 경로, event 발생을 적용하는지 확인합니다.

4) Fuzz test에 invariant를 추가합니다.
   - 예: 가치 보존, 음수가 아닌 잔액, 권한 invariant, 해당되는 경우 supply의 단조성.

5) 실제 양성과 의미상 no-op을 구분합니다.
   - 예: `x > 0` -> `x != 0`은 `x`가 unsigned일 때 의미가 없습니다.

6) 살아남은 mutant가 제거되거나 명시적으로 정당화될 때까지 campaign을 다시 실행합니다.

## 사례 연구: 누락된 상태 assertion 발견(Arkis protocol)

Arkis DeFi protocol 감사 중 진행한 mutation campaign에서 다음과 같은 mutant가 살아남았습니다:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

주석 처리한 할당문 때문에 테스트가 실패하지 않았으며, 이는 사후 상태 어설션이 누락되었음을 입증합니다. 근본 원인은 코드가 실제 토큰 전송을 검증하지 않고 사용자가 제어하는 `_cmd.value`를 신뢰한 것입니다. 공격자는 예상 전송량과 실제 전송량을 불일치시켜 자금을 빼돌릴 수 있었습니다. 결과: 프로토콜 지급 능력에 대한 심각도가 높은 위험입니다.<sup>[[2]](#references)[[3]](#references)</sup>

지침: 가치 전송, 회계 또는 접근 제어에 영향을 미치는 생존 mutant는 제거될 때까지 고위험으로 취급하세요.

## 모든 mutant를 제거하는 테스트를 무작정 생성하지 마세요

현재 구현이 잘못된 경우, mutation 기반 테스트 생성은 역효과를 낼 수 있습니다. 예를 들어 `priority >= 2`를 `priority > 2`로 바꾸면 동작이 달라지지만, 올바른 수정 방법이 항상 "`priority == 2`인 테스트를 작성하는 것"은 아닙니다. 해당 동작 자체가 버그일 수도 있습니다.<sup>[[1]](#references)</sup>

더 안전한 작업 흐름:
- 살아남은 mutant를 사용해 요구사항이 모호한 부분을 찾습니다.
- 사양, 프로토콜 문서 또는 리뷰어를 통해 기대 동작을 검증합니다.
- 그런 다음에만 해당 동작을 테스트/불변 조건으로 표현합니다.

그렇지 않으면 구현상의 우연한 동작을 테스트 스위트에 고정해 잘못된 확신을 얻을 위험이 있습니다.

## 실용적인 체크리스트

- 범위를 좁힌 캠페인을 실행합니다:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- 사용 가능한 경우 정규식 전용 mutation보다 구문을 인식하는 mutator(AST/Tree-sitter)를 우선합니다.
- 살아남은 mutant를 분류하고, 변이된 동작에서 실패할 테스트/불변 조건을 작성합니다.
- 잔액, 공급량, 권한 부여 및 이벤트를 검증합니다.
- 경계값 테스트를 추가합니다(`==`, 오버플로/언더플로, zero-address, zero-amount, 빈 배열).
- 비현실적인 mock을 교체하고 실패 상황을 시뮬레이션합니다.
- 도구가 지원하면 결과를 저장하고, 분류 전에 잡히지 않은 mutant를 필터링합니다.
- 실행 시간을 관리할 수 있도록 2단계 또는 대상별 캠페인을 사용합니다.
- 모든 mutant가 제거되거나, 근거와 설명을 주석으로 남겨 정당화될 때까지 반복합니다.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
