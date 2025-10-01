# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing은 "tests your tests" 방식으로, Solidity 코드에 작은 변경사항(mutants)을 체계적으로 도입하고 test suite를 다시 실행합니다. 테스트가 실패하면 해당 mutant는 제거(killed)됩니다. 테스트가 여전히 통과하면 mutant는 생존하여 line/branch coverage로는 탐지할 수 없는 테스트 스위트의 맹점을 드러냅니다.

핵심 아이디어: Coverage는 코드가 실행되었음을 보여주고; mutation testing은 실제로 동작이 검증되었는지를 보여줍니다.

## 왜 Coverage는 오도할 수 있는가

다음의 간단한 임계값 체크를 살펴보자:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
단위 테스트가 임계값 아래와 위의 값만 검사하면, equality boundary (==)에 대한 어설션 없이도 라인/분기 커버리지 100%에 도달할 수 있습니다. `deposit >= 2 ether`로 리팩터링하면 이런 테스트를 통과해 프로토콜 로직이 은밀히 깨질 수 있습니다.

뮤테이션 테스트는 조건을 변형(mutate)하고 테스트가 실패하는지 확인함으로써 이 간극을 드러냅니다.

## 일반적인 Solidity mutation 연산자

Slither의 mutation 엔진은 다음과 같은 작은 의미 변경 편집을 적용합니다:
- 연산자 교체: `+` ↔ `-`, `*` ↔ `/`, 등
- 할당 교체: `+=` → `=`, `-=` → `=`
- 상수 교체: 0이 아닌 값 → `0`, `true` ↔ `false`
- `if`/루프 내부 조건 부정/교체
- 전체 라인 주석 처리 (CR: Comment Replacement)
- 한 줄을 `revert()`로 교체
- 데이터 타입 교체 예: `int128` → `int64`

목표: 생성된 뮤턴트 100%를 제거하거나, 생존한 뮤턴트에 대해 명확한 근거로 정당화하세요.

## slither-mutate로 뮤테이션 테스트 실행하기

요구사항: Slither v0.10.2+.

- 옵션 및 mutators 나열:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 예시 (결과를 캡처하고 전체 로그를 보관):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry를 사용하지 않는 경우 `--test-cmd`를 테스트를 실행하는 방식(예: `npx hardhat test`, `npm test`)으로 바꿔주세요.

아티팩트와 리포트는 기본적으로 `./mutation_campaign`에 저장됩니다. 검출되지 않은(생존한) mutants는 검사 목적으로 그곳에 복사됩니다.

### 출력 이해하기

리포트 행은 다음과 같습니다:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 대괄호 안의 태그는 뮤테이터 별칭입니다 (예: `CR` = Comment Replacement).
- `UNCAUGHT`는 변경된 동작 하에서 테스트가 통과했음을 의미합니다 → 누락된 assertion.

## Reducing runtime: prioritize impactful mutants

Mutation 캠페인은 몇 시간에서 며칠까지 걸릴 수 있습니다. 비용을 줄이기 위한 팁:
- Scope: 먼저 중요한 contracts/디렉터리만 대상으로 시작한 다음 확장하세요.
- Prioritize mutators: 한 줄에서 우선순위가 높은 mutant가 생존하면(예: 전체 줄이 주석 처리됨) 해당 줄에 대해 낮은 우선순위 변형은 건너뛸 수 있습니다.
- Parallelize tests if your runner allows it; cache dependencies/builds.
- Fail-fast: 변경이 명확히 assertion 간극을 보여줄 때 조기에 중단하세요.

## Triage workflow for surviving mutants

1) 변경된 라인과 동작을 검사하세요.
- 변경된 라인을 적용하고 집중된 테스트를 실행해 로컬에서 재현하세요.

2) 테스트를 강화해 반환값뿐 아니라 상태를 단언하세요.
- 동등성 경계 검사 추가(예: test threshold `==`).
- 사후 조건을 단언: 잔액, 총 공급량, 권한 효과, 발생한 이벤트 등.

3) 지나치게 관대한 mocks를 현실적인 동작으로 교체하세요.
- mocks가 온체인에서 발생하는 전송, 실패 경로, 이벤트 발생을 강제하는지 확인하세요.

4) fuzz 테스트를 위한 불변식 추가.
- 예: 가치 보존, 음수가 아닌 잔액, 권한 불변식, 적용 가능한 경우 단조 증가하는 공급 등.

5) 생존한 뮤턴트가 제거되거나 명시적으로 정당화될 때까지 slither-mutate를 다시 실행하세요.

## Case study: revealing missing state assertions (Arkis protocol)

Arkis DeFi protocol 감사 중 실행한 mutation 캠페인에서 다음과 같은 생존자들이 나타났습니다:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
주석 처리로 할당을 제거해도 테스트가 깨지지 않았으므로 post-state assertions가 누락되었음이 입증됨. 근본 원인: 실제 토큰 전송을 검증하지 않고 사용자 제어 `_cmd.value` 를 신뢰함. 공격자는 기대된 전송과 실제 전송을 비동기화시켜 자금을 유출할 수 있음. 결과: 프로토콜 지급능력(solency)에 대한 높은 심각도 위험.

Guidance: 값 전송, 회계(accounting) 또는 접근 제어에 영향을 주는 survivors는 삭제(kill)될 때까지 고위험으로 취급하라.

## 실무 체크리스트

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Triage survivors and write tests/invariants that would fail under the mutated behavior.
- 잔액, 공급(supply), 권한(authorizations), 및 이벤트를 검증(assert)하라.
- 경계 테스트 추가 (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- 비현실적인 mocks를 교체하고 실패 모드를 시뮬레이션하라.
- 모든 mutants가 kill되거나 주석과 근거로 정당화될 때까지 반복하라.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
