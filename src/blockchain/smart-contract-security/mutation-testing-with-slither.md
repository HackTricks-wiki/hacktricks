# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing은 Solidity 코드에 작은 변경(mutants)을 체계적으로 도입하고 테스트 스위트를 다시 실행함으로써 "테스트를 테스트"합니다. 테스트가 실패하면 해당 뮤턴트는 killed됩니다. 테스트가 여전히 통과하면 뮤턴트는 살아남아 line/branch coverage로는 탐지할 수 없는 테스트 스위트의 맹점을 드러냅니다.

핵심 아이디어: Coverage는 코드가 실행되었음을 보여주고; mutation testing은 동작이 실제로 단언(asserted)되었는지를 보여줍니다.

## Coverage가 오도할 수 있는 이유

다음의 간단한 threshold 검사를 고려해보자:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit tests that only check a value below and a value above the threshold can reach 100% line/branch coverage while failing to assert the equality boundary (==). A refactor to `deposit >= 2 ether` would still pass such tests, silently breaking protocol logic.

Mutation testing exposes this gap by mutating the condition and verifying your tests fail.

## Common Solidity mutation operators

Slither’s mutation engine applies many small, semantics-changing edits, such as:
- Operator replacement: `+` ↔ `-`, `*` ↔ `/`, etc.
- Assignment replacement: `+=` → `=`, `-=` → `=`
- Constant replacement: non-zero → `0`, `true` ↔ `false`
- Condition negation/replacement inside `if`/loops
- Comment out whole lines (CR: Comment Replacement)
- Replace a line with `revert()`
- Data type swaps: e.g., `int128` → `int64`

Goal: Kill 100% of generated mutants, or justify survivors with clear reasoning.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 예제 (결과 캡처 및 전체 로그 보관):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry를 사용하지 않는 경우, `--test-cmd`을(를) 테스트 실행 방법(예: `npx hardhat test`, `npm test`)으로 바꿔주세요.

아티팩트와 리포트는 기본적으로 `./mutation_campaign`에 저장됩니다. 검출되지 않은(생존한) mutants는 검사를 위해 그곳에 복사됩니다.

### 출력 이해하기

리포트 라인은 다음과 같습니다:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 대괄호 안의 태그는 뮤테이터 별칭입니다 (예: `CR` = Comment Replacement).
- `UNCAUGHT`는 변형된 동작 하에서 테스트가 통과했음을 의미합니다 → 누락된 assertion.

## 실행 시간 단축: 영향력 있는 뮤턴트 우선

Mutation 캠페인은 수시간에서 수일이 걸릴 수 있습니다. 비용을 줄이기 위한 팁:
- 범위: 핵심 contracts/디렉토리부터 시작한 뒤 확장하세요.
- 뮤테이터 우선순위 지정: 한 줄에서 우선순위가 높은 뮤턴트가 생존하는 경우(예: 전체 줄 주석 처리) 해당 줄의 낮은 우선순 변형은 건너뛸 수 있습니다.
- 러너에서 허용하면 테스트를 병렬화하세요; 의존성/빌드를 캐시하세요.
- Fail-fast: 변경이 명백히 assertion 격차를 보여주면 조기에 중단하세요.

## 생존한 뮤턴트에 대한 트리아지 워크플로우

1) 변경된 줄과 동작을 검사합니다.
- 변경된 줄을 적용하고 특정 테스트를 실행해 로컬에서 재현하세요.

2) 테스트를 강화하여 상태(state)를 단언(assert)하세요, 반환값만이 아니라.
- 동등성 경계 검사 추가(예: 임계값 `==` 테스트).
- 후조건을 단언: 잔액, 총 공급량(total supply), 권한 영향(authorization effects), 발생한 이벤트(emitted events).

3) 지나치게 관대한 mocks를 현실적인 동작으로 교체하세요.
- mocks가 체인 상에서 발생하는 전송(transfers), 실패 경로(failure paths), 이벤트 발생(event emissions)을 강제하도록 하세요.

4) 퍼즈(fuzz) 테스트를 위한 불변성(invariants)을 추가하세요.
- 예: 가치 보존(conservation of value), 음수 불가 잔액(non-negative balances), 권한 불변성, 적용 가능한 경우 단조 증가하는 공급량(monotonic supply).

5) slither-mutate를 다시 실행하여 생존자가 제거되거나 명확히 정당화될 때까지 반복하세요.

## 사례 연구: 누락된 상태 단언 드러내기 (Arkis protocol)

Arkis DeFi protocol의 감사 중 수행된 뮤테이션 캠페인에서 다음과 같은 생존자가 나타났습니다:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
할당문을 주석 처리해도 테스트가 깨지지 않았는데, 이는 사후 상태 검증(post-state assertions)이 누락되었음을 증명한다. 근본 원인: 코드가 실제 토큰 전송을 검증하지 않고 사용자 제어 `_cmd.value`를 신뢰했다. 공격자는 기대된 전송과 실제 전송을 비동기화시켜 자금을 탈취할 수 있다. 결과: 프로토콜 지급능력에 대한 높은 심각도 위험.

지침: 가치 전송(value transfers), 회계(accounting) 또는 접근 제어(access control)에 영향을 미치는 survivors는 제거(killed)될 때까지 고위험으로 간주하라.

## 실무 체크리스트

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Triage survivors and write tests/invariants that would fail under the mutated behavior.
- Assert balances, supply, authorizations, and events.
- Add boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Replace unrealistic mocks; simulate failure modes.
- Iterate until all mutants are killed or justified with comments and rationale.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
