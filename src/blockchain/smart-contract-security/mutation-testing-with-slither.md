# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing은 Solidity 코드에 작은 변경사항(mutants)을 체계적으로 주입하고 테스트 스위트를 다시 실행함으로써 "테스트를 테스트"합니다. 테스트가 실패하면 mutant는 죽고(killed), 테스트가 여전히 통과하면 mutant는 살아남아 라인/브랜치 커버리지가 감지하지 못하는 테스트 스위트의 맹점을 드러냅니다.

핵심 아이디어: 커버리지는 코드가 실행되었다는 사실만 보여주고, mutation testing은 동작이 실제로 단언(asserted)되는지를 보여줍니다.

## 커버리지가 오도할 수 있는 이유

Consider this simple threshold check:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
단위 테스트가 임계값 아래의 값과 위의 값만 검사하는 경우, 라인/브랜치 커버리지가 100%에 도달할 수 있지만 동등성 경계(==)를 확인하지 못할 수 있습니다. `deposit >= 2 ether`로 리팩터링해도 이러한 테스트는 여전히 통과하여 프로토콜 로직을 조용히 깨뜨릴 수 있습니다.

Mutation testing은 조건을 변형시키고 테스트가 실패하는지 확인함으로써 이 간극을 드러냅니다.

## Common Solidity mutation operators

Slither’s mutation engine은 다음과 같은 여러 작은 의미 변경 수정을 적용합니다:
- 연산자 교체: `+` ↔ `-`, `*` ↔ `/`, 등
- 할당 연산자 교체: `+=` → `=`, `-=` → `=`
- 상수 교체: 0이 아닌 값 → `0`, `true` ↔ `false`
- `if`/루프 내부 조건의 부정/교체
- 전체 라인 주석 처리 (CR: Comment Replacement)
- 한 줄을 `revert()`로 교체
- 데이터 타입 교체: 예: `int128` → `int64`

목표: 생성된 뮤턴트의 100%를 kill 하거나, 살아남은 뮤턴트에 대해 명확한 근거로 정당화하세요.

## Running mutation testing with slither-mutate

요구사항: Slither v0.10.2+.

- 옵션과 mutators 목록:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 예제 (결과를 캡처하고 전체 로그를 보관):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry를 사용하지 않는다면, `--test-cmd`를 테스트 실행 방법(예: `npx hardhat test`, `npm test`)으로 대체하세요.

아티팩트와 보고서는 기본적으로 `./mutation_campaign`에 저장됩니다. 포착되지 않은(생존한) mutants는 검사 목적으로 그곳에 복사됩니다.

### 출력 이해하기

보고서 행은 다음과 같습니다:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 대괄호 안의 태그는 뮤테이터 별칭입니다(예: `CR` = Comment Replacement).
- `UNCAUGHT`는 변형된 동작에서 테스트가 통과했음을 의미합니다 → 누락된 assertion.

## Reducing runtime: prioritize impactful mutants

Mutation 캠페인은 수시간에서 수일까지 걸릴 수 있습니다. 비용을 줄이기 위한 팁:
- Scope: 우선 중요한 contracts/디렉터리만 대상으로 시작한 후 확장하세요.
- Prioritize mutators: 한 줄에서 우선순위가 높은 뮤턴트가 생존하면(예: 전체 줄이 주석 처리된 경우) 그 줄에 대해 우선순위가 낮은 변형은 건너뛸 수 있습니다.
- 테스트를 러너가 허용하면 병렬화하고; 의존성/빌드를 캐시하세요.
- Fail-fast: 변경이 명백히 assertion의 공백을 드러낼 때 조기에 중단하세요.

## Triage workflow for surviving mutants

1) 변형된 줄과 동작을 검사하세요.
- 해당 변형된 줄을 적용하고 집중 테스트를 실행해 로컬에서 재현하세요.

2) 반환값뿐 아니라 상태를 검증하도록 테스트를 강화하세요.
- 동등성/경계 검사를 추가하세요(예: 임계값 테스트 `==`).
- 사후 조건을 검증하세요: 잔액, 총 공급량, 권한 영향 및 발생한 이벤트 등.

3) 지나치게 관대한 mocks를 현실적인 동작으로 교체하세요.
- 모의 객체가 온체인에서 발생하는 전송, 실패 경로 및 이벤트 발생을 강제하도록 하세요.

4) 퍼즈(fuzz) 테스트를 위한 불변식(invariants)을 추가하세요.
- 예: 가치 보존, 음수 불가 잔액, 권한 불변식, 적용 가능한 경우 단조 증가하는 공급량 등.

5) slither-mutate를 재실행하여 생존자들이 제거되거나 명확히 정당화될 때까지 반복하세요.

## Case study: revealing missing state assertions (Arkis protocol)

Arkis DeFi protocol에 대한 감사 중 진행된 mutation 캠페인은 다음과 같은 생존자를 드러냈습니다:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
주석 처리로 할당문이 제거되어도 테스트가 통과했는데, 이는 사후 상태 검증(post-state assertions)이 누락되었음을 증명한다. 근본 원인: 실제 토큰 전송을 검증하지 않고 사용자 제어 `_cmd.value`를 신뢰했다. 공격자는 기대되는 전송과 실제 전송을 비동기화하여 자금을 유출할 수 있다. 결과: 프로토콜의 지급능력(solency)에 대한 높은 심각도 위험.

지침: 가치 전송(value transfers), 회계(accounting), 또는 접근 제어에 영향을 미치는 살아남은 변이(survivors)는 제거(killed)될 때까지 고위험으로 취급하라.

## 실무 체크리스트

- 대상 캠페인 실행:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 생존한 변이를 분류(triage)하고, 변형된 동작에서 실패할 테스트/불변식(invariants)을 작성하라.
- 잔액, 공급량, 권한, 이벤트를 검증하라.
- 경계 테스트 추가 (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- 비현실적인 mocks를 대체하고, 실패 모드를 시뮬레이션하라.
- 모든 mutants가 제거(killed)되거나 주석과 근거로 정당화될 때까지 반복하라.

## 참고자료

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
