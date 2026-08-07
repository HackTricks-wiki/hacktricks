# Smart Contract Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing은 contract code에 작은 변경 사항(mutant)을 체계적으로 적용한 후 test suite를 다시 실행하여 "tests를 테스트"합니다. test가 실패하면 mutant는 killed됩니다. tests가 계속 통과하면 mutant는 살아남으며, 이는 line/branch coverage로는 감지할 수 없는 blind spot을 드러냅니다.

핵심 아이디어: Coverage는 code가 실행되었음을 보여주고, mutation testing은 동작이 실제로 assert되었는지를 보여줍니다.<sup>[[2]](#references)</sup>

## Coverage가 오해를 불러일으킬 수 있는 이유

다음과 같은 간단한 threshold check를 살펴보겠습니다:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
임계값보다 작은 값과 큰 값만 확인하는 Unit tests는 동등성 경계(`==`)에 대한 검증 없이도 100% line/branch coverage를 달성할 수 있습니다. `deposit >= 2 ether`로 refactor하더라도 이러한 tests는 계속 통과하므로, protocol logic이 조용히 손상될 수 있습니다.<sup>[[2]](#references)</sup>

Mutation testing은 조건을 mutate하고 tests가 실패하는지 검증하여 이러한 gap을 드러냅니다.

Smart contracts에서 surviving mutants는 다음과 같은 누락된 check와 자주 연결됩니다:
- Authorization 및 role 경계
- Accounting/value-transfer invariant
- Revert conditions 및 failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## 가장 높은 security signal을 제공하는 mutation operators

Contract auditing에 유용한 mutation classes:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: statements를 `revert()`로 교체하여 실행되지 않은 paths를 노출
- **Medium severity**: lines를 주석 처리하거나 logic을 제거하여 검증되지 않은 side effects를 확인
- **Low severity**: `>=` -> `>` 또는 `+` -> `-`와 같은 미묘한 operator 또는 constant 교체
- 기타 일반적인 edits: assignment replacement, boolean flips, condition negation, type changes

실질적인 목표는 의미 있는 모든 mutants를 kill하고, 관련이 없거나 semantically equivalent한 surviving mutants는 명시적으로 정당화하는 것입니다.

## regex보다 syntax-aware mutation이 더 나은 이유

이전 mutation engines는 regex 또는 line-oriented rewrites에 의존했습니다. 작동하기는 하지만 중요한 한계가 있습니다:<sup>[[1]](#references)</sup>
- Multi-line statements를 안전하게 mutate하기 어려움
- Language structure를 이해하지 못하므로 comments/tokens가 잘못 대상으로 지정될 수 있음
- 취약한 line에서 가능한 모든 variant를 생성하면 runtime이 크게 낭비됨

AST- 또는 Tree-sitter-based tooling은 raw lines 대신 structured nodes를 대상으로 지정하여 이를 개선합니다:<sup>[[1]](#references)</sup>
- **slither-mutate**는 Slither의 Solidity AST를 사용<sup>[[4]](#references)</sup>
- **mewt**는 language-agnostic core로 Tree-sitter를 사용<sup>[[6]](#references)</sup>
- **MuTON**은 `mewt`를 기반으로 하며 FunC, Tolk, Tact와 같은 TON languages에 first-class support를 추가<sup>[[7]](#references)</sup>

이를 통해 multi-line constructs와 expression-level mutations를 regex-only approaches보다 훨씬 안정적으로 처리할 수 있습니다.

## slither-mutate로 mutation testing 실행

Requirements: Slither v0.10.2+.

- Options와 mutators 나열:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 예제 (결과를 캡처하고 전체 로그를 보관):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry를 사용하지 않는 경우 `--test-cmd`를 테스트 실행 방법으로 변경하세요(예: `npx hardhat test`, `npm test`).

Artifacts는 기본적으로 `./mutation_campaign`에 저장됩니다. 포착되지 않은(surviving) mutants는 검사를 위해 해당 위치에 복사됩니다.<sup>[[5]](#references)</sup>

### 출력 이해하기

Report 줄은 다음과 같은 형식입니다:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 대괄호 안의 tag는 mutator alias입니다(예: `CR` = Comment Replacement).
- `UNCAUGHT`는 변형된 동작에서 테스트가 통과했다는 의미입니다 → assertion 누락입니다.

## 실행 시간 줄이기: 영향도 높은 mutant 우선 처리

Mutation campaign은 몇 시간 또는 며칠이 걸릴 수 있습니다. 비용을 줄이기 위한 팁:<sup>[[1]](#references)[[2]](#references)</sup>
- 범위: 먼저 중요한 contract/디렉터리만 대상으로 시작한 다음 확장합니다.
- Mutator 우선순위 지정: 한 줄에서 높은 우선순위의 mutant가 살아남으면(예: `revert()` 또는 comment-out), 해당 줄의 낮은 우선순위 variant는 건너뜁니다.
- 2단계 campaign 사용: 먼저 집중된 빠른 테스트를 실행한 다음, 전체 suite에서는 `UNCAUGHT` mutant만 다시 테스트합니다.
- 가능한 경우 mutation target을 특정 테스트 명령에 매핑합니다(예: auth code -> auth tests).
- 시간이 부족하면 high/medium severity mutant로 campaign을 제한합니다.
- test runner가 지원하면 테스트를 병렬화하고, dependency/build를 cache합니다.
- Fail-fast: 변경 사항이 assertion gap을 명확히 보여주면 조기에 중지합니다.

실행 시간 계산은 가혹합니다. `1000 mutants x 5-minute tests ~= 83 hours`이므로 campaign 설계는 mutator 자체만큼 중요합니다.<sup>[[1]](#references)</sup>

## 지속적인 campaign 및 대규모 triage

기존 workflow의 한 가지 약점은 결과를 `stdout`에만 출력한다는 점입니다. 장시간 campaign에서는 이로 인해 일시 중지/재개, filtering, review가 더 어려워집니다.<sup>[[1]](#references)</sup>

`mewt`/`MuTON`은 mutant와 결과를 SQLite 기반 campaign에 저장하여 이를 개선합니다. 이점:<sup>[[1]](#references)</sup>
- 진행 상황을 잃지 않고 장시간 실행을 일시 중지하고 재개
- 특정 file 또는 mutation class에서 `UNCAUGHT` mutant만 filtering
- review tooling을 위해 결과를 SARIF로 export/translate
- raw terminal log 대신 AI-assisted triage에 더 작고 filtering된 결과 set 제공

Mutation testing이 일회성 수동 review가 아니라 audit pipeline의 일부가 되면 지속적인 결과가 특히 유용합니다.

## 살아남은 mutant를 위한 triage workflow

1) 변형된 line과 동작을 검사합니다.
- 변형된 line을 적용하고 집중된 테스트를 실행하여 local에서 재현합니다.

2) return value뿐만 아니라 state를 assertion하도록 테스트를 강화합니다.
- equality 경계 확인을 추가합니다(예: threshold `==` 테스트).
- post-condition을 assertion합니다: balance, total supply, authorization effect, emitted event.

3) 지나치게 허용적인 mock을 현실적인 동작으로 교체합니다.
- mock이 on-chain에서 발생하는 transfer, failure path, event emission을 적용하도록 합니다.

4) fuzz test에 invariant를 추가합니다.
- 예: value 보존, 음수가 아닌 balance, authorization invariant, 해당되는 경우 monotonic supply.

5) true positive와 semantic no-op을 구분합니다.
- 예: `x > 0` -> `x != 0`은 `x`가 unsigned일 때 의미가 없습니다.

6) survivor가 제거되거나 명시적으로 정당화될 때까지 campaign을 다시 실행합니다.

## 사례 연구: 누락된 state assertion 발견(Arkis protocol)

Arkis DeFi protocol audit 중 수행한 mutation campaign에서 다음과 같은 survivor가 발견되었습니다:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
할당을 주석 처리해도 테스트가 깨지지 않았으며, 이는 누락된 post-state assertions를 입증합니다. 근본 원인은 실제 token transfer를 검증하지 않고 사용자가 제어하는 `_cmd.value`를 신뢰한 것입니다. 공격자는 예상된 transfer와 실제 transfer를 불일치시켜 자금을 고갈시킬 수 있었습니다. 결과적으로 protocol solvency에 대한 high severity risk가 발생합니다.<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: value transfer, accounting 또는 access control에 영향을 주는 survivors는 kill될 때까지 high-risk로 취급하세요.

## 모든 mutant를 kill하기 위해 테스트를 맹목적으로 생성하지 마세요

Mutation-driven test generation은 현재 구현이 잘못된 경우 역효과를 낼 수 있습니다. 예를 들어 `priority >= 2`를 `priority > 2`로 mutation하면 동작이 바뀌지만, 올바른 수정이 항상 "`priority == 2`에 대한 테스트를 작성하는 것"은 아닙니다. 해당 동작 자체가 bug일 수도 있습니다.<sup>[[1]](#references)</sup>

더 안전한 workflow:
- surviving mutants를 사용해 모호한 요구사항 식별
- specs, protocol docs 또는 reviewers를 통해 예상 동작 검증
- 그런 다음에만 해당 동작을 test/invariant로 인코딩

그렇지 않으면 구현 과정에서 발생한 우연한 동작을 test suite에 하드코딩하여 false confidence를 얻을 위험이 있습니다.

## Practical checklist

- targeted campaign 실행:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 가능한 경우 regex-only mutation보다 syntax-aware mutators(AST/Tree-sitter) 사용
- survivors를 triage하고 mutation된 동작에서 실패할 tests/invariants 작성
- balances, supply, authorizations 및 events assertion
- boundary tests 추가(`==`, overflows/underflows, zero-address, zero-amount, empty arrays)
- 비현실적인 mocks 교체; failure modes 시뮬레이션
- tooling이 지원하면 results를 persist하고, triage 전에 uncaught mutants 필터링
- runtime을 관리 가능한 수준으로 유지하기 위해 two-phase 또는 per-target campaigns 사용
- 모든 mutants가 kill되거나 comments와 rationale을 통해 정당화될 때까지 반복

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
