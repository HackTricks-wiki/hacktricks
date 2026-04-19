# Smart Contracts용 Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing은 계약 코드에 작은 변화(mutants)를 체계적으로 주입하고 test suite를 다시 실행함으로써 "tests your tests"를 수행합니다. test가 실패하면 mutant는 killed 됩니다. tests가 여전히 통과하면 mutant는 survive 하며, line/branch coverage로는 감지할 수 없는 blind spot을 드러냅니다.

Key idea: Coverage는 code가 실행되었는지를 보여주고; mutation testing은 behavior가 실제로 assert되는지를 보여줍니다.

## Why coverage can deceive

이 간단한 threshold check를 보자:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
단위 테스트가 임계값 아래의 값과 임계값 위의 값만 확인하면, equality 경계(`==`)를 검증하지 못한 채 100% line/branch coverage에 도달할 수 있습니다. `deposit >= 2 ether`로의 refactor도 이런 테스트를 통과할 수 있으며, 프로토콜 logic을 조용히 깨뜨릴 수 있습니다.

Mutation testing은 condition을 mutating하고 테스트가 실패하는지 검증함으로써 이 gap을 드러냅니다.

smart contract의 경우, 살아남은 mutant는 자주 다음 항목 주변의 누락된 check와 연결됩니다:
- Authorization 및 role 경계
- Accounting/value-transfer invariant
- Revert condition 및 failure path
- Boundary condition (`==`, zero values, empty arrays, max/min values)

## 가장 높은 security signal을 가진 Mutation operator

contract auditing에 유용한 mutation class:
- **High severity**: 실행되지 않은 path를 드러내기 위해 statement를 `revert()`로 교체
- **Medium severity**: 검증되지 않은 side effect를 드러내기 위해 line 주석 처리 / logic 제거
- **Low severity**: `>=` -> `>` 또는 `+` -> `-` 같은 미묘한 operator나 constant 교체
- 기타 일반적인 edit: assignment replacement, boolean flip, condition negation, type change

실질적인 목표는 의미 있는 모든 mutant를 kill하고, 살아남은 mutant가 무관하거나 의미적으로 동등함을 명시적으로 정당화하는 것입니다.

## regex보다 syntax-aware mutation이 더 나은 이유

초기 mutation engine은 regex나 line-oriented rewrite에 의존했습니다. 그것도 동작은 하지만, 중요한 한계가 있습니다:
- multi-line statement를 안전하게 mutating하기 어렵습니다
- language structure를 이해하지 못하므로 comment/token이 잘못 대상이 될 수 있습니다
- 약한 line에서 가능한 모든 variant를 생성하면 runtime이 크게 낭비됩니다

AST- 또는 Tree-sitter 기반 tooling은 raw line 대신 structured node를 대상으로 삼아 이를 개선합니다:
- **slither-mutate**는 Slither의 Solidity AST를 사용합니다
- **mewt**는 language-agnostic core로 Tree-sitter를 사용합니다
- **MuTON**은 `mewt`를 기반으로 하며 FunC, Tolk, Tact 같은 TON language에 대한 first-class 지원을 추가합니다

이로 인해 multi-line construct와 expression-level mutation이 regex-only 접근보다 훨씬 더 신뢰할 수 있습니다.

## slither-mutate로 mutation testing 실행하기

요구사항: Slither v0.10.2+.

- option과 mutator 목록 보기:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry example (결과를 캡처하고 전체 로그를 유지):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry를 사용하지 않는다면 `--test-cmd`를 테스트를 실행하는 방식으로 바꾸세요(예: `npx hardhat test`, `npm test`).

Artifacts는 기본적으로 `./mutation_campaign`에 저장됩니다. 포착되지 않은(생존한) mutants는 검사를 위해 그곳으로 복사됩니다.

### Understanding the output

Report lines look like:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 대괄호 안의 태그는 mutator alias입니다(예: `CR` = Comment Replacement).
- `UNCAUGHT`는 mutated behavior에서도 tests가 통과했다는 뜻입니다 → assertion이 누락됨.

## runtime 줄이기: 영향력 큰 mutants 우선순위 지정

Mutation campaigns는 몇 시간 또는 며칠이 걸릴 수 있습니다. 비용을 줄이는 팁:
- Scope: 중요한 contracts/directories부터 시작한 뒤, 그다음 확장합니다.
- Mutators 우선순위 지정: 한 line에서 우선순위가 높은 mutant가 살아남으면(예: `revert()` 또는 comment-out), 그 line의 낮은 우선순위 variant는 건너뜁니다.
- 두 단계 campaign 사용: 먼저 focused/fast tests를 실행하고, 그다음 full suite로 uncaught mutants만 다시 테스트합니다.
- 가능하면 mutation targets를 특정 test command에 매핑합니다(예: auth code -> auth tests).
- 시간이 촉박하면 high/medium severity mutants만 대상으로 제한합니다.
- runner가 허용하면 tests를 parallelize하고, dependencies/builds는 cache합니다.
- Fail-fast: 변경이 assertion gap을 명확히 보여주면 조기에 중단합니다.

runtime 계산은 매우 가혹합니다: `1000 mutants x 5-minute tests ~= 83 hours`이므로, campaign 설계가 mutator 자체만큼 중요합니다.

## Persistent campaigns 및 대규모 triage

이전 workflow의 한 가지 약점은 결과를 `stdout`에만 덤프한다는 점입니다. 긴 campaign에서는 pause/resume, filtering, review가 더 어려워집니다.

`mewt`/`MuTON`은 mutants와 outcomes를 SQLite-backed campaigns에 저장함으로써 이를 개선합니다. 장점:
- 진행 상황을 잃지 않고 긴 run을 pause 및 resume
- 특정 file 또는 mutation class에서 uncaught mutants만 filter
- review tooling용으로 결과를 SARIF로 export/translate
- AI-assisted triage에 raw terminal logs 대신 더 작고 필터링된 result set 제공

Persistent results는 mutation testing이 일회성 manual review가 아니라 audit pipeline의 일부가 될 때 특히 유용합니다.

## 살아남은 mutants를 위한 triage workflow

1) mutated line과 behavior를 검토합니다.
- mutated line을 적용한 뒤 focused test를 실행해 로컬에서 재현합니다.

2) return value만이 아니라 state를 assertion하도록 tests를 강화합니다.
- equality-boundary checks를 추가합니다(예: threshold `==` 테스트).
- post-conditions를 assertion합니다: balances, total supply, authorization effects, emitted events.

3) 지나치게 permissive한 mocks를 현실적인 behavior로 교체합니다.
- mocks가 on-chain에서 발생하는 transfers, failure paths, event emissions를 강제하도록 합니다.

4) fuzz tests에 invariants를 추가합니다.
- 예: 가치 보존, 음수가 아닌 balances, authorization invariants, 적용 가능한 경우 monotonic supply.

5) true positives와 semantic no-ops를 분리합니다.
- 예: `x > 0` -> `x != 0`는 `x`가 unsigned일 때 의미가 없습니다.

6) survivors가 죽거나 명시적으로 정당화될 때까지 campaign을 다시 실행합니다.

## Case study: 누락된 state assertions 드러내기 (Arkis protocol)

Arkis DeFi protocol 감사 중의 mutation campaign에서 다음과 같은 survivors가 발견되었습니다:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
할당을 주석 처리해도 테스트가 깨지지 않았고, 이는 post-state assertions가 빠져 있음을 증명한다. 근본 원인: 코드가 실제 token transfers를 검증하는 대신 사용자 제어 `_cmd.value`를 신뢰했다. 공격자는 기대한 transfer와 실제 transfer를 불일치하게 만들어 자금을 drain할 수 있었다. 결과: protocol solvency에 대한 high severity risk.

Guidance: value transfers, accounting, 또는 access control에 영향을 주는 survivors는 kill될 때까지 high-risk로 취급하라.

## 모든 mutant를 죽이기 위해 테스트를 무작정 생성하지 말 것

mutation-driven test generation은 현재 구현이 잘못된 경우 역효과를 낼 수 있다. 예: `priority >= 2`를 `priority > 2`로 mutating하면 behavior가 바뀌지만, 올바른 fix가 항상 " `priority == 2`에 대한 test를 작성하라"는 뜻은 아니다. 그 behavior 자체가 bug일 수 있다.

더 안전한 workflow:
- surviving mutants를 사용해 ambiguous requirements를 식별
- specs, protocol docs, 또는 reviewers로부터 expected behavior를 검증
- 그 다음에야 그 behavior를 test/invariant로 encode

그렇지 않으면, implementation accident를 test suite에 hard-coding하고 false confidence를 얻을 위험이 있다.

## Practical checklist

- targeted campaign을 실행:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 가능하면 regex-only mutation보다 syntax-aware mutators(AST/Tree-sitter)를 우선 사용.
- survivors를 triage하고, mutated behavior 아래에서 실패할 tests/invariants를 작성.
- balances, supply, authorizations, events를 assert.
- boundary tests(`==`, overflows/underflows, zero-address, zero-amount, empty arrays)를 추가.
- 비현실적인 mocks를 교체하고, failure modes를 simulate.
- tooling이 지원하면 results를 persist하고, triage 전에 uncaught mutants를 filter.
- runtime을 관리 가능하게 유지하기 위해 two-phase 또는 per-target campaigns를 사용.
- 모든 mutants가 죽거나, comments와 rationale로 정당화될 때까지 iterate.

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
