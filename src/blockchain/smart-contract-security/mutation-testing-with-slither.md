# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" by systematically introducing small changes (mutants) into your Solidity code and re-running your test suite. If a test fails, the mutant is killed. If the tests still pass, the mutant survives, revealing a blind spot in your test suite that line/branch coverage cannot detect.

Key idea: Coverage shows code was executed; mutation testing shows whether behavior is actually asserted.

## Why coverage can deceive

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

- Foundry example (capture results and keep a full log):

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- If you don’t use Foundry, replace `--test-cmd` with how you run tests (e.g., `npx hardhat test`, `npm test`).

Artifacts and reports are stored in `./mutation_campaign` by default. Uncaught (surviving) mutants are copied there for inspection.

### Understanding the output

Report lines look like:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- The tag in brackets is the mutator alias (e.g., `CR` = Comment Replacement).
- `UNCAUGHT` means tests passed under the mutated behavior → missing assertion.

## Reducing runtime: prioritize impactful mutants

Mutation campaigns can take hours or days. Tips to reduce cost:
- Scope: Start with critical contracts/directories only, then expand.
- Prioritize mutators: If a high-priority mutant on a line survives (e.g., entire line commented), you can skip lower-priority variants for that line.
- Parallelize tests if your runner allows it; cache dependencies/builds.
- Fail-fast: stop early when a change clearly demonstrates an assertion gap.

## Triage workflow for surviving mutants

1) Inspect the mutated line and behavior.
   - Reproduce locally by applying the mutated line and running a focused test.

2) Strengthen tests to assert state, not only return values.
   - Add equality-boundary checks (e.g., test threshold `==`).
   - Assert post-conditions: balances, total supply, authorization effects, and emitted events.

3) Replace overly permissive mocks with realistic behavior.
   - Ensure mocks enforce transfers, failure paths, and event emissions that occur on-chain.

4) Add invariants for fuzz tests.
   - E.g., conservation of value, non-negative balances, authorization invariants, monotonic supply where applicable.

5) Re-run slither-mutate until survivors are killed or explicitly justified.

## Case study: revealing missing state assertions (Arkis protocol)

A mutation campaign during an audit of the Arkis DeFi protocol surfaced survivors like:

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Commenting out the assignment didn’t break the tests, proving missing post-state assertions. Root cause: code trusted a user-controlled `_cmd.value` instead of validating actual token transfers. An attacker could desynchronize expected vs. actual transfers to drain funds. Result: high severity risk to protocol solvency.

Guidance: Treat survivors that affect value transfers, accounting, or access control as high-risk until killed.

## Practical checklist

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

