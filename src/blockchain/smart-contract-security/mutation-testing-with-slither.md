# Smart Contracts 的 Mutation Testing（slither-mutate、mewt、MuTON）

{{#include ../../banners/hacktricks-training.md}}

Mutation testing 通过系统地对合约代码引入小型变更（mutants）并重新运行测试套件来“测试你的测试”。如果测试失败，则 mutant 被杀死。如果测试仍然通过，则 mutant 存活，说明存在行覆盖率或分支覆盖率无法检测的盲点。

核心思想：Coverage 表明代码被执行过；mutation testing 表明行为是否真正得到了断言。<sup>[[2]](#references)</sup>

## Coverage 为什么会产生误导

考虑下面这个简单的阈值检查：
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
仅检查低于阈值和高于阈值的值的 Unit tests，可能达到 100% 的 line/branch coverage，却未能断言相等边界（==）。将代码重构为 `deposit >= 2 ether` 后，这些 tests 仍会通过，从而悄然破坏 protocol logic。<sup>[[2]](#references)</sup>

Mutation testing 通过修改条件并验证 tests 是否失败来暴露这一缺口。

对于 smart contracts，surviving mutants 通常对应于缺失的检查，包括：
- Authorization 和 role boundaries
- Accounting/value-transfer invariants
- Revert conditions 和 failure paths
- Boundary conditions（`==`、零值、空数组、最大值/最小值）

## 具有最高 security signal 的 mutation operators

对 contract auditing 有用的 mutation classes：<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**：将 statements 替换为 `revert()`，以暴露未执行的 paths
- **Medium severity**：注释掉 lines / 移除 logic，以揭示未经验证的 side effects
- **Low severity**：细微的 operator 或 constant 替换，例如 `>=` -> `>` 或 `+` -> `-`
- 其他常见 edits：assignment replacement、boolean flips、condition negation 和 type changes

实际目标：kill 所有有意义的 mutants，并明确说明与实际无关或语义等价的 survivors。

## 为什么 syntax-aware mutation 优于 regex

较早的 mutation engines 依赖 regex 或面向 line 的重写。这种方式可行，但存在重要限制：<sup>[[1]](#references)</sup>
- Multi-line statements 难以安全地进行 mutation
- 无法理解 language structure，因此可能错误地定位 comments/tokens
- 在较弱的 line 上生成所有可能的 variants，会浪费大量 runtime

基于 AST 或 Tree-sitter 的 tooling 通过定位结构化 nodes，而不是原始 lines，改进了这一点：<sup>[[1]](#references)</sup>
- **slither-mutate** 使用 Slither 的 Solidity AST<sup>[[4]](#references)</sup>
- **mewt** 使用 Tree-sitter 作为 language-agnostic core<sup>[[6]](#references)</sup>
- **MuTON** 基于 `mewt` 构建，并为 FunC、Tolk 和 Tact 等 TON languages 添加 first-class support<sup>[[7]](#references)</sup>

与仅使用 regex 的 approaches 相比，这使 multi-line constructs 和 expression-level mutations 更加可靠。

## 使用 slither-mutate 运行 mutation testing

Requirements：Slither v0.10.2+。

- 列出 options 和 mutators：
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 示例（捕获结果并保留完整日志）：<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- 如果不使用 Foundry，请将 `--test-cmd` 替换为运行测试的命令（例如 `npx hardhat test`、`npm test`）。

默认情况下，Artifacts 存储在 `./mutation_campaign` 中。未捕获（存活）的变异体会被复制到该目录，以便检查。<sup>[[5]](#references)</sup>

### 理解输出

报告行如下所示：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 方括号中的 tag 是 mutator alias（例如，`CR` = Comment Replacement）。
- `UNCAUGHT` 表示测试在变异后的行为下通过了 → 缺少 assertion。

## 降低运行时间：优先处理影响较大的 mutants

Mutation campaigns 可能需要数小时或数天。降低成本的建议：<sup>[[1]](#references)[[2]](#references)</sup>
- 范围：先仅针对关键 contracts/directories，然后再逐步扩大。
- 优先处理 mutators：如果某一行上的高优先级 mutant 存活（例如 `revert()` 或 comment-out），则跳过该行的低优先级变体。
- 使用两阶段 campaigns：先运行聚焦且快速的测试，然后仅使用完整测试套件重新测试未捕获的 mutants。
- 尽可能将 mutation targets 映射到特定的测试命令（例如 auth code -> auth tests）。
- 时间紧张时，将 campaigns 限制在高/中 severity mutants。
- 如果 runner 支持，则并行运行测试；缓存 dependencies/builds。
- Fail-fast：当某个变更明确证明存在 assertion gap 时，尽早停止。

运行时间的计算非常严峻：`1000 mutants x 5-minute tests ~= 83 hours`，因此 campaign design 与 mutator 本身同样重要。<sup>[[1]](#references)</sup>

## 持久化 campaigns 和大规模 triage

旧式 workflows 的一个缺点是只将结果输出到 `stdout`。对于长期 campaigns，这会使暂停/恢复、过滤和审查更加困难。<sup>[[1]](#references)</sup>

`mewt`/`MuTON` 通过将 mutants 和 outcomes 存储在基于 SQLite 的 campaigns 中，改善了这一点。优点包括：<sup>[[1]](#references)</sup>
- 暂停并恢复长期运行而不会丢失进度
- 仅过滤特定文件或 mutation class 中未捕获的 mutants
- 将结果导出/转换为 SARIF，以供 review tooling 使用
- 为 AI-assisted triage 提供更小且经过过滤的结果集，而不是原始 terminal logs

当 mutation testing 成为 audit pipeline 的一部分，而不是一次性的人工审查时，持久化结果尤其有用。

## 存活 mutants 的 triage workflow

1) 检查 mutated line 和 behavior。
- 应用 mutated line 并运行 focused test，在本地重现。

2) 强化 tests，使其断言 state，而不仅是 return values。
- 添加 equality-boundary checks（例如，测试 threshold `==`）。
- 断言 post-conditions：balances、total supply、authorization effects 和 emitted events。

3) 用 realistic behavior 替换过于宽松的 mocks。
- 确保 mocks 强制执行链上发生的 transfers、failure paths 和 event emissions。

4) 为 fuzz tests 添加 invariants。
- 例如：value conservation、non-negative balances、authorization invariants，以及适用情况下的 monotonic supply。

5) 区分 true positives 和 semantic no-ops。
- 示例：当 `x` 为 unsigned 时，`x > 0` -> `x != 0` 没有意义。

6) 重新运行 campaign，直到 survivors 被 kill 或得到明确说明。

## Case study：揭示缺失的 state assertions（Arkis protocol）

在对 Arkis DeFi protocol 进行 audit 期间，一次 mutation campaign 发现了如下 survivors：<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
将赋值注释掉并未导致测试失败，这证明缺少 post-state assertions。根本原因：代码信任用户可控的 `_cmd.value`，而不是验证实际的 token transfers。攻击者可以使预期 transfer 与实际 transfer 脱节，从而 drain funds。结果：对 protocol solvency 构成 high severity risk。<sup>[[2]](#references)[[3]](#references)</sup>

指导原则：对于影响 value transfers、accounting 或 access control 的 survivors，在将其 kill 之前，应视为 high-risk。

## 不要盲目生成 tests 来 kill 每个 mutant

Mutation-driven test generation 可能适得其反，尤其是在当前实现本身存在错误时。例如，将 `priority >= 2` mutation 为 `priority > 2` 会改变行为，但正确修复并不总是“为 `priority == 2` 编写 test”。该行为本身可能就是 bug。<sup>[[1]](#references)</sup>

更安全的 workflow：
- 使用 surviving mutants 识别含义不明确的 requirements
- 根据 specs、protocol docs 或 reviewers 验证预期行为
- 只有这样，才将该行为编码为 test/invariant

否则，你可能会将实现中的偶然行为硬编码到 test suite 中，并获得虚假的信心。

## 实用 checklist

- 运行 targeted campaign：
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 在可用时，优先使用 syntax-aware mutators（AST/Tree-sitter），而不是仅基于 regex 的 mutation。
- 对 survivors 进行 triage，并编写在 mutated behavior 下会失败的 tests/invariants。
- Assert balances、supply、authorizations 和 events。
- 添加 boundary tests（`==`、overflows/underflows、zero-address、zero-amount、empty arrays）。
- 替换不现实的 mocks；模拟 failure modes。
- 在 tooling 支持时持久化 results，并在 triage 前过滤 uncaught mutants。
- 使用 two-phase 或 per-target campaigns，以保持 runtime 可控。
- 持续迭代，直到所有 mutants 都被 killed，或通过 comments 和 rationale 说明其合理性。

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
