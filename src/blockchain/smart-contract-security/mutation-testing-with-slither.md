# Smart Contracts 的 Mutation Testing（slither-mutate、mewt、MuTON）

{{#include ../../banners/hacktricks-training.md}}

Mutation testing 通过系统地向合约代码引入小幅修改（mutants），然后重新运行测试套件来“测试你的测试”。如果测试失败，则 mutant 被 kill；如果测试仍然通过，则 mutant 存活，这表明存在 line/branch coverage 无法检测的盲点。

核心思想：Coverage 表明代码已被执行；Mutation testing 则表明行为是否确实被断言。<sup>[[2]](#references)</sup>

## 为什么 coverage 可能产生误导

考虑下面这个简单的 threshold check：
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
仅检查低于阈值和高于阈值的值的单元测试，即使没有断言相等边界（==），也可以达到 100% 的行/分支覆盖率。将代码重构为 `deposit >= 2 ether` 后，这些测试仍会通过，却会悄然破坏协议逻辑。<sup>[[2]](#references)</sup>

Mutation testing 通过改变条件并验证测试是否失败来暴露这一缺口。

对于 smart contracts，未被发现的 mutants 通常对应于缺失的检查，包括：
- Authorization 和 role 边界
- Accounting/value-transfer 不变量
- Revert 条件和 failure paths
- 边界条件（`==`、零值、空数组、最大/最小值）

## 具有最高 security signal 的 mutation operators

对 contract auditing 有用的 mutation 类别：<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**：将语句替换为 `revert()`，以暴露未执行的 paths
- **Medium severity**：注释掉代码行 / 移除 logic，以发现未经验证的 side effects
- **Low severity**：细微的 operator 或 constant 替换，例如 `>=` -> `>` 或 `+` -> `-`
- 其他常见编辑：assignment replacement、boolean flips、condition negation 和 type changes

实际目标：kill 所有有意义的 mutants，并明确说明幸存者为何无关或在语义上等价。

## 为什么 syntax-aware mutation 优于 regex

较早的 mutation engines 依赖 regex 或面向行的重写。这种方式可行，但存在一些重要限制：<sup>[[1]](#references)</sup>
- 多行语句难以安全地进行 mutation
- 无法理解 language structure，因此可能错误地定位 comments/tokens
- 在较弱的行上生成所有可能的 variants 会浪费大量 runtime

基于 AST 或 Tree-sitter 的 tooling 通过定位结构化 nodes，而不是原始代码行，改进了这一点：<sup>[[1]](#references)</sup>
- **slither-mutate** 使用 Slither 的 Solidity AST
- **mewt** 使用 Tree-sitter 作为 language-agnostic core
- **MuTON** 基于 `mewt` 构建，并为 FunC、Tolk 和 Tact 等 TON languages 添加 first-class support

与仅使用 regex 的 approaches 相比，这使多行 constructs 和 expression-level mutations 更加可靠。

## 使用 slither-mutate 运行 mutation testing

Requirements：Slither v0.10.2+。

- 列出 options 和 mutators：
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry example (capture results and keep a full log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- 如果不使用 Foundry，请将 `--test-cmd` 替换为你运行测试的方式（例如 `npx hardhat test`、`npm test`）。

Artifacts 默认存储在 `./mutation_campaign` 中。未捕获的（surviving）mutants 会被复制到该目录，供检查。<sup>[[5]](#references)</sup>

### 理解输出

Report 行格式如下：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 方括号中的 tag 是 mutator alias（例如，`CR` = Comment Replacement）。
- `UNCAUGHT` 表示在 mutated behavior 下测试通过 → 缺少 assertion。

## 降低运行时间：优先处理影响较大的 mutants

Mutation campaigns 可能需要数小时或数天。降低成本的建议：<sup>[[1]](#references)[[2]](#references)</sup>
- 范围：先只针对关键 contracts/directories，然后再逐步扩大。
- 优先处理 mutators：如果某一行上的高优先级 mutant 存活（例如 `revert()` 或 comment-out），则跳过该行的低优先级变体。
- 使用两阶段 campaigns：先运行 focused/fast tests，然后仅使用完整测试套件重新测试未捕获的 mutants。
- 尽可能将 mutation targets 映射到特定的 test commands（例如 auth code -> auth tests）。
- 时间紧张时，将 campaigns 限制为 high/medium severity mutants。
- 如果 runner 支持，则并行运行 tests；缓存 dependencies/builds。
- Fail-fast：当某个 change 明确证明存在 assertion gap 时尽早停止。

运行时间的计算非常严峻：`1000 mutants x 5-minute tests ~= 83 hours`，因此 campaign 设计与 mutator 本身同样重要。

## 持久化 campaigns 和大规模 triage

旧式 workflows 的一个缺点是只将结果输出到 `stdout`。对于长期 campaigns，这会让暂停/恢复、过滤和审查更加困难。<sup>[[1]](#references)</sup>

`mewt`/`MuTON` 通过将 mutants 和 outcomes 存储在基于 SQLite 的 campaigns 中，改善了这一点。优势包括：<sup>[[1]](#references)</sup>
- 暂停和恢复长时间运行，而不会丢失进度
- 仅过滤特定文件或 mutation class 中未捕获的 mutants
- 将结果导出/转换为 SARIF，以供审查工具使用
- 为 AI-assisted triage 提供更小且经过过滤的结果集，而不是原始 terminal logs

当 mutation testing 成为 audit pipeline 的一部分，而不是一次性的手动审查时，持久化结果尤其有用。

## 存活 mutants 的 triage workflow

1) 检查 mutated line 和 behavior。
- 应用 mutated line 并运行 focused test，在本地复现。

2) 强化 tests，使其断言 state，而不仅是 return values。
- 添加 equality-boundary checks（例如，测试 threshold `==`）。
- 断言 post-conditions：balances、total supply、authorization effects 和 emitted events。

3) 用 realistic behavior 替换过于宽松的 mocks。
- 确保 mocks 强制执行 on-chain 发生的 transfers、failure paths 和 event emissions。

4) 为 fuzz tests 添加 invariants。
- 例如，value conservation、non-negative balances、authorization invariants，以及适用时的 monotonic supply。

5) 将 true positives 与 semantic no-ops 分开。
- 示例：当 `x` 为 unsigned 时，`x > 0` -> `x != 0` 没有意义。

6) 重新运行 campaign，直到 survivors 被 kill，或得到明确说明。

## Case study：揭示缺失的 state assertions（Arkis protocol）

在对 Arkis DeFi protocol 进行 audit 期间，一次 mutation campaign 发现了如下 survivors：<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
将 assignment 注释掉并没有导致 tests 失败，这证明缺少 post-state assertions。根本原因：代码信任了用户可控的 `_cmd.value`，而不是验证实际的 token transfers。攻击者可以使预期 transfers 与实际 transfers 不同步，从而 drain funds。结果：对 protocol solvency 构成高严重性风险。<sup>[[2]](#references)[[3]](#references)</sup>

指导原则：在确认其已被 kill 之前，将影响 value transfers、accounting 或 access control 的 survivors 视为高风险。

## 不要盲目生成 tests 来 kill 每个 mutant

Mutation-driven test generation 如果当前 implementation 存在错误，可能适得其反。例如，将 `priority >= 2` mutation 为 `priority > 2` 会改变行为，但正确的修复并不总是“为 `priority == 2` 编写一个 test”。该行为本身可能就是 bug。<sup>[[1]](#references)</sup>

更安全的 workflow：
- 使用 surviving mutants 识别含义不明确的 requirements
- 根据 specs、protocol docs 或 reviewers 验证预期行为
- 只有这样，才将该行为编码为 test/invariant

否则，你可能会把 implementation accidents 硬编码到 test suite 中，并获得 false confidence。

## Practical checklist

- 运行 targeted campaign：
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 如果可用，优先使用 syntax-aware mutators（AST/Tree-sitter），而不是仅基于 regex 的 mutation。
- 对 survivors 进行 triage，并编写在 mutated behavior 下会失败的 tests/invariants。
- Assert balances、supply、authorizations 和 events。
- 添加 boundary tests（`==`、overflows/underflows、zero-address、zero-amount、empty arrays）。
- 替换不现实的 mocks；模拟 failure modes。
- 在 tooling 支持时持久化 results，并在 triage 前过滤 uncaught mutants。
- 使用 two-phase 或 per-target campaigns，使 runtime 保持可控。
- 持续迭代，直到所有 mutants 都被 kill，或通过 comments 和 rationale 证明其合理性。

## References

- [1] [agentic era 的 Mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [使用 mutation testing 查找 tests 未能捕获的 bugs（Trail of Bits）](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review（Appendix C）](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither（GitHub）](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
