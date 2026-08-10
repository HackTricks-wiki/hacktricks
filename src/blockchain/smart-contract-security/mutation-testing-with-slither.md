# Smart Contracts 的 Mutation Testing（slither-mutate、mewt、MuTON）

Mutation testing 通过系统地对合约代码引入小型更改（mutants）并重新运行测试套件来“测试你的测试”。如果测试失败，则 mutant 被 kill；如果测试仍然通过，则 mutant 存活，说明存在代码行覆盖率或分支覆盖率无法检测的盲点。

核心思想：覆盖率表明代码已被执行；Mutation testing 则表明相关行为是否真正得到了断言。<sup>[[2]](#references)</sup>

## 为什么覆盖率可能会误导

考虑这个简单的阈值检查：
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
仅检查低于阈值和高于阈值的值的单元测试，即使未断言相等边界（==），也可以达到 100% 的行/分支覆盖率。将代码重构为 `deposit >= 2 ether` 后，这些测试仍会通过，却会悄然破坏协议逻辑。<sup>[[2]](#references)</sup>

Mutation testing 通过变更条件并验证测试是否失败来暴露这一缺口。

对于 smart contracts，存活的 mutants 通常对应于缺失的检查，包括：
- Authorization 和 role 边界
- Accounting/value-transfer 不变量
- Revert 条件和失败路径
- 边界条件（`==`、零值、空数组、最大值/最小值）

## 具有最高 security signal 的 mutation operators

对 contract auditing 有用的 mutation 类别：<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**：将语句替换为 `revert()`，以暴露未执行的路径
- **Medium severity**：注释掉行 / 移除逻辑，以发现未经验证的副作用
- **Low severity**：细微的 operator 或 constant 替换，例如 `>=` -> `>` 或 `+` -> `-`
- 其他常见编辑：assignment 替换、boolean 翻转、condition negation 和 type 更改

实际目标：杀死所有有意义的 mutants，并明确说明无关或语义等价的存活 mutants。

## 为什么 syntax-aware mutation 优于 regex

较旧的 mutation engines 依赖 regex 或面向行的重写。虽然可行，但存在一些重要限制：<sup>[[1]](#references)</sup>
- 多行语句难以安全地进行 mutation
- 无法理解语言结构，因此可能错误地定位 comments/tokens
- 在较弱的行上生成所有可能的变体会浪费大量 runtime

基于 AST 或 Tree-sitter 的 tooling 通过定位结构化 nodes 而非原始行，改善了这一点：<sup>[[1]](#references)</sup>
- **slither-mutate** 使用 Slither 的 Solidity AST。<sup>[[4]](#references)</sup>
- **mewt** 使用 Tree-sitter 作为 language-agnostic core。<sup>[[6]](#references)</sup>
- **MuTON** 基于 `mewt` 构建，并为 FunC、Tolk 和 Tact 等 TON languages 增加 first-class support。<sup>[[7]](#references)</sup>

与仅使用 regex 的方法相比，这使多行结构和 expression-level mutations 更加可靠。

## 使用 slither-mutate 运行 mutation testing

要求：Slither v0.10.2+。

- 列出选项和 mutators：
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 示例（捕获结果并保留完整日志）：<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- 如果不使用 Foundry，请将 `--test-cmd` 替换为你的测试运行方式（例如 `npx hardhat test`、`npm test`）。

Artifacts 默认存储在 `./mutation_campaign` 中。未捕获的（存活的）变异体会被复制到该目录以供检查。<sup>[[5]](#references)</sup>

### 理解输出

报告行如下所示：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 方括号中的标签是 mutator alias（例如，`CR` = Comment Replacement）。
- `UNCAUGHT` 表示测试在 mutated behavior 下通过 → 缺少 assertion。

## 降低运行时间：优先处理有影响的 mutants

Mutation campaigns 可能需要数小时甚至数天。以下是降低成本的建议：<sup>[[1]](#references)[[2]](#references)</sup>
- 范围：仅从关键 contracts/directories 开始，然后逐步扩展。
- 优先选择 mutators：如果某一行上的高优先级 mutant 存活（例如 `revert()` 或 comment-out），则跳过该行优先级较低的 variants。
- 使用两阶段 campaigns：先运行聚焦且快速的测试，然后仅使用完整 test suite 重新测试未捕获的 mutants。
- 尽可能将 mutation targets 映射到特定的 test commands（例如 auth code -> auth tests）。
- 时间紧张时，将 campaigns 限制为 high/medium severity mutants。
- 如果 runner 支持，则并行运行测试；缓存 dependencies/builds。
- Fail-fast：当某个 change 明确证明存在 assertion gap 时，尽早停止。

运行时间的计算非常严苛：`1000 mutants x 5-minute tests ~= 83 hours`，因此 campaign design 与 mutator 本身同样重要。<sup>[[1]](#references)</sup>

## 持久化 campaigns 和大规模 triage

旧式 workflows 的一个缺点是只将结果输出到 `stdout`。对于长期运行的 campaigns，这会使暂停/恢复、过滤和审查更加困难。<sup>[[1]](#references)</sup>

`mewt`/`MuTON` 通过将 mutants 和 outcomes 存储在基于 SQLite 的 campaigns 中改进了这一点。优点包括：<sup>[[1]](#references)</sup>
- 暂停和恢复长期运行而不会丢失进度
- 仅过滤特定文件或 mutation class 中未捕获的 mutants
- 将结果导出/转换为 SARIF，以供审查工具使用
- 为 AI-assisted triage 提供更小且经过过滤的结果集，而不是原始终端日志

当 mutation testing 成为 audit pipeline 的一部分，而不是一次性的人工审查时，持久化结果尤其有用。

## 存活 mutants 的 triage workflow

1) 检查 mutated line 及其 behavior。
- 应用 mutated line 并运行 focused test，在本地复现。

2) 强化测试，使其断言 state，而不仅仅是 return values。
- 添加 equality-boundary checks（例如，测试 threshold `==`）。
- 断言 post-conditions：balances、total supply、authorization effects 以及 emitted events。

3) 将过于宽松的 mocks 替换为 realistic behavior。
- 确保 mocks 强制执行链上发生的 transfers、failure paths 和 event emissions。

4) 为 fuzz tests 添加 invariants。
- 例如，value conservation、non-negative balances、authorization invariants，以及适用时的 monotonic supply。

5) 区分 true positives 和 semantic no-ops。
- 示例：当 `x` 为 unsigned 时，`x > 0` -> `x != 0` 没有意义。

6) 重新运行 campaign，直到 survivors 被 killed 或得到明确说明。

## Case study：揭示缺失的 state assertions（Arkis protocol）

在对 Arkis DeFi protocol 进行 audit 时，一次 mutation campaign 发现了如下 survivors：<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
注释掉赋值并没有导致测试失败，这证明缺少 post-state assertions。根本原因：代码信任用户可控的 `_cmd.value`，而不是验证实际的 token transfers。攻击者可以使预期 transfer 与实际 transfer 不同步，从而 drain funds。结果：对 protocol solvency 构成高严重性风险。<sup>[[2]](#references)[[3]](#references)</sup>

指导原则：对于影响 value transfers、accounting 或 access control 的 survivors，在被 kill 之前都应视为高风险。

## 不要盲目生成测试来 kill 每个 mutant

Mutation-driven test generation 如果当前实现本身有误，可能适得其反。例如，将 `priority >= 2` mutation 为 `priority > 2` 会改变行为，但正确的修复并不总是“为 `priority == 2` 编写测试”。该行为本身可能就是 bug。<sup>[[1]](#references)</sup>

更安全的工作流程：
- 使用 surviving mutants 识别含义不明确的 requirements
- 从 specs、protocol docs 或 reviewers 处验证预期行为
- 之后才将该行为编码为 test/invariant

否则，你可能会将实现中的意外行为硬编码到 test suite 中，并获得虚假的信心。

## 实用 checklist

- 运行 targeted campaign：
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 在可用时，优先使用 syntax-aware mutators（AST/Tree-sitter），而不是仅基于 regex 的 mutation。
- 对 survivors 进行 triage，并编写在 mutated behavior 下会失败的 tests/invariants。
- 断言 balances、supply、authorizations 和 events。
- 添加 boundary tests（`==`、overflows/underflows、zero-address、zero-amount、empty arrays）。
- 替换不现实的 mocks；模拟 failure modes。
- 在 tooling 支持时持久化 results，并在 triage 前过滤 uncaught mutants。
- 使用 two-phase 或 per-target campaigns，以控制 runtime。
- 持续迭代，直到所有 mutants 都被 kill，或通过 comments 和 rationale 说明其合理性。

## References

- [1] [面向 agentic 时代的 Mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [使用 Mutation testing 找出测试未捕获的 bugs（Trail of Bits）](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review（附录 C）](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither（GitHub）](https://github.com/crytic/slither)
- [5] [Slither Mutator 文档](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
