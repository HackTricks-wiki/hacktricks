# Smart Contracts 的 Mutation Testing（slither-mutate、mewt、MuTON）

{{#include ../../banners/hacktricks-training.md}}

Mutation testing 通过系统地向 contract code 引入小幅变更（mutants）并重新运行 test suite 来“测试你的测试”。如果测试失败，则该 mutant 被 kill。如果测试仍然通过，则该 mutant 存活，揭示出 line/branch coverage 无法检测的盲点。

核心理念：Coverage 表明代码已被执行；mutation testing 表明其行为是否确实被断言。<sup>[[2]](#references)</sup>

## Why coverage can deceive

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
仅检查低于阈值的值和高于阈值的值的单元测试，可能达到 100% 的行/分支覆盖率，却未能断言相等边界（==）。将代码重构为 `deposit >= 2 ether` 后，这些测试仍会通过，从而悄无声息地破坏协议逻辑。<sup>[[2]](#references)</sup>

Mutation testing 通过修改条件并验证测试是否失败来暴露这一缺口。

对于 smart contracts，存活的 mutants 通常对应于缺失的检查，包括：
- Authorization 和角色边界
- Accounting/value-transfer 不变量
- Revert 条件和失败路径
- 边界条件（`==`、零值、空数组、最大值/最小值）

## Mutation operators with the highest security signal

对 contract auditing 有用的 mutation 类别：<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**：将语句替换为 `revert()`，以暴露未执行的路径
- **Medium severity**：注释掉行或移除逻辑，以揭示未经验证的副作用
- **Low severity**：细微的 operator 或 constant 替换，例如 `>=` -> `>` 或 `+` -> `-`
- 其他常见修改：赋值替换、布尔值翻转、条件取反以及类型更改

实际目标是：kill 所有有意义的 mutants，并明确说明与测试无关或语义等价的 survivors。

## Why syntax-aware mutation is better than regex

较早的 mutation engines 依赖 regex 或基于行的重写。这种方式可行，但存在一些重要限制：<sup>[[1]](#references)</sup>
- 多行语句难以安全地进行 mutation
- 无法理解语言结构，因此可能错误地定位 comments/tokens
- 在较弱的行级粒度上生成所有可能的变体，会浪费大量运行时间

基于 AST 或 Tree-sitter 的 tooling 通过定位结构化节点而非原始行，改善了这一点：<sup>[[1]](#references)</sup>
- **slither-mutate** 使用 Slither 的 Solidity AST。<sup>[[4]](#references)</sup>
- **mewt** 使用 Tree-sitter 作为 language-agnostic 核心。<sup>[[6]](#references)</sup>
- **MuTON** 基于 `mewt` 构建，并为 FunC、Tolk 和 Tact 等 TON languages 添加 first-class support。<sup>[[7]](#references)</sup>

与仅使用 regex 的方法相比，这使多行构造和 expression-level mutations 更加可靠。

## Running mutation testing with slither-mutate

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

Artifacts 默认存储在 `./mutation_campaign` 中。未捕获（存活）的 mutants 会被复制到该目录，供检查。<sup>[[5]](#references)</sup>

### 理解输出

报告行如下所示：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 方括号中的 tag 是 mutator alias（例如，`CR` = Comment Replacement）。
- `UNCAUGHT` 表示测试在 mutation behavior 下通过 → 缺少 assertion。

## 降低运行时间：优先处理高影响 mutants

Mutation campaigns 可能需要数小时甚至数天。以下是降低成本的建议：<sup>[[1]](#references)[[2]](#references)</sup>
- 范围：仅从 critical contracts/directories 开始，然后逐步扩大。
- 优先处理 mutators：如果某行上的 high-priority mutant 存活（例如 `revert()` 或 comment-out），则跳过该行的 lower-priority variants。
- 使用两阶段 campaigns：先运行 focused/fast tests，然后仅使用 full suite 重新测试未捕获的 mutants。
- 尽可能将 mutation targets 映射到特定的 test commands（例如 auth code -> auth tests）。
- 时间紧张时，将 campaigns 限制为 high/medium severity mutants。
- 如果 runner 支持，则并行运行 tests；缓存 dependencies/builds。
- Fail-fast：当某个 change 明确证明存在 assertion gap 时，尽早停止。

运行时间的计算非常严峻：`1000 mutants x 5-minute tests ~= 83 hours`，因此 campaign design 与 mutator 本身同样重要。<sup>[[1]](#references)</sup>

## 持久化 campaigns 和大规模 triage

较旧 workflows 的一个弱点是只将结果输出到 `stdout`。对于长期 campaigns，这会使 pause/resume、filtering 和 review 更加困难。<sup>[[1]](#references)</sup>

`mewt`/`MuTON` 通过将 mutants 和 outcomes 存储在 SQLite-backed campaigns 中改进了这一点。优点包括：<sup>[[1]](#references)</sup>
- 暂停并恢复长期运行而不会丢失进度
- 仅筛选特定文件或 mutation class 中未捕获的 mutants
- 将结果导出/转换为 SARIF，以供 review tooling 使用
- 为 AI-assisted triage 提供更小且经过筛选的 result sets，而不是原始 terminal logs

当 mutation testing 成为 audit pipeline 的一部分，而不是一次性的人工 review 时，持久化结果尤其有用。

## 存活 mutants 的 triage workflow

1) 检查 mutated line 及其 behavior。
- 应用 mutated line 并运行 focused test，在本地复现。

2) 强化 tests，使其断言 state，而不仅是 return values。
- 添加 equality-boundary checks（例如，测试 threshold `==`）。
- 断言 post-conditions：balances、total supply、authorization effects 以及 emitted events。

3) 用 realistic behavior 替换过于宽松的 mocks。
- 确保 mocks 强制执行链上发生的 transfers、failure paths 和 event emissions。

4) 为 fuzz tests 添加 invariants。
- 例如，value conservation、non-negative balances、authorization invariants，以及适用时的 monotonic supply。

5) 区分 true positives 和 semantic no-ops。
- 示例：当 `x` 为 unsigned 时，`x > 0` -> `x != 0` 没有实际意义。

6) 重新运行 campaign，直到存活者被消除或得到明确说明。

## 案例研究：揭示缺失的 state assertions（Arkis protocol）

在对 Arkis DeFi protocol 进行 audit 期间，一次 mutation campaign 发现了如下存活者：<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
将赋值语句注释掉并未导致测试失败，证明缺少 post-state assertions。根本原因：代码信任了用户可控的 `_cmd.value`，而没有验证实际的 token transfers。攻击者可以使预期 transfer 与实际 transfer 产生不同步，从而 drain funds。结果：对 protocol solvency 构成 high severity 风险。<sup>[[2]](#references)[[3]](#references)</sup>

Guidance：在被 kill 之前，将影响 value transfers、accounting 或 access control 的 survivors 视为 high-risk。

## Do not blindly generate tests to kill every mutant

Mutation-driven test generation 如果当前实现本身有误，可能适得其反。例如，将 `priority >= 2` 变异为 `priority > 2` 会改变行为，但正确的修复并不总是“为 `priority == 2` 编写测试”。该行为本身可能就是 bug。<sup>[[1]](#references)</sup>

更安全的 workflow：
- 使用 surviving mutants 识别含义不明确的 requirements
- 根据 specs、protocol docs 或 reviewers 验证预期行为
- 之后再将该行为编码为 test/invariant

否则，你可能会将实现中的偶然行为硬编码到 test suite 中，并获得虚假的信心。

## Practical checklist

- 执行 targeted campaign：
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 如果可用，优先使用 syntax-aware mutators（AST/Tree-sitter），而不是仅基于 regex 的 mutation。
- 对 survivors 进行 triage，并编写在 mutated behavior 下会失败的 tests/invariants。
- Assert balances、supply、authorizations 和 events。
- 添加 boundary tests（`==`、overflows/underflows、zero-address、zero-amount、empty arrays）。
- 替换不现实的 mocks；模拟 failure modes。
- 在 tooling 支持时持久化 results，并在 triage 前过滤 uncaught mutants。
- 使用 two-phase 或 per-target campaigns，以控制 runtime。
- 持续迭代，直到所有 mutants 都被 kill，或通过 comments 和 rationale 说明其合理性。

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
