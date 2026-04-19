# Smart Contracts 的 Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing 会通过系统性地向 contract code 中引入小改动（mutants），然后重新运行 test suite，从而“测试你的 tests”。如果某个 test 失败了，说明这个 mutant 被 killed。如果 tests 仍然通过，说明这个 mutant survived，暴露出 line/branch coverage 无法检测到的 blind spot。

核心思想：Coverage 显示 code 是否被执行；mutation testing 显示行为是否真的被 asserted。

## Why coverage can deceive

考虑这个简单的 threshold check:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
仅检查阈值以下和阈值以上值的单元测试，可以在达到 100% line/branch coverage 的同时，却没有断言等号边界（==）。将 `deposit >= 2 ether` 重构后，这类测试仍然会通过，从而静默破坏协议逻辑。

Mutation testing 通过变异条件并验证测试是否失败来暴露这个缺口。

对于 smart contracts，存活下来的 mutants 往往对应于缺失的检查，常见于：
- Authorization 和 role 边界
- Accounting/value-transfer 不变量
- Revert 条件和失败路径
- 边界条件（`==`、零值、空数组、最大/最小值）

## 具有最高安全信号的 Mutation operators

对合约审计有用的 mutation classes：
- **高严重性**：将语句替换为 `revert()`，以暴露未执行路径
- **中严重性**：注释掉行 / 移除逻辑，以揭示未验证的副作用
- **低严重性**：细微的 operator 或常量替换，例如 `>=` -> `>` 或 `+` -> `-`
- 其他常见编辑：assignment replacement、boolean flips、condition negation，以及 type changes

实际目标是：杀死所有有意义的 mutants，并明确说明那些无关或语义等价的存活 mutants 的理由。

## 为什么语法感知的 mutation 比 regex 更好

较早的 mutation engines 依赖 regex 或按行重写。这可行，但有重要局限：
- 多行语句很难安全地进行 mutation
- 无法理解语言结构，因此可能错误地针对 comments/tokens
- 在弱 line 上生成所有可能变体会浪费大量 runtime

基于 AST 或 Tree-sitter 的工具通过针对结构化节点而不是原始行来改进这一点：
- **slither-mutate** 使用 Slither 的 Solidity AST
- **mewt** 使用 Tree-sitter 作为语言无关核心
- **MuTON** 构建在 `mewt` 之上，并为 TON languages 提供一等支持，例如 FunC、Tolk 和 Tact

这使得多行结构和 expression-level mutation 比仅依赖 regex 的方法可靠得多。

## 使用 slither-mutate 运行 mutation testing

Requirements: Slither v0.10.2+。

- 列出选项和 mutators：
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 示例（捕获结果并保留完整日志）：
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- 如果你不使用 Foundry，就把 `--test-cmd` 替换为你运行测试的方式（例如 `npx hardhat test`、`npm test`）。

Artifacts 默认存储在 `./mutation_campaign` 中。未被捕获（存活的）mutants 会被复制到那里以供检查。

### 理解输出

报告行看起来像：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 方括号中的 tag 是 mutator alias（例如，`CR` = Comment Replacement）。
- `UNCAUGHT` 表示测试在 mutated behavior 下通过了 → 缺少 assertion。

## 减少 runtime：优先处理影响大的 mutants

Mutation campaigns 可能需要几小时或几天。减少成本的建议：
- Scope: 先只覆盖关键 contracts/directories，然后再扩展。
- 优先 mutators: 如果某一行上的高优先级 mutant 存活了（例如 `revert()` 或 comment-out），就跳过该行更低优先级的变体。
- 使用 two-phase campaigns: 先运行聚焦/快速 tests，再只用完整测试套件重测 uncaught mutants。
- 在可能的情况下，将 mutation targets 映射到特定的 test commands（例如 auth code -> auth tests）。
- 时间紧张时，只限制在 high/medium severity mutants 上跑。
- 如果 runner 允许，就并行化 tests；缓存 dependencies/builds。
- Fail-fast: 当某个变更清楚地表明存在 assertion gap 时，尽早停止。

runtime 的数学很残酷：`1000 mutants x 5-minute tests ~= 83 hours`，所以 campaign design 和 mutator 本身一样重要。

## 持久化 campaigns 与大规模 triage

旧工作流的一个弱点是只把结果输出到 `stdout`。对于长时间 campaigns，这会让 pause/resume、过滤和 review 更困难。

`mewt`/`MuTON` 通过将 mutants 和 outcomes 存储在 SQLite-backed campaigns 中改进了这一点。好处：
- 在不丢失进度的情况下 pause 和 resume 长时间运行
- 只过滤特定文件或 mutation class 中的 uncaught mutants
- 将结果导出/translate 为 SARIF 以供 review tooling 使用
- 给 AI-assisted triage 提供更小、已过滤的结果集，而不是原始 terminal logs

当 mutation testing 变成 audit pipeline 的一部分，而不是一次性的手动 review 时，持久化结果尤其有用。

## surviving mutants 的 triage workflow

1) 检查 mutated line 和 behavior。
- 通过应用 mutated line 并运行聚焦测试，在本地复现。

2) 强化 tests，使其断言 state，而不只是 return values。
- 添加 equality-boundary 检查（例如，测试 threshold `==`）。
- 断言 post-conditions：balances、total supply、authorization effects，以及 emitted events。

3) 用更真实的行为替换过于宽松的 mocks。
- 确保 mocks 强制执行链上实际发生的 transfers、failure paths 和 event emissions。

4) 为 fuzz tests 添加 invariants。
- 例如，value 守恒、non-negative balances、authorization invariants，以及适用场景下的 monotonic supply。

5) 将 true positives 与 semantic no-ops 分开。
- 例如：当 `x` 是 unsigned 时，`x > 0` -> `x != 0` 没有意义。

6) 重新运行 campaign，直到 survivors 被杀死或被明确说明原因。

## Case study: 揭示缺失的 state assertions（Arkis protocol）

在对 Arkis DeFi protocol 的 audit 期间进行的一次 mutation campaign 发现了类似这样的 survivors：
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
注释掉该赋值并没有破坏测试，这证明缺少 post-state 断言。根因：代码信任了用户可控的 `_cmd.value`，而不是验证实际的 token 转移。攻击者可以让预期转移与实际转移不同步，从而提走资金。结果：对协议偿付能力构成 high severity 风险。

指导：把那些影响价值转移、记账或访问控制的 survivors 视为 high-risk，直到它们被 killed。

## 不要盲目生成 tests 来 kill 每个 mutant

基于 mutation 的 test 生成如果当前实现本身就是错的，就会适得其反。例子：把 `priority >= 2` 改成 `priority > 2` 会改变行为，但正确修复未必是“为 `priority == 2` 编写一个 test”。这个行为本身也可能就是 bug。

更安全的流程：
- 使用 surviving mutants 来识别含糊不清的需求
- 从 specs、协议文档或 reviewer 那里验证预期行为
- 然后再把该行为编码为 test/invariant

否则，你可能会把实现中的偶然错误硬编码进 test suite，反而产生错误的信心。

## 实用 checklist

- 运行有针对性的 campaign：
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 在可用时，优先使用语法感知的 mutators（AST/Tree-sitter），而不是仅靠 regex 的 mutation。
- 对 survivors 做分流，并编写在 mutated 行为下会失败的 tests/invariants。
- 断言 balances、supply、authorizations 和 events。
- 添加边界 tests（`==`、overflows/underflows、zero-address、zero-amount、空数组）。
- 替换不现实的 mocks；模拟 failure modes。
- 如果工具支持，持久化结果，并在分流前过滤未捕获的 mutants。
- 使用两阶段或按目标分别进行的 campaign，以保持运行时间可控。
- 反复迭代，直到所有 mutants 都被 killed，或用注释和理由证明其合理性。

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
