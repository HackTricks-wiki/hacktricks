# 智能合约变异测试 (slither-mutate、mewt、MuTON)

{{#include ../../banners/hacktricks-training.md}}

变异测试通过系统地在合约代码中引入微小改动（变异体）并重新运行测试套件，来“测试你的测试”。如果测试失败，变异体就被杀死。如果测试仍然通过，变异体就存活下来，揭示出代码行/分支覆盖率无法检测到的盲点。

核心思想：覆盖率表明代码已执行；变异测试则表明行为是否确实经过断言。<sup>[[2]](#references)</sup>

## 为什么覆盖率会造成误导

来看这个简单的阈值检查：

```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
    if (deposit >= 1 ether) {
        return true;
    } else {
        return false;
    }
}
```

单元测试如果只检查一个低于阈值的值和一个高于阈值的值，即使未断言相等边界（==），也可能达到 100% 的行/分支覆盖率。将代码重构为 `deposit >= 2 ether` 后，这类测试仍会通过，却悄然破坏协议逻辑。<sup>[[2]](#references)</sup>

变异测试通过修改条件并验证测试是否失败，来暴露这一缺口。

对于智能合约，存活的变异通常对应于以下方面缺少检查：
- 授权和角色边界
- 记账/价值转移不变量
- 回滚条件和失败路径
- 边界条件（`==`、零值、空数组、最大/最小值）

## 安全信号最强的变异操作符

适用于合约审计的变异类别：<sup>[[1]](#references)[[2]](#references)</sup>
- **高严重性**：将语句替换为 `revert()`，以暴露未执行的路径
- **中严重性**：注释掉代码行/移除逻辑，以发现未经验证的副作用
- **低严重性**：细微地替换操作符或常量，例如 `>=` -> `>` 或 `+` -> `-`
- 其他常见修改：替换赋值、翻转布尔值、取反条件以及更改类型

实际目标：杀死所有有意义的变异，并明确说明那些无关或语义等价的存活变异为何可以接受。

## 为什么语法感知型变异优于正则表达式

较早的变异引擎依赖正则表达式或按行重写。这种方法可行，但有一些重要局限：<sup>[[1]](#references)</sup>
- 多行语句难以安全地进行变异
- 工具无法理解语言结构，因此可能错误地针对注释/词元
- 在薄弱代码行上生成所有可能的变体会浪费大量运行时间

基于 AST 或 Tree-sitter 的工具通过针对结构化节点而非原始代码行，改进了这一点：<sup>[[1]](#references)</sup>
- **slither-mutate** 使用 Slither 的 Solidity AST。<sup>[[4]](#references)</sup>
- **mewt** 使用 Tree-sitter 作为语言无关的核心。<sup>[[6]](#references)</sup>
- **MuTON** 基于 `mewt` 构建，并为 FunC、Tolk 和 Tact 等 TON 语言提供一等支持。<sup>[[7]](#references)</sup>

与仅使用正则表达式的方法相比，这使多行结构和表达式级变异更加可靠。

## 使用 slither-mutate 运行变异测试

要求：Slither v0.10.2+。

- 列出选项和变异器：

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Foundry 示例（捕获结果并保留完整日志）：<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- 如果你不使用 Foundry，请将 `--test-cmd` 替换为你运行测试的命令（例如 `npx hardhat test`、`npm test`）。

默认情况下，Artifacts 存储在 `./mutation_campaign` 中。未捕获（存活）的 mutants 会被复制到该目录以供检查。<sup>[[5]](#references)</sup>

### 理解输出

报告行如下所示：

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- 方括号中的标签是 mutator 别名（例如，`CR` = Comment Replacement）。
- `UNCAUGHT` 表示在变异后的行为下测试通过 → 缺少断言。

## 降低运行时间：优先处理影响较大的 mutants

Mutation campaigns 可能需要数小时甚至数天。以下建议有助于降低成本：<sup>[[1]](#references)[[2]](#references)</sup>
- 范围：先只针对关键合约/目录，再逐步扩大范围。
- 优先选择 mutators：如果某行上的高优先级 mutant 仍然存活（例如 `revert()` 或注释掉代码），就跳过该行优先级较低的变体。
- 使用两阶段 campaigns：先运行范围聚焦、速度较快的测试，再仅用完整测试套件重新测试未捕获的 mutants。
- 尽可能将 mutation targets 映射到特定测试命令（例如，auth 代码 -> auth 测试）。
- 时间紧张时，将 campaigns 限定在高/中严重性 mutants。
- 如果 runner 支持并行测试，就并行运行；同时缓存依赖项/构建结果。
- 快速失败：如果某项更改明确暴露了断言缺失，就尽早停止。

运行时间的计算很残酷：`1000 mutants x 5-minute tests ~= 83 hours`，因此 campaign 设计和 mutator 本身同样重要。<sup>[[1]](#references)</sup>

## 持久化 campaigns 和大规模分类处理

旧式工作流的一个缺点是只将结果输出到 `stdout`。对于长时间运行的 campaigns，这会让暂停/恢复、筛选和审查变得更加困难。<sup>[[1]](#references)</sup>

`mewt`/`MuTON` 通过在 SQLite 支持的 campaigns 中存储 mutants 和结果来改善这一点。优点包括：<sup>[[1]](#references)</sup>
- 暂停和恢复长时间运行的任务，而不会丢失进度
- 仅筛选特定文件或 mutation class 中未捕获的 mutants
- 将结果导出/转换为 SARIF，以供审查工具使用
- 为 AI 辅助分类提供更小、经过筛选的结果集，而不是原始终端日志

当 mutation testing 成为审计流程的一部分，而不是一次性的手动审查时，持久化结果尤其有用。

## 存活 mutants 的分类处理工作流

1) 检查被变异的代码行及其行为。
   - 在本地应用变异后的代码行并运行范围聚焦的测试，以复现问题。

2) 加强测试，断言状态，而不仅仅是返回值。
   - 添加相等边界检查（例如，测试阈值 `==`）。
   - 断言后置条件：余额、总供应量、授权效果和触发的事件。

3) 用行为真实的 mock 替换过于宽松的 mock。
   - 确保 mock 会强制执行链上发生的转账、失败路径和事件触发。

4) 为 fuzz tests 添加不变量。
   - 例如：价值守恒、余额非负、授权不变量，以及适用时的供应量单调性。

5) 区分真正的问题与语义上的无操作。
   - 示例：当 `x` 是无符号数时，`x > 0` -> `x != 0` 没有实际意义。

6) 重新运行 campaign，直到存活的 mutants 被杀死或明确说明其合理性。

## 案例研究：揭示缺失的状态断言（Arkis protocol）

在审计 Arkis DeFi protocol 期间进行的一次 mutation campaign 发现了以下存活项：<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

注释掉赋值语句并未导致测试失败，这证明缺少对后置状态的断言。根本原因：代码信任用户可控的 `_cmd.value`，而没有验证实际的 token 转账。攻击者可以使预期转账与实际转账不同步，从而耗尽资金。结果：协议偿付能力面临高危风险。<sup>[[2]](#references)[[3]](#references)</sup>

建议：对于影响价值转移、账目核算或访问控制的存活 mutant，在将其杀死之前都应视为高风险。

## 不要盲目生成测试来杀死每个 mutant

如果当前实现本身有误，由 mutation 驱动的测试生成可能适得其反。示例：将 `priority >= 2` 改为 `priority > 2` 会改变行为，但正确的修复并不总是“为 `priority == 2` 编写测试”。该行为本身可能就是 bug。<sup>[[1]](#references)</sup>

更安全的工作流程：
- 利用存活的 mutant 找出含糊不清的需求
- 根据规范、协议文档或评审人员的意见验证预期行为
- 之后再将该行为编码为测试/不变量

否则，你可能会把实现中的偶然行为硬编码进测试套件，从而产生虚假的信心。

## 实用检查清单

- 运行有针对性的测试：
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- 在可用时，优先使用语法感知的 mutator（AST/Tree-sitter），而不是仅使用正则表达式进行 mutation。
- 对存活的 mutant 进行分类，并编写在行为被 mutation 后会失败的测试/不变量。
- 断言余额、供应量、授权和事件。
- 添加边界测试（`==`、溢出/下溢、零地址、零金额、空数组）。
- 替换不切实际的 mock；模拟故障模式。
- 如果工具支持，则保留结果，并在分类前筛除未捕获的 mutant。
- 使用两阶段或按目标划分的测试，以控制运行时间。
- 持续迭代，直到所有 mutant 都被杀死，或通过注释和理由说明其合理性。

## References

- [1] [面向 agentic 时代的 mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [使用 mutation testing 找出测试未能捕获的 bug（Trail of Bits）](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage 安全审查（附录 C）](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither（GitHub）](https://github.com/crytic/slither)
- [5] [Slither Mutator 文档](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
