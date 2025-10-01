# 使用 Slither (slither-mutate) 对 Solidity 进行变异测试

{{#include ../../banners/hacktricks-training.md}}

变异测试通过有系统地在你的 Solidity 代码中引入小的改动（mutants）并重新运行你的测试套件来“测试你的测试”。如果某个测试失败，该 mutant 被杀死。如果测试仍然通过，该 mutant 存活，暴露了测试套件中的盲点，这是行/分支覆盖率无法发现的。

关键思想：覆盖率显示代码被执行；变异测试显示行为是否被实际断言。

## 为什么覆盖率会误导

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
如果单元测试只检查阈值以下和阈值以上的值，可能在未断言相等边界 (==) 的情况下达到 100% 的行/分支覆盖率。将条件重构为 `deposit >= 2 ether` 仍会通过这类测试，从而悄然破坏协议逻辑。

变异测试通过修改条件并验证测试是否失败来揭示这一漏洞。

## 常见的 Solidity 变异操作符

Slither 的变异引擎会应用许多小的、改变语义的编辑，例如：
- 运算符替换：`+` ↔ `-`，`*` ↔ `/` 等。
- 赋值替换：`+=` → `=`，`-=` → `=`
- 常量替换：非零 → `0`，`true` ↔ `false`
- 在 `if`/循环 内部的条件取反/替换
- 注释整行（CR: Comment Replacement）
- 用 `revert()` 替换某行
- 数据类型替换：例如 `int128` → `int64`

目标：消灭 100% 的生成变异体，或者对幸存者给出明确的理由说明。

## 使用 slither-mutate 运行变异测试

要求：Slither v0.10.2+。

- 列出选项和 mutators：
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 示例（捕获结果并保存完整日志）：
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- 如果你不使用 Foundry，请将 `--test-cmd` 替换为运行测试的方式（例如，`npx hardhat test`、`npm test`）。

产物和报告默认存储在 `./mutation_campaign`。未被捕获（存活）的变异体会被复制到那里以便检查。

### 理解输出

报告行示例：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 方括号中的标签是变异器别名（例如，`CR` = Comment Replacement）。
- `UNCAUGHT` 表示在被变异的行为下测试通过 → 缺少断言。

## Reducing runtime: prioritize impactful mutants

变异测试活动可能需要数小时或数天。降低成本的建议：
- Scope：先只对关键合约/目录进行测试，然后逐步扩大。
- Prioritize mutators：如果一行上的高优先级变异体幸存（例如，整行被注释），可以跳过该行的低优先级变体。
- Parallelize tests if your runner allows it；缓存依赖/构建。
- Fail-fast：当某个变更清楚地暴露断言缺口时，尽早停止。

## Triage workflow for surviving mutants

1) Inspect the mutated line and behavior.
- 通过应用被变异的行并运行有针对性的测试在本地复现。

2) Strengthen tests to assert state, not only return values.
- 添加等值边界检查（例如，测试阈值 `==`）。
- 断言后置条件：余额、总供应、授权效果以及触发的事件。

3) Replace overly permissive mocks with realistic behavior.
- 确保 mocks 强制执行链上会发生的转账、失败路径和事件触发。

4) Add invariants for fuzz tests.
- 例如，价值守恒、非负余额、授权不变量、在适用时单调供应。

5) Re-run slither-mutate until survivors are killed or explicitly justified.
- 重新运行 slither-mutate，直到幸存者被消除或有明确理由保留。

## Case study: revealing missing state assertions (Arkis protocol)

在对 Arkis DeFi 协议进行审计的变异测试活动中出现了如下幸存变异体：
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
注释掉赋值并未使测试失败，证明缺少事后状态断言。根本原因：代码信任了由用户控制的 `_cmd.value`，而没有验证实际的 token 转移。攻击者可以使预期转移与实际转移不同步，从而抽取资金。结果：对协议偿付能力构成高严重性风险。

建议：对影响价值转移、账务或访问控制的幸存变异体，在被消灭之前一律视为高风险。

## 实操检查清单

- 运行定向活动：
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 对幸存变异体进行分类并编写在变异行为下会失败的测试/不变量。
- 断言余额、供应、授权和事件。
- 添加边界测试 (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- 替换不现实的 mocks；模拟失败模式。
- 迭代直到所有变异体被消灭，或以注释和理由解释清楚。

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
