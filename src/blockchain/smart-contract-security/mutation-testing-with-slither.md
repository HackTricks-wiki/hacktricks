# 使用 Slither 的 Solidity 变异测试 (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

变异测试通过系统性地在你的 Solidity 代码中引入小改动 (mutants) 并重新运行你的测试套件来“测试你的测试”。如果一个测试失败，该 mutant 就被杀死。如果测试仍然通过，该 mutant 存活，暴露出你的测试套件中的盲点，这是行/分支覆盖率无法检测到的。

关键点：覆盖率显示代码被执行；变异测试显示行为是否被真正断言。

## 覆盖率可能会误导

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
仅检查阈值以下和阈值以上值的单元测试，可能达到 100% 的行/分支覆盖率，但仍未断言相等边界 (==)。如果重构为 `deposit >= 2 ether`，这些测试仍会通过，从而在不知情的情况下破坏协议逻辑。

变异测试通过修改条件并验证你的测试会失败来暴露这一漏洞。

## 常见的 Solidity 变异操作符

Slither 的变异引擎会应用许多小的、改变语义的修改，例如：
- 运算符替换：`+` ↔ `-`、`*` ↔ `/` 等
- 赋值替换：`+=` → `=`、`-=` → `=`
- 常量替换：非零 → `0`、`true` ↔ `false`
- 在 `if`/循环 内对条件取反或替换
- 注释整行（CR: Comment Replacement）
- 将一行替换为 `revert()`
- 数据类型交换：例如 `int128` → `int64`

目标：杀死 100% 的生成变体，或对幸存者给出明确的理由说明。

## 使用 slither-mutate 运行变异测试

要求：Slither v0.10.2+。

- 列出选项和 mutators：
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 示例（捕获结果并保留完整日志):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- 如果你不使用 Foundry，请把 `--test-cmd` 替换成你运行测试的方式（例如：`npx hardhat test`、`npm test`）。

产物和报告默认存放在 `./mutation_campaign`。未被捕获（存活）的变异体会被复制到该目录以便检查。

### 理解输出

报告行如下所示：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 方括号内的标签是 mutator 别名（例如，`CR` = Comment Replacement）。
- `UNCAUGHT` 表示 tests 在被修改的行为下通过 → 缺少断言。

## 减少运行时间：优先考虑高影响的 mutants

Mutation campaigns 可能需要数小时或数天。降低成本的技巧：
- 范围：先只从关键 contracts/directories 开始，然后再扩展。
- 优先 mutators：如果某行上的高优先级 mutant 存活（例如，整行被注释），可以跳过该行的低优先级变体。
- 如果你的 runner 支持，则并行运行 tests；缓存 dependencies/builds。
- Fail-fast：当变更明显展示出断言缺失时，尽早停止。

## 对存活 mutants 的甄别工作流

1) 检查被修改的行和行为。
- 通过应用该被修改的行并运行针对性的 test 在本地重现。

2) 强化 tests，断言状态而不仅仅是返回值。
- 添加等值/边界检查（例如，测试阈值 `==`）。
- 断言后置条件：balances、total supply、authorization 效果，以及 emitted events。

3) 用更真实的行为替换过于宽松的 mocks。
- 确保 mocks 强制执行 transfers、failure paths 和链上会发生的 event emissions。

4) 为 fuzz tests 增加不变量。
- 例如：conservation of value、非负 balances、authorization 不变量，以及适用时单调的 supply。

5) 反复运行 slither-mutate，直到 survivors 被消灭或有明确理由说明其存在。

## 案例研究：揭示缺失的状态断言（Arkis protocol）

在对 Arkis DeFi protocol 的审计过程中，一次 mutation campaign 发现了类似以下的 survivors：
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenting out the assignment didn’t break the tests, proving missing post-state assertions. Root cause: code trusted a user-controlled `_cmd.value` instead of validating actual token transfers. An attacker could desynchronize expected vs. actual transfers to drain funds. Result: high severity risk to protocol solvency.

Guidance: Treat survivors that affect value transfers, accounting, or access control as high-risk until killed.

## Practical checklist

- 运行一次有针对性的 campaign：
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 对幸存者进行分流（triage），并编写在变异行为下会失败的测试/不变量。
- 断言余额、供应、授权和事件。
- 添加边界测试（`==`、overflows/underflows、零地址、零金额、空数组）。
- 替换不现实的 mocks；模拟失败模式。
- 迭代直到所有变异体被消除或通过注释和理由得到合理解释。

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
