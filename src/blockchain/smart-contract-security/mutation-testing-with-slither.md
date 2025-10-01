# 用 Slither (slither-mutate) 对 Solidity 进行变异测试

{{#include ../../banners/hacktricks-training.md}}

变异测试通过在你的 Solidity 代码中系统性地引入小改动（突变体）并重新运行测试套件来“测试你的测试”。如果某个测试失败，该突变体就被消灭；如果测试仍然通过，该突变体就存活，从而暴露出行/分支覆盖率无法检测到的测试盲点。

关键思想：覆盖率说明代码被执行过；变异测试说明行为是否真正被断言。

## 为什么覆盖率会误导

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
单元测试如果只检查阈值以下和阈值以上的值，可能在行/分支覆盖率上达到 100%，但却没有断言等于边界 (==)。将条件重构为 `deposit >= 2 ether` 仍会通过这样的测试，从而在不发声的情况下破坏协议逻辑。

Mutation testing 通过变异条件并验证你的测试是否失败来暴露这个缺口。

## Common Solidity mutation operators

Slither 的变异引擎会应用许多小的、改变语义的修改，例如：
- 运算符替换：`+` ↔ `-`, `*` ↔ `/`, 等等
- 赋值替换：`+=` → `=`, `-=` → `=`
- 常量替换：non-zero → `0`, `true` ↔ `false`
- 在 `if`/loops 中对条件取反/替换
- 注释掉整行 (CR: Comment Replacement)
- 用 `revert()` 替换整行
- 数据类型互换：例如，`int128` → `int64`

目标：杀死 100% 的生成突变体，或用明确的理由说明幸存者。

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+。

- 列出选项和变异器：
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry 示例（捕获结果并保留完整日志）：
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- 如果你不使用 Foundry，请将 `--test-cmd` 替换为你运行测试的方式（例如：`npx hardhat test`、`npm test`）。

Artifacts and reports are stored in `./mutation_campaign` by default. 未被捕获（存活）的变异体会被复制到该目录以便检查。

### 理解输出

报告行如下：
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- 方括号中的标签是变异器别名（例如，`CR` = Comment Replacement）。
- `UNCAUGHT` 表示在被变异的行为下测试通过 → 缺失断言。

## 减少运行时间：优先考虑有影响的变异体

Mutation campaigns can take hours or days. Tips to reduce cost:
- Scope: 仅针对关键合约/目录开始，然后再扩展。
- Prioritize mutators: 如果某行上的高优先级变体幸存（例如，整行被注释），则可以跳过该行的低优先级变体。
- Parallelize tests if your runner allows it; cache dependencies/builds.
- Fail-fast: 在修改清晰地暴露断言缺失时尽早终止。

## 幸存变体的分流工作流程

1) 检查被变异的行和行为。
- 通过应用被变异的那一行并运行针对性的测试，在本地重现。

2) 强化测试以断言状态，而不仅仅是返回值。
- 添加等式/边界检查（例如，测试阈值 `==`）。
- 断言后置条件：balances、total supply、authorization effects，以及 emitted events。

3) 用真实行为替换过于宽松的 mocks。
- 确保 mocks 强制执行 transfers、failure paths，以及链上会发生的 event emissions。

4) 为 fuzz 测试添加不变量。
- 例如，conservation of value、non-negative balances、authorization invariants，以及在适用时的 monotonic supply。

5) 重新运行 slither-mutate，直到幸存者被消除或有明确理由保留为止。

## 案例研究：揭示缺失的状态断言 (Arkis protocol)

在对 Arkis DeFi protocol 的审计期间进行的一次变异测试活动暴露出了如下幸存者：
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
注释掉赋值并未导致测试失败，证明缺少后置状态断言。根本原因：代码信任了用户可控的 `_cmd.value`，而没有验证实际的代币转移。攻击者可以使预期转移与实际转移不同步，从而抽干资金。结果：对协议偿付能力构成高严重性风险。

Guidance: 将影响价值转移、会计或访问控制的存活变异体视为高风险，直到其被消灭。

## Practical checklist

- 运行有针对性的变异测试：
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- 筛查存活的变异体，并编写在变异行为下会失败的测试/不变量。
- 断言余额、供应量、授权和事件。
- 添加边界测试（`==`、溢出/下溢、零地址、零数额、空数组）。
- 替换不现实的 mocks；模拟失败模式。
- 重复迭代，直到所有变异体被消灭或通过注释与理由得到证明。

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
