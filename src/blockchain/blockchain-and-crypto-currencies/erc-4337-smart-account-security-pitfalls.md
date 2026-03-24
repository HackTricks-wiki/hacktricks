# ERC-4337 智能账户的安全陷阱

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 的账户抽象将钱包变成可编程的系统。核心流程是在整个捆绑上执行 **validate-then-execute**：`EntryPoint` 会在执行任何 `UserOperation` 之前验证每个操作。此执行顺序在验证策略宽松或有状态时会产生不明显的攻击面。

## 1) 通过直接调用绕过特权函数
任何可被外部调用的 `execute`（或移动资金的）函数，如果没有限制仅由 `EntryPoint`（或经审查的执行器模块）调用，就可以被直接调用以清空账户资金。
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全做法：将范围限制为 `EntryPoint`，并在管理员/自管理流程（模块安装、验证者更改、升级）中使用 `msg.sender == address(this)`。
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 未签名或未校验的 gas 字段 -> 费用耗尽
如果签名校验只覆盖意图 (`callData`) 但不覆盖与 gas 相关的字段，bundler 或 frontrunner 可以抬高费用并抽干 ETH。签名的 payload 必须至少绑定：

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

防御性模式：使用 `EntryPoint` 提供的 `userOpHash`（它包含 gas 字段）和/或严格限制每个字段的上限。
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle semantics)
由于所有验证在任何执行之前运行，将验证结果存储在合约状态中是不安全的。同一 bundle 中的另一个 op 可能会覆盖它，导致你的执行使用被攻击者影响的状态。

避免在 `validateUserOp` 中写入 storage。如果不得不写，使用 `userOpHash` 对临时数据建键，并在使用后确定性地删除（优先采用无状态验证）。

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` 必须把签名绑定到 **本合约** 和 **本链**。对原始 hash 进行 recover 会让签名在不同账户或链上重放。

使用 EIP-712 typed data（domain 包含 `verifyingContract` 和 `chainId`），并在成功时返回准确的 ERC-1271 魔术值 `0x1626ba7e`。

## 5) Reverts do not refund after validation
一旦 `validateUserOp` 成功，费用即已锁定，即使后续执行 revert，也不会退回。攻击者可以反复提交会失败的 ops，仍然从账户中收取费用。

对于 paymasters 来说，在 `validateUserOp` 中从共享池付款并在 `postOp` 向用户收费是脆弱的，因为 `postOp` 可能 revert 而不撤销付款。在验证期间确保资金安全（按用户托管/存款），并让 `postOp` 保持最小化且不发生 revert。

## 6) ERC-7702 initialization frontrun
ERC-7702 允许一个 EOA 在单个 tx 中运行 smart-account 代码。如果初始化可以外部调用，frontrunner 可以将自己设置为 owner。

缓解：仅允许在 **self-call** 时初始化，且仅允许执行一次。
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## 快速合并前检查
- 使用 `EntryPoint` 的 `userOpHash` 验证签名（绑定 gas 字段）。
- 将特权函数限制为 `EntryPoint` 和/或 `address(this)`（视情况而定）。
- 保持 `validateUserOp` 无状态。
- 对 ERC-1271 强制执行 EIP-712 域分离，并在成功时返回 `0x1626ba7e`。
- 保持 `postOp` 最小、有界且不回退；在验证期间确保费用安全。
- 对于 ERC-7702，只允许在自调用时初始化，且只能执行一次。

## 参考资料

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
