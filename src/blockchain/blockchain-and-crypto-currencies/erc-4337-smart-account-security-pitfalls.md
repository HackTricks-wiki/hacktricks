# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction 将钱包变成可编程系统。核心流程是整个 bundle 的 **validate-then-execute**：`EntryPoint` 会先验证每个 `UserOperation`，然后再执行它们。这种顺序在 validation 宽松、有状态，或与 bundler simulation 规则不一致时，会产生不明显的 attack surface。

## 1) Direct-call bypass of privileged functions
任何可被外部调用的 `execute`（或资金转移）函数，如果没有限制为仅 `EntryPoint`（或经过验证的 executor module）可调用，就可以被直接调用，从而掏空账户。
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全模式：将范围限制为 `EntryPoint`，并在管理/自我管理流程中（模块安装、验证器更改、升级）使用 `msg.sender == address(this)`。
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 未签名或未检查的 gas 字段 -> fee drain
如果签名验证只覆盖 intent（`callData`），但不覆盖与 gas 相关的字段，那么 bundler 或 frontrunner 就可以抬高费用并 drain ETH。签名负载至少必须绑定：

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

防御模式：使用 `EntryPoint` 提供的 `userOpHash`（其中包含 gas 字段），和/或严格限制每个字段的上限。
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
因为所有 validations 都会在任何 execution 之前运行，所以把 validation 结果存到 contract state 里是不安全的。同一个 bundle 里的另一个 op 可能会覆盖它，导致你的 execution 使用 attacker 影响的 state。

避免在 `validateUserOp` 里写 storage。如果无法避免，就用 `userOpHash` 给临时数据做 key，并在使用后以确定性方式删除它（最好还是使用无状态 validation）。

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` 必须把 signatures 绑定到 **这个 contract** 和 **这条 chain**。对原始 hash 做 recover 会让 signatures 在不同 accounts 或 chains 之间 replay。

使用 EIP-712 typed data（domain 包含 `verifyingContract` 和 `chainId`），并在成功时返回精确的 ERC-1271 magic value `0x1626ba7e`。

## 5) Reverts do not refund after validation
一旦 `validateUserOp` 成功，即使后面的 execution revert，fees 也已经被锁定。攻击者可以反复提交会失败的 ops，但仍然从 account 中收取 fees。

对于 paymasters，在 `validateUserOp` 里从 shared pool 支付、再在 `postOp` 里向 users 收费这种方式很脆弱，因为 `postOp` 可能会 revert，而且不会撤销之前的 payment。应在 validation 期间就锁定 funds（按 user 的 escrow/deposit），保持 `postOp` 尽量简短且不 revert，并为最坏情况的 reimbursement path 预留 `paymasterPostOpGasLimit`。

## 6) Counterfactual deployment / factory assumptions
第一个 `UserOperation` 通常会带有 `initCode`，这会让 account 在 validation 期间通过一个 **factory** 被部署。这个路径很容易被低估审计，因为它只在首次使用时运行。

常见失败包括：

- factory/initializer 信任 `msg.sender == entryPoint`，但 ERC-4337 的 deployment path 并不会直接从 `EntryPoint` 调用 `initCode`。
- salt、owner、validator 或 module configuration 没有完全绑定到已签名的 intent，因此 frontrunner 可以抢在首次部署前完成竞争，并用 attacker-controlled 的设置烧掉这个 counterfactual address。
- factory 不是 idempotent，所以重复的首次使用流程会把 wallet 变砖，而不是返回已经创建好的 address。

安全模式：根据已签名的 deployment 参数重新计算预期的 sender，使 deployment 可确定性复现（通常是 `CREATE2`），并让 initialization 只能执行一次。
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundlers 拒绝的 validation logic
Validation code 在本地测试中可能是正确的，但在真实 bundlers 中仍然可能无法使用。Public bundlers 会在链下模拟 `validateUserOp()` / `validatePaymasterUserOp()`，并且通常会在纳入之前完整运行 `debug_traceCall(handleOps)`。

这使得以下模式在 validation 中很危险：

- 依赖区块的 opcode，例如 `TIMESTAMP`、`NUMBER` 或 `BLOCKHASH`
- 状态写入，例如 `SSTORE`
- 对 storage 的无限迭代
- 任意 external calls 或 oracle reads，这些内容可能在 simulation 和纳入之间发生变化

Bad example:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // SSTORE in validation
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
将验证视为一个确定性的、有边界的预检函数。如果你确实需要共享状态或外部查询，就把这些复杂性推到有 stake/声誉跟踪的实体中，并测试精确的 bundler simulation 路径，而不只是单元测试。

## 8) ERC-7702 initialization frontrun
ERC-7702 允许一个 EOA 在单笔 tx 中运行 smart-account 代码。如果 initialization 可被外部调用，frontrunner 就可以把自己设为 owner。

Mitigation: 只允许在 **self-call** 时进行 initialization，并且只能一次。
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Quick pre-merge checks
- 使用 `EntryPoint` 的 `userOpHash` 验证签名（绑定 gas 字段）。
- 将特权函数限制为 `EntryPoint` 和/或 `address(this)`，视情况而定。
- 保持 `validateUserOp` 无状态、确定性，并兼容 bundler simulation 规则。
- 为 ERC-1271 强制执行 EIP-712 domain separation，并在成功时返回 `0x1626ba7e`。
- 保持 `postOp` 最小化、有上限且不回滚；在 validation 期间确保费用安全。
- 单独测试第一个 `initCode` 路径：确定性部署、factory 的幂等行为，以及一次性初始化。
- 在发布前运行完整的 bundler simulation（`simulateValidation` 加上带 trace 的 `handleOps`）。
- 对于 ERC-7702，只允许在 self-call 时初始化，并且只能一次。



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
