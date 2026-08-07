# ERC-4337 Smart Account 安全陷阱

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 账户抽象将钱包转变为可编程系统。核心流程是对整个 bundle 执行 **validate-then-execute**：`EntryPoint` 会在执行任何 `UserOperation` 之前验证每一个 `UserOperation`。当验证逻辑过于宽松、具有状态依赖，或与 bundler simulation 规则不一致时，这种顺序会产生不明显的攻击面。

## 1) 对特权函数的直接调用绕过
任何可从外部调用的 `execute`（或资金转移）函数，如果未限制为只能由 `EntryPoint`（或经过审查的 executor module）调用，就可能被直接调用以耗尽账户资金。<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全模式：将调用限制为 `EntryPoint`，并在管理员/自管理流程（模块安装、validator 变更、升级）中使用 `msg.sender == address(this)`。
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 未签名或未检查的 gas 字段 -> fee drain
如果签名验证只覆盖 intent（`callData`），而不覆盖与 gas 相关的字段，bundler 或 frontrunner 就可以抬高费用并 drain ETH。签名 payload 至少必须绑定以下字段：<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

防御模式：使用 `EntryPoint` 提供的 `userOpHash`（其中包含 gas 字段），和/或严格限制每个字段的上限。<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering（bundle 语义）
由于所有 validation 都会在任何 execution 之前运行，因此将 validation 结果存储在合约状态中是不安全的。同一 bundle 中的另一个 op 可能覆盖该结果，导致 execution 使用受攻击者影响的状态。<sup>[[1]](#references)</sup>

避免在 `validateUserOp` 中写入 storage。如果无法避免，应按 `userOpHash` 为临时数据建立索引，并在使用后以确定性方式删除这些数据（优先采用 stateless validation）。<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains（缺少 domain separation）
`isValidSignature(bytes32 hash, bytes sig)` 必须将签名绑定到**当前合约**和**当前 chain**。如果基于 raw hash 进行 recover，签名就可能在不同账户或 chain 之间 replay。<sup>[[1]](#references)</sup>

使用 EIP-712 typed data（domain 包含 `verifyingContract` 和 `chainId`），并在成功时返回精确的 ERC-1271 magic value `0x1626ba7e`。<sup>[[1]](#references)</sup>

## 5) validation 后发生 revert 不会退款
一旦 `validateUserOp` 成功，即使 execution 随后 revert，费用仍已提交。攻击者可以反复提交最终会失败的 op，同时继续从账户收取费用。<sup>[[1]](#references)</sup>

对于 paymaster，在 `validateUserOp` 中从共享 pool 支付款项、再在 `postOp` 中向用户收费，这种做法很脆弱，因为 `postOp` 可能 revert，且不会撤销已经支付的款项。在 validation 期间确保资金安全（使用按用户划分的 escrow/deposit），让 `postOp` 保持最小化且不发生 revert，并针对最坏情况下的 reimbursement 路径为 `paymasterPostOpGasLimit` 预留足够预算。<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
第一个 `UserOperation` 通常会携带 `initCode`，这会导致账户在 validation 期间通过 **factory** 部署。这条路径很容易审计不足，因为它只会在首次使用时运行。<sup>[[2]](#references)</sup>

常见故障：

- factory/initializer 信任 `msg.sender == entryPoint`，但 ERC-4337 deployment 路径**不会**直接从 `EntryPoint` 调用 `initCode`。
- salt、owner、validator 或 module 配置没有完全绑定到已签名的 intent，因此 frontrunner 可以抢先完成首次 deployment，并使用攻击者控制的设置占用 counterfactual address。
- factory 不是幂等的，因此重复的首次使用流程会使 wallet 失效，而不是返回已创建的 address。

安全模式：根据已签名的 deployment 参数重新计算预期的 sender，使 deployment 具备确定性（通常使用 `CREATE2`），并使 initialization 只能执行一次。<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Bundlers 拒绝的 Validation 逻辑
Validation 代码在本地测试中可能完全正确，但在真实 Bundlers 中仍然无法使用。公共 Bundlers 会在链下模拟 `validateUserOp()` / `validatePaymasterUserOp()`，并且通常会在纳入前对 `handleOps` 执行完整的 `debug_traceCall`。

因此，在 Validation 中使用以下模式会带来风险：

- 依赖区块的 opcode，例如 `TIMESTAMP`、`NUMBER` 或 `BLOCKHASH`
- 状态写入，例如 `SSTORE`
- 对 storage 进行无界迭代
- 任意外部调用，或可能在模拟与纳入之间发生变化的 oracle 读取

错误示例：
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
将 validation 视为确定性且有界的 preflight 函数。如果确实需要共享状态或外部查询，应将该复杂性转移到具有质押和 reputation tracking 的实体中，并测试确切的 bundler simulation 路径，而不只是进行 unit tests。

## 8) ERC-7702 initialization frontrun
ERC-7702 允许 EOA 在单笔 tx 中运行 smart-account code。如果 initialization 可被外部调用，frontrunner 就可以将自己设置为 owner。<sup>[[1]](#references)</sup>

Mitigation：仅允许通过 **self-call** 进行 initialization，并且只能执行一次。<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## 合并前快速检查
- 使用 `EntryPoint` 的 `userOpHash` 验证签名（绑定 gas 字段）。
- 根据适用情况，将特权函数限制为仅允许 `EntryPoint` 和/或 `address(this)` 调用。
- 保持 `validateUserOp` 无状态、确定性，并兼容 bundler simulation 规则。
- 为 ERC-1271 强制执行 EIP-712 domain separation，并在成功时返回 `0x1626ba7e`。
- 保持 `postOp` 简洁、有界且不会 revert；在验证期间确保费用安全。
- 单独测试首次 `initCode` 路径：确定性部署、factory 行为幂等，以及一次性初始化。
- 在发布前运行完整的 bundler simulation（`simulateValidation` 加上带 trace 的 `handleOps`）。
- 对于 ERC-7702，仅允许在 self-call 时进行初始化，并且只能初始化一次。



## 参考资料

- [1] [ERC-4337 smart accounts 的六个错误（Trail of Bits）](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337：使用 Alt Mempool 的账户抽象](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
