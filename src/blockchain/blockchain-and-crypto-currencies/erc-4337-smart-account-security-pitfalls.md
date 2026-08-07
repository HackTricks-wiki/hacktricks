# ERC-4337 Smart Account 安全陷阱

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction 将钱包转变为可编程系统。核心流程是针对整个 bundle 执行 **validate-then-execute**：`EntryPoint` 会在执行任何 `UserOperation` 之前验证每一个 `UserOperation`。当验证逻辑过于宽松、具有状态性，或与 bundler simulation 规则不一致时，这种执行顺序会产生不明显的攻击面。

## 1) 对特权函数的直接调用绕过
任何可从外部调用的 `execute`（或转移资金）函数，如果没有限制为仅允许 `EntryPoint`（或经过审核的 executor module）调用，就可能被直接调用以耗尽账户资金。<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全模式：将调用限制为 `EntryPoint`，并在 admin/自管理流程（模块安装、validator 更改、升级）中使用 `msg.sender == address(this)`。
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 未签名或未检查的 gas 字段 -> fee drain
如果签名验证仅覆盖意图（`callData`），却未覆盖与 gas 相关的字段，bundler 或 frontrunner 便可抬高费用并 drain ETH。签名 payload 至少必须绑定以下字段：<sup>[[1]](#references)</sup>

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
## 3) 有状态验证覆盖（bundle 语义）
由于所有验证都会在任何执行之前运行，因此将验证结果存储在合约状态中是不安全的。同一 bundle 中的其他 op 可能覆盖该结果，导致你的执行使用受攻击者影响的状态。<sup>[[1]](#references)</sup>

避免在 `validateUserOp` 中写入 storage。如果无法避免，应使用 `userOpHash` 作为临时数据的键，并在使用后以确定性方式删除这些数据（优先采用无状态验证）。<sup>[[1]](#references)</sup>

## 4) ERC-1271 跨账户/跨链重放（缺少域分离）
`isValidSignature(bytes32 hash, bytes sig)` 必须将签名绑定到**当前合约**和**当前链**。如果仅针对原始 hash 进行恢复，签名就可能在不同账户或不同链之间重放。<sup>[[1]](#references)</sup>

使用 EIP-712 typed data（domain 包含 `verifyingContract` 和 `chainId`），并在成功时返回准确的 ERC-1271 magic value `0x1626ba7e`。<sup>[[1]](#references)</sup>

## 5) 验证后发生 revert 不会退款
一旦 `validateUserOp` 成功，即使执行随后发生 revert，费用也已经被确认。攻击者可以反复提交最终会失败的 op，仍然从账户中收取费用。<sup>[[1]](#references)</sup>

对于 paymasters，在 `validateUserOp` 中从共享池支付、并在 `postOp` 中向用户收费，这种做法很脆弱，因为 `postOp` 可能 revert，且不会撤销之前的支付。在验证期间确保资金安全（使用按用户划分的 escrow/deposit），使 `postOp` 保持最小化且不发生 revert，并针对最坏情况下的补偿路径为 `paymasterPostOpGasLimit` 预留足够预算。<sup>[[1]](#references)</sup>

## 6) 反事实部署 / factory 假设
第一个 `UserOperation` 通常会携带 `initCode`，导致账户在验证期间通过 **factory** 部署。这条路径很容易因仅在首次使用时运行而缺乏充分审计。<sup>[[2]](#references)</sup>

常见失败包括：

- factory/initializer 信任 `msg.sender == entryPoint`，但 ERC-4337 部署路径**不会**直接从 `EntryPoint` 调用 `initCode`。
- salt、owner、validator 或 module 配置没有完全绑定到签名意图，因此 frontrunner 可以抢先执行首次部署，并使用攻击者控制的设置占用反事实地址。
- factory 不是幂等的，因此重复的首次使用流程会使钱包失效，而不是返回已创建的地址。

安全模式：根据已签名的部署参数重新计算预期 sender，使部署具有确定性（通常使用 `CREATE2`），并使初始化只能执行一次。<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundlers 会拒绝的 Validation 逻辑
Validation 代码可能在本地测试中完全正确，但在真实 bundlers 中仍然无法使用。公共 bundlers 会在链下模拟 `validateUserOp()` / `validatePaymasterUserOp()`，并且通常会在纳入区块前运行完整的 `debug_traceCall(handleOps)`。<sup>[[3]](#references)</sup>

因此，在 Validation 中使用以下模式会带来风险：

- 依赖区块的 opcode，例如 `TIMESTAMP`、`NUMBER` 或 `BLOCKHASH`
- 状态写入，例如 `SSTORE`
- 对 storage 进行无界迭代
- 任意 external calls 或 oracle 读取，这些数据可能在模拟和纳入区块之间发生变化

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
将 validation 视为一个确定性、有界的 preflight 函数。如果确实需要共享状态或外部查询，应将此复杂性转移到具有质押和 reputation-tracked 的实体中，并测试确切的 bundler simulation 路径，而不仅仅是进行 unit tests。

## 8) ERC-7702 初始化抢跑

ERC-7702 允许 EOA 在单个 tx 中运行 smart-account 代码。如果初始化函数可被外部调用，抢跑者就可以将自己设置为 owner。<sup>[[1]](#references)</sup>

缓解措施：仅允许通过 **self-call** 进行初始化，并且只能初始化一次。<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## 合并前快速检查
- 使用 `EntryPoint` 的 `userOpHash` 验证签名（绑定 gas 字段）。
- 根据适用情况，将特权函数限制为仅可由 `EntryPoint` 和/或 `address(this)` 调用。
- 保持 `validateUserOp` 无状态、确定性，并兼容 bundler simulation 规则。
- 为 ERC-1271 强制执行 EIP-712 domain separation，并在成功时返回 `0x1626ba7e`。
- 保持 `postOp` 简洁、有界且不会 revert；在验证期间确保费用安全。
- 单独测试第一条 `initCode` 路径：确定性部署、幂等的 factory 行为，以及一次性初始化。
- 在发布前运行完整的 bundler simulation（`simulateValidation` 加上带 trace 的 `handleOps`）。
- 对于 ERC-7702，仅允许在 self-call 中进行 init，并且只能执行一次。

## 参考资料

- [1] [ERC-4337 smart accounts 的六个错误（Trail of Bits）](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337：使用 Alt Mempool 的账户抽象](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562：账户抽象验证范围规则](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
