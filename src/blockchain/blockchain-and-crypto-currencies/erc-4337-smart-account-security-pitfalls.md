# ERC-4337 Smart Account 安全隐患

ERC-4337 account abstraction 将钱包转变为可编程系统。核心流程是跨整个 bundle 的 **validate-then-execute**：`EntryPoint` 会在执行任何 `UserOperation` 之前，验证每一个 `UserOperation`。<sup>[[5]](#references)</sup> 当验证逻辑过于宽松、具有状态性，或与 bundler simulation rules 不一致时，这种执行顺序会产生不明显的 attack surface。

## 1) 对特权函数的 Direct-call bypass
任何可从外部调用、且未限制为仅允许 `EntryPoint`（或经过审核的 executor module）调用的 `execute`（或转移资金）函数，都可能被直接调用以耗尽账户资金。<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
安全模式：将调用限制为 `EntryPoint`，并在 admin/self-management 流程（模块安装、validator 更改、升级）中使用 `msg.sender == address(this)`。<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) 未签名或未检查的 gas 字段 -> 费用耗尽
如果签名验证只涵盖意图（`callData`），而不涵盖与 gas 相关的字段，bundler 或 frontrunner 就可以抬高费用并耗尽 ETH。签名载荷至少必须绑定以下字段：<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

防御模式：使用 `EntryPoint` 提供的 `userOpHash`（其中包含 gas 字段），和/或严格限制每个字段的上限。<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) 有状态 validation 覆盖（bundle 语义）
由于所有 validation 都会在任何 execution 之前运行，将 validation 结果存储在 contract state 中是不安全的。同一个 bundle 中的另一个 op 可能覆盖该结果，导致 execution 使用受 attacker 影响的 state。<sup>[[2]](#references)</sup>

避免在 `validateUserOp` 中写入 storage。如果无法避免，应以 `userOpHash` 作为临时数据的 key，并在使用后以确定性方式删除这些数据（优先采用 stateless validation）。<sup>[[2]](#references)</sup>

## 4) ERC-1271 跨 account/chain replay（缺少 domain separation）
`isValidSignature(bytes32 hash, bytes sig)` 必须将签名绑定到**当前 contract**和**当前 chain**。如果基于 raw hash 进行恢复，签名可能在不同 account 或 chain 之间 replay。<sup>[[1]](#references)[[4]](#references)</sup>

使用 EIP-712 typed data（domain 包含 `verifyingContract` 和 `chainId`），并在成功时返回准确的 ERC-1271 magic value `0x1626ba7e`。<sup>[[3]](#references)[[4]](#references)</sup>

## 5) validation 后的 revert 不会退款
一旦 `validateUserOp` 成功，即使 execution 随后 revert，费用仍会被提交。攻击者可以反复提交将会失败的 op，同时仍从 account 收取费用。<sup>[[2]](#references)</sup>

对于 paymaster，在 `validateUserOp` 中从共享 pool 支付款项、再在 `postOp` 中向用户收费是一种脆弱设计，因为 `postOp` 可能在不撤销付款的情况下 revert。在 validation 期间确保资金安全（使用每用户 escrow/deposit），保持 `postOp` 简洁且不会 revert，并根据最坏情况下的 reimbursement 路径为 `paymasterPostOpGasLimit` 预留足够预算。<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory 假设
第一个 `UserOperation` 通常会携带 `initCode`，导致 account 在 validation 期间通过 **factory** 部署。这条路径很容易被低估审计，因为它只会在首次使用时运行。<sup>[[5]](#references)</sup>

常见故障包括：<sup>[[5]](#references)</sup>

- factory/initializer 信任 `msg.sender == entryPoint`，但 ERC-4337 deployment 路径**不会**从 `EntryPoint` 直接调用 `initCode`。
- salt、owner、validator 或 module 配置没有完全绑定到已签名的 intent，因此 frontrunner 可以抢先执行首次部署，并使用 attacker 控制的设置占用 counterfactual address。
- factory 不是幂等的，因此重复的首次使用流程会使 wallet 无法使用，而不是返回已经创建的 address。

安全模式：根据已签名的 deployment 参数重新计算预期 sender，使 deployment 具有确定性（通常使用 `CREATE2`），并使 initialization 只能执行一次。<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) bundler 会拒绝的验证逻辑
验证代码可能在本地测试中正确，但在真实 bundler 中仍然无法使用。bundler 会多次运行验证，并应在提交前执行经过追踪的完整 bundle 验证。<sup>[[6]](#references)</sup>

根据这些验证范围规则，以下模式存在危险：<sup>[[6]](#references)</sup>

- 依赖区块的 opcode，例如 `TIMESTAMP`、`NUMBER` 或 `BLOCKHASH`
- 在允许的账户/实体范围之外访问 Storage，或对 Storage 进行无界迭代
- 依赖允许验证范围之外的可变状态的外部调用或 oracle 读取

错误示例：
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // stateful validation can be clobbered by another op
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
将 validation 视为一个确定性、有界的 preflight function。如果必须使用共享状态或进行外部查询，请遵循 staked-entity 规则，并测试相同的多轮 bundler simulation 路径，而不只是进行 unit tests。<sup>[[6]](#references)</sup>

## 8) ERC-7702 初始化 frontrun
ERC-7702 为 EOA 提供了对 smart-account 代码的持久 delegation；该 delegation 不会以原子方式运行初始化。如果初始化可被外部调用，观察者就可以对其进行 front-run，并将自己设置为 owner。<sup>[[7]](#references)</sup>

缓解措施：要求初始化 calldata 获得 EOA 授权，并且只允许初始化一次。在 ERC-4337 EIP-7702 流程中，还应将调用者限制为 `EntryPoint.senderCreator()`。<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## 合并前快速检查
- 使用 `EntryPoint` 的 `userOpHash` 验证签名（绑定 gas 字段）。
- 根据实际情况，将特权函数限制为 `EntryPoint` 和/或 `address(this)`。
- 保持 `validateUserOp` 无状态、确定性，并符合 bundler simulation 规则。
- 为 ERC-1271 强制实施 EIP-712 domain separation，并在成功时返回 `0x1626ba7e`。
- 保持 `postOp` 简洁、有界且不引发 revert；在验证期间确保费用安全。
- 单独测试首个 `initCode` 路径：确定性部署、factory 行为幂等，以及一次性初始化。
- 在发布前运行 bundler 的多轮验证和带 trace 的完整 bundle 检查。
- 对于 ERC-7702，将 init 绑定到 EOA authorization，并且仅允许执行一次；在 ERC-4337 flows 中，将 caller 限制为 `EntryPoint.senderCreator()`。

## References

- [1] [ERC1271 Replay - 15+ Teams Affected (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [ERC-4337 smart accounts 中的六个错误 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271：合约的标准签名验证方法](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712：类型化结构化数据的 hashing 和 signing](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337：使用 Alt Mempool 的账户抽象](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562：账户抽象验证范围规则](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702：为 EOA 设置 Code](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
