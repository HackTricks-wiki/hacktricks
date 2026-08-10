# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

## 概述

一次 cold-wallet theft chain 将 **Safe{Wallet} web UI 的 supply-chain compromise** 与一种 **on-chain delegatecall primitive** 结合，该 primitive 覆写了 proxy 的 implementation pointer（slot 0）。关键要点如下：

- 如果 dApp 能够向 signing path 注入 code，就可以让 signer 针对攻击者选择的 fields 生成有效的 **EIP-712 signature**，同时恢复原始 UI data，使其他 signers 不知情。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies 将 `masterCopy`（implementation）存储在 **storage slot 0**。向一个会写入 slot 0 的 contract 发起 delegatecall，实际上就能将 Safe “升级”为攻击者的 logic，从而完全控制 wallet。<sup>[[3]](#references)</sup>

## Off-chain：Safe{Wallet} 中针对性的 signing mutation

被篡改的 Safe bundle（`_app-*.js`）会选择性攻击特定的 Safe + signer addresses。注入的 logic 会在 signing call 前立即执行：<sup>[[1]](#references)[[3]](#references)</sup>
```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
tx.data.to = attackerContract;
tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
tx.data.operation = 1;                 // delegatecall
tx.data.value = 0;
tx.data.safeTxGas = 45746;
const sig = await sdk.signTransaction(tx, safeVersion);
sig.data = orig;                       // restore original before submission
tx.data = orig;
return sig;
}
```
### 攻击属性
- **Context-gated**：针对受害者 Safe/signers 的硬编码 allowlists 减少了噪声并降低了 detection 风险。<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**：`to`、`data`、`operation`、gas 等字段在 `signTransaction` 之前立即被覆写，随后又恢复，因此 UI 中的 proposal payload 看起来是良性的，但 signatures 实际匹配的是 attacker payload。<sup>[[3]](#references)</sup>
- **EIP-712 opacity**：wallets 会显示结构化数据，但不会 decode 嵌套 calldata，也不会突出显示 `operation = delegatecall`，使被 mutation 的消息实际上变成 blind-signed。<sup>[[3]](#references)[[4]](#references)</sup>

### Gateway validation relevance
Safe proposals 会提交到 **Safe Client Gateway**。<sup>[[5]](#references)</sup> 在 hardened checks 实施之前，如果 UI 在 signing 后重写相关字段，gateway 可能接受 `safeTxHash`/signature 与 JSON body 中不同字段相对应的 proposal。事件发生后，gateway 现在会拒绝 hash/signature 与所提交 transaction 不匹配的 proposals。<sup>[[3]](#references)</sup>任何 signing-orchestration API 都应实施类似的 server-side hash verification。

### 2025 Bybit/Safe incident highlights
- 2025 年 2 月 21 日的 Bybit cold-wallet drain（约 401k ETH）复用了相同模式：被 compromise 的 Safe S3 bundle 仅对 Bybit signers 触发，并将 `operation=0` → `1`，将 `to` 指向一个预先部署的 attacker contract，该 contract 会写入 slot 0。<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback 缓存的 `_app-52c9031bfa03da47.js` 显示，该逻辑以 Bybit 的 Safe（`0x1db9…cf4`）和 signer addresses 为条件，随后在 execution 两分钟后立即恢复为 clean bundle，复现了“mutate → sign → restore”技巧。<sup>[[1]](#references)[[2]](#references)</sup>
- 恶意 contract（例如 `0x9622…c7242`）包含简单的 `sweepETH/sweepERC20` 函数，以及一个会写入 implementation slot 的 `transfer(address,uint256)`。执行 `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` 会改变 proxy implementation 并取得完整控制权。<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies 将 `masterCopy` 保存在 **storage slot 0**，并将所有逻辑 delegate 给它。由于 Safe 支持 **`operation = 1` (delegatecall)**，任何 signed transaction 都可以指向任意 contract，并在 proxy 的 storage context 中执行其代码。<sup>[[3]](#references)</sup>

一个 attacker contract 模仿 ERC-20 `transfer(address,uint256)`，但实际上会将 `_to` 写入 slot 0：<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
执行路径：<sup>[[1]](#references)[[3]](#references)</sup>
1. 受害者使用 `operation = delegatecall`、`to = attackerContract`、`data = transfer(newImpl, 0)` 对 `execTransaction` 进行签名。
2. Safe masterCopy 针对这些参数验证签名。
3. Proxy delegatecall 进入 `attackerContract`；其中的 `transfer` 函数体写入 slot 0。
4. Slot 0（`masterCopy`）现在指向攻击者控制的逻辑 → **full wallet takeover and fund drain**。

### Guard 和版本说明（事件后的加固）
- Transaction guards 在 Safe v1.3.0 中引入，可以在执行前检查所有 `execTransaction` 参数；guard 可以拒绝 `delegatecall`，或对目标地址和 calldata 强制执行策略。Bybit 使用的是 v1.1.1，早于这一 hook。<sup>[[2]](#references)[[6]](#references)</sup>

## 检测与加固检查清单

- **UI 完整性**：固定 JS assets / SRI；监控 bundle 差异；将 signing UI 视为信任边界的一部分。
- **签名时验证**：使用支持 **EIP-712 clear-signing** 的 hardware wallets；明确显示 `operation` 并解码嵌套 calldata。除非策略允许，否则在 `operation = 1` 时拒绝签名。<sup>[[3]](#references)</sup>
- **服务端 hash 检查**：中继 proposals 的 gateways/services 必须重新计算 `safeTxHash`，并验证签名与提交的字段匹配。<sup>[[3]](#references)</sup>
- **策略/allowlists**：针对 `to`、selectors、asset types 制定 preflight rules，并禁止 delegatecall，经过审查的流程除外。在广播完全签名的 transactions 前，要求经过内部 policy service。
- **Contract 设计**：除非严格必要，否则避免在 multisig/treasury wallets 中暴露 arbitrary delegatecall。将任何 implementation pointer 视为 upgrade primitive：使用显式 access control 保护它，并对 delegatecall targets/selectors 设置 guard；仅将 pointer 移动到另一个 slot 并不是完整的防御措施。<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**：对持有 treasury funds 的 wallets 执行 delegatecall，以及将 `operation` 从典型 `call` 模式更改的 proposals 发出 alert。

## References

- [1] [AnChain.AI 对 Bybit Safe exploit 的取证分析](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology 对 Safe bundle compromise 的分析](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack 的深入技术分析（NCC Group）](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway（GitHub）](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 更新日志（GitHub）](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
