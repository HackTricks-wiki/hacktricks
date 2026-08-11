# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 概述

一次冷钱包盗窃链结合了 **Safe{Wallet} Web UI 的供应链 compromise** 与 **链上 delegatecall 原语，该原语会覆盖 proxy 的实现指针（slot 0）**。关键要点如下：

- 如果 dApp 能够向 signing path 注入代码，就可以让 signer 生成一份针对攻击者所选字段的有效 **EIP-712 signature**，同时恢复原始 UI 数据，使其他 signers 不知情。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies 将 `masterCopy`（implementation）存储在 **storage slot 0**。对会写入 slot 0 的 contract 执行 delegatecall，实际上会将 Safe “升级”为攻击者控制的 logic，从而完全控制该钱包。<sup>[[3]](#references)</sup>

## 链下：Safe{Wallet} 中针对性 signing mutation

被篡改的 Safe bundle（`_app-*.js`）有选择地攻击特定的 Safe + signer addresses。注入的 logic 在 signing call 之前立即执行：<sup>[[1]](#references)[[3]](#references)</sup>
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
### 攻击特性
- **上下文门控**：针对受害者 Safe/签名者的硬编码 allowlist 减少了噪声并降低了被检测的可能性。<sup>[[1]](#references)[[3]](#references)</sup>
- **最后时刻变更**：`to`、`data`、`operation`、gas 等字段在 `signTransaction` 前立即被覆盖，随后又恢复，因此 UI 中的提案 payload 看起来是良性的，而签名却与攻击者 payload 匹配。<sup>[[3]](#references)</sup>
- **EIP-712 不透明性**：钱包会显示结构化数据，但不会解码嵌套 calldata，也不会突出显示 `operation = delegatecall`，导致被变更的消息实际上处于 blind-signing 状态。<sup>[[3]](#references)[[4]](#references)</sup>

### Gateway 验证的相关性
Safe 提案会提交到 **Safe Client Gateway**。<sup>[[5]](#references)</sup> 在强化检查之前，如果 UI 在签名后重写相关字段，gateway 可能接受 `safeTxHash`/签名与 JSON body 中不同字段相对应的提案。事件发生后，gateway 现在会拒绝 hash/签名与所提交交易不匹配的提案。<sup>[[3]](#references)</sup> 任何 signing-orchestration API 也都应执行类似的 server-side hash verification。

### 2025 Bybit/Safe 事件要点
- 2025 年 2 月 21 日 Bybit 冷钱包被盗（约 401k ETH）复用了相同模式：被 compromise 的 Safe S3 bundle 仅对 Bybit 签名者触发，并将 `operation=0` → `1`，把 `to` 指向一个预先部署的 attacker contract，该合约会写入 slot 0。<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback 缓存的 `_app-52c9031bfa03da47.js` 显示，该逻辑以 Bybit 的 Safe（`0x1db9…cf4`）和签名者地址为触发条件，然后在执行两分钟后立即恢复为干净的 bundle，复现了“mutate → sign → restore”技巧。<sup>[[1]](#references)[[2]](#references)</sup>
- 恶意合约（例如 `0x9622…c7242`）包含简单的 `sweepETH/sweepERC20` 函数，以及一个会写入 implementation slot 的 `transfer(address,uint256)`。执行 `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` 后，proxy implementation 被替换，从而获得完全控制权。<sup>[[1]](#references)[[3]](#references)</sup>

## 链上：通过 slot collision 接管 Delegatecall proxy

Safe proxy 将 `masterCopy` 保存在 **storage slot 0**，并将所有逻辑 delegatecall 到其中。由于 Safe 支持 **`operation = 1` (delegatecall)**，任何已签名交易都可以指向任意合约，并在 proxy 的 storage context 中执行其代码。<sup>[[3]](#references)</sup>

攻击者合约伪装成 ERC-20 `transfer(address,uint256)`，但实际上会将 `_to` 写入 slot 0：<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
执行路径：<sup>[[1]](#references)[[3]](#references)</sup>
1. 受害者使用 `operation = delegatecall`、`to = attackerContract`、`data = transfer(newImpl, 0)` 签署 `execTransaction`。
2. Safe masterCopy 根据这些参数验证签名。
3. Proxy delegatecall 进入 `attackerContract`；`transfer` 函数体写入 slot 0。
4. Slot 0（`masterCopy`）现在指向攻击者控制的逻辑 → **完全接管钱包并转走资金**。

### Guard 与版本说明（事件后的加固措施）
- Transaction guards 于 Safe v1.3.0 中引入，可在执行前检查所有 `execTransaction` 参数；guard 可以拒绝 `delegatecall`，或对目标地址和 calldata 强制执行策略。Bybit 使用的是早于此 hook 的 v1.1.1。<sup>[[2]](#references)[[6]](#references)</sup>

## 检测与加固清单

- **UI 完整性**：固定 JS assets / SRI；监控 bundle 差异；将 signing UI 视为 trust boundary 的一部分。
- **签署时验证**：使用支持 **EIP-712 clear-signing** 的 hardware wallets；明确显示 `operation` 并解码嵌套 calldata。当 `operation = 1` 时，除非策略允许，否则拒绝签署。<sup>[[3]](#references)</sup>
- **服务端 hash 检查**：中继 proposals 的 gateways/services 必须重新计算 `safeTxHash`，并验证签名与提交的字段匹配。<sup>[[3]](#references)</sup>
- **策略/allowlists**：针对 `to`、selectors、asset types 制定 preflight 规则，除经过审查的流程外禁止 delegatecall。在广播 fully signed transactions 前，要求经过内部 policy service。
- **Contract 设计**：除非严格必要，否则避免在 multisig/treasury wallets 中暴露任意 delegatecall。将任何 implementation pointer 视为 upgrade primitive：使用明确的 access control 保护它，并对 delegatecall targets/selectors 实施 guard；仅将 pointer 移动到另一个 slot 并不是完整的防御措施。<sup>[[3]](#references)[[6]](#references)</sup>
- **监控**：对持有 treasury funds 的 wallets 执行 delegatecall，以及将 `operation` 从常见 `call` 模式更改的 proposals 发出告警。

## References

- [1] [AnChain.AI 对 Bybit Safe exploit 的 forensic breakdown](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology 对 Safe bundle compromise 的分析](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack 的深度技术分析（NCC Group）](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway（GitHub）](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog（GitHub）](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
