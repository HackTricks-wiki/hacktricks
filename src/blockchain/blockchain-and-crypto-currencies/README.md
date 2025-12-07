# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** 被定义为在区块链上在满足特定条件时执行的程序，自动化执行协议而无需中介。
- **Decentralized Applications (dApps)** 建立在智能合约之上，具有用户友好的前端和透明、可审计的后端。
- **Tokens & Coins** 区分了币作为数字货币的角色，而代币在特定场景中代表价值或所有权。
- **Utility Tokens** 赋予对服务的访问权限，**Security Tokens** 表示资产所有权。
- **DeFi** 代表去中心化金融，提供无中央机构的金融服务。
- **DEX** 和 **DAOs** 分别指代去中心化交易平台和去中心化自治组织。

## Consensus Mechanisms

共识机制确保区块链上交易验证的安全性与一致性：

- **Proof of Work (PoW)** 依赖计算能力来进行交易验证。
- **Proof of Stake (PoS)** 要求验证者持有一定数量的代币，与 PoW 相比降低了能耗。

## Bitcoin Essentials

### Transactions

比特币交易涉及在地址之间转移资金。交易通过数字签名进行验证，确保只有私钥持有者可以发起转账。

#### Key Components:

- **Multisignature Transactions** 需要多个签名来授权交易。
- 交易由 **inputs**（资金来源）、**outputs**（目的地）、**fees**（支付给矿工的费用）和 **scripts**（交易规则）组成。

### Lightning Network

旨在通过允许在通道内进行多次交易并仅将最终状态广播到区块链上来提高比特币的可扩展性。

## Bitcoin Privacy Concerns

隐私攻击，例如 **Common Input Ownership** 和 **UTXO Change Address Detection**，利用交易模式进行攻击。使用 **Mixers** 和 **CoinJoin** 等策略通过模糊用户之间的交易链接来提高匿名性。

## Acquiring Bitcoins Anonymously

方法包括现金交易、挖矿和使用混合器。**CoinJoin** 将多个交易混合以增加可追踪性的难度，而 **PayJoin** 则将 CoinJoin 伪装为普通交易以提高隐私。

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

在比特币领域，交易隐私和用户匿名性经常成为关注点。下面是几种攻击者可能用来破坏比特币隐私的常见方法的简要概述。

## **Common Input Ownership Assumption**

由于将不同用户的 inputs 合并在单笔交易中比较少见且较复杂，因此 **同一交易中的两个输入地址常被假定为属于同一所有者**。

## **UTXO Change Address Detection**

UTXO（UTXO，Unspent Transaction Output，未花费交易输出）在交易中必须被完全消费。如果只将其中一部分发送到另一个地址，剩余部分会发到一个新的找零地址。观察者可以假定该新地址属于发送者，从而泄露隐私。

### Example

为缓解此问题，可以使用混合服务或使用多个地址来帮助模糊所有权。

## **Social Networks & Forums Exposure**

用户有时会在网上共享他们的比特币地址，使得**很容易将地址与其所有者关联**。

## **Transaction Graph Analysis**

交易可以被可视化为图，揭示基于资金流动的潜在用户连接。

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

该启发式基于分析具有多个输入和输出的交易，推测哪个输出是返回给发送者的找零。

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
如果加入更多输入导致找零输出大于任何单个输入，可能会混淆该启发式方法。

## **强制地址重用**

攻击者可能向先前使用过的地址发送小额资金，希望接收者在未来的交易中把这些与其他输入合并，从而将地址关联起来。

### 正确的钱包行为

钱包应避免使用已被使用且为空的地址上接收到的币，以防止这种隐私 leak。

## **其他区块链分析技术**

- **Exact Payment Amounts:** 没有找零的交易很可能是两个属于同一用户的地址之间的交易。
- **Round Numbers:** 交易中的整数金额通常表明那是一笔支付，而非整数的输出很可能是找零。
- **Wallet Fingerprinting:** 不同的钱包在创建交易时有独特的模式，分析人员可以据此识别所用软件并有可能找到找零地址。
- **Amount & Timing Correlations:** 公开交易时间或金额会使交易可被追踪。

## **流量分析**

通过监控网络流量，攻击者能够将交易或区块与 IP 地址关联，从而破坏用户隐私。如果某个实体运行大量比特币节点，这种监控能力会更强，情形尤其如此。

## 更多

有关隐私攻击和防御的完整列表，请访问 [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)。

# 匿名比特币交易

## 匿名获取比特币的方法

- **现金交易**：通过现金获取比特币。
- **现金替代方式**：购买礼品卡并在网上兑换为比特币。
- **挖矿**：通过挖矿获得比特币是最私密的方法，尤其是单独挖矿，因为矿池可能知道矿工的 IP 地址。 [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **盗窃**：理论上，窃取比特币也可能是另一种匿名获取方式，但这是非法且不建议的。

## 混币服务

通过使用混币服务，用户可以 **发送比特币** 并获得 **不同的比特币作为回报**，这使得追踪原始持有者变得困难。然而，这需要信任该服务不会保存日志并且确实会返还比特币。替代的混币选项包括比特币赌场。

## CoinJoin

**CoinJoin** 将来自不同用户的多个交易合并为一个，使试图对比输入和输出的人更难匹配。尽管有效，但输入和输出大小独一无二的交易仍可能被追踪。

可能使用 CoinJoin 的示例交易包括 `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` 和 `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`。

欲了解更多信息，请访问 [CoinJoin](https://coinjoin.io/en)。对于以太坊上的类似服务，请查看 [Tornado Cash](https://tornado.cash)，它使用矿工的资金来匿名化交易。

## PayJoin

作为 CoinJoin 的一种变体，**PayJoin**（或 P2EP）将双方（例如客户和商家）之间的交易伪装成普通交易，而没有 CoinJoin 那种典型的相等输出特征。这使其极难被检测，并可能使交易监控机构使用的 common-input-ownership heuristic 失效。
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# 隐私最佳实践（加密货币）

## **钱包同步技术**

为了保持隐私和安全，与区块链同步钱包至关重要。有两种突出的方法：

- **Full node**：通过下载整个区块链，full node 可确保最大的隐私。所有历史交易都会本地保存，令对手无法识别用户感兴趣的是哪些交易或地址。
- **Client-side block filtering**：此方法为区块链中的每个区块创建过滤器，使钱包能够在不向网络观察者暴露具体兴趣的情况下识别相关交易。轻量级钱包会下载这些过滤器，仅在与用户地址匹配时才获取完整区块。

## **使用 Tor 以提高匿名性**

鉴于 Bitcoin 在点对点网络上运行，建议使用 Tor 来掩盖你的 IP 地址，从而在与网络交互时增强隐私。

## **防止地址重用**

为保护隐私，每次交易使用新的地址至关重要。地址重用会通过将交易链接到同一实体而损害隐私。现代钱包通过设计来 discourage 地址重用。

## **交易隐私策略**

- **Multiple transactions**：将付款拆分为多笔交易可以混淆交易金额，抵抗隐私攻击。
- **Change avoidance**：选择不需要找零输出的交易可以提高隐私，因为这会破坏找零检测方法。
- **Multiple change outputs**：如果无法避免找零，生成多个找零输出仍可提升隐私。

# **Monero：匿名性的灯塔**

Monero 致力于在数字交易中实现绝对匿名，为隐私设定了高标准。

# **Ethereum：Gas 与交易**

## **理解 Gas**

Gas 衡量在 Ethereum 上执行操作所需的计算工作量，以 **gwei** 计价。例如，花费 2,310,000 gwei（或 0.00231 ETH）的交易涉及 gas limit 和 base fee，并有 tip 来激励矿工。用户可以设置 max fee 以确保不会支付过多，多出的部分会被退还。

## **执行交易**

Ethereum 的交易涉及发送方和接收方，这两者可以是用户地址或智能合约地址。它们需要支付费用并且必须被打包到区块中。交易中的关键信息包括接收方、发送方的签名、数额、可选数据、gas limit 和费用。值得注意的是，发送方地址是从签名推导出来的，因此不需要在交易数据中明示。

这些实践和机制是任何在重视隐私和安全的前提下参与加密货币活动的人所应掌握的基础。

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
